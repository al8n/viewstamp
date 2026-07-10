use std::sync::{
  Arc,
  atomic::{AtomicUsize, Ordering},
};

use bytes::Bytes;
use compio::{
  buf::{BufResult, IntoInner, IoBuf},
  io::{AsyncRead, AsyncWrite},
  net::TcpStream,
};
use viewstamp_proto::ConnId;

const RECV_BUF_LEN: usize = 64 * 1024;

/// A connection task -> the coordinator (ONE shared channel; the tag carries which [`ConnId`]).
pub(crate) enum BridgeInbound {
  Bytes { id: ConnId, bytes: Vec<u8> },
  Eof { id: ConnId },
  Error { id: ConnId },
}

/// The coordinator -> ONE connection task (per-conn FIFO so queued bytes flush before close). A
/// graceful close is signalled by dropping the sender (`Conn.out_tx`): the writer's
/// `out_rx.recv_async()` then resolves `Err` after first draining the FIFO bytes queued ahead of it.
/// The driver drops `out_tx` (by dropping the whole `Conn`) rather than sending an explicit close
/// message, so there is no `Close` variant — one frame type keeps the queue's byte accounting
/// unambiguous.
pub(crate) struct BridgeOut(pub(crate) Bytes);

/// A dial completion handed back to the driver. The conn was registered and its [`Conn`] inserted at
/// dial time (so the coordinator's queued handshake bytes aren't lost while the socket connects); on
/// success `out_rx` + `queued_bytes` ride this back so the writer can drain the queue and decrement
/// the byte budget. Redial info (peer/addr) is NOT carried here — it lives in [`Conn::redial`], so a
/// failed dial reads it from the still-present `Conn`.
pub(crate) struct DialReady {
  pub(crate) id: ConnId,
  pub(crate) result: std::io::Result<TcpStream>,
  /// The outbound receiver the writer drains (moved into the connect task in `dial_peer`, shipped
  /// back here on completion so the bridge — not the connect task — owns it).
  pub(crate) out_rx: flume::Receiver<BridgeOut>,
  /// The same byte counter the driver's `Conn` holds a clone of: the writer decrements it as it
  /// writes, the driver increments it on enqueue.
  pub(crate) queued_bytes: Arc<AtomicUsize>,
}

/// The live task(s) the driver holds for one connection. Dropping it cancels whatever is running:
/// compio aborts a non-detached task when its [`JoinHandle`](compio::runtime::JoinHandle) drops, so
/// dropping a `Connecting` drops the connect task and dropping a `Bridged` drops BOTH split-half
/// tasks — aborting a stuck write and dropping the socket.
///
/// The handles are held ONLY so their drop performs that cancel; they are never read again (the
/// `#[allow(dead_code)]` records that drop is the load-bearing use, not the value).
pub(crate) enum ConnTask {
  /// The dial/connect task, until it succeeds.
  #[allow(dead_code)]
  Connecting(compio::runtime::JoinHandle<()>),
  /// The two independent split-half tasks: one reads the socket, one writes it. Each owns one owned
  /// half (via `into_split`), so a large write on the `write` task never starves the `read` task —
  /// the proactor drives both concurrently. Either task signalling EOF/error leads the driver to
  /// `close_conn`, which drops this `Bridged` and so cancels the OTHER half.
  #[allow(dead_code)]
  Bridged {
    read: compio::runtime::JoinHandle<()>,
    write: compio::runtime::JoinHandle<()>,
  },
}

/// The redial target a DIALED conn carries: who to re-dial when this conn is lost, and how long to
/// wait before doing so. Living ON the conn (not in a separate per-peer map) keeps one owned unit
/// per connection — the redial state is created, carried, and consumed with the conn itself, so
/// there is no side table to drift out of sync.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Redial {
  pub(crate) peer: viewstamp_proto::ReplicaId,
  pub(crate) addr: std::net::SocketAddr,
  /// The (un-jittered) delay before the redial issued when THIS conn is lost. The replacement conn
  /// stores the doubled value, capped at the stream driver's redial ceiling, so consecutive losses
  /// space out exponentially; validation resets it to the base (the stream mirror of the QUIC
  /// driver's `PeerLink` backoff).
  pub(crate) backoff: std::time::Duration,
}

/// Everything the driver owns for one connection. Dropping it tears the connection down completely:
/// the `tasks` JoinHandle(s) drop cancels the live compio task(s) (connect OR both bridge halves) —
/// aborting a stuck write and dropping the socket — and `out_tx`'s drop signals a still-running
/// writer to close.
pub(crate) struct Conn {
  /// The connection's live task(s): the dial/connect task until it succeeds, then the two bridge
  /// halves.
  pub(crate) tasks: ConnTask,
  /// Outbound frames to the writer (drained from the coordinator).
  pub(crate) out_tx: flume::Sender<BridgeOut>,
  /// Bytes currently queued toward this conn's socket (driver adds on enqueue, writer subtracts as it
  /// writes) — the byte budget that bounds memory.
  pub(crate) queued_bytes: Arc<AtomicUsize>,
  /// `Some` for a DIALED conn (redial it on loss, at its carried backoff); `None` for an ACCEPTED
  /// conn (the peer redials us).
  pub(crate) redial: Option<Redial>,
  /// `Some(deadline)` while this conn is still subject to the handshake/auth deadline; cleared to
  /// `None` once the coordinator reports it validated. A conn still unvalidated at `deadline` is torn
  /// down, so a peer that completes the socket connect but stalls before the `Labeled`/TLS handshake
  /// validates cannot pin a slot (and a coordinator entry) forever — a connection-table-exhaustion
  /// DoS reachable within the non-Byzantine threat model.
  pub(crate) auth_deadline: Option<viewstamp_proto::Instant>,
}

/// Read one socket half to EOF/error, tagging every received chunk with `id` onto the shared
/// `inbound_tx`. Runs on its own task so a concurrent large write (the writer half) cannot stop this
/// half from reading: the two halves make progress independently via the proactor. On `Ok(0)` the
/// peer closed its write side (EOF); on `Err` the socket failed. Either ends this half with the
/// matching inbound signal, and the driver's `close_conn` then drops the whole `Conn` — cancelling
/// the writer half (for a dialed conn, the close path also redials).
pub(crate) async fn bridge_read(
  mut read_half: impl AsyncRead,
  id: ConnId,
  inbound_tx: flume::Sender<BridgeInbound>,
) {
  // One buffer for the task's lifetime: the completed read hands it back in the `BufResult`, so each
  // iteration re-lends the same allocation instead of zeroing a fresh 64 KiB per read. Only the
  // exactly-`n`-sized inbound copy is allocated per chunk (the channel needs an owned `Vec` while
  // the buffer goes back on the wire).
  let mut buf = vec![0u8; RECV_BUF_LEN];
  loop {
    let BufResult(res, returned) = read_half.read(buf).await;
    buf = returned;
    match res {
      Ok(0) => {
        let _ = inbound_tx.send_async(BridgeInbound::Eof { id }).await;
        return;
      }
      Ok(n) => {
        let _ = inbound_tx
          .send_async(BridgeInbound::Bytes {
            id,
            bytes: buf[..n].to_vec(),
          })
          .await;
      }
      Err(_) => {
        let _ = inbound_tx.send_async(BridgeInbound::Error { id }).await;
        return;
      }
    }
  }
}

/// Write one socket half from the per-conn FIFO until a graceful close or an I/O error. Runs on its
/// own task so writing a whole large `Bytes` chunk never blocks the reader half: the two halves make
/// progress independently via the proactor (the full-duplex stall a single read+write task suffers
/// under large bidirectional traffic cannot happen here).
///
/// Each chunk is written with the completion-based partial-write/`into_inner` recovery loop, and
/// `queued_bytes` is released INCREMENTALLY — by the count actually written on each partial write —
/// so the driver's enqueue-side byte budget reflects what is still in flight WHILE a large chunk is
/// still draining, not only once it finishes (a chunk mid-drain must not keep the counter over the
/// cap and false-close a healthy conn). The decrements for one chunk always sum to exactly its length
/// (no under/over-count, no underflow): on a terminal short-write/error the REMAINING unwritten bytes
/// are released. Dropping `out_tx` (the driver dropped this conn's `Conn`) drains the FIFO, then ends
/// this half with `Eof`; an I/O error ends it with `Error`. A HARD abort (a stuck write the graceful
/// close can't preempt) is external: the driver drops this task's `JoinHandle`, which compio cancels.
pub(crate) async fn bridge_write(
  mut write_half: impl AsyncWrite,
  id: ConnId,
  out_rx: flume::Receiver<BridgeOut>,
  queued_bytes: Arc<AtomicUsize>,
  inbound_tx: flume::Sender<BridgeInbound>,
) {
  loop {
    match out_rx.recv_async().await {
      Ok(BridgeOut(mut bytes)) => {
        let total = bytes.len();
        let mut written = 0;
        while written < total {
          // Completion-based write: the slice is moved in and returned in the `BufResult`; recover
          // the owned buffer with `into_inner` and loop on the unwritten tail.
          let BufResult(res, slice) = write_half.write(bytes.slice(written..)).await;
          bytes = slice.into_inner();
          match res {
            // No progress: error out rather than spin. Release this chunk's REMAINING bytes (those
            // not yet accounted by the per-write decrements below) so its total decrement is exactly
            // `total` — no leak, no underflow.
            Ok(0) => {
              queued_bytes.fetch_sub(total - written, Ordering::Relaxed);
              let _ = inbound_tx.send_async(BridgeInbound::Error { id }).await;
              return;
            }
            // Release exactly what this partial write moved onto the wire, so the budget tracks
            // in-flight bytes as the chunk drains (not only at completion).
            Ok(n) => {
              written += n;
              queued_bytes.fetch_sub(n, Ordering::Relaxed);
            }
            Err(_) => {
              queued_bytes.fetch_sub(total - written, Ordering::Relaxed);
              let _ = inbound_tx.send_async(BridgeInbound::Error { id }).await;
              return;
            }
          }
        }
        // The chunk is fully written: the per-write decrements already released all `total` bytes, so
        // there is nothing left to subtract here.
      }
      // The coordinator dropped `out_tx` (the driver dropped this conn's `Conn`): the FIFO has
      // flushed, so signal Eof and exit.
      Err(_) => {
        let _ = inbound_tx.send_async(BridgeInbound::Eof { id }).await;
        return;
      }
    }
  }
}

#[cfg(test)]
mod tests;

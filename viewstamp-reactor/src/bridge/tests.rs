use std::{
  sync::{Arc, atomic::AtomicUsize},
  time::Duration,
};

use agnostic::{
  Runtime, RuntimeLite,
  net::{Net, TcpListener, TcpStream},
};
use bytes::Bytes;
use viewstamp_proto::ConnId;

use super::{BridgeInbound, BridgeOut, Conn, ConnTask, bridge_read, bridge_write};
use crate::task::AbortOnDrop;

type TestRt = agnostic::tokio::TokioRuntime;
type TestListener = <<TestRt as Runtime>::Net as Net>::TcpListener;
type TestStream = <<TestRt as Runtime>::Net as Net>::TcpStream;

/// Bind an ephemeral loopback listener, dial it, and accept, returning the connected
/// `(client, server)` stream pair so a bridge can run on each end.
async fn connected_pair() -> (TestStream, TestStream) {
  let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
  let listener = TestListener::bind(addr).await.expect("bind loopback");
  let addr = listener.local_addr().expect("listener addr");
  let connect = TestStream::connect(addr);
  let accept = listener.accept();
  let (client, accepted) = futures_util::future::join(connect, accept).await;
  let (server, _peer) = accepted.expect("accept");
  (client.expect("connect"), server)
}

/// Spawn the read + write halves of one bridge over `stream`, returning its
/// `(out_tx, inbound_rx)`: push `BridgeOut` chunks into `out_tx`, observe inbound on `inbound_rx`.
/// The `queued_bytes` counter is internal to the write half's accounting and not asserted here.
/// The tasks are deliberately fire-and-forget (`spawn_detach`): they exit on socket EOF/error and
/// die with the test runtime — the owned-handle teardown is pinned by
/// [`dropping_a_conn_aborts_its_parked_write_task`].
fn run_bridge(
  stream: TestStream,
  id: ConnId,
) -> (
  flume::Sender<BridgeOut>,
  flume::Receiver<BridgeInbound>,
  Arc<AtomicUsize>,
) {
  let (out_tx, out_rx) = flume::unbounded();
  let (inbound_tx, inbound_rx) = flume::unbounded();
  let queued_bytes = Arc::new(AtomicUsize::new(0));
  let (read_half, write_half) = stream.into_split();
  TestRt::spawn_detach(bridge_read(read_half, id, inbound_tx.clone()));
  TestRt::spawn_detach(bridge_write(
    write_half,
    id,
    out_rx,
    queued_bytes.clone(),
    inbound_tx,
  ));
  (out_tx, inbound_rx, queued_bytes)
}

/// Collect inbound `Bytes` from one bridge until `want` bytes have arrived, returning them
/// concatenated. An `Eof`/`Error` before `want` is a failure (the conn died mid-transfer).
async fn recv_n(inbound_rx: &flume::Receiver<BridgeInbound>, want: usize) -> Vec<u8> {
  let mut got = Vec::with_capacity(want);
  while got.len() < want {
    match inbound_rx.recv_async().await.expect("inbound channel open") {
      BridgeInbound::Bytes { bytes, .. } => got.extend_from_slice(&bytes),
      BridgeInbound::Eof { .. } => panic!("EOF before the full payload arrived"),
      BridgeInbound::Error { .. } => panic!("Error before the full payload arrived"),
    }
  }
  got
}

/// Two healthy peers each writing a payload LARGER than the socket buffers must BOTH make progress:
/// reads and writes run on independent tasks, so a large in-flight write never stops the same conn
/// from reading. A single read+write task under one `select` would (with the out arm awaiting the
/// whole write inside the arm) stop reading for the duration of its write; two such peers each
/// blocked in `write().await` past the TCP window — neither reading — deadlock. The 16 MiB payload
/// exceeds any default socket buffer, so the write cannot complete without the peer draining its
/// read side concurrently. A generous timeout bounds the (expected) success; the single-task design
/// hangs here instead.
#[tokio::test]
async fn duplex_large_write_does_not_deadlock() {
  const PAYLOAD: usize = 16 * 1024 * 1024;
  let (client, server) = connected_pair().await;
  let (c_out, c_in, _c_qb) = run_bridge(client, ConnId::new(1));
  let (s_out, s_in, _s_qb) = run_bridge(server, ConnId::new(2));

  // Two distinct payloads so each side proves it received the OTHER's bytes, not its own.
  let from_client = vec![0xA5u8; PAYLOAD];
  let from_server = vec![0x5Au8; PAYLOAD];
  c_out
    .send(BridgeOut(Bytes::from(from_client.clone())))
    .expect("queue client payload");
  s_out
    .send(BridgeOut(Bytes::from(from_server.clone())))
    .expect("queue server payload");

  // Both ends must receive the other's full payload. With the single-task bridge this times out
  // (both writers parked past the TCP window, neither reading); the two-task bridge converges.
  let both = futures_util::future::join(recv_n(&s_in, PAYLOAD), recv_n(&c_in, PAYLOAD));
  let (server_got, client_got) = tokio::time::timeout(Duration::from_secs(30), both)
    .await
    .expect("a full-duplex large transfer completes (no read-starving-write deadlock)");

  assert_eq!(
    server_got, from_client,
    "the server received the client's full payload"
  );
  assert_eq!(
    client_got, from_server,
    "the client received the server's full payload"
  );
}

/// LEAK WITNESS: dropping a [`Conn`] ABORTS its write task even while that task is parked
/// mid-chunk on a socket whose peer never reads. The witness is the `queued_bytes` `Arc`'s strong
/// count: the test holds one reference, the `Conn` one, and the spawned write task one (= 3);
/// dropping the `Conn` must drain the count to the test-side-only 1, which can only happen if the
/// parked task's future was genuinely dropped — on tokio a raw (non-[`AbortOnDrop`]) handle drop
/// would DETACH instead, leaving the task parked forever and the count pinned at 2.
#[tokio::test]
async fn dropping_a_conn_aborts_its_parked_write_task() {
  // Far larger than any default socket buffer pair, so the writer MUST park mid-chunk once the
  // kernel buffers fill (the peer never reads).
  const PAYLOAD: usize = 16 * 1024 * 1024;
  let (client, server) = connected_pair().await;

  let (out_tx, out_rx) = flume::unbounded();
  let (inbound_tx, inbound_rx) = flume::unbounded();
  let queued_bytes = Arc::new(AtomicUsize::new(0));
  queued_bytes.store(PAYLOAD, std::sync::atomic::Ordering::Relaxed);

  // The REAL spawn path: both halves spawned via `R::spawn` and owned as `AbortOnDrop` inside a
  // `Conn`, exactly as the driver builds one.
  let (read_half, write_half) = client.into_split();
  let conn: Conn<TestRt> = Conn {
    tasks: ConnTask::Bridged {
      read: AbortOnDrop::new(TestRt::spawn(bridge_read(
        read_half,
        ConnId::new(1),
        inbound_tx.clone(),
      ))),
      write: AbortOnDrop::new(TestRt::spawn(bridge_write(
        write_half,
        ConnId::new(1),
        out_rx,
        queued_bytes.clone(),
        inbound_tx,
      ))),
    },
    out_tx,
    queued_bytes: queued_bytes.clone(),
    redial: None,
    auth_deadline: None,
  };
  assert_eq!(
    Arc::strong_count(&queued_bytes),
    3,
    "test + Conn + write task each hold the counter"
  );

  // Park the writer mid-backlog: queue one over-buffer chunk, then wait until SOME bytes were
  // written (the cursor is inside the chunk's drain loop) while the unread peer guarantees the
  // chunk can never finish — the task is now parked in `write().await`.
  conn
    .out_tx
    .send(BridgeOut(Bytes::from(vec![0xA5u8; PAYLOAD])))
    .expect("queue the over-buffer chunk");
  let mut parked = false;
  for _ in 0..500 {
    let queued = queued_bytes.load(std::sync::atomic::Ordering::Relaxed);
    if queued < PAYLOAD {
      parked = true;
      break;
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert!(
    parked,
    "the write task picked up the chunk and wrote part of it (it is parked mid-chunk)"
  );

  // Drop the Conn: its AbortOnDrop handles must abort BOTH tasks. The write task's clone of the
  // counter can only drop if the parked future was destroyed, so the strong count draining to the
  // test-side-only 1 is the proof the abort genuinely happened (a detached task would survive,
  // parked, holding its clone forever).
  drop(conn);
  let mut drained = false;
  for _ in 0..500 {
    if Arc::strong_count(&queued_bytes) == 1 {
      drained = true;
      break;
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert!(
    drained,
    "dropping the Conn aborted the parked write task (its counter clone was released)"
  );
  drop(inbound_rx);
  drop(server); // the unread peer stays alive until after the abort is proven
}

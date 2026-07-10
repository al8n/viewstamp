use std::{
  sync::{Arc, atomic::AtomicUsize},
  time::Duration,
};

use bytes::Bytes;
use compio::net::{TcpListener, TcpStream};
use viewstamp_proto::ConnId;

use super::{BridgeInbound, BridgeOut, bridge_read, bridge_write};

/// Bind an ephemeral loopback listener, dial it, and accept, returning the connected
/// `(client, server)` `TcpStream` pair so a bridge can run on each end.
async fn connected_pair() -> (TcpStream, TcpStream) {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("bind loopback");
  let addr = listener.local_addr().expect("listener addr");
  let connect = TcpStream::connect(addr);
  let accept = listener.accept();
  let (client, accepted) = futures_util::future::join(connect, accept).await;
  let (server, _peer) = accepted.expect("accept");
  (client.expect("connect"), server)
}

/// Spawn the read + write halves of one bridge over `stream`, returning its
/// `(out_tx, inbound_rx)`: push `BridgeOut` chunks into `out_tx`, observe inbound on `inbound_rx`.
/// The `queued_bytes` counter is internal to the write half's accounting and not asserted here.
fn run_bridge(
  stream: TcpStream,
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
  compio::runtime::spawn(bridge_read(read_half, id, inbound_tx.clone())).detach();
  compio::runtime::spawn(bridge_write(
    write_half,
    id,
    out_rx,
    queued_bytes.clone(),
    inbound_tx,
  ))
  .detach();
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
#[compio::test]
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
  let (server_got, client_got) = compio::time::timeout(Duration::from_secs(30), both)
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

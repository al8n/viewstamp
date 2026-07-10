//! The stream-transport ingress pipeline fed arbitrary bytes in arbitrary CHUNKINGS, through the
//! public API: `StreamCoordinator::handle_conn_data` on an accepted `Labeled<Passthrough>` conn —
//! i.e. record layer -> `Labeled` hello handshake -> incremental `FrameDecoder` -> the per-frame
//! `decode_message` -> endpoint ingress. (`FrameDecoder` itself is crate-private; this is its
//! only public reachability, and it exercises the decoder exactly as a driver does.)
//!
//! Input shape: the first byte picks the lane, the rest is the wire payload.
//! - Lane 0 (even): the payload is fed raw from byte 0 — fuzzes the pre-validation path (the
//!   hello frame parse + rejection).
//! - Lane 1 (odd): a CANONICAL replica-1 hello (obtained from a real dialer conn, the only public
//!   source of one) is fed first so the conn validates, then the payload — fuzzes the
//!   post-validation path (frame chunk reassembly, `decode_message`, endpoint dispatch).
//!
//! Chunk sizes are derived from the payload bytes themselves, so the corpus explores both the
//! byte content and its fragmentation. Nothing here may panic; outputs are drained every chunk so
//! backlogs stay bounded.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use viewstamp_proto::{
  Config, Conn, Endpoint, Instant, LabelOptions, Labeled, MemberId, Membership, Passthrough, Peer,
  ReplicaId, StreamCoordinator,
};
use viewstamp_simulation::{InMemorySuperblock, InMemoryWal, MemBlockStore, sm::LogSm};

const CLUSTER: u128 = 0xF022;

fn genesis(n: u8) -> Membership {
  Membership::from_durable_parts(
    viewstamp_proto::Epoch::new(0),
    n,
    0,
    (0..n as u128).map(MemberId::new).collect(),
    0,
  )
  .expect("valid genesis membership")
}

fn coordinator(me: u8) -> StreamCoordinator<LogSm, Labeled<Passthrough>> {
  let config =
    Config::try_new(CLUSTER, MemberId::new(u128::from(me))).expect("static config is valid");
  StreamCoordinator::new(Endpoint::with_reconfig(
    config,
    genesis(3),
    0,
    LogSm::default(),
  ))
}

/// The canonical bytes a replica-1 DIALER writes first (its `Labeled` hello): registered on a
/// scratch coordinator and drained from its transmit queue — the hello encoder is crate-private,
/// so a real dialer conn is the public source. Deterministic, so computed once.
fn replica1_hello() -> &'static [u8] {
  static HELLO: OnceLock<Vec<u8>> = OnceLock::new();
  HELLO.get_or_init(|| {
    let mut peer = coordinator(1);
    let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(1)));
    let conn = Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts));
    let id = peer.register_dialed(Peer::Replica(ReplicaId::new(0)), conn);
    let mut out = Vec::new();
    while let Some((cid, bytes)) = peer.poll_conn_transmit() {
      if cid == id {
        out.extend_from_slice(&bytes);
      }
    }
    assert!(
      !out.is_empty(),
      "a dialer conn writes its hello on registration"
    );
    out
  })
}

fuzz_target!(|data: &[u8]| {
  let Some((&lane, payload)) = data.split_first() else {
    return;
  };

  let mut wal = InMemoryWal::new();
  let mut sb = InMemorySuperblock::new();
  let mut blocks = MemBlockStore::new();
  let now = Instant::ZERO;

  let mut coord = coordinator(0);
  let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
  let conn = Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts));
  let id = coord.register_accepted(Peer::Replica(ReplicaId::new(1)), conn);

  if lane & 1 == 1 {
    coord.handle_conn_data(
      id,
      replica1_hello(),
      false,
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
    );
    // Postcondition (and proof the deep path is reached): the canonical hello always validates,
    // so everything after it exercises the post-validation frame/message/endpoint pipeline.
    assert!(
      coord.is_conn_validated(id),
      "the canonical replica-1 hello must validate the accepted conn"
    );
  }

  let mut rest = payload;
  while !rest.is_empty() {
    // Self-referential chunking: the chunk's own leading byte sizes it (1..=67 bytes).
    let take = ((rest[0] as usize) % 67 + 1).min(rest.len());
    let (chunk, tail) = rest.split_at(take);
    rest = tail;
    coord.handle_conn_data(id, chunk, false, now, &mut wal, &mut sb, &mut blocks);
    while coord.poll_conn_transmit().is_some() {}
    while coord.poll_event().is_some() {}
    while coord.poll_conn_closed().is_some() {}
  }

  // EOF pass: a peer-finished conn finalizes + closes cleanly.
  coord.handle_conn_data(id, &[], true, now, &mut wal, &mut sb, &mut blocks);
  while coord.poll_conn_transmit().is_some() {}
  while coord.poll_conn_closed().is_some() {}
});

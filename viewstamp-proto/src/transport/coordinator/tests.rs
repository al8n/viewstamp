use std::vec;

use super::*;
use crate::{
  ClientId, Config, LabelOptions, Labeled, MemberId, ReplicaId, RequestNumber, SingleChange,
  encode_message,
  message::Request,
  transport::{
    Passthrough,
    stream::RecordIo,
    testutil::{CountSm, MockRecords, TestSb, TestWal, genesis},
  },
};

fn req() -> Message {
  Message::Request(Request::new(
    ClientId::new(7),
    RequestNumber::with(1),
    Bytes::from_static(b"x"),
  ))
}

fn labeled_conn(cluster: u128, me: u16, accept: bool) -> Conn<Labeled<Passthrough>> {
  let opts = LabelOptions::new(cluster, Peer::Member(MemberId::new(me as u128)));
  if accept {
    Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
  } else {
    Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
  }
}

/// Registers a conn that presents `Peer::Member(MemberId::new(member_idx))` as its handshake
/// identity and triggers validation through the coordinator seal. After this call the conn is
/// authoritative for `Peer::Replica(ReplicaId::new(member_idx))` (assumes the genesis membership
/// assigns `MemberId::new(i)` to slot `i`). Drives a zero-byte `handle_conn_data` so
/// `try_note_established_member` fires without needing a real inbound frame.
fn register_and_validate_member(
  coord: &mut StreamCoordinator<CountSm, MockRecords>,
  wal: &mut TestWal,
  sb: &mut TestSb,
  blocks: &mut crate::block_store::MemBlockStore,
  member_idx: u128,
) -> ConnId {
  let member = MemberId::new(member_idx);
  let id = coord.register_accepted(
    Peer::Replica(ReplicaId::new(member_idx as u16)),
    Conn::from_parts(MockRecords::new(false, Some(Peer::Member(member)))),
  );
  coord.handle_conn_data(id, &[], false, Instant::ZERO, wal, sb, blocks);
  id
}

#[test]
fn inbound_request_produces_outbound_to_a_backup() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap(); // replica 0 = primary of view 0
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  // Register backup conns attesting Peer::Member so try_note_established_member validates them
  // through note_established_member (the production path that stores the stable MemberId).
  register_and_validate_member(&mut coord, &mut wal, &mut sb, &mut blocks, 1);
  register_and_validate_member(&mut coord, &mut wal, &mut sb, &mut blocks, 2);
  coord.inject_message_for_test(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    req(),
  );
  // The Prepare may emit immediately or after a storage/timer nudge; drive a few ticks.
  let mut now = Instant::ZERO;
  let mut produced = coord.poll_conn_transmit().is_some();
  for _ in 0..10 {
    if produced {
      break;
    }
    now = now + core::time::Duration::from_millis(50);
    coord.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    coord.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
    produced = coord.poll_conn_transmit().is_some();
  }
  assert!(
    produced,
    "an inbound request must produce outbound transport bytes to a backup"
  );
}

/// A relayed (replica-sent) `Request` whose body is ONE byte over the deliverable maximum is dropped
/// at the transport ingress BEFORE the endpoint: no op is appended and no `Prepare` is routed to any
/// backup. The hazard: a buggy / version-skewed member relays a `Request` that fits its own frame
/// but whose resulting `Prepare` would exceed `MAX_FRAME_LEN`, so the primary would log an op it
/// can never replicate. The
/// at-maximum body, by contrast, is served and routed — the boundary is usable, not rejected
/// off-by-one. The ingress gate keeps the consensus `Endpoint` itself transport-agnostic.
#[test]
fn a_relayed_over_max_request_is_dropped_at_ingress_with_no_side_effects() {
  use crate::transport::frame::{MAX_FRAME_LEN, max_request_body_len};

  // Replica 0 is the primary of view 0, so an admitted relayed Request would be served.
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  // Two backup conns validated through the coordinator seal, so a served Prepare HAS somewhere to
  // route — proving the over-max case routes NOTHING, not merely that no conn was available.
  register_and_validate_member(&mut coord, &mut wal, &mut sb, &mut blocks, 1);
  register_and_validate_member(&mut coord, &mut wal, &mut sb, &mut blocks, 2);
  assert_eq!(coord.endpoint().op().get(), 0, "no op before any request");

  // A relayed Request (from a configured REPLICA — the replica-relayed ingress this gate guards)
  // whose body is one byte past the deliverable maximum: its resulting Prepare would exceed
  // MAX_FRAME_LEN.
  let over = Message::Request(Request::new(
    ClientId::new(7),
    RequestNumber::with(1),
    Bytes::from(vec![0u8; max_request_body_len() + 1]),
  ));
  coord.inject_message_for_test(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    over,
  );

  // No side effects: the op head did not advance, so no op was appended and no `Prepare` minted for
  // it. Pump STORAGE ONLY (never `handle_timeout`) so the primary's heartbeat does not fire — then
  // `poll_conn_transmit` reflects only what this request produced, which is nothing.
  let mut now = Instant::ZERO;
  for _ in 0..5 {
    now = now + core::time::Duration::from_millis(50);
    coord.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    coord.endpoint().op().get(),
    0,
    "an over-max relayed request appends no op (dropped before the endpoint)"
  );
  assert!(
    coord.poll_conn_transmit().is_none(),
    "an over-max relayed request routes no Prepare to any backup (no side effects)"
  );

  // The BOUNDARY: a body of EXACTLY max_request_body_len() is served (op appended) and routed.
  let at_max = Message::Request(Request::new(
    ClientId::new(7),
    RequestNumber::with(1),
    Bytes::from(vec![0u8; max_request_body_len()]),
  ));
  assert!(
    max_request_body_len() < MAX_FRAME_LEN as usize,
    "the deliverable max is under the frame cap by the request overhead"
  );
  coord.inject_message_for_test(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    at_max,
  );
  assert_eq!(
    coord.endpoint().op().get(),
    1,
    "an at-maximum relayed request IS served (one op appended): the boundary is usable"
  );
  // Drive the append to completion via STORAGE so the resulting Prepare is routed to the backups
  // (still no `handle_timeout`, so the transmit observed is the Prepare, not a heartbeat).
  let mut routed = coord.poll_conn_transmit().is_some();
  for _ in 0..10 {
    if routed {
      break;
    }
    now = now + core::time::Duration::from_millis(50);
    coord.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    routed = coord.poll_conn_transmit().is_some();
  }
  assert!(
    routed,
    "an at-maximum relayed request IS routed to a backup (the gate admits exactly the max)"
  );
}

// A single large valid read (more than one STAGE_CHUNK of framed messages) is fully processed:
// handle_conn_data feeds it to the conn in bounded chunks, decoding between each, and the conn
// stays open because every frame decodes cleanly.
#[test]
fn a_large_multi_chunk_read_is_processed_without_closing_the_conn() {
  use crate::transport::frame::encode_frame;
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  // Register and validate the conn through the coordinator seal, then feed inbound frames.
  let id = register_and_validate_member(&mut coord, &mut wal, &mut sb, &mut blocks, 1);
  // Build more than one 64 KiB STAGE_CHUNK worth of framed messages so the read spans chunks.
  let mut frames = Vec::new();
  while frames.len() <= 64 * 1024 {
    encode_frame(&encode_message(&req()), &mut frames);
  }
  coord.handle_conn_data(
    id,
    &frames,
    false,
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  assert!(
    coord.router_ref().conn(id).is_some(),
    "a large valid multi-chunk read keeps the conn open"
  );
  assert!(coord.is_conn_validated(id), "the conn stays validated");
}

// max_outbound_backlog is 2x the router's per-conn outbound_cap staging size — the driver's
// accumulation threshold (not the out-queue peak), config-independent of any record-layer ciphertext
// prediction. A default-cap coordinator reports 2x the default 64 MiB staging cap.
#[test]
fn max_outbound_backlog_is_twice_the_router_outbound_cap() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let coord = StreamCoordinator::<CountSm, Passthrough>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  const DEFAULT_CAP: usize = 64 * 1024 * 1024;
  assert_eq!(
    coord.max_outbound_backlog(),
    DEFAULT_CAP * 2,
    "the coordinator reports 2x the router's per-conn outbound_cap staging size (the accumulation \
     threshold)"
  );
}

// A peer presenting the wrong cluster id is rejected and the conn reaped.
#[test]
fn wrong_cluster_conn_is_reaped() {
  let cfg = Config::try_new(0xAAAA, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord =
    StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
  let id = coord.register_accepted(
    Peer::Replica(ReplicaId::new(1)),
    labeled_conn(0xAAAA, 0, true),
  );
  // A peer that dials with the WRONG cluster (0xBBBB) sends its hello.
  let mut wrong = Labeled::<Passthrough>::dialer(
    Passthrough::new(),
    &LabelOptions::new(0xBBBB, Peer::Replica(ReplicaId::new(1))),
  );
  let mut hello = Vec::new();
  wrong.poll_transport_transmit(&mut hello);
  coord.handle_conn_data(
    id,
    &hello,
    false,
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  assert!(
    coord.router_ref().conn(id).is_none(),
    "wrong-cluster conn must be reaped"
  );
}

// A conn the coordinator reaps internally (here: a wrong-cluster hello fails the Labeled identity
// handshake, so the record layer rejects + closes it) surfaces through poll_conn_closed exactly
// once — with the record-reject cause — so the driver can tear down the still-open socket, redial,
// and attribute the close. After the single drained entry, poll_conn_closed yields None (no
// spurious closes for the surviving healthy table).
#[test]
fn an_internally_reaped_conn_surfaces_through_poll_conn_closed() {
  let cfg = Config::try_new(0xAAAA, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord =
    StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
  // Nothing reaped yet on a fresh table.
  assert_eq!(coord.poll_conn_closed(), None, "no closed conn initially");
  let id = coord.register_accepted(
    Peer::Replica(ReplicaId::new(1)),
    labeled_conn(0xAAAA, 0, true),
  );
  // A peer that dials with the WRONG cluster (0xBBBB) sends its hello; the acceptor rejects it.
  let mut wrong = Labeled::<Passthrough>::dialer(
    Passthrough::new(),
    &LabelOptions::new(0xBBBB, Peer::Replica(ReplicaId::new(1))),
  );
  let mut hello = Vec::new();
  wrong.poll_transport_transmit(&mut hello);
  coord.handle_conn_data(
    id,
    &hello,
    false,
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  assert!(
    coord.router_ref().conn(id).is_none(),
    "the wrong-cluster conn is reaped"
  );
  assert_eq!(
    coord.poll_conn_closed(),
    Some((id, CloseCause::RecordRejected)),
    "the reaped conn's id and record-reject cause surface through poll_conn_closed"
  );
  assert_eq!(
    coord.poll_conn_closed(),
    None,
    "the closed signal is drained exactly once (no duplicate / no spurious id)"
  );
}

// A bad frame (a length-prefixed payload that fails decode_message) closes the conn at the decode
// boundary, and the reap surfaces (id, BadFrame) through poll_conn_closed — the typed cause a
// driver attributes the close to, instead of a bare id.
#[test]
fn a_bad_frame_close_yields_its_cause_through_poll_conn_closed() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  // Register and validate through the coordinator seal so the garbage frame reaches decode.
  let id = register_and_validate_member(&mut coord, &mut wal, &mut sb, &mut blocks, 1);
  assert_eq!(coord.poll_conn_closed(), None, "no closed conn initially");
  // A well-formed frame header carrying an undecodable payload: decode fails, the conn closes.
  let mut frames = Vec::new();
  crate::transport::frame::encode_frame(&[0xFF; 8], &mut frames);
  coord.handle_conn_data(
    id,
    &frames,
    false,
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  assert!(
    coord.router_ref().conn(id).is_none(),
    "the bad-frame conn is reaped"
  );
  assert_eq!(
    coord.poll_conn_closed(),
    Some((id, CloseCause::BadFrame)),
    "a bad-frame close surfaces its decode cause through poll_conn_closed"
  );
  assert_eq!(coord.poll_conn_closed(), None, "drained exactly once");
}

// After a conn closes and is reaped, a freshly-registered redial is present in the table but is
// NOT authoritative until its handshake validates (note_established is the sole writer of `peers`).
#[test]
fn a_redial_is_registered_but_not_authoritative_until_validated() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord =
    StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
  let p = Peer::Replica(ReplicaId::new(1));
  let a = coord.register_dialed(p, labeled_conn(0xABCD, 0, false));
  // Close A with a wrong-cluster inbound, which reaps it.
  let mut wrong = Labeled::<Passthrough>::dialer(
    Passthrough::new(),
    &LabelOptions::new(0x9999, Peer::Replica(ReplicaId::new(1))),
  );
  let mut hello = Vec::new();
  wrong.poll_transport_transmit(&mut hello);
  coord.handle_conn_data(
    a,
    &hello,
    false,
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  assert!(coord.router_ref().conn(a).is_none(), "A reaped");
  let b = coord.register_dialed(p, labeled_conn(0xABCD, 0, false));
  assert!(
    coord.router_ref().conn(b).is_some(),
    "the redial is in the table"
  );
  assert_eq!(
    coord.router_ref().authoritative(p),
    None,
    "a not-yet-validated redial is not authoritative"
  );
}

// A still-handshaking conn receives no app bytes (the prepare is not routed to it).
#[test]
fn route_skips_a_handshaking_conn() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord =
    StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
  // The only backup conn is an acceptor that has NOT yet validated an inbound hello -> handshaking.
  coord.register_accepted(
    Peer::Replica(ReplicaId::new(1)),
    labeled_conn(0xABCD, 0, true),
  );
  coord.register_accepted(
    Peer::Replica(ReplicaId::new(2)),
    labeled_conn(0xABCD, 0, true),
  );
  coord.inject_message_for_test(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    req(),
  );
  let mut now = Instant::ZERO;
  for _ in 0..5 {
    now = now + core::time::Duration::from_millis(50);
    coord.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    coord.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
  }
  assert!(
    coord.poll_conn_transmit().is_none(),
    "no app bytes routed to a handshaking conn"
  );
}

// A single handle_conn_data delivering a complete request AND eof, with a validated standby for
// the same peer, must finalize the peer-finished conn BEFORE pumping the response, so the response
// routes to the promoted standby in the SAME call — not black-holed on a conn that is immediately
// closed and discarded. A primary answers a GetView with a StartView addressed back to the
// requesting replica; that response is the one whose routing must survive the EOF.
#[test]
fn a_final_frame_response_routes_to_a_promoted_standby_in_the_same_call() {
  use crate::{GetView, View, transport::frame::encode_frame};
  // Replica 0 is the primary of view 0, so it answers a GetView(view 0) synchronously.
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  let peer = Peer::Replica(ReplicaId::new(1));
  // Two conns validated through the coordinator seal for the same peer (member 1 = slot 1):
  // the first becomes a live standby, the second (last-established via note_established_member)
  // is authoritative.
  let standby = register_and_validate_member(&mut coord, &mut wal, &mut sb, &mut blocks, 1);
  let authoritative = register_and_validate_member(&mut coord, &mut wal, &mut sb, &mut blocks, 1);
  assert_eq!(
    coord.router_ref().authoritative(peer),
    Some(authoritative),
    "last-established conn is authoritative; the first is a live standby"
  );
  // A complete GetView frame AND eof arrive together on the authoritative conn.
  let get_view = Message::GetView(GetView::new(
    View::with(0),
    ReplicaId::new(1),
    0x1234,
    crate::Epoch::new(0),
    0,
  ));
  let mut framed = Vec::new();
  encode_frame(&encode_message(&get_view), &mut framed);
  coord.handle_conn_data(
    authoritative,
    &framed,
    true,
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  // The peer-finished conn was reaped and the standby promoted BEFORE the StartView was routed.
  assert!(
    coord.router_ref().conn(authoritative).is_none(),
    "the peer-finished conn is finalized and reaped in the same call"
  );
  assert_eq!(
    coord.router_ref().authoritative(peer),
    Some(standby),
    "the validated standby is promoted before the response is routed"
  );
  // The StartView response is queued on the promoted standby, not black-holed on the closed conn.
  assert!(
    coord.router_ref().conn(standby).unwrap().queued_outbound() > 0,
    "the final-frame response routed to the standby in the same call"
  );
  let drained = coord.poll_conn_transmit();
  assert_eq!(
    drained.map(|(id, _)| id),
    Some(standby),
    "poll_conn_transmit drains the response from the promoted standby"
  );
}

// A settled conn whose handshake_identity is Peer::Replica(slot) is NOT auto-validated on
// register and is rejected by try_note_established_member. The coordinator requires every replica
// conn to attest a stable MemberId (via Peer::Member) so reconcile_routing can close stale bindings on
// membership changes; a raw slot claim carries no stable id and would bypass reconciliation.
// This test drives the production shape WITHOUT reset_validated_for_test: the conn is never
// auto-validated because note_established blocks Peer::Replica identities at the router level.
#[test]
fn a_settled_replica_slot_claim_is_rejected_with_identity_rejected() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  let slot = ReplicaId::new(1);
  // A settled MockRecords reporting Peer::Replica(slot). note_established blocks Peer::Replica
  // identity, so the conn is NOT auto-validated on register — no reset helper needed.
  let id = coord.register_dialed(
    Peer::Replica(slot),
    Conn::from_parts(MockRecords::new(false, Some(Peer::Replica(slot)))),
  );
  assert!(
    !coord.is_conn_validated(id),
    "a Peer::Replica conn is not auto-validated on register (the bypass is closed)"
  );
  assert!(
    coord
      .router_ref()
      .authoritative(Peer::Replica(slot))
      .is_none(),
    "a non-auto-validated conn is not authoritative"
  );
  // Drive the identity-seal: a Peer::Replica claim must be aborted.
  coord.try_note_established_for_test(id);
  assert!(
    coord
      .router_ref()
      .conn(id)
      .map(|c| c.is_closed())
      .unwrap_or(true),
    "a settled Peer::Replica claim is aborted by try_note_established_member"
  );
  assert!(
    !coord.is_conn_validated(id),
    "an aborted Peer::Replica conn is not validated (not a routing target)"
  );
}

// A settled conn whose handshake_identity is None (raw transport, no identity claim) is also
// not auto-validated and is rejected by try_note_established_member — note_established blocks
// Peer::Replica identity (which is what `(None, _) => expected` resolves to for a slot-registered
// conn), so the coordinator seal classifies it as None and aborts it.
#[test]
fn a_settled_none_identity_is_rejected_with_identity_rejected() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  let slot = ReplicaId::new(2);
  // MockRecords with identity=None registered as Peer::Replica: note_established would resolve
  // (None, _) => expected = Peer::Replica(slot), which is now blocked — so the conn is NOT
  // auto-validated on register. No reset helper needed.
  let id = coord.register_accepted(
    Peer::Replica(slot),
    Conn::from_parts(MockRecords::new(false, None)),
  );
  assert!(
    !coord.is_conn_validated(id),
    "a None-identity conn registered for a replica slot is not auto-validated (bypass closed)"
  );
  assert!(
    coord
      .router_ref()
      .authoritative(Peer::Replica(slot))
      .is_none(),
    "a non-auto-validated conn is not authoritative"
  );
  coord.try_note_established_for_test(id);
  assert!(
    coord
      .router_ref()
      .conn(id)
      .map(|c| c.is_closed())
      .unwrap_or(true),
    "a settled None-identity conn is aborted by try_note_established_member"
  );
  assert!(
    !coord.is_conn_validated(id),
    "an aborted None-identity conn is not validated (not a routing target)"
  );
}

// A settled conn whose handshake_identity is Peer::Client IS auto-validated on register (note_established
// does not block Client identities) and is never rejected by try_note_established_member: clients
// are not membership-tracked and must be preserved.
#[test]
fn a_settled_client_identity_is_preserved_and_not_rejected() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  let cid = ClientId::new(0xDEAD_BEEF);
  // A settled MockRecords that reports Peer::Client: note_established allows Client, so the conn
  // IS auto-validated on register. try_note_established_member then early-returns (already validated).
  let id = coord.register_accepted(
    Peer::Client(cid),
    Conn::from_parts(MockRecords::new(false, Some(Peer::Client(cid)))),
  );
  assert!(
    coord.is_conn_validated(id),
    "a Peer::Client conn IS auto-validated on register (clients are not blocked)"
  );
  // try_note_established_member is a no-op for already-validated conns: clients are preserved.
  coord.try_note_established_for_test(id);
  assert!(
    coord.is_conn_validated(id),
    "a Peer::Client conn is not rejected by try_note_established_member"
  );
  assert!(
    coord
      .router_ref()
      .conn(id)
      .map(|c| !c.is_closed())
      .unwrap_or(false),
    "a Peer::Client conn stays open after try_note_established_member"
  );
}

// An accepted conn attesting THIS node's own MemberId is aborted with IdentityRejected before
// slot_of is consulted. A node IS in its own active membership, so without this guard a peer
// presenting a valid cluster cert for our member_id would bind AS this node — then frames from
// it would be delivered under this node's own `from` slot, satisfying sender_matches for a
// network-supplied self-identifying message. Mirrors the guard in the QUIC coordinator.
#[test]
fn an_accepted_conn_attesting_the_local_member_id_is_aborted() {
  let local_member = MemberId::new(0); // endpoint.local() is member 0 in this config
  let cfg = Config::try_new(0xABCD, local_member).unwrap();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  // A settled acceptor whose handshake identity claims to be the LOCAL member.
  // note_established does not auto-validate Peer::Member identities (only Peer::Client and
  // Peer::Replica, and the latter is blocked), so the conn is not auto-validated on register.
  // Instead, try_note_established_member must classify and abort it.
  let id = coord.register_accepted(
    Peer::Replica(ReplicaId::new(0)),
    Conn::from_parts(MockRecords::new(false, Some(Peer::Member(local_member)))),
  );
  assert!(
    !coord.is_conn_validated(id),
    "a Peer::Member conn is not auto-validated on register (handshake identity, not a routing key)"
  );
  // Drive validation: the local-member guard must abort before slot_of is called.
  coord.try_note_established_for_test(id);
  assert!(
    coord
      .router_ref()
      .conn(id)
      .map(|c| c.is_closed())
      .unwrap_or(true),
    "a conn attesting the local MemberId is aborted (IdentityRejected)"
  );
  assert!(
    !coord.is_conn_validated(id),
    "an aborted self-attesting conn is not a routing target"
  );
  // No authoritative conn for the local slot — the abort did not install a self-routing entry.
  assert!(
    coord
      .router_ref()
      .authoritative(Peer::Replica(ReplicaId::new(0)))
      .is_none(),
    "no authoritative conn for the local slot after the self-attest abort"
  );
}

#[test]
fn coordinator_debug_is_non_exhaustive() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let coord = StreamCoordinator::<CountSm, Passthrough>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  let debug = std::format!("{coord:?}");
  assert!(
    debug.contains("StreamCoordinator"),
    "the Debug impl names the type: {debug}"
  );
}

#[test]
fn with_outbound_cap_scales_the_backlog_threshold() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let coord = StreamCoordinator::<CountSm, Passthrough>::with_outbound_cap(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    4096,
  );
  assert_eq!(
    coord.max_outbound_backlog(),
    4096 * 2,
    "with_outbound_cap sizes the coordinator's backlog threshold from the given cap, not the default"
  );
}

#[test]
fn propose_membership_delegates_to_the_endpoint() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap(); // primary of view 0, Normal
  let mut wal = TestWal::default();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  let op = coord
    .propose_membership(
      Instant::ZERO,
      &mut wal,
      crate::SingleVoterDelta::AddLearner(MemberId::new(5)),
    )
    .expect("a Normal primary with no in-flight change can propose");
  assert_eq!(
    op.get(),
    1,
    "the first proposed op follows the fresh op head (0)"
  );
}

#[test]
fn recently_acked_voters_is_empty_before_any_prepare_ack() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  assert!(
    coord.recently_acked_voters(64).is_empty(),
    "a fresh endpoint has acknowledged no in-flight prepare"
  );
}

#[test]
fn try_note_established_member_on_an_unknown_id_is_a_no_op() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  let bogus = crate::ConnId::new(u64::MAX);
  // No conn was ever registered at this id: the identity-seal must return without panicking or
  // installing any routing entry.
  coord.try_note_established_for_test(bogus);
  assert!(
    coord.router_ref().conn(bogus).is_none(),
    "an unknown ConnId stays absent from the router"
  );
}

#[test]
fn a_member_outside_the_active_membership_is_rejected_with_identity_rejected() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  // MemberId(99) is not in the genesis(3) membership {0,1,2}: slot_of must miss and the conn aborts.
  let id = coord.register_accepted(
    Peer::Replica(ReplicaId::new(9)),
    Conn::from_parts(MockRecords::new(
      false,
      Some(Peer::Member(MemberId::new(99))),
    )),
  );
  coord.try_note_established_for_test(id);
  assert!(
    coord
      .router_ref()
      .conn(id)
      .map(|c| c.is_closed())
      .unwrap_or(true),
    "a member outside the active membership is aborted (IdentityRejected)"
  );
  assert!(!coord.is_conn_validated(id));
}

#[test]
fn a_settling_client_handshake_is_validated_through_try_note_established_member() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord =
    StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
  // Registered still-handshaking (an acceptor that has not yet seen a hello): note_established is a
  // no-op at registration time, so the Client identity settles only once try_note_established_member
  // is driven by a real inbound handshake — the production path for a genuine client connection.
  let id = coord.register_accepted(
    Peer::Client(ClientId::new(0)),
    labeled_conn(0xABCD, 0, true),
  );
  assert!(
    !coord.is_conn_validated(id),
    "still handshaking at registration"
  );
  let client = ClientId::new(0xFEED);
  let mut dialer = Labeled::<Passthrough>::dialer(
    Passthrough::new(),
    &LabelOptions::new(0xABCD, Peer::Client(client)),
  );
  let mut hello = Vec::new();
  dialer.poll_transport_transmit(&mut hello);
  coord.handle_conn_data(
    id,
    &hello,
    false,
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  assert!(
    coord.is_conn_validated(id),
    "the settled Client handshake is validated via note_established (Client is never blocked)"
  );
  assert_eq!(
    coord.router_ref().authoritative(Peer::Client(client)),
    Some(id),
    "the conn is bound to the attested Client identity"
  );
}

#[test]
fn submit_client_request_drops_an_over_max_body_with_no_side_effects() {
  use crate::transport::frame::max_request_body_len;
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  let over = Request::new(
    ClientId::new(1),
    RequestNumber::with(1),
    Bytes::from(vec![0u8; max_request_body_len() + 1]),
  );
  coord.submit_client_request(Instant::ZERO, &mut wal, &mut sb, &mut blocks, over);
  assert_eq!(
    coord.endpoint().op().get(),
    0,
    "an over-max local submit appends no op (dropped before the endpoint)"
  );
  assert!(
    coord.poll_conn_transmit().is_none(),
    "an over-max local submit routes nothing to the backups"
  );
}

/// Drives a fresh 3-voter primary (local = `local`, primary of view 0) to propose
/// `RemoveVoter(removed)` and commit + durably install it — generalizes
/// `endpoint::tests::reconfigure::removed_self_primary` to any voter, not only self-removal. Two
/// validated conns for members 1 and 2 are registered BEFORE the removal, so the caller can inspect
/// how `reconcile_routing` treated each afterward. The acking voter is whichever of {0,1,2} is
/// neither `local` nor `removed`, so the 2-of-3 commit quorum always forms.
fn commit_and_install_a_voter_removal(
  local: u128,
  removed: u128,
) -> (
  StreamCoordinator<CountSm, MockRecords>,
  TestWal,
  TestSb,
  crate::block_store::MemBlockStore,
  ConnId,
  ConnId,
) {
  use crate::{SingleVoterDelta, View, message::Body};
  let cfg = Config::try_new(0xABCD, MemberId::new(local)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 0, CountSm::default()),
  );
  let conn1 = register_and_validate_member(&mut coord, &mut wal, &mut sb, &mut blocks, 1);
  let conn2 = register_and_validate_member(&mut coord, &mut wal, &mut sb, &mut blocks, 2);

  let successor = coord
    .live_membership()
    .apply_delta(&SingleVoterDelta::RemoveVoter(MemberId::new(removed)))
    .expect("removing one of three voters is valid");
  let payload = crate::ReconfigurePayload::from_membership(&successor, 0);
  let op = coord
    .propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::RemoveVoter(MemberId::new(removed)),
    )
    .expect("the primary mints the removal Reconfigure op");
  coord.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // own append durable -> own vote
  let acker = (0..3u128)
    .find(|&m| m != local && m != removed)
    .expect("a third voter exists to ack");
  coord.inject_message_for_test(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(acker as u16)),
    Message::PrepareOk(crate::PrepareOk::new(
      View::new(),
      op,
      ReplicaId::new(acker as u16),
      OpNumber::new(),
      crate::storage::prepare_identity(
        ClientId::RECONFIGURATION,
        RequestNumber::with(op.get()),
        Body::Reconfigure(payload.clone()).body_checksum(),
      ),
      crate::Epoch::new(0),
      0,
    )),
  );
  // The 2-of-3 commit quorum stages the SwapEpoch root; a further handle_storage lands that durable
  // root, which installs the successor (config_id changes) and triggers reconcile_routing/pump.
  coord.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks);
  (coord, wal, sb, blocks, conn1, conn2)
}

#[test]
fn a_removed_local_member_routes_nothing_gracefully() {
  // The local member (0, primary of view 0) proposes and commits its OWN removal, all the way to a
  // durable, installed swap. Once installed, local_slot_opt() is None: pump() (driven by the trailing
  // pump inside handle_storage's own install) and submit_client_request() must each route nothing
  // rather than panic on an absent local slot.
  let (mut coord, mut wal, mut sb, mut blocks, _conn1, _conn2) =
    commit_and_install_a_voter_removal(0, 0);
  assert!(
    coord.endpoint().local_slot_opt().is_none(),
    "the removed local member has no slot in the installed successor"
  );
  coord.submit_client_request(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Request::new(
      ClientId::new(1),
      RequestNumber::with(1),
      Bytes::from_static(b"x"),
    ),
  );
  assert!(
    coord.poll_conn_transmit().is_none(),
    "a removed local member routes nothing (graceful no-op, not a panic)"
  );
}

#[test]
fn reconcile_routing_closes_a_removed_member_and_leaves_an_unshifted_survivor_bound() {
  // Removing member 2 (the HIGHEST-slot voter) leaves the retained voters at their OLD slots {0,1}.
  // reconcile_routing (driven automatically inside handle_storage, right after the installing pump)
  // must therefore close member 2's conn (slot_of(2) is now None) while leaving member 1's conn
  // untouched (still slot 1, so no churn for the unmoved retained member).
  let (coord, _wal, _sb, _blocks, conn1, conn2) = commit_and_install_a_voter_removal(0, 2);
  assert_eq!(
    coord.membership_config_id(),
    coord.live_membership().config_id(),
    "the installed config_id matches the live membership snapshot"
  );
  assert!(
    coord
      .router_ref()
      .conn(conn1)
      .map(|c| !c.is_closed())
      .unwrap_or(false),
    "member 1 keeps its slot across the removal of the higher-slot member 2, so reconcile leaves it bound"
  );
  assert!(
    coord.router_ref().conn(conn2).is_none(),
    "member 2's conn is closed and reaped: reconcile_routing sees slot_of(2) == None post-removal"
  );
}

#[test]
fn poll_timeout_reports_a_scheduled_deadline_for_a_fresh_primary() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  // A brand-new endpoint has no timer armed yet; the first handle_timeout bootstraps the Normal
  // primary's cadence (its own commit-heartbeat / prepare-retransmit deadline).
  coord.handle_timeout(Instant::ZERO, &mut wal, &mut sb, &mut blocks);
  assert!(
    coord.poll_timeout().is_some(),
    "a bootstrapped Normal primary has a scheduled timer deadline (poll_timeout delegates to the endpoint)"
  );
}

#[test]
fn poll_event_is_empty_on_a_fresh_coordinator() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  assert!(
    coord.poll_event().is_none(),
    "a fresh endpoint has no queued application event yet"
  );
}

#[test]
fn membership_config_id_and_live_membership_reflect_the_active_config() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  let live = coord.live_membership();
  assert_eq!(
    coord.membership_config_id(),
    live.config_id(),
    "membership_config_id is a cheap read of the same config_id live_membership's clone carries"
  );
  assert_eq!(
    live.replica_count(),
    3,
    "the genesis(3) membership has 3 voters"
  );
}

#[test]
fn oversized_outbound_dropped_starts_at_zero_and_delegates_to_the_router() {
  let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
  let coord = StreamCoordinator::<CountSm, MockRecords>::new(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
  );
  assert_eq!(
    coord.oversized_outbound_dropped(),
    0,
    "oversized_outbound_dropped reads the router's counter, which starts at zero"
  );
}

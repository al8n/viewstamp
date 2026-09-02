//! End-to-end QUIC loopback: two `QuicCoordinator`s over an in-memory UDP pipe reach consensus over
//! REAL cluster-private mutual TLS.
//!
//! The functional proof that the [`QuicCoordinator`] drives the consensus `Endpoint` to convergence
//! over real quinn-proto handshakes and per-peer streams — the QUIC counterpart of
//! [`transport::loopback`](super::super::loopback), which does the same over the byte-stream
//! transport. Two replicas mutually dial, complete a MANDATORY mTLS handshake against a shared
//! cluster CA (every cert carries the SNI SAN the dialer validates), bind each other's identity, carry
//! the consensus message stream over the per-peer bidi streams, and apply one client request on BOTH
//! replicas. The convergence test is parameterized over the identity [`Scheme`] — `Hello` (control-stream
//! preface) and `CertOid` (CA-attested certificate extension) — AND the [`StreamLayout`] (`Single` and
//! `ControlBulk`): all four combinations converge over the same mTLS link. A separate test commits a
//! large (over-64-KiB) op whose `Prepare` routes to the Bulk class, proving the per-class routing
//! delivers end-to-end (routing + delivery, NOT head-of-line isolation under pressure — that is the
//! seeded `datagram_sim`'s job).
//!
//! A negative companion proves the separation guarantee is load-bearing: a replica whose cert chains
//! to a DIFFERENT CA fails chain validation at the TLS layer, so its connection never reaches
//! `Validated` and the cluster never adopts it.
//!
//! **Continuous monotonic clock.** `max_idle_timeout` is 1 s, so the loop advances `now` in small
//! 5 ms steps and threads ONE monotonic instant through every `handle_*` call: a >1 s gap between
//! two calls on a coordinator would silently trip the QUIC idle timeout and close the connections.

use core::time::Duration;

use bytes::Bytes;

use crate::{
  ClientId, Commit, Config, Endpoint, Event, Instant, MemberId, Message, OpNumber, Peer, ReplicaId,
  RequestNumber, SingleChange, View, encode_message,
  message::Request,
  transport::{
    frame::{LEN_PREFIX, STAGE_CHUNK, encode_frame},
    quic::{
      IdentityConfig, ProvidedIdentity, QuicCoordinator, QuicOptions, StreamLayout,
      crypto::{ClusterTls, TestClusterCa, test_ca},
      testutil::{PacketPipe, addr},
    },
    testutil::{CountSm, TestSb, TestWal, genesis},
  },
};

const CLUSTER: u128 = 0x5151;

/// One coordinator plus its in-memory storage doubles (WAL, superblock, block store).
pub(super) type Replica = (
  QuicCoordinator<CountSm, ProvidedIdentity>,
  crate::storage::Storage<TestWal, TestSb, CountSm>,
  crate::block_store::InMemoryBlockStore,
);

/// The identity scheme a cluster-private mTLS link establishes its peer with, on top of the shared
/// chain-only TLS membership check. Both converge; they differ only in WHERE the authenticated
/// replica index comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scheme {
  /// The peer announces its index in the [`Hello`](super::Hello) control-stream preface (self-asserted
  /// on top of the CA-proven cluster membership).
  Hello,
  /// The peer's index is the CA-attested [`CertOid`](super::CertOid) certificate extension.
  CertOid,
}

/// Build replica `id` of a 2-replica cluster over cluster-private mTLS: its cert is issued by the
/// SHARED `ca` (so the two replicas validate each other's chains), carries the SNI SAN
/// `replica-<id>.<cluster-hex>.viewstamp` the dialer's stock `WebPkiServerVerifier` matches, and — for
/// the [`Scheme::CertOid`] case — the CA-attested identity OID extension. The matching
/// [`IdentityConfig`] selects how the authenticated peer is established on top of the mTLS link.
/// `layout` selects the QUIC stream layout (threaded into the per-replica [`ClusterTls`] builder).
pub(super) fn replica(
  ca: &TestClusterCa,
  id: u16,
  rng_seed: [u8; 32],
  scheme: Scheme,
  layout: StreamLayout,
) -> Replica {
  let cfg = Config::try_new(CLUSTER, MemberId::new(id as u128)).unwrap();
  let endpoint = Endpoint::<_, SingleChange>::genesis_unchecked(
    cfg,
    genesis(2),
    u64::from(id) + 1,
    CountSm::default(),
    u64::MAX,
  );

  let (cert, identity) = match scheme {
    Scheme::Hello => (
      ca.issue_replica(id, CLUSTER),
      IdentityConfig::Hello(CLUSTER),
    ),
    Scheme::CertOid => (
      ca.issue_replica_with_oid(id, CLUSTER),
      IdentityConfig::CertOid(CLUSTER),
    ),
  };
  let opts = ClusterTls::new(ca.roots(), cert.chain(), cert.key())
    .with_layout(layout)
    .build();

  let coord = QuicCoordinator::with_identity(endpoint, opts, Some(rng_seed), identity);
  (
    coord,
    crate::storage::Storage::new(TestWal::default(), TestSb::default()),
    crate::block_store::InMemoryBlockStore::new(),
  )
}

/// The `(op, body)` a single applied client request leaves in the state machine.
pub(super) fn applied_one(body: &[u8]) -> Vec<(u64, Vec<u8>)> {
  std::vec![(1u64, body.to_vec())]
}

/// Drive two coordinators over the in-memory pipe for a bounded budget, ferrying every outbound
/// datagram to whichever coordinator owns the destination address under ONE continuous monotonic
/// clock (5 ms steps). Each iteration advances the clock, fires storage + timeout on both sides, then
/// routes datagrams: a datagram a coordinator emits is FROM its own address TO `dst`; it is delivered
/// to the coordinator that owns `dst`, tagged with the emitter's address as `remote`. Returns `true`
/// once BOTH state machines have applied exactly one op (and short-circuits then).
///
/// The mutual mTLS handshake (real cert exchange + chain/SNI verification) is heavier than the
/// accept-any path, so the budget is generous.
fn run_until_converged(
  r0: &mut Replica,
  addr0: std::net::SocketAddr,
  r1: &mut Replica,
  addr1: std::net::SocketAddr,
) -> bool {
  let (r0, storage0, blocks0) = r0;
  let (r1, storage1, blocks1) = r1;
  let mut now = Instant::ZERO;
  let mut to_r0 = PacketPipe::default();
  let mut to_r1 = PacketPipe::default();
  for _ in 0..12_000 {
    now = now + Duration::from_millis(5);
    r0.handle_storage(now, storage0, blocks0);
    r1.handle_storage(now, storage1, blocks1);
    r0.handle_timeout(now, storage0);
    r1.handle_timeout(now, storage1);

    // Collect every outbound datagram from both sides, routing by destination: r0's traffic to r1
    // is queued toward r1 (from addr0), and vice versa. A self-addressed datagram cannot arise (a
    // replica never dials its own address), so anything not bound for the peer is dropped.
    while let Some((dst, bytes)) = r0.poll_transmit() {
      if dst == addr1 {
        to_r1.push(addr0, bytes);
      }
    }
    while let Some((dst, bytes)) = r1.poll_transmit() {
      if dst == addr0 {
        to_r0.push(addr1, bytes);
      }
    }

    // Deliver everything queued this tick to the OTHER coordinator under the same `now`.
    while let Some((from, bytes)) = to_r1.pop() {
      r1.handle_udp(now, from, None, &bytes, storage1);
    }
    while let Some((from, bytes)) = to_r0.pop() {
      r0.handle_udp(now, from, None, &bytes, storage0);
    }

    if r0.endpoint().state_machine_ref().applied().len() == 1
      && r1.endpoint().state_machine_ref().applied().len() == 1
    {
      return true;
    }
  }
  false
}

/// Like [`run_until_converged`] but returns the viewstamp [`Instant`] convergence happened at (or
/// `None` if the budget ran out), so a later stage of the same test can thread the SAME monotonic
/// clock forward without a >1 s idle-timeout gap closing the connections.
fn converged_at(
  r0: &mut Replica,
  addr0: std::net::SocketAddr,
  r1: &mut Replica,
  addr1: std::net::SocketAddr,
) -> Option<Instant> {
  let (r0, storage0, blocks0) = r0;
  let (r1, storage1, blocks1) = r1;
  let mut now = Instant::ZERO;
  let mut to_r0 = PacketPipe::default();
  let mut to_r1 = PacketPipe::default();
  for _ in 0..12_000 {
    now = now + Duration::from_millis(5);
    r0.handle_storage(now, storage0, blocks0);
    r1.handle_storage(now, storage1, blocks1);
    r0.handle_timeout(now, storage0);
    r1.handle_timeout(now, storage1);
    while let Some((dst, bytes)) = r0.poll_transmit() {
      if dst == addr1 {
        to_r1.push(addr0, bytes);
      }
    }
    while let Some((dst, bytes)) = r1.poll_transmit() {
      if dst == addr0 {
        to_r0.push(addr1, bytes);
      }
    }
    while let Some((from, bytes)) = to_r1.pop() {
      r1.handle_udp(now, from, None, &bytes, storage1);
    }
    while let Some((from, bytes)) = to_r0.pop() {
      r0.handle_udp(now, from, None, &bytes, storage0);
    }
    if r0.endpoint().state_machine_ref().applied().len() == 1
      && r1.endpoint().state_machine_ref().applied().len() == 1
    {
      return Some(now);
    }
  }
  None
}

/// Mutually dial r0↔r1 with their EXPECTED peers and seed the primary (replica 0) with one client
/// request carrying `body`. Replica 0 is the primary for view 0 (`view % replica_count == 0`), so the
/// request is seeded there. The Prepare is staged immediately; the consensus layer retransmits it
/// until the per-peer send stream is up (staged sends flush on `Validated`), so seeding before the
/// ferry loop needs no handshake-complete barrier.
///
/// `body` controls the Prepare size: a small body rides the Control class, a body over
/// `PREPARE_BULK_THRESHOLD` (64 KiB) rides the Bulk class under `ControlBulk` — the partition the
/// large-op test below relies on.
pub(super) fn dial_and_seed(
  r0: &mut Replica,
  addr0: std::net::SocketAddr,
  r1: &mut Replica,
  addr1: std::net::SocketAddr,
  body: Bytes,
) {
  // Mutual dial: each side opens its own connection to the other, recording the dialed expectation
  // so the binding policy's match-or-abort uses the right peer. Each side opens its own send
  // stream(s) and accepts the peer's, so the mutual-dial doubling is handled per layout. A fresh
  // coordinator is well under the default connection cap, so each dial is admitted.
  r0.0
    .connect(Instant::ZERO, addr1, Peer::Replica(ReplicaId::new(1)))
    .expect("a fresh coordinator dials under the connection cap");
  r1.0
    .connect(Instant::ZERO, addr0, Peer::Replica(ReplicaId::new(0)))
    .expect("a fresh coordinator dials under the connection cap");

  let (coord0, storage0, _blocks0) = r0;
  coord0.inject_message_for_test(
    Instant::ZERO,
    storage0,
    Peer::Client(ClientId::new(1)),
    Message::Request(Request::new(ClientId::new(1), RequestNumber::with(1), body)),
  );
}

/// Two replicas mutually dial over cluster-private mTLS and commit one small client request on both
/// sides, establishing identity via `scheme` over the given stream `layout`. Returns whether both
/// applied exactly the one seeded op. A small body rides the Control class under either layout, so
/// this is the pure convergence proof; the Bulk-routing proof is `large_op_commits_over_bulk` below.
fn converges_with(scheme: Scheme, layout: StreamLayout) -> bool {
  let ca = test_ca();
  let addr0 = addr(1);
  let addr1 = addr(2);
  let mut r0 = replica(&ca, 0, [0u8; 32], scheme, layout);
  let mut r1 = replica(&ca, 1, [1u8; 32], scheme, layout);

  dial_and_seed(&mut r0, addr0, &mut r1, addr1, Bytes::from_static(b"x"));
  let converged = run_until_converged(&mut r0, addr0, &mut r1, addr1);

  if converged {
    assert_eq!(
      r0.0.endpoint().state_machine_ref().applied(),
      applied_one(b"x").as_slice(),
      "primary applied op 1 over QUIC mTLS"
    );
    assert_eq!(
      r1.0.endpoint().state_machine_ref().applied(),
      applied_one(b"x").as_slice(),
      "backup converged over the QUIC mTLS transport"
    );
  }
  converged
}

/// A replica whose cert chains to a DIFFERENT CA than the one the cluster trusts CANNOT complete the
/// mTLS handshake (chain validation fails), so its connection never reaches `Validated` and no
/// consensus message is ever accepted from it. Returns whether the cluster converged (it must NOT):
/// the foreign replica is rejected at the TLS layer, the primary's lone Prepare is never acked, and
/// neither side commits within the budget.
fn converges_with_foreign_ca() -> bool {
  // Two DISTINCT cluster CAs. r0 trusts (and is issued by) CA-A; r1 is issued by CA-B but still only
  // trusts CA-A. So r0 rejects r1's CA-B cert in BOTH directions — as a server verifying r1's client
  // cert, and as a client verifying r1's server cert — and that alone fails every handshake between
  // them, exactly as a foreign node joining the cluster would be turned away. (r1 trusts CA-A and
  // would accept r0's cert, but r0's rejection is sufficient.)
  let ca_a = test_ca();
  let ca_b = test_ca();
  let addr0 = addr(1);
  let addr1 = addr(2);

  // r0: cert from CA-A, trusts CA-A.
  let cfg0 = Config::try_new(CLUSTER, MemberId::new(0)).unwrap();
  let cert0 = ca_a.issue_replica(0, CLUSTER);
  let opts0 = ClusterTls::new(ca_a.roots(), cert0.chain(), cert0.key()).build();
  let mut r0: Replica = (
    QuicCoordinator::with_identity(
      Endpoint::<_, SingleChange>::genesis_unchecked(
        cfg0,
        genesis(2),
        1,
        CountSm::default(),
        u64::MAX,
      ),
      opts0,
      Some([0u8; 32]),
      IdentityConfig::Hello(CLUSTER),
    ),
    crate::storage::Storage::new(TestWal::default(), TestSb::default()),
    crate::block_store::InMemoryBlockStore::new(),
  );

  // r1 (the foreign replica): cert from CA-B, but trusts only CA-A.
  let cfg1 = Config::try_new(CLUSTER, MemberId::new(1)).unwrap();
  let cert1 = ca_b.issue_replica(1, CLUSTER);
  let opts1 = ClusterTls::new(ca_a.roots(), cert1.chain(), cert1.key()).build();
  let mut r1: Replica = (
    QuicCoordinator::with_identity(
      Endpoint::<_, SingleChange>::genesis_unchecked(
        cfg1,
        genesis(2),
        2,
        CountSm::default(),
        u64::MAX,
      ),
      opts1,
      Some([1u8; 32]),
      IdentityConfig::Hello(CLUSTER),
    ),
    crate::storage::Storage::new(TestWal::default(), TestSb::default()),
    crate::block_store::InMemoryBlockStore::new(),
  );

  dial_and_seed(&mut r0, addr0, &mut r1, addr1, Bytes::from_static(b"x"));
  run_until_converged(&mut r0, addr0, &mut r1, addr1)
}

/// Both stream layouts × both identity schemes converge: a 2-replica cluster commits one small client
/// request on both sides over cluster-private mTLS under `Single` AND `ControlBulk`, with identity
/// established by either the `Hello` control-stream preface or the CA-attested `CertOid` extension.
///
/// This is the both-layouts validation: it proves the coordinator's per-class routing (the
/// `partition` send-path selector plus the Control/Bulk inbound drain) carries consensus to
/// convergence under either layout. The small request rides the Control class in both layouts;
/// `large_op_commits_over_bulk` separately exercises the Bulk-routing path.
#[test]
fn converges_under_both_layouts() {
  for layout in [StreamLayout::Single, StreamLayout::ControlBulk] {
    assert!(
      converges_with(Scheme::CertOid, layout),
      "the CertOid-over-mTLS cluster did not converge under {layout:?}"
    );
    assert!(
      converges_with(Scheme::Hello, layout),
      "the Hello-over-mTLS cluster did not converge under {layout:?}"
    );
  }
}

/// Partition-correctness end-to-end: under `ControlBulk`, a >64 KiB client op commits on both
/// replicas. Its `Prepare` body exceeds [`PREPARE_BULK_THRESHOLD`](super::layout::PREPARE_BULK_THRESHOLD)
/// (64 KiB), so `partition` routes that `Prepare` to the **Bulk** class — the backup can only apply
/// the op if the Bulk-routed `Prepare` was opened, delivered on the Bulk stream, adopted on the peer's
/// Bulk recv (StreamId index 1), and drained by the coordinator's Bulk-class read. The state machine
/// records the FULL body, so convergence on the exact >64 KiB bytes proves Bulk routing + delivery
/// end-to-end (small control traffic — votes, commits — flows on Control concurrently, so BOTH classes
/// carry data).
///
/// Scope: the instant loopback has NO flow-control pressure, so this proves Bulk ROUTING and delivery,
/// NOT head-of-line isolation under congestion — that is the seeded `datagram_sim`'s job.
#[test]
fn large_op_commits_over_bulk() {
  // A body strictly larger than the bulk threshold so its Prepare routes to the Bulk class.
  let big = vec![0xABu8; super::layout::PREPARE_BULK_THRESHOLD + 1];

  let ca = test_ca();
  let addr0 = addr(1);
  let addr1 = addr(2);
  let mut r0 = replica(
    &ca,
    0,
    [0u8; 32],
    Scheme::CertOid,
    StreamLayout::ControlBulk,
  );
  let mut r1 = replica(
    &ca,
    1,
    [1u8; 32],
    Scheme::CertOid,
    StreamLayout::ControlBulk,
  );

  dial_and_seed(&mut r0, addr0, &mut r1, addr1, Bytes::from(big.clone()));
  let converged = run_until_converged(&mut r0, addr0, &mut r1, addr1);
  assert!(
    converged,
    "the >64 KiB op (Prepare routed to Bulk) did not commit on both replicas under ControlBulk"
  );
  assert_eq!(
    r0.0.endpoint().state_machine_ref().applied(),
    applied_one(&big).as_slice(),
    "primary applied the full >64 KiB op"
  );
  assert_eq!(
    r1.0.endpoint().state_machine_ref().applied(),
    applied_one(&big).as_slice(),
    "backup converged on the full >64 KiB op — only possible if the Bulk-routed Prepare was delivered"
  );
}

/// An outbound message whose encoded frame would exceed `MAX_FRAME_LEN` is dropped by the send path
/// and surfaced through the PUBLIC [`QuicCoordinator::oversized_outbound_dropped`](super::QuicCoordinator::oversized_outbound_dropped)
/// counter — the operator/driver-visible signal a real QUIC driver needs (the bridge's underlying
/// counter is `pub(crate)`, so without the coordinator forwarder a driver could not observe that a
/// state-transfer / view-change carrier is being permanently refused; retransmission just re-drops it).
///
/// Two coordinators converge over real mTLS so a peer is bound (the steady-state send path is live),
/// then ONE over-`MAX_FRAME_LEN` `SyncCheckpoint` is routed to that bound peer through the PRODUCTION
/// path (`route` → `write_to_peer` → `Bridge::write_framed`). The frame is dropped before encoding and
/// the count, read through the PUBLIC accessor, goes 0 → 1; a normal-sized message afterwards does not
/// bump it.
///
/// NEUTER CHECK: remove `QuicCoordinator::oversized_outbound_dropped` (or stop forwarding the bridge's
/// counter) and this test cannot compile / observe the drop — exactly the missing driver-visible signal
/// the forwarder restores.
#[test]
fn an_oversized_outbound_message_is_surfaced_through_the_public_coordinator_counter() {
  use crate::{Recipient, SyncCheckpoint, transport::frame::MAX_FRAME_LEN};

  let ca = test_ca();
  let addr0 = addr(1);
  let addr1 = addr(2);
  let mut r0 = replica(
    &ca,
    0,
    [0u8; 32],
    Scheme::CertOid,
    StreamLayout::ControlBulk,
  );
  let mut r1 = replica(
    &ca,
    1,
    [1u8; 32],
    Scheme::CertOid,
    StreamLayout::ControlBulk,
  );

  // Bring the link up (small op) so r0 holds a BOUND connection to Replica(1): the routed message
  // below then reaches the real `write_framed` send path rather than being dropped for want of a peer.
  dial_and_seed(&mut r0, addr0, &mut r1, addr1, Bytes::from_static(b"x"));
  let now = converged_at(&mut r0, addr0, &mut r1, addr1)
    .expect("the two coordinators must converge so a peer is bound before the oversized route");
  assert!(
    r0.0
      .bound_replica_peers_for_test()
      .contains(&Peer::Replica(ReplicaId::new(1))),
    "Replica(1) must be bound on r0 so the oversized message routes through the live send path"
  );
  assert_eq!(
    r0.0.oversized_outbound_dropped(),
    0,
    "no oversized drop recorded before the over-cap route"
  );

  // A `SyncCheckpoint` whose snapshot alone is `MAX_FRAME_LEN` bytes — the surrounding header pushes the
  // encoded length strictly over the cap. ONE such message is allocated; the over-cap property is checked
  // via the cheap `encoded_len()` so no second 16 MiB copy is paid.
  let snapshot = Bytes::from(vec![0u8; MAX_FRAME_LEN as usize]);
  let huge = Message::SyncCheckpoint(SyncCheckpoint::new(
    View::with(1),
    OpNumber::with(1),
    0,
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    0,
    snapshot,
    Bytes::new(),
  ));
  assert!(
    huge.encoded_len() > MAX_FRAME_LEN as usize,
    "the crafted message's encoded length exceeds the frame cap (checked without encoding)"
  );

  // Route it to the bound peer through the PRODUCTION send path; the size preflight drops it.
  r0.0
    .route_message_for_test(now, Recipient::To(Peer::Replica(ReplicaId::new(1))), &huge);
  assert_eq!(
    r0.0.oversized_outbound_dropped(),
    1,
    "an oversized outbound message is surfaced through the PUBLIC coordinator counter"
  );

  // A normal-sized message on the same bound peer still routes and does NOT bump the counter.
  r0.0.route_message_for_test(
    now,
    Recipient::To(Peer::Replica(ReplicaId::new(1))),
    &Message::Commit(Commit::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    r0.0.oversized_outbound_dropped(),
    1,
    "a normal-sized message does not increment the public oversized counter"
  );
}

/// A replica whose certificate chains to a foreign CA is rejected at the mTLS handshake, so the
/// cluster never adopts it and never converges.
#[test]
fn a_foreign_ca_replica_is_rejected_and_the_cluster_does_not_adopt_it() {
  assert!(
    !converges_with_foreign_ca(),
    "a foreign-CA replica must be rejected at the TLS layer; the cluster must NOT converge"
  );
}

/// A custom [`IdentitySource`](super::IdentitySource) that authenticates the peer's REPLICA index
/// correctly (parsing the real hello frame) but ALWAYS reports the WRONG cluster — modelling a
/// misconfigured or hostile source whose own cluster self-check passed against a foreign value. The
/// coordinator's un-bypassable cross-check must reject it: the attested cluster does not equal the
/// endpoint's `Config.cluster`, so no peer binds and the cluster cannot converge.
struct WrongClusterSource {
  /// The cluster the source advertises in its own preface (the real cluster, so the QUIC link forms).
  write_cluster: u128,
  /// The cluster the source FALSELY attests in `authenticate` (a foreign value the coordinator
  /// must reject).
  attested_cluster: u128,
}

impl super::IdentitySource for WrongClusterSource {
  fn write_control_preface(&self, me: super::AttestedId, out: &mut Vec<u8>) {
    let id = match me {
      super::AttestedId::Replica(m) => crate::transport::labeled::HelloId::Replica(m.get()),
      super::AttestedId::Client(c) => crate::transport::labeled::HelloId::Client(c),
    };
    crate::transport::labeled::encode_hello(self.write_cluster, id, out);
  }

  fn authenticate(&self, ctx: &super::IdentityCtx<'_>) -> super::IdentityOutcome {
    use super::{AttestedId, Identified, IdentityOutcome};
    use crate::transport::labeled::{HelloId, HelloOutcome, classify_hello};
    // No control frame yet (the `Connected` cert-only probe): wait for the peer's first frame.
    let Some(frame) = ctx.control_frame() else {
      return IdentityOutcome::Pending;
    };
    // Parse the genuine peer member id from the hello, but REPORT the wrong cluster. The coordinator's
    // cross-check is the only thing standing between this and a wrong-cluster bind.
    match classify_hello(frame, self.write_cluster) {
      HelloOutcome::Accepted(claimed, _) => {
        let id = match claimed {
          HelloId::Replica(m) => AttestedId::Replica(crate::MemberId::new(m)),
          HelloId::Client(c) => AttestedId::Client(c),
        };
        IdentityOutcome::Identified(Identified::new(id, self.attested_cluster))
      }
      HelloOutcome::Incomplete | HelloOutcome::Rejected => IdentityOutcome::Rejected,
    }
  }
}

/// The coordinator's cluster cross-check is un-bypassable: a custom `IdentitySource` that attests a
/// peer for the WRONG cluster (while the QUIC/mTLS handshake itself completes fine) never binds the
/// peer, so the cluster does not converge.
///
/// This is the structural complement to `a_foreign_ca_replica_is_rejected...`: there the TLS layer
/// turns the peer away; here the handshake succeeds and the COORDINATOR's binding policy is the
/// guard. It proves the cross-check lives in `apply_outcome` (against `Config.cluster`), not solely
/// inside the source's self-check — so a source that lies about the cluster cannot smuggle a peer in.
#[test]
fn a_custom_source_attesting_the_wrong_cluster_is_rejected_by_the_coordinator() {
  let addr0 = addr(1);
  let addr1 = addr(2);

  // Two coordinators over accept-any TLS (so the QUIC handshake completes regardless of identity),
  // each with a custom source that writes the REAL cluster in its preface but attests a FOREIGN
  // cluster in `authenticate`. The coordinator must reject the wrong-cluster candidate.
  let build = |id: u16,
               seed: [u8; 32]|
   -> (
    QuicCoordinator<CountSm, WrongClusterSource>,
    crate::storage::Storage<TestWal, TestSb, CountSm>,
    crate::block_store::InMemoryBlockStore,
  ) {
    let cfg = Config::try_new(CLUSTER, MemberId::new(id as u128)).unwrap();
    let endpoint = Endpoint::<_, SingleChange>::genesis_unchecked(
      cfg,
      genesis(2),
      u64::from(id) + 1,
      CountSm::default(),
      u64::MAX,
    );
    let opts = QuicOptions::accept_any_for_test();
    let src = WrongClusterSource {
      write_cluster: CLUSTER,
      attested_cluster: CLUSTER ^ 0xFFFF, // a foreign cluster the cross-check must reject
    };
    let coord = QuicCoordinator::dangerous_custom_identity(endpoint, opts, Some(seed), src);
    (
      coord,
      crate::storage::Storage::new(TestWal::default(), TestSb::default()),
      crate::block_store::InMemoryBlockStore::new(),
    )
  };
  let mut r0 = build(0, [0u8; 32]);
  let mut r1 = build(1, [1u8; 32]);

  // Mutual dial + seed the primary, then drive the same ferry the convergence harness uses. The
  // generic loop below mirrors `run_until_converged` but is monomorphised for this source type.
  r0.0
    .connect(Instant::ZERO, addr1, Peer::Replica(ReplicaId::new(1)))
    .expect("a fresh coordinator dials under the connection cap");
  r1.0
    .connect(Instant::ZERO, addr0, Peer::Replica(ReplicaId::new(0)))
    .expect("a fresh coordinator dials under the connection cap");
  {
    let (coord0, storage0, _blocks0) = &mut r0;
    coord0.inject_message_for_test(
      Instant::ZERO,
      storage0,
      Peer::Client(ClientId::new(1)),
      Message::Request(Request::new(
        ClientId::new(1),
        RequestNumber::with(1),
        Bytes::from_static(b"x"),
      )),
    );
  }

  let mut now = Instant::ZERO;
  let mut to_r0 = PacketPipe::default();
  let mut to_r1 = PacketPipe::default();
  let mut converged = false;
  for _ in 0..4_000 {
    now = now + Duration::from_millis(5);
    r0.0.handle_storage(now, &mut r0.1, &mut r0.2);
    r1.0.handle_storage(now, &mut r1.1, &mut r1.2);
    r0.0.handle_timeout(now, &mut r0.1);
    r1.0.handle_timeout(now, &mut r1.1);
    while let Some((dst, bytes)) = r0.0.poll_transmit() {
      if dst == addr1 {
        to_r1.push(addr0, bytes);
      }
    }
    while let Some((dst, bytes)) = r1.0.poll_transmit() {
      if dst == addr0 {
        to_r0.push(addr1, bytes);
      }
    }
    while let Some((from, bytes)) = to_r1.pop() {
      r1.0.handle_udp(now, from, None, &bytes, &mut r1.1);
    }
    while let Some((from, bytes)) = to_r0.pop() {
      r0.0.handle_udp(now, from, None, &bytes, &mut r0.1);
    }
    if r0.0.endpoint().state_machine_ref().applied().len() == 1
      && r1.0.endpoint().state_machine_ref().applied().len() == 1
    {
      converged = true;
      break;
    }
  }

  assert!(
    !converged,
    "a custom source attesting the wrong cluster must be rejected by the coordinator's cross-check; \
     the cluster must NOT converge"
  );
  assert!(
    r1.0.endpoint().state_machine_ref().applied().is_empty(),
    "the backup must never apply an op: no peer was bound because the attested cluster was rejected"
  );
}

/// Build replica `id` of a `count`-replica cluster (explicit `replica_count`, otherwise as
/// [`replica`]). Lets a test mint a node whose genuine, in-config index (`id < count`) is OUTSIDE a
/// SMALLER peer's configured membership — modelling a node from a since-shrunk cluster, or one issued
/// a cert for a replica index the receiving node no longer recognises.
fn replica_in_cluster_of(
  ca: &TestClusterCa,
  id: u16,
  count: u8,
  rng_seed: [u8; 32],
  scheme: Scheme,
  layout: StreamLayout,
) -> Replica {
  let cfg = Config::try_new(CLUSTER, MemberId::new(id as u128)).unwrap();
  let endpoint = Endpoint::<_, SingleChange>::genesis_unchecked(
    cfg,
    genesis(count),
    u64::from(id) + 1,
    CountSm::default(),
    u64::MAX,
  );
  let (cert, identity) = match scheme {
    Scheme::Hello => (
      ca.issue_replica(id, CLUSTER),
      IdentityConfig::Hello(CLUSTER),
    ),
    Scheme::CertOid => (
      ca.issue_replica_with_oid(id, CLUSTER),
      IdentityConfig::CertOid(CLUSTER),
    ),
  };
  let opts = ClusterTls::new(ca.roots(), cert.chain(), cert.key())
    .with_layout(layout)
    .build();
  let coord = QuicCoordinator::with_identity(endpoint, opts, Some(rng_seed), identity);
  (
    coord,
    crate::storage::Storage::new(TestWal::default(), TestSb::default()),
    crate::block_store::InMemoryBlockStore::new(),
  )
}

/// How the small node settled an accepted peer's attested identity.
#[derive(Debug, PartialEq, Eq)]
enum PeerOutcome {
  /// Resolved to a slot in the active membership and bound into the replica fanout.
  BoundReplica,
  /// Authenticated but not resolvable to a slot: bound under the never-routable `Peer::Member`
  /// quarantine key on the no-authority learn lane (kept, but out of the replica fanout).
  Quarantined,
  /// Refused before `bind_validated` — no slot pinned, no learn lane (a self-claim or a stale dial).
  Rejected,
}

/// Drive a `small`-replica node (`Replica(0)` of a `SMALL`-replica cluster) being dialed by a peer
/// whose genuine, validly-attested replica index is `peer_id`, over real cluster-private mTLS for
/// `scheme`. Both share the cluster CA and id, so the mTLS handshake completes and the binding policy
/// runs; the small node ADOPTS the peer's attested index (it did not dial the peer, so the accept path
/// takes the adopt branch). Returns how the small node settled the peer — bound as a replica,
/// quarantined on the learn lane, or rejected.
///
/// `peer_id < SMALL` is a member id in the small node's active membership (`genesis(SMALL)`) and MUST
/// bind (resolved to its slot); `peer_id >= SMALL` is NOT a member and, as an ACCEPTED inbound, MUST be
/// QUARANTINED (bound `Peer::Member`, on the learn lane, never in the replica fanout) rather than
/// consuming a replica slot.
fn small_node_admits_peer(scheme: Scheme, peer_id: u8) -> PeerOutcome {
  const SMALL: u8 = 3;
  // The peer must live in a cluster large enough that `peer_id` is a valid index THERE (so it can
  // mint a genuine cert / hello for it), even when `peer_id` is out of the small node's membership.
  let peer_count = SMALL.max(peer_id + 1);

  let ca = test_ca();
  let small_addr = addr(1);
  let peer_addr = addr(2);

  // The node under test: `Replica(0)` of a SMALL-replica cluster.
  let mut small =
    replica_in_cluster_of(&ca, 0, SMALL, [0u8; 32], scheme, StreamLayout::ControlBulk);
  // The dialing peer: genuine `Replica(peer_id)` of its own (possibly larger) cluster config.
  let mut peer = replica_in_cluster_of(
    &ca,
    u16::from(peer_id),
    peer_count,
    [1u8; 32],
    scheme,
    StreamLayout::ControlBulk,
  );

  // ONLY the peer dials the small node (an inbound accept on the small side — the realistic shape: the
  // small node does not know to dial an index it no longer carries). The small node adopts the peer's
  // attested identity on accept, where the membership-range gate applies.
  peer
    .0
    .connect(Instant::ZERO, small_addr, Peer::Replica(ReplicaId::new(0)))
    .expect("a fresh coordinator dials under the connection cap");

  let mut now = Instant::ZERO;
  let mut to_small = PacketPipe::default();
  let mut to_peer = PacketPipe::default();
  for _ in 0..2_000 {
    now = now + Duration::from_millis(5);
    small.0.handle_timeout(now, &mut small.1);
    peer.0.handle_timeout(now, &mut peer.1);
    while let Some((dst, bytes)) = small.0.poll_transmit() {
      if dst == peer_addr {
        to_peer.push(small_addr, bytes);
      }
    }
    while let Some((dst, bytes)) = peer.0.poll_transmit() {
      if dst == small_addr {
        to_small.push(peer_addr, bytes);
      }
    }
    while let Some((from, bytes)) = to_small.pop() {
      small.0.handle_udp(now, from, None, &bytes, &mut small.1);
    }
    while let Some((from, bytes)) = to_peer.pop() {
      peer.0.handle_udp(now, from, None, &bytes, &mut peer.1);
    }
    // Stop early once the small node has settled the peer either way — bound as a replica, or
    // quarantined on the learn lane. Both positive outcomes settle fast.
    if !small.0.bound_replica_peers_for_test().is_empty()
      || !small.0.quarantined_members_for_test().is_empty()
    {
      break;
    }
  }

  let bound_as_replica = small
    .0
    .bound_replica_peers_for_test()
    .contains(&Peer::Replica(ReplicaId::new(u16::from(peer_id))));
  let quarantined = small
    .0
    .quarantined_members_for_test()
    .contains(&MemberId::new(u128::from(peer_id)));
  match (bound_as_replica, quarantined) {
    (true, _) => PeerOutcome::BoundReplica,
    (false, true) => PeerOutcome::Quarantined,
    (false, false) => {
      // Rejected: the reject path runs BEFORE bind_validated, so a rejected candidate leaves the small
      // node holding no live connection for it — neither a replica bind nor a quarantine slot. (The
      // peer's own redial attempts are each refused the same way.)
      assert!(
        small.0.bridge_table_len() == 0,
        "a rejected candidate must not pin a connection slot on the small node"
      );
      PeerOutcome::Rejected
    }
  }
}

/// A replica whose validly-attested stable [`MemberId`] is NOT in the receiving node's active
/// membership is QUARANTINED by the binding policy — for BOTH provided schemes (`Hello` and `CertOid`)
/// — bound under the never-routable `Peer::Member` key on the no-authority learn lane rather than into
/// the replica fanout. An IN-membership member still binds normally (resolved to its routing slot).
///
/// The mechanism: a node from a since-shrunk cluster (a member offline across a rolling replacement, or
/// one removed while offline) presents a genuine cluster cert + Hello/OID for a member id the receiving
/// node's ACTIVE membership does not resolve. Its chain validates (same CA) and its attested cluster
/// matches, so neither the TLS layer nor the cluster cross-check turns it away; the coordinator's
/// `Endpoint::slot_of` returns `None`. Binding it as a replica would pin a slot and enter
/// `Backups`/`AllReplicas` — wasted, since the endpoint's own `sender_matches` drops every inbound
/// consensus frame from a non-member. Instead it is QUARANTINED: `Peer::Member` has `as_replica()`
/// `None`, so it is dropped at every vote / lead / view / fanout gate by construction while it rides
/// state-sync + the epoch-ahead hint to rejoin or learn its own retirement. (The test fixtures map
/// `MemberId == slot`, so an out-of-range index IS an out-of-membership member id.)
///
/// NEUTER CHECK: make the `slot_of` `None` arm in `apply_outcome` bind `Peer::Replica(fixed_slot)`
/// instead of quarantining, and the out-of-membership peer enters `bound_replica_peers` (asserted
/// `BoundReplica` not `Quarantined`), so this test fails — exactly the slot-and-fanout waste the
/// quarantine avoids.
#[test]
fn an_out_of_membership_member_is_quarantined_for_both_provided_schemes() {
  for scheme in [Scheme::Hello, Scheme::CertOid] {
    // In-membership (member id 1 ∈ genesis(3)): resolves to its slot and binds into the fanout.
    assert_eq!(
      small_node_admits_peer(scheme, 1),
      PeerOutcome::BoundReplica,
      "an in-membership member (id 1 ∈ genesis(3)) must bind as a replica under {scheme:?}"
    );
    // Out-of-membership (member id 3 ∉ genesis(3), and 4 ∉): an ACCEPTED inbound is QUARANTINED — bound
    // on the never-routable learn lane, never entering the replica fanout — so it can rejoin or learn
    // its own retirement, not rejected outright.
    assert_eq!(
      small_node_admits_peer(scheme, 3),
      PeerOutcome::Quarantined,
      "a member at the membership boundary (id 3 ∉ genesis(3)) must be quarantined under {scheme:?}, \
       never entering the replica fanout"
    );
    assert_eq!(
      small_node_admits_peer(scheme, 4),
      PeerOutcome::Quarantined,
      "a member beyond the membership (id 4 ∉ genesis(3)) must be quarantined under {scheme:?}"
    );
  }
}

/// A peer that authenticates as THIS replica's own id (`Replica(0)` dialing the `Replica(0)` node)
/// is REJECTED by the binding policy — for BOTH provided schemes — before it can bind, pin a slot, or
/// enter the outbound fanout. An OTHER in-membership id (`Replica(1)`) still binds, so the gate is the
/// self-id one and not a blanket refusal.
///
/// The mechanism: a duplicate-id or misconfigured member presents a genuine cluster cert + Hello/OID
/// attesting member id 0 — the small node's OWN member id. Its chain validates (same CA), its attested
/// cluster matches, and that member id IS in the membership, so neither the TLS layer nor the cluster /
/// membership gates turn it away. It arrives as an ACCEPTED connection (the node did not dial itself),
/// so there is NO dialed expectation to catch the mismatch — `dialed_expectation_of` is `None`. Without
/// the `member_id == self.endpoint.local()` gate it would bind AS `Replica(0)`, and that bound peer
/// becomes the `from` a consensus frame is delivered under, so a network-supplied self-identifying
/// message would satisfy the endpoint's sender check. This is in-model duplicate-identity /
/// misconfiguration (it needs a valid cluster cert for our id), NOT a Byzantine claim.
///
/// NEUTER CHECK: drop the `candidate != self.me()` gate in `apply_outcome` and the self-claiming peer
/// binds as `Replica(0)` (asserted `BoundReplica` not `Rejected`), so this test fails — exactly the
/// bind-as-self hole the gate closes. The self-id (id 0 ∈ membership) takes the self-claim reject
/// path BEFORE `slot_of`, so it is genuinely REJECTED (no slot, no learn lane) — distinct from the
/// out-of-membership QUARANTINE path.
#[test]
fn a_peer_claiming_this_replicas_own_identity_is_rejected_for_both_provided_schemes() {
  for scheme in [Scheme::Hello, Scheme::CertOid] {
    // A peer attesting `Replica(0)` — the small node's OWN id — must be REJECTED (not quarantined):
    // never bound, never in the fanout, never pinning a slot (the no-slot assertion lives in
    // `small_node_admits_peer`). The self-claim gate runs before `slot_of`, and id 0 IS in membership.
    assert_eq!(
      small_node_admits_peer(scheme, 0),
      PeerOutcome::Rejected,
      "a peer authenticating as this replica's own id (Replica(0)) must be rejected under {scheme:?}, \
       never binding as the local replica"
    );
    // A DIFFERENT in-membership id still binds, so the gate is the self-id one, not a blanket refusal.
    assert_eq!(
      small_node_admits_peer(scheme, 1),
      PeerOutcome::BoundReplica,
      "a legitimate OTHER replica id (Replica(1)) still binds under {scheme:?}"
    );
  }
}

/// A multi-budget receive window buffered before a drain is consumed ONE read budget per PUBLIC pump,
/// not all at once — and a `poll_timeout`-driven driver sees an immediate deadline between pumps while
/// data remains, so it re-pumps until the window is fully drained, every frame delivered in order.
///
/// This is the coordinator-surface proof of the receive-path pacing. Two replicas converge over real
/// mTLS (so r0 is a bound, `Validated` peer of r1), then a large burst of tiny pre-framed `Commit`
/// frames is staged on r0's send stream and ALL of r0's datagrams are fed into r1 WITHOUT draining —
/// pre-loading r1's reassembly with several budgets' worth of frames (the realistic exhaustion setup a
/// bulk datagram batch produces). r1 is then pumped through `drain_bridge` + `pump` (the public receive
/// pump) one step at a time. The assertions hold the contract:
/// - each pump delivers AT MOST one budget's worth of frames (`STAGE_CHUNK / LEN_PREFIX`), never the
///   whole window;
/// - while undrained budgets remain, `poll_timeout` returns an immediate deadline (`bridge` reports
///   `deferred_ready` work), so a sleep-until-`poll_timeout` driver re-pumps at once;
/// - it takes MULTIPLE pumps to drain the burst, and ALL frames arrive (in order — the decoder is a
///   strict FIFO and the consensus endpoint receives each).
///
/// NEUTER CHECK: with the synchronous whole-window drain (no per-pump dedup + leftover deferral) one
/// pump delivers the ENTIRE burst, so `pumps > 1` fails and the per-pump budget bound is blown — which
/// is exactly the unbounded per-pump work this paces.
#[test]
fn a_buffered_tiny_frame_window_drains_one_budget_per_pump() {
  let ca = test_ca();
  let addr0 = addr(1);
  let addr1 = addr(2);
  // `Single` keeps every frame on the Control class, so the whole burst rides one recv stream.
  let mut r0 = replica(&ca, 0, [0u8; 32], Scheme::CertOid, StreamLayout::Single);
  let mut r1 = replica(&ca, 1, [1u8; 32], Scheme::CertOid, StreamLayout::Single);

  // Converge one op so BOTH sides are `Validated` with the peer bound (r0 is r1's peer, and vice
  // versa). After this, r0 can stage frames on its send stream to r1 and they route to r1's recv.
  // `converged_at` returns the clock convergence happened at, so the burst below continues the SAME
  // monotonic clock — a fixed far-future base would trip the 1 s idle timeout and close the link.
  dial_and_seed(&mut r0, addr0, &mut r1, addr1, Bytes::from_static(b"x"));
  let mut now = converged_at(&mut r0, addr0, &mut r1, addr1)
    .expect("the cluster must converge so both peers are Validated before the burst");
  now = now + Duration::from_millis(5);

  // Build a burst of distinguishable tiny Commit frames spanning several read budgets. Each frame is
  // `[u32 len][Commit]`; size N off the real encoded size so the test is robust to it.
  let mut blob = Vec::new();
  let mut frames = 0u64;
  while blob.len() <= 4 * STAGE_CHUNK {
    let msg = Message::Commit(Commit::new(
      View::with(1),
      OpNumber::with(frames + 1),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
    ));
    encode_frame(&encode_message(&msg), &mut blob);
    frames += 1;
  }
  let total_frames = frames;
  assert!(
    blob.len() > 4 * STAGE_CHUNK,
    "the burst must exceed several read budgets so draining needs several pumps"
  );

  // Baseline the delivery counter: convergence already drained the seed op's frames into r1's
  // endpoint, so everything below is measured as a DELTA past this point.
  let base_delivered = r1.0.consensus_frames_delivered();

  // Stage the burst on r0's send stream to r1, then drive r0 to flush the WHOLE staged buffer into
  // r1's reassembly WITHOUT r1 draining its decoder. r1's INBOUND uses `feed_datagram_for_test`, which
  // runs the bridge service pass (so r1 still ACKs, letting r0's congestion window open and the whole
  // burst flow) but NOT `drain_bridge` — so no frame is popped to r1's endpoint yet. r1's ACKs are
  // delivered back to r0 normally so r0 keeps sending. The result is a multi-budget window buffered at
  // r1 with zero frames delivered, the realistic state a bulk datagram batch leaves before a drain.
  let (coord0, _, _) = &mut r0;
  coord0.stage_control_burst_for_test(now, Peer::Replica(ReplicaId::new(1)), &blob);
  let mut idle = 0u64;
  for _ in 0..4000u64 {
    now = now + Duration::from_millis(1);
    {
      let (c0, w0, _b0) = &mut r0;
      c0.handle_timeout(now, w0);
    }
    let mut moved = false;
    // r0's datagrams → buffered into r1 (no drain); r1's ACK datagrams → delivered to r0 normally.
    let mut to_r1: Vec<Vec<u8>> = Vec::new();
    {
      let (c0, _, _) = &mut r0;
      while let Some((dst, bytes)) = c0.poll_transmit() {
        if dst == addr1 {
          to_r1.push(bytes);
        }
      }
    }
    for bytes in &to_r1 {
      moved = true;
      let (c1, _, _) = &mut r1;
      c1.feed_datagram_for_test(now, addr0, bytes);
    }
    let mut to_r0: Vec<Vec<u8>> = Vec::new();
    {
      let (c1, _, _) = &mut r1;
      while let Some((dst, bytes)) = c1.poll_transmit() {
        if dst == addr0 {
          to_r0.push(bytes);
        }
      }
    }
    for bytes in &to_r0 {
      moved = true;
      let (c0, w0, _b0) = &mut r0;
      c0.handle_udp(now, addr1, None, bytes, w0);
    }
    // Stop once the link has quiesced (r0 flushed its whole staged burst and the ACK exchange settled).
    if moved {
      idle = 0;
    } else {
      idle += 1;
      if idle >= 32 {
        break;
      }
    }
  }
  assert_eq!(
    r1.0.consensus_frames_delivered(),
    base_delivered,
    "no NEW frame may be delivered to r1's endpoint during the buffering phase (no drain ran)"
  );
  assert!(
    r1.0.bridge_deferred_ready_len() > 0 || r1.0.poll_timeout().is_some(),
    "r1 must hold buffered receive work before the measured drain"
  );

  // Drain r1 one PUBLIC receive pump at a time. Each pump must deliver at most one budget's worth of
  // frames; while undrained budgets remain, poll_timeout must be immediate; it must take several pumps.
  let budget_frames = (STAGE_CHUNK / LEN_PREFIX) as u64;
  let mut pumps = 0u64;
  let mut guard = 0u64;
  loop {
    let before = r1.0.consensus_frames_delivered();
    // While the bridge still holds a deferred (half-drained) read, poll_timeout is immediate.
    if r1.0.bridge_deferred_ready_len() > 0 {
      let deadline = r1.0.poll_timeout();
      assert!(
        deadline.is_some_and(|d| d <= std::time::Instant::now()),
        "while a buffered receive window has budgets left, poll_timeout must be immediate so the \
         driver re-pumps instead of sleeping"
      );
    }
    now = now + Duration::from_millis(1);
    let (c1, w1, _b1) = &mut r1;
    c1.receive_pump_for_test(now, w1);
    let delivered = r1.0.consensus_frames_delivered() - before;
    if delivered > 0 {
      pumps += 1;
      assert!(
        delivered <= budget_frames,
        "one pump must deliver at most a budget's worth of frames ({budget_frames}), got {delivered}"
      );
    }
    // The burst is the FIRST `total_frames` consensus frames on r1's Control recv (strict-FIFO
    // decoder), so reaching that count means every burst frame has been delivered, in order. (A few of
    // r0's idle heartbeat Commits may trail the burst on the same stream; `>=` tolerates them.)
    if r1.0.consensus_frames_delivered() - base_delivered >= total_frames {
      break;
    }
    guard += 1;
    assert!(
      guard < total_frames + 64,
      "draining must make forward progress every pump (no stall): delivered {} of {total_frames}",
      r1.0.consensus_frames_delivered() - base_delivered
    );
  }

  assert!(
    pumps > 1,
    "the multi-budget window must take MULTIPLE public pumps to drain (one budget each), took {pumps}"
  );
  assert!(
    r1.0.consensus_frames_delivered() - base_delivered >= total_frames,
    "every frame in the burst must eventually be delivered to the endpoint across the bounded pumps \
     (got {}, burst was {total_frames})",
    r1.0.consensus_frames_delivered() - base_delivered
  );
}

/// The driver drains consensus commit events through the PUBLIC `QuicCoordinator::poll_event` — the
/// only by-value consensus output the coordinator exposes (every other observation goes through the
/// immutable `endpoint()`). Two replicas converge one client op over real mTLS; the op committed on
/// both, so each endpoint enqueued exactly one [`Event::Committed`]. This drains that event through
/// `poll_event` (NOT by inspecting `endpoint()` internals) on BOTH sides and asserts:
/// - the FIRST `poll_event` returns `Event::Committed` for the converged op (op 1);
/// - the NEXT `poll_event` returns `None` — the queue is now empty, so the events do not accumulate
///   unbounded (the leak a missing public drain would cause).
///
/// NEUTER CHECK: remove `QuicCoordinator::poll_event` and a driver has no public drain for these
/// events — `Event::Committed` piles up in `Endpoint.events` unbounded and the commit notification
/// never reaches the driver; this test cannot even be written against the public surface, which is the
/// gap it closes.
#[test]
fn commits_are_drained_through_the_public_poll_event() {
  let ca = test_ca();
  let addr0 = addr(1);
  let addr1 = addr(2);
  let mut r0 = replica(&ca, 0, [0u8; 32], Scheme::CertOid, StreamLayout::Single);
  let mut r1 = replica(&ca, 1, [1u8; 32], Scheme::CertOid, StreamLayout::Single);

  dial_and_seed(&mut r0, addr0, &mut r1, addr1, Bytes::from_static(b"x"));
  assert!(
    run_until_converged(&mut r0, addr0, &mut r1, addr1),
    "the cluster must converge so both endpoints emitted a commit event to drain"
  );

  // Both replicas committed op 1, so each holds exactly one queued Committed event. Drain it through
  // the PUBLIC poll_event (the driver's surface), then assert the queue is empty (no leak).
  for (coord, who) in [(&mut r0.0, "primary"), (&mut r1.0, "backup")] {
    let event = coord
      .poll_event()
      .unwrap_or_else(|| panic!("{who} must surface its commit through the public poll_event"));
    let Event::Committed(committed) = event else {
      panic!("{who}'s drained event must be the Committed for op 1, got {event:?}");
    };
    assert_eq!(
      committed.op(),
      OpNumber::with(1),
      "{who}'s drained event is the commit of the converged op 1"
    );
    assert_eq!(
      committed.reply(),
      b"x",
      "{who}'s committed reply carries the applied op body"
    );
    assert!(
      coord.poll_event().is_none(),
      "after draining the one commit, {who}'s poll_event must return None — the events do not \
       accumulate unbounded"
    );
  }
}

/// The PUBLIC node-local request path: [`QuicCoordinator::submit_client_request`] injects a client
/// request at this replica AND broadcasts it to the backups, so whichever replica holds the primary
/// role for the current view serves it. Two replicas converge over real mTLS; the request is submitted
/// at replica 0 (primary for view 0 of a 2-node cluster) through the PUBLIC api — NOT the
/// `inject_message_for_test` seam — and the committed reply is drained through the public
/// `poll_event` as [`Event::Committed`].
///
/// This is the driver's submit surface: a real QUIC driver has only `submit_client_request` to feed a
/// node-local app request into consensus (the inject seam is `#[cfg(test)]`), so this proves that
/// public path drives a request to commit and surfaces the reply.
#[test]
fn public_submit_client_request_converges() {
  let ca = test_ca();
  let addr0 = addr(1);
  let addr1 = addr(2);
  let mut r0 = replica(&ca, 0, [7u8; 32], Scheme::Hello, StreamLayout::ControlBulk);
  let mut r1 = replica(&ca, 1, [9u8; 32], Scheme::Hello, StreamLayout::ControlBulk);

  // Mutual dial so each side records the dialed expectation its binding policy match-or-aborts on.
  r0.0
    .connect(Instant::ZERO, addr1, Peer::Replica(ReplicaId::new(1)))
    .expect("a fresh coordinator dials under the connection cap");
  r1.0
    .connect(Instant::ZERO, addr0, Peer::Replica(ReplicaId::new(0)))
    .expect("a fresh coordinator dials under the connection cap");

  // Submit at replica 0 (the view-0 primary) via the PUBLIC api: it injects locally AND broadcasts to
  // backups. The Prepare is staged immediately; the consensus layer retransmits it until the per-peer
  // send stream is up, so submitting before the ferry loop needs no handshake-complete barrier.
  r0.0.submit_client_request(
    Instant::ZERO,
    &mut r0.1,
    Request::new(
      ClientId::new(1),
      RequestNumber::with(1),
      Bytes::from_static(b"x"),
    ),
  );

  assert!(
    run_until_converged(&mut r0, addr0, &mut r1, addr1),
    "the publicly-submitted client request must commit on both replicas"
  );

  // The committed reply reaches the app through the PUBLIC poll_event on the submitting replica.
  let event = r0
    .0
    .poll_event()
    .expect("the submitting replica surfaces its commit through the public poll_event");
  let Event::Committed(committed) = event else {
    panic!("the drained event must be the Committed for the submitted op, got {event:?}");
  };
  assert_eq!(
    committed.op(),
    OpNumber::with(1),
    "the drained event is the commit of the submitted op 1"
  );
  assert_eq!(
    committed.reply(),
    b"x",
    "the committed reply carries the submitted op body"
  );
}

/// End-to-end coverage of a frame that CROSSES the per-stream receive window: a single consensus op
/// whose `Prepare` is larger than the 1 MiB `stream_receive_window` (but within the 16 MiB frame cap)
/// commits on both replicas over real mTLS, its body routed to the Bulk class under `ControlBulk`.
/// Such a frame cannot fit the receiver's stream window in one shot, so it can only complete if the
/// receiver keeps issuing `MAX_STREAM_DATA` as it drains each budget — exercising the multi-window
/// flow-control path the smaller `large_op_commits_over_bulk` (>64 KiB, within one window) does not.
///
/// This drives the standard fixed-5 ms-step ferry, which fires `handle_timeout` every tick and so
/// services the connection (and ships any queued credit) every tick regardless. It is therefore an
/// end-to-end PATH test, NOT the decisive proof that the inbound read itself emits the credit: that —
/// the credit reaching the wire from `ingest_recv`'s own pump, without unrelated traffic servicing the
/// connection (the case that hangs a `poll_timeout`-driven driver) — is the bridge-level
/// `a_budget_read_emits_flow_control_credit_this_pump`.
#[test]
fn a_prepare_larger_than_the_stream_window_commits_over_bulk() {
  // Strictly larger than the 1 MiB stream window, comfortably under the 16 MiB frame cap.
  let big = vec![0x5Au8; 9 * 1024 * 1024];

  let ca = test_ca();
  let addr0 = addr(1);
  let addr1 = addr(2);
  let mut r0 = replica(
    &ca,
    0,
    [0u8; 32],
    Scheme::CertOid,
    StreamLayout::ControlBulk,
  );
  let mut r1 = replica(
    &ca,
    1,
    [1u8; 32],
    Scheme::CertOid,
    StreamLayout::ControlBulk,
  );

  dial_and_seed(&mut r0, addr0, &mut r1, addr1, Bytes::from(big.clone()));
  let converged = run_until_converged(&mut r0, addr0, &mut r1, addr1);
  assert!(
    converged,
    "the over-window Prepare must commit on both replicas — only possible if the receiver emits \
     flow-control credit after each budget read so the sender keeps feeding past the first window"
  );
  assert_eq!(
    r0.0.endpoint().state_machine_ref().applied(),
    applied_one(&big).as_slice(),
    "primary applied the full over-window op"
  );
  assert_eq!(
    r1.0.endpoint().state_machine_ref().applied(),
    applied_one(&big).as_slice(),
    "backup converged on the full over-window op across the per-budget flow-control window updates"
  );
}

/// Drive `sender` at full speed while `stalled` receives datagrams but never DRAINS them, until
/// `stalled`'s reassembler refuses the stream (its `RecordRejected` count rises above `base_rr`).
///
/// The stall models a node whose event loop is not running while its network stack still accepts
/// packets: `feed_datagram_for_test` runs the bridge service pass — so the stalled side still ACKs
/// and the sender's window keeps opening, exactly as a real receiver's kernel and quinn would — but
/// never runs `drain_bridge`, so no frame is read out and every arriving STREAM frame stays a span.
/// The traffic itself is the protocol's own: client requests submitted at the primary, and the
/// `Prepare` retransmissions its timers drive because the stalled backup never acknowledges.
///
/// Returns the clock it stopped at and how many requests were submitted.
fn flood_a_stalled_receiver(
  sender: &mut Replica,
  sender_addr: std::net::SocketAddr,
  stalled: &mut Replica,
  stalled_addr: std::net::SocketAddr,
  start: Instant,
  base_rr: u64,
  client_base: u128,
) -> (Instant, u64) {
  let mut now = start;
  let mut submits = 0u64;
  for k in 0..60_000u64 {
    now = now + Duration::from_micros(200);
    {
      let (c, w, b) = sender;
      c.handle_storage(now, w, b);
      c.handle_timeout(now, w);
      // One small request per few ticks: each mints a `Prepare` too small to fill a packet, which is
      // the sub-packet span shape. The rest of the spans come from the retransmissions the stalled
      // backup's silence provokes.
      if k % 4 == 0 {
        submits += 1;
        c.submit_client_request(
          now,
          w,
          Request::new(
            ClientId::new(client_base + submits as u128),
            RequestNumber::with(1),
            Bytes::from_static(b"z"),
          ),
        );
      }
    }
    let mut to_stalled: Vec<Vec<u8>> = Vec::new();
    while let Some((dst, bytes)) = sender.0.poll_transmit() {
      if dst == stalled_addr {
        to_stalled.push(bytes);
      }
    }
    for bytes in &to_stalled {
      stalled.0.feed_datagram_for_test(now, sender_addr, bytes);
    }
    let mut to_sender: Vec<Vec<u8>> = Vec::new();
    while let Some((dst, bytes)) = stalled.0.poll_transmit() {
      if dst == sender_addr {
        to_sender.push(bytes);
      }
    }
    for bytes in &to_sender {
      let (c, w, _) = &mut *sender;
      c.handle_udp(now, stalled_addr, None, bytes, w);
    }
    if stalled
      .0
      .conn_close_count(crate::transport::CloseCause::RecordRejected)
      > base_rr
    {
      break;
    }
  }
  (now, submits)
}

/// Both loops run normally again: pump each side, redial any peer left with no bound connection on
/// the backoff a driver's link reconcile uses, and re-submit the SAME client request the way the
/// driver's stale-request scan does, until BOTH replicas have applied `want`.
///
/// Returns the clock it stopped at, whether the request completed, and how many redials were issued.
fn recover_and_complete(
  r0: &mut Replica,
  r1: &mut Replica,
  addrs: (std::net::SocketAddr, std::net::SocketAddr),
  start: Instant,
  client: u128,
  want: &[u8],
  redial: bool,
) -> (Instant, bool, u64) {
  let (addr0, addr1) = addrs;
  let p0 = Peer::Replica(ReplicaId::new(0));
  let p1 = Peer::Replica(ReplicaId::new(1));
  let mut now = start;
  let mut redials = 0u64;
  let mut due: Option<Instant> = None;
  let mut done = false;
  for k in 0..80_000u64 {
    now = now + Duration::from_millis(5);
    {
      let (c, w, b) = &mut *r0;
      c.handle_storage(now, w, b);
      c.handle_timeout(now, w);
    }
    {
      let (c, w, b) = &mut *r1;
      c.handle_storage(now, w, b);
      c.handle_timeout(now, w);
    }
    // The link reconcile a driver runs each iteration: a peer with no bound connection is redialed
    // once its backoff is due, and binding stops the redials.
    if redial
      && (!r0.0.has_bound_conn(p1) || !r1.0.has_bound_conn(p0))
      && due.is_none_or(|d| now >= d)
    {
      if !r0.0.has_bound_conn(p1) {
        let _ = r0.0.connect(now, addr1, p1);
        redials += 1;
      }
      if !r1.0.has_bound_conn(p0) {
        let _ = r1.0.connect(now, addr0, p0);
        redials += 1;
      }
      due = Some(now + Duration::from_millis(50));
    }
    // The client retransmission the driver's stale-request scan performs: the SAME request, resent
    // until it commits. Nothing new is injected — this is the operation that was in flight.
    if k % 200 == 0 {
      let (c, w, _) = &mut *r0;
      c.submit_client_request(
        now,
        w,
        Request::new(
          ClientId::new(client),
          RequestNumber::with(1),
          Bytes::copy_from_slice(want),
        ),
      );
    }
    let mut to_r1: Vec<Vec<u8>> = Vec::new();
    while let Some((dst, bytes)) = r0.0.poll_transmit() {
      if dst == addr1 {
        to_r1.push(bytes);
      }
    }
    for bytes in &to_r1 {
      let (c, w, _) = &mut *r1;
      c.handle_udp(now, addr0, None, bytes, w);
    }
    let mut to_r0: Vec<Vec<u8>> = Vec::new();
    while let Some((dst, bytes)) = r1.0.poll_transmit() {
      if dst == addr0 {
        to_r0.push(bytes);
      }
    }
    for bytes in &to_r0 {
      let (c, w, _) = &mut *r0;
      c.handle_udp(now, addr1, None, bytes, w);
    }
    let applied_at = |r: &Replica| {
      r.0
        .endpoint()
        .state_machine_ref()
        .applied()
        .iter()
        .any(|(_, body)| body == want)
    };
    if applied_at(r0) && applied_at(r1) {
      done = true;
      break;
    }
  }
  (now, done, redials)
}

/// COMPONENT-LEVEL exercise of the recovery path over real cluster-private mTLS and real consensus
/// traffic, with THREE seams MODELLED: the receiver's stall, the redial schedule, and the client's
/// stale-request rebroadcast — this test rebuilds and resubmits the pending request on its own
/// cadence, so the driver's pending map, timeout scan and `retransmit_stale` never run here.
///
/// The transport's stream receive window bounds an unread backlog's BYTES, not the number of spans
/// the peer segments them into, so a sender producing sub-packet `Prepare`s to a receiver that is not
/// draining walks the span count to quinn's per-stream ceiling and the connection is closed with a
/// transport error. That is documented as recoverable rather than prevented. What follows is what
/// this test drives — every step real except the three seams named above, and NOT a whole-chain
/// proof, which would take a real-driver test that reaches the refusal and does not exist:
///
/// 1. two coordinators mutually dial, authenticate and commit a client request;
/// 2. a second request is submitted and left in flight;
/// 3. the backup's loop stalls — its stack still receives and ACKs, it just never drains — while the
///    primary submits and retransmits, until the reassembler refuses the stream;
/// 4. BOTH ends observe the loss: the stalled side classifies it `RecordRejected`, the sender sees the
///    peer's close, and each reaps the dead connection out of its table;
/// 5. the loops resume, an unbound peer is redialed on the reconcile's backoff, and the SAME client
///    request — resent the way the driver's stale-request scan resends it, not injected as fresh
///    bytes — commits on both replicas;
/// 6. the overload is repeated from whichever replica the intervening view change left as primary,
///    and a further request commits after that too.
///
/// Every connection here comes from a real dial and mTLS handshake, every frame from the consensus
/// endpoint, and the close from quinn's own refusal. Removing the redial leaves step 6 with no route
/// to rebuild and the final request never commits.
///
/// **Scope — what is MODELLED, and how far the claim reaches.** The stall itself: production's
/// `handle_udp` feeds quinn and drains it in the same call, so a driver whose loop is behind leaves
/// datagrams in its socket, not in quinn, and cannot produce a receiver that ACKs without draining.
/// This test constructs that shape deliberately, because it is the shortest path to the ceiling and
/// therefore the way to exercise what happens AFTER it. The redial schedule is modelled here too
/// (armed, then dialed when due); the real one lives in the drivers and is proved by
/// `viewstamp-compio`'s `the_link_reconcile_arms_then_redials_an_unbound_peer_on_a_doubling_backoff`.
/// And so is the client's stale-request rebroadcast: [`recover_and_complete`] rebuilds the same
/// `Request` on a fixed cadence, where production reaches it through the driver's pending map, its
/// timeout scan and `retransmit_stale` — none of which run here.
///
/// So this is COMPONENT-level evidence for the recovery path — connection-lost, unbind and reap,
/// backoff redial, protocol retransmission — and nothing wider. There is no end-to-end real-driver
/// test of the refusal, because the refusal was not reached through `handle_udp` on the paths
/// tested; `viewstamp-compio`'s `a_lossy_real_link_keeps_the_cluster_committing_and_recovers` drives
/// real drivers under real relayed loss and is loss-tolerance evidence, not evidence for this claim.
#[test]
fn a_modelled_receiver_stall_at_the_reassembly_ceiling_recovers_and_completes_its_operation() {
  let ca = test_ca();
  let addr0 = addr(41);
  let addr1 = addr(42);
  let p0 = Peer::Replica(ReplicaId::new(0));
  let p1 = Peer::Replica(ReplicaId::new(1));
  let mut r0 = replica(&ca, 0, [7u8; 32], Scheme::Hello, StreamLayout::ControlBulk);
  let mut r1 = replica(&ca, 1, [9u8; 32], Scheme::Hello, StreamLayout::ControlBulk);
  r0.0
    .connect(Instant::ZERO, addr1, p1)
    .expect("a fresh coordinator dials under the connection cap");
  r1.0
    .connect(Instant::ZERO, addr0, p0)
    .expect("a fresh coordinator dials under the connection cap");
  r0.0.submit_client_request(
    Instant::ZERO,
    &mut r0.1,
    Request::new(
      ClientId::new(1),
      RequestNumber::with(1),
      Bytes::from_static(b"warm"),
    ),
  );
  let mut now = converged_at(&mut r0, addr0, &mut r1, addr1)
    .expect("the cluster commits one request over real mTLS before anything is broken");

  // The operation that must survive the fault: in flight when the backup stalls.
  r0.0.submit_client_request(
    now,
    &mut r0.1,
    Request::new(
      ClientId::new(2),
      RequestNumber::with(1),
      Bytes::from_static(b"survivor"),
    ),
  );

  let table_before = (r0.0.bridge_table_len(), r1.0.bridge_table_len());
  let (n, submits) = flood_a_stalled_receiver(&mut r0, addr0, &mut r1, addr1, now, 0, 1_000);
  now = n;
  assert_eq!(
    r1.0
      .conn_close_count(crate::transport::CloseCause::RecordRejected),
    1,
    "the stalled receiver's reassembler must refuse the stream and the QUIC layer close the \
     connection — {submits} submitted requests and their retransmissions did not get there"
  );
  assert!(
    r0.0
      .conn_close_count(crate::transport::CloseCause::PeerClosed)
      >= 1,
    "and the SENDER must observe that close too, not keep writing into a dead connection"
  );

  // The loops resume. Both ends must reap the dead connection, and the in-flight request completes.
  let (n, done, _) =
    recover_and_complete(&mut r0, &mut r1, (addr0, addr1), now, 2, b"survivor", true);
  now = n;
  assert!(
    done,
    "the request that was in flight when the connection died must complete once the loops resume — \
     resent by the client, carried by whatever route the mesh recovered"
  );
  assert!(
    r0.0.bridge_table_len() < table_before.0 && r1.0.bridge_table_len() < table_before.1,
    "both ends must have REAPED the refused connection, not left it in the table: {:?} -> {:?}",
    table_before,
    (r0.0.bridge_table_len(), r1.0.bridge_table_len())
  );

  // Overload it again, from whichever replica the stall's view change left as primary.
  let prim0 = r0.0.endpoint().is_primary();
  let refusals_before = r0
    .0
    .conn_close_count(crate::transport::CloseCause::RecordRejected)
    + r1
      .0
      .conn_close_count(crate::transport::CloseCause::RecordRejected);
  let (n, _) = if prim0 {
    let base = r1
      .0
      .conn_close_count(crate::transport::CloseCause::RecordRejected);
    flood_a_stalled_receiver(&mut r0, addr0, &mut r1, addr1, now, base, 500_000)
  } else {
    let base = r0
      .0
      .conn_close_count(crate::transport::CloseCause::RecordRejected);
    flood_a_stalled_receiver(&mut r1, addr1, &mut r0, addr0, now, base, 500_000)
  };
  now = n;
  let refusals_after = r0
    .0
    .conn_close_count(crate::transport::CloseCause::RecordRejected)
    + r1
      .0
      .conn_close_count(crate::transport::CloseCause::RecordRejected);
  assert_eq!(
    refusals_after,
    refusals_before + 1,
    "the second overload must reach the ceiling exactly once more — a recovery that left the link \
     churning would show extra refusals"
  );

  let (_, done, redials) = recover_and_complete(
    &mut r0,
    &mut r1,
    (addr0, addr1),
    now,
    3,
    b"after-second",
    true,
  );
  assert!(
    done,
    "a further request must commit after the SECOND overload — the fault is repeatable and the \
     cluster keeps making progress across it"
  );
  assert!(
    redials > 0,
    "the second overload left the peer with no bound connection, so the recovery must have gone \
     through a redial"
  );
  assert!(
    r0.0.has_bound_conn(p1) && r1.0.has_bound_conn(p0),
    "and the mesh must be bound again at the end, not limping on a half-open route"
  );
}

/// What the sender actually guarantees about sub-packet spans, measured on the production call path.
///
/// A receiver's reassembler refuses a stream once it holds too many spans, and a span is one STREAM
/// frame, so how the sender segments matters. The guarantee is per PACKETIZING PASS: every message
/// staged for a class since the last pass is written to quinn as one contiguous run, so the pass
/// emits packet-filling frames plus at most one short tail — one sub-packet span, however many
/// messages went into it. It is NOT one per coordinator entry: an entry can packetize more than once
/// (the read pass services to release flow-control credit, the pump services at the end), so the
/// per-entry count is a small constant.
///
/// Both halves are measured here on the real path — `route` per message exactly as `pump` does, then
/// the real pump-end service:
///
/// - a batch of 64 small Control messages leaves as a couple of datagrams with ONE short one, not 64
///   short ones. Servicing per message instead (or staging per message without coalescing) turns
///   that into 64 sub-packet spans and fails this by a wide margin;
/// - across a converged run that includes a multi-megabyte Bulk frame — so partial writes and the
///   `Writable`-driven retries of a blocked stream are in the sample — no coordinator entry emits
///   more than a couple of short datagrams.
///
/// **Scope: newly written contiguous data.** Retransmissions are excluded — loss recovery packs
/// disjoint ranges of already-sent data into whatever packet is going out, so one datagram can carry
/// several short STREAM frames and the guarantee says nothing about them. The spans are therefore
/// counted at the RECEIVER, from quinn's own `frame_rx.stream`, not inferred from datagram lengths:
/// a datagram-length proxy would score a recovery packet as one span when it is several.
///
/// The alternating-loss phase then puts recovery in the sample deliberately: with every other
/// datagram dropped, the sender is retransmitting continuously, and the receiver's span count must
/// still stay proportional to the data — bounded recovery, not span multiplication.
#[test]
fn a_class_batch_leaves_as_one_sub_packet_span_per_packetizing_pass() {
  /// Below the 1200-byte QUIC path minimum: a datagram this small could not have been packet-filling.
  const SHORT: usize = 1100;

  let ca = test_ca();
  let addr0 = addr(51);
  let addr1 = addr(52);
  let p0 = Peer::Replica(ReplicaId::new(0));
  let p1 = Peer::Replica(ReplicaId::new(1));
  let mut r0 = replica(&ca, 0, [7u8; 32], Scheme::Hello, StreamLayout::ControlBulk);
  let mut r1 = replica(&ca, 1, [9u8; 32], Scheme::Hello, StreamLayout::ControlBulk);
  r0.0
    .connect(Instant::ZERO, addr1, p1)
    .expect("a fresh coordinator dials under the connection cap");
  r1.0
    .connect(Instant::ZERO, addr0, p0)
    .expect("a fresh coordinator dials under the connection cap");
  r0.0.submit_client_request(
    Instant::ZERO,
    &mut r0.1,
    Request::new(
      ClientId::new(1),
      RequestNumber::with(1),
      Bytes::from_static(b"warm"),
    ),
  );
  let mut now = converged_at(&mut r0, addr0, &mut r1, addr1).expect("the link comes up");
  while r0.0.poll_transmit().is_some() {}

  // A pump's worth of small same-class messages, routed one at a time exactly as `pump` routes them.
  const BATCH: usize = 64;
  let heartbeat = Message::Commit(Commit::new(
    View::with(0),
    OpNumber::with(1),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
  ));
  for _ in 0..BATCH {
    r0.0
      .route_message_for_test(now, crate::Recipient::To(p1), &heartbeat);
  }
  now = now + Duration::from_millis(1);
  {
    let (c, w, _) = &mut r0;
    c.handle_timeout(now, w);
  }
  let spans_before = r1.0.rx_stream_frames_for_test();
  let (mut datagrams, mut short) = (0usize, 0usize);
  let mut batch_out: Vec<Vec<u8>> = Vec::new();
  while let Some((dst, d)) = r0.0.poll_transmit() {
    datagrams += 1;
    if d.len() < SHORT {
      short += 1;
    }
    if dst == addr1 {
      batch_out.push(d);
    }
  }
  now = now + Duration::from_millis(1);
  for d in &batch_out {
    let (c, w, _) = &mut r1;
    c.handle_udp(now, addr0, None, d, w);
  }
  // The direct count: STREAM frames the receiver's quinn actually parsed out of that batch.
  let spans = r1.0.rx_stream_frames_for_test() - spans_before;
  assert!(
    spans <= 2,
    "{BATCH} messages staged for one class must reach the peer as packet-filling frames plus at \
     most one short tail; its quinn counted {spans} STREAM frames"
  );
  assert!(
    short <= 1,
    "and at most one datagram may be short: {short} of {datagrams}"
  );
  assert!(
    datagrams < BATCH / 8,
    "and they must not leave as a datagram apiece: {datagrams} datagrams for {BATCH} messages"
  );

  // A converged run whose traffic includes a frame far larger than the stream window, so the sample
  // contains partial writes and the `Writable` retries that drain a blocked stream's tail.
  r0.0.submit_client_request(
    now,
    &mut r0.1,
    Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from(std::vec![0x5Au8; 3 * 1024 * 1024]),
    ),
  );
  let mut worst = 0usize;
  let mut phase_bytes = 0usize;
  let spans_at_phase = r1.0.rx_stream_frames_for_test();
  let mut delivered = false;
  for _ in 0..40_000u64 {
    now = now + Duration::from_millis(1);
    {
      let (c, w, b) = &mut r0;
      c.handle_storage(now, w, b);
      c.handle_timeout(now, w);
    }
    {
      let (c, w, b) = &mut r1;
      c.handle_storage(now, w, b);
      c.handle_timeout(now, w);
    }
    let mut entry_short = 0usize;
    let mut to_r1: Vec<Vec<u8>> = Vec::new();
    while let Some((dst, d)) = r0.0.poll_transmit() {
      if dst == addr1 {
        if d.len() < SHORT {
          entry_short += 1;
        }
        to_r1.push(d);
      }
    }
    worst = worst.max(entry_short);
    for d in &to_r1 {
      phase_bytes += d.len();
      let (c, w, _) = &mut r1;
      c.handle_udp(now, addr0, None, d, w);
    }
    let mut to_r0: Vec<Vec<u8>> = Vec::new();
    while let Some((dst, d)) = r1.0.poll_transmit() {
      if dst == addr0 {
        to_r0.push(d);
      }
    }
    for d in &to_r0 {
      let (c, w, _) = &mut r0;
      c.handle_udp(now, addr1, None, d, w);
    }
    if r1.0.endpoint().state_machine_ref().applied().len() >= 2 {
      delivered = true;
      break;
    }
  }
  assert!(
    delivered,
    "the large op must commit, so the measured sample really did include its blocked-stream retries"
  );
  let phase_spans = r1.0.rx_stream_frames_for_test() - spans_at_phase;
  assert!(
    phase_spans <= (phase_bytes / SHORT) as u64 + 64,
    "carrying a multi-megabyte frame — partial writes and Writable retries included — the receiver's \
     span count must stay proportional to the bytes: {phase_spans} spans for {phase_bytes} B \
     ({worst} short datagrams in the worst entry)"
  );

  // Recovery in the sample: every other datagram to r1 is dropped, so the sender is retransmitting
  // continuously and packing disjoint ranges into single packets. The receiver's span count must
  // stay proportional to the data it actually took, and the link must survive.
  let spans_before = r1.0.rx_stream_frames_for_test();
  let refusals_before = r1
    .0
    .conn_close_count(crate::transport::CloseCause::RecordRejected);
  let mut delivered_bytes = 0usize;
  let mut drop_next = false;
  for k in 0..3_000u64 {
    now = now + Duration::from_millis(1);
    {
      let (c, w, b) = &mut r0;
      c.handle_storage(now, w, b);
      c.handle_timeout(now, w);
      if k % 2 == 0 {
        c.route_message_for_test(now, crate::Recipient::To(p1), &heartbeat);
      }
    }
    {
      let (c, w, b) = &mut r1;
      c.handle_storage(now, w, b);
      c.handle_timeout(now, w);
    }
    let mut to_r1: Vec<Vec<u8>> = Vec::new();
    while let Some((dst, d)) = r0.0.poll_transmit() {
      if dst == addr1 {
        drop_next = !drop_next;
        if drop_next {
          continue;
        }
        to_r1.push(d);
      }
    }
    for d in &to_r1 {
      delivered_bytes += d.len();
      let (c, w, _) = &mut r1;
      c.handle_udp(now, addr0, None, d, w);
    }
    let mut to_r0: Vec<Vec<u8>> = Vec::new();
    while let Some((dst, d)) = r1.0.poll_transmit() {
      if dst == addr0 {
        to_r0.push(d);
      }
    }
    for d in &to_r0 {
      let (c, w, _) = &mut r0;
      c.handle_udp(now, addr1, None, d, w);
    }
  }
  let spans = r1.0.rx_stream_frames_for_test() - spans_before;
  assert_eq!(
    r1.0
      .conn_close_count(crate::transport::CloseCause::RecordRejected),
    refusals_before,
    "50% loss must not walk the receiver into the reassembly ceiling"
  );
  assert!(
    spans > 0 && delivered_bytes > 0,
    "the loss phase must actually have carried traffic: {spans} spans, {delivered_bytes} B"
  );
  // The scope limit, measured rather than asserted: recovery packs disjoint retransmit ranges into
  // whatever packet is going out, so the receiver parses far MORE spans than the new-data ratio
  // would give — which is exactly why the guarantee above is scoped to newly written contiguous
  // data, and why counting datagram lengths would have shown nothing here.
  assert!(
    spans > (delivered_bytes / SHORT) as u64,
    "retransmission recovery must be visible as extra spans — {spans} for {delivered_bytes} B — or \
     this phase is not exercising the case the guarantee excludes"
  );
}

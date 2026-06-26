//! Reconfiguration and peer address book tests for the compio QUIC driver.
//!
//! Reconfiguration gate: a real single-node driver drives a membership change through its own
//! run loop to convergence (`reconfigure_to` → `Ok(())`), and a fail-closed shrink with no live
//! witness times out within its deadline.
//!
//! Address book gate: a driver that receives `AddPeer` commands continues to commit work correctly,
//! and the address book accepts registrations at any point without panicking.

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use rustls::{
  RootCertStore,
  pki_types::{CertificateDer, PrivateKeyDer},
};
use viewstamp_driver::{HealthHint, ReconfigureError};
use viewstamp_proto::{
  BlockAddress, BlockStore, ClusterTls, Event, IdentityConfig, MemberId, Membership,
  MembershipTarget, QuicOptions, ReplicaId, Superblock, Wal,
};
use viewstamp_simulation::{InMemorySuperblock, InMemoryWal};

const CLUSTER: u128 = 0x5151;

/// A throwaway in-memory [`BlockStore`] for the driver tests: the proto's own `MemBlockStore` is
/// crate-private, so each driver instance owns one of these for its state-machine checkpoint blocks
/// (one per replica, persisting for that replica's lifetime, parallel to its superblock).
#[derive(Default)]
struct MemBlocks(std::collections::HashMap<BlockAddress, Bytes>);

impl BlockStore for MemBlocks {
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    self.0.get(&addr).cloned()
  }
  fn write_block(&mut self, addr: BlockAddress, block: Bytes) {
    self.0.insert(addr, block);
  }
  fn has_block(&self, addr: BlockAddress) -> bool {
    self.0.contains_key(&addr)
  }
}

/// A genesis configuration with `replica_count` voters (`MemberId::new(0..replica_count)`) and
/// `learner_count` learners (the next ids), at `config_id = 0` so it mirrors the loopback harness.
/// A single-node test only ever runs the voter in slot 0, which is the view-0 primary.
fn genesis(replica_count: u8, learner_count: u16) -> Membership {
  let total = u128::from(replica_count) + u128::from(learner_count);
  Membership::from_durable_parts(
    viewstamp_proto::Epoch::new(0),
    replica_count,
    learner_count,
    (0..total).map(MemberId::new).collect(),
    0,
  )
  .expect("valid genesis membership")
}

/// A self-signed cluster CA + per-replica leaf certs, mirroring the proto's own `test_ca` /
/// `issue_replica` (same rcgen API, SAN form, EKU/KU): the mandatory cluster mTLS handshake needs it
/// even for a single node that forms no peer connections.
struct TestCa {
  ca_cert: rcgen::Certificate,
  issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl TestCa {
  fn new() -> Self {
    let mut params = rcgen::CertificateParams::new(vec![]).expect("empty SAN for CA is valid");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
    params
      .key_usages
      .push(rcgen::KeyUsagePurpose::DigitalSignature);
    let ca_key = rcgen::KeyPair::generate().expect("CA key pair generation succeeds");
    let ca_cert = params
      .self_signed(&ca_key)
      .expect("self-signed CA cert generation succeeds");
    let issuer = rcgen::Issuer::new(params, ca_key);
    Self { ca_cert, issuer }
  }

  fn roots(&self) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store
      .add(CertificateDer::from(self.ca_cert.der().to_vec()))
      .expect("CA cert parses as a trust anchor");
    store
  }

  fn issue(&self, id: u8) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let san = format!("replica-{id}.{CLUSTER:032x}.viewstamp");
    let mut params =
      rcgen::CertificateParams::new(vec![san]).expect("valid DNS SAN for replica cert");
    params
      .key_usages
      .push(rcgen::KeyUsagePurpose::DigitalSignature);
    params
      .extended_key_usages
      .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    params
      .extended_key_usages
      .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let leaf_key = rcgen::KeyPair::generate().expect("key pair generation succeeds");
    let cert = params
      .signed_by(&leaf_key, &self.issuer)
      .expect("leaf cert signed by cluster CA");
    let chain = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::try_from(leaf_key.serialize_der())
      .expect("leaf key serialises as a valid private key DER");
    (chain, key)
  }
}

/// Wraps an in-memory store and signals the storage-ready notifier on every submit, so the driver
/// re-pumps. (A real async store signals on completion; the synchronous in-memory store completes on
/// submit, so it signals there.)
struct Notifying<T> {
  inner: T,
  ready: flume::Sender<()>,
}
impl<T> Notifying<T> {
  fn new(inner: T, ready: flume::Sender<()>) -> Self {
    Self { inner, ready }
  }
  fn signal(&self) {
    let _ = self.ready.try_send(());
  }
}
impl<T: Wal> Wal for Notifying<T> {
  fn op_head(&self) -> viewstamp_proto::OpNumber {
    self.inner.op_head()
  }
  fn header(&self, op: viewstamp_proto::OpNumber) -> Option<viewstamp_proto::Header> {
    self.inner.header(op)
  }
  fn status(&self, op: viewstamp_proto::OpNumber) -> viewstamp_proto::SlotStatus {
    self.inner.status(op)
  }
  fn capacity(&self) -> u64 {
    self.inner.capacity()
  }
  fn submit_append(
    &mut self,
    id: viewstamp_proto::OpId,
    op: viewstamp_proto::OpNumber,
    h: viewstamp_proto::Header,
    b: bytes::Bytes,
  ) {
    self.inner.submit_append(id, op, h, b);
    self.signal();
  }
  fn submit_read(&mut self, id: viewstamp_proto::OpId, op: viewstamp_proto::OpNumber) {
    self.inner.submit_read(id, op);
    self.signal();
  }
  fn truncate(&mut self, above: viewstamp_proto::OpNumber) {
    self.inner.truncate(above);
  }
  fn prune(&mut self, below: viewstamp_proto::OpNumber) {
    self.inner.prune(below);
  }
  fn poll(&mut self) -> Option<viewstamp_proto::WalDone> {
    self.inner.poll()
  }
}
impl<T: Superblock> Superblock for Notifying<T> {
  fn state(&self) -> viewstamp_proto::VsrState {
    self.inner.state()
  }
  fn submit_write(&mut self, id: viewstamp_proto::OpId, s: viewstamp_proto::VsrState) {
    self.inner.submit_write(id, s);
    self.signal();
  }
  fn submit_write_checkpoint(
    &mut self,
    id: viewstamp_proto::OpId,
    op: viewstamp_proto::OpNumber,
    snap: bytes::Bytes,
  ) {
    self.inner.submit_write_checkpoint(id, op, snap);
    self.signal();
  }
  fn submit_read_checkpoint(&mut self, id: viewstamp_proto::OpId) {
    self.inner.submit_read_checkpoint(id);
    self.signal();
  }
  fn poll(&mut self) -> Option<viewstamp_proto::SuperblockDone> {
    self.inner.poll()
  }
}

type GateDriver = viewstamp_compio::CompioQuicDriver<
  viewstamp_simulation::sm::LogSm,
  Notifying<InMemoryWal>,
  Notifying<InMemorySuperblock>,
  MemBlocks,
  viewstamp_proto::ProvidedIdentity,
>;

/// Build a single-node driver (slot 0, no peers) over `membership` and `cfg`, and return it with its
/// `Handle`. Slot 0 is the view-0 primary; a single voter self-commits at quorum 1.
async fn build_driver(
  ca: &TestCa,
  bind: SocketAddr,
  membership: Membership,
  cfg: viewstamp_compio::DriverConfig,
) -> (GateDriver, viewstamp_compio::Handle) {
  let (chain, key) = ca.issue(0);
  let opts: QuicOptions = viewstamp_proto::ClusterTls::new(ca.roots(), chain, key).build();
  let config = viewstamp_proto::Config::try_new(CLUSTER, MemberId::new(0)).unwrap();
  let (ready_tx, ready_rx) = flume::unbounded();
  let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
  let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  let blocks = MemBlocks::default();
  GateDriver::with_config(
    config,
    membership,
    viewstamp_simulation::sm::LogSm::default(),
    wal,
    sb,
    blocks,
    viewstamp_proto::ClientId::new(1),
    0,
    opts,
    IdentityConfig::Hello { cluster: CLUSTER },
    Some([0u8; 32]),
    bind,
    Vec::new(), // no peers: a single-voter cluster self-commits at quorum 1
    ready_rx,
    cfg,
  )
  .await
  .expect("driver builds")
}

/// Build a driver for a multi-node cluster node, dialing the given peers.
async fn build_cluster_driver(
  ca: &TestCa,
  id: u8,
  bind: SocketAddr,
  peers: Vec<(ReplicaId, SocketAddr)>,
  membership: Membership,
) -> (GateDriver, viewstamp_compio::Handle) {
  let (chain, key) = ca.issue(id);
  let opts: QuicOptions = ClusterTls::new(ca.roots(), chain, key).build();
  let config = viewstamp_proto::Config::try_new(CLUSTER, MemberId::new(u128::from(id))).unwrap();
  let (ready_tx, ready_rx) = flume::unbounded();
  let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
  let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  let blocks = MemBlocks::default();
  viewstamp_compio::CompioQuicDriver::new(
    config,
    membership,
    viewstamp_simulation::sm::LogSm::default(),
    wal,
    sb,
    blocks,
    viewstamp_proto::ClientId::new(u128::from(id) + 1),
    0,
    opts,
    IdentityConfig::Hello { cluster: CLUSTER },
    Some([id; 32]),
    bind,
    peers,
    ready_rx,
  )
  .await
  .expect("driver builds")
}

/// CONVERGENCE: a single-node driver drives a real membership change to completion through its own
/// run loop. Genesis is one voter (slot 0) plus a learner; the target adds a SECOND learner, so the
/// plan is a single `AddLearner` — admitted on the primary, self-committed at quorum 1, and installed
/// via the durable epoch swap. The whole driver stack carries it: the run loop's storage pump commits
/// the op, `advance_reconfigure` detects the successor's `config_id` becoming live and resolves the
/// executor, and `reconfigure_to` returns `Ok(())`. The installed `MembershipChanged` event names the
/// successor epoch (1), the witness that the change genuinely committed + installed.
#[compio::test]
async fn single_node_reconfigure_converges_ok() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41220".parse().unwrap();
  // Genesis: voter 0 + learner 1. Target: voter 0 + learners {1, 2} (an AddLearner(2) plan).
  let (driver, handle) = build_driver(
    &ca,
    bind,
    genesis(1, 1),
    viewstamp_compio::DriverConfig::new(),
  )
  .await;
  let events = handle.events();
  compio::runtime::spawn(driver.run()).detach();

  let target = MembershipTarget::new(
    std::collections::BTreeSet::from([MemberId::new(0)]),
    std::collections::BTreeSet::from([MemberId::new(1), MemberId::new(2)]),
  );
  compio::time::timeout(
    Duration::from_secs(10),
    handle.reconfigure_to(target, HealthHint::default()),
  )
  .await
  .expect("the reconfiguration converges within 10s")
  .expect("reconfigure_to resolves Ok once the membership reaches the target");

  // The committed change installed its epoch swap: a `MembershipChanged` to epoch 1 was observed
  // (the durable witness that the AddLearner committed + installed on the single voter).
  let mut saw_epoch_1 = false;
  while let Ok(event) = events.try_recv() {
    if let Event::MembershipChanged(m) = event
      && m.epoch().get() == 1
    {
      saw_epoch_1 = true;
    }
  }
  assert!(
    saw_epoch_1,
    "the installed swap advanced the membership to epoch 1 (the AddLearner committed + installed)"
  );

  let _ = handle.shutdown().await;
}

/// SHRINK STALL → TIMEOUT: a shrink with NO positive liveness evidence fails closed and the call
/// resolves `Timeout` once its deadline elapses. Genesis is two voters; only slot 0's node runs (no
/// peer), the cluster is idle (the automatic ack oracle is empty), and `HealthHint::default()` offers
/// no operator witness — so the executor's quorum-preserving removal picker can confirm no successor
/// quorum and stalls rather than removing on a guess. With nothing ever committing, only the
/// deadline-driven `cap_exhausted` ends the call: a short `reconfigure_timeout` makes the
/// `ReconfigureError::Timeout` fire promptly. This is the regression for the deadline path (a
/// hardwired `cap_exhausted = false` would hang here forever).
#[compio::test]
async fn single_node_shrink_with_no_witness_times_out() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41230".parse().unwrap();
  // A short deadline so the fail-closed stall resolves Timeout quickly.
  let cfg = viewstamp_compio::DriverConfig::new().with_reconfigure_timeout(Duration::from_secs(1));
  // Genesis: voters {0, 1}; only node 0 runs. Target: drop voter 1 (a RemoveVoter shrink).
  let (driver, handle) = build_driver(&ca, bind, genesis(2, 0), cfg).await;
  compio::runtime::spawn(driver.run()).detach();

  let target = MembershipTarget::new(
    std::collections::BTreeSet::from([MemberId::new(0)]),
    std::collections::BTreeSet::new(),
  );
  // Idle cluster + default hint = no positive successor-quorum evidence: the shrink stalls, and only
  // the deadline ends it. Generously bound the test wait above the 1s deadline.
  let outcome = compio::time::timeout(
    Duration::from_secs(10),
    handle.reconfigure_to(target, HealthHint::default()),
  )
  .await
  .expect("the call resolves (Timeout) well within 10s — it does not hang");
  assert!(
    matches!(outcome, Err(ReconfigureError::Timeout(_))),
    "a fail-closed shrink with no witness resolves Timeout once the deadline elapses, got {outcome:?}"
  );

  let _ = handle.shutdown().await;
}

/// LATE `add_peer` DIALS AN ALREADY-PRESENT MEMBER: a 2-voter genesis where member 1 is in the
/// membership from the start, but neither node knows the other's address at construction (both are
/// built with an EMPTY initial peer list). With no peers and no membership change, neither node ever
/// dials, so the mesh never forms and the 2-voter cluster cannot reach quorum — a commit at the
/// primary (member 0) would hang forever.
///
/// The only thing that can break the deadlock is the late `add_peer(member 1, addr1)` at node 0:
/// because member 1 is ALREADY in the live membership, the driver must rebuild its dial list against
/// the CURRENT config immediately (not wait for some later, unrelated membership change) so it dials
/// member 1 now. node 1 accepts that dial, the mutual mesh edge forms, quorum-2 is reached, and the
/// commit lands. Before the fix, `add_peer` only populated the address book and node 0 never dialed,
/// so this commit would time out.
#[compio::test]
async fn late_add_peer_dials_an_already_present_member() {
  let ca = TestCa::new();
  let addr0: SocketAddr = "127.0.0.1:41700".parse().unwrap();
  let addr1: SocketAddr = "127.0.0.1:41701".parse().unwrap();

  // Both nodes start with NO peers: member 1 is in genesis(2,0) but its address is unknown to node 0
  // (and node 0's is unknown to node 1), so nothing is dialed at startup and the mesh is absent.
  let (driver0, handle0) = build_cluster_driver(&ca, 0, addr0, Vec::new(), genesis(2, 0)).await;
  // Keep node 1's handle alive for the whole test: dropping the last handle ends its run loop (the
  // command channel closes), which would kill the peer the quorum depends on.
  let (driver1, handle1) = build_cluster_driver(&ca, 1, addr1, Vec::new(), genesis(2, 0)).await;
  compio::runtime::spawn(driver0.run()).detach();
  compio::runtime::spawn(driver1.run()).detach();

  // The late registration: member 1 is already in the membership, so this must trigger an immediate
  // dial of member 1 from node 0, forming the mesh edge a 2-voter quorum needs.
  handle0
    .add_peer(MemberId::new(1), addr1)
    .expect("the address update enqueues on a live driver");

  // A commit at the primary (member 0) requires quorum 2, which can only be reached once node 0 dials
  // member 1 in response to the `add_peer`. Convergence within the deadline IS the assertion.
  let reply = compio::time::timeout(
    Duration::from_secs(20),
    handle0.submit(Bytes::from_static(b"late-add-peer")),
  )
  .await
  .expect("the commit lands within 20s once the late add_peer dials member 1 and quorum forms")
  .expect("a committed reply");
  assert_eq!(
    &reply[..],
    &1u64.to_be_bytes(),
    "the first committed op replies the post-apply count 1 (the mesh formed via the late dial)"
  );

  let _ = handle0.shutdown().await;
  let _ = handle1.shutdown().await;
}

/// ADDRESS BOOK DOES NOT DISRUPT NORMAL COMMITS: a 3-node cluster with `add_peer` called for each
/// peer's address before the cluster starts (simulating the embedder pre-registering addresses for
/// future membership changes) continues to commit client requests normally. The `add_peer` commands
/// populate the peer_book but leave the initial `peers` mesh unchanged; the cluster commits one
/// request, proving no regression in the hot path.
#[compio::test]
async fn add_peer_does_not_disrupt_a_running_cluster() {
  let ca = TestCa::new();
  let addrs: Vec<SocketAddr> = (0..3)
    .map(|i: u16| format!("127.0.0.1:{}", 41600 + i).parse().unwrap())
    .collect();
  let rid = |i: u8| ReplicaId::new(i as u16);
  let mid = |i: u8| MemberId::new(i as u128);

  let mut handles = Vec::new();
  for id in 0u8..3 {
    let peers: Vec<_> = (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (rid(p), addrs[p as usize]))
      .collect();
    let (driver, handle) =
      build_cluster_driver(&ca, id, addrs[id as usize], peers, genesis(3, 0)).await;
    // Pre-register all peer addresses in the address book before the cluster is fully up.
    // This simulates an embedder that calls add_peer for every potential future member.
    for peer_id in 0u8..3 {
      if peer_id != id {
        handle
          .add_peer(mid(peer_id), addrs[peer_id as usize])
          .expect("the address update enqueues on a fresh driver");
      }
    }
    compio::runtime::spawn(driver.run()).detach();
    handles.push(handle);
  }

  // Commit one request through the view-0 primary (replica 0).
  let reply = compio::time::timeout(
    std::time::Duration::from_secs(10),
    handles[0].submit(Bytes::from_static(b"after-add-peer")),
  )
  .await
  .expect("commit within 10s after add_peer calls")
  .expect("a committed reply");
  // LogSm::apply returns the post-apply count as 8 big-endian bytes; first op = 1.
  assert_eq!(&reply[..], &1u64.to_be_bytes());

  for h in &handles {
    let _ = h.shutdown().await;
  }
}

/// ADDRESS BOOK ACCEPTS REGISTRATIONS BEFORE THE DRIVER IS UP AND AFTER: `add_peer` is non-blocking
/// and idempotent from the caller's side — it must not panic regardless of when it is called (before
/// the driver loop drains it, during a live run, or even after the driver has shut down). While the
/// driver is live (buffer not yet drained, or running) the update enqueues `Ok`; once the driver has
/// stopped the channel is closed and `add_peer` REPORTS `DriverGone` rather than dropping silently,
/// so a caller learns the update did not land. This test builds a single-node driver (never commits,
/// no peers), calls `add_peer` before and after the driver starts, then shuts down cleanly and
/// asserts the post-shutdown call surfaces the closed-channel error.
#[compio::test]
async fn add_peer_is_non_blocking_and_does_not_panic() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41630".parse().unwrap();
  // No initial peers: single-node, never forms a quorum.
  let (driver, handle) = build_driver(
    &ca,
    bind,
    genesis(1, 0),
    viewstamp_compio::DriverConfig::new(),
  )
  .await;

  // Call add_peer before the driver loop starts: the command sits in the channel buffer until the
  // run loop drains it, so the enqueue succeeds.
  handle
    .add_peer(MemberId::new(1), "127.0.0.1:41631".parse().unwrap())
    .expect("enqueues into the channel buffer before the loop drains it");
  handle
    .add_peer(MemberId::new(2), "127.0.0.1:41632".parse().unwrap())
    .expect("a second pre-start registration enqueues");
  // Duplicate add_peer for the same member — must be idempotent (last write wins in the book).
  handle
    .add_peer(MemberId::new(1), "127.0.0.1:41633".parse().unwrap())
    .expect("a duplicate registration enqueues (last write wins in the book)");

  compio::runtime::spawn(driver.run()).detach();

  // Call add_peer while the driver is live.
  handle
    .add_peer(MemberId::new(3), "127.0.0.1:41634".parse().unwrap())
    .expect("a registration on a live driver enqueues");

  compio::time::timeout(std::time::Duration::from_secs(5), handle.shutdown())
    .await
    .expect("shutdown acks within 5s")
    .expect("driver acks shutdown");

  // After the driver has stopped, add_peer must not panic — and the closed channel is now REPORTED
  // as DriverGone (the update did not land), not dropped silently.
  match handle.add_peer(MemberId::new(4), "127.0.0.1:41635".parse().unwrap()) {
    Err(viewstamp_driver::DriverError::DriverGone) => {}
    other => panic!("expected DriverGone after shutdown, got {other:?}"),
  }
}

/// SLOT-SHIFT REGRESSION (TCP/TLS stream transport): a real 4-voter cluster over `Labeled<Passthrough>`
/// commits a baseline request, then removes a voter whose departure SHIFTS the surviving members to new
/// slots, and must still commit a post-reconfiguration request THROUGH a shifted node.
///
/// The `Labeled` handshake now attests each peer by its stable [`MemberId`] (the full u128), not by its
/// SLOT, so a conn keeps its stable identity across a reconfiguration that renumbers slots; the
/// coordinator's `reconcile_routing` re-resolves each conn's attested member to its NEW slot and closes
/// only the conns whose member genuinely moved (which then re-bind under the new slot on the next
/// handshake). Genesis is voters {0,1,2,3} at slots {0,1,2,3}; the primary (member 0) proposes
/// `RemoveVoter(1)`, leaving voters {0,2,3} at slots {0,1,2} — members 2 and 3 each shift DOWN one slot.
/// The post-reconfiguration commit is submitted at member 3 (now at slot 2, shifted from slot 3): it can
/// only converge if member 3's mesh conns re-resolved to the survivors' new slots, which is exactly the
/// stable-id routing the handshake redesign provides. A regression to slot-attestation routing strands
/// the shifted conns and the second commit times out.
#[compio::test]
async fn stream_cluster_survives_slot_shift() {
  use std::{collections::BTreeSet, rc::Rc};

  use viewstamp_proto::{Conn, LabelOptions, Labeled, Passthrough, Peer};

  const STREAM_CLUSTER: u128 = 0x5252;

  // Self-attesting factories: each node announces its OWN stable MemberId in the `Labeled` handshake
  // (matching its `Config::member`), so a peer binds it by stable id and the coordinator resolves that
  // id to whatever slot the member currently occupies.
  let mk_dialer = |me: u8| -> Rc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>>> {
    Rc::new(move |_peer| {
      let opts = LabelOptions::new(STREAM_CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Rc<dyn Fn() -> Conn<Labeled<Passthrough>>> {
    Rc::new(move || {
      let opts = LabelOptions::new(STREAM_CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };

  let base_port: u16 = 46000;
  let addrs: Vec<SocketAddr> = (0..4)
    .map(|i| format!("127.0.0.1:{}", base_port + i).parse().unwrap())
    .collect();

  let mut handles = Vec::new();
  for id in 0u8..4 {
    let peers: Vec<_> = (0u8..4)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect();
    let config =
      viewstamp_proto::Config::try_new(STREAM_CLUSTER, MemberId::new(id as u128)).unwrap();
    let (ready_tx, ready_rx) = flume::unbounded();
    let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
    let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
    let blocks = MemBlocks::default();
    let (driver, handle) = viewstamp_compio::CompioStreamDriver::new(
      config,
      genesis(4, 0),
      viewstamp_simulation::sm::LogSm::default(),
      wal,
      sb,
      blocks,
      viewstamp_proto::ClientId::new(u128::from(id) + 1),
      0,
      addrs[id as usize],
      peers,
      mk_dialer(id),
      mk_acceptor(id),
      ready_rx,
    )
    .await
    .expect("stream driver builds");
    compio::runtime::spawn(driver.run()).detach();
    handles.push(handle);
  }

  // BASELINE: a committed request through member 0 (the view-0 primary at slot 0) proves the 4-voter
  // mesh formed and converges over real TCP before any reconfiguration.
  let reply = compio::time::timeout(
    Duration::from_secs(20),
    handles[0].submit(Bytes::from_static(b"pre-shift")),
  )
  .await
  .expect("the baseline commit lands within 20s")
  .expect("a baseline reply");
  assert_eq!(
    &reply[..],
    &1u64.to_be_bytes(),
    "the first committed op replies the post-apply count 1"
  );

  // RECONFIGURE: the primary (member 0) drives the removal of voter 1, leaving voters {0,2,3} at slots
  // {0,1,2}. `known_up = {0,2,3}` is the operator's positive witness that the successor quorum is live,
  // so the quorum-preserving removal picker confirms it rather than fail-closed stalling.
  let target = MembershipTarget::new(
    BTreeSet::from([MemberId::new(0), MemberId::new(2), MemberId::new(3)]),
    BTreeSet::new(),
  );
  let health = HealthHint {
    known_up: BTreeSet::from([MemberId::new(0), MemberId::new(2), MemberId::new(3)]),
    known_down: BTreeSet::new(),
  };
  compio::time::timeout(
    Duration::from_secs(20),
    handles[0].reconfigure_to(target, health),
  )
  .await
  .expect("the reconfiguration converges within 20s")
  .expect("reconfigure_to resolves Ok once voter 1 is removed and the slots shift");

  // POST-SHIFT: a request submitted at member 3 — now at slot 2 (shifted DOWN from slot 3) — must still
  // commit. It relays to the primary over the mesh, so its convergence proves member 3's conns
  // re-resolved to the survivors' NEW slots; under slot-attestation routing the shifted conns would
  // strand and this would time out. The reply is the post-apply count 2 (the second committed op).
  let reply = compio::time::timeout(
    Duration::from_secs(20),
    handles[3].submit(Bytes::from_static(b"post-shift")),
  )
  .await
  .expect("the post-shift commit lands within 20s through the slot-shifted node")
  .expect("a post-shift reply");
  assert_eq!(
    &reply[..],
    &2u64.to_be_bytes(),
    "the second committed op replies the post-apply count 2 (routing survived the slot shift)"
  );

  for h in &handles {
    let _ = h.shutdown().await;
  }
}

/// QUIC TLS SNI SLOT-SHIFT REGRESSION: a 4-voter cluster over real mTLS QUIC removes a low-slot
/// voter so retained members shift slots, then commits a second request THROUGH a shifted member.
///
/// Genesis is voters {0,1,2,3} at slots {0,1,2,3}. The primary (member 0) proposes `RemoveVoter(1)`,
/// leaving voters {0,2,3} at slots {0,1,2} — members 2 and 3 each shift DOWN one slot. The
/// post-reconfiguration commit is submitted at member 3 (now at slot 2, shifted from slot 3): it
/// succeeds only if member 3 can reconnect to its peers after the slot shift.
///
/// Before the `sni_for` fix, `connect` derived the SNI from the routing slot (`replica-1`) while
/// member 2's cert SAN was minted per stable identity (`replica-2`). The stock `WebPkiServerVerifier`
/// rejected the mismatch BEFORE the `CertOid` attestation ran, so the shifted member could never
/// reconnect and the second commit timed out.
#[compio::test]
async fn quic_cluster_survives_slot_shift() {
  use std::collections::BTreeSet;

  const QUIC_CLUSTER: u128 = 0x5353;
  let base_port: u16 = 46100;

  struct QuicTestCa {
    ca_cert: rcgen::Certificate,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
  }
  impl QuicTestCa {
    fn new() -> Self {
      let mut params = rcgen::CertificateParams::new(vec![]).expect("empty SAN for CA is valid");
      params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
      params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
      params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
      let ca_key = rcgen::KeyPair::generate().expect("CA key pair generation succeeds");
      let ca_cert = params
        .self_signed(&ca_key)
        .expect("self-signed CA cert generation succeeds");
      let issuer = rcgen::Issuer::new(params, ca_key);
      Self { ca_cert, issuer }
    }
    fn roots(&self) -> rustls::RootCertStore {
      let mut store = rustls::RootCertStore::empty();
      store
        .add(rustls::pki_types::CertificateDer::from(
          self.ca_cert.der().to_vec(),
        ))
        .expect("CA cert parses as a trust anchor");
      store
    }
    /// Issue a cert whose SAN is keyed to the STABLE member id (not the slot), matching the form
    /// `ClusterTls` uses: `replica-<member_id>.<cluster-hex>.viewstamp`.
    fn issue(
      &self,
      member_id: u8,
    ) -> (
      Vec<rustls::pki_types::CertificateDer<'static>>,
      rustls::pki_types::PrivateKeyDer<'static>,
    ) {
      let san = format!("replica-{member_id}.{QUIC_CLUSTER:032x}.viewstamp");
      let mut params =
        rcgen::CertificateParams::new(vec![san]).expect("valid DNS SAN for replica cert");
      params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
      params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
      params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
      let leaf_key = rcgen::KeyPair::generate().expect("key pair generation succeeds");
      let cert = params
        .signed_by(&leaf_key, &self.issuer)
        .expect("leaf cert signed by cluster CA");
      let chain = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
      let key = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
        .expect("leaf key serialises as a valid private key DER");
      (chain, key)
    }
  }

  let qca = QuicTestCa::new();
  let addrs: Vec<SocketAddr> = (0..4)
    .map(|i| format!("127.0.0.1:{}", base_port + i).parse().unwrap())
    .collect();

  let mut handles = Vec::new();
  for id in 0u8..4 {
    let peers: Vec<_> = (0u8..4)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect();
    let (chain, key) = qca.issue(id);
    let opts: QuicOptions = ClusterTls::new(qca.roots(), chain, key).build();
    let config = viewstamp_proto::Config::try_new(QUIC_CLUSTER, MemberId::new(id as u128)).unwrap();
    let (ready_tx, ready_rx) = flume::unbounded();
    let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
    let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
    let blocks = MemBlocks::default();
    let (driver, handle) = viewstamp_compio::CompioQuicDriver::new(
      config,
      genesis(4, 0),
      viewstamp_simulation::sm::LogSm::default(),
      wal,
      sb,
      blocks,
      viewstamp_proto::ClientId::new(u128::from(id) + 1),
      0,
      opts,
      viewstamp_proto::IdentityConfig::Hello {
        cluster: QUIC_CLUSTER,
      },
      Some([id; 32]),
      addrs[id as usize],
      peers,
      ready_rx,
    )
    .await
    .expect("QUIC driver builds");
    compio::runtime::spawn(driver.run()).detach();
    handles.push(handle);
  }

  // BASELINE: prove the 4-voter QUIC mesh formed and converges over real mTLS.
  let reply = compio::time::timeout(
    Duration::from_secs(20),
    handles[0].submit(Bytes::from_static(b"pre-shift")),
  )
  .await
  .expect("the baseline commit lands within 20s")
  .expect("a baseline reply");
  assert_eq!(
    &reply[..],
    &1u64.to_be_bytes(),
    "the first committed op replies the post-apply count 1"
  );

  // RECONFIGURE: remove voter 1, shifting members 2→slot 1 and 3→slot 2.
  let target = MembershipTarget::new(
    BTreeSet::from([MemberId::new(0), MemberId::new(2), MemberId::new(3)]),
    BTreeSet::new(),
  );
  let health = HealthHint {
    known_up: BTreeSet::from([MemberId::new(0), MemberId::new(2), MemberId::new(3)]),
    known_down: BTreeSet::new(),
  };
  compio::time::timeout(
    Duration::from_secs(20),
    handles[0].reconfigure_to(target, health),
  )
  .await
  .expect("the reconfiguration converges within 20s")
  .expect("reconfigure_to resolves Ok once voter 1 is removed and slots shift");

  // POST-SHIFT: submit at member 3 (now slot 2). Convergence requires that member 3 redialed its
  // peers with SNI `replica-<MemberId>` (not `replica-<slot>`), so the mTLS handshake succeeds.
  let reply = compio::time::timeout(
    Duration::from_secs(20),
    handles[3].submit(Bytes::from_static(b"post-shift")),
  )
  .await
  .expect("the post-shift QUIC commit lands within 20s through the slot-shifted node")
  .expect("a post-shift reply");
  assert_eq!(
    &reply[..],
    &2u64.to_be_bytes(),
    "the second committed op replies the post-apply count 2 (QUIC mTLS survived the slot shift)"
  );

  for h in &handles {
    let _ = h.shutdown().await;
  }
}

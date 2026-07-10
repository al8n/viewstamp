//! Reconfiguration and peer address book tests for the reactor (tokio) QUIC driver.
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

type GateDriver = viewstamp_reactor::ReactorQuicDriver<
  agnostic::tokio::TokioRuntime,
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
  cfg: viewstamp_reactor::DriverConfig,
) -> (GateDriver, viewstamp_reactor::Handle) {
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
    IdentityConfig::Hello(CLUSTER),
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
) -> (GateDriver, viewstamp_reactor::Handle) {
  let (chain, key) = ca.issue(id);
  let opts: QuicOptions = ClusterTls::new(ca.roots(), chain, key).build();
  let config = viewstamp_proto::Config::try_new(CLUSTER, MemberId::new(u128::from(id))).unwrap();
  let (ready_tx, ready_rx) = flume::unbounded();
  let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
  let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  let blocks = MemBlocks::default();
  GateDriver::new(
    config,
    membership,
    viewstamp_simulation::sm::LogSm::default(),
    wal,
    sb,
    blocks,
    viewstamp_proto::ClientId::new(u128::from(id) + 1),
    0,
    opts,
    IdentityConfig::Hello(CLUSTER),
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_node_reconfigure_converges_ok() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41200".parse().unwrap();
  // Genesis: voter 0 + learner 1. Target: voter 0 + learners {1, 2} (an AddLearner(2) plan).
  let (driver, handle) = build_driver(
    &ca,
    bind,
    genesis(1, 1),
    viewstamp_reactor::DriverConfig::new(),
  )
  .await;
  let events = handle.events();
  drop(tokio::spawn(driver.run()));

  let target = MembershipTarget::new(
    std::collections::BTreeSet::from([MemberId::new(0)]),
    std::collections::BTreeSet::from([MemberId::new(1), MemberId::new(2)]),
  );
  tokio::time::timeout(
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_node_shrink_with_no_witness_times_out() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41210".parse().unwrap();
  // A short deadline so the fail-closed stall resolves Timeout quickly.
  let cfg = viewstamp_reactor::DriverConfig::new().with_reconfigure_timeout(Duration::from_secs(1));
  // Genesis: voters {0, 1}; only node 0 runs. Target: drop voter 1 (a RemoveVoter shrink).
  let (driver, handle) = build_driver(&ca, bind, genesis(2, 0), cfg).await;
  drop(tokio::spawn(driver.run()));

  let target = MembershipTarget::new(
    std::collections::BTreeSet::from([MemberId::new(0)]),
    std::collections::BTreeSet::new(),
  );
  // Idle cluster + default hint = no positive successor-quorum evidence: the shrink stalls, and only
  // the deadline ends it. Generously bound the test wait above the 1s deadline.
  let outcome = tokio::time::timeout(
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

/// ADDRESS BOOK DOES NOT DISRUPT NORMAL COMMITS (reactor variant): a 3-node cluster with `add_peer`
/// called for each peer's address before the cluster starts continues to commit client requests
/// normally. The `add_peer` commands populate the peer_book without touching the initial peer mesh;
/// the cluster commits one request, proving no regression in the hot path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_peer_does_not_disrupt_a_running_cluster() {
  let ca = TestCa::new();
  let addrs: Vec<SocketAddr> = (0..3)
    .map(|i: u16| format!("127.0.0.1:{}", 41700 + i).parse().unwrap())
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
    // Pre-register all peer addresses in the address book.
    for peer_id in 0u8..3 {
      if peer_id != id {
        handle
          .add_peer(mid(peer_id), addrs[peer_id as usize])
          .expect("the address update enqueues on a fresh driver");
      }
    }
    // The dropped JoinHandle DETACHES the task (tokio drop never cancels).
    drop(tokio::spawn(driver.run()));
    handles.push(handle);
  }

  let reply = tokio::time::timeout(
    std::time::Duration::from_secs(10),
    handles[0].submit(Bytes::from_static(b"after-add-peer")),
  )
  .await
  .expect("commit within 10s after add_peer calls")
  .expect("a committed reply");
  assert_eq!(&reply[..], &1u64.to_be_bytes());

  for h in &handles {
    let _ = h.shutdown().await;
  }
}

/// ADDRESS BOOK ACCEPTS REGISTRATIONS BEFORE AND AFTER THE DRIVER RUNS (reactor variant): `add_peer`
/// is non-blocking and idempotent from the caller's side — it must not panic regardless of timing.
/// While the driver is live the update enqueues `Ok`; once it has stopped the closed channel is
/// REPORTED as `DriverGone` (the update did not land), not dropped silently. A single-node driver
/// receives `add_peer` commands before, during, and after its run loop; the shutdown ack proves no
/// regression in the teardown path, and the post-shutdown call surfaces the closed-channel error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_peer_is_non_blocking_and_does_not_panic() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41730".parse().unwrap();
  let (driver, handle) = build_driver(
    &ca,
    bind,
    genesis(1, 0),
    viewstamp_reactor::DriverConfig::new(),
  )
  .await;

  // Register peers before the loop starts.
  handle
    .add_peer(MemberId::new(1), "127.0.0.1:41731".parse().unwrap())
    .expect("enqueues into the channel buffer before the loop drains it");
  handle
    .add_peer(MemberId::new(2), "127.0.0.1:41732".parse().unwrap())
    .expect("a second pre-start registration enqueues");
  // Duplicate: last write wins in the book.
  handle
    .add_peer(MemberId::new(1), "127.0.0.1:41733".parse().unwrap())
    .expect("a duplicate registration enqueues (last write wins in the book)");

  drop(tokio::spawn(driver.run()));

  // Register a peer while the driver is live.
  handle
    .add_peer(MemberId::new(3), "127.0.0.1:41734".parse().unwrap())
    .expect("a registration on a live driver enqueues");

  tokio::time::timeout(std::time::Duration::from_secs(5), handle.shutdown())
    .await
    .expect("shutdown acks within 5s")
    .expect("driver acks shutdown");

  // After the driver has stopped, add_peer must not panic — and the closed channel is now REPORTED
  // as DriverGone (the update did not land), not dropped silently.
  match handle.add_peer(MemberId::new(4), "127.0.0.1:41735".parse().unwrap()) {
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
/// The post-reconfiguration commit is submitted at the primary (member 0): committing it requires a
/// PrepareOk quorum from the SHIFTED successor voter set, so its success proves the primary's mesh conns
/// to the shifted backups re-resolved to their NEW slots — exactly the stable-id routing the handshake
/// redesign provides. A regression to slot-attestation routing strands the shifted conns and the second
/// commit times out. (The compio gate submits the post-shift op at the shifted backup itself, the
/// stronger reply-to-shifted-backup direction.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_cluster_survives_slot_shift() {
  use std::{collections::BTreeSet, sync::Arc};

  use viewstamp_proto::{Conn, LabelOptions, Labeled, Passthrough, Peer};

  const STREAM_CLUSTER: u128 = 0x5252;

  // Self-attesting factories: each node announces its OWN stable MemberId in the `Labeled` handshake
  // (matching its `Config::member`), so a peer binds it by stable id and the coordinator resolves that
  // id to whatever slot the member currently occupies.
  let mk_dialer = |me: u8| -> Arc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move |_peer| {
      let opts = LabelOptions::new(STREAM_CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Arc<dyn Fn() -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move || {
      let opts = LabelOptions::new(STREAM_CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };

  // Reserve kernel-assigned TCP ports (bind port-0 listeners, read the addresses, drop them):
  // fresh ephemeral ports per process keep repeated runs of this binary (CI runs it once per cargo
  // feature combination, back-to-back) from colliding with the previous run's TIME_WAIT connection
  // remnants. (The QUIC tests keep fixed ports: UDP has no TIME_WAIT.)
  let reservations: Vec<std::net::TcpListener> = (0..4)
    .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a loopback port"))
    .collect();
  let addrs: Vec<SocketAddr> = reservations
    .iter()
    .map(|l| l.local_addr().expect("reserved listener has an address"))
    .collect();
  drop(reservations);

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
    let (driver, handle) = viewstamp_reactor::ReactorStreamDriver::<
      agnostic::tokio::TokioRuntime,
      viewstamp_simulation::sm::LogSm,
      Labeled<Passthrough>,
      Notifying<InMemoryWal>,
      Notifying<InMemorySuperblock>,
      MemBlocks,
    >::new(
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
    // The dropped JoinHandle DETACHES the task (a tokio drop never cancels), so each node's run loop
    // keeps driving on its own.
    drop(tokio::spawn(driver.run()));
    handles.push(handle);
  }

  // BASELINE: a committed request through member 0 (the view-0 primary at slot 0) proves the 4-voter
  // mesh formed and converges over real TCP before any reconfiguration.
  let reply = tokio::time::timeout(
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
  let health = HealthHint::new().with_known_up(BTreeSet::from([
    MemberId::new(0),
    MemberId::new(2),
    MemberId::new(3),
  ]));
  tokio::time::timeout(
    Duration::from_secs(20),
    handles[0].reconfigure_to(target, health),
  )
  .await
  .expect("the reconfiguration converges within 20s")
  .expect("reconfigure_to resolves Ok once voter 1 is removed and the slots shift");

  // POST-SHIFT: a request committed at the primary (member 0) must reach a PrepareOk quorum from the
  // SHIFTED successor voter set {0,2,3} (members 2,3 now at slots 1,2). Its success proves the primary's
  // mesh conns to the shifted backups re-resolved to their NEW slots; under slot-attestation routing the
  // shifted conns would strand and the prepare could never reach a quorum, so this would time out. The
  // reply is the post-apply count 2 (the second committed op).
  let reply = tokio::time::timeout(
    Duration::from_secs(20),
    handles[0].submit(Bytes::from_static(b"post-shift")),
  )
  .await
  .expect("the post-shift commit lands within 20s after the slot shift")
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

/// QUIC TLS SNI SLOT-SHIFT REGRESSION (reactor variant): a 4-voter cluster over real mTLS QUIC
/// removes a low-slot voter so retained members shift slots, then commits a second request THROUGH
/// a shifted member.
///
/// Genesis is voters {0,1,2,3} at slots {0,1,2,3}. The primary (member 0) proposes `RemoveVoter(1)`,
/// leaving voters {0,2,3} at slots {0,1,2} — members 2 and 3 each shift DOWN one slot. The
/// post-reconfiguration commit is submitted at the primary (member 0): a PrepareOk quorum from the
/// SHIFTED successor voter set {0,2,3} is required, proving the primary's mesh reconnected to the
/// shifted backups with the corrected SNI.
///
/// Before the `sni_for` fix, `connect` derived the SNI from the routing slot (`replica-1`) while
/// member 2's cert SAN was minted per stable identity (`replica-2`). The stock `WebPkiServerVerifier`
/// rejected the mismatch BEFORE the `CertOid` attestation ran, so the shifted member could never
/// reconnect and the commit timed out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_cluster_survives_slot_shift() {
  use std::collections::BTreeSet;

  const QUIC_CLUSTER: u128 = 0x5454;
  let base_port: u16 = 47200;

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
    let (driver, handle) = viewstamp_reactor::ReactorQuicDriver::<
      agnostic::tokio::TokioRuntime,
      _,
      _,
      _,
      _,
      viewstamp_proto::ProvidedIdentity,
    >::new(
      config,
      genesis(4, 0),
      viewstamp_simulation::sm::LogSm::default(),
      wal,
      sb,
      blocks,
      viewstamp_proto::ClientId::new(u128::from(id) + 1),
      0,
      opts,
      viewstamp_proto::IdentityConfig::Hello(QUIC_CLUSTER),
      Some([id; 32]),
      addrs[id as usize],
      peers,
      ready_rx,
    )
    .await
    .expect("QUIC driver builds");
    drop(tokio::spawn(driver.run()));
    handles.push(handle);
  }

  // BASELINE: prove the 4-voter QUIC mesh formed and converges over real mTLS.
  let reply = tokio::time::timeout(
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
  let health = HealthHint::new().with_known_up(BTreeSet::from([
    MemberId::new(0),
    MemberId::new(2),
    MemberId::new(3),
  ]));
  tokio::time::timeout(
    Duration::from_secs(20),
    handles[0].reconfigure_to(target, health),
  )
  .await
  .expect("the reconfiguration converges within 20s")
  .expect("reconfigure_to resolves Ok once voter 1 is removed and slots shift");

  // POST-SHIFT: submit at the primary (member 0). A PrepareOk quorum from the SHIFTED survivor set
  // {0,2,3} (members 2,3 at new slots 1,2) is required, proving mesh reconnected with stable SNI.
  let reply = tokio::time::timeout(
    Duration::from_secs(20),
    handles[0].submit(Bytes::from_static(b"post-shift")),
  )
  .await
  .expect("the post-shift QUIC commit lands within 20s")
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

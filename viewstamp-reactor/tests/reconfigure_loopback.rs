//! Reconfiguration and peer address book tests for the reactor (tokio) QUIC driver.
//!
//! Reconfiguration gate: a real single-node driver drives a membership change through its own run
//! loop to convergence (`reconfigure_to` → `Ok(())`); a multi-voter cluster's shrink converges from
//! the primary's active voter-liveness PROBE alone, even with zero client traffic ever submitted (no
//! acked op is needed — the probe is the sole positive liveness source); and a shrink whose successor
//! still needs a voter that never runs anywhere to answer stays fail-closed, resolving
//! `InsufficientLiveness` once its deadline elapses rather than hanging forever.
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
  AcceptReducedFaultTolerance, BlockAddress, BlockStore, ClusterTls, Event, IdentityConfig,
  MemberId, Membership, MembershipTarget, QuicOptions, ReplicaId, Superblock, Wal,
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
  fn truncate(&mut self, above: viewstamp_proto::OpNumber) -> Vec<viewstamp_proto::OpId> {
    self.inner.truncate(above)
  }
  fn prune(&mut self, below: viewstamp_proto::OpNumber) -> Vec<viewstamp_proto::OpId> {
    self.inner.prune(below)
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
  let mut sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  // A real new cluster: FORMAT the store once (the pinned genesis root) so recovery resumes the
  // designated primary — an unformatted SOLE VOTER would fail-stop (the wipe-amnesia safeguard).
  viewstamp_driver::format(config, &membership, &wal, &mut sb).expect("format the genesis store");
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
  let mut sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  // A real new cluster: FORMAT each store once (the pinned genesis root) so recovery resumes the
  // designated view-0 primary as Normal — an unformatted store would abdicate (the wipe-amnesia
  // safeguard), spuriously cold-starting a view change.
  viewstamp_driver::format(config, &membership, &wal, &mut sb).expect("format the genesis store");
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
    handle.reconfigure_to(target, HealthHint::default(), None),
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

/// SHRINK STALL → INSUFFICIENT LIVENESS: a shrink whose successor still needs a voter that never
/// answers anywhere fails closed and the call resolves `InsufficientLiveness` once its deadline
/// elapses. Genesis is THREE voters; only slot 0's node runs (no peers), so voters 1 and 2 never
/// answer a health-probe round and can never be proven live.
///
/// The genesis MUST be three voters, not two: shrinking a two-voter genesis down to a SELF-ONLY
/// successor ({0}) is exactly the idle-but-live case the probe fixes — `proven_live_voters` unions the
/// local member into a live round unconditionally, so a lone running node can always prove ITSELF alive and
/// that shrink now correctly COMPLETES (see the idle multi-voter completion test below). Here the
/// target is still `{0}` alone, so the first step's successor (dropping either peer) is a TWO-voter
/// config that needs the OTHER never-running peer proven too — evidence no probe round can ever
/// produce — so the picker genuinely has nothing to confirm and stalls on every iteration. With
/// nothing ever committing, only the deadline-driven `cap_exhausted` ends the call: a short
/// `reconfigure_timeout` makes `ReconfigureError::InsufficientLiveness` fire promptly. This is the
/// regression for the deadline path (a hardwired `cap_exhausted = false` would hang here forever).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_node_shrink_with_an_unreachable_successor_voter_stalls_to_insufficient_liveness() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41210".parse().unwrap();
  // A short deadline so the fail-closed stall resolves quickly.
  let cfg = viewstamp_reactor::DriverConfig::new().with_reconfigure_timeout(Duration::from_secs(1));
  // Genesis: voters {0, 1, 2}; only node 0 runs. Target: drop voters 1 AND 2, down to {0} alone.
  let (driver, handle) = build_driver(&ca, bind, genesis(3, 0), cfg).await;
  drop(tokio::spawn(driver.run()));

  let target = MembershipTarget::new(
    std::collections::BTreeSet::from([MemberId::new(0)]),
    std::collections::BTreeSet::new(),
  );
  // No process ever answers for voters 1 or 2: every removal's successor still needs the OTHER one
  // proven, which never happens. Generously bound the test wait above the 1s deadline.
  let outcome = tokio::time::timeout(
    Duration::from_secs(10),
    handle.reconfigure_to(
      target,
      HealthHint::default(),
      Some(AcceptReducedFaultTolerance),
    ),
  )
  .await
  .expect("the call resolves (InsufficientLiveness) well within 10s — it does not hang");
  match outcome {
    Err(ReconfigureError::InsufficientLiveness { unproven, .. }) => {
      assert!(
        !unproven.is_empty(),
        "a genuinely unreachable successor voter is named unproven"
      );
      assert!(
        unproven.is_subset(&std::collections::BTreeSet::from([
          MemberId::new(1),
          MemberId::new(2)
        ])),
        "only the two never-running peers can ever be named unproven, got {unproven:?}"
      );
    }
    other => panic!(
      "a fail-closed shrink with an unreachable successor voter resolves InsufficientLiveness once the deadline elapses, got {other:?}"
    ),
  }

  let _ = handle.shutdown().await;
}

/// THE HEALTH PROBE ALONE PROVES AN IDLE SHRINK'S SUCCESSOR QUORUM (reactor variant): a real
/// 3-voter cluster with ZERO client traffic EVER submitted still converges a shrink to 2 voters,
/// because the primary's active `solicit_health_proofs` round — not any inflight acked op — proves the
/// successor voter alive. This is the direct end-to-end regression for the idle-shrink-stall defect the
/// probe fixes: the deleted `recently_acked_voters` oracle read only in-flight uncommitted prepares and was empty on an idle
/// cluster, so this exact scenario used to stall to `Timeout` before the probe replaced it. All three
/// nodes run as separate driver processes over real mTLS QUIC, and the shrink is driven with the
/// stock default `DriverConfig` (no shortened deadline, no operator `HealthHint`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_three_voter_shrink_completes_from_health_probes_alone() {
  let ca = TestCa::new();
  let addrs: Vec<SocketAddr> = (0..3)
    .map(|i: u16| format!("127.0.0.1:{}", 41920 + i).parse().unwrap())
    .collect();

  let mut handles = Vec::new();
  for id in 0u8..3 {
    let peers: Vec<_> = (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect();
    let (driver, handle) =
      build_cluster_driver(&ca, id, addrs[id as usize], peers, genesis(3, 0)).await;
    drop(tokio::spawn(driver.run()));
    handles.push(handle);
  }

  // ZERO app traffic: no client op is ever submitted on any node. Only the health-probe round can
  // supply the successor's liveness evidence. Target: drop voter 2, keeping {0, 1}.
  let target = MembershipTarget::new(
    std::collections::BTreeSet::from([MemberId::new(0), MemberId::new(1)]),
    std::collections::BTreeSet::new(),
  );
  tokio::time::timeout(
    viewstamp_driver::RECONFIGURE_TIMEOUT + Duration::from_secs(2),
    handles[0].reconfigure_to(target, HealthHint::default(), Some(AcceptReducedFaultTolerance)),
  )
  .await
  .expect("the call resolves within the deadline band")
  .expect("the shrink converges from the health-probe evidence alone, with no client traffic ever submitted");

  for h in &handles {
    let _ = h.shutdown().await;
  }
}

/// A SURVIVOR THAT NEVER PROVES BLOCKS A SHRINK THAT WOULD STRAND IT, AND THE REST STAY
/// AVAILABLE (reactor variant): a real 3-voter cluster {0,1,2}; the primary (0) is asked to shrink to
/// {0,1} (the sole delta is `RemoveVoter(2)`), and voter 1 — a SURVIVOR of the target, not the
/// departing voter — is killed BEFORE the shrink is issued. `RemoveVoter(2)` is NEVER issued: its
/// successor `{0,1}` would leave 1 dead, an immediate outage, so the shrink stalls fail-closed naming
/// 1 unproven. Meanwhile the ORIGINAL 3-voter quorum (2 of 3) does not need voter 1: voter 0 and
/// voter 2 alone still commit a client op after the stall, proving continued availability despite both
/// the crash and the stall — and, since a wrongly-installed `{0,1}` successor with 1 dead could never
/// commit anything again, that commit landing is itself proof voter 2 was never removed. Killing
/// BEFORE the call is deliberate: a post-call kill is structurally racy against the documented bounded
/// point-in-time freshness residual (a survivor that answers one probe within `max_age`, then dies,
/// legitimately authorizes the removal), so this loopback pins the deterministic end-to-end form while
/// the crashed-after-answering nuances live in the unit/executor falsifiers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_killed_survivor_blocks_the_shrink_and_the_rest_stay_available() {
  let ca = TestCa::new();
  let addrs: Vec<SocketAddr> = (0..3)
    .map(|i: u16| format!("127.0.0.1:{}", 41930 + i).parse().unwrap())
    .collect();

  let mut handles = Vec::new();
  for id in 0u8..3 {
    let peers: Vec<_> = (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect();
    let (driver, handle) =
      build_cluster_driver(&ca, id, addrs[id as usize], peers, genesis(3, 0)).await;
    drop(tokio::spawn(driver.run()));
    handles.push(handle);
  }

  // Target {0, 1}: the sole delta is RemoveVoter(2).
  let target = MembershipTarget::new(
    std::collections::BTreeSet::from([MemberId::new(0), MemberId::new(1)]),
    std::collections::BTreeSet::new(),
  );
  // Kill voter 1 BEFORE issuing the shrink: from this point on it can never answer a health-probe
  // round, so the successor {0,1} can never be proven live and the removal deterministically stalls.
  // The RemoveVoter op still commits via the surviving {0,2} quorum of the current 3-voter config.
  let _ = handles[1].shutdown().await;

  let primary = handles[0].clone();
  let recon = tokio::spawn(async move {
    primary
      .reconfigure_to(
        target,
        HealthHint::default(),
        Some(AcceptReducedFaultTolerance),
      )
      .await
  });

  let outcome = tokio::time::timeout(
    viewstamp_driver::RECONFIGURE_TIMEOUT + Duration::from_secs(5),
    recon,
  )
  .await
  .expect("the call resolves (does not hang) within the deadline band")
  .expect("the spawned reconfigure_to task completes without panicking");
  match outcome {
    Err(ReconfigureError::InsufficientLiveness { unproven, .. }) => {
      assert!(
        unproven.contains(&MemberId::new(1)),
        "voter 1 (killed, never proves again) is named unproven, got {unproven:?}"
      );
    }
    other => panic!("expected InsufficientLiveness naming voter 1, got {other:?}"),
  }

  // AVAILABILITY PRESERVED: voter 0 and voter 2 (both still alive) commit a client op despite voter
  // 1's death and the stalled shrink — the original 3-voter quorum (2 of 3) never needed voter 1.
  let reply = tokio::time::timeout(
    Duration::from_secs(20),
    handles[0].submit(Bytes::from_static(b"post-stall")),
  )
  .await
  .expect("the commit lands within 20s despite voter 1's death and the stalled shrink")
  .expect("a committed reply");
  assert_eq!(
    &reply[..],
    &1u64.to_be_bytes(),
    "the first (and only) committed op replies the post-apply count 1"
  );

  let _ = handles[0].shutdown().await;
  let _ = handles[2].shutdown().await;
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
    let mut sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
    // A real new cluster: FORMAT each store once so recovery resumes the designated view-0 primary
    // as Normal — an unformatted store would abdicate (the wipe-amnesia safeguard).
    viewstamp_driver::format(config, &genesis(4, 0), &wal, &mut sb).expect("format genesis store");
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
  // {0,1,2}. All three nodes are live and committing, so the primary's health-probe round proves the
  // successor quorum live and the quorum-preserving removal picker confirms it — no operator hint
  // needed (`HealthHint::default()`).
  let target = MembershipTarget::new(
    BTreeSet::from([MemberId::new(0), MemberId::new(2), MemberId::new(3)]),
    BTreeSet::new(),
  );
  tokio::time::timeout(
    Duration::from_secs(20),
    handles[0].reconfigure_to(target, HealthHint::default(), None),
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

/// EMPTY-PROCESS LEARNER BOOTSTRAP: a genesis learner boots from a GENUINELY EMPTY process (a freshly
/// formatted store carrying only the genesis root — no prior log), catches up to the committed frontier
/// over the mesh, and is then promoted to a voter. This is the end-to-end validation of the
/// genesis-learner bootstrap: the learner is handed NO log; it reaches the frontier by replication.
///
/// Genesis is voter 0 (slot 0, the view-0 primary) + learner 1 (slot 1, non-voting). BOTH run as
/// SEPARATE driver processes over real TCP. The voter commits three client ops (self-committing at
/// quorum 1); the empty learner receives them over the mesh and applies them (its `Committed` events
/// reach the third op's post-apply count — the committed frontier). The primary then promotes the
/// learner (the planner lowers the target to `PromoteLearner`, admitted only because the learner's fresh
/// durable-prefix proof covers the head), and a post-promotion client op — now needing a two-voter
/// quorum — commits ONLY with the ex-learner's vote, proving it is an active, caught-up voter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn learner_bootstraps_from_an_empty_process_and_is_promoted() {
  use std::{collections::BTreeSet, sync::Arc};

  use viewstamp_proto::{Conn, Epoch, LabelOptions, Labeled, OpNumber, Passthrough, Peer};

  const LEARNER_CLUSTER: u128 = 0x5353;

  // Genesis: voter 0 (slot 0, view-0 primary) + learner 1 (slot 1, a non-voting member).
  let membership = genesis(1, 1);

  // Self-attesting factories: each node announces its OWN stable MemberId in the `Labeled` handshake, so
  // a peer binds it by stable id regardless of the slot it currently occupies.
  let mk_dialer = |me: u8| -> Arc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move |_peer| {
      let opts = LabelOptions::new(LEARNER_CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Arc<dyn Fn() -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move || {
      let opts = LabelOptions::new(LEARNER_CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };

  // Reserve two kernel-assigned TCP ports (fresh ephemeral ports keep repeated CI runs from colliding
  // with the previous run's TIME_WAIT remnants).
  let reservations: Vec<std::net::TcpListener> = (0..2)
    .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a loopback port"))
    .collect();
  let addrs: Vec<SocketAddr> = reservations
    .iter()
    .map(|l| l.local_addr().expect("reserved listener has an address"))
    .collect();
  drop(reservations);

  let mut handles = Vec::new();
  for id in 0u8..2 {
    let peers: Vec<_> = (0u8..2)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect();
    let config =
      viewstamp_proto::Config::try_new(LEARNER_CLUSTER, MemberId::new(id as u128)).unwrap();
    let (ready_tx, ready_rx) = flume::unbounded();
    let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
    let mut sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
    // FORMAT the fresh store: this writes ONLY the pinned genesis root (epoch 0, empty log). The voter
    // and the learner start from the IDENTICAL fresh-genesis state — neither is handed a prior log.
    viewstamp_driver::format(config, &membership, &wal, &mut sb).expect("format genesis store");
    // EMPTY-PROCESS WITNESS (load-bearing for the learner, id 1): after formatting, the durable store
    // holds only the genesis root and the WAL holds no ops. The learner is handed NO prior log; it must
    // reach the voter's frontier purely by catching up over the mesh. An already-populated fixture would
    // show a non-genesis `op_head` / commit here.
    assert_eq!(
      wal.op_head(),
      OpNumber::new(),
      "node {id} starts with an empty WAL (genesis, no ops)"
    );
    assert_eq!(
      sb.state().commit(),
      OpNumber::new(),
      "node {id} has committed nothing at genesis"
    );
    assert_eq!(
      sb.state().checkpoint_op(),
      OpNumber::new(),
      "node {id} holds no checkpoint at genesis"
    );
    assert_eq!(
      sb.state().epoch(),
      Epoch::new(0),
      "node {id} boots in the genesis epoch"
    );
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
      membership.clone(),
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

  // Subscribe to the LEARNER's events BEFORE any op is submitted, so none of its catch-up `Committed`
  // events are missed.
  let learner_events = handles[1].events();

  // The voter (member 0, the view-0 primary) commits three client ops, each self-committing at quorum 1.
  // Their replies are the post-apply counts 1, 2, 3.
  for expected in 1..=3u64 {
    let reply = tokio::time::timeout(
      Duration::from_secs(20),
      handles[0].submit(Bytes::from_static(b"op")),
    )
    .await
    .expect("the client op commits within 20s")
    .expect("a client reply");
    assert_eq!(
      &reply[..],
      &expected.to_be_bytes(),
      "the voter's committed op replies the post-apply count {expected}"
    );
  }

  // CATCH-UP: the empty learner receives the voter's committed log over the mesh and applies it. Wait for
  // its `Committed` event carrying the post-apply count 3 — the proof it reached the committed frontier
  // (the third client op) from an empty start, by replication rather than a handed-over log.
  tokio::time::timeout(Duration::from_secs(20), async {
    loop {
      match learner_events.recv_async().await {
        Ok(Event::Committed(c)) if c.reply() == 3u64.to_be_bytes() => break,
        Ok(_) => {}
        Err(_) => panic!("the learner's event channel closed before it caught up"),
      }
    }
  })
  .await
  .expect("the empty learner catches up to the committed frontier (count 3) within 20s");

  // PROMOTE: the primary drives the learner's promotion to a voter (target voters {0, 1}, no learners).
  // The planner lowers this to `PromoteLearner(1)`; the promote-time challenge admits it only because the
  // learner durably holds the head — which it just caught up to.
  let target = MembershipTarget::new(
    BTreeSet::from([MemberId::new(0), MemberId::new(1)]),
    BTreeSet::new(),
  );
  // The health hint is irrelevant here: `PromoteLearner` is a grow-phase step the liveness gate never
  // consults (only a `RemoveVoter` shrink does) — the promote-time durable-prefix challenge is what
  // admits it.
  tokio::time::timeout(
    Duration::from_secs(20),
    handles[0].reconfigure_to(target, HealthHint::default(), None),
  )
  .await
  .expect("the promotion converges within 20s")
  .expect("reconfigure_to resolves Ok once the learner is promoted to a voter");

  // POST-PROMOTION: the ex-learner is now a VOTER, so the cluster is two voters at quorum 2. A fresh op
  // committed at the primary REQUIRES the promoted member's `PrepareOk` — its success proves member 1 is
  // an active, caught-up voter (not merely installed). The reply is the post-apply count 4 (the
  // reconfiguration op is not delivered to the state machine, so it does not advance the count).
  let reply = tokio::time::timeout(
    Duration::from_secs(20),
    handles[0].submit(Bytes::from_static(b"post-promote")),
  )
  .await
  .expect("the post-promotion commit lands within 20s")
  .expect("a post-promotion reply");
  assert_eq!(
    &reply[..],
    &4u64.to_be_bytes(),
    "the two-voter-quorum commit lands only with the promoted voter's vote (count 4)"
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
    let mut sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
    // A real new cluster: FORMAT each store once so recovery resumes the designated view-0 primary
    // as Normal — an unformatted store would abdicate (the wipe-amnesia safeguard).
    viewstamp_driver::format(config, &genesis(4, 0), &wal, &mut sb).expect("format genesis store");
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

  // RECONFIGURE: remove voter 1, shifting members 2→slot 1 and 3→slot 2. All four nodes are live and
  // committing, so the primary's health-probe round proves the successor quorum live.
  let target = MembershipTarget::new(
    BTreeSet::from([MemberId::new(0), MemberId::new(2), MemberId::new(3)]),
    BTreeSet::new(),
  );
  tokio::time::timeout(
    Duration::from_secs(20),
    handles[0].reconfigure_to(target, HealthHint::default(), None),
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

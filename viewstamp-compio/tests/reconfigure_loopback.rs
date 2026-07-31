//! Reconfiguration and peer address book tests for the compio QUIC driver.
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

use std::{
  net::SocketAddr,
  time::{Duration, Instant},
};

use bytes::Bytes;
use rustls::{
  RootCertStore,
  pki_types::{CertificateDer, PrivateKeyDer},
};
use viewstamp_compio::BlockLane;
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
  fn put(&mut self, block: Bytes) -> BlockAddress {
    let addr = viewstamp_proto::block_address(&block);
    self.0.insert(addr, block);
    addr
  }
  fn flush(&mut self) -> Result<(), viewstamp_proto::BlockStoreError> {
    Ok(())
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
    id: viewstamp_proto::WriteId,
    op: viewstamp_proto::OpNumber,
    h: viewstamp_proto::Header,
    b: bytes::Bytes,
  ) {
    self.inner.submit_append(id, op, h, b);
    self.signal();
  }
  fn submit_read(&mut self, id: viewstamp_proto::ReadId, op: viewstamp_proto::OpNumber) {
    self.inner.submit_read(id, op);
    self.signal();
  }
  fn truncate(&mut self, above: viewstamp_proto::OpNumber) -> Vec<viewstamp_proto::WriteId> {
    self.inner.truncate(above)
  }
  fn prune(&mut self, below: viewstamp_proto::OpNumber) -> Vec<viewstamp_proto::WriteId> {
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
  fn submit_write(&mut self, id: viewstamp_proto::WriteId, s: viewstamp_proto::VsrState) {
    self.inner.submit_write(id, s);
    self.signal();
  }
  fn submit_write_checkpoint(
    &mut self,
    id: viewstamp_proto::WriteId,
    op: viewstamp_proto::OpNumber,
    snap: bytes::Bytes,
  ) {
    self.inner.submit_write_checkpoint(id, op, snap);
    self.signal();
  }
  fn submit_read_checkpoint(&mut self, id: viewstamp_proto::ReadId) {
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
  let mut sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  // A real new cluster: FORMAT the store once (the pinned genesis root) so recovery resumes the
  // designated primary — an unformatted SOLE VOTER would fail-stop (the wipe-amnesia safeguard).
  viewstamp_driver::format(config, &membership, &wal, &mut sb).expect("format the genesis store");
  let blocks = BlockLane::spawn(MemBlocks::default());
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
) -> (GateDriver, viewstamp_compio::Handle) {
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
  let blocks = BlockLane::spawn(MemBlocks::default());
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
    IdentityConfig::Hello(CLUSTER),
    Some([id; 32]),
    bind,
    peers,
    ready_rx,
  )
  .await
  .expect("driver builds")
}

/// Drive `reconfigure_to` to convergence, treating a fail-closed `InsufficientLiveness` refusal as
/// RETRYABLE rather than a test failure: the successor-liveness probe is a real network round trip,
/// and a machine under load can miss its window without the successor voter being genuinely
/// unreachable, so a fresh call — which re-plans from wherever the live membership landed and
/// re-probes from scratch — gets another chance to gather the proof the first attempt's window
/// missed. Any OTHER error fails immediately: it names a genuine defect, not a proof that merely
/// has not landed yet.
///
/// Bounded by `budget`, the same overall allowance the call used before retries existed: once
/// elapsed time passes it while still `InsufficientLiveness`, this panics naming the last unproven
/// successor set rather than retrying without end. It also panics the moment the remaining plan
/// GROWS between attempts — proof the reconfiguration is genuinely stalled (or regressing), which
/// the retry must never paper over, rather than merely waiting on a liveness proof still in
/// flight. The wrapping timeout is pure defense against an unrelated hang: `reconfigure_to` itself
/// always resolves within its own configured deadline, so this should never fire in practice.
async fn reconfigure_until_proven(
  handle: &viewstamp_compio::Handle,
  target: MembershipTarget,
  health: HealthHint,
  ack: Option<AcceptReducedFaultTolerance>,
  budget: Duration,
) {
  compio::time::timeout(budget + viewstamp_driver::RECONFIGURE_TIMEOUT, async {
    let deadline = Instant::now() + budget;
    let mut prior_remaining = None;
    loop {
      match handle
        .reconfigure_to(target.clone(), health.clone(), ack)
        .await
      {
        Ok(()) => return,
        Err(ReconfigureError::InsufficientLiveness { progress, unproven }) => {
          let remaining = progress.remaining().unwrap_or(&[]).len();
          if let Some(prior) = prior_remaining {
            assert!(
              remaining <= prior,
              "the reconfiguration regressed instead of merely stalling on a liveness proof: the \
               remaining plan grew from {prior} step(s) to {remaining} step(s); last unproven \
               {unproven:?}"
            );
          }
          prior_remaining = Some(remaining);
          if Instant::now() >= deadline {
            panic!(
              "reconfigure_to exhausted its retry budget still reporting InsufficientLiveness; \
               last unproven {unproven:?}, remaining plan {:?}",
              progress.remaining()
            );
          }
        }
        Err(other) => panic!("reconfigure_to failed: {other:?}"),
      }
    }
  })
  .await
  .expect(
    "reconfigure_to (retried across InsufficientLiveness refusals) hung well past its retry \
     budget — an unrelated defect, not a liveness proof that merely has not landed",
  );
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
  reconfigure_until_proven(
    &handle,
    target,
    HealthHint::default(),
    None,
    Duration::from_secs(10),
  )
  .await;

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
#[compio::test]
async fn single_node_shrink_with_an_unreachable_successor_voter_stalls_to_insufficient_liveness() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41230".parse().unwrap();
  // A short deadline so the fail-closed stall resolves quickly.
  let cfg = viewstamp_compio::DriverConfig::new().with_reconfigure_timeout(Duration::from_secs(1));
  // Genesis: voters {0, 1, 2}; only node 0 runs. Target: drop voters 1 AND 2, down to {0} alone.
  let (driver, handle) = build_driver(&ca, bind, genesis(3, 0), cfg).await;
  compio::runtime::spawn(driver.run()).detach();

  let target = MembershipTarget::new(
    std::collections::BTreeSet::from([MemberId::new(0)]),
    std::collections::BTreeSet::new(),
  );
  // No process ever answers for voters 1 or 2: every removal's successor still needs the OTHER one
  // proven, which never happens. Generously bound the test wait above the 1s deadline.
  let outcome = compio::time::timeout(
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

/// THE HEALTH PROBE ALONE PROVES AN IDLE SHRINK'S SUCCESSOR QUORUM: a real 3-voter cluster with
/// ZERO client traffic EVER submitted still converges a shrink to 2 voters, because the primary's
/// active `solicit_health_proofs` round — not any inflight acked op — proves the successor voter
/// alive. This is the direct end-to-end regression for the idle-shrink-stall defect the probe fixes:
/// the deleted `recently_acked_voters` oracle read only in-flight uncommitted prepares and was empty on an idle
/// cluster, so this exact scenario used to stall to `Timeout` before the probe replaced it. All three
/// nodes run as separate driver processes over real mTLS QUIC, and the shrink is driven with the
/// stock default `DriverConfig` (no shortened deadline, no operator `HealthHint`).
#[compio::test]
async fn idle_three_voter_shrink_completes_from_health_probes_alone() {
  let ca = TestCa::new();
  let addrs: Vec<SocketAddr> = (0..3)
    .map(|i: u16| format!("127.0.0.1:{}", 41900 + i).parse().unwrap())
    .collect();

  let mut handles = Vec::new();
  for id in 0u8..3 {
    let peers: Vec<_> = (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect();
    let (driver, handle) =
      build_cluster_driver(&ca, id, addrs[id as usize], peers, genesis(3, 0)).await;
    compio::runtime::spawn(driver.run()).detach();
    handles.push(handle);
  }

  // ZERO app traffic: no client op is ever submitted on any node. Only the health-probe round can
  // supply the successor's liveness evidence. Target: drop voter 2, keeping {0, 1}.
  let target = MembershipTarget::new(
    std::collections::BTreeSet::from([MemberId::new(0), MemberId::new(1)]),
    std::collections::BTreeSet::new(),
  );
  reconfigure_until_proven(
    &handles[0],
    target,
    HealthHint::default(),
    Some(AcceptReducedFaultTolerance),
    viewstamp_driver::RECONFIGURE_TIMEOUT + Duration::from_secs(2),
  )
  .await;

  for h in &handles {
    let _ = h.shutdown().await;
  }
}

/// A SURVIVOR THAT NEVER PROVES BLOCKS A SHRINK THAT WOULD STRAND IT, AND THE REST STAY
/// AVAILABLE: a real 3-voter cluster {0,1,2}; the primary (0) is asked to shrink to {0,1} (the sole
/// delta is `DemoteVoter(2)`), and voter 1 — a SURVIVOR of the target, not the departing voter — is
/// killed BEFORE the shrink is issued. `DemoteVoter(2)` is NEVER issued: its successor `{0,1}` would
/// leave 1 dead, an immediate outage, so the shrink stalls fail-closed naming 1 unproven. Meanwhile
/// the ORIGINAL 3-voter quorum (2 of 3) does not need voter 1: voter 0 and voter 2 alone still commit
/// a client op after the stall, proving continued availability despite both the crash and the stall —
/// and, since a wrongly-installed `{0,1}` successor with 1 dead could never commit anything again,
/// that commit landing is itself proof voter 2 was never removed. Killing BEFORE the call is
/// deliberate: a post-call kill is structurally racy against the documented bounded point-in-time
/// freshness residual (a survivor that answers one probe within `max_age`, then dies, legitimately
/// authorizes the removal), so this loopback pins the deterministic end-to-end form while the
/// crashed-after-answering nuances live in the unit/executor falsifiers.
#[compio::test]
async fn a_killed_survivor_blocks_the_shrink_and_the_rest_stay_available() {
  let ca = TestCa::new();
  let addrs: Vec<SocketAddr> = (0..3)
    .map(|i: u16| format!("127.0.0.1:{}", 41910 + i).parse().unwrap())
    .collect();

  let mut handles = Vec::new();
  for id in 0u8..3 {
    let peers: Vec<_> = (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect();
    let (driver, handle) =
      build_cluster_driver(&ca, id, addrs[id as usize], peers, genesis(3, 0)).await;
    compio::runtime::spawn(driver.run()).detach();
    handles.push(handle);
  }

  // Target {0, 1}: the sole delta is DemoteVoter(2).
  let target = MembershipTarget::new(
    std::collections::BTreeSet::from([MemberId::new(0), MemberId::new(1)]),
    std::collections::BTreeSet::new(),
  );
  // Kill voter 1 BEFORE issuing the shrink: from this point on it can never answer a health-probe
  // round, so the successor {0,1} can never be proven live and the removal deterministically stalls.
  // The DemoteVoter op still commits via the surviving {0,2} quorum of the current 3-voter config.
  let _ = handles[1].shutdown().await;

  let primary = handles[0].clone();
  let recon = compio::runtime::spawn(async move {
    primary
      .reconfigure_to(
        target,
        HealthHint::default(),
        Some(AcceptReducedFaultTolerance),
      )
      .await
  });

  let outcome = compio::time::timeout(
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
  let reply = compio::time::timeout(
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

/// DEMOTE-THEN-GC END-TO-END: a real 3-voter cluster {0,1,2} shrinks to {0,1} via the demote-first
/// path, driven by a single `reconfigure_to` call from the PRIMARY (member 0) — a SURVIVING node, never
/// the departing member itself (the H1 drive-from-a-surviving-node rule: an about-to-leave voter is
/// never a sound driver of its own departure). The target names {0,1} as voters and retains member 2 in
/// NEITHER the voter nor the learner set, so the planner sequences TWO steps: `DemoteVoter(2)` (voter →
/// live learner) then, once that swap installs, `RemoveLearner(2)` (race-free GC — the successor
/// quorum's own commit, gated on a fresh liveness probe of {0,1}). Member 2 stays a normal, connected
/// process throughout (never crashed), so it OBSERVES both installs on its own event stream, in order:
/// first `self_is_voter=false, self_is_learner=true` (demoted — still a member, no longer a voter), then
/// `self_is_voter=false, self_is_learner=false` (GCed — fully out of the membership), each installing at
/// a strictly later epoch than the one before. 3→2 is an ODD-count shrink (`f` drops from 1 to 0), so
/// the call carries `AcceptReducedFaultTolerance` — the operator's honest acknowledgement that crash
/// tolerance is genuinely reduced, or the propose gate would refuse the demote. After the GC installs,
/// the SHRUNK 2-voter cluster {0,1} still commits a fresh client request through the primary, proving
/// availability survived the whole demote-then-GC round trip.
#[compio::test]
async fn a_demoted_voter_becomes_a_learner_then_is_gced_and_the_smaller_cluster_still_commits() {
  let ca = TestCa::new();
  let addrs: Vec<SocketAddr> = (0..3)
    .map(|i: u16| format!("127.0.0.1:{}", 41960 + i).parse().unwrap())
    .collect();

  let mut handles = Vec::new();
  for id in 0u8..3 {
    let peers: Vec<_> = (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect();
    let (driver, handle) =
      build_cluster_driver(&ca, id, addrs[id as usize], peers, genesis(3, 0)).await;
    compio::runtime::spawn(driver.run()).detach();
    handles.push(handle);
  }

  // Subscribe to member 2's OWN event stream BEFORE issuing the shrink, so neither install is missed.
  let demotee_events = handles[2].events();

  // Target {0, 1}: member 2 is named in neither the voter nor the learner set, so the planner drives
  // `DemoteVoter(2)` then `RemoveLearner(2)` — the full demote-then-GC sequence — as ONE `reconfigure_to`
  // call. Issued from member 0 (a survivor), never from member 2 itself.
  let target = MembershipTarget::new(
    std::collections::BTreeSet::from([MemberId::new(0), MemberId::new(1)]),
    std::collections::BTreeSet::new(),
  );
  reconfigure_until_proven(
    &handles[0],
    target,
    HealthHint::default(),
    Some(AcceptReducedFaultTolerance),
    viewstamp_driver::RECONFIGURE_TIMEOUT + Duration::from_secs(2),
  )
  .await;

  // Drain member 2's own two installs, in order: the demote (still a member, now a learner), then the
  // GC (fully removed). Waited for explicitly (not opportunistically drained) — member 2's own install
  // can lag the primary's view by a message or two, even with no faults.
  let mut demote_swap = None;
  let mut gc_swap = None;
  compio::time::timeout(Duration::from_secs(20), async {
    loop {
      match demotee_events.recv_async().await {
        Ok(Event::MembershipChanged(m)) if demote_swap.is_none() => demote_swap = Some(m),
        Ok(Event::MembershipChanged(m)) => {
          gc_swap = Some(m);
          break;
        }
        Ok(_) => {}
        Err(_) => panic!("member 2's event channel closed before its GC install arrived"),
      }
    }
  })
  .await
  .expect("member 2 observes both its demote-install and its GC-install within 20s");
  let demote_swap = demote_swap.expect("the demote install was observed");
  let gc_swap = gc_swap.expect("the GC install was observed");
  assert!(
    !demote_swap.self_is_voter() && demote_swap.self_is_learner(),
    "the first install demotes member 2 to a live learner (still a member), got {demote_swap:?}"
  );
  assert!(
    !gc_swap.self_is_voter() && !gc_swap.self_is_learner(),
    "the second install GCs member 2 out of the membership entirely, got {gc_swap:?}"
  );
  assert!(
    gc_swap.epoch() > demote_swap.epoch(),
    "the GC installs at a strictly later epoch than the demote (epoch {} vs {})",
    gc_swap.epoch(),
    demote_swap.epoch()
  );

  // AVAILABILITY: the SHRUNK 2-voter cluster {0,1} still commits a fresh client request through the
  // primary — the demote-then-GC round trip left the surviving quorum fully functional.
  let reply = compio::time::timeout(
    Duration::from_secs(20),
    handles[0].submit(Bytes::from_static(b"post-demote-gc")),
  )
  .await
  .expect("the shrunk cluster commits within 20s")
  .expect("a committed reply");
  assert_eq!(
    &reply[..],
    &1u64.to_be_bytes(),
    "the first client op on the shrunk 2-voter cluster replies the post-apply count 1"
  );

  for h in &handles {
    let _ = h.shutdown().await;
  }
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
/// handshake). Genesis is voters {0,1,2,3} at slots {0,1,2,3}; the primary (member 0) proposes a shrink
/// to {0,2,3}. Member 1 is named in neither the target's voter nor learner set, so the planner
/// sequences `DemoteVoter(1)` then, once that installs, `RemoveLearner(1)` — leaving voters {0,2,3} at
/// slots {0,1,2} — members 2 and 3 each shift DOWN one slot. The post-reconfiguration commit is
/// submitted at member 3 (now at slot 2, shifted from slot 3): it can only converge if member 3's mesh
/// conns re-resolved to the survivors' new slots, which is exactly the stable-id routing the handshake
/// redesign provides. A regression to slot-attestation routing strands the shifted conns and the second
/// commit times out.
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

  // Reserve kernel-assigned TCP ports (bind port-0 listeners, read the addresses, drop them):
  // fresh ephemeral ports per process keep repeated runs of this binary (CI runs it once per cargo
  // feature combination, back-to-back) from colliding with the previous run's TIME_WAIT connection
  // remnants — rebinding a fixed port constant fails with `AddrInUse` for up to a minute after the
  // prior run's cluster connections closed. (The QUIC tests above keep fixed ports: UDP has no
  // TIME_WAIT.)
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
    let blocks = BlockLane::spawn(MemBlocks::default());
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
  // {0,1,2}. All three nodes are live and committing, so the primary's health-probe round proves the
  // successor quorum live and the quorum-preserving removal picker confirms it — no operator hint
  // needed (`HealthHint::default()`).
  let target = MembershipTarget::new(
    BTreeSet::from([MemberId::new(0), MemberId::new(2), MemberId::new(3)]),
    BTreeSet::new(),
  );
  reconfigure_until_proven(
    &handles[0],
    target,
    HealthHint::default(),
    None,
    Duration::from_secs(20),
  )
  .await;

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
#[compio::test]
async fn learner_bootstraps_from_an_empty_process_and_is_promoted() {
  use std::{collections::BTreeSet, rc::Rc};

  use viewstamp_proto::{Conn, Epoch, LabelOptions, Labeled, OpNumber, Passthrough, Peer};

  const LEARNER_CLUSTER: u128 = 0x5353;

  // Genesis: voter 0 (slot 0, view-0 primary) + learner 1 (slot 1, a non-voting member).
  let membership = genesis(1, 1);

  // Self-attesting factories: each node announces its OWN stable MemberId in the `Labeled` handshake, so
  // a peer binds it by stable id regardless of the slot it currently occupies.
  let mk_dialer = |me: u8| -> Rc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>>> {
    Rc::new(move |_peer| {
      let opts = LabelOptions::new(LEARNER_CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Rc<dyn Fn() -> Conn<Labeled<Passthrough>>> {
    Rc::new(move || {
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
    let blocks = BlockLane::spawn(MemBlocks::default());
    let (driver, handle) = viewstamp_compio::CompioStreamDriver::new(
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
    compio::runtime::spawn(driver.run()).detach();
    handles.push(handle);
  }

  // Subscribe to the LEARNER's events BEFORE any op is submitted, so none of its catch-up `Committed`
  // events are missed.
  let learner_events = handles[1].events();

  // The voter (member 0, the view-0 primary) commits three client ops, each self-committing at quorum 1.
  // Their replies are the post-apply counts 1, 2, 3.
  for expected in 1..=3u64 {
    let reply = compio::time::timeout(
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
  compio::time::timeout(Duration::from_secs(20), async {
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
  // consults (only a `DemoteVoter` shrink does) — the promote-time durable-prefix challenge is what
  // admits it.
  reconfigure_until_proven(
    &handles[0],
    target,
    HealthHint::default(),
    None,
    Duration::from_secs(20),
  )
  .await;

  // POST-PROMOTION: the ex-learner is now a VOTER, so the cluster is two voters at quorum 2. A fresh op
  // committed at the primary REQUIRES the promoted member's `PrepareOk` — its success proves member 1 is
  // an active, caught-up voter (not merely installed). The reply is the post-apply count 4 (the
  // reconfiguration op is not delivered to the state machine, so it does not advance the count).
  let reply = compio::time::timeout(
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

/// PULL-LANE EPOCH CROSSING (TCP/TLS stream transport): an epoch-lagged Normal LEARNER whose ONLY link is a
/// stream conn to a RETAINED, settled-Normal, NON-PRIMARY member of the successor epoch bootstraps its
/// learner-status cadence, emits `LearnerStatus`, draws an `EpochAhead` hint back, completes the crossing
/// sync, and INSTALLS the successor epoch — with NO successor-PRIMARY traffic ever reaching it.
///
/// This is the end-to-end regression for the stream driver servicing its consensus timer UNCONDITIONALLY. A
/// fresh Normal learner boots with EVERY timer disarmed, so `poll_timeout()` is `None`; a due-gated
/// `handle_timeout` would never run, so the learner-status cadence (which self-bootstraps INSIDE
/// `handle_timeout`, its sole arm site) would never arm, the learner would never emit `LearnerStatus`, never
/// draw `EpochAhead`, never arm the crossing sync — stranded forever. Serviced every iteration, the cadence
/// bootstraps and the crossing completes.
///
/// OBSERVABILITY — asserted BY CONSEQUENCE: the record layer (`RecordIo`) is `pub(crate)`-sealed and
/// `StreamTransport` is sealed, so the wire `LearnerStatus`/`EpochAhead` messages CANNOT be tapped from this
/// test crate — the only observability is the public `events()` stream. The crossing is proven by two events
/// on the LEARNER's `events()`: `StateSyncStarted` (the learner armed the forced crossing sync off the
/// pulled hint — reachable ONLY after it emitted `LearnerStatus` and the bound member answered `EpochAhead`)
/// and `StateSyncCompleted` (the crossing checkpoint installed + went durable). A cross-epoch sync install
/// emits NO `MembershipChanged` (`install_membership` is passed `None` for the reconfigure op — the laggard
/// synced PAST it), so `StateSyncCompleted` is the terminal witness; in this topology the learner's ONLY
/// possible sync is the E0->E1 crossing (it boots at E0 checkpoint 0 with a single peer that is a settled-E1
/// donor), so a completed sync IS the crossing. Without the timer fix neither event arrives and the wait
/// times out.
///
/// NON-PRIMARY IS LOAD-BEARING: any successor-PRIMARY `Prepare`/`Commit` reaching the learner would trigger
/// the crossing via `maybe_request_cross_epoch_catchup` (inbound-driven, INDEPENDENT of the cadence) and the
/// test would pass even WITHOUT the fix. So the learner's sole link is member 0 — the E0 primary DEMOTED to
/// an E1 learner-seat — which answers `EpochAhead` and serves the crossing checkpoint (its `RequestSync`
/// `Backups` fan-out reaches every bound replica conn) but NEVER broadcasts to a learner. The E1 primary
/// (member 1) is never wired to the learner (asymmetric peer lists), so no successor-primary traffic ever
/// reaches it.
///
/// TOPOLOGY: genesis E0 = voters {0,1,2} + learner {3}. Members 0,1,2 mesh among THEMSELVES (never dialing
/// the learner) and commit baseline ops so the donor holds a checkpoint above 0 (a donor at checkpoint 0
/// serves nothing). The primary (member 0) then DEMOTES ITSELF (only the primary can propose its own
/// demotion) to a learner, retaining {1,2} as voters and {0,3} as learners — a 3->2 voter shrink
/// (`AcceptReducedFaultTolerance`). The view is durable across the swap, so primaryship remaps 0->1 WITHOUT
/// a view change. The stranded learner (member 3) then boots formatted at E0 (never receiving the
/// SwapEpoch), wired to dial ONLY member 0 at the learner's E0 slot 0 — so its `LearnerStatus`, addressed to
/// `primary(view 0) = slot 0`, routes to member 0, and its `Backups` `RequestSync` fan-out (every bound
/// replica conn) also reaches member 0.
#[compio::test]
async fn a_stranded_learner_crosses_an_epoch_over_a_non_primary_link() {
  use std::{collections::BTreeSet, rc::Rc};

  use viewstamp_proto::{Conn, LabelOptions, Labeled, Passthrough, Peer};

  const CROSS_CLUSTER: u128 = 0x5454;
  // A small checkpoint interval so a handful of baseline ops advances the donor's checkpoint above 0 — the
  // crossing donor serves nothing at checkpoint 0 (`on_request_sync` is silent there).
  const CHECKPOINT_OPS: u64 = 4;

  // Self-attesting factories: each node announces its OWN stable MemberId in the `Labeled` handshake, so a
  // peer binds it by stable id and the coordinator resolves that id to whatever slot the local membership
  // assigns it.
  let mk_dialer = |me: u8| -> Rc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>>> {
    Rc::new(move |_peer| {
      let opts = LabelOptions::new(CROSS_CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Rc<dyn Fn() -> Conn<Labeled<Passthrough>>> {
    Rc::new(move || {
      let opts = LabelOptions::new(CROSS_CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };

  // Reserve four kernel-assigned TCP ports (fresh ephemeral ports keep repeated CI runs from colliding with
  // the previous run's TIME_WAIT remnants).
  let reservations: Vec<std::net::TcpListener> = (0..4)
    .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a loopback port"))
    .collect();
  let addrs: Vec<SocketAddr> = reservations
    .iter()
    .map(|l| l.local_addr().expect("reserved listener has an address"))
    .collect();
  drop(reservations);

  // Boot the three genesis voters {0,1,2}. Each dials ONLY the other two voters — never the learner (member
  // 3) — so the learner stays stranded, reached by nobody, and no successor node ever pushes it E1 traffic.
  let mut handles = Vec::new();
  for id in 0u8..3 {
    let peers: Vec<_> = (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect();
    let config = viewstamp_proto::Config::with_checkpoint_ops(
      CROSS_CLUSTER,
      MemberId::new(id as u128),
      CHECKPOINT_OPS,
    )
    .unwrap();
    let (ready_tx, ready_rx) = flume::unbounded();
    let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
    let mut sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
    viewstamp_driver::format(config, &genesis(3, 1), &wal, &mut sb).expect("format genesis store");
    let blocks = BlockLane::spawn(MemBlocks::default());
    let (driver, handle) = viewstamp_compio::CompioStreamDriver::new(
      config,
      genesis(3, 1),
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

  // Commit baseline ops through the primary (member 0) so member 0 durably holds a checkpoint above 0 — the
  // frontier it will later serve to cross the stranded learner. With `CHECKPOINT_OPS = 4`, twelve committed
  // ops form several checkpoints.
  for expected in 1..=12u64 {
    let reply = compio::time::timeout(
      Duration::from_secs(20),
      handles[0].submit(Bytes::from_static(b"op")),
    )
    .await
    .expect("the baseline op commits within 20s")
    .expect("a baseline reply");
    assert_eq!(
      &reply[..],
      &expected.to_be_bytes(),
      "the baseline op replies the post-apply count {expected}"
    );
  }

  // The primary (member 0) DEMOTES ITSELF to a learner: target voters {1,2}, learners {0,3}. Only the
  // primary can propose its own demotion, so this is issued on member 0's handle. 3->2 voters drops `f`
  // from 1 to 0, so the shrink carries `AcceptReducedFaultTolerance`. Spawned in the background: the
  // readiness signal this test turns on is member 0's OWN install to the E1 learner seat (its commit-first
  // swap DOES emit `MembershipChanged`), not whether the reconfigure future resolves on the just-demoted
  // handle.
  let member0_events = handles[0].events();
  let demoter = handles[0].clone();
  compio::runtime::spawn(async move {
    let _ = demoter
      .reconfigure_to(
        MembershipTarget::new(
          BTreeSet::from([MemberId::new(1), MemberId::new(2)]),
          BTreeSet::from([MemberId::new(0), MemberId::new(3)]),
        ),
        HealthHint::default(),
        Some(AcceptReducedFaultTolerance),
      )
      .await;
  })
  .detach();
  compio::time::timeout(Duration::from_secs(20), async {
    loop {
      match member0_events.recv_async().await {
        Ok(Event::MembershipChanged(m)) if m.epoch().get() == 1 => {
          assert!(
            !m.self_is_voter() && m.self_is_learner(),
            "member 0 demoted itself to an E1 learner seat, got {m:?}"
          );
          break;
        }
        Ok(_) => {}
        Err(_) => panic!("member 0's event channel closed before its self-demote install"),
      }
    }
  })
  .await
  .expect("member 0 installs its self-demotion to an E1 learner within 20s");

  // Boot the stranded learner (member 3) AFTER E1 installed, so it never received the SwapEpoch: it is
  // genuinely one epoch behind at E0. Its ONLY dial peer is member 0 at slot 0 (the learner's E0
  // view-0 primary slot) — the retained, settled-Normal, NON-PRIMARY E1 learner-seat that answers
  // `EpochAhead` and serves the crossing checkpoint.
  let learner_id = 3u8;
  let learner_config = viewstamp_proto::Config::with_checkpoint_ops(
    CROSS_CLUSTER,
    MemberId::new(learner_id as u128),
    CHECKPOINT_OPS,
  )
  .unwrap();
  let (learner_ready_tx, learner_ready_rx) = flume::unbounded();
  let learner_wal = Notifying::new(InMemoryWal::new(), learner_ready_tx.clone());
  let mut learner_sb = Notifying::new(InMemorySuperblock::new(), learner_ready_tx);
  viewstamp_driver::format(
    learner_config,
    &genesis(3, 1),
    &learner_wal,
    &mut learner_sb,
  )
  .expect("format the stranded learner's genesis (E0) store");
  let learner_blocks = BlockLane::spawn(MemBlocks::default());
  let (learner_driver, learner_handle) = viewstamp_compio::CompioStreamDriver::new(
    learner_config,
    genesis(3, 1),
    viewstamp_simulation::sm::LogSm::default(),
    learner_wal,
    learner_sb,
    learner_blocks,
    viewstamp_proto::ClientId::new(u128::from(learner_id) + 1),
    0,
    addrs[learner_id as usize],
    // The sole link: member 0, dialed at ReplicaId 0 — the slot the learner's own E0 membership assigns
    // member 0, so its attested id resolves to the dialed slot (a mismatch would be `IdentityRejected`).
    vec![(ReplicaId::new(0), addrs[0])],
    mk_dialer(learner_id),
    mk_acceptor(learner_id),
    learner_ready_rx,
  )
  .await
  .expect("the stranded learner's stream driver builds");
  // Subscribe to the learner's events BEFORE spawning its run loop, so no crossing event is missed.
  let learner_events = learner_handle.events();
  compio::runtime::spawn(learner_driver.run()).detach();

  // THE GATE: wait for `StateSyncCompleted` on the learner's events — the crossing checkpoint installed +
  // went durable. `StateSyncStarted` must precede it (the learner armed the forced crossing sync off the
  // pulled `EpochAhead`, which is reachable ONLY after it self-bootstrapped its cadence and emitted
  // `LearnerStatus`). Without the driver's unconditional-timer fix the cadence never bootstraps, so neither
  // event arrives and this wait times out.
  let mut saw_started = false;
  compio::time::timeout(Duration::from_secs(20), async {
    loop {
      match learner_events.recv_async().await {
        Ok(Event::StateSyncStarted(_)) => saw_started = true,
        Ok(Event::StateSyncCompleted(_)) => break,
        Ok(_) => {}
        Err(_) => panic!("the learner's event channel closed before it crossed"),
      }
    }
  })
  .await
  .expect(
    "the stranded learner self-bootstraps its cadence, pulls an EpochAhead hint over its non-primary \
     link, and completes the crossing sync within 20s",
  );
  assert!(
    saw_started,
    "the learner armed a crossing sync (StateSyncStarted) before completing it — the witness it emitted \
     LearnerStatus and drew the EpochAhead hint back"
  );

  let _ = learner_handle.shutdown().await;
  for h in &handles {
    let _ = h.shutdown().await;
  }
}

/// QUIC TLS SNI SLOT-SHIFT REGRESSION: a 4-voter cluster over real mTLS QUIC removes a low-slot
/// voter so retained members shift slots, then commits a second request THROUGH a shifted member.
///
/// Genesis is voters {0,1,2,3} at slots {0,1,2,3}. The primary (member 0) proposes a shrink to {0,2,3};
/// member 1 is named in neither the target's voter nor learner set, so the planner sequences
/// `DemoteVoter(1)` then `RemoveLearner(1)`, leaving voters {0,2,3} at slots {0,1,2} — members 2 and 3
/// each shift DOWN one slot. The post-reconfiguration commit is submitted at member 3 (now at slot 2,
/// shifted from slot 3): it succeeds only if member 3 can reconnect to its peers after the slot shift.
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
    let mut sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
    // A real new cluster: FORMAT each store once so recovery resumes the designated view-0 primary
    // as Normal — an unformatted store would abdicate (the wipe-amnesia safeguard).
    viewstamp_driver::format(config, &genesis(4, 0), &wal, &mut sb).expect("format genesis store");
    let blocks = BlockLane::spawn(MemBlocks::default());
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
      viewstamp_proto::IdentityConfig::Hello(QUIC_CLUSTER),
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

  // RECONFIGURE: remove voter 1, shifting members 2→slot 1 and 3→slot 2. All four nodes are live and
  // committing, so the primary's health-probe round proves the successor quorum live.
  let target = MembershipTarget::new(
    BTreeSet::from([MemberId::new(0), MemberId::new(2), MemberId::new(3)]),
    BTreeSet::new(),
  );
  reconfigure_until_proven(
    &handles[0],
    target,
    HealthHint::default(),
    None,
    Duration::from_secs(20),
  )
  .await;

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

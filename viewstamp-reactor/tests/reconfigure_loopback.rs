//! The reconfiguration gate: a real single-node driver drives a membership change through its own
//! run loop to convergence (`reconfigure_to` → `Ok(())`), and a fail-closed shrink with no live
//! witness times out within its deadline (the regression for the deadline-driven `cap_exhausted`).
//!
//! These run a single-voter driver — its own primary at view 0, so `propose_membership` is admitted,
//! and the write quorum is 1, so it self-commits its own proposals once its WAL append is durable —
//! over real loopback UDP. A learner PROMOTE is deliberately NOT tested here: the proto's
//! catch-up-then-promote gate solicits a fresh `LearnerProof` from the target learner over the
//! network, which a single-node driver (no learner peer) can never answer, so a promote would stall
//! at `ProofPending` by design. The single-node-convergeable change is an `AddLearner`/`RemoveLearner`
//! (no proof gate, no quorum-intersection constraint); the promote path's end-to-end convergence is
//! covered by the `reconfig_live` simulation lane, which injects the learner's proof.

use std::{net::SocketAddr, time::Duration};

use rustls::{
  RootCertStore,
  pki_types::{CertificateDer, PrivateKeyDer},
};
use viewstamp_driver::{HealthHint, ReconfigureError};
use viewstamp_proto::{
  Event, IdentityConfig, MemberId, Membership, MembershipTarget, QuicOptions, Superblock, Wal,
};
use viewstamp_simulation::{InMemorySuperblock, InMemoryWal};

const CLUSTER: u128 = 0x5151;

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
  GateDriver::with_config(
    config,
    membership,
    viewstamp_simulation::sm::LogSm::default(),
    wal,
    sb,
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

//! The driver gate: a real 3-node cluster on loopback UDP converges and replies.

use std::net::SocketAddr;

use bytes::Bytes;
use rustls::{
  RootCertStore,
  pki_types::{CertificateDer, PrivateKeyDer},
};
use viewstamp_proto::{
  BlockAddress, BlockStore, ClusterTls, IdentityConfig, QuicOptions, Superblock, Wal,
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

/// The genesis membership for an `n`-voter cluster: `MemberId::new(i)` occupies slot `i`, so each
/// node's local slot equals its old replica index (byte-identical quorum/primary/voter at epoch 0).
///
/// Built with a fixed `config_id = 0` (via `from_durable_parts`) so any hand-built test message (which
/// carries 0) passes the strict `(epoch, config_id)` ingress gate; production uses the hash-chained id.
fn genesis(n: u8) -> viewstamp_proto::Membership {
  viewstamp_proto::Membership::from_durable_parts(
    viewstamp_proto::Epoch::new(0),
    n,
    0,
    (0..n as u128).map(viewstamp_proto::MemberId::new).collect(),
    0,
  )
  .expect("valid genesis membership")
}

/// A self-signed cluster CA + per-replica leaf certs, mirroring the proto's own `test_ca` /
/// `issue_replica` (`viewstamp-proto/src/transport/quic/crypto.rs`): same rcgen 0.14 API, same SAN
/// form `replica-<n>.<cluster-hex>.viewstamp`, same EKU (ServerAuth + ClientAuth) and KU. The leaf
/// chains to this CA, which is the sole trust anchor in [`roots`](TestCa::roots), so the mandatory
/// cluster mTLS handshake completes.
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
    b: Bytes,
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
    snap: Bytes,
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

async fn build_driver(
  ca: &TestCa,
  id: u8,
  bind: SocketAddr,
  peers: Vec<(viewstamp_proto::ReplicaId, SocketAddr)>,
) -> (GateDriver, viewstamp_reactor::Handle) {
  let (chain, key) = ca.issue(id);
  let opts: QuicOptions = ClusterTls::new(ca.roots(), chain, key).build();
  let config =
    viewstamp_proto::Config::try_new(CLUSTER, viewstamp_proto::MemberId::new((id as u16) as u128))
      .unwrap();
  let (ready_tx, ready_rx) = flume::unbounded();
  let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
  let mut sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  // A genesis fixture: FORMAT so recovery resumes rather than fail-stopping this voter.
  viewstamp_driver::format(config, &genesis(3), &wal, &mut sb).expect("format the genesis store");
  let blocks = MemBlocks::default();
  GateDriver::new(
    config,
    genesis(3),
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

/// Bind a fresh 3-node cluster on `127.0.0.1` UDP ports starting at `base_port`, each on its own
/// spawned `run` task, and return the node handles (index = replica id). Distinct ports per test keep
/// concurrently-running tests from colliding on the loopback address.
async fn spawn_cluster(ca: &TestCa, base_port: u16) -> Vec<viewstamp_reactor::Handle> {
  let addrs: Vec<SocketAddr> = (0..3)
    .map(|i| format!("127.0.0.1:{}", base_port + i).parse().unwrap())
    .collect();
  let rid = |i: u8| viewstamp_proto::ReplicaId::new(i as u16);

  let mut handles = Vec::new();
  for id in 0u8..3 {
    let peers: Vec<_> = (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (rid(p), addrs[p as usize]))
      .collect();
    let (driver, handle) = build_driver(ca, id, addrs[id as usize], peers).await;
    // The dropped JoinHandle DETACHES the task (a tokio drop never cancels), so each node's run
    // loop keeps driving on its own.
    drop(tokio::spawn(driver.run()));
    handles.push(handle);
  }
  handles
}

/// The gate: a real 3-node cluster over cluster-private mTLS QUIC on loopback UDP commits one client
/// request and surfaces its reply through the submitting node's `Handle`.
///
/// The request is submitted at replica 0 — the primary for view 0 (`view % replica_count == 0`) — the
/// path a VSR client takes to reach the cluster (the proto serves a `Request` only at the primary). The
/// primary mints the op, drives `Prepare`/`PrepareOk`/`Commit` across the mesh to a quorum, applies it,
/// and the driver intercepts the committed event to answer `submit()`. A green assertion here proves
/// the whole driver stack end-to-end: the rcgen cluster CA + leaf certs chain through the mandatory
/// mTLS handshake, three coordinators converge over real quinn-proto datagrams on real sockets, the
/// `Clock`/timer/storage-ready pumping makes forward progress, and reply interception completes the
/// `submit` future. Runs on the multi-thread flavor so the spawned `run()` futures are scheduled (and
/// may migrate) across worker threads, exercising their `Send`-ness for real.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_node_cluster_commits_a_client_request() {
  let ca = TestCa::new();
  let handles = spawn_cluster(&ca, 41000).await;

  let reply = tokio::time::timeout(
    std::time::Duration::from_secs(10),
    handles[0].submit(Bytes::from_static(b"hello")),
  )
  .await
  .expect("commit within 10s")
  .expect("a reply");

  // `LogSm::apply` returns the post-apply count as 8 big-endian bytes (NOT an echo of the body), so the
  // first committed op replies 1.
  assert_eq!(&reply[..], &1u64.to_be_bytes());

  for h in &handles {
    let _ = h.shutdown().await;
  }
}

/// FAILOVER AFTER AN IDLE QUIET PERIOD: steady-state consensus traffic is primary→backups only
/// (heartbeats), so the backup↔backup mesh edges carry NOTHING between view changes. The cluster
/// sits idle well past several QUIC idle-timeout periods (1s each), then the primary is shut down —
/// and the view change that follows rides EXACTLY those long-quiet backup↔backup edges
/// (`StartViewChange`/`DoViewChange` flow between the backups). Committing a request at the new
/// primary proves the mesh survived the quiet period: the transport's keep-alives held the
/// zero-traffic edges under the idle timeout, and the driver's redial reconcile re-establishes any
/// edge that genuinely dies. Without either, the first failover after >1s of healthy idling wedges —
/// the view-change messages route to no bound conn and retransmit forever — and this test times out.
#[tokio::test]
async fn failover_after_an_idle_quiet_period_commits() {
  let ca = TestCa::new();
  let handles = spawn_cluster(&ca, 41030).await;

  // Converge: one committed request through the view-0 primary (replica 0).
  let reply = tokio::time::timeout(
    std::time::Duration::from_secs(10),
    handles[0].submit(Bytes::from_static(b"warm")),
  )
  .await
  .expect("initial commit within 10s")
  .expect("a reply");
  assert_eq!(&reply[..], &1u64.to_be_bytes());

  // Idle past several 1s idle-timeout periods: only primary→backup heartbeats flow, so the
  // backup↔backup edges see zero traffic for the whole window.
  tokio::time::sleep(std::time::Duration::from_secs(4)).await;

  // Kill the primary: the backups must now view-change over the long-quiet backup↔backup edges.
  let _ = handles[0].shutdown().await;

  // A request at a surviving node commits once the view change completes (replica 1 is the view-1
  // primary; if the view escalates further, the relayed-request path still reaches the new primary).
  // The committed log already holds the pre-idle op, so this op applies second.
  let reply = tokio::time::timeout(
    std::time::Duration::from_secs(15),
    handles[1].submit(Bytes::from_static(b"after-idle")),
  )
  .await
  .expect("post-failover commit within 15s")
  .expect("a reply");
  assert_eq!(&reply[..], &2u64.to_be_bytes());

  for h in &handles[1..] {
    let _ = h.shutdown().await;
  }
}

/// Handle-drop termination: `run()` must return when the LAST `Handle` is dropped (the command
/// channel disconnects), even while the UDP socket stays continuously pollable. A single node never
/// converges, so it only ever stops on shutdown or handle-drop; we build one, keep its `run` task's
/// `JoinHandle` (so we can await it), drop the sole `Handle`, and require the task to finish inside
/// the timeout. A regression where the iter-top drain treats `Closed` like `Empty` (or the select
/// command arm ignores the `Err`) spins the loop forever, so the `timeout` fires and the test fails.
#[tokio::test]
async fn quic_driver_exits_when_all_handles_dropped() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41020".parse().unwrap();
  // One node, no peers and no self-address: it binds + runs but never forms a cluster.
  let (driver, handle) = build_driver(&ca, 0, bind, Vec::new()).await;
  let task = tokio::spawn(driver.run());

  drop(handle); // last Handle gone -> command channel closes

  // The outer `expect` asserts the timeout did not elapse (no spin); the inner asserts the task ran
  // `run()` to completion rather than panicking (a held tokio JoinHandle never cancels its task, so
  // completion is the only other outcome).
  tokio::time::timeout(std::time::Duration::from_secs(5), task)
    .await
    .expect("driver.run() returns within 5s after the last Handle is dropped")
    .expect("the run task completes without panicking");
}

/// SHUTDOWN-ACK REBIND BARRIER (QUIC): `Handle::shutdown().await` resolves only after the driver's
/// UDP socket fd is fully RELEASED — the driver is the socket's SOLE owner (the recv arm borrows it
/// in-loop; no helper task holds a clone), and the teardown drops the socket BEFORE sending the ack
/// — so constructing a new driver bound to the SAME address IMMEDIATELY after the ack must succeed.
/// The await of the ack is the ONLY synchronization here: no awaiting the (detached) run task, no
/// settling sleeps. UDP binds without `SO_REUSEADDR`, so a still-open prior fd fails the rebind
/// with `DriverError::Bind`. An ack sent before the socket drop would race the fd close; looping
/// the cycle pins the contract rather than one lucky pass.
#[tokio::test]
async fn shutdown_ack_frees_the_address_for_immediate_rebind() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41040".parse().unwrap();
  for i in 0..5 {
    // Iterations 1.. bind the address the PREVIOUS iteration's driver just released: this
    // `build_driver` succeeding immediately after the ack is the assertion.
    let (driver, handle) = build_driver(&ca, 0, bind, Vec::new()).await;
    drop(tokio::spawn(driver.run()));
    handle
      .shutdown()
      .await
      .unwrap_or_else(|e| panic!("shutdown #{i} acks teardown: {e:?}"));
  }
}

/// The relayed-backup request path: submitting at a backup (replica 1 in view 0) and relying on the
/// coordinator to relay the `Request` to the primary over the mesh. `submit_client_request` broadcasts
/// the `Request` to peers, so it reaches the primary tagged `Peer::Replica(1)`; the consensus ingress
/// backstop `sender_matches` accepts a `Request` relayed from a configured cluster replica (safe in the
/// non-Byzantine model: the relay is an authenticated cluster member, `on_request` serves only at the
/// primary and dedups by session, and a `Request` carries no view/quorum authority — see
/// `endpoint/mod.rs`). The primary serves it, mints the op, and the cluster commits — client routing
/// works through any node without admitting clients as QUIC peers. With the primary-submit gate above,
/// both the client→primary and the backup→relay→primary paths are proven end-to-end over real QUIC.
#[tokio::test]
async fn backup_submit_relays_to_the_primary() {
  let ca = TestCa::new();
  let handles = spawn_cluster(&ca, 41010).await;

  let reply = tokio::time::timeout(
    std::time::Duration::from_secs(10),
    handles[1].submit(Bytes::from_static(b"hello")),
  )
  .await
  .expect("commit within 10s")
  .expect("a reply");
  assert_eq!(&reply[..], &1u64.to_be_bytes());

  for h in &handles {
    let _ = h.shutdown().await;
  }
}

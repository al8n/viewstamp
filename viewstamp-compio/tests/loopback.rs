//! The driver gate: a real 3-node cluster on loopback UDP converges and replies.

use std::net::SocketAddr;

use bytes::Bytes;
use rustls::{
  RootCertStore,
  pki_types::{CertificateDer, PrivateKeyDer},
};
use viewstamp_compio::BlockLane;
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
    id: viewstamp_proto::WriteId,
    op: viewstamp_proto::OpNumber,
    h: viewstamp_proto::Header,
    b: Bytes,
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
    snap: Bytes,
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

async fn build_driver(
  ca: &TestCa,
  id: u8,
  bind: SocketAddr,
  peers: Vec<(viewstamp_proto::ReplicaId, SocketAddr)>,
) -> (GateDriver, viewstamp_compio::Handle) {
  build_driver_with(
    ca,
    id,
    bind,
    peers,
    BlockLane::spawn(MemBlocks::default()),
    viewstamp_proto::DEFAULT_CHECKPOINT_OPS,
  )
  .await
}

/// [`build_driver`] with the node's storage lane and checkpoint interval chosen by the caller — the
/// two knobs the heartbeat-continuity falsifier needs to give ONE node a deliberately slow store
/// that checkpoints on its very first commit.
async fn build_driver_with(
  ca: &TestCa,
  id: u8,
  bind: SocketAddr,
  peers: Vec<(viewstamp_proto::ReplicaId, SocketAddr)>,
  blocks: BlockLane<viewstamp_simulation::sm::LogSm>,
  checkpoint_ops: u64,
) -> (GateDriver, viewstamp_compio::Handle) {
  let (chain, key) = ca.issue(id);
  let opts: QuicOptions = ClusterTls::new(ca.roots(), chain, key).build();
  let config = viewstamp_proto::Config::with_checkpoint_ops(
    CLUSTER,
    viewstamp_proto::MemberId::new((id as u16) as u128),
    checkpoint_ops,
  )
  .unwrap();
  let (ready_tx, ready_rx) = flume::unbounded();
  let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
  let mut sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  // A real new cluster: FORMAT each store once so recovery resumes the designated primary — an
  // unformatted voter would fail-stop (the wipe-amnesia safeguard).
  viewstamp_driver::format(config, &genesis(3), &wal, &mut sb).expect("format the genesis store");
  viewstamp_compio::CompioQuicDriver::new(
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
async fn spawn_cluster(ca: &TestCa, base_port: u16) -> Vec<viewstamp_compio::Handle> {
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
    compio::runtime::spawn(driver.run()).detach();
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
/// `submit` future.
#[compio::test]
async fn three_node_cluster_commits_a_client_request() {
  let ca = TestCa::new();
  let handles = spawn_cluster(&ca, 41000).await;

  let reply = compio::time::timeout(
    std::time::Duration::from_secs(10),
    handles[0].submit(Bytes::from_static(b"hello")),
  )
  .await
  .expect("commit within 10s")
  .expect("a reply");

  // `LogSm::apply` returns the post-apply count as 8 big-endian bytes (NOT an echo of the body), so the
  // first committed op replies 1.
  assert_eq!(&reply[..], &1u64.to_be_bytes());

  // A cluster that just committed a request has written its WAL and durable root, so an orderly
  // stop must be able to say so: each node's teardown drains what its endpoint still owed and the
  // ack reports storage quiesced. A driver that acked without draining would be indistinguishable
  // here from one that was cut off mid-write.
  for (i, h) in handles.iter().enumerate() {
    let report = h
      .shutdown()
      .await
      .unwrap_or_else(|e| panic!("node {i} acks shutdown: {e:?}"));
    assert!(
      report.storage_quiesced(),
      "node {i} stopped with storage still in flight"
    );
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
#[compio::test]
async fn failover_after_an_idle_quiet_period_commits() {
  let ca = TestCa::new();
  let handles = spawn_cluster(&ca, 41030).await;

  // Converge: one committed request through the view-0 primary (replica 0).
  let reply = compio::time::timeout(
    std::time::Duration::from_secs(10),
    handles[0].submit(Bytes::from_static(b"warm")),
  )
  .await
  .expect("initial commit within 10s")
  .expect("a reply");
  assert_eq!(&reply[..], &1u64.to_be_bytes());

  // Idle past several 1s idle-timeout periods: only primary→backup heartbeats flow, so the
  // backup↔backup edges see zero traffic for the whole window.
  compio::time::sleep(std::time::Duration::from_secs(4)).await;

  // Kill the primary: the backups must now view-change over the long-quiet backup↔backup edges.
  let _ = handles[0].shutdown().await;

  // A request at a surviving node commits once the view change completes (replica 1 is the view-1
  // primary; if the view escalates further, the relayed-request path still reaches the new primary).
  // The committed log already holds the pre-idle op, so this op applies second.
  let reply = compio::time::timeout(
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
/// converges, so it only ever stops on shutdown or handle-drop; we build one, hold its `run` task's
/// `JoinHandle` (NOT detached, so we can await it), drop the sole `Handle`, and require the task to
/// finish inside the timeout. A regression where the iter-top drain treats `Disconnected` like
/// `Empty` (or the select command arm ignores the `Err`) spins the loop forever, so the `timeout`
/// fires and the test fails.
#[compio::test]
async fn quic_driver_exits_when_all_handles_dropped() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41020".parse().unwrap();
  // One node, no peers and no self-address: it binds + runs but never forms a cluster.
  let (driver, handle) = build_driver(&ca, 0, bind, Vec::new()).await;
  let task = compio::runtime::spawn(driver.run());

  drop(handle); // last Handle gone -> command channel closes

  // `.expect` asserts the timeout did not elapse (no spin); the inner join result (`run()` returns
  // `()`, or the task was cancelled) is intentionally ignored.
  let _ = compio::time::timeout(std::time::Duration::from_secs(5), task)
    .await
    .expect("driver.run() returns within 5s after the last Handle is dropped");
}

/// SHUTDOWN-ACK REBIND BARRIER (QUIC): `Handle::shutdown().await` resolves only after the driver's
/// UDP socket fd is fully RELEASED — the recv task's socket clone and its in-flight `recv_from`
/// reference are gone and the fd closed — so constructing a new driver bound to the SAME address
/// IMMEDIATELY after the ack must succeed. The await of the ack is the ONLY synchronization here:
/// no awaiting the (detached) run task, no settling sleeps. UDP binds without `SO_REUSEADDR`, so a
/// still-open prior fd fails the rebind with `DriverError::Bind`. An ack sent before the fd release
/// (e.g. tearing the recv task down by `JoinHandle` drop alone, whose cancel is only marked +
/// scheduled) races the runtime's cancel processing; looping the cycle pins the contract rather
/// than one lucky pass.
#[compio::test]
async fn shutdown_ack_frees_the_address_for_immediate_rebind() {
  let ca = TestCa::new();
  let bind: SocketAddr = "127.0.0.1:41040".parse().unwrap();
  for i in 0..5 {
    // Iterations 1.. bind the address the PREVIOUS iteration's driver just released: this
    // `build_driver` succeeding immediately after the ack is the assertion.
    let (driver, handle) = build_driver(&ca, 0, bind, Vec::new()).await;
    compio::runtime::spawn(driver.run()).detach();
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
#[compio::test]
async fn backup_submit_relays_to_the_primary() {
  let ca = TestCa::new();
  let handles = spawn_cluster(&ca, 41010).await;

  let reply = compio::time::timeout(
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

/// The storage notifier is a wake-latency optimization the embedder may not wire at all: dropping
/// every sender clone must DOWNGRADE storage pumping to timer cadence, not turn the dead channel
/// into an always-ready select arm. This builds a driver whose notifier is disconnected from the
/// start and drives the production `run()` loop on the single-threaded executor: a spinning loop
/// would starve the timer driver and the sleep below would never fire (a HANG here is the
/// regression); parked correctly, the sleep elapses and the shutdown acks within its bound.
#[compio::test]
async fn a_disconnected_storage_notifier_parks_its_arm_instead_of_spinning() {
  let ca = TestCa::new();
  let (chain, key) = ca.issue(0);
  let opts: QuicOptions = ClusterTls::new(ca.roots(), chain, key).build();
  let config = viewstamp_proto::Config::try_new(CLUSTER, viewstamp_proto::MemberId::new(0_u128))
    .expect("valid config");
  // The notifier sender is dropped on the spot: the driver must treat the dead channel as
  // "downgrade to timer cadence", not as a wake source.
  let (_, ready_rx) = flume::unbounded();
  let wal = InMemoryWal::new();
  let mut sb = InMemorySuperblock::new();
  // A genesis fixture: FORMAT the store so recovery resumes rather than fail-stopping this voter.
  viewstamp_driver::format(config, &genesis(3), &wal, &mut sb).expect("format the genesis store");
  let (driver, handle) = viewstamp_compio::CompioQuicDriver::new(
    config,
    genesis(3),
    viewstamp_simulation::sm::LogSm::default(),
    wal,
    sb,
    BlockLane::spawn(MemBlocks::default()),
    viewstamp_proto::ClientId::new(1),
    0,
    opts,
    IdentityConfig::Hello(CLUSTER),
    Some([0; 32]),
    "127.0.0.1:41050".parse().unwrap(),
    Vec::new(),
    ready_rx,
  )
  .await
  .expect("driver builds");
  compio::runtime::spawn(driver.run()).detach();
  compio::time::sleep(std::time::Duration::from_millis(10)).await;
  compio::time::timeout(std::time::Duration::from_secs(5), handle.shutdown())
    .await
    .expect("the shutdown ack arrives")
    .expect("driver acks shutdown");
}

/// How long the slow store's durability barrier parks waiting for the test's release. Bounded
/// rather than forever: a lane that regressed back onto the run loop would park that loop right
/// here, and a BOUNDED park makes the continuity awaits below fail on their own timeouts instead of
/// hanging the suite.
const SLOW_FLUSH_MAX_PARK: std::time::Duration = std::time::Duration::from_secs(30);

/// How long the falsifier waits for the slow materialize to START. Reaching it means no checkpoint
/// was ever issued, which would make the continuity assertions vacuous, so it fails loudly.
const MATERIALIZE_START_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// A block store whose durability barrier PARKS until the test releases it — the deliberately slow
/// store the heartbeat-continuity falsifier runs one node's checkpoint through.
///
/// `entered`/`finished` are the anti-vacuity witnesses: a commit observed while `entered > finished`
/// landed while a block job was genuinely mid-execution, not after a fast store had already
/// finished it.
struct SlowBlocks {
  blocks: std::collections::HashMap<BlockAddress, Bytes>,
  entered: std::sync::Arc<std::sync::atomic::AtomicUsize>,
  finished: std::sync::Arc<std::sync::atomic::AtomicUsize>,
  released: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl BlockStore for SlowBlocks {
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    self.blocks.get(&addr).cloned()
  }
  fn put(&mut self, block: Bytes) -> BlockAddress {
    let addr = viewstamp_proto::block_address(&block);
    self.blocks.insert(addr, block);
    addr
  }
  fn flush(&mut self) -> Result<(), viewstamp_proto::BlockStoreError> {
    use std::sync::atomic::Ordering;
    self.entered.fetch_add(1, Ordering::SeqCst);
    let deadline = std::time::Instant::now() + SLOW_FLUSH_MAX_PARK;
    while !self.released.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
      std::thread::sleep(std::time::Duration::from_millis(2));
    }
    self.finished.fetch_add(1, Ordering::SeqCst);
    Ok(())
  }
  fn has_block(&self, addr: BlockAddress) -> bool {
    self.blocks.contains_key(&addr)
  }
}

/// The test's side of a [`SlowBlocks`]: observe whether a durability barrier is executing right
/// now, and let it through once the continuity assertions are done.
struct FlushGate {
  entered: std::sync::Arc<std::sync::atomic::AtomicUsize>,
  finished: std::sync::Arc<std::sync::atomic::AtomicUsize>,
  released: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl FlushGate {
  fn new() -> (Self, SlowBlocks) {
    let entered = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let finished = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    (
      Self {
        entered: entered.clone(),
        finished: finished.clone(),
        released: released.clone(),
      },
      SlowBlocks {
        blocks: std::collections::HashMap::new(),
        entered,
        finished,
        released,
      },
    )
  }
  fn started(&self) -> usize {
    self.entered.load(std::sync::atomic::Ordering::SeqCst)
  }
  fn finished(&self) -> usize {
    self.finished.load(std::sync::atomic::Ordering::SeqCst)
  }
  fn release(&self) {
    self
      .released
      .store(true, std::sync::atomic::Ordering::SeqCst);
  }
}

/// The node given the parked store: a BACKUP in view 0, so its own in-flight checkpoint fences
/// nothing in the protocol (only a PRIMARY refuses to mint new ops while one is outstanding) and
/// what the falsifier measures is purely whether its run loop kept running.
const SLOW_NODE: u8 = 1;

/// A 3-node cluster in which [`SLOW_NODE`] holds a [`SlowBlocks`] lane and checkpoints on its first
/// commit; the other two keep ordinary stores and the default checkpoint interval, so no node but
/// the parked one has a block job outstanding while the falsifier runs.
async fn spawn_cluster_with_a_parked_backup(
  ca: &TestCa,
  base_port: u16,
) -> (Vec<viewstamp_compio::Handle>, FlushGate) {
  let (gate, slow) = FlushGate::new();
  let mut slow = Some(slow);
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
    let (blocks, checkpoint_ops) = if id == SLOW_NODE {
      (
        BlockLane::spawn(
          slow
            .take()
            .expect("exactly one node takes the parked store"),
        ),
        1,
      )
    } else {
      (
        BlockLane::spawn(MemBlocks::default()),
        viewstamp_proto::DEFAULT_CHECKPOINT_OPS,
      )
    };
    let (driver, handle) =
      build_driver_with(ca, id, addrs[id as usize], peers, blocks, checkpoint_ops).await;
    compio::runtime::spawn(driver.run()).detach();
    handles.push(handle);
  }
  (handles, gate)
}

/// SLOW-STORE HEARTBEAT CONTINUITY — the operational claim of the driver storage lane.
///
/// One backup's block store PARKS inside the durability barrier of its checkpoint materialize. That
/// job runs on the driver's storage lane, not on the run loop, so while it is parked the node must
/// keep doing consensus. Every submit below is made AT THE PARKED NODE, so resolving it needs that
/// node's own loop to drain the command, relay the `Request` to the primary, take the `Prepare`,
/// append, ack, take the `Commit`, apply, and deliver the committed event — a full heartbeat round
/// trip through the loop, not a liveness ping past it.
///
/// ANTI-VACUITY, in two parts. The test does not proceed until the barrier has actually STARTED, and
/// it asserts after EVERY commit that the barrier had not yet RETURNED — so each commit provably
/// landed while a block job was mid-execution, not after a fast store had already finished. Without
/// both halves a store that finished first would pass this trivially.
///
/// A lane that regressed back onto the run loop fails the FIRST await here: that loop would be
/// inside `flush` for [`SLOW_FLUSH_MAX_PARK`], far past the per-commit timeout.
#[compio::test]
async fn a_parked_checkpoint_materialize_does_not_stop_the_node_committing() {
  let ca = TestCa::new();
  let (handles, gate) = spawn_cluster_with_a_parked_backup(&ca, 41060).await;

  // Converge the cluster. The parked node's checkpoint interval is 1, so committing this op is what
  // issues its materialize — and that materialize's durability barrier is what parks.
  let reply = compio::time::timeout(
    std::time::Duration::from_secs(10),
    handles[0].submit(Bytes::from_static(b"warm")),
  )
  .await
  .expect("the cluster commits within 10s")
  .expect("a reply");
  assert_eq!(&reply[..], &1u64.to_be_bytes());

  // ANTI-VACUITY (1/2): do not proceed until the barrier has genuinely started.
  let start_by = std::time::Instant::now() + MATERIALIZE_START_DEADLINE;
  while gate.started() == 0 {
    assert!(
      std::time::Instant::now() < start_by,
      "no checkpoint materialize reached the parked node's storage lane within \
       {MATERIALIZE_START_DEADLINE:?}: the continuity assertions below would be vacuous",
    );
    compio::time::sleep(std::time::Duration::from_millis(5)).await;
  }

  for expected in 2..=4u64 {
    let reply = compio::time::timeout(
      std::time::Duration::from_secs(10),
      handles[SLOW_NODE as usize].submit(Bytes::from_static(b"during")),
    )
    .await
    .unwrap_or_else(|_| {
      panic!("the parked node commits op {expected} within 10s while its storage lane executes")
    })
    .expect("a reply");
    assert_eq!(&reply[..], &expected.to_be_bytes());
    // ANTI-VACUITY (2/2): the barrier had not returned when this commit landed, so the commit is
    // genuinely concurrent with a block job rather than after a fast store finished first.
    assert_eq!(
      gate.finished(),
      0,
      "op {expected} committed only after the parked durability barrier returned ({} started, {} \
       finished): the concurrency this test asserts was never exercised",
      gate.started(),
      gate.finished(),
    );
  }

  // Let the barrier through, then stop: the teardown drains the lane like any other storage.
  gate.release();
  for h in &handles {
    let _ = h.shutdown().await;
  }
}

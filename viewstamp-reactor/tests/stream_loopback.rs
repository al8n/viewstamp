//! The stream-driver gate: a real 3-node cluster over real TCP sockets converges and replies, both
//! plain (`Labeled<Passthrough>`) and over TLS (`Labeled<TlsRecords>`). Plain proves the hard
//! part — connection management (listen/accept/dial, the redial-on-fail recovery, the `Labeled`
//! cleartext handshake); TLS is the same loop with a record-layer swap.

use std::{
  net::SocketAddr,
  sync::{Arc, Mutex},
};

use bytes::Bytes;
use viewstamp_proto::{
  BlockAddress, BlockStore, Conn, LabelOptions, Labeled, MemberId, Membership, Passthrough, Peer,
  ReplicaId, StreamTransport, Superblock, Wal,
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

/// Wraps an in-memory store and signals the storage-ready notifier on every submit, so the driver
/// re-pumps. (A real async store signals on completion; the synchronous in-memory store completes on
/// submit, so it signals there.) Identical to the QUIC gate's `Notifying` (`tests/loopback.rs`).
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

/// Like [`Notifying`], but the store lives behind `Arc<Mutex<..>>` so it SURVIVES its driver: the
/// wrapper handed to a driver drops with it, while the test's `Arc` clone hands the SAME durable
/// state to a restarted driver — the in-memory stand-in for the on-disk store a real embedder
/// re-opens after a crash. Restart gates need this shape because the driver takes its storage by
/// value (and the simulation fixtures are not themselves shareable); the lock (not a `RefCell`)
/// keeps the wrapper `Send`, which `tokio::spawn` requires of the driver's `run()` future.
struct Shared<T> {
  inner: Arc<Mutex<T>>,
  ready: flume::Sender<()>,
}
impl<T> Shared<T> {
  fn new(inner: Arc<Mutex<T>>, ready: flume::Sender<()>) -> Self {
    Self { inner, ready }
  }
  fn signal(&self) {
    let _ = self.ready.try_send(());
  }
}
impl<T: Wal> Wal for Shared<T> {
  fn op_head(&self) -> viewstamp_proto::OpNumber {
    self.inner.lock().unwrap().op_head()
  }
  fn header(&self, op: viewstamp_proto::OpNumber) -> Option<viewstamp_proto::Header> {
    self.inner.lock().unwrap().header(op)
  }
  fn status(&self, op: viewstamp_proto::OpNumber) -> viewstamp_proto::SlotStatus {
    self.inner.lock().unwrap().status(op)
  }
  fn capacity(&self) -> u64 {
    self.inner.lock().unwrap().capacity()
  }
  fn submit_append(
    &mut self,
    id: viewstamp_proto::OpId,
    op: viewstamp_proto::OpNumber,
    h: viewstamp_proto::Header,
    b: Bytes,
  ) {
    self.inner.lock().unwrap().submit_append(id, op, h, b);
    self.signal();
  }
  fn submit_read(&mut self, id: viewstamp_proto::OpId, op: viewstamp_proto::OpNumber) {
    self.inner.lock().unwrap().submit_read(id, op);
    self.signal();
  }
  fn truncate(&mut self, above: viewstamp_proto::OpNumber) {
    self.inner.lock().unwrap().truncate(above);
  }
  fn prune(&mut self, below: viewstamp_proto::OpNumber) {
    self.inner.lock().unwrap().prune(below);
  }
  fn poll(&mut self) -> Option<viewstamp_proto::WalDone> {
    self.inner.lock().unwrap().poll()
  }
}
impl<T: Superblock> Superblock for Shared<T> {
  fn state(&self) -> viewstamp_proto::VsrState {
    self.inner.lock().unwrap().state()
  }
  fn submit_write(&mut self, id: viewstamp_proto::OpId, s: viewstamp_proto::VsrState) {
    self.inner.lock().unwrap().submit_write(id, s);
    self.signal();
  }
  fn submit_write_checkpoint(
    &mut self,
    id: viewstamp_proto::OpId,
    op: viewstamp_proto::OpNumber,
    snap: Bytes,
  ) {
    self
      .inner
      .lock()
      .unwrap()
      .submit_write_checkpoint(id, op, snap);
    self.signal();
  }
  fn submit_read_checkpoint(&mut self, id: viewstamp_proto::OpId) {
    self.inner.lock().unwrap().submit_read_checkpoint(id);
    self.signal();
  }
  fn poll(&mut self) -> Option<viewstamp_proto::SuperblockDone> {
    self.inner.lock().unwrap().poll()
  }
}

/// The concrete driver under test: pinned to the tokio `agnostic` runtime so construction needs no
/// runtime turbofish; the record layer `R` stays generic (plain vs TLS gates) over [`Notifying`]
/// throwaway storage.
type GateDriver<R> = viewstamp_reactor::ReactorStreamDriver<
  agnostic::tokio::TokioRuntime,
  viewstamp_simulation::sm::LogSm,
  R,
  Notifying<InMemoryWal>,
  Notifying<InMemorySuperblock>,
  MemBlocks,
>;

/// [`GateDriver`] over [`Shared`] storage, for the restart gate (the durable store outlives its
/// driver).
type RestartDriver = viewstamp_reactor::ReactorStreamDriver<
  agnostic::tokio::TokioRuntime,
  viewstamp_simulation::sm::LogSm,
  Labeled<Passthrough>,
  Shared<InMemoryWal>,
  Shared<InMemorySuperblock>,
  MemBlocks,
>;

/// Bind a fresh 3-node cluster on `127.0.0.1` TCP ports starting at `base_port`, each on its own
/// spawned `run` task, and return the node handles (index = replica id). The record layer `R` is
/// fixed by the `make_dialer` / `make_acceptor` factories (plain or TLS); each takes the node's own
/// replica id so the `Labeled` handshake announces the correct `Peer::Replica(me)`. Distinct ports
/// per test keep concurrently-running tests from colliding on the loopback address.
async fn spawn_cluster<R, MkD, MkA>(
  base_port: u16,
  make_dialer: MkD,
  make_acceptor: MkA,
) -> Vec<viewstamp_reactor::Handle>
where
  R: StreamTransport + Send + 'static,
  MkD: Fn(u8) -> Arc<dyn Fn(Peer) -> Conn<R> + Send + Sync>,
  MkA: Fn(u8) -> Arc<dyn Fn() -> Conn<R> + Send + Sync>,
{
  let addrs: Vec<SocketAddr> = (0..3)
    .map(|i| format!("127.0.0.1:{}", base_port + i).parse().unwrap())
    .collect();
  let mut handles = Vec::new();
  for id in 0u8..3 {
    let peers: Vec<_> = (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect();
    let config =
      viewstamp_proto::Config::try_new(CLUSTER, MemberId::new((id as u16) as u128)).unwrap();
    let (ready_tx, ready_rx) = flume::unbounded();
    let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
    let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
    let blocks = MemBlocks::default();
    let (driver, handle) = GateDriver::new(
      config,
      genesis(3),
      viewstamp_simulation::sm::LogSm::default(),
      wal,
      sb,
      blocks,
      viewstamp_proto::ClientId::new(u128::from(id) + 1),
      0,
      addrs[id as usize],
      peers,
      make_dialer(id),
      make_acceptor(id),
      ready_rx,
    )
    .await
    .expect("driver builds");
    // The dropped JoinHandle DETACHES the task (a tokio drop never cancels), so each node's run
    // loop keeps driving on its own.
    drop(tokio::spawn(driver.run()));
    handles.push(handle);
  }
  handles
}

/// The plain-TCP gate: a real 3-node cluster over `Labeled<Passthrough>` on loopback TCP commits one
/// client request and surfaces its reply through a backup's `Handle`. This proves the whole stream
/// driver stack end-to-end: the listener accepts, the dialer connects (recovering via redial when a
/// node dials a peer whose listener is not yet bound), the `Labeled` cleartext handshake registers +
/// rebinds each peer, three coordinators converge over real TCP byte streams, and reply interception
/// completes the `submit` future. The request is submitted at replica 1 (a backup in view 0): the
/// coordinator relays the `Request` to the primary over the mesh, exercising the relay path. Runs on
/// the multi-thread flavor so the spawned `run()` futures are scheduled (and may migrate) across
/// worker threads, exercising their `Send`-ness for real.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_node_tcp_cluster_commits_a_client_request() {
  let mk_dialer = |me: u8| -> Arc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move |_peer| {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Arc<dyn Fn() -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move || {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };
  let handles = spawn_cluster::<Labeled<Passthrough>, _, _>(45000, mk_dialer, mk_acceptor).await;

  let reply = tokio::time::timeout(
    std::time::Duration::from_secs(15),
    handles[1].submit(Bytes::from_static(b"hello")),
  )
  .await
  .expect("commit within 15s")
  .expect("a reply");

  // `LogSm::apply` returns the post-apply count as 8 big-endian bytes (NOT an echo of the body), so
  // the first committed op replies 1.
  assert_eq!(&reply[..], &1u64.to_be_bytes());

  for h in &handles {
    let _ = h.shutdown().await;
  }
}

/// Poll `cond` every 50ms until it holds, panicking with `what` after ~`secs` seconds.
async fn wait_until(secs: u64, mut cond: impl FnMut() -> bool, what: &str) {
  for _ in 0..(secs * 20) {
    if cond() {
      return;
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
  }
  panic!("timed out after {secs}s waiting for {what}");
}

/// RESTART GATE (stream driver): a converged 3-node cluster KILLS one node — its driver torn down
/// completely, its durable store kept — then RESTARTS it as a NEW driver over the SAME store, and
/// the cluster converges on a post-restart submit THROUGH the restarted node. The restarted node's
/// store is dirty (a durable WAL op), so the constructor must take the `Endpoint::recover` path:
/// the reply to the second submit is the state machine's post-apply count, so it is only correct if
/// the restarted node recovered op 1 from its WAL/commit catch-up and applied op 2 ON TOP — a node
/// that booted fresh-but-stale or never rejoined cannot produce it. Its own WAL receiving the
/// post-restart op then pins genuine consensus participation, not mere relay.
#[tokio::test]
async fn a_killed_node_restarts_over_its_durable_store_and_rejoins() {
  let mk_dialer = |me: u8| -> Arc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move |_peer| {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Arc<dyn Fn() -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move || {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };
  let addrs: Vec<SocketAddr> = (0..3)
    .map(|i| format!("127.0.0.1:{}", 45500 + i).parse().unwrap())
    .collect();
  let peers_of = |id: u8| -> Vec<(ReplicaId, SocketAddr)> {
    (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect()
  };

  // The durable stores OUTLIVE the drivers: the test holds the `Arc`s, each driver only a `Shared`
  // wrapper over them.
  let wals: Vec<Arc<Mutex<InMemoryWal>>> = (0..3)
    .map(|_| Arc::new(Mutex::new(InMemoryWal::new())))
    .collect();
  let sbs: Vec<Arc<Mutex<InMemorySuperblock>>> = (0..3)
    .map(|_| Arc::new(Mutex::new(InMemorySuperblock::new())))
    .collect();

  let mut handles = Vec::new();
  let mut victim_task = None;
  for id in 0u8..3 {
    let config =
      viewstamp_proto::Config::try_new(CLUSTER, MemberId::new((id as u16) as u128)).unwrap();
    let (ready_tx, ready_rx) = flume::unbounded();
    let wal = Shared::new(wals[id as usize].clone(), ready_tx.clone());
    let sb = Shared::new(sbs[id as usize].clone(), ready_tx);
    let blocks = MemBlocks::default();
    let (driver, handle) = RestartDriver::new(
      config,
      genesis(3),
      viewstamp_simulation::sm::LogSm::default(),
      wal,
      sb,
      blocks,
      viewstamp_proto::ClientId::new(u128::from(id) + 1),
      0,
      addrs[id as usize],
      peers_of(id),
      mk_dialer(id),
      mk_acceptor(id),
      ready_rx,
    )
    .await
    .expect("driver builds");
    let task = tokio::spawn(driver.run());
    if id == 2 {
      victim_task = Some(task); // held so the kill can await full teardown
    } else {
      drop(task); // the dropped JoinHandle detaches (a tokio drop never cancels)
    }
    handles.push(handle);
  }

  // Converge once: a committed op through a surviving backup.
  let reply = tokio::time::timeout(
    std::time::Duration::from_secs(15),
    handles[1].submit(Bytes::from_static(b"first")),
  )
  .await
  .expect("first commit within 15s")
  .expect("a reply");
  assert_eq!(&reply[..], &1u64.to_be_bytes());

  // The victim's store must be DIRTY before the kill (op 1 durably appended), so the restart is a
  // genuine recover, not a genesis boot.
  wait_until(
    5,
    || wals[2].lock().unwrap().op_head().get() >= 1,
    "the victim to durably append op 1",
  )
  .await;

  // KILL node 2: shutdown, then await its run task so the teardown is COMPLETE (conns dropped,
  // listener closed — the port is free for the restart to rebind) before restarting. The outer
  // `.expect` asserts the timeout did not elapse; the inner asserts the run task completed without
  // panicking (a held tokio JoinHandle never cancels its task).
  let _ = handles[2].shutdown().await;
  tokio::time::timeout(
    std::time::Duration::from_secs(5),
    victim_task.expect("the victim's run task was held"),
  )
  .await
  .expect("the victim's run() exits within 5s of shutdown")
  .expect("the victim's run task completes without panicking");

  // The crash boundary on the surviving store: anything in flight at the kill dies with the
  // process — staged (not-yet-durable) writes are lost and already-queued completions are never
  // delivered. This is also the driver constructor's storage contract: the handles a new driver
  // receives must carry no in-flight ops from a prior endpoint incarnation.
  wals[2].lock().unwrap().discard_inflight();
  sbs[2].lock().unwrap().discard_inflight();
  while wals[2].lock().unwrap().poll().is_some() {}
  while sbs[2].lock().unwrap().poll().is_some() {}

  // RESTART node 2 as a NEW driver over the SAME durable store (a fresh client session per the
  // constructor's session contract). Its dirty WAL forces the recover path.
  let (ready_tx, ready_rx) = flume::unbounded();
  let wal = Shared::new(wals[2].clone(), ready_tx.clone());
  let sb = Shared::new(sbs[2].clone(), ready_tx);
  let blocks = MemBlocks::default();
  let (driver, restarted) = RestartDriver::new(
    viewstamp_proto::Config::try_new(CLUSTER, MemberId::new(2_u128)).unwrap(),
    genesis(3),
    viewstamp_simulation::sm::LogSm::default(),
    wal,
    sb,
    blocks,
    viewstamp_proto::ClientId::new(99),
    0,
    addrs[2],
    peers_of(2),
    mk_dialer(2),
    mk_acceptor(2),
    ready_rx,
  )
  .await
  .expect("the restarted driver builds over the surviving store");
  // The dropped JoinHandle DETACHES the task (a tokio drop never cancels), so the restarted node's
  // run loop keeps driving on its own.
  drop(tokio::spawn(driver.run()));

  // Post-restart convergence THROUGH the restarted node: it must have rejoined the mesh (its own
  // dials, plus the peers' backed-off redials), caught its commit up, and applied op 1 then op 2 in
  // order — the reply is the post-apply count, so 2 proves the recovered prefix.
  let reply = tokio::time::timeout(
    std::time::Duration::from_secs(20),
    restarted.submit(Bytes::from_static(b"second")),
  )
  .await
  .expect("post-restart commit within 20s")
  .expect("a reply through the restarted node");
  assert_eq!(
    &reply[..],
    &2u64.to_be_bytes(),
    "the restarted node recovered op 1 and applied op 2 on top"
  );

  // And the restarted node PARTICIPATED (not merely relayed): its recovered WAL holds the
  // post-restart op.
  wait_until(
    5,
    || wals[2].lock().unwrap().op_head().get() >= 2,
    "the restarted node to durably append the post-restart op",
  )
  .await;

  let _ = restarted.shutdown().await;
  for h in &handles[..2] {
    let _ = h.shutdown().await;
  }
}

/// Handle-drop termination: `run()` must return when the LAST `Handle` is dropped (the command
/// channel disconnects), even under listener/accept pressure. A single node never converges, so it
/// only ever stops on shutdown or handle-drop; we build one (no peers, so no dials fire), keep its
/// `run` task's `JoinHandle` (so we can await it), drop the sole `Handle`, and require the task to
/// finish inside the timeout. A regression where the iter-top drain treats `Closed` like `Empty` —
/// or the select command arm silently ignores the `Err` — spins the loop forever (the accept arm
/// keeps winning the biased select while the dead command channel is dropped), so the `timeout`
/// fires and the test fails.
#[tokio::test]
async fn stream_driver_exits_when_all_handles_dropped() {
  let mk_dialer = |me: u8| -> Arc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move |_peer| {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Arc<dyn Fn() -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move || {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };

  let config = viewstamp_proto::Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
  let (ready_tx, ready_rx) = flume::unbounded();
  let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
  let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  let blocks = MemBlocks::default();
  let bind: SocketAddr = "127.0.0.1:45200".parse().unwrap();
  let (driver, handle) = GateDriver::new(
    config,
    genesis(3),
    viewstamp_simulation::sm::LogSm::default(),
    wal,
    sb,
    blocks,
    viewstamp_proto::ClientId::new(1),
    0,
    bind,
    Vec::new(), // no peers: nothing dials, the node just binds + runs
    mk_dialer(0),
    mk_acceptor(0),
    ready_rx,
  )
  .await
  .expect("driver builds");
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

/// SHUTDOWN-ACK REBIND BARRIER (stream): `Handle::shutdown().await` resolves only after the
/// driver's listener fd is fully RELEASED — the driver is the listener's SOLE owner (the accept
/// arm borrows it in-loop; no helper task holds a clone), and the teardown drops the listener
/// BEFORE sending the ack — so constructing a new driver bound to the SAME address IMMEDIATELY
/// after the ack must succeed. The await of the ack is the ONLY synchronization: unlike the
/// restart gate (which also awaits the victim's run task before rebinding), this pins the ack
/// itself as the barrier. A live prior listener fails the rebind with `DriverError::Bind` even
/// under `SO_REUSEADDR` (that option only bypasses `TIME_WAIT` remnants, not a still-open
/// listener). An ack sent before the listener drop would race the fd close; looping the cycle
/// pins the contract rather than one lucky pass.
#[tokio::test]
async fn shutdown_ack_frees_the_address_for_immediate_rebind_stream() {
  let mk_dialer = |me: u8| -> Arc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move |_peer| {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Arc<dyn Fn() -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move || {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };

  let bind: SocketAddr = "127.0.0.1:45600".parse().unwrap();
  for i in 0..5 {
    // Iterations 1.. bind the address the PREVIOUS iteration's driver just released: this
    // constructor succeeding immediately after the ack is the assertion.
    let config = viewstamp_proto::Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
    let (ready_tx, ready_rx) = flume::unbounded();
    let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
    let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
    let blocks = MemBlocks::default();
    let (driver, handle) = GateDriver::new(
      config,
      genesis(3),
      viewstamp_simulation::sm::LogSm::default(),
      wal,
      sb,
      blocks,
      viewstamp_proto::ClientId::new(1),
      0,
      bind,
      Vec::new(), // no peers: nothing dials, the node just binds + runs
      mk_dialer(0),
      mk_acceptor(0),
      ready_rx,
    )
    .await
    .unwrap_or_else(|e| panic!("rebind #{i} immediately after the ack succeeds: {e:?}"));
    // The dropped JoinHandle DETACHES the task (a tokio drop never cancels), so the run loop keeps
    // driving on its own.
    drop(tokio::spawn(driver.run()));
    handle
      .shutdown()
      .await
      .unwrap_or_else(|e| panic!("shutdown #{i} acks teardown: {e:?}"));
    // The command channel is non-admitting once the ack arrives: a surviving clone's submit takes
    // the disconnected path immediately (no parked command, no pinned reservation).
    let post = handle.submit(bytes::Bytes::from_static(b"post-ack")).await;
    assert!(
      matches!(post, Err(viewstamp_reactor::DriverError::DriverGone)),
      "a post-ack submit is DriverGone, got {post:?}"
    );
  }
}

/// The shutdown ack releases driver-held QUEUED resources, not just the listener: a completed dial
/// whose `TcpStream` is still in flight toward the run loop (queued as a dial completion, or just
/// promoted to an unvalidated conn) must be released by the teardown — on either path (cleared
/// conns abort their dial/bridge tasks; the dial-completion channel tears down with the driver,
/// dropping any still-queued stream). The witness is the test-held PEER socket: it reads EOF/reset
/// within a short bound after the ack. A regression that keeps the queued stream alive past the
/// teardown leaves the peer read blocked.
#[tokio::test]
async fn shutdown_releases_a_queued_dial_completion() {
  let mk_dialer = |me: u8| -> Arc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move |_peer| {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Arc<dyn Fn() -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move || {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };

  // A raw listener the driver will dial; the test accepts the connection and never speaks the
  // protocol, so the driver-side stream stays queued/unvalidated until teardown releases it.
  let raw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let peer_addr = raw.local_addr().unwrap();

  let config = viewstamp_proto::Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
  let (ready_tx, ready_rx) = flume::unbounded();
  let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
  let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  let blocks = MemBlocks::default();
  let (driver, handle) = GateDriver::new(
    config,
    genesis(3),
    viewstamp_simulation::sm::LogSm::default(),
    wal,
    sb,
    blocks,
    viewstamp_proto::ClientId::new(1),
    0,
    "127.0.0.1:45620".parse().unwrap(),
    vec![(ReplicaId::new(1), peer_addr)],
    mk_dialer(0),
    mk_acceptor(0),
    ready_rx,
  )
  .await
  .unwrap();
  // The dropped JoinHandle DETACHES the task (a tokio drop never cancels), so the run loop keeps
  // driving on its own.
  drop(tokio::spawn(driver.run()));

  // The driver's dial lands here; hold the peer end open and silent.
  let (peer_stream, _) = raw.accept().await.unwrap();

  handle.shutdown().await.unwrap();

  // The ack barrier: the driver-side stream is released (aborted with the conn table or dropped
  // with the dial-completion channel), so this end observes EOF/reset within a short bound rather
  // than blocking.
  // Drain until EOF/reset: depending on how far the dial got before the ack, the peer may first
  // receive the driver's hello bytes (the dialer speaks first once a bridge starts); the assertion
  // is that the stream CLOSES within the bound, on either teardown path.
  let read = tokio::time::timeout(std::time::Duration::from_secs(3), async {
    use tokio::io::AsyncReadExt;
    let mut s = peer_stream;
    let mut buf = vec![0u8; 64];
    loop {
      match s.read(&mut buf).await {
        Ok(0) | Err(_) => return, // EOF or reset: the driver-side fd is released
        Ok(_) => {}               // hello bytes from a briefly-live bridge: keep draining
      }
    }
  })
  .await;
  assert!(
    read.is_ok(),
    "the peer socket stayed open past the shutdown ack"
  );
}

/// Accept-side admission control: a peer that completes the TCP connect but sends NOTHING (no
/// `Labeled` hello, so the conn never validates) must NOT pin a connection slot forever — the driver
/// reaps it at `AUTH_DEADLINE` (5 s). We build a 1-node driver (no peers, so the ONLY conn is the
/// stalled raw one), open a RAW `tokio` `TcpStream` to its listener, send nothing, then assert the
/// SERVER closes it within the deadline window: a bounded read on the raw stream resolves with EOF
/// (0 bytes) or a reset (Err) once the driver drops the conn (the conn's abort-on-drop handles
/// abort both bridge halves, closing the socket). A regression that drops the auth-deadline
/// reconcile leaves the read blocked, so the read-timeout fires and the test fails.
#[tokio::test]
async fn stalled_unvalidated_accept_is_reaped_at_the_auth_deadline() {
  use tokio::io::AsyncReadExt;

  let mk_dialer = |me: u8| -> Arc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move |_peer| {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Arc<dyn Fn() -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move || {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };

  let bind: SocketAddr = "127.0.0.1:45300".parse().unwrap();
  let config = viewstamp_proto::Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
  let (ready_tx, ready_rx) = flume::unbounded();
  let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
  let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  let blocks = MemBlocks::default();
  let (driver, handle) = GateDriver::new(
    config,
    genesis(3),
    viewstamp_simulation::sm::LogSm::default(),
    wal,
    sb,
    blocks,
    viewstamp_proto::ClientId::new(1),
    0,
    bind,
    Vec::new(), // no peers: the only conn the driver ever holds is the stalled raw one below
    mk_dialer(0),
    mk_acceptor(0),
    ready_rx,
  )
  .await
  .expect("driver builds");
  // The dropped JoinHandle DETACHES the task (a tokio drop never cancels), so the run loop keeps
  // driving on its own.
  drop(tokio::spawn(driver.run()));

  // Raw client: complete the TCP connect, then send NOTHING — no `Labeled` hello, so the server's
  // accepted conn never validates and is subject to the auth deadline.
  let mut raw = tokio::net::TcpStream::connect(bind)
    .await
    .expect("raw client connects to the driver listener");

  // The read blocks until bytes arrive OR the peer closes; the server sends nothing, so this
  // resolves only when the driver reaps the unvalidated conn (EOF/reset). Bound it at AUTH_DEADLINE
  // + slack: the auth deadline is folded into the run loop's wake schedule, so the reap fires at
  // the 5 s deadline, well inside 8 s.
  let mut buf = vec![0u8; 64];
  let res = tokio::time::timeout(std::time::Duration::from_secs(8), raw.read(&mut buf))
    .await
    .expect("the driver closes the stalled unvalidated conn within AUTH_DEADLINE + slack");
  match res {
    Ok(0) => {} // EOF: the server closed the socket (graceful) — the conn was reaped
    Ok(n) => panic!("a stalled conn that sent no hello should never receive {n} bytes"),
    Err(_) => {} // reset/closed by the server — also a valid "reaped" observable
  }

  let _ = handle.shutdown().await;
}

/// Dial-side admission control + redial: a DIALED conn whose peer ACCEPTS the TCP connect but then
/// stays silent (no `Labeled` hello, so the conn never validates) must be reaped at `AUTH_DEADLINE`
/// (5 s) and REDIALED — the dial-path mirror of the accept-side reap above. This is the regression
/// guard for stamping the dialed conn's `auth_deadline` at the bridge handoff (`handle_dial_ready`)
/// rather than at dial registration: a pending dial carries no deadline (it is bounded by
/// `DIAL_TIMEOUT`), so without the handoff stamp the dialed conn would keep `auth_deadline = None`
/// forever, never be reaped, and never redial. We stand up a RAW `tokio` `TcpListener`, point a
/// configured peer at it, run the driver, and require the listener to observe a SECOND inbound
/// connection within a bounded wait — proving the first dialed conn was reaped at ~AUTH_DEADLINE and
/// redialed. A regression that removes the handoff stamp leaves the dialed conn pinned, so no second
/// connection arrives and the accept-timeout fires.
#[tokio::test]
async fn stalled_dialed_conn_is_reaped_at_the_auth_deadline_and_redials() {
  let mk_dialer = |me: u8| -> Arc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move |_peer| {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Arc<dyn Fn() -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move || {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };

  // Raw peer: a bare listener that accepts the driver's dial but never speaks the `Labeled` hello, so
  // the driver's dialed conn validates against nothing. Bind it first so its address is the
  // configured peer the driver dials at run() start.
  let peer_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
    .await
    .expect("raw peer listener binds");
  let peer_addr: SocketAddr = peer_listener.local_addr().expect("listener has an address");

  let bind: SocketAddr = "127.0.0.1:45400".parse().unwrap();
  let config = viewstamp_proto::Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
  let (ready_tx, ready_rx) = flume::unbounded();
  let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
  let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  let blocks = MemBlocks::default();
  let (driver, handle) = GateDriver::new(
    config,
    genesis(3),
    viewstamp_simulation::sm::LogSm::default(),
    wal,
    sb,
    blocks,
    viewstamp_proto::ClientId::new(1),
    0,
    bind,
    // One configured peer = the silent raw listener: the driver dials it at run() start, the connect
    // completes (the listener accepts), and the dialed conn then never validates.
    vec![(ReplicaId::new(1), peer_addr)],
    mk_dialer(0),
    mk_acceptor(0),
    ready_rx,
  )
  .await
  .expect("driver builds");
  // The dropped JoinHandle DETACHES the task (a tokio drop never cancels), so the run loop keeps
  // driving on its own.
  drop(tokio::spawn(driver.run()));

  // The driver's FIRST dial: the raw listener accepts it, then stays silent (no hello).
  let _first = tokio::time::timeout(std::time::Duration::from_secs(5), peer_listener.accept())
    .await
    .expect("the driver dials the configured peer promptly")
    .expect("first inbound connection accepted");

  // The SECOND inbound connection only arrives if the driver reaped the unvalidated first dial at
  // ~AUTH_DEADLINE (5 s) and redialed (after the jittered base redial backoff, ~200 ms). Bound it at
  // AUTH_DEADLINE + generous slack (the auth deadline is folded into the run loop's wake schedule,
  // so the reap fires at the 5 s deadline); a regression that drops the bridge-handoff stamp pins
  // the first conn forever, so no second connection ever arrives.
  let _second = tokio::time::timeout(std::time::Duration::from_secs(7), peer_listener.accept())
    .await
    .expect(
      "the stalled dialed conn is reaped at AUTH_DEADLINE and the driver redials within slack",
    )
    .expect("second inbound connection accepted");

  let _ = handle.shutdown().await;
}

// TLS is unconditionally available here: the reactor crate enables the proto's `tls-rustls-ring`,
// so there is no reactor-level `tls` cargo feature to gate on (a `cfg(feature = "tls")` gate would
// be always-false from this test crate and silently skip the TLS gate).
mod tls {
  use super::*;
  use viewstamp_proto::TlsRecords;

  /// A test-only certificate verifier that accepts ANY server certificate. Safe here because the
  /// `Labeled` handshake (not TLS) carries the cluster id + peer identity, and the loopback cluster
  /// shares one self-signed `"localhost"` cert; a real deployment supplies a cluster-CA verifier
  /// (see the QUIC driver's mandatory mTLS). Mirrors the proto's own `#[cfg(test)]`-private verifier
  /// in `transport/tls.rs`, which this test cannot reach.
  #[derive(Debug)]
  struct AcceptAny;
  impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
      &self,
      _end_entity: &rustls::pki_types::CertificateDer<'_>,
      _intermediates: &[rustls::pki_types::CertificateDer<'_>],
      _server_name: &rustls::pki_types::ServerName<'_>,
      _ocsp_response: &[u8],
      _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
      Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
      &self,
      _message: &[u8],
      _cert: &rustls::pki_types::CertificateDer<'_>,
      _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
      &self,
      _message: &[u8],
      _cert: &rustls::pki_types::CertificateDer<'_>,
      _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
      rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .supported_schemes()
    }
  }

  /// One self-signed `"localhost"` cert shared by the whole cluster, mirroring the proto's own
  /// `tls_options()` (`transport/loopback.rs`): server side trusts no client (`with_no_client_auth`),
  /// client side accepts any server cert via [`AcceptAny`]. Installs the ring crypto provider once.
  fn tls_config() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der =
      rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    let server = rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(vec![cert_der], key_der)
      .unwrap();
    let client = rustls::ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(AcceptAny))
      .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
  }

  /// The TLS gate: the same 3-node convergence as the plain gate, but each link is wrapped in
  /// `Labeled<TlsRecords>`. The connection management is identical; only the record layer changes, so
  /// a green here proves the driver carries a real TLS session over real sockets end-to-end.
  #[tokio::test]
  async fn three_node_tls_cluster_commits_a_client_request() {
    let (server, client) = tls_config();
    let mk_dialer = move |me: u8| -> Arc<dyn Fn(Peer) -> Conn<Labeled<TlsRecords>> + Send + Sync> {
      let client = client.clone();
      Arc::new(move |_peer| {
        let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let inner = TlsRecords::client(client.clone(), name).unwrap();
        Conn::from_parts(Labeled::dialer(inner, &opts))
      })
    };
    let mk_acceptor = move |me: u8| -> Arc<dyn Fn() -> Conn<Labeled<TlsRecords>> + Send + Sync> {
      let server = server.clone();
      Arc::new(move || {
        let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
        let inner = TlsRecords::server(server.clone()).unwrap();
        Conn::from_parts(Labeled::acceptor(inner, &opts))
      })
    };
    let handles = spawn_cluster::<Labeled<TlsRecords>, _, _>(45100, mk_dialer, mk_acceptor).await;

    let reply = tokio::time::timeout(
      std::time::Duration::from_secs(15),
      handles[1].submit(Bytes::from_static(b"hello")),
    )
    .await
    .expect("commit within 15s")
    .expect("a reply");
    assert_eq!(&reply[..], &1u64.to_be_bytes());

    for h in &handles {
      let _ = h.shutdown().await;
    }
  }
}

/// Unvalidated accepted sockets cannot durably deny admission: at the cap, a fresh accept EVICTS
/// the oldest unvalidated accepted conn instead of being dropped, so an inbound mesh socket is
/// never refused merely because earlier junk squats the table (the refusal would otherwise last
/// until the auth-deadline reap). Witness: with the cap full of stalled never-validating sockets,
/// a third raw connect is admitted — the OLDEST squatter reads EOF promptly (the eviction aborts
/// its bridges, dropping its socket halves) while the newcomer stays open well past the eviction
/// window (it lives on toward its own auth deadline, far beyond this test's bound).
#[tokio::test]
async fn a_full_cap_evicts_the_oldest_unvalidated_accept_for_a_fresh_one() {
  use tokio::io::AsyncReadExt;

  let mk_dialer = |me: u8| -> Arc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move |_peer| {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    })
  };
  let mk_acceptor = |me: u8| -> Arc<dyn Fn() -> Conn<Labeled<Passthrough>> + Send + Sync> {
    Arc::new(move || {
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(me as u128)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    })
  };

  let bind: SocketAddr = "127.0.0.1:45800".parse().unwrap();
  let config = viewstamp_proto::Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
  let (ready_tx, ready_rx) = flume::unbounded();
  let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
  let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
  let blocks = MemBlocks::default();
  let (driver, handle) = GateDriver::with_config(
    config,
    genesis(3),
    viewstamp_simulation::sm::LogSm::default(),
    wal,
    sb,
    blocks,
    viewstamp_proto::ClientId::new(1),
    0,
    bind,
    Vec::new(), // no peers: every slot below is an accepted raw socket
    mk_dialer(0),
    mk_acceptor(0),
    ready_rx,
    viewstamp_reactor::DriverConfig::new().with_max_conns(2),
  )
  .await
  .expect("driver builds");
  // The dropped JoinHandle DETACHES the task (a tokio drop never cancels), so the run loop keeps
  // driving on its own.
  drop(tokio::spawn(driver.run()));

  // Fill the cap with two stalled raw sockets (no Labeled hello: never validating). The sleeps
  // land them in distinct loop iterations, so the first holds the strictly oldest auth deadline.
  let mut s1 = tokio::net::TcpStream::connect(bind)
    .await
    .expect("first squatter connects");
  tokio::time::sleep(std::time::Duration::from_millis(50)).await;
  let s2 = tokio::net::TcpStream::connect(bind)
    .await
    .expect("second squatter connects");
  tokio::time::sleep(std::time::Duration::from_millis(50)).await;

  // The cap is full: this accept must EVICT the oldest squatter rather than be dropped.
  let mut s3 = tokio::net::TcpStream::connect(bind)
    .await
    .expect("fresh socket connects");

  // The evicted squatter's bridges die, dropping its socket halves: s1 drains to EOF within the
  // bound (any bytes first are the acceptor-side handshake output; EOF is the witness).
  let mut buf = [0u8; 256];
  let eof = tokio::time::timeout(std::time::Duration::from_secs(2), async {
    loop {
      match s1.read(&mut buf).await {
        Ok(0) => break true,
        Ok(_) => continue,
        Err(_) => break true, // a reset is the same witness: the conn was torn down
      }
    }
  })
  .await
  .expect("the oldest squatter is evicted within the bound");
  assert!(eof, "the evicted socket reached EOF/reset");

  // The newcomer was ADMITTED: a refused accept is closed on the spot (the at-cap drop path),
  // so staying open through this window — far short of its own auth deadline — is the
  // admission witness.
  let newcomer_alive = tokio::time::timeout(std::time::Duration::from_millis(300), async {
    match s3.read(&mut buf).await {
      Ok(0) | Err(_) => false, // closed: the fresh socket was the one refused
      Ok(_) => true,           // handshake bytes from the acceptor: definitely admitted
    }
  })
  .await
  // The timeout ELAPSING is the pass: nothing closed the newcomer within the window.
  .unwrap_or(true);
  assert!(newcomer_alive, "the fresh accept was admitted, not dropped");

  // The middle squatter is untouched by this test's assertions; shut the driver down.
  drop(s2);
  handle.shutdown().await.expect("driver acks shutdown");
}

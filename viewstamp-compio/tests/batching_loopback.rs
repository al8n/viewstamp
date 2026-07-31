//! The edge-batching gate: a real 3-node TCP cluster whose embedder state machine decodes batch
//! bodies, with ONE node's `Handle` consumed by the batching aggregator. Concurrent caller units
//! coalesce into FEWER consensus ops than units — witnessed from the cluster side by the per-unit
//! apply history each replica records — and every unit's reply matches the state machine's
//! deterministic per-unit function. The stall-smoke companion pins the `!Send`-class sleep
//! factory: `compio::time::sleep`'s future is `!Send`, and the bound-free aggregator API plus
//! `compio::runtime::spawn` genuinely admit it.

use std::{cell::RefCell, net::SocketAddr, rc::Rc, time::Duration};

use bytes::Bytes;
use viewstamp_driver::{BatchConfig, aggregator, aggregator_with_stall};
use viewstamp_proto::{
  BlockAddress, BlockStore, Conn, LabelOptions, Labeled, MemberId, Membership, Passthrough, Peer,
  ReplicaId, StateMachine, Superblock, Wal,
};
use viewstamp_simulation::{
  InMemorySuperblock, InMemoryWal,
  sm::{BatchSm, SIM_UNIT_REPLY_CEILING},
};

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
/// submit, so it signals there.) Identical to the stream gate's `Notifying` (`tests/stream_loopback.rs`).
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

/// The batch-decoding state machine behind a shared recorder: the driver takes the wrapper by
/// value while the test keeps an `Rc` clone of the inner [`BatchSm`] to read its per-unit apply
/// history — the cluster-side witness that units coalesced into fewer consensus ops.
struct SharedSm(Rc<RefCell<BatchSm>>);

impl SharedSm {
  fn new() -> (Self, Rc<RefCell<BatchSm>>) {
    let inner = Rc::new(RefCell::new(BatchSm::default()));
    (Self(inner.clone()), inner)
  }
}

impl StateMachine for SharedSm {
  fn apply(&mut self, op: viewstamp_proto::OpNumber, body: &[u8]) -> Bytes {
    self.0.borrow_mut().apply(op, body)
  }
  fn checkpoint(&mut self, store: &mut dyn BlockStore) -> BlockAddress {
    self.0.borrow_mut().checkpoint(store)
  }
  fn block_references(block: &[u8]) -> std::vec::Vec<BlockAddress> {
    BatchSm::block_references(block)
  }
  fn restore(
    &mut self,
    root: BlockAddress,
    store: &dyn BlockStore,
  ) -> Result<(), viewstamp_proto::RestoreError> {
    self.0.borrow_mut().restore(root, store)
  }
}

fn mk_dialer(me: u8) -> Rc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>>> {
  Rc::new(move |_peer| {
    let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(me as u16)));
    Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
  })
}

fn mk_acceptor(me: u8) -> Rc<dyn Fn() -> Conn<Labeled<Passthrough>>> {
  Rc::new(move || {
    let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(me as u16)));
    Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
  })
}

/// Bind a fresh 3-node cluster on freshly reserved `127.0.0.1` TCP ports over the plain
/// record layer (batching is record-layer-independent — the TLS swap is the stream gate's
/// concern), each on its own spawned `run` task, and return the node handles (index = replica id)
/// alongside each node's shared [`BatchSm`] recorder. Kernel-assigned ports per cluster keep
/// concurrently-running tests — and back-to-back per-feature-combination re-runs of this binary,
/// whose previous run's connections sit in TIME_WAIT for up to a minute — from colliding on the
/// loopback address (a fixed port constant fails `bind` with AddrInUse in that window).
async fn spawn_cluster() -> (Vec<viewstamp_compio::Handle>, Vec<Rc<RefCell<BatchSm>>>) {
  let reservations: Vec<std::net::TcpListener> = (0..3)
    .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a loopback port"))
    .collect();
  let addrs: Vec<SocketAddr> = reservations
    .iter()
    .map(|l| l.local_addr().expect("reserved listener has an address"))
    .collect();
  drop(reservations);
  let mut handles = Vec::new();
  let mut sms = Vec::new();
  for id in 0u8..3 {
    let peers: Vec<_> = (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p as u16), addrs[p as usize]))
      .collect();
    let config =
      viewstamp_proto::Config::try_new(CLUSTER, MemberId::new((id as u16) as u128)).unwrap();
    let (ready_tx, ready_rx) = flume::unbounded();
    let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
    let mut sb = Notifying::new(InMemorySuperblock::new(), ready_tx);
    // A real new cluster: FORMAT each store so recovery resumes the designated primary (an
    // unformatted voter would fail-stop — the wipe-amnesia safeguard).
    viewstamp_driver::format(config, &genesis(3), &wal, &mut sb).expect("format the genesis store");
    let blocks = MemBlocks::default();
    let (sm, recorder) = SharedSm::new();
    let (driver, handle) = viewstamp_compio::CompioStreamDriver::new(
      config,
      genesis(3),
      sm,
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
    .expect("driver builds");
    compio::runtime::spawn(driver.run()).detach();
    handles.push(handle);
    sms.push(recorder);
  }
  (handles, sms)
}

/// Poll `cond` every 50ms until it holds, panicking with `what` after ~`secs` seconds.
async fn wait_until(secs: u64, mut cond: impl FnMut() -> bool, what: &str) {
  for _ in 0..(secs * 20) {
    if cond() {
      return;
    }
    compio::time::sleep(Duration::from_millis(50)).await;
  }
  panic!("timed out after {secs}s waiting for {what}");
}

/// THE BATCHING GATE: replica 1's `Handle` (a backup in view 0, exercising the relay path) is
/// consumed by [`aggregator`]; 12 single units plus one atomic 4-unit group fire concurrently from
/// separate tasks. While each body flies the one-in-flight pump queues everything behind it, so
/// the 16 units must ride FEWER than 16 consensus ops (the atomic group alone caps the count at 13
/// even under pathological scheduling — its 4 units share one body by contract). The witness reads
/// replica 0's [`BatchSm`] recorder: exactly the 16 submitted units applied, across fewer distinct
/// ops, with the group's units sharing one op at consecutive unit indexes — two units visibly
/// sharing an op. Each caller's reply must equal its unit's 1-based global apply position (8
/// big-endian bytes), [`BatchSm`]'s deterministic per-unit function, demultiplexed back through
/// the aggregator.
#[compio::test]
async fn concurrent_units_batch_into_fewer_ops_over_a_real_cluster() {
  let (mut handles, sms) = spawn_cluster().await;

  // Consume replica 1's Handle into the aggregator. A clone survives ONLY for the final driver
  // shutdown: it never submits — the pump must stay the session's sole submitter.
  let node1 = handles.remove(1);
  let shutdown1 = node1.clone();
  let (batch, pump) = aggregator(node1, BatchConfig::new(SIM_UNIT_REPLY_CEILING));
  let pump_task = compio::runtime::spawn(pump.run());

  // 12 singles from 12 tasks, each resolving to its (unit, reply) pair.
  let mut singles = Vec::new();
  for i in 0..12u32 {
    let batch = batch.clone();
    singles.push(compio::runtime::spawn(async move {
      let unit = Bytes::from(format!("unit-{i:02}"));
      let reply = batch.submit(unit.clone()).await.expect("the unit commits");
      (unit, reply)
    }));
  }
  // One atomic group: all four units must ride ONE body, never split across ops.
  let group_units: Vec<Bytes> = (0..4).map(|i| Bytes::from(format!("group-{i}"))).collect();
  let group_task = {
    let batch = batch.clone();
    let units = group_units.clone();
    compio::runtime::spawn(
      async move { batch.submit_group(units).await.expect("the group commits") },
    )
  };

  let mut unit_replies = Vec::new();
  for task in singles {
    unit_replies.push(
      compio::time::timeout(Duration::from_secs(15), task)
        .await
        .expect("a unit reply within 15s")
        .expect("the submit task completes without panicking"),
    );
  }
  let group_replies = compio::time::timeout(Duration::from_secs(15), group_task)
    .await
    .expect("the group replies within 15s")
    .expect("the group task completes without panicking");

  // Every reply is in, so the view-0 primary has applied every unit; read the authoritative apply
  // order from its recorder (the wait only covers a mid-run view change shifting who applied
  // first — commits still propagate to replica 0).
  wait_until(
    10,
    || sms[0].borrow().units().len() >= 16,
    "replica 0 to apply all 16 units",
  )
  .await;
  let applied: Vec<(u64, u32, Bytes)> = sms[0].borrow().units().to_vec();
  assert_eq!(applied.len(), 16, "exactly the submitted units applied");

  // Exactly-once: the applied unit payloads are exactly the 16 submitted ones.
  let mut applied_bodies: Vec<&[u8]> = applied.iter().map(|(_, _, b)| b.as_ref()).collect();
  applied_bodies.sort_unstable();
  let mut submitted: Vec<&[u8]> = unit_replies
    .iter()
    .map(|(u, _)| u.as_ref())
    .chain(group_units.iter().map(|u| u.as_ref()))
    .collect();
  submitted.sort_unstable();
  assert_eq!(
    applied_bodies, submitted,
    "every submitted unit applied exactly once, nothing else"
  );

  // The batching witness: fewer consensus ops than units, i.e. some op carries several units.
  let ops: std::collections::BTreeSet<u64> = applied.iter().map(|(op, _, _)| *op).collect();
  assert!(
    ops.len() < 16,
    "batching engaged: {} ops carried 16 units",
    ops.len()
  );
  assert!(
    applied.windows(2).any(|w| w[0].0 == w[1].0),
    "at least two units share one consensus op"
  );

  // Per-unit reply oracle: BatchSm replies with the unit's 1-based GLOBAL apply position as 8
  // big-endian bytes, so each caller's demultiplexed reply must match its unit's recorder slot.
  let position = |unit: &Bytes| -> usize {
    applied
      .iter()
      .position(|(_, _, b)| b == unit)
      .expect("the unit was applied")
  };
  for (unit, reply) in &unit_replies {
    let k = position(unit) as u64;
    assert_eq!(
      &reply[..],
      &(k + 1).to_be_bytes(),
      "the reply is the unit's apply position"
    );
  }

  // The atomic group: one op, consecutive unit indexes in submission order, replies matching the
  // consecutive positions.
  assert_eq!(group_replies.len(), 4, "one reply per group unit, in order");
  let first = position(&group_units[0]);
  let (group_op, first_idx, _) = applied[first];
  for (j, (unit, reply)) in group_units.iter().zip(&group_replies).enumerate() {
    let (op, idx, body) = applied
      .get(first + j)
      .expect("the group occupies consecutive apply positions");
    assert_eq!(body, unit, "the group applied whole, in unit order");
    assert_eq!(*op, group_op, "the whole group shares one consensus op");
    assert_eq!(*idx, first_idx + j as u32, "consecutive unit indexes");
    assert_eq!(&reply[..], &((first + j) as u64 + 1).to_be_bytes());
  }

  // Pump teardown: the task clones are already gone, so dropping the last BatchHandle drains the
  // pump and `run()` RETURNS — awaited as the teardown ack before the drivers shut down.
  drop(batch);
  compio::time::timeout(Duration::from_secs(5), pump_task)
    .await
    .expect("the pump exits within 5s of the last BatchHandle dropping")
    .expect("the pump task completes without panicking");

  let _ = shutdown1.shutdown().await;
  for h in &handles {
    let _ = h.shutdown().await;
  }
}

/// The stall-smoke + the `!Send`-class pin: `compio::time::sleep`'s future is `!Send`, so this
/// factory is exactly what the aggregator's bound-free API exists to admit — the pump's `run()`
/// future is `!Send` here and `compio::runtime::spawn` (no `Send` bound) carries it anyway. A
/// GENEROUS deadline never fires on a healthy cluster: every reply resolves Ok (a stall would
/// resolve them `OutcomeUnknown`/`Refused` instead) and the pump still exits through the
/// drained-queue path at teardown. The terminal-stall BEHAVIOR is unit-tested in viewstamp-driver;
/// this pins the runtime wiring.
#[compio::test]
async fn a_generous_stall_deadline_never_fires_on_a_healthy_cluster() {
  let (mut handles, _sms) = spawn_cluster().await;

  let node1 = handles.remove(1);
  let shutdown1 = node1.clone();
  let (batch, pump) = aggregator_with_stall(
    node1,
    BatchConfig::new(SIM_UNIT_REPLY_CEILING),
    // Generous: loopback commits land in milliseconds, so a healthy run never loses the race.
    Duration::from_secs(60),
    compio::time::sleep,
  );
  let pump_task = compio::runtime::spawn(pump.run());

  // Sequential submits: each body arms (and beats) its own fresh sleep; the replies are the
  // global unit counts 1..=3 — deterministic because each unit ships alone.
  for i in 0..3u64 {
    let reply = compio::time::timeout(
      Duration::from_secs(15),
      batch.submit(Bytes::from(format!("steady-{i}"))),
    )
    .await
    .expect("commit within 15s")
    .expect("a healthy run resolves Ok, never Stalled");
    assert_eq!(&reply[..], &(i + 1).to_be_bytes());
  }

  drop(batch);
  compio::time::timeout(Duration::from_secs(5), pump_task)
    .await
    .expect("the pump exits within 5s of the last BatchHandle dropping")
    .expect("the pump task completes without panicking");

  let _ = shutdown1.shutdown().await;
  for h in &handles {
    let _ = h.shutdown().await;
  }
}

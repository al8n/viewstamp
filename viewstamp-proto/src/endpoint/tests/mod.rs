//! Shared test harness for the endpoint unit tests: the mock `Wal`/`Superblock`/
//! [`StateMachine`] impls and the `backup()`/`prepare()`/... helper constructors the
//! per-subsystem submodules below build on. Split out of the former monolithic
//! `endpoint/tests.rs` — the test bodies themselves are unchanged.

use super::*;

/// A deep-tail size the recovery fixtures share: comfortably larger than any real pipeline, so a test
/// tail of this depth (or a corrupt `op_head` capped to it via a bounded `capacity`) exercises the
/// window machinery well past ordinary operation.
const RECOVER_TAIL_WINDOW: u64 = 8192;
use crate::{
  BlockAddress, BlockStore, CheckpointRead, ClientId, Config, DoViewChange, Header, MemberId,
  Membership, OpId, OpNumber, Prepare, PreparedEntry, ReadOk, ReplicaId, Request, RequestNumber,
  SlotStatus, StartViewChange, Superblock, SuperblockDone, View, VsrState, Wal, WalDone,
  block_address,
};
use std::collections::VecDeque;

/// The genesis membership for an `n`-voter cluster (no learners) used across the endpoint fixtures:
/// `MemberId::new(i)` occupies slot `i`, so `slot_of(MemberId::new(i)) == ReplicaId::new(i)` and the
/// relocated quorum/primary/voter logic is byte-identical to the pre-`Membership` `Config` at epoch 0.
/// Pair it with a `Config` whose local member is `MemberId::new(old_replica_index)`.
///
/// Test fixtures use a fixed `config_id = 0` so hand-built test messages (which carry 0) pass the
/// strict ingress gate; production uses the hash-chained id (`Membership::genesis`).
fn genesis(n: u8) -> Membership {
  Membership::from_durable_parts(
    crate::Epoch::new(0),
    n,
    0,
    (0..n as u128).map(MemberId::new).collect(),
    0,
  )
  .expect("valid genesis membership")
}

/// The genesis membership for an `n`-voter cluster plus `learners` non-voting learners: voters take
/// slots `0..n` and learners take `n..n+learners`, each `MemberId::new(slot)`. Mirrors [`genesis`]
/// for the learner-membership fixtures.
///
/// Test fixtures use a fixed `config_id = 0` so hand-built test messages (which carry 0) pass the
/// strict ingress gate; production uses the hash-chained id (`Membership::genesis`).
fn genesis_with_learners(n: u8, learners: u16) -> Membership {
  let total = n as u128 + learners as u128;
  Membership::from_durable_parts(
    crate::Epoch::new(0),
    n,
    learners,
    (0..total).map(MemberId::new).collect(),
    0,
  )
  .expect("valid genesis membership with learners")
}

mod checkpoint;
mod epoch_ingress;
mod forfeit;
mod invariants;
mod learner_membership;
mod normal;
mod reconfig;
mod reconfigure;
mod recovery;
mod repair;
mod sender_binding;
mod state_sync;
mod timers;
mod view_change;

struct NoopSm;
impl StateMachine for NoopSm {
  fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> Bytes {
    Bytes::new()
  }

  fn checkpoint(&mut self, store: &mut dyn BlockStore) -> BlockAddress {
    let block = Bytes::new();
    let addr = block_address(&block);
    store.write_block(addr, block);
    addr
  }

  fn restore(
    &mut self,
    root: BlockAddress,
    store: &dyn BlockStore,
  ) -> Result<(), crate::RestoreError> {
    store
      .read_block(root)
      .map(|_| ())
      .ok_or(crate::RestoreError::new(root))
  }
}

/// Echoes the request body as its reply, so a test can observe exactly which bytes were applied
/// (used to prove `recover` restores real bodies — an empty-body regression echoes empty bytes).
struct EchoSm;
impl StateMachine for EchoSm {
  fn apply(&mut self, _op: OpNumber, body: &[u8]) -> Bytes {
    Bytes::copy_from_slice(body)
  }

  fn checkpoint(&mut self, store: &mut dyn BlockStore) -> BlockAddress {
    let block = Bytes::new();
    let addr = block_address(&block);
    store.write_block(addr, block);
    addr
  }

  fn restore(
    &mut self,
    root: BlockAddress,
    store: &dyn BlockStore,
  ) -> Result<(), crate::RestoreError> {
    store
      .read_block(root)
      .map(|_| ())
      .ok_or(crate::RestoreError::new(root))
  }
}

/// Records every applied `(op, body)` and round-trips them through a single-block `checkpoint` /
/// `restore` (mirrors the sim's `LogSm`). Used to prove `recover` restores the SM from the durable
/// checkpoint (a fresh SM has 0 applied; a restored one reflects the checkpoint). The inherent
/// `snapshot`/`restore_bytes` helpers carry the leaf serialization the block round-trip uses.
#[derive(Default)]
struct CountSm {
  applied: std::vec::Vec<(u64, std::vec::Vec<u8>)>,
}
impl CountSm {
  fn applied(&self) -> &[(u64, std::vec::Vec<u8>)] {
    &self.applied
  }

  fn snapshot(&self) -> Bytes {
    let mut out = std::vec::Vec::new();
    out.extend_from_slice(&(self.applied.len() as u64).to_be_bytes());
    for (op, body) in &self.applied {
      out.extend_from_slice(&op.to_be_bytes());
      out.extend_from_slice(&(body.len() as u64).to_be_bytes());
      out.extend_from_slice(body);
    }
    Bytes::from(out)
  }

  fn restore_bytes(&mut self, snapshot: &[u8]) {
    let mut applied = std::vec::Vec::new();
    let mut i = 0usize;
    let count = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
    i += 8;
    for _ in 0..count {
      let op = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
      i += 8;
      let len = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap()) as usize;
      i += 8;
      applied.push((op, snapshot[i..i + len].to_vec()));
      i += len;
    }
    self.applied = applied;
  }
}
impl StateMachine for CountSm {
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes {
    self.applied.push((op.get(), body.to_vec()));
    Bytes::copy_from_slice(body)
  }

  fn checkpoint(&mut self, store: &mut dyn BlockStore) -> BlockAddress {
    let block = self.snapshot();
    let addr = block_address(&block);
    store.write_block(addr, block);
    addr
  }

  fn restore(
    &mut self,
    root: BlockAddress,
    store: &dyn BlockStore,
  ) -> Result<(), crate::RestoreError> {
    let block = store
      .read_block(root)
      .ok_or(crate::RestoreError::new(root))?;
    self.restore_bytes(&block);
    Ok(())
  }
}

/// A `CountSm` whose checkpoint is a MULTI-block DAG — a root block referencing two distinct leaves
/// (`leaf-x` = the first half of the applied ops, `leaf-y` = the second half). Two leaves let a test
/// fault DIFFERENT (complementary) blocks on two replicas: replica A corrupts `leaf-x` but holds clean
/// `leaf-y`, replica B corrupts `leaf-y` but holds clean `leaf-x`. The block format mirrors the
/// `block_sync` tests: a 1-byte tag then a sequence of 16-byte child addresses, which `block_references`
/// parses (leaves carry no addresses). `restore` walks the DAG through the VERIFY-ON-READ `store`, so a
/// corrupt leaf reads back absent and surfaces a [`RestoreError`] — exactly the post-root SM-reconstruct
/// fault the obligation-failover paths recover from.
#[derive(Default)]
struct TwoLeafSm {
  applied: std::vec::Vec<(u64, std::vec::Vec<u8>)>,
}
impl TwoLeafSm {
  fn applied(&self) -> &[(u64, std::vec::Vec<u8>)] {
    &self.applied
  }

  fn leaf_bytes(tag: u8, ops: &[(u64, std::vec::Vec<u8>)]) -> Bytes {
    let mut out = std::vec::Vec::new();
    out.push(tag); // a leaf tag (no trailing addresses) — `block_references` yields none.
    out.extend_from_slice(&(ops.len() as u64).to_be_bytes());
    for (op, body) in ops {
      out.extend_from_slice(&op.to_be_bytes());
      out.extend_from_slice(&(body.len() as u64).to_be_bytes());
      out.extend_from_slice(body);
    }
    Bytes::from(out)
  }

  fn decode_leaf(block: &[u8], out: &mut std::vec::Vec<(u64, std::vec::Vec<u8>)>) {
    let mut i = 1usize; // skip the tag byte
    let count = u64::from_be_bytes(block[i..i + 8].try_into().unwrap());
    i += 8;
    for _ in 0..count {
      let op = u64::from_be_bytes(block[i..i + 8].try_into().unwrap());
      i += 8;
      let len = u64::from_be_bytes(block[i..i + 8].try_into().unwrap()) as usize;
      i += 8;
      out.push((op, block[i..i + len].to_vec()));
      i += len;
    }
  }

  /// The two leaf splits: the first `len/2` applied ops in `leaf-x`, the rest in `leaf-y`.
  fn leaves(&self) -> (Bytes, Bytes) {
    let mid = self.applied.len() / 2;
    (
      Self::leaf_bytes(b'x', &self.applied[..mid]),
      Self::leaf_bytes(b'y', &self.applied[mid..]),
    )
  }
}
impl StateMachine for TwoLeafSm {
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes {
    self.applied.push((op.get(), body.to_vec()));
    Bytes::copy_from_slice(body)
  }

  fn checkpoint(&mut self, store: &mut dyn BlockStore) -> BlockAddress {
    let (leaf_x, leaf_y) = self.leaves();
    let xa = block_address(&leaf_x);
    let ya = block_address(&leaf_y);
    store.write_block(xa, leaf_x);
    store.write_block(ya, leaf_y);
    let mut root = std::vec::Vec::new();
    root.push(b'R');
    root.extend_from_slice(xa.as_bytes());
    root.extend_from_slice(ya.as_bytes());
    let root = Bytes::from(root);
    let roota = block_address(&root);
    store.write_block(roota, root);
    roota
  }

  fn restore(
    &mut self,
    root: BlockAddress,
    store: &dyn BlockStore,
  ) -> Result<(), crate::RestoreError> {
    let root_block = store
      .read_block(root)
      .ok_or(crate::RestoreError::new(root))?;
    let mut applied = std::vec::Vec::new();
    for child in Self::block_references(&root_block) {
      let leaf = store
        .read_block(child)
        .ok_or(crate::RestoreError::new(child))?;
      Self::decode_leaf(&leaf, &mut applied);
    }
    self.applied = applied;
    Ok(())
  }

  fn block_references(block: &[u8]) -> std::vec::Vec<BlockAddress> {
    let payload = match block.split_first() {
      Some((b'R', rest)) => rest, // only the root tag carries child addresses; leaves carry none.
      _ => return std::vec::Vec::new(),
    };
    payload
      .chunks_exact(16)
      .map(|c| {
        let mut a = [0u8; 16];
        a.copy_from_slice(c);
        BlockAddress::from_bytes(a)
      })
      .collect()
  }
}

#[derive(Default)]
struct TestWal {
  entries: BTreeMap<u64, (Header, Bytes)>,
  head: u64,
  done: VecDeque<WalDone>,
}
impl Wal for TestWal {
  fn op_head(&self) -> OpNumber {
    OpNumber::with(self.head)
  }
  fn header(&self, op: OpNumber) -> Option<Header> {
    self.entries.get(&op.get()).map(|(h, _)| *h)
  }
  fn status(&self, op: OpNumber) -> SlotStatus {
    if self.entries.contains_key(&op.get()) {
      SlotStatus::Clean
    } else {
      SlotStatus::Empty
    }
  }
  fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes) {
    self.entries.insert(op.get(), (header, body));
    self.head = self.head.max(op.get());
    self.done.push_back(WalDone::Appended(id));
  }
  fn submit_read(&mut self, id: OpId, op: OpNumber) {
    self.done.push_back(match self.entries.get(&op.get()) {
      Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    });
  }
  fn truncate(&mut self, above: OpNumber) -> std::vec::Vec<OpId> {
    self.entries.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
    std::vec::Vec::new()
  }
  fn prune(&mut self, below: OpNumber) -> std::vec::Vec<OpId> {
    self.entries.retain(|&op, _| op >= below.get());
    std::vec::Vec::new()
  }
  fn poll(&mut self) -> Option<WalDone> {
    self.done.pop_front()
  }
}

/// One submitted-but-not-yet-landed physical append held by [`ReorderWal`]: its bytes are already at
/// the device but its completion is withheld until the test releases (or cancels) it.
#[derive(Clone)]
struct StagedAppend {
  id: OpId,
  op: u64,
  header: Header,
  body: Bytes,
}

/// An async WAL modelling a proactor whose submitted writes are ALREADY AT THE DEVICE: `submit_append`
/// STAGES the `(id, op, header, body)` in submission order — the bytes do NOT land and the completion is
/// HELD until the test drives it. The synchronous views ([`Wal::op_head`], [`Wal::header`],
/// [`Wal::status`]) reflect ONLY the landed `entries`; a staged slot reports [`SlotStatus::Dirty`]. The
/// test releases completions EXPLICITLY (newest-first per op), so it can reproduce a device completing
/// the OLD write of a slot AFTER the endpoint abandoned it — the reordering the slot-quiescence fence
/// exists to survive.
///
/// `truncate`/`prune` trim the landed `entries` but KEEP every staged write — an un-cancellable device
/// write that may land late into the trimmed region (the tolerated resurrection) — and report NOTHING
/// cancelled, UNLESS `cancel_on_truncate` is set, in which case they synchronously drop the affected
/// staged writes and return their ids (the ideal cancelling backend, which opens no deferral window).
struct ReorderWal {
  /// Durably LANDED entries. Only these back `op_head`/`header`/a `Clean` `status`.
  entries: BTreeMap<u64, (Header, Bytes)>,
  head: u64,
  capacity: u64,
  /// Submitted appends whose completion is HELD, in submission order (newest last).
  staged: std::vec::Vec<StagedAppend>,
  /// Completions produced by `release_latest_for` (`Appended`) / `cancel_latest_for` (`Cancelled`).
  done: VecDeque<WalDone>,
  /// When set, `truncate`/`prune` SYNCHRONOUSLY cancel the staged writes they trim and return their
  /// ids (`wal_writes` clears on the spot, so a replacement append submits WITHOUT deferral).
  cancel_on_truncate: bool,
}
impl ReorderWal {
  /// A ring-less reorder WAL (`capacity == u64::MAX`): only the same op number aliases a slot.
  fn new() -> Self {
    Self::with_capacity(u64::MAX)
  }

  /// A BOUNDED reorder WAL of `n` slots: op `K` occupies slot `K mod n`, so op `K + n` aliases op `K`'s
  /// slot (the ring-wrap flavour of the reuse hazard).
  fn bounded(n: u64) -> Self {
    Self::with_capacity(n)
  }

  fn with_capacity(capacity: u64) -> Self {
    Self {
      entries: BTreeMap::new(),
      head: 0,
      capacity,
      staged: std::vec::Vec::new(),
      done: VecDeque::new(),
      cancel_on_truncate: false,
    }
  }

  /// Enable the ideal synchronously-cancelling backend: `truncate`/`prune` cancel their trimmed staged
  /// writes on the spot (returning the cancelled ids) instead of keeping them for a late landing.
  fn cancelling(mut self) -> Self {
    self.cancel_on_truncate = true;
    self
  }

  /// The index of the NEWEST staged append for `op` (the last submitted — its completion is the one a
  /// newest-first device would release first), or `None` if none is staged for `op`.
  fn newest_staged_for(&self, op: u64) -> Option<usize> {
    self.staged.iter().rposition(|s| s.op == op)
  }

  /// Pop the NEWEST staged append for `op` and LAND its bytes: insert into `entries`, raise `head`, and
  /// (on a bounded ring) EVICT the ring-aliased entry whatever op last held that slot — the physical
  /// overwrite a wrap performs. Queues its `Appended` completion. Landing happens even into a
  /// truncated/pruned region (the resurrection the fence tolerates). Returns `false` if none is staged.
  fn release_latest_for(&mut self, op: u64) -> bool {
    let Some(i) = self.newest_staged_for(op) else {
      return false;
    };
    let s = self.staged.remove(i);
    // Bounded ring: writing slot `op mod capacity` physically evicts the DIFFERENT op that last held it.
    if self.capacity != u64::MAX {
      let slot = s.op % self.capacity;
      self
        .entries
        .retain(|&k, _| k == s.op || k % self.capacity != slot);
    }
    self.entries.insert(s.op, (s.header, s.body));
    self.head = self.head.max(s.op);
    self.done.push_back(WalDone::Appended(s.id));
    true
  }

  /// Pop the NEWEST staged append for `op` WITHOUT landing its bytes and queue its `Cancelled`
  /// completion — the ASYNCHRONOUS cancellation report a proactor delivers at completion time. Returns
  /// `false` if none is staged.
  fn cancel_latest_for(&mut self, op: u64) -> bool {
    let Some(i) = self.newest_staged_for(op) else {
      return false;
    };
    let s = self.staged.remove(i);
    self.done.push_back(WalDone::Cancelled(s.id));
    true
  }

  /// The number of staged (submitted-but-not-yet-landed) appends.
  fn staged_len(&self) -> usize {
    self.staged.len()
  }

  /// The op numbers currently staged, in submission order — the witness a test asserts against to prove
  /// a fence-deferred append was NOT yet submitted (its op is absent) or was released (its op appears).
  fn staged_ops(&self) -> std::vec::Vec<u64> {
    self.staged.iter().map(|s| s.op).collect()
  }

  /// The LANDED body at `op` (the durable slot content), or `None` if no completed append holds it — the
  /// final-state witness that the durable slot holds exactly the value this replica's vote/ack named.
  fn durable_body(&self, op: u64) -> Option<Bytes> {
    self.entries.get(&op).map(|(_, b)| b.clone())
  }

  /// The staged writes a `truncate`/`prune` for the trimmed region cancels: their ids (cleared from the
  /// staged set). Only used when `cancel_on_truncate` is set.
  fn cancel_trimmed(&mut self, keep: impl Fn(u64) -> bool) -> std::vec::Vec<OpId> {
    let mut cancelled = std::vec::Vec::new();
    self.staged.retain(|s| {
      if keep(s.op) {
        true
      } else {
        cancelled.push(s.id);
        false
      }
    });
    cancelled
  }
}
impl Wal for ReorderWal {
  fn op_head(&self) -> OpNumber {
    OpNumber::with(self.head)
  }
  fn capacity(&self) -> u64 {
    self.capacity
  }
  fn header(&self, op: OpNumber) -> Option<Header> {
    self.entries.get(&op.get()).map(|(h, _)| *h)
  }
  fn status(&self, op: OpNumber) -> SlotStatus {
    if self.entries.contains_key(&op.get()) {
      SlotStatus::Clean
    } else if self.staged.iter().any(|s| s.op == op.get()) {
      // Submitted but not yet landed — the in-flight window the fence tracks; NEVER `Clean`.
      SlotStatus::Dirty
    } else {
      SlotStatus::Empty
    }
  }
  fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes) {
    // STAGE only — the bytes are at the device but the completion is withheld until the test releases
    // it. `entries`/`head` are untouched, so the synchronous views keep reporting only landed data.
    self.staged.push(StagedAppend {
      id,
      op: op.get(),
      header,
      body,
    });
  }
  fn submit_read(&mut self, id: OpId, op: OpNumber) {
    // Reads reflect only LANDED entries (a staged slot reads `Absent`, per the poll-ordering contract).
    self.done.push_back(match self.entries.get(&op.get()) {
      Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    });
  }
  fn truncate(&mut self, above: OpNumber) -> std::vec::Vec<OpId> {
    self.entries.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
    if self.cancel_on_truncate {
      return self.cancel_trimmed(|op| op <= above.get());
    }
    // Un-cancellable device writes: keep every staged append (it may land late — the resurrection the
    // fence tolerates) and report NOTHING cancelled, so the endpoint awaits each completion.
    std::vec::Vec::new()
  }
  fn prune(&mut self, below: OpNumber) -> std::vec::Vec<OpId> {
    self.entries.retain(|&op, _| op >= below.get());
    if self.cancel_on_truncate {
      return self.cancel_trimmed(|op| op >= below.get());
    }
    std::vec::Vec::new()
  }
  fn poll(&mut self) -> Option<WalDone> {
    self.done.pop_front()
  }
}

#[derive(Default)]
struct TestSb {
  state: VsrState,
  done: VecDeque<SuperblockDone>,
  /// The last checkpoint snapshot written (op, bytes) — stored so a recover/read test can read it
  /// back, mirroring `InMemorySuperblock`.
  checkpoint: Option<(OpNumber, Bytes)>,
}
impl Superblock for TestSb {
  fn state(&self) -> VsrState {
    self.state.clone()
  }
  fn submit_write(&mut self, id: OpId, state: VsrState) {
    self.state = state;
    self.done.push_back(SuperblockDone::Wrote(id));
  }
  fn submit_write_checkpoint(&mut self, id: OpId, op: OpNumber, snapshot: Bytes) {
    self.checkpoint = Some((op, snapshot));
    self.done.push_back(SuperblockDone::Wrote(id));
  }
  fn submit_read_checkpoint(&mut self, id: OpId) {
    let done = match &self.checkpoint {
      Some((op, snap)) => {
        SuperblockDone::CheckpointRead(CheckpointRead::new(id, *op, snap.clone()))
      }
      None => SuperblockDone::Fault(id),
    };
    self.done.push_back(done);
  }
  fn poll(&mut self) -> Option<SuperblockDone> {
    self.done.pop_front()
  }
}

/// A superblock that completes writes *lazily*, one durability round at a time — modelling a real
/// async superblock where a write submitted during a `handle_storage` drain does NOT complete in
/// that same drain (it lands on disk between ticks). Submissions queue in `inflight`; `flush()`
/// (called by the test between `handle_storage` rounds) makes the currently-inflight writes
/// durable (`ready`). This lets a test step the 3-step checkpoint sequence one superblock write at
/// a time and observe the intermediate (not-yet-durable) states the synchronous `TestSb` hides.
#[derive(Default)]
struct StepSb {
  state: VsrState,
  inflight: VecDeque<SuperblockDone>,
  ready: VecDeque<SuperblockDone>,
  /// The state each inflight write will publish once flushed (paired by position with `inflight`).
  inflight_states: VecDeque<VsrState>,
  checkpoint: Option<(OpNumber, Bytes)>,
}
impl StepSb {
  /// Make all currently-inflight writes durable: publish their states and move completions to
  /// `ready`. Writes submitted *after* this call wait for the next `flush`.
  fn flush(&mut self) {
    while let Some(done) = self.inflight.pop_front() {
      if let Some(state) = self.inflight_states.pop_front() {
        self.state = state;
      }
      self.ready.push_back(done);
    }
  }
  /// Whether a checkpoint write or root write is still inflight (not yet flushed).
  fn has_inflight(&self) -> bool {
    !self.inflight.is_empty()
  }
}
impl Superblock for StepSb {
  fn state(&self) -> VsrState {
    self.state.clone()
  }
  fn submit_write(&mut self, id: OpId, state: VsrState) {
    self.inflight.push_back(SuperblockDone::Wrote(id));
    self.inflight_states.push_back(state);
  }
  fn submit_write_checkpoint(&mut self, id: OpId, op: OpNumber, snapshot: Bytes) {
    // The checkpoint snapshot becomes readable only once this write is flushed; record it eagerly
    // for simplicity (the durability gate that matters is the VsrState root ordering).
    self.checkpoint = Some((op, snapshot));
    self.inflight.push_back(SuperblockDone::Wrote(id));
    self.inflight_states.push_back(self.state.clone()); // a checkpoint write does not change the root
  }
  fn submit_read_checkpoint(&mut self, id: OpId) {
    let done = match &self.checkpoint {
      Some((op, snap)) => {
        SuperblockDone::CheckpointRead(CheckpointRead::new(id, *op, snap.clone()))
      }
      None => SuperblockDone::Fault(id),
    };
    self.ready.push_back(done);
  }
  fn poll(&mut self) -> Option<SuperblockDone> {
    self.ready.pop_front()
  }
}

/// A WAL whose reads can be *scripted* to fault, so a test can drive the async `Recovering`
/// loop's retry/RecoveringHead branches deterministically. Each slot carries a real
/// `(header, body)` (so a clean read verifies) plus an optional fault script:
/// - `read_faults[op] = n` → the next `n` reads of `op` return `WalDone::Fault` (a TRANSIENT
///   fault: the `n+1`-th read succeeds). `u8::MAX` models a fault that outlives any finite
///   retry budget (→ a *permanently* faulty slot from the proto's view).
/// - `corrupt[op]` → every read of `op` returns a `ReadOk` whose body does NOT match its header
///   (a torn write / bit-rot the backend cannot hide): the proto's `Header::verify` chokepoint
///   must reject it rather than adopt the corrupt body.
///
/// Reads complete synchronously into the queue (like `TestWal`); the fault is in the *verdict*,
/// not the timing, which is exactly what the recover loop must tolerate.
struct ScriptedWal {
  entries: BTreeMap<u64, (Header, Bytes)>,
  head: u64,
  /// The ring slot capacity reported by [`Wal::capacity`] — `u64::MAX` (unbounded) by default; a test sets
  /// it to model a bounded WAL whose `op_head` cannot exceed `checkpoint_op + capacity`.
  capacity: u64,
  read_faults: BTreeMap<u64, u8>,
  corrupt: std::collections::BTreeSet<u64>,
  /// Slots whose HEADER is durable (still served by `header()`) but whose BODY is permanently
  /// unrecoverable (torn / bit-rot): every read yields `WalDone::BodyFaulty(header)`. Mirrors the sim
  /// WAL's torn/rotted-body verdict — the op EXISTS, only the body needs peer-repair.
  body_faulty: std::collections::BTreeSet<u64>,
  /// `op → n`: the next `n` APPENDS of `op` complete as `WalDone::Fault` without landing (a
  /// contract-violating backend; the `n+1`-th append succeeds). Drives the endpoint's defensive
  /// faulted-append retry.
  append_faults: BTreeMap<u64, u8>,
  /// `op → count` of `submit_append` calls observed, so a test can prove a faulted append was
  /// re-submitted.
  append_submits: BTreeMap<u64, u32>,
  /// Ops whose READ is HELD (deferred), modelling a real async WAL whose read latency exceeds the
  /// recover-retry cadence: `submit_read` records the submitted id in `deferred_reads` but enqueues NO
  /// completion. `release_deferred(op)` later completes the OLDEST still-held submission under its
  /// ORIGINAL id — the way a real proactor completes the read that was actually submitted first, long
  /// after a retry has minted a newer id. Additive-id retransmission keeps that original id live, so the
  /// late completion resolves; the old retire-on-retry behavior had retired it (the completion would be
  /// ignored and the pending set never empty — the wedge this models).
  deferred: std::collections::BTreeSet<u64>,
  /// Per deferred op: the submitted read ids still HELD, oldest-first. Each `submit_read` of a deferred
  /// op pushes its id; `release_deferred` pops the front (the original slow read finally completing).
  deferred_reads: BTreeMap<u64, VecDeque<OpId>>,
  done: VecDeque<WalDone>,
}
impl ScriptedWal {
  /// A WAL holding dense ops `1..=n`, each with header+body `[op]` (a clean read verifies).
  fn with_entries(n: u64) -> Self {
    let mut entries = BTreeMap::new();
    for op in 1..=n {
      let body = Bytes::copy_from_slice(&[op as u8]);
      let h = Header::new(
        OpNumber::with(op),
        View::new(),
        ClientId::new(7),
        RequestNumber::with(op),
        &body,
      );
      entries.insert(op, (h, body));
    }
    Self {
      entries,
      head: n,
      capacity: u64::MAX,
      read_faults: BTreeMap::new(),
      corrupt: std::collections::BTreeSet::new(),
      body_faulty: std::collections::BTreeSet::new(),
      append_faults: BTreeMap::new(),
      append_submits: BTreeMap::new(),
      deferred: std::collections::BTreeSet::new(),
      deferred_reads: BTreeMap::new(),
      done: VecDeque::new(),
    }
  }
  /// Script the next `times` APPENDS of `op` to fault without landing (a contract-violating
  /// backend; the following append succeeds).
  fn script_append_fault(&mut self, op: OpNumber, times: u8) {
    self.append_faults.insert(op.get(), times);
  }
  /// How many `submit_append` calls this WAL has seen for `op`.
  fn append_submits(&self, op: OpNumber) -> u32 {
    self.append_submits.get(&op.get()).copied().unwrap_or(0)
  }
  /// Script the next `times` reads of `op` to fault (transient). `u8::MAX` ⇒ never clears.
  fn script_read_fault(&mut self, op: OpNumber, times: u8) {
    self.read_faults.insert(op.get(), times);
  }
  /// Script every read of `op` to return a ReadOk whose body fails `Header::verify` (permanent).
  fn script_corrupt_body(&mut self, op: OpNumber) {
    self.corrupt.insert(op.get());
  }
  /// Script every read of `op` to return `WalDone::BodyFaulty` carrying `op`'s durable header (the
  /// header survives, only the body is unrecoverable). Permanent: the verdict never clears on disk.
  fn script_body_faulty(&mut self, op: OpNumber) {
    self.body_faulty.insert(op.get());
  }
  /// Remove `op`'s slot entirely (no durable header, no body): `header()` returns `None` and a read of
  /// `op` resolves to `WalDone::Absent`. Models a genuine hole the writer never held.
  fn remove_entry_for_test(&mut self, op: OpNumber) {
    self.entries.remove(&op.get());
  }
  /// HOLD every read of `op`: `submit_read` records the submitted id (pushed oldest-first) but enqueues
  /// NO completion, modelling a real async WAL whose read latency exceeds the recover-retry cadence.
  /// `release_deferred(op)` later completes the OLDEST held submission under its original id.
  fn script_defer_read(&mut self, op: OpNumber) {
    self.deferred.insert(op.get());
  }
  /// Complete the OLDEST still-held read of a deferred `op` under its ORIGINAL id — the slow first
  /// submission finally landing, AFTER a retry has minted a newer id. (Under retire-on-retry that
  /// original id was retired, so the completion would be IGNORED and recovery would never resolve `op`;
  /// additive ids keep it live, so this resolves.) Returns `false` if no read of `op` is outstanding.
  fn release_deferred(&mut self, op: OpNumber) -> bool {
    let Some(id) = self
      .deferred_reads
      .get_mut(&op.get())
      .and_then(|q| q.pop_front())
    else {
      return false;
    };
    let done = match self.entries.get(&op.get()) {
      Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    };
    self.done.push_back(done);
    true
  }
}
impl Wal for ScriptedWal {
  fn op_head(&self) -> OpNumber {
    OpNumber::with(self.head)
  }
  fn capacity(&self) -> u64 {
    self.capacity
  }
  fn header(&self, op: OpNumber) -> Option<Header> {
    self.entries.get(&op.get()).map(|(h, _)| *h)
  }
  fn status(&self, op: OpNumber) -> SlotStatus {
    if self.entries.contains_key(&op.get()) {
      SlotStatus::Clean
    } else {
      SlotStatus::Empty
    }
  }
  fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes) {
    *self.append_submits.entry(op.get()).or_default() += 1;
    // A scripted append fault completes as `Fault` WITHOUT landing the entry (the
    // contract-violating backend shape the endpoint's defensive retry degrades gracefully).
    if let Some(remaining) = self.append_faults.get_mut(&op.get())
      && *remaining > 0
    {
      *remaining -= 1;
      self.done.push_back(WalDone::Fault(id));
      return;
    }
    self.entries.insert(op.get(), (header, body));
    self.head = self.head.max(op.get());
    self.done.push_back(WalDone::Appended(id));
  }
  fn submit_read(&mut self, id: OpId, op: OpNumber) {
    // A scripted transient fault takes precedence and decrements its remaining count.
    if let Some(remaining) = self.read_faults.get_mut(&op.get())
      && *remaining > 0
    {
      if *remaining != u8::MAX {
        *remaining -= 1;
      }
      self.done.push_back(WalDone::Fault(id));
      return;
    }
    // A DEFERRED read is HELD: record the submitted id (oldest-first) and enqueue NOTHING.
    // `release_deferred(op)` later completes the OLDEST held submission under its original id.
    if self.deferred.contains(&op.get()) {
      self
        .deferred_reads
        .entry(op.get())
        .or_default()
        .push_back(id);
      return;
    }
    let done = match self.entries.get(&op.get()) {
      // A body-faulty slot: the HEADER is durable (still served), only the body is unrecoverable →
      // BodyFaulty carrying that header (the sim WAL's torn/rotted-body verdict). Checked before the
      // clean-read arm so it wins for a held slot.
      Some((h, _)) if self.body_faulty.contains(&op.get()) => {
        WalDone::BodyFaulty(crate::storage::BodyFaulty::new(id, *h))
      }
      Some((h, b)) if self.corrupt.contains(&op.get()) => {
        // A corrupt slot returns the ORIGINAL header with a flipped body so verify fails.
        let mut torn = b.to_vec();
        torn.push(0xFF);
        WalDone::ReadOk(ReadOk::new(id, *h, Bytes::from(torn)))
      }
      Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    };
    self.done.push_back(done);
  }
  fn truncate(&mut self, above: OpNumber) -> std::vec::Vec<OpId> {
    self.entries.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
    std::vec::Vec::new()
  }
  fn prune(&mut self, below: OpNumber) -> std::vec::Vec<OpId> {
    self.entries.retain(|&op, _| op >= below.get());
    std::vec::Vec::new()
  }
  fn poll(&mut self) -> Option<WalDone> {
    self.done.pop_front()
  }
}

// Helper: build a backup endpoint (replica 1 of 3).
fn backup() -> Endpoint<NoopSm> {
  Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).expect("valid cluster config"),
    genesis(3),
    0,
    NoopSm,
    u64::MAX,
  )
}

fn primary_peer() -> Peer {
  Peer::Replica(ReplicaId::new(0))
}

fn prepare(op: u64, commit: u64) -> Message {
  prepare_ck(op, commit, 0)
}

/// A `Prepare` carrying an explicit `checkpoint_op` (the state-sync trigger signal).
fn prepare_ck(op: u64, commit: u64, checkpoint_op: u64) -> Message {
  Message::Prepare(Prepare::new(
    View::new(),
    OpNumber::with(op),
    OpNumber::with(commit),
    OpNumber::with(checkpoint_op),
    crate::Epoch::new(0),
    0,
    ClientId::new(7),
    RequestNumber::with(op),
    Bytes::copy_from_slice(&[op as u8]),
  ))
}

/// Build a DoViewChange whose log is the contiguous prefix `[1..=op]`.
fn dvc(replica: u16, log_view: u64, op: u64, commit: u64) -> DoViewChange {
  let log = (1..=op)
    .map(|i| {
      PreparedEntry::new(
        OpNumber::with(i),
        ClientId::new(1),
        RequestNumber::with(i),
        bytes::Bytes::copy_from_slice(&i.to_be_bytes()),
      )
    })
    .collect();
  DoViewChange::new(
    View::with(log_view + 10),
    View::with(log_view),
    OpNumber::with(op),
    OpNumber::with(commit),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(replica),
    log,
  )
}

/// A real `Prepare` for op `op` from `view`, carrying client 7 / request `op` / body `[op]` (the
/// exact bytes `ScriptedWal::with_entries` stores), so a repair fill verifies against it.
fn repair_prepare(view: u64, op: u64, commit: u64) -> Message {
  Message::Prepare(Prepare::new(
    View::with(view),
    OpNumber::with(op),
    OpNumber::with(commit),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
    ClientId::new(7),
    RequestNumber::with(op),
    Bytes::copy_from_slice(&[op as u8]),
  ))
}

/// The negative answer `replica` sends a new primary's `RequestPrepare(op)` when it durably LACKS the
/// op — the vote the primary counts toward its `f+1` truncation quorum. Carries the fixture lineage
/// (`config_id = 0`), matching the strict-self-id ingress the counted nack binds to.
fn nack(view: u64, op: u64, replica: u16) -> Message {
  Message::Nack(crate::Nack::new(
    View::with(view),
    OpNumber::with(op),
    ReplicaId::new(replica),
    0,
  ))
}

/// Drive replica 1 of `membership` to become the new primary of view 1 holding op 1 (committed, real
/// body) plus a header-only `Repairing` op 2 ABOVE `commit_max` — the repair-or-truncate candidate the
/// nack quorum decides — with its view already DURABLE (so it `participates_as_primary`). Op 2's header
/// is client 7 / request 2 / `fnv1a_128([2])`, and NO canonical donor holds it `Present`, so it is a
/// runtime candidate the primary solicits. Returns the endpoint and its storage, drained of chatter.
fn new_primary_with_op2_candidate(
  membership: Membership,
) -> (
  Endpoint<NoopSm>,
  TestWal,
  TestSb,
  crate::block_store::MemBlockStore,
) {
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    membership,
    0,
    NoopSm,
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(2),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        ),
        PreparedEntry::repairing(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          op2_checksum,
        ),
      ],
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  (e, wal, sb, blocks)
}

/// Recover replica 1 of 3 from a WAL holding dense ops `1..=head` where the single NON-head
/// committed slot `faulty_op` read back permanently faulty (bit-rot). Returns the recovered
/// endpoint (now Normal, holding a peer-repair hole at `faulty_op`) + its wal/sb.
fn recovering_with_hole(head: u64, faulty_op: u64) -> (Endpoint<CountSm>, ScriptedWal, TestSb) {
  assert!(faulty_op < head, "the hole must be below the head");
  let mut wal = ScriptedWal::with_entries(head);
  wal.script_read_fault(OpNumber::with(faulty_op), u8::MAX); // permanent: never clears on disk
  // A store that RAN (its op_head/body faulted), not a wipe: a FORMATTED root so recovery of this voter
  // exercises the read mechanics rather than the empty-voter fail-stop.
  let mut sb = sb_formatted();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery(&mut r, &mut wal, &mut sb, &mut blocks, now);
  (r, wal, sb)
}

/// Drive a `Recovering` replica to a terminal status, pumping BOTH storage completions AND the
/// recover-retry timer — the way a real async driver does. Retransmission + budget-exhaustion
/// resolution of a faulty/slow tail read live on the `recover_retry` timer (`recover_timeouts`), so a
/// fixture whose reads fault/defer must fire that timer to make progress; a `handle_storage`-only loop
/// would never exhaust the budget (the completion arm submits no re-read). Each iteration drains the
/// WAL/SB completions, then advances to the next armed deadline and fires it (re-submitting an additive
/// read whose scripted completion the next drain consumes). Bounded so a genuinely-stuck recovery still
/// returns rather than spins.
fn drive_recovery<S: StateMachine, W: Wal, B: Superblock>(
  r: &mut Endpoint<S>,
  wal: &mut W,
  sb: &mut B,
  blocks: &mut dyn BlockStore,
  now: Instant,
) {
  // Drive on a LOCAL advancing clock `t` so the recover-retry timer actually fires across the budget;
  // the deterministic fixtures complete each (re)read synchronously, so one storage drain + one timer
  // fire per step is enough to count a pending op's budget down to its exhaustion resolution.
  let mut t = now;
  for _ in 0..(RECOVER_READ_RETRIES as usize + 4) {
    r.handle_storage(t, wal, sb, blocks);
    if !r.status().is_recovering() {
      break;
    }
    if let Some(deadline) = r.poll_timeout() {
      t = deadline;
      r.handle_timeout(t, wal, sb, blocks);
    }
  }
  // Re-baseline every timer to the caller's `now`, so the terminal state is observably identical to a
  // synchronous (clock-at-`now`) recovery: the retransmission this helper drove on the timer advanced
  // the endpoint's clock, but the production code exposes no such offset (a real driver advances real
  // time), and the recover-phase timing tests downstream phase their ticks from `now`.
  r.arm_timers(now);
}

/// Drive a replica (replica 1 of 3) into `RecoveringHead` by permanently faulting its head op's
/// read, returning the recovered endpoint + its (still-faulty) wal/sb. The head op is `head`.
fn recovering_head(head: u64) -> (Endpoint<NoopSm>, ScriptedWal, TestSb) {
  let mut wal = ScriptedWal::with_entries(head);
  wal.script_read_fault(OpNumber::with(head), u8::MAX); // head read never clears → permanently faulty
  // A store that RAN (its head read faults), not a wipe: a FORMATTED root so recovery of this voter
  // reaches RecoveringHead rather than the empty-voter fail-stop.
  let mut sb = sb_formatted();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery(&mut r, &mut wal, &mut sb, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "setup: head faulty → RecoveringHead"
  );
  (r, wal, sb)
}

/// A `Request` from client 7 (request `rn`, body `[rn]`) — a FRESH client request, used to prove a
/// non-Normal recovered replica does not serve it (no Prepare/Reply emitted).
fn client_request(rn: u64) -> Message {
  Message::Request(Request::new(
    ClientId::new(7),
    RequestNumber::with(rn),
    Bytes::from(std::vec![rn as u8]),
  ))
}

/// Build a `TestSb` whose durable root names `(view, log_view)` (checkpoint 0, commit 0) — so a
/// recover() reads back a replica that was Normal (log_view == view) or mid-view-change
/// (log_view < view) before the crash.
/// A FORMATTED-but-empty superblock: a genesis-shaped root (view 0, op 0, no checkpoint) carrying the
/// WAL-geometry witness (`checkpoint_ops` = the default recover config, `wal_capacity` exempt 0) but no
/// membership (bridged to the passed genesis at recover). Models a store `format` initialized whose
/// consensus state is still empty — distinct from `TestSb::default()`, whose empty `VsrState::new()`
/// root is a WIPED/virgin store that fails-stops for a voter. Use this when a test recovers a voter
/// over an empty (or op_head-corrupt) WAL and wants the RECOVERY MECHANICS, not the wipe fail-stop.
fn sb_formatted() -> TestSb {
  sb_formatted_with(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX)
}

/// A FORMATTED-but-empty superblock whose genesis-shaped root records an EXPLICIT WAL-geometry pair —
/// for tests whose recover [`Config`] / WAL is not the `(DEFAULT_CHECKPOINT_OPS, u64::MAX)` default that
/// [`sb_formatted`] stamps. `checkpoint_ops` MUST equal the recover config's interval and `wal_capacity`
/// the backend's [`Wal::capacity`], or recovery's geometry fence refuses the mismatch.
fn sb_formatted_with(checkpoint_ops: u64, wal_capacity: u64) -> TestSb {
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::new(),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
  )
  .expect("a genesis-shaped root is valid")
  .with_wal_geometry(checkpoint_ops, wal_capacity);
  TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  }
}

fn sb_with_view(view: u64, log_view: u64) -> TestSb {
  let state = VsrState::try_new(
    View::with(view),
    View::with(log_view),
    OpNumber::new(),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
  )
  .expect("log_view <= view, commit >= checkpoint")
  // Pin the geometry a running node's `durable_root` write stamps, so recovery sees a FORMATTED,
  // geometry-recorded store (a real store that ever wrote a root carries it). `checkpoint_ops` matches
  // the default recover config; `wal_capacity` is the ring-less test WAL's `u64::MAX` (the
  // `Wal::capacity` default these tests run over), so recovery's capacity fence compares equal.
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  }
}

/// A WAL holding dense ops `1..=head`, each header stamped with `view` (so a recovered replica's
/// tail reads verify against the view the root names). Bodies are `[op]`.
fn wal_in_view(head: u64, view: u64) -> TestWal {
  let mut wal = TestWal::default();
  for op in 1..=head {
    let body = Bytes::copy_from_slice(&[op as u8]);
    let h = Header::new(
      OpNumber::with(op),
      View::with(view),
      ClientId::new(7),
      RequestNumber::with(op),
      &body,
    );
    wal.entries.insert(op, (h, body));
  }
  wal.head = head;
  wal
}

/// Drive replica 1 to become the NEW PRIMARY of view 1 (via a DVC quorum) over an ASYNC superblock
/// (`StepSb`), leaving it `Normal` with the durable-view write STILL inflight (`pending_sb` armed) —
/// the exact durable-view-before-participate window. The adopted canonical log
/// is op 1 (committed) + op 2 (uncommitted, commit* = 1), supplied by replica 2's DVC. The WAL
/// completions (the AdoptVote append for op 2) are pumped so they do not muddy the window; the
/// superblock write is left inflight (not flushed), so the view is NOT yet durable.
#[cfg(test)]
fn primed_new_primary_in_pending_view_window() -> (Endpoint<NoopSm>, TestWal, StepSb) {
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Drive into ViewChange(view 1) (replica 1 is primary of view 1): own SVC + replica 0's SVC.
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  // A DVC quorum (own + replica 2) carrying op 1 committed, op 2 uncommitted.
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b"),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  // Now Normal primary of view 1, op 2 — but the durable-view write is inflight (StepSb has not
  // flushed it). Pump the WAL (so the op-2 AdoptVote append completes) WITHOUT flushing the SB, so
  // the window stays open. Discard anything emitted by the transition itself.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(e.view(), View::with(1));
  assert!(
    e.pending_sb_for_test(),
    "the durable-view write must still be pending (the durable-view window is open)"
  );
  assert!(
    sb.has_inflight(),
    "the superblock view write is inflight (not yet durable)"
  );
  (e, wal, sb)
}

/// A superblock whose `state()` names a durable checkpoint at op 2 with a FIXED content id, and whose
/// checkpoint reads return a SCRIPTED sequence of snapshots (front of the queue first). Used to model
/// a torn/stale/corrupt checkpoint read during recover: the first read can return wrong bytes/op, a
/// later one the correct snapshot — so the recover path can be observed to REJECT the bad read (no
/// restore), retry, then restore from the good read. Writes are not exercised here.
///
/// Reads complete LAZILY (like `StepSb`): a read submitted during a `handle_storage` drain does NOT
/// complete in that same drain — its response queues in `inflight` and surfaces on the NEXT `poll`
/// round. This lets a retry submitted mid-drain be observed on the following drain (rather than the
/// whole script collapsing into one synchronous drain), so each reject→retry step is distinct.
struct ScriptedCheckpointSb {
  state: VsrState,
  reads: VecDeque<(OpNumber, Bytes)>,
  ready: VecDeque<SuperblockDone>,
  inflight: VecDeque<SuperblockDone>,
}
impl Superblock for ScriptedCheckpointSb {
  fn state(&self) -> VsrState {
    self.state.clone()
  }
  fn submit_write(&mut self, id: OpId, state: VsrState) {
    self.state = state;
    self.inflight.push_back(SuperblockDone::Wrote(id));
  }
  fn submit_write_checkpoint(&mut self, id: OpId, _op: OpNumber, _snapshot: Bytes) {
    self.inflight.push_back(SuperblockDone::Wrote(id));
  }
  fn submit_read_checkpoint(&mut self, id: OpId) {
    // Pop the next scripted response; if the script is exhausted, fault (forces the budget path).
    let done = match self.reads.pop_front() {
      Some((op, snap)) => SuperblockDone::CheckpointRead(CheckpointRead::new(id, op, snap)),
      None => SuperblockDone::Fault(id),
    };
    self.inflight.push_back(done); // completes on the NEXT poll round, not this drain
  }
  fn poll(&mut self) -> Option<SuperblockDone> {
    self.ready.pop_front()
  }
}
impl ScriptedCheckpointSb {
  fn new(state: VsrState, reads: VecDeque<(OpNumber, Bytes)>) -> Self {
    Self {
      state,
      reads,
      ready: VecDeque::new(),
      inflight: VecDeque::new(),
    }
  }
  /// Make currently-inflight reads available to the next `poll` (mirrors `StepSb::flush`).
  fn flush(&mut self) {
    while let Some(done) = self.inflight.pop_front() {
      self.ready.push_back(done);
    }
  }
}

/// Drive a `ScriptedCheckpointSb` recovery to its terminal state on a LOCAL advancing clock, flushing the
/// scripted superblock and pumping the recover-retry timer each round. The checkpoint-read budget is owned
/// by `recover_timeouts` (the timer is the SOLE retry owner), so a recovery whose checkpoint reads
/// fault/mismatch makes progress only when the timer fires: `flush` surfaces the inflight read,
/// `handle_storage` processes it (a fault/mismatch is discarded), then a timer fire re-submits the next
/// read (decrementing the absolute budget) or, on exhaustion, escalates to a peer fetch. Mirrors
/// [`drive_recovery`] but flushes the scripted SB (whose reads surface only on `flush`). Stops early once
/// recovery leaves the Recovering/RecoveringHead states (a verified read restored the SM → Normal); an
/// escalated replica stays Recovering (awaiting a peer checkpoint), so the loop runs its full budget there.
fn drive_recovery_scripted_sb<S: StateMachine, W: Wal>(
  r: &mut Endpoint<S>,
  wal: &mut W,
  sb: &mut ScriptedCheckpointSb,
  blocks: &mut dyn BlockStore,
  now: Instant,
) {
  let mut t = now;
  for _ in 0..(RECOVER_READ_RETRIES as usize + 8) {
    sb.flush();
    r.handle_storage(t, wal, sb, blocks);
    if !r.status().is_recovering() && !r.status().is_recovering_head() {
      break;
    }
    if let Some(deadline) = r.poll_timeout() {
      t = deadline;
      r.handle_timeout(t, wal, sb, blocks);
    }
  }
}

/// Drive a real 3-replica primary (replica 0) to a DURABLE checkpoint at `ckpt`, returning the
/// endpoint + its storage so a test can read the checkpoint envelope back (the donor for sync apply
/// tests). `checkpoint_ops == ckpt`, so committing `ckpt` ops takes exactly one checkpoint.
fn donor_primary_at_checkpoint(ckpt: u64) -> (Endpoint<CountSm>, TestWal, TestSb) {
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), ckpt).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  for rn in 1..=ckpt {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // primary's own append durable (own vote)
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(1)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(rn),
        ReplicaId::new(1),
        OpNumber::new(),
        crate::storage::prepare_identity(
          ClientId::new(7),
          RequestNumber::with(rn),
          crate::storage::fnv1a_128(&[rn as u8]),
        ),
        crate::Epoch::new(0),
        0,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drain checkpoint writes
  }
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(ckpt),
    "donor checkpoint is durable"
  );
  (e, wal, sb)
}

/// Read the durable checkpoint envelope (+ its id) back from a donor's superblock.
fn donor_envelope(sb: &TestSb) -> (Bytes, u128) {
  let (_op, env) = sb
    .checkpoint
    .clone()
    .expect("donor has a durable checkpoint snapshot");
  let id = sb.state().checkpoint_id();
  assert_eq!(
    crate::checkpoint_id(&env),
    id,
    "donor envelope hashes to its durable id"
  );
  (env, id)
}

/// Capture the nonce of the `RequestSync` a replica just emitted (and drain the rest).
fn captured_sync_nonce(e: &mut Endpoint<CountSm>) -> u64 {
  let mut nonce = None;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSync(r) = out.msg_ref() {
      nonce = Some(r.nonce());
    }
  }
  nonce.expect("a RequestSync was emitted")
}

// A backup over CountSm (replica 1 of 3) — the laggard in sync tests.
fn sync_backup() -> Endpoint<CountSm> {
  Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  )
}

/// Trigger a sync on a laggard backup and deliver `m`, returning the post-delivery endpoint state.
/// `donor_sb` provides the durable checkpoint snapshot the laggard re-persists to.
fn sync_apply_harness(checkpoint_op: u64) -> (Endpoint<CountSm>, TestWal, TestSb, Bytes, u128) {
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(checkpoint_op);
  let (env, id) = donor_envelope(&dsb);
  let e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  (e, wal, sb, env, id)
}

/// Seed `blocks` with BOTH content-addressed DAGs a `donor_primary_at_checkpoint(ckpt)` /
/// `sync_apply_harness(ckpt)` donor produced — the SM checkpoint DAG AND the client-session-table DAG —
/// so a laggard that delivers that donor's `SyncCheckpoint` installs immediately, both block-fetch
/// frontiers draining against the local store with no `RequestBlock` round trip. Re-runs the donor's
/// exact checkpoint sequence into `blocks`, so every block its `force_checkpoint` wrote (the SM leaf
/// plus the session-table DAG, whose root the envelope names) lands under the exact content addresses the
/// envelope references.
fn seed_donor_blocks(blocks: &mut crate::block_store::MemBlockStore, ckpt: u64) {
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), ckpt).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  for rn in 1..=ckpt {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      blocks,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, blocks);
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      blocks,
      Peer::Replica(ReplicaId::new(1)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(rn),
        ReplicaId::new(1),
        OpNumber::new(),
        crate::storage::prepare_identity(
          ClientId::new(7),
          RequestNumber::with(rn),
          crate::storage::fnv1a_128(&[rn as u8]),
        ),
        crate::Epoch::new(0),
        0,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, blocks);
  }
}

/// A DVC whose dense log starts at `floor+1` (a state-synced donor, checkpoint at `floor`), head
/// `op`, commit `commit`. Models the offset log a synced replica carries.
fn dvc_offset(replica: u16, log_view: u64, floor: u64, op: u64, commit: u64) -> DoViewChange {
  let log = ((floor + 1)..=op)
    .map(|i| {
      PreparedEntry::new(
        OpNumber::with(i),
        ClientId::new(1),
        RequestNumber::with(i),
        bytes::Bytes::copy_from_slice(&i.to_be_bytes()),
      )
    })
    .collect();
  DoViewChange::new(
    View::with(log_view + 10),
    View::with(log_view),
    OpNumber::with(op),
    OpNumber::with(commit),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(replica),
    log,
  )
}

/// A DVC whose log is the HEADER-ONLY (`Repairing`) band `(floor .. op]`, advertising `checkpoint`
/// as its vouched floor — the exact wire shape `log_entries()` emits for a deep band (fixed 49
/// bytes per entry), so frame-cap arithmetic on it matches a real carrier.
fn dvc_header_band(
  replica: u16,
  log_view: u64,
  checkpoint: u64,
  floor: u64,
  op: u64,
  commit: u64,
) -> DoViewChange {
  let log = ((floor + 1)..=op)
    .map(|i| {
      PreparedEntry::repairing(
        OpNumber::with(i),
        ClientId::new(1),
        RequestNumber::with(i),
        0,
      )
    })
    .collect();
  DoViewChange::new(
    View::with(log_view + 10),
    View::with(log_view),
    OpNumber::with(op),
    OpNumber::with(commit),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(replica),
    log,
  )
  .with_checkpoint_op(OpNumber::with(checkpoint))
}

/// Build a MALFORMED DVC that CLAIMS head `claimed_op` but carries only `present` real entries
/// (`1..=present`). Models a peer (or fuzzed wire input) advertising an enormous op far above its
/// actual log — the attack shape.
fn dvc_claiming(
  replica: u16,
  log_view: u64,
  claimed_op: u64,
  commit: u64,
  present: u64,
) -> DoViewChange {
  let log = (1..=present)
    .map(|i| {
      PreparedEntry::new(
        OpNumber::with(i),
        ClientId::new(1),
        RequestNumber::with(i),
        Bytes::copy_from_slice(&i.to_be_bytes()),
      )
    })
    .collect();
  DoViewChange::new(
    View::with(log_view + 10),
    View::with(log_view),
    OpNumber::with(claimed_op),
    OpNumber::with(commit),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(replica),
    log,
  )
}

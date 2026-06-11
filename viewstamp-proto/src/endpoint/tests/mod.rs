//! Shared test harness for the endpoint unit tests: the mock `Wal`/`Superblock`/
//! [`StateMachine`] impls and the `backup()`/`prepare()`/... helper constructors the
//! per-subsystem submodules below build on. Split out of the former monolithic
//! `endpoint/tests.rs` — the test bodies themselves are unchanged.

use super::*;
use crate::{
  CheckpointRead, ClientId, Config, DoViewChange, Header, OpId, OpNumber, Prepare, PreparedEntry,
  ReadOk, ReplicaId, Request, RequestNumber, SlotStatus, StartViewChange, Superblock,
  SuperblockDone, View, VsrState, Wal, WalDone,
};
use std::collections::VecDeque;

mod checkpoint;
mod forfeit;
mod invariants;
mod normal;
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

  fn snapshot(&self) -> Bytes {
    Bytes::new()
  }

  fn restore(&mut self, _snapshot: &[u8]) {}
}

/// Echoes the request body as its reply, so a test can observe exactly which bytes were applied
/// (used to prove `recover` restores real bodies — an empty-body regression echoes empty bytes).
struct EchoSm;
impl StateMachine for EchoSm {
  fn apply(&mut self, _op: OpNumber, body: &[u8]) -> Bytes {
    Bytes::copy_from_slice(body)
  }

  fn snapshot(&self) -> Bytes {
    Bytes::new()
  }

  fn restore(&mut self, _snapshot: &[u8]) {}
}

/// Records every applied `(op, body)` and round-trips them through `snapshot`/`restore`
/// (mirrors the sim's `LogSm`). Used to prove `recover` restores the SM from the durable
/// checkpoint snapshot (a fresh SM has 0 applied; a restored one reflects the checkpoint).
#[derive(Default)]
struct CountSm {
  applied: std::vec::Vec<(u64, std::vec::Vec<u8>)>,
}
impl CountSm {
  fn applied(&self) -> &[(u64, std::vec::Vec<u8>)] {
    &self.applied
  }
}
impl StateMachine for CountSm {
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes {
    self.applied.push((op.get(), body.to_vec()));
    Bytes::copy_from_slice(body)
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

  fn restore(&mut self, snapshot: &[u8]) {
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
  fn truncate(&mut self, above: OpNumber) {
    self.entries.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
  }
  fn prune(&mut self, below: OpNumber) {
    self.entries.retain(|&op, _| op >= below.get());
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
      read_faults: BTreeMap::new(),
      corrupt: std::collections::BTreeSet::new(),
      body_faulty: std::collections::BTreeSet::new(),
      append_faults: BTreeMap::new(),
      append_submits: BTreeMap::new(),
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
}
impl Wal for ScriptedWal {
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
  fn truncate(&mut self, above: OpNumber) {
    self.entries.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
  }
  fn prune(&mut self, below: OpNumber) {
    self.entries.retain(|&op, _| op >= below.get());
  }
  fn poll(&mut self) -> Option<WalDone> {
    self.done.pop_front()
  }
}

// Helper: build a backup endpoint (replica 1 of 3).
fn backup() -> Endpoint<NoopSm> {
  Endpoint::new(
    Config::try_new(1, ReplicaId::new(1), 3).expect("valid cluster config"),
    0,
    NoopSm,
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
    ClientId::new(7),
    RequestNumber::with(op),
    Bytes::copy_from_slice(&[op as u8]),
  ))
}

/// Build a DoViewChange whose log is the contiguous prefix `[1..=op]`.
fn dvc(replica: u8, log_view: u64, op: u64, commit: u64) -> DoViewChange {
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
    ClientId::new(7),
    RequestNumber::with(op),
    Bytes::copy_from_slice(&[op as u8]),
  ))
}

/// Recover replica 1 of 3 from a WAL holding dense ops `1..=head` where the single NON-head
/// committed slot `faulty_op` read back permanently faulty (bit-rot). Returns the recovered
/// endpoint (now Normal, holding a peer-repair hole at `faulty_op`) + its wal/sb.
fn recovering_with_hole(head: u64, faulty_op: u64) -> (Endpoint<CountSm>, ScriptedWal, TestSb) {
  assert!(faulty_op < head, "the hole must be below the head");
  let mut wal = ScriptedWal::with_entries(head);
  wal.script_read_fault(OpNumber::with(faulty_op), u8::MAX); // permanent: never clears on disk
  let mut sb = TestSb::default();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    CountSm::default(),
    &mut wal,
    &mut sb,
  );
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  (r, wal, sb)
}

/// Drive a replica (replica 1 of 3) into `RecoveringHead` by permanently faulting its head op's
/// read, returning the recovered endpoint + its (still-faulty) wal/sb. The head op is `head`.
fn recovering_head(head: u64) -> (Endpoint<NoopSm>, ScriptedWal, TestSb) {
  let mut wal = ScriptedWal::with_entries(head);
  wal.script_read_fault(OpNumber::with(head), u8::MAX); // head read never clears → permanently faulty
  let mut sb = TestSb::default();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() != Status::Recovering {
      break;
    }
  }
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
fn sb_with_view(view: u64, log_view: u64) -> TestSb {
  let state = VsrState::try_new(
    View::with(view),
    View::with(log_view),
    OpNumber::new(),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
  )
  .expect("log_view <= view, commit >= checkpoint");
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
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
  let now = Instant::ZERO;
  // Drive into ViewChange(view 1) (replica 1 is primary of view 1): own SVC + replica 0's SVC.
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  // A DVC quorum (own + replica 2) carrying op 1 committed, op 2 uncommitted.
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
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
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  // Now Normal primary of view 1, op 2 — but the durable-view write is inflight (StepSb has not
  // flushed it). Pump the WAL (so the op-2 AdoptVote append completes) WITHOUT flushing the SB, so
  // the window stays open. Discard anything emitted by the transition itself.
  e.handle_storage(now, &mut wal, &mut sb);
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

/// Drive a real 3-replica primary (replica 0) to a DURABLE checkpoint at `ckpt`, returning the
/// endpoint + its storage so a test can read the checkpoint envelope back (the donor for sync apply
/// tests). `checkpoint_ops == ckpt`, so committing `ckpt` ops takes exactly one checkpoint.
fn donor_primary_at_checkpoint(ckpt: u64) -> (Endpoint<CountSm>, TestWal, TestSb) {
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, ckpt).unwrap();
  let mut e = Endpoint::new(cfg, 0, CountSm::default());
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
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb); // primary's own append durable (own vote)
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(rn),
        ReplicaId::new(1),
        OpNumber::new(),
        // content-address the vote to op rn's full identity (client 7, request rn, body [rn])
        crate::storage::prepare_identity(
          ClientId::new(7),
          RequestNumber::with(rn),
          crate::storage::fnv1a_128(&[rn as u8]),
        ),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb); // drain checkpoint writes
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
  Endpoint::new(
    Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap(),
    0,
    CountSm::default(),
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

/// A DVC whose dense log starts at `floor+1` (a state-synced donor, checkpoint at `floor`), head
/// `op`, commit `commit`. Models the offset log a synced replica carries.
fn dvc_offset(replica: u8, log_view: u64, floor: u64, op: u64, commit: u64) -> DoViewChange {
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
    ReplicaId::new(replica),
    log,
  )
}

/// A DVC whose log is the HEADER-ONLY (`Repairing`) band `(floor .. op]`, advertising `checkpoint`
/// as its vouched floor — the exact wire shape `log_entries()` emits for a deep band (fixed 49
/// bytes per entry), so frame-cap arithmetic on it matches a real carrier.
fn dvc_header_band(
  replica: u8,
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
    ReplicaId::new(replica),
    log,
  )
  .with_checkpoint_op(OpNumber::with(checkpoint))
}

/// Build a MALFORMED DVC that CLAIMS head `claimed_op` but carries only `present` real entries
/// (`1..=present`). Models a peer (or fuzzed wire input) advertising an enormous op far above its
/// actual log — the attack shape.
fn dvc_claiming(
  replica: u8,
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
    ReplicaId::new(replica),
    log,
  )
}

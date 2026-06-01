use super::*;
use crate::{
  CheckpointRead, ClientId, Config, DoViewChange, GetView, Header, OpId, OpNumber, Prepare,
  PreparedEntry, ReadOk, Recovery, RecoveryResponse, ReplicaId, Request, RequestNumber, SlotStatus,
  StartView, StartViewChange, Superblock, SuperblockDone, View, VsrState, Wal, WalDone,
};
use std::collections::VecDeque;

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

struct TestSb {
  state: VsrState,
  done: VecDeque<SuperblockDone>,
  /// The last checkpoint snapshot written (op, bytes) — stored so a recover/read test can read it
  /// back, mirroring `InMemorySuperblock`.
  checkpoint: Option<(OpNumber, Bytes)>,
}
impl Default for TestSb {
  fn default() -> Self {
    Self {
      state: VsrState::initial(),
      done: VecDeque::new(),
      checkpoint: None,
    }
  }
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
struct StepSb {
  state: VsrState,
  inflight: VecDeque<SuperblockDone>,
  ready: VecDeque<SuperblockDone>,
  /// The state each inflight write will publish once flushed (paired by position with `inflight`).
  inflight_states: VecDeque<VsrState>,
  checkpoint: Option<(OpNumber, Bytes)>,
}
impl Default for StepSb {
  fn default() -> Self {
    Self {
      state: VsrState::initial(),
      inflight: VecDeque::new(),
      ready: VecDeque::new(),
      inflight_states: VecDeque::new(),
      checkpoint: None,
    }
  }
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
      done: VecDeque::new(),
    }
  }
  /// Script the next `times` reads of `op` to fault (transient). `u8::MAX` ⇒ never clears.
  fn script_read_fault(&mut self, op: OpNumber, times: u8) {
    self.read_faults.insert(op.get(), times);
  }
  /// Script every read of `op` to return a ReadOk whose body fails `Header::verify` (permanent).
  fn script_corrupt_body(&mut self, op: OpNumber) {
    self.corrupt.insert(op.get());
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
    self.entries.insert(op.get(), (header, body));
    self.head = self.head.max(op.get());
    self.done.push_back(WalDone::Appended(id));
  }
  fn submit_read(&mut self, id: OpId, op: OpNumber) {
    // A scripted transient fault takes precedence and decrements its remaining count.
    if let Some(remaining) = self.read_faults.get_mut(&op.get()) {
      if *remaining > 0 {
        if *remaining != u8::MAX {
          *remaining -= 1;
        }
        self.done.push_back(WalDone::Fault(id));
        return;
      }
    }
    let done = match self.entries.get(&op.get()) {
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

#[test]
fn fresh_endpoint_state() {
  let cfg = Config::try_new(1, ReplicaId::new(0), 3).expect("valid cluster config");
  let e = Endpoint::new(cfg, 99, NoopSm);
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(e.view(), View::new());
  assert_eq!(e.op(), OpNumber::new());
  assert_eq!(e.commit(), OpNumber::new());
  assert!(e.is_primary()); // replica 0 is primary of view 0
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

#[test]
fn backup_appends_and_acks_then_commits_via_piggyback() {
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(!e.is_primary());
  let now = Instant::ZERO;

  // Prepare op=1, commit=0: submit append, pump storage so it completes, ack, commit stays 0.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  assert_eq!(e.op(), OpNumber::with(1));
  assert_eq!(e.commit(), OpNumber::with(0));
  e.handle_storage(now, &mut wal, &mut sb); // pump WAL → on_wal_done → PrepareOk
  match e.poll_message().expect("prepare_ok emitted").into_msg() {
    Message::PrepareOk(ok) => {
      assert_eq!(ok.op(), OpNumber::with(1));
      assert_eq!(ok.replica(), ReplicaId::new(1));
    }
    _ => panic!("expected PrepareOk"),
  }

  // Prepare op=2, commit=1: piggybacked commit applies op 1 (synchronously), then append op 2.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  assert_eq!(e.op(), OpNumber::with(2));
  assert_eq!(e.commit(), OpNumber::with(1));
}

#[test]
fn backup_buffers_out_of_order_prepares() {
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  // op=2 arrives before op=1: buffered, head op stays 0.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 0));
  assert_eq!(e.op(), OpNumber::with(0));

  // op=1 arrives: append 1, then drain buffered op 2.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  assert_eq!(e.op(), OpNumber::with(2));
}

#[test]
fn backup_caches_the_reply_so_a_backup_turned_primary_can_resend_it() {
  // REGRESSION (the lost-reply-across-failover hang the M3 sweep exposed): the primary caches each
  // committed reply (`commit_op`), but a BACKUP used to discard it. So if a client's reply was LOST
  // in flight and the primary then failed over, the new primary (a former backup) saw the client's
  // resend as a duplicate (`request == session.request`) yet had NO cached reply to resend — staying
  // SILENT and hanging the client forever, even with a healthy quorum. The fix caches the reply on
  // the backup's apply path too (it is the SM's deterministic output). Here: a backup applies op 1
  // (client 7, request 1) and must hold its cached reply.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Prepare op 1 (client 7, request 1), make it durable, then Commit to apply it.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(1), OpNumber::new())),
  );
  assert_eq!(e.commit(), OpNumber::with(1), "the backup applied op 1");
  // The backup cached the reply for client 7's request 1 — so once it becomes primary it can resend
  // it on a duplicate request (NoopSm's reply body is empty, but the cache ENTRY must be present and
  // keyed to request 1, which is what the duplicate-resend path checks).
  let cached = e.session_reply_for_test(7);
  assert!(
    cached.is_some(),
    "a backup must cache the committed reply (so a backup-turned-primary can resend a lost reply)"
  );
  assert_eq!(
    cached.unwrap().0,
    1,
    "the cached reply is keyed to the applied request number"
  );
}

#[test]
fn backup_below_primary_commit_solicits_the_committed_tail_gap() {
  // REGRESSION (the backup tail-gap liveness bug): a backup whose head fell BELOW the primary's
  // commit_min is missing committed ops that are ABOVE the cluster checkpoint (so the `> self.op`
  // state-sync trigger is FALSE) yet ABOVE its head (so advance_commit can't reach them). The
  // primary's prepare-retransmit only covers `commit_min+1..=op`, so it never re-sends them. Without
  // a backup-side solicitation the backup stalls at its head forever (and can wedge the whole cluster
  // if it is in the only surviving quorum). The fix: on hearing a Commit whose commit is above our
  // head, solicit the band `(head .. commit]` via RequestPrepare so it arrives as ordinary Prepares.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  // Bring the backup to head op 2 (append 1, 2 via in-order Prepares; commit stays 0).
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.op(), OpNumber::with(2));
  while e.poll_message().is_some() {} // drain the acks

  // A Commit learns the primary committed up to op 5 (checkpoint still 2, so 3,4,5 are above the
  // checkpoint — NOT snapshot-only). The backup holds only up to op 2 → it must solicit 3,4,5.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(5),
      OpNumber::with(2),
    )),
  );
  // It does NOT advance commit past its head (it lacks 3,4,5) and does NOT state-sync (head >= ckpt).
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "commit is held at the head until the gap fills"
  );
  // It solicits exactly the committed tail-gap (3,4,5) via RequestPrepare — NOT a state-sync.
  let mut requested = std::collections::BTreeSet::new();
  let mut saw_request_sync = false;
  while let Some(out) = e.poll_message() {
    match out.into_msg() {
      Message::RequestPrepare(rp) => {
        requested.insert(rp.op().get());
      }
      Message::RequestSync(_) => saw_request_sync = true,
      _ => {}
    }
  }
  assert_eq!(
    requested,
    [3, 4, 5].into_iter().collect(),
    "the backup solicits exactly the committed tail-gap (3,4,5) above its head"
  );
  assert!(
    !saw_request_sync,
    "the gap is above the cluster checkpoint → ordinary tail-gap repair, not a state-sync"
  );
}

#[test]
fn tail_gap_repair_is_bounded_per_call() {
  // REGRESSION (the unbounded tail-gap DoS): a backup that learns a `commit_max` FAR above its head
  // (a large legitimate gap, or a malformed/bogus Commit) must NOT push the whole `(head .. commit_max]`
  // band into `outgoing` in a single `request_tail_gap` call — that is unbounded CPU/memory in the
  // Sans-I/O core. It must emit at most `TAIL_GAP_WINDOW` RequestPrepares per call (the rest follow on
  // later heartbeats as the head advances). Before the fix this enqueued ~1,000,000 RequestPrepares.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // The backup is at head 0, checkpoint 0. A single Commit advertises a colossal commit_max — above
  // the checkpoint (so this is tail-gap territory, not state-sync) and far above the head.
  let bogus = 1_000_000u64;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(bogus),
      OpNumber::with(0),
    )),
  );
  // It records the learned commit_max but solicits only a bounded window above its head.
  assert_eq!(
    e.commit_max(),
    OpNumber::with(bogus),
    "the learned commit_max is recorded (it just is not all solicited at once)"
  );
  let mut requested: std::vec::Vec<u64> = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::RequestPrepare(rp) = out.msg_ref() {
      requested.push(rp.op().get());
    }
  }
  assert_eq!(
    requested.len() as u64,
    TAIL_GAP_WINDOW,
    "at most TAIL_GAP_WINDOW RequestPrepares are emitted per call, not the whole range"
  );
  // The window starts at the first op above the head (1) and is contiguous up to the cap — so the gap
  // is closed incrementally from the bottom across heartbeats, never all at once.
  assert_eq!(
    requested,
    (1..=TAIL_GAP_WINDOW).collect::<std::vec::Vec<u64>>(),
    "the bounded window is the contiguous band (head+1 ..= head+TAIL_GAP_WINDOW)"
  );
}

#[test]
fn tail_gap_repair_within_the_window_requests_the_whole_gap() {
  // The cap must not under-serve a SMALL gap: a backup whose gap fits inside one window still solicits
  // exactly the gap (no truncation, no over-request past commit_max).
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Head 0, checkpoint 0, commit_max 3 (< TAIL_GAP_WINDOW) → solicit exactly {1,2,3}.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::with(0),
    )),
  );
  let mut requested: std::vec::Vec<u64> = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::RequestPrepare(rp) = out.msg_ref() {
      requested.push(rp.op().get());
    }
  }
  assert_eq!(
    requested,
    std::vec![1, 2, 3],
    "a gap smaller than the window is requested in full (no truncation, no over-request)"
  );
}

#[test]
fn fresh_endpoint_log_view_is_zero() {
  let e = Endpoint::new(
    Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
    99,
    NoopSm,
  );
  assert_eq!(e.log_view(), View::new());
  assert_eq!(e.status(), Status::Normal);
}

#[test]
fn backup_transitions_on_svc_quorum_and_sends_dvc() {
  // replica 1 of 3. After primary_idle and one peer SVC, the SVC quorum (2) is met:
  // it transitions to ViewChange(view 1) and sends a DoViewChange to primary(1)=replica 1.
  use crate::StartViewChange;
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_timeout(now, &mut wal, &mut sb); // status=Normal backup → bootstraps primary_idle; not yet due
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb); // primary_idle due → on_primary_idle → broadcast SVC(view 1), own bit set
  assert_eq!(e.status(), Status::Normal); // 1 of 2 — not yet quorum
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
  );
  assert_eq!(e.status(), Status::ViewChange);
  assert_eq!(e.view(), View::with(1));
  // DoViewChange is deferred until the view is durable — pump storage first.
  e.handle_storage(later, &mut wal, &mut sb);
  // it should have emitted a DoViewChange to primary(view 1) = replica 1 (itself).
  let mut saw_dvc = false;
  while let Some(out) = e.poll_message() {
    if let Message::DoViewChange(d) = out.into_msg() {
      assert_eq!(d.view(), View::with(1));
      assert_eq!(d.replica(), ReplicaId::new(1));
      saw_dvc = true;
    }
  }
  assert!(saw_dvc, "must send a DoViewChange to the new primary");
}

#[test]
fn new_primary_adopts_canonical_log_and_starts_view() {
  // replica 1 is primary of view 1. Feed a DVC quorum (2 of 3) of DoViewChange for view 1.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // drive it into ViewChange(view 1) first (reuse the SVC path):
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
  ); // primary_idle → SVC(view1), own bit
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  assert_eq!(e.status(), Status::ViewChange); // now collecting DVCs as primary(view 1)
  while e.poll_message().is_some() {} // discard outgoing so far
  // Feed a DoViewChange from replica 2 with a richer log (log_view 0, op 2, commit 1):
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
  // replica 1's own DVC (op 0) + replica 2's DVC (op 2) = quorum 2 → adopt op 2, become Normal primary.
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(e.view(), View::with(1));
  assert_eq!(e.op(), OpNumber::with(2));
  // StartView is deferred until the view is durable — pump storage first.
  e.handle_storage(now, &mut wal, &mut sb);
  // It must broadcast a StartView carrying the canonical log.
  let mut saw_sv = false;
  while let Some(out) = e.poll_message() {
    if let Message::StartView(sv) = out.into_msg() {
      assert_eq!(sv.op(), OpNumber::with(2));
      assert_eq!(sv.log_slice().len(), 2);
      saw_sv = true;
    }
  }
  assert!(saw_sv, "new primary must broadcast StartView");
}

#[test]
fn new_primary_does_not_vote_for_an_adopted_op_before_its_wal_append() {
  // codex R6-F1 (REGRESSION, the cardinal append-before-ack invariant): a new primary that adopts an
  // uncommitted-tail op it learned from a PEER's DVC (it did NOT hold the op before) must NOT count
  // its OWN vote for that op — and must NOT commit it — until the op's WAL append is durable. The
  // own vote could only be cast from memory before, so a crash+recover would lose the op it voted
  // for. Here replica 1 becomes primary of view 1 and adopts op 2 (uncommitted: commit* = 1) supplied
  // ONLY by replica 2's DVC; replica 1's own DVC holds op 0, so op 2 is peer-learned + memory-only.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
  ); // primary_idle → SVC(view1), own bit
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
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
  // Now the new primary (replica 1) is Normal with op 2 adopted, commit* = 1 — BEFORE any storage.
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(2));
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "op 1 applied; op 2 still uncommitted"
  );
  let own_bit = 1u64 << 1; // replica 1
  // THE INVARIANT: op 2's inflight entry carries NO own vote yet — the WAL append has not completed.
  // Fail-before (the bug): the own vote was seeded immediately (`oks: own`), so this was `own_bit`.
  assert_eq!(
    e.inflight.get(&2).map(|i| i.oks),
    Some(0),
    "the new primary must NOT vote for the adopted op 2 before its WAL append is durable (R6-F1)"
  );

  // Pump storage: the AdoptVote append for op 2 completes → on_wal_done sets the own vote; the
  // durable-view write completes → start_view_participate broadcasts StartView + try_commit. With a
  // 3-cluster quorum of 2, the lone own vote still cannot commit op 2.
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.inflight.get(&2).map(|i| i.oks),
    Some(own_bit),
    "after the WAL append completes the own vote is recorded (append-before-ack honoured)"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the own vote alone is below quorum (2) — op 2 is not yet committed"
  );
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "op 2 was durably appended to the WAL before its own vote was counted (R6-F1)"
  );

  // A backup PrepareOk for op 2 now reaches quorum (own + backup) → op 2 commits.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(PrepareOk::new(
      View::with(1),
      OpNumber::with(2),
      ReplicaId::new(2),
      OpNumber::new(),
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "op 2 commits once the durable own vote + a backup ack reach quorum"
  );
}

#[test]
fn new_primary_adopted_vote_survives_crash_before_checkpoint() {
  // codex R6-F1 (REGRESSION): after the new primary records its OWN vote for an adopted peer-learned
  // op, that op MUST be in its durable WAL — so a crash+recover BEFORE any checkpoint still produces
  // it. We drive the adoption, pump until the AdoptVote append lands (own vote recorded), then CRASH
  // (drop all in-memory state) and RECOVER from the durable WAL+Superblock; op 2 must be present.
  // Fail-before: the vote was memory-only, so the op was absent from the WAL and lost on recover.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
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
  // Pump until the AdoptVote append is durable (the own vote is recorded only then).
  let own_bit = 1u64 << 1;
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb);
    if e.inflight.get(&2).map(|i| i.oks) == Some(own_bit) {
      break;
    }
  }
  assert_eq!(
    e.inflight.get(&2).map(|i| i.oks),
    Some(own_bit),
    "precondition: the new primary recorded its own vote for op 2"
  );

  // CRASH: discard `e` (all in-memory state) and RECOVER from the durable WAL + Superblock — exactly
  // what the simulation's crash/restart does. The op the primary voted for must survive.
  drop(e);
  let mut recovered = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    recovered.handle_storage(now, &mut wal, &mut sb);
    if !recovered.status().is_recovering() {
      break;
    }
  }
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "op 2 the new primary voted for is in the durable WAL after crash+recover (R6-F1)"
  );
  assert!(
    recovered.op().get() >= 2,
    "the recovered replica re-establishes its head through the voted-for op (it was durable)"
  );
}

#[test]
fn backup_adopted_ack_survives_crash_before_checkpoint() {
  // codex R6-F1 (REGRESSION, backup side): after a backup sends its PrepareOk for an adopted
  // StartView tail op, that op MUST be in its durable WAL — a crash+recover before any checkpoint
  // still produces it. Drive the adoption, pump until the PrepareOk is emitted (its AdoptAck append
  // landed), then CRASH + RECOVER; op 2 must be present. Fail-before: the ack was memory-only.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(2),
    OpNumber::with(1),
    ReplicaId::new(1),
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
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  // Pump until the PrepareOk for op 2 is emitted (which is gated on its AdoptAck append landing).
  let mut acked = false;
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb);
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg() {
        if ok.op() == OpNumber::with(2) {
          acked = true;
        }
      }
    }
    if acked {
      break;
    }
  }
  assert!(acked, "precondition: the backup acked the adopted op 2");

  // CRASH + RECOVER from durable storage.
  drop(e);
  let mut recovered = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(2), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    recovered.handle_storage(now, &mut wal, &mut sb);
    if !recovered.status().is_recovering() {
      break;
    }
  }
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "op 2 the backup acked is in the durable WAL after crash+recover (R6-F1 append-before-ack)"
  );
  assert!(
    recovered.op().get() >= 2,
    "the recovered backup re-establishes its head through the acked op (it was durable)"
  );
}

#[test]
fn new_primary_truncates_an_uncommitted_interior_canonical_log_gap() {
  // codex R7-F2 (CONSENSUS-CRITICAL): a replica that recovered with a faulty INTERIOR slot (here
  // checkpoint 0, head 3, op 2 read back permanently faulty + still uncommitted) drops op 2 from its
  // cache, so its log is `{1, 3}` with an interior GAP at op 2. It then becomes the new primary via a
  // DVC quorum where no donor supplies op 2 (op 2 is uncommitted and unique — no quorum holds it). The
  // adopted canonical log is `{1, 3}`, op_head 3, commit* 0; op 2 is ABOVE the committed frontier
  // (commit* == 0) yet held by NO canonical donor, so it is provably UNCOMMITTED (a committed op would
  // be held by a quorum and thus by some canonical donor → present in the offset-union).
  //
  // Fail-before: the seeding loop registered an `inflight` entry for EVERY op in `(commit_min, op_head]`
  // and `adopt_append`ed each — but `adopt_append` only appends ops PRESENT in `self.log`, so the gap op
  // 2 was silently skipped, its own vote was never recorded (`inflight[2].oks == 0` forever), and
  // `try_commit` (strictly in order) wedged at op 2 — no fresh client op above it could ever commit, and
  // no peer can supply the unique uncommitted op. The fix truncates the head at the first gap above
  // commit* BEFORE seeding, dropping the uncommitted suffix `{2, 3}`.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  assert_eq!(r.op(), OpNumber::with(3), "recovered head is op 3");
  assert!(
    !r.log.contains_key(&2),
    "precondition: the faulty op 2 is absent from the cache (interior gap)"
  );
  assert!(
    !r.has_repair_hole_for_test(2),
    "precondition: op 2 is uncommitted, so it is NOT a repair hole (R6-F2)"
  );
  while r.poll_message().is_some() {} // discard the recovery-time chatter
  let now = Instant::ZERO;

  // Drive replica 1 to primary of view 1: an SVC quorum (own + replica 0) enters ViewChange(1); pump
  // the durable-view write so it sends its own DVC; then a peer DVC reaches the DVC quorum.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  assert_eq!(r.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  r.handle_storage(now, &mut wal, &mut sb); // complete the SendDoViewChange durable-view write
  while r.poll_message().is_some() {}
  // Replica 2's DVC ALSO lacks op 2 (uncommitted+unique: no quorum holds it), same generation
  // (log_view 0), head 3, commit 0 → the offset-union still has the interior gap at op 2.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(3),
      OpNumber::with(0),
      ReplicaId::new(2),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::copy_from_slice(&[1u8]),
        ),
        PreparedEntry::new(
          OpNumber::with(3),
          ClientId::new(7),
          RequestNumber::with(3),
          bytes::Bytes::copy_from_slice(&[3u8]),
        ),
      ],
    )),
  );
  assert!(r.is_primary(), "replica 1 became the primary of view 1");

  // The head is truncated to op 1 (just below the uncommitted gap at op 2); the uncommitted suffix
  // `{2, 3}` is dropped from the cache.
  assert_eq!(
    r.op(),
    OpNumber::with(1),
    "the head is truncated below the first uncommitted interior gap (op 2)"
  );
  assert!(
    !r.log.contains_key(&2) && !r.log.contains_key(&3),
    "the uncommitted suffix above the gap is dropped from the cache"
  );
  assert!(
    !r.has_repair_hole_for_test(2) && !r.has_repair_hole_for_test(3),
    "an uncommitted gap above commit* is truncated, NOT left as a (futile) repair hole"
  );
  assert!(
    !r.inflight.contains_key(&2),
    "no stuck inflight entry for the gap op (fail-before: inflight[2].oks == 0 forever)"
  );

  // Pump the StartViewAsPrimary durable-view write so the new primary begins participating.
  r.handle_storage(now, &mut wal, &mut sb);
  while r.poll_message().is_some() {}
  // Land the AdoptVote append for the surviving tail op 1 (its own vote is recorded then).
  for _ in 0..4 {
    r.handle_storage(now, &mut wal, &mut sb);
  }

  // Liveness: a fresh client request is accepted (commit_max == commit_min == 0, repair empty) and —
  // crucially — COMMITS. It is assigned op 2 (the truncated head + 1), and with a backup ack it reaches
  // the commit quorum, proving `try_commit` is NOT wedged at the former gap.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"fresh"),
    )),
  );
  assert_eq!(
    r.op(),
    OpNumber::with(2),
    "the fresh client op fills the truncated head's next slot (op 2), not op 4"
  );
  for _ in 0..4 {
    r.handle_storage(now, &mut wal, &mut sb); // land the fresh op's own-vote append
  }
  // Both backups ack the surviving tail op 1 AND the fresh op 2 → each reaches the quorum of 2.
  for ack_op in [1u64, 2] {
    for backup in [0u8, 2] {
      r.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Replica(ReplicaId::new(backup)),
        Message::PrepareOk(PrepareOk::new(
          View::with(1),
          OpNumber::with(ack_op),
          ReplicaId::new(backup),
          OpNumber::new(),
        )),
      );
    }
  }
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "commit progresses through the fresh op — try_commit is not wedged at the former interior gap"
  );
}

#[test]
fn new_primary_does_not_truncate_a_committed_interior_gap_it_repairs_it() {
  // codex R7-F2 (the COMPLEMENT — a COMMITTED gap must NOT be truncated). Same faulty-interior-slot
  // replica (checkpoint 0, head 3, op 2 absent), but this time the DVC quorum reports commit* == 3, so
  // op 2 is BELOW the committed frontier — a real B4 repair hole the offset-union could not carry, NOT
  // an uncommitted gap. The seeding-site truncation only scans `(commit* .. op]`, so op 2 (≤ commit*)
  // is OUTSIDE it: the head is NOT truncated, op 2 stays a `repair` hole, the commit is HELD at op 1,
  // and a peer-supplied (committed-vouching) Prepare fills it and resumes the held commit. This guards
  // the truncation from over-reaching into a committed op (which would silently drop it).
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  while r.poll_message().is_some() {}
  let now = Instant::ZERO;
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  r.handle_storage(now, &mut wal, &mut sb); // complete the SendDoViewChange durable-view write
  while r.poll_message().is_some() {}
  // Replica 2's DVC: same generation (log_view 0), head 3, but commit 3 (it committed past op 2). Its
  // own offset log still lacks op 2, so the union has the gap at op 2 — but commit* now == 3.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(3),
      OpNumber::with(3),
      ReplicaId::new(2),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::copy_from_slice(&[1u8]),
        ),
        PreparedEntry::new(
          OpNumber::with(3),
          ClientId::new(7),
          RequestNumber::with(3),
          bytes::Bytes::copy_from_slice(&[3u8]),
        ),
      ],
    )),
  );
  assert!(r.is_primary(), "replica 1 became the primary of view 1");

  // The head is NOT truncated (op 2 is committed, ≤ commit* == 3) — it stays at op 3 — and op 2 is a
  // repair hole with the commit HELD at op 1 (the apply loop never skips the committed hole).
  assert_eq!(
    r.op(),
    OpNumber::with(3),
    "a committed interior gap does NOT truncate the head (op 2 ≤ commit*)"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "the committed gap is a repair hole (on-demand B4 repair), not silently dropped"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "the commit is HELD below the committed hole until a peer supplies op 2"
  );

  // Pump the StartViewAsPrimary durable-view write, then a peer answers our RequestPrepare with op 2's
  // committed-vouching Prepare (commit 3 >= op 2) → fill the hole and resume the held commit to op 3.
  r.handle_storage(now, &mut wal, &mut sb);
  while r.poll_message().is_some() {}
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 3),
  );
  assert!(
    !r.has_repair_hole_for_test(2),
    "the committed-vouching Prepare fills the hole"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "the held commit resumes once the committed gap is repaired (op 2 then 3 apply in order)"
  );
}

#[test]
fn recover_carries_the_durable_commit_so_a_known_committed_op_is_not_truncated() {
  // CONSENSUS-CRITICAL regression (codex R9-F1). `recover` set BOTH commit_min AND commit_max to
  // checkpoint_op, DISCARDING the durable known-committed frontier `state.commit()` (which can exceed
  // checkpoint_op). A replica whose durable root says op N is committed — but whose WAL slot N read back
  // stale/faulty (now DROPPED → repair hole by the R9-F2 / seed-52 vsr_headers cross-check) — recovered
  // having FORGOTTEN that N is committed. Its DoViewChange then UNDER-reported its commit (commit_min ==
  // checkpoint_op), so if the DVC quorum is this recovered replica + a LAGGARD (the other old
  // commit-quorum holder crashed/partitioned), `commit*` never reached N, the offset-union treated the
  // missing op N as an UNCOMMITTED interior gap, and `start_view_as_new_primary` TRUNCATED — LOSING the
  // known-committed op N.
  //
  // Fix: `recover` sets commit_max = state.commit() (the durable known frontier, keeping commit_min ==
  // checkpoint_op), and the DVC reports commit_max (VSR's commit-number `k` = highest KNOWN committed),
  // so `commit*` reaches N → N is a COMMITTED repair hole (held + peer-repaired), never truncated.
  //
  // Setup: replica 1 of 3. Durable root: view 0, commit 2 (op 2 is KNOWN committed), checkpoint_op 0,
  // with canonical vsr_headers for ops 1 + 2. WAL head 3, but slot 2 reads back PERMANENTLY FAULTY → the
  // recover loop drops it (an interior committed hole). Op 3 is the uncommitted tail.
  let mk_header = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2), // durable commit — op 2 is KNOWN committed cluster-wide
    OpNumber::new(),   // checkpoint_op 0
    0,
    std::vec![mk_header(1), mk_header(2)],
  )
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(3);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // op 2's slot is permanently faulty → dropped
  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovers to Normal (op 2 below the head 3 → peer-repair)"
  );
  assert!(
    !r.log.contains_key(&2),
    "the faulty committed slot is dropped from the cache (interior hole)"
  );
  // The durable known-committed frontier is CARRIED: commit_max == 2 (NOT checkpoint_op 0). commit_min
  // stays at checkpoint_op 0 (the SM is restored to the checkpoint; the band re-applies via the WAL).
  // (FAIL-BEFORE: recover set commit_max = checkpoint_op = 0, forgetting op 2 was committed.)
  assert_eq!(
    r.commit_max(),
    OpNumber::with(2),
    "recover carries the durable commit frontier (op 2 is KNOWN committed), not checkpoint_op"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(0),
    "commit_min stays at checkpoint_op — the committed band re-applies as it is repaired/re-announced"
  );
  while r.poll_message().is_some() {} // discard recovery chatter
  while r.poll_event().is_some() {}

  // Drive replica 1 to primary of view 1 with a DVC quorum of {replica 1 (recovered), replica 0 (a
  // LAGGARD)}. The other old commit-quorum holder (replica 2) is ABSENT (crashed/partitioned). The
  // laggard holds only op 1 (head 1, commit 0) — it does NOT supply op 2 and does NOT know op 2 is
  // committed. So the ONLY donor that knows op 2 is committed is the recovered replica itself, via its
  // carried commit_max.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  assert_eq!(r.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  r.handle_storage(now, &mut wal, &mut sb); // complete the SendDoViewChange durable-view write
  // The recovered replica's OWN DVC must report its KNOWN committed frontier (commit_max == 2), not
  // commit_min == 0 — otherwise the laggard quorum loses op 2. Verify it on the wire.
  let own_dvc_commit = std::iter::from_fn(|| r.poll_message())
    .filter_map(|out| match out.into_msg() {
      Message::DoViewChange(d) => Some(d.commit()),
      _ => None,
    })
    .next()
    .expect("the recovered replica sends its DVC");
  assert_eq!(
    own_dvc_commit,
    OpNumber::with(2),
    "the DVC reports the KNOWN committed frontier (commit_max == 2), so commit* covers op 2 \
     (FAIL-BEFORE: it reported commit_min == 0 and op 2 was treated as an uncommitted gap)"
  );

  // The laggard replica 0's DVC: same generation (log_view 0), head 1, commit 0, log {1} only — it
  // neither supplies op 2 nor vouches it committed. With the recovered replica's own DVC (commit 2),
  // commit* == 2, so op 2 is a COMMITTED hole — repaired, NOT truncated.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(1),
      OpNumber::with(0),
      ReplicaId::new(0),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::copy_from_slice(&[1u8]),
      )],
    )),
  );
  assert!(r.is_primary(), "replica 1 became the primary of view 1");
  // op 2 is NOT truncated: the head stays at op 3 (op 2 ≤ commit* == 2 is a committed hole). The
  // commit is HELD at op 1 until op 2 is repaired. (FAIL-BEFORE: commit* == 0, op 2 was an uncommitted
  // interior gap, the head truncated to op 1, and the known-committed op 2 was LOST.)
  assert_eq!(
    r.op(),
    OpNumber::with(3),
    "the known-committed op 2 is NOT truncated — the head stays at op 3"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "op 2 is a COMMITTED repair hole (held + peer-repaired), not silently dropped"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "the commit is HELD below the known-committed hole until a peer supplies op 2"
  );

  // Pump the StartViewAsPrimary durable-view write, then a committed-vouching peer answers our
  // RequestPrepare for op 2 (commit 2 >= op 2) → fill the hole and resume the held commit to op 2.
  r.handle_storage(now, &mut wal, &mut sb);
  while r.poll_message().is_some() {}
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );
  assert!(
    !r.has_repair_hole_for_test(2),
    "the committed-vouching Prepare fills the known-committed hole"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the held commit resumes — the known-committed op 2 is RETAINED, never lost"
  );
  assert_eq!(
    r.state_machine().applied(),
    &[(1, std::vec![1u8]), (2, std::vec![2u8])],
    "the committed log retains op 2 end to end (FAIL-BEFORE: op 2 was truncated and lost)"
  );
}

#[test]
fn new_primary_reconstructs_sessions_so_retries_dedup() {
  // replica 1 becomes primary of view 1, adopting client 7's requests 1 (committed) and 2.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
  ); // primary_idle → SVC
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
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
    )),
  );
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(2));
  while e.poll_message().is_some() {}
  // The new primary deferred participation until its view is durable; pump storage so the
  // durable-view write completes and it may serve requests (durable-view-before-participate).
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}

  // A retry of request 1 (already adopted+committed) must NOT create a new op (dedup, no re-exec).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"a"),
    )),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "retry of an adopted request must be deduplicated, not re-executed"
  );

  // A genuinely new request (3) IS accepted → op advances to 3.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(3),
      bytes::Bytes::from_static(b"c"),
    )),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(3),
    "a new request after the adopted ones is accepted"
  );
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

#[test]
fn canonical_selection_prefers_highest_log_view_over_longer_log() {
  // r0 has the newest generation (log_view 2) but a SHORTER log; r1/r2 are longer but stale.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
  e.dvc_from.insert(0, dvc(0, 2, 3, 1));
  e.dvc_from.insert(1, dvc(1, 1, 5, 1));
  e.dvc_from.insert(2, dvc(2, 1, 5, 1));
  let (log, op_head, commit_star) = e.select_canonical_log();
  assert_eq!(op_head, 3, "newest log_view wins, not the longer stale log");
  assert_eq!(log.len(), 3);
  assert_eq!(commit_star, 1);
}

#[test]
fn nack_prepare_truncates_provably_uncommitted_tail() {
  // N=5 → quorum_nack_prepare = 3. Head op 5 held only by r0; r1,r2,r3 stop at op 2.
  // ops 3..=5 each get 3 nacks (r1,r2,r3) ≥ 3 → truncated to op 2.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
  e.dvc_from.insert(0, dvc(0, 1, 5, 2));
  e.dvc_from.insert(1, dvc(1, 1, 2, 2));
  e.dvc_from.insert(2, dvc(2, 1, 2, 2));
  e.dvc_from.insert(3, dvc(3, 1, 2, 2));
  let (log, op_head, _) = e.select_canonical_log();
  assert_eq!(op_head, 2, "ops 3..=5 had a nack quorum → truncated");
  assert_eq!(log.len(), 2);
}

#[test]
fn committed_ops_are_never_truncated() {
  // commit* = 4: op 5 is the only uncommitted op, nacked by 3 → truncated; 1..=4 survive.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
  e.dvc_from.insert(0, dvc(0, 1, 5, 4));
  e.dvc_from.insert(1, dvc(1, 1, 4, 4));
  e.dvc_from.insert(2, dvc(2, 1, 4, 4));
  e.dvc_from.insert(3, dvc(3, 1, 4, 4));
  let (log, op_head, commit_star) = e.select_canonical_log();
  assert_eq!(commit_star, 4);
  assert_eq!(
    op_head, 4,
    "uncommitted op 5 truncated, committed 1..=4 kept"
  );
  assert_eq!(log.len(), 4);
}

#[test]
fn no_truncation_at_minimal_quorum() {
  // Documents the contiguous-model property: with exactly quorum_view_change=3 DVCs,
  // the head-holder (r0) prevents a nack quorum (≤ 2 nacks < 3) → adopt whole.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
  e.dvc_from.insert(0, dvc(0, 1, 5, 2));
  e.dvc_from.insert(1, dvc(1, 1, 2, 2));
  e.dvc_from.insert(2, dvc(2, 1, 2, 2));
  let (_, op_head, _) = e.select_canonical_log();
  assert_eq!(
    op_head, 5,
    "no nack quorum possible at minimal quorum → no truncation"
  );
}

#[test]
fn stalled_view_change_escalates_to_the_next_view() {
  // replica 3 of 5 (a backup at views 0,1,2). Drive it into ViewChange(1); the new primary(1)
  // never sends a StartView, so view_change_status escalates it toward view 2.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(3), 5).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let t = Instant::ZERO + core::time::Duration::from_millis(300);
  e.handle_timeout(t, &mut wal, &mut sb); // primary_idle → propose view 1 (own bit, 1/3)
  e.handle_message(
    t,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  ); // 2/3
  e.handle_message(
    t,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(1))),
  ); // 3/3 → ViewChange(1)
  assert_eq!(e.view(), View::with(1));
  assert_eq!(e.status(), Status::ViewChange);

  // Stuck: fire view_change_status (~500ms after transition) → escalate, proposing view 2.
  let t2 = t + core::time::Duration::from_millis(600);
  e.handle_timeout(t2, &mut wal, &mut sb);
  // Two peers also propose view 2 → quorum → transition to view 2.
  e.handle_message(
    t2,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(2), ReplicaId::new(0))),
  );
  e.handle_message(
    t2,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(StartViewChange::new(View::with(2), ReplicaId::new(1))),
  );
  assert_eq!(e.view(), View::with(2), "escalated to the next view");
  assert_eq!(e.status(), Status::ViewChange);
}

#[test]
fn backup_adopts_start_view() {
  // replica 2 of 3 receives a StartView for view 1 from primary(1)=replica 1.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(2),
    OpNumber::with(1),
    ReplicaId::new(1),
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
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(e.view(), View::with(1));
  assert_eq!(e.log_view(), View::with(1));
  assert_eq!(e.op(), OpNumber::with(2));
  assert_eq!(e.commit(), OpNumber::with(1)); // op 1 applied
  // codex R6-F1: the PrepareOk for the held uncommitted op (op 2) is deferred until BOTH the new
  // view is durable AND op 2 is durably (re-)appended to the WAL (append-before-ack). Two sequential
  // storage steps: (1) the durable-view write completes → `start_view_acks` submits the WAL append;
  // (2) the append completes → `on_wal_done` sends the PrepareOk. Pump until it appears (bounded).
  let mut acked_op2 = false;
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb);
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg() {
        if ok.op() == OpNumber::with(2) {
          acked_op2 = true;
        }
      }
    }
    if acked_op2 {
      break;
    }
  }
  assert!(
    acked_op2,
    "backup must ack its held uncommitted ops in the new view"
  );
  // Append-before-ack: op 2 is in the durable WAL by the time it is acked (so a crash+recover after
  // the ack still produces it). The committed op 1 below the ack range is also durably present.
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "the acked op 2 was durably (re-)appended to the WAL before the PrepareOk (R6-F1)"
  );
}

#[test]
fn higher_view_prepare_triggers_get_view_catch_up() {
  // replica 0 at view 0 receives a Prepare for view 1 → catch up, sending GetView to primary(1)=1.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::Prepare(Prepare::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      OpNumber::with(0),
      ClientId::new(7),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"x"),
    )),
  );
  assert_eq!(e.view(), View::with(1));
  assert_eq!(e.status(), Status::ViewChange);
  let mut saw_get_view = false;
  while let Some(out) = e.poll_message() {
    if let Message::GetView(g) = out.into_msg() {
      assert_eq!(g.view(), View::with(1));
      saw_get_view = true;
    }
  }
  assert!(
    saw_get_view,
    "catch-up sends GetView (not a StartViewChange)"
  );

  // The StartView reply ends the catch-up: replica 0 becomes Normal in view 1.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(StartView::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(1),
      ReplicaId::new(1),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"x"),
      )],
    )),
  );
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(e.view(), View::with(1));
}

#[test]
fn normal_primary_answers_get_view_with_start_view() {
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::GetView(GetView::new(View::with(0), ReplicaId::new(1), 5)),
  );
  let mut saw_sv = false;
  while let Some(out) = e.poll_message() {
    if let Message::StartView(sv) = out.into_msg() {
      assert_eq!(sv.view(), View::with(0));
      assert_eq!(sv.replica(), ReplicaId::new(0));
      saw_sv = true;
    }
  }
  assert!(saw_sv, "a Normal primary answers GetView with a StartView");
}

#[test]
fn lone_high_svc_is_ignored_not_driven() {
  // A single StartViewChange for a far-future view must NOT inflate our view (C1 guard):
  // an SVC is not evidence a primary exists at that view.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 5).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(100), ReplicaId::new(0))),
  );
  assert_eq!(
    e.view(),
    View::new(),
    "a lone high SVC must not inflate our view"
  );
  assert_eq!(e.status(), Status::Normal);
}

#[test]
fn commit_max_tracks_learned_commit_above_applied() {
  // A backup that hears commit=5 but only holds op 2 records commit_max=5, commit_min=2.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 5)); // primary says commit=5, we have op 2
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "commit_min only advances over ops we hold"
  );
  assert_eq!(
    e.commit_max(),
    OpNumber::with(5),
    "commit_max records the learned commit"
  );
}

#[test]
fn backup_acks_only_after_append_is_durable() {
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  assert!(
    e.poll_message().is_none(),
    "no PrepareOk before the append is durable"
  );
  assert_eq!(
    wal.op_head(),
    OpNumber::with(1),
    "the prepare was submitted to the WAL"
  );
  e.handle_storage(now, &mut wal, &mut sb);
  match e
    .poll_message()
    .expect("PrepareOk after durable")
    .into_msg()
  {
    Message::PrepareOk(ok) => assert_eq!(ok.op(), OpNumber::with(1)),
    _ => panic!("expected PrepareOk"),
  }
}

#[test]
#[should_panic(expected = "must not rewind below our committed op")]
fn on_start_view_rewind_below_commit_panics() {
  // Adopt a StartView for view 1 with op 2 (commit 2), then a StartView for view 2 with op 1
  // (< our committed op 2). The second must fail-stop, not silently rewind.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)), // primary of view 1
    Message::StartView(StartView::new(
      View::with(1),
      OpNumber::with(2),
      OpNumber::with(2),
      ReplicaId::new(1),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a")
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b")
        ),
      ],
    )),
  );
  assert_eq!(e.commit(), OpNumber::with(2));
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)), // primary of view 2
    Message::StartView(StartView::new(
      View::with(2),
      OpNumber::with(1),
      OpNumber::with(1),
      ReplicaId::new(2),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a")
      )],
    )),
  );
}

#[test]
fn recover_enters_recovering_then_reaches_normal_after_reads_drain() {
  // recover() is now a metadata-only constructor: it returns in Recovering and only reaches
  // Normal after handle_storage drains the tail reads. (Was: synchronous → Normal immediately.)
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  drop(e);

  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  assert_eq!(
    r.status(),
    Status::Recovering,
    "recover is now a metadata-only constructor (Recovering)"
  );
  r.handle_storage(now, &mut wal, &mut sb); // drain the tail reads
  assert_eq!(r.status(), Status::Normal, "tail consistent => Normal");
  assert_eq!(r.op(), OpNumber::with(2));
}

#[test]
fn recover_retries_a_transient_read_fault_then_reaches_normal() {
  // A ScriptedWal faults op 2's read ONCE, then reads clean. The Recovering loop retries and
  // reaches Normal with the real body — a transient storage fault during recovery is tolerated.
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), 1);
  let mut sb = TestSb::default();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    EchoSm,
    &mut wal,
    &mut sb,
  );
  assert_eq!(r.status(), Status::Recovering);
  // Pump until the retry clears (bounded): each handle_storage drains one round + re-submits.
  for _ in 0..8 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() == Status::Normal {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "transient read-fault retried => Normal"
  );
  assert_eq!(r.op(), OpNumber::with(2));
}

#[test]
fn recover_head_permanently_faulty_enters_recovering_head() {
  // A ScriptedWal faults op 2's (the head's) read PERMANENTLY (beyond the retry budget). The
  // replica cannot trust its head => RecoveringHead, never Normal. It then SOLICITS the canonical
  // head (a Recovery broadcast) but still casts no ack/vote in response to a re-delivered prepare.
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // exceeds the retry budget
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
    "permanently-faulty head => RecoveringHead"
  );
  // On entry it solicits the canonical head (Recovery); drain that — it is NOT participation.
  while let Some(out) = r.poll_message() {
    assert!(
      out.msg_ref().is_recovery(),
      "the only message a RecoveringHead replica emits on entry is a Recovery solicitation"
    );
  }
  // A RecoveringHead replica must not participate: it casts no PrepareOk on a re-delivered prepare.
  r.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  assert!(
    r.poll_message().is_none(),
    "RecoveringHead replica emits no ack/vote in response to a prepare"
  );
}

// ── B4: peer fault-repair (RequestPrepare → Prepare) ──

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

#[test]
fn on_request_prepare_holder_replies_with_the_prepare() {
  // A Normal replica that holds a committed op answers a peer's RequestPrepare with the Prepare
  // carrying that op's body — the peer-fault-repair *server* side.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Hold ops 1 + 2 (apply 1 via the piggybacked commit).
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {} // discard acks

  // Replica 2 asks us for op 1.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(2),
    )),
  );
  let out = e.poll_message().expect("holder answers RequestPrepare");
  assert_eq!(
    out.to(),
    Recipient::To(Peer::Replica(ReplicaId::new(2))),
    "the Prepare is addressed back to the requester"
  );
  match out.into_msg() {
    Message::Prepare(p) => {
      assert_eq!(p.op(), OpNumber::with(1));
      assert_eq!(p.body(), &[1u8], "carries op 1's real body");
    }
    other => panic!("expected a Prepare reply, got {other:?}"),
  }
}

#[test]
fn on_request_prepare_for_an_op_we_lack_is_silent() {
  // A replica that does NOT hold the requested op stays silent (another peer answers) — never
  // fabricates a Prepare.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(9),
      ReplicaId::new(2),
    )),
  );
  assert!(
    e.poll_message().is_none(),
    "a replica that lacks the op answers no RequestPrepare"
  );
}

#[test]
fn on_request_prepare_serves_only_committed_ops_not_uncommitted_held_ops() {
  // R5-F1 (mirror, server side): a replica must NEVER vouch for an UNCOMMITTED op as a repair source.
  // It serves a RequestPrepare only for ops it has COMMITTED (`op <= commit_min`); for an op it merely
  // HOLDS but has not yet applied/committed (`op > commit_min`) it stays SILENT — that op is not its
  // to certify, and the answering Prepare's `commit` (= commit_min) would otherwise be < op, i.e. a
  // stale uncommitted vouch the requester's `fill_repair` now rejects anyway. A caught-up peer answers.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Hold ops 1 + 2 but COMMIT only op 1 (prepare(2,1) piggybacks commit=1 → commit_min == 1, op == 2).
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {} // discard acks
  assert_eq!(e.commit(), OpNumber::with(1), "committed through op 1 only");
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "but holds op 2 (uncommitted) in its log"
  );

  // Asking for op 2 (> commit_min == 1, held-but-uncommitted) → SILENT (not ours to certify).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(2),
      ReplicaId::new(2),
    )),
  );
  assert!(
    e.poll_message().is_none(),
    "no Prepare for an uncommitted held op (op 2 > commit_min) — we never vouch for it"
  );

  // Asking for op 1 (<= commit_min, committed) → answered (the answering Prepare carries commit >= op).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(2),
    )),
  );
  match e
    .poll_message()
    .expect("a committed op IS served")
    .into_msg()
  {
    Message::Prepare(p) => {
      assert_eq!(p.op(), OpNumber::with(1), "serves the committed op 1");
      assert!(
        p.commit().get() >= p.op().get(),
        "the answer vouches op 1 is committed (commit = commit_min >= op)"
      );
    }
    other => panic!("expected a Prepare for the committed op, got {other:?}"),
  }
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

#[test]
fn recover_non_head_faulty_committed_slot_becomes_normal_and_requests_repair() {
  // A permanently-faulty NON-head committed slot must NOT strand the replica (the old behaviour) and
  // must NOT panic: the replica returns to Normal, drops the unreadable slot from its cache, and
  // — once its commit reaches the slot — broadcasts a RequestPrepare for it (peer fault-repair),
  // HOLDING its commit below the hole. (codex R6-F2) The slot is NOT pre-registered as a repair hole
  // at recovery time: a faulty slot above the checkpoint may be UNCOMMITTED, and registering it then
  // would be an unfillable hole after the R5 repair restrictions; `advance_commit` requests it ON
  // DEMAND only when commit reaches it (which only happens once it is committed).
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  assert_eq!(
    r.status(),
    Status::Normal,
    "a non-head faulty committed slot peer-repairs from Normal (never strands in Recovering)"
  );
  // It did NOT pre-register op 2 as a repair hole at recovery time (commit_max is still 0, so op 2
  // is uncommitted as far as this replica knows). No RequestPrepare is solicited yet.
  assert!(
    !r.has_repair_hole_for_test(2),
    "the faulty slot is NOT pre-registered as a repair hole at recovery (it may be uncommitted)"
  );
  assert!(
    r.poll_message().is_none(),
    "no RequestPrepare is solicited at recovery time — repair is on-demand"
  );

  // Learn commit up to 3 (e.g. a Commit from the primary): op 1 applies, op 2 is a HOLE → commit
  // HELD at 1 (never skips to apply op 3 with op 2 missing). Reaching op 2 with commit now covering
  // it is exactly when `advance_commit` requests the repair ON DEMAND.
  let now = Instant::ZERO;
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(3), OpNumber::new())),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "commit is HELD below the hole — op 2's body is missing, so op 3 must not apply"
  );
  assert_eq!(
    r.state_machine().applied(),
    &[(1, std::vec![1u8])],
    "only op 1 applied; the hole stops the apply strictly in order"
  );
  // NOW op 2 is registered (on demand) and solicited: advance_commit reached it once commit covered it.
  assert!(
    r.has_repair_hole_for_test(2),
    "advance_commit registers the now-committed faulty op as a repair hole on demand"
  );
  let mut asked_for_2 = false;
  while let Some(out) = r.poll_message() {
    if let Message::RequestPrepare(rp) = out.into_msg() {
      assert_eq!(rp.op(), OpNumber::with(2));
      asked_for_2 = true;
    }
  }
  assert!(
    asked_for_2,
    "the replica solicits the faulty committed op once its commit reaches it"
  );
}

#[test]
fn recover_drops_a_superseded_above_commit_tail_slot_so_the_canonical_body_is_applied() {
  // REGRESSION (vopr seed 253 / 299 / 335), CONSENSUS-CRITICAL committed-divergence. A replica's WAL can
  // retain a STALE tail op from an EARLIER view that a later view never overwrote — a proposal it appended
  // as an old-view primary, which a view change SUPERSEDED (the new view assigns that op number a DIFFERENT
  // client request). Adoption only dropped it from the in-memory cache, not the WAL. On a later crash +
  // `recover`, the loop rebuilds the cache from the WAL and re-loads that stale body; when the cluster then
  // commits the op (whose CANONICAL value differs), `advance_commit` APPLIED the stale local body → the
  // replica diverged from every other replica at that one committed op number (no second op number is minted
  // and no request is committed twice — at-most-once holds — but a single committed slot carried two values).
  //
  // The seed-52 `vsr_headers` cross-check only guards the persisted committed band `(checkpoint .. commit]`;
  // a slot ABOVE the durable known-committed frontier is not in that band, so it was trusted blindly. The fix
  // generalises the cross-check: on `recover`, a self-verifying tail slot above `commit_max` whose ORIGINAL
  // header `view` is BELOW the durable `log_view` is a SUPERSEDED earlier-view proposal (we advanced our
  // `log_view` past it), so it is dropped and routed to peer-repair — the canonical body is fetched, never
  // re-derived from the stale WAL. A current-generation uncommitted tail op (`view == log_view`) is KEPT.
  //
  // Reproduction (replica 2 of 3 = a BACKUP of view 1): durable root view 1, log_view 1, commit 2, checkpoint
  // 0, with vsr_headers for the committed prefix ops 1 + 2 (current-view, canonical). The WAL holds an
  // INTERIOR stale slot op 3 (a view-0 proposal — client 9, request 99, body 0xAA) ABOVE the durable commit 2,
  // with current-view (view 1) ops 4 + 5 above it (a legitimate uncommitted tail that must be KEPT). The
  // cluster's canonical op 3 is (client 7, request 3, body [3]). Recover must DROP slot 3 (not hold its stale
  // body) yet keep 4 + 5; a committed-vouching peer-repair `Prepare` then supplies op 3's canonical body.
  let now = Instant::ZERO;
  let mk_header = |op: u64, view: u64, client: u128, request: u64, body: &[u8]| {
    Header::new(
      OpNumber::with(op),
      View::with(view),
      ClientId::new(client),
      RequestNumber::with(request),
      body,
    )
  };
  // Ops 1 + 2: current-view (view 1) canonical committed prefix. Op 3: STALE view-0 superseded INTERIOR slot.
  // Ops 4 + 5: current-view (view 1) uncommitted tail (kept — `view == log_view`), so op 3 is interior.
  let mut wal = ScriptedWal::with_entries(2); // seeds ops 1, 2 — view/body overwritten next
  wal.entries.insert(
    1,
    (mk_header(1, 1, 7, 1, &[1]), Bytes::copy_from_slice(&[1])),
  );
  wal.entries.insert(
    2,
    (mk_header(2, 1, 7, 2, &[2]), Bytes::copy_from_slice(&[2])),
  );
  wal.entries.insert(
    3,
    (
      mk_header(3, 0, 9, 99, &[0xAA]),
      Bytes::copy_from_slice(&[0xAA]),
    ),
  );
  wal.entries.insert(
    4,
    (mk_header(4, 1, 7, 4, &[4]), Bytes::copy_from_slice(&[4])),
  );
  wal.entries.insert(
    5,
    (mk_header(5, 1, 7, 5, &[5]), Bytes::copy_from_slice(&[5])),
  );
  wal.head = 5;
  let state = VsrState::try_new(
    View::with(1), // durable view 1 — recovers as a backup of view 1 (primary is replica 1)
    View::with(1), // durable log_view 1 — a view-0 tail slot is from a SUPERSEDED generation
    OpNumber::with(2), // commit 2 — ops 1 + 2 are KNOWN committed; op 3 is ABOVE the frontier
    OpNumber::new(), // checkpoint_op 0
    0,
    std::vec![mk_header(1, 1, 7, 1, &[1]), mk_header(2, 1, 7, 2, &[2])], // vsr_headers for 1 + 2
  )
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let cfg = Config::try_new(1, ReplicaId::new(2), 3).unwrap();
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(r.status(), Status::Normal, "recovers to Normal in view 1");
  assert_eq!(r.view(), View::with(1), "recovered into the durable view 1");
  assert!(!r.is_primary(), "replica 2 is a BACKUP of view 1");
  // The crux of the fix: the STALE view-0 slot 3 is DROPPED from the cache (FAIL-BEFORE: it was held as
  // `(client 9, request 99, body 0xAA)` and would later be applied for the committed op). Ops 1 + 2 (current
  // view, in the committed band) are kept.
  assert!(
    !r.log.contains_key(&3),
    "FAIL-BEFORE: the superseded view-0 slot 3 must be dropped on recover (not re-loaded as committed)"
  );
  assert!(
    r.log.contains_key(&1) && r.log.contains_key(&2),
    "the current-view committed prefix (ops 1 + 2) is retained"
  );
  assert!(
    r.log.contains_key(&4) && r.log.contains_key(&5),
    "the current-view uncommitted tail (ops 4 + 5, view == log_view) is KEPT — only the older-view slot is dropped"
  );
  while r.poll_message().is_some() {} // discard recovery chatter
  while r.poll_event().is_some() {}

  // The cluster commits op 3 (canonical = client 7, request 3, body [3]). A Commit reaches op 3 → the backup
  // holds at op 2 and solicits a peer-repair (op 3 is now a known-committed hole). A committed-vouching peer
  // answers with the canonical `Prepare` (commit >= op), which `fill_repair` adopts.
  let primary1 = Peer::Replica(ReplicaId::new(1));
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary1,
    Message::Commit(Commit::new(
      View::with(1),
      OpNumber::with(3),
      OpNumber::new(),
    )),
  );
  r.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "commit HELD at op 2 — op 3's stale slot was dropped, so it is a hole until peer-repair supplies it"
  );
  assert!(
    r.has_repair_hole_for_test(3),
    "op 3 is solicited as a committed-op repair hole (its stale local body is never trusted)"
  );
  // A committed-vouching peer-repair Prepare for the CANONICAL op 3 (commit = 3 >= op) fills the hole.
  let canonical_op3 = Message::Prepare(Prepare::new(
    View::with(1),
    OpNumber::with(3),
    OpNumber::with(3), // commit >= op: the answerer vouches op 3 is committed (fill_repair gate)
    OpNumber::new(),
    ClientId::new(7),
    RequestNumber::with(3),
    Bytes::copy_from_slice(&[3]),
  ));
  r.handle_message(now, &mut wal, &mut sb, primary1, canonical_op3);
  r.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "the hole filled → committed through op 3"
  );
  // The crux: op 3 applied the CANONICAL body [3], NEVER the stale [0xAA]. With the bug, the applied log read
  // `(3, [0xAA])` — a committed-state divergence from every replica that applied [3].
  assert_eq!(
    r.state_machine().applied(),
    &[
      (1, std::vec![1u8]),
      (2, std::vec![2u8]),
      (3, std::vec![3u8])
    ],
    "op 3 applied the canonical body [3]; the stale [0xAA] must NEVER be applied for the committed op"
  );
}

#[test]
fn adopting_a_canonical_head_truncates_the_wal_above_it() {
  // REGRESSION (vopr seed 253 / 299), the source-side half of the committed-divergence fix. When a replica
  // adopts a new view's canonical head, any WAL slot ABOVE that head is an UNCOMMITTED earlier-view proposal
  // (the canonical head is the new view's authoritative head — nothing above it is committed). Leaving such a
  // slot in the WAL lets a later `recover` re-load it and apply its stale body for a committed op the new view
  // assigns at that number. So adoption must physically TRUNCATE the WAL above the adopted head — dropping only
  // uncommitted ops (no durability dip). Here replica 2 of 3 holds a stale tail op 3 in its WAL, then adopts a
  // StartView for view 1 whose head is op 2; the WAL must no longer contain op 3.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Seed the WAL with a stale uncommitted tail op 3 (as if appended in an earlier generation).
  let stale = Header::new(
    OpNumber::with(3),
    View::new(),
    ClientId::new(9),
    RequestNumber::with(99),
    &[0xAA],
  );
  wal.submit_append(
    OpId::new(999),
    OpNumber::with(3),
    stale,
    Bytes::copy_from_slice(&[0xAA]),
  );
  while wal.poll().is_some() {} // discard the seed completion
  assert_eq!(
    wal.op_head(),
    OpNumber::with(3),
    "precondition: the WAL holds the stale tail op 3"
  );

  // Adopt a StartView for view 1 (from primary(1) = replica 1) whose canonical head is op 2.
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(2),
    OpNumber::with(1),
    ReplicaId::new(1),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        Bytes::from_static(b"a"),
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        Bytes::from_static(b"b"),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.op(), OpNumber::with(2), "adopted the canonical head op 2");
  // The crux: the stale slot 3 was TRUNCATED from the WAL (FAIL-BEFORE: it lingered, to be re-loaded by a
  // later recover and applied as a stale committed body).
  assert!(
    !wal.entries.contains_key(&3),
    "FAIL-BEFORE: the uncommitted tail op 3 above the adopted head must be truncated from the WAL"
  );
  assert!(
    wal.op_head().get() <= 2,
    "the WAL head no longer sits above the adopted canonical head"
  );
}

#[test]
fn recover_does_not_pre_register_an_uncommitted_faulty_tail_slot_as_a_repair_hole() {
  // codex R6-F2 (REGRESSION): a faulty slot ABOVE the checkpoint may be UNCOMMITTED. At recovery the
  // replica only knows `commit_min == commit_max == checkpoint_op`, so it must NOT pre-register the
  // slot in `self.repair`: post-R5 a peer serves only `op <= commit_min` and `fill_repair` rejects
  // `commit < op`, so an uncommitted repair hole can NEVER be filled — and the R5-F2 `on_request`
  // guard (`!self.repair.is_empty()`) would then drop every client forever (a liveness deadlock).
  //
  // Recover with an uncommitted interior faulty slot (checkpoint 0, head 3, faulty op 2, and NO
  // Commit ever raising commit_max past 0). After recovery `self.repair` must be EMPTY (fail-before:
  // it was `{2}`), so the apply path never wedges on an unfillable hole.
  let (r, _wal, _sb) = recovering_with_hole(3, 2);
  assert_eq!(
    r.status(),
    Status::Normal,
    "the recovered backup resumes Normal (the faulty slot is dropped from the cache, not stranding)"
  );
  assert!(
    !r.has_repair_hole_for_test(2),
    "an UNCOMMITTED faulty tail slot is NOT registered as a repair hole at recovery (R6-F2)"
  );
  assert!(
    r.repair.is_empty(),
    "the repair set is empty after recovery — no unfillable hole, no on_request deadlock (R6-F2)"
  );

  // Liveness consequence: with an empty repair set the R5-F2 `on_request` guard does NOT drop
  // clients. Demonstrate on a Normal PRIMARY (the role that serves requests): with the buggy
  // pre-registration (`repair = {uncommitted op}`) `on_request` returns early and the client hangs;
  // with the empty repair the recovery now produces, the primary accepts the request and prepares it.
  let now = Instant::ZERO;
  let mk_request = || {
    Message::Request(crate::Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::copy_from_slice(b"x"),
    ))
  };
  // (a) buggy state: an uncommitted op stranded in `repair` → every client is dropped (the deadlock).
  {
    let mut p = Endpoint::new(
      Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
      0,
      CountSm::default(),
    );
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    p.repair.insert(5); // simulate the old pre-registration of an uncommitted faulty slot
    p.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      mk_request(),
    );
    assert!(
      p.poll_message().is_none(),
      "with a stranded uncommitted hole in `repair`, on_request drops the client (the deadlock R6-F2 removes)"
    );
  }
  // (b) fixed state: empty repair (what recovery now leaves) → the primary serves the request.
  {
    let mut p = Endpoint::new(
      Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
      0,
      CountSm::default(),
    );
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(p.repair.is_empty(), "fresh primary has no repair holes");
    p.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      mk_request(),
    );
    let prepared = std::iter::from_fn(|| p.poll_message())
      .any(|out| matches!(out.into_msg(), Message::Prepare(_)));
    assert!(
      prepared,
      "with an empty repair set the primary serves the client (broadcasts a Prepare) — no deadlock"
    );
  }
}

#[test]
fn repaired_prepare_fills_the_hole_and_resumes_the_held_commit() {
  // End to end: a held-commit replica receives the peer-supplied Prepare for its hole, verifies it
  // (checksum + placement), fills the cache, and resumes applying the committed prefix in order —
  // the committed op is restored, NOT lost.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  while r.poll_message().is_some() {} // discard the solicitation
  let now = Instant::ZERO;
  // Learn commit up to 3 → applies op 1, holds at the op-2 hole.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(3), OpNumber::new())),
  );
  assert_eq!(r.commit(), OpNumber::with(1), "held at the hole");

  // A peer answers our RequestPrepare with op 2's Prepare → fill + resume.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 3),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "the hole filled → the held commit resumes and applies ops 2 then 3 in order"
  );
  assert_eq!(
    r.state_machine().applied(),
    &[
      (1, std::vec![1u8]),
      (2, std::vec![2u8]),
      (3, std::vec![3u8])
    ],
    "every committed op applied in order — the rotted op 2 was repaired from a peer, not lost"
  );
  // The repaired op was persisted durably (a later read serves it), so the hole cannot reopen.
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "the repaired op 2 is re-appended to the WAL (durable for future reads / DVCs)"
  );
}

#[test]
fn a_misplaced_repaired_prepare_is_rejected_not_adopted() {
  // Placement guard (the misdirected-IO defense the recovery read path makes, applied to a peer
  // reply): a Prepare for an op that is NOT our hole must NOT fill it. The hole stays open, the
  // commit stays HELD, and no wrong op's body is applied to the held slot.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  while r.poll_message().is_some() {}
  let now = Instant::ZERO;
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(3), OpNumber::new())),
  );
  assert_eq!(r.commit(), OpNumber::with(1));
  // A Prepare for op 5 (not our hole, op 2) is rejected by the placement check (`repair.contains`).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 5, 3),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "a Prepare whose op is not the hole does not fill it (placement mismatch)"
  );
  assert_eq!(
    r.state_machine().applied(),
    &[(1, std::vec![1u8])],
    "no wrong body applied; the commit stays held until the CORRECT op 2 arrives"
  );
  // The correct op 2 still repairs it (liveness: a wrong reply did not poison the hole).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 3),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "the correct op 2 fills the hole"
  );
}

#[test]
fn fill_repair_rejects_a_stale_uncommitted_prepare_for_a_committed_hole() {
  // R5-F1 (committed-op survival): a committed repair hole may ONLY be filled with the committed
  // value for the op. A STALE/reordered Prepare from an old view, broadcast while its body was still
  // UNCOMMITTED (`commit < op`), must be REJECTED — it does not vouch the op is committed, and the
  // committed value at that op could be a DIFFERENT body. Accepting it would diverge the replica from
  // the quorum that committed the real body. The hole stays open + the commit stays HELD until a
  // Prepare that vouches commit >= op arrives.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  while r.poll_message().is_some() {} // discard the solicitation
  let now = Instant::ZERO;
  // Learn commit up to 3 → applies op 1, holds at the op-2 hole.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(3), OpNumber::new())),
  );
  assert_eq!(r.commit(), OpNumber::with(1), "held at the hole");

  // A STALE Prepare for op 2 carrying `commit = 1` (< op 2): an old-view primary broadcast it while
  // op 2 was still uncommitted. Placement (op 2 IS our hole) + body checksum both PASS — only the new
  // commit-vouch guard rejects it.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 1),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "a stale Prepare (commit < op) does NOT fill a committed hole — commit stays HELD"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "the hole stays OPEN (re-solicited) — the uncommitted old-view body is never adopted"
  );
  assert_eq!(
    r.state_machine().applied(),
    &[(1, std::vec![1u8])],
    "no uncommitted body applied to the held slot"
  );

  // A Prepare that VOUCHES op 2 is committed (`commit = 2` >= op 2, from a peer that holds it
  // committed) fills the hole and resumes the held commit — liveness preserved.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );
  assert!(
    !r.has_repair_hole_for_test(2),
    "a committed-vouching Prepare (commit >= op) clears the hole"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "the committed value fills the hole → the held commit resumes (ops 2 then 3 apply in order)"
  );
  assert_eq!(
    r.state_machine().applied(),
    &[
      (1, std::vec![1u8]),
      (2, std::vec![2u8]),
      (3, std::vec![3u8])
    ],
    "every committed op applied in order — only the committed value filled the hole"
  );
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "the committed op 2 is durably (re)appended once the vouching Prepare fills it"
  );
}

#[test]
fn repair_holds_the_commit_across_a_long_unrepaired_window() {
  // Liveness/safety under delay: while the hole is unrepaired the commit stays HELD no matter how
  // much further commit the primary announces — a committed op above the hole is NEVER applied
  // before the hole is filled (strict in-order apply). Then a single repair fills it and the whole
  // suffix applies at once.
  let (mut r, mut wal, mut sb) = recovering_with_hole(4, 2);
  while r.poll_message().is_some() {}
  let now = Instant::ZERO;
  // Repeatedly learn commit up to the head; the hole at op 2 pins the applied frontier at op 1.
  for _ in 0..5 {
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(View::new(), OpNumber::with(4), OpNumber::new())),
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(1),
      "commit pinned at the hole regardless of how far the primary's commit advances"
    );
  }
  // One repair → the entire held suffix (2,3,4) applies in order.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 4),
  );
  assert_eq!(r.commit(), OpNumber::with(4));
  assert_eq!(
    r.state_machine().applied(),
    &[
      (1, std::vec![1u8]),
      (2, std::vec![2u8]),
      (3, std::vec![3u8]),
      (4, std::vec![4u8])
    ],
    "every committed op applied in order once the single hole was repaired"
  );
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

#[test]
fn recovering_head_solicits_recovery_on_entry() {
  // On entering RecoveringHead the replica broadcasts a Recovery solicitation (it cannot recover
  // its head from its own disk) carrying its replica id + nonce.
  let (mut r, _wal, _sb) = recovering_head(2);
  let mut saw_recovery = false;
  while let Some(out) = r.poll_message() {
    if let Message::Recovery(rec) = out.into_msg() {
      assert_eq!(rec.replica(), ReplicaId::new(1));
      saw_recovery = true;
    }
  }
  assert!(
    saw_recovery,
    "RecoveringHead solicits the canonical head via Recovery"
  );
  // It also armed the solicitation timer so an owner driving poll_timeout keeps re-soliciting.
  assert!(
    r.poll_timeout().is_some(),
    "RecoveringHead arms the recover_head timer"
  );
}

#[test]
fn recovering_head_adopts_start_view_and_becomes_normal() {
  // A replica stuck in RecoveringHead (head slot permanently lost) receives a StartView from the
  // view's primary; it adopts the canonical head + log, persists the view, and becomes Normal —
  // the committed op it could not read locally is restored from the canonical log.
  let (mut r, mut wal, mut sb) = recovering_head(2);
  while r.poll_message().is_some() {} // discard the solicitation
  let now = Instant::ZERO;
  // primary(view 1) of a 3-cluster is replica 1 — but THIS replica is replica 1, so use view 0's
  // primary (replica 0) at a view >= ours (view 0). A same-view StartView from the primary adopts
  // because a RecoveringHead replica is not Normal.
  let sv = StartView::new(
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    ReplicaId::new(0), // primary of view 0
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
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartView(sv),
  );
  assert_eq!(
    r.status(),
    Status::Normal,
    "RecoveringHead adopts the StartView → Normal"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(2),
    "head re-established from the canonical log"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the committed prefix is restored"
  );
  // The recovery bookkeeping is cleared (structurally None in Normal).
  assert!(r.recover.is_none(), "recover state cleared on adoption");
  // The new view is persisted before participation; pump the durable-view write, then it re-acks.
  r.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(sb.state().view(), View::new());
}

#[test]
fn recovering_head_with_a_faulty_non_head_slot_never_applies_an_empty_body() {
  // REGRESSION (the empty-body divergence the M3 sweep exposed): a replica that recovers with BOTH a
  // faulty HEAD slot (→ RecoveringHead) AND a faulty NON-head committed slot must STILL drop the
  // non-head slot from its `log` cache (it holds only an EMPTY placeholder body from recover Phase 1).
  // Otherwise, when it later adopts a canonical head whose (offset) log OMITS that slot, `adopt_log`
  // PRESERVES the empty-bodied held copy, `adopt_canonical_head` retires its repair hole (it is now
  // "held"), and `advance_commit` applies it with the EMPTY body — diverging a committed op. The fix
  // drops every faulty slot from the cache on the RecoveringHead path and registers the non-head ones
  // as repair holes, so adoption keeps the hole and the commit is HELD until a peer serves the op.
  let mut wal = ScriptedWal::with_entries(4);
  wal.script_read_fault(OpNumber::with(4), u8::MAX); // faulty HEAD → RecoveringHead
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // faulty NON-head committed slot (empty in cache)
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
    if r.status() != Status::Recovering {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "faulty head → RecoveringHead"
  );
  while r.poll_message().is_some() {} // discard the Recovery solicitation

  // Adopt a StartView from the view-0 primary (replica 0): canonical head op 4, commit 4, but an
  // OFFSET log carrying only ops 3,4 — it OMITS op 2 (modelling a primary whose log starts above 2).
  let sv = StartView::new(
    View::new(),
    OpNumber::with(4),
    OpNumber::with(4),
    ReplicaId::new(0),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(3),
        ClientId::new(7),
        RequestNumber::with(3),
        bytes::Bytes::copy_from_slice(&[3u8]),
      ),
      PreparedEntry::new(
        OpNumber::with(4),
        ClientId::new(7),
        RequestNumber::with(4),
        bytes::Bytes::copy_from_slice(&[4u8]),
      ),
    ],
  );
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartView(sv),
  );

  // Op 2 was NOT resurrected from the empty placeholder: it stays a solicited repair hole, NEVER
  // applied empty. This replica recovered from its WAL alone (no checkpoint, commit_min == 0), so it
  // had APPLIED nothing — ops 1 AND 2 are both committed-but-unapplied at adopt time. The offset
  // canonical log omits op 2 (and op 1), so BOTH become repair holes: the commit is HELD at 0 at the
  // first hole (op 1), op 2 is registered once op 1 fills. (The seed-24 safety fix means an UNAPPLIED
  // omitted committed op is never resurrected from the local cache — including op 1, whose clean-read
  // WAL body could itself be a superseded proposal — so it is fetched from a peer, not trusted local.
  // This only STRENGTHENS the original guard: still no empty/stale body is ever applied to op 2.)
  assert!(
    r.has_repair_hole_for_test(2) || r.has_repair_hole_for_test(1),
    "an omitted unapplied committed op (op 1 first, then op 2) is a repair hole — never resurrected"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(0),
    "the commit is HELD below the first unfilled hole (op 1), never advanced over an empty/stale body"
  );
  // CRUCIAL: no op was ever applied with an empty body (the divergence signature).
  for (op, body) in r.state_machine().applied() {
    assert!(
      !body.is_empty(),
      "op {op} was applied with an EMPTY body — the committed-op divergence this guards against"
    );
  }
  // And op 2 specifically is not applied at all yet (held — its faulty empty placeholder was dropped).
  assert!(
    !r.state_machine().applied().iter().any(|(op, _)| *op == 2),
    "op 2 is not applied until a verified body arrives"
  );
  assert!(
    !r.log.contains_key(&2),
    "op 2's faulty empty placeholder is never re-introduced into the log cache"
  );
}

#[test]
fn recovering_head_adopts_recovery_response_from_primary() {
  // The full handshake: a RecoveringHead replica's Recovery is answered by the primary with a
  // RecoveryResponse carrying the canonical head; the replica adopts it and returns to Normal.
  let (mut r, mut wal, mut sb) = recovering_head(2);
  // Capture the nonce the replica solicited with (so we echo it in the primary's response).
  let mut nonce = 0;
  while let Some(out) = r.poll_message() {
    if let Message::Recovery(rec) = out.into_msg() {
      nonce = rec.nonce();
    }
  }
  let now = Instant::ZERO;
  // The primary of view 0 (replica 0) answers with its canonical log + head + commit, echoing nonce.
  let resp = RecoveryResponse::new(
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    ReplicaId::new(0),
    nonce,
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
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::RecoveryResponse(resp),
  );
  assert_eq!(
    r.status(),
    Status::Normal,
    "adopt the primary's RecoveryResponse → Normal"
  );
  assert_eq!(r.op(), OpNumber::with(2));
  assert_eq!(r.commit(), OpNumber::with(2));
  assert!(r.recover.is_none());
}

#[test]
fn recovering_head_ignores_stale_or_non_primary_recovery_response() {
  // A RecoveryResponse with the WRONG nonce (a stale prior solicitation) is ignored, and a
  // response from a NON-primary (empty log) cannot re-establish a head — the replica stays
  // RecoveringHead in both cases, never adopting an unauthoritative head.
  let (mut r, mut wal, mut sb) = recovering_head(2);
  let mut nonce = 0;
  while let Some(out) = r.poll_message() {
    if let Message::Recovery(rec) = out.into_msg() {
      nonce = rec.nonce();
    }
  }
  let now = Instant::ZERO;
  // Wrong nonce → ignored.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::RecoveryResponse(RecoveryResponse::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      ReplicaId::new(0),
      nonce.wrapping_add(1), // stale/forged
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      )],
    )),
  );
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "a wrong-nonce response is ignored"
  );
  // A response from a non-primary (replica 2, with empty log) → ignored (no canonical head).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RecoveryResponse(RecoveryResponse::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      ReplicaId::new(2), // NOT primary(view 0)
      nonce,
      std::vec![],
    )),
  );
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "a non-primary response cannot re-establish the head"
  );
}

#[test]
fn recovering_head_does_not_participate_on_non_head_learning_messages() {
  // The guard relaxation is SURGICAL: a RecoveringHead replica processes only StartView /
  // RecoveryResponse. A Prepare/Commit/PrepareOk must NOT be acted on (no vote/ack), and must NOT
  // pull it into a view change via the higher-view rule.
  let (mut r, mut wal, mut sb) = recovering_head(2);
  while r.poll_message().is_some() {} // discard the solicitation
  let now = Instant::ZERO;
  // A higher-view Prepare would normally trigger catch_up_to_view → ViewChange. It must be dropped.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::with(5),
      OpNumber::with(3),
      OpNumber::with(2),
      OpNumber::with(0),
      ClientId::new(7),
      RequestNumber::with(3),
      Bytes::from_static(b"z"),
    )),
  );
  // A current-view Prepare for an op we hold would normally re-ack. It must be dropped too.
  r.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  // A Commit would normally advance commit. Dropped.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(1), OpNumber::new())),
  );
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "no message pulled it out of RecoveringHead"
  );
  assert_eq!(r.view(), View::new(), "view unchanged (no catch-up)");
  assert!(
    r.poll_message().is_none(),
    "RecoveringHead casts no ack/vote on non-head-learning messages"
  );
}

// ── R4-F1: a recovered replica must NOT resume as the established primary ──

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

#[test]
fn recovered_primary_abdicates_to_a_view_change_instead_of_resuming_normal() {
  // A replica that was the PRIMARY of its restored view (log_view == view, replica_count > 1) must
  // NOT resume Normal with an empty pipeline (which would freeze commit at checkpoint_op and risk
  // re-executing a retried request). Per TigerBeetle replica.zig open(), it abdicates: forces a
  // view change to view+1. Replica 0 is primary of view 0; the root names view 0 / log_view 0.
  let mut wal = wal_in_view(2, 0);
  let mut sb = sb_with_view(0, 0);
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::ViewChange,
    "a recovered primary abdicates (ViewChange), never resumes Normal with an empty pipeline"
  );
  assert_eq!(
    r.view(),
    View::with(1),
    "abdication forces the NEXT view (view + 1)"
  );
  // Drain the abdication's own view-change traffic (StartViewChange etc.) — it is NOT request service.
  while r.poll_message().is_some() {}
  // The double-execute hazard is closed: a fresh client request is NOT served while not Normal —
  // no Prepare to backups, no Reply to the client (on_request returns early on status != Normal).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    client_request(1),
  );
  while let Some(out) = r.poll_message() {
    let m = out.into_msg();
    assert!(
      !matches!(m, Message::Prepare(_) | Message::Reply(_)),
      "an abdicating recovered primary serves no request: neither Prepare nor Reply, got {m:?}"
    );
  }
}

#[test]
fn recovered_backup_resumes_normal_unchanged() {
  // A replica that is NOT the primary of its restored view resumes Normal (unchanged behaviour).
  // Replica 1 of 3 in view 0 is a backup (primary of view 0 is replica 0).
  let mut wal = wal_in_view(2, 0);
  let mut sb = sb_with_view(0, 0);
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
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "a recovered backup resumes Normal (it waits for the primary's Prepare/Commit)"
  );
  assert_eq!(
    r.view(),
    View::new(),
    "a recovered backup does not advance the view"
  );
  assert_eq!(r.op(), OpNumber::with(2));
}

#[test]
fn recovered_mid_view_change_redrives_the_in_progress_view_change() {
  // log_view < view: the durable view advanced (a view change was in progress) but the new log was
  // not yet installed. On recovery the replica re-drives VC(view) — it enters ViewChange AT `view`
  // (not view+1, not Normal). Root names view 1 / log_view 0; replica 2 of 3 (a backup of view 1).
  let mut wal = wal_in_view(2, 0);
  let mut sb = sb_with_view(1, 0);
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(2), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::ViewChange,
    "a replica that crashed mid-view-change re-drives the view change (ViewChange)"
  );
  assert_eq!(
    r.view(),
    View::with(1),
    "it re-drives the SAME in-progress view (log_view < view → VC at view, not view+1)"
  );
}

#[test]
fn recovered_solo_primary_resumes_normal_and_commits_its_tail() {
  // A solo cluster (replica_count == 1) is always its own primary and CANNOT view-change (no peer
  // quorum) — it must resume Normal, NOT abdicate (which would deadlock). It must also still make
  // progress: the recovered tail (ops the solo primary committed pre-crash, above the last
  // checkpoint) re-commits from the rebuilt pipeline rather than stalling on an empty inflight.
  let mut wal = wal_in_view(2, 0);
  let mut sb = sb_with_view(0, 0);
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(0), 1).unwrap(),
    0,
    CountSm::default(),
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "a solo replica resumes Normal (it cannot view-change)"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the solo primary re-commits its recovered tail (no stall on an empty inflight)"
  );
  // And it still serves a fresh request end-to-end (op 3 commits).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    client_request(1),
  );
  for _ in 0..4 {
    r.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "a solo primary still commits a NEW request after recovery"
  );
}

#[test]
fn normal_primary_answers_recovery_with_canonical_response() {
  // A Normal primary answers a peer's Recovery with a RecoveryResponse carrying its canonical
  // log + head + commit, echoing the nonce. (Replica 0 is primary of view 0.)
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Give the primary one committed op so its response is non-trivial.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"a"),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // own append durable → commit op 1 (quorum 2 in N=3? no)
  while e.poll_message().is_some() {}
  // A peer (replica 2) solicits recovery.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::Recovery(Recovery::new(ReplicaId::new(2), 0x1234)),
  );
  let mut resp = None;
  while let Some(out) = e.poll_message() {
    if let Message::RecoveryResponse(rr) = out.into_msg() {
      resp = Some(rr);
    }
  }
  let rr = resp.expect("Normal primary answers Recovery with a RecoveryResponse");
  assert_eq!(rr.replica(), ReplicaId::new(0), "answered by the primary");
  assert_eq!(rr.nonce(), 0x1234, "the nonce is echoed");
  assert_eq!(rr.op(), OpNumber::with(1), "carries the primary's head");
  assert_eq!(rr.log_slice().len(), 1, "carries the canonical log");
}

#[test]
fn normal_backup_answers_recovery_with_view_only() {
  // A Normal BACKUP answers a Recovery with only its view + echoed nonce (no canonical head):
  // op/commit are 0 and the log is empty. (Replica 2 is a backup of view 0.)
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::Recovery(Recovery::new(ReplicaId::new(1), 0x5678)),
  );
  let mut rr = None;
  while let Some(out) = e.poll_message() {
    if let Message::RecoveryResponse(r) = out.into_msg() {
      rr = Some(r);
    }
  }
  let rr = rr.expect("a Normal backup also answers a Recovery (view only)");
  assert_eq!(rr.nonce(), 0x5678);
  assert!(
    rr.log_slice().is_empty(),
    "a backup carries no canonical log"
  );
  assert_eq!(rr.op(), OpNumber::new(), "a backup reports no head");
}

#[test]
fn recover_read_ok_with_bad_checksum_does_not_adopt_the_corrupt_body() {
  // The verify chokepoint (spec §3): a ReadOk whose body fails Header::verify is treated as a
  // fault, not adopted. With it as the head and permanently corrupt => RecoveringHead.
  let mut wal = ScriptedWal::with_entries(1);
  wal.script_corrupt_body(OpNumber::with(1)); // ReadOk with a body that fails verify, forever
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
    "a checksum-failing head body is never adopted"
  );
}

#[test]
fn recover_repairs_a_committed_slot_whose_wal_body_mismatches_the_persisted_header() {
  // CONSENSUS-CRITICAL regression (VOPR seed 52). `recover` blindly re-derived committed ops from
  // the WAL bytes, so an ADOPTED committed slot whose WAL kept a STALE superseded body (a prior-view
  // proposal whose OWN header is internally consistent) was resurrected on crash+recover → the
  // recovered replica diverged. The fix: the durable `VsrState` carries the CANONICAL `vsr_headers`
  // for the committed band `(checkpoint_op .. commit]`, and `recover` cross-checks each committed-band
  // WAL slot's body against the persisted canonical `body_checksum`. A MISMATCH is routed to
  // peer-repair (the B4 path) instead of being trusted — the canonical body is fetched from a peer.
  //
  // Setup: replica 1 of 3. Durable root: view 0, commit 2, checkpoint_op 0, with canonical headers
  // recording op 1 = body [1] and op 2 = body [2] (bodyY). The WAL holds op 1 = [1] (canonical) but
  // op 2 = [0xBB] (bodyX — STALE), with a SELF-CONSISTENT header for [0xBB] (so plain `Header::verify`
  // passes, exactly the seed-52 hazard). Op 3 = [3] sits above the committed band (uncommitted tail).
  let canonical_op1 = Header::new(
    OpNumber::with(1),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(1),
    &[1u8],
  );
  // op 2's CANONICAL header records body [2]; this is what the durable root persists (vsr_headers).
  let canonical_op2 = Header::new(
    OpNumber::with(2),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(2),
    &[2u8],
  );
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2), // commit
    OpNumber::new(),   // checkpoint_op
    0,
    std::vec![canonical_op1, canonical_op2],
  )
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };

  // The WAL: ops 1 + 3 canonical, but op 2 holds the STALE body [0xBB] with a header self-consistent
  // for [0xBB] (a superseded prior-view proposal the WAL never re-wrote on adoption).
  let mut wal = ScriptedWal::with_entries(3);
  let stale_body = Bytes::copy_from_slice(&[0xBBu8]);
  let stale_header = Header::new(
    OpNumber::with(2),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(2),
    &stale_body,
  );
  assert!(
    stale_header.verify(&stale_body),
    "the stale slot is SELF-CONSISTENT (its own header matches its own body) — plain verify passes"
  );
  wal.entries.insert(2, (stale_header, stale_body));

  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  // The stale committed slot was DETECTED (canonical-header mismatch) and DROPPED — never adopted. The
  // replica returns to Normal (op 2 is below the head 3, so it peer-repairs rather than RecoveringHead).
  assert_eq!(
    r.status(),
    Status::Normal,
    "a stale committed slot is dropped + peer-repaired (not stranded, not RecoveringHead)"
  );
  assert!(
    !r.log.contains_key(&2),
    "the stale slot is dropped from the in-memory log so it can never be applied with the stale body"
  );
  // Recovery did not apply anything yet (commit_min == checkpoint_op == 0); the stale body [0xBB] was
  // never applied.
  assert!(
    r.state_machine().applied().is_empty(),
    "nothing applied yet — the stale body [0xBB] is never re-derived from the WAL"
  );

  // The primary announces commit=2. advance_commit reaches op 2, finds the HOLE, HOLDS the commit at 1
  // (only op 1 applies), and solicits op 2 via RequestPrepare (on-demand peer-repair).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "commit HELD below the stale-detected hole — op 2's canonical body is not yet present"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "op 2 is registered as a repair hole once commit reaches it (on demand)"
  );
  let mut asked_for_2 = false;
  while let Some(out) = r.poll_message() {
    if let Message::RequestPrepare(rp) = out.into_msg() {
      if rp.op() == OpNumber::with(2) {
        asked_for_2 = true;
      }
    }
  }
  assert!(
    asked_for_2,
    "the replica solicits the canonical op 2 from a peer"
  );

  // A committed-vouching peer answers with the CANONICAL op 2 (body [2], commit=2 >= op 2). This fills
  // the hole and resumes the held commit: op 2 applies with [2] (bodyY), NEVER [0xBB] (bodyX).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the canonical op 2 fills the hole → the held commit resumes"
  );
  assert_eq!(
    r.state_machine().applied(),
    &[(1, std::vec![1u8]), (2, std::vec![2u8])],
    "the applied band is CANONICAL ([1],[2]) — the stale WAL body [0xBB] was never resurrected \
     (FAIL-BEFORE: the old recover trusted the WAL and applied [0xBB], diverging)"
  );
  // The repaired canonical op 2 is durably (re)appended, so a subsequent restart reads it cleanly.
  let (h2, b2) = wal.entries.get(&2).expect("op 2 present after repair");
  assert_eq!(
    b2.as_ref(),
    &[2u8],
    "the WAL slot now holds the CANONICAL body [2]"
  );
  assert_eq!(h2.body_checksum(), canonical_op2.body_checksum());
}

#[test]
fn recover_repairs_a_committed_slot_with_matching_body_but_wrong_client_or_request() {
  // CONSENSUS-CRITICAL regression (codex R9-F2). A committed op's identity is `(op, client, request,
  // body)`, NOT body bytes alone. Two clients can submit IDENTICAL payload bytes, so a STALE superseded
  // WAL slot that kept the SAME body but a DIFFERENT `client`/`request` would pass the body-only
  // cross-check, be adopted, and applied under the WRONG session — corrupting dedup/reply (duplicate
  // execution under the wrong client). The fix keys the canonical cross-check on FULL operation identity
  // `(client, request, body_checksum)`: a same-body-different-identity slot now MISMATCHES and is dropped
  // → peer-repaired, exactly like the seed-52 stale-body case.
  //
  // Setup: replica 1 of 3. Durable root: view 0, commit 2, checkpoint_op 0. The canonical header for op 2
  // records identity `(clientB = 9, req 3, body [2])` — what the cluster actually committed. The WAL slot
  // for op 2 SELF-VERIFIES but holds a DIFFERENT identity `(clientA = 7, req 5, body [2])` with the SAME
  // body bytes [2] (so the body checksum is IDENTICAL — only client/request differ). Op 1 is clean
  // canonical; op 3 sits above the committed band (uncommitted tail).
  let client_a = ClientId::new(7);
  let client_b = ClientId::new(9);
  let canonical_op1 = Header::new(
    OpNumber::with(1),
    View::new(),
    client_a,
    RequestNumber::with(1),
    &[1u8],
  );
  // op 2's CANONICAL identity: clientB / request 3 / body [2] — persisted in the durable root (vsr_headers).
  let canonical_op2 = Header::new(
    OpNumber::with(2),
    View::new(),
    client_b,
    RequestNumber::with(3),
    &[2u8],
  );
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2), // commit
    OpNumber::new(),   // checkpoint_op
    0,
    std::vec![canonical_op1, canonical_op2],
  )
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };

  // The WAL: ops 1 + 3 canonical, but op 2 holds the SAME body [2] under a DIFFERENT identity
  // `(clientA = 7, req 5)`. Its header self-verifies (header checksum + body checksum both valid), so
  // plain `Header::verify` passes — and its body checksum EQUALS the canonical one (same bytes). Only the
  // FULL-identity check distinguishes it.
  let mut wal = ScriptedWal::with_entries(3);
  let same_body = Bytes::copy_from_slice(&[2u8]);
  let wrong_identity_header = Header::new(
    OpNumber::with(2),
    View::new(),
    client_a,               // WRONG client (canonical is clientB)
    RequestNumber::with(5), // WRONG request (canonical is req 3)
    &same_body,
  );
  assert!(
    wrong_identity_header.verify(&same_body),
    "the wrong-identity slot is SELF-CONSISTENT — plain verify passes; only full identity differs"
  );
  assert_eq!(
    wrong_identity_header.body_checksum(),
    canonical_op2.body_checksum(),
    "the body checksum is IDENTICAL (same bytes) — a body-only check would WRONGLY trust this slot \
     (FAIL-BEFORE: same-body-different-client slot is adopted under clientA/req5)"
  );
  wal.entries.insert(2, (wrong_identity_header, same_body));

  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  // The wrong-identity committed slot was DETECTED (identity mismatch) and DROPPED — never adopted.
  assert_eq!(
    r.status(),
    Status::Normal,
    "a wrong-identity committed slot is dropped + peer-repaired (not stranded, not RecoveringHead)"
  );
  assert!(
    !r.log.contains_key(&2),
    "the wrong-identity slot is dropped from the in-memory log so it can never be applied as clientA/req5"
  );
  assert!(
    r.state_machine().applied().is_empty(),
    "nothing applied yet — the wrong-identity body is never re-derived from the WAL"
  );

  // The primary announces commit=2. advance_commit reaches op 2, finds the HOLE, HOLDS the commit at 1,
  // and solicits op 2 via RequestPrepare (on-demand peer-repair).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "commit HELD below the wrong-identity hole — op 2's canonical identity is not yet present"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "op 2 is registered as a repair hole once commit reaches it (on demand)"
  );
  // Drop the events from applying op 1 so the assertion below sees ONLY op 2's commit.
  while r.poll_event().is_some() {}

  // A committed-vouching peer answers with the CANONICAL op 2: identity `(clientB = 9, req 3, body [2])`,
  // commit = 2 >= op 2. This fills the hole and resumes the held commit.
  let canonical_repair = Message::Prepare(Prepare::new(
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2), // commit >= op → a committed repair value
    OpNumber::new(),
    client_b,
    RequestNumber::with(3),
    Bytes::copy_from_slice(&[2u8]),
  ));
  r.handle_message(now, &mut wal, &mut sb, primary_peer(), canonical_repair);
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the canonical op 2 fills the hole → the held commit resumes"
  );
  // The op 2 that COMMITTED carries the CANONICAL session `clientB / req 3`, NEVER the stale
  // `clientA / req 5` the WAL slot held. (FAIL-BEFORE: the body-only check adopted clientA/req5.)
  let committed_op2 = std::iter::from_fn(|| r.poll_event())
    .map(|e| e.unwrap_committed())
    .find(|c| c.op() == OpNumber::with(2))
    .expect("op 2 committed event");
  assert_eq!(
    committed_op2.client(),
    client_b,
    "op 2 applied under the CANONICAL clientB — never the stale WAL clientA"
  );
  assert_eq!(
    committed_op2.request(),
    RequestNumber::with(3),
    "op 2 applied under the CANONICAL request 3 — never the stale WAL request 5"
  );
  // The dedup session table reflects clientB/req3 (the canonical identity), and clientA was never
  // advanced by op 2 (its only mention was the stale, dropped slot).
  assert_eq!(
    r.clients.get(&client_b.get()).map(|s| s.request),
    Some(RequestNumber::with(3)),
    "clientB's session watermark is the canonical request 3"
  );
  assert!(
    r.clients
      .get(&client_a.get())
      .is_none_or(|s| s.request < RequestNumber::with(5)),
    "clientA/req5 was NEVER applied — the stale slot's identity never touched a session"
  );
}

#[test]
fn recover_trusts_a_committed_slot_that_matches_its_persisted_header() {
  // The complement of the seed-52 regression: a NORMAL-operation recover (no staleness) must NOT
  // spuriously peer-repair. Every committed-band WAL slot matches its persisted canonical header, so
  // recovery trusts them all — no repair hole, no dropped slot, the SM re-applies the canonical band
  // directly from the WAL once commit is announced.
  let mk_header = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  // Durable root: commit 2, checkpoint_op 0, canonical headers for ops 1 + 2 matching the WAL bodies.
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::new(),
    0,
    std::vec![mk_header(1), mk_header(2)],
  )
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(3); // ops 1,2,3 all canonical [op]
  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "a consistent tail recovers cleanly to Normal"
  );
  assert!(
    r.repair.is_empty(),
    "no spurious repair hole — every committed-band slot matched its persisted header"
  );
  assert!(
    r.log.get(&2).is_some_and(|e| e.body.as_ref() == [2u8]),
    "op 2 kept its canonical WAL body (trusted, not dropped)"
  );
  // Announce commit=2: both committed ops apply directly from the trusted WAL, no peer-repair needed.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the consistent committed band applies straight through"
  );
  assert!(
    r.repair.is_empty(),
    "still no repair hole after applying the trusted band"
  );
  assert_eq!(
    r.state_machine().applied(),
    &[(1, std::vec![1u8]), (2, std::vec![2u8])],
    "the trusted WAL band applied verbatim"
  );
}

#[test]
fn recovering_replica_ignores_messages_and_does_not_join_a_view_change() {
  // Non-participation: a Recovering replica must NOT process consensus messages — in particular a
  // higher-view Prepare must NOT pull it into ViewChange (the catch_up_to_view leak). It stays
  // Recovering and emits nothing until its own storage loop completes.
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), 2); // keep it Recovering (not yet drained)
  let mut sb = TestSb::default();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  assert_eq!(r.status(), Status::Recovering);
  // A higher-view Prepare (view 5) — would normally trigger catch_up_to_view → ViewChange.
  let higher = Message::Prepare(Prepare::new(
    View::with(5),
    OpNumber::with(3),
    OpNumber::with(2),
    OpNumber::with(0),
    ClientId::new(7),
    RequestNumber::with(3),
    Bytes::from_static(b"z"),
  ));
  r.handle_message(now, &mut wal, &mut sb, primary_peer(), higher);
  assert_eq!(
    r.status(),
    Status::Recovering,
    "a Recovering replica ignores a higher-view message (no catch_up_to_view)"
  );
  assert_eq!(r.view(), View::new(), "view is unchanged (no adoption)");
  assert!(
    r.poll_message().is_none(),
    "Recovering replica emits nothing"
  );
}

#[test]
fn recover_timer_resubmits_a_dropped_transient_fault() {
  // Robustness for a real async driver: if a transient fault's completion never produces a clean
  // read in the SAME drain, the recover_retry timer must re-submit pending/faulty reads so the
  // loop still terminates. Here op 2 faults twice (so one pump leaves it faulty-with-budget); a
  // timeout fires the retry, the next read is clean, and we reach Normal.
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), 2);
  let mut sb = TestSb::default();
  let mut now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    EchoSm,
    &mut wal,
    &mut sb,
  );
  // A Recovering replica must arm a timer (so an owner driving poll_timeout makes progress).
  assert!(
    r.poll_timeout().is_some(),
    "Recovering arms the recover_retry timer"
  );
  for _ in 0..8 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() == Status::Normal {
      break;
    }
    // Advance to the next timer deadline and fire it (re-submits pending/faulty reads).
    if let Some(t) = r.poll_timeout() {
      now = t;
      r.handle_timeout(now, &mut wal, &mut sb);
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "the recover_retry timer drives the loop to termination"
  );
}

#[test]
fn recover_rebuilds_log_and_op_from_wal() {
  // A backup appends ops 1,2 durably, then "crashes". recover() from the SAME wal/sb rebuilds
  // op=2 with REAL bodies, view from the superblock. recover() is now metadata-only (returns
  // Recovering); a no-fault TestWal completes the tail reads in one handle_storage → Normal.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  // Drop `e` (crash). Recover a fresh endpoint from the SAME durable wal/sb.
  drop(e);
  let mut recovered = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  assert_eq!(
    recovered.status(),
    Status::Recovering,
    "recover is a metadata-only constructor (Recovering)"
  );
  recovered.handle_storage(now, &mut wal, &mut sb); // drain the tail reads → Normal
  assert_eq!(
    recovered.op(),
    OpNumber::with(2),
    "op restored from the WAL head"
  );
  assert_eq!(
    recovered.view(),
    View::new(),
    "view restored from the superblock"
  );
  assert_eq!(recovered.status(), Status::Normal);
  // Recovery is read-only: the durable WAL head is unchanged.
  assert_eq!(
    wal.op_head(),
    OpNumber::with(2),
    "WAL head is intact after recovery"
  );
  // Body restoration itself is asserted end-to-end in `recover_restores_real_bodies`.
}

#[test]
fn recover_restores_real_bodies() {
  // recover() must rebuild REAL bodies from the WAL, not empty placeholders: the SM-apply paths
  // read `entry.body`, so an empty body would silently diverge the recovered replica. Durably
  // append ops 1,2 (bodies [1],[2]) to a backup, crash, recover with an echoing SM, then have
  // the primary announce commit=2 — the recovered backup re-applies both ops from its restored
  // WAL bodies, and the Committed events must carry the ORIGINAL bytes.
  let cfg = || Config::try_new(1, ReplicaId::new(1), 3).expect("valid cluster config");
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  let mut e = Endpoint::new(cfg(), 0, EchoSm);
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  drop(e); // crash

  let mut recovered = Endpoint::recover(cfg(), 0, EchoSm, &mut wal, &mut sb);
  assert_eq!(recovered.status(), Status::Recovering);
  recovered.handle_storage(now, &mut wal, &mut sb); // restore the tail bodies → Normal
  assert_eq!(recovered.status(), Status::Normal);
  recovered.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
  );

  let mut applied = std::vec::Vec::new();
  while let Some(ev) = recovered.poll_event() {
    if let Ok(c) = ev.try_unwrap_committed() {
      applied.push((c.op().get(), c.reply().to_vec()));
    }
  }
  assert_eq!(
    applied,
    std::vec![(1u64, std::vec![1u8]), (2u64, std::vec![2u8])],
    "recovered replica re-applies ops 1,2 with their ORIGINAL restored bodies"
  );
}

#[test]
fn dvc_is_deferred_until_view_is_durable() {
  use crate::StartViewChange;
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let later = Instant::ZERO + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb);
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
  );
  assert_eq!(e.status(), Status::ViewChange);
  assert_eq!(e.view(), View::with(1));
  let mut saw_dvc_before = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.into_msg(), Message::DoViewChange(_)) {
      saw_dvc_before = true;
    }
  }
  assert!(
    !saw_dvc_before,
    "DoViewChange must NOT be sent before the view is durable"
  );
  assert_eq!(
    sb.state().view(),
    View::with(1),
    "new view submitted to the superblock"
  );
  e.handle_storage(later, &mut wal, &mut sb);
  let mut saw_dvc_after = false;
  while let Some(out) = e.poll_message() {
    if let Message::DoViewChange(d) = out.into_msg() {
      assert_eq!(d.view(), View::with(1));
      saw_dvc_after = true;
    }
  }
  assert!(
    saw_dvc_after,
    "DoViewChange is sent once the view is durable"
  );
}

#[test]
fn superseded_view_write_is_ignored() {
  use crate::StartViewChange;
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(3), 5).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let t = Instant::ZERO + core::time::Duration::from_millis(300);
  e.handle_timeout(t, &mut wal, &mut sb);
  e.handle_message(
    t,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  e.handle_message(
    t,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(1))),
  );
  assert_eq!(e.view(), View::with(1));
  while e.poll_message().is_some() {}
  let t2 = t + core::time::Duration::from_millis(600);
  e.handle_timeout(t2, &mut wal, &mut sb);
  e.handle_message(
    t2,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(2), ReplicaId::new(0))),
  );
  e.handle_message(
    t2,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(StartViewChange::new(View::with(2), ReplicaId::new(1))),
  );
  assert_eq!(e.view(), View::with(2));
  while e.poll_message().is_some() {}
  e.handle_storage(t2, &mut wal, &mut sb);
  let mut dvc_views = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::DoViewChange(d) = out.into_msg() {
      dvc_views.push(d.view().get());
    }
  }
  assert!(
    !dvc_views.contains(&1),
    "superseded view-1 DoViewChange must never be sent"
  );
  assert!(
    dvc_views.contains(&2),
    "live view-2 DoViewChange is sent once view 2 is durable"
  );
}

#[test]
fn backup_does_not_prepare_ok_before_start_view_is_durable() {
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(2),
    OpNumber::with(1),
    ReplicaId::new(1),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a")
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b")
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(e.view(), View::with(1));
  assert!(
    e.poll_message().is_none(),
    "backup must NOT PrepareOk before the view is durable"
  );
  assert_eq!(sb.state().view(), View::with(1));
  // codex R6-F1: the re-ack now ALSO waits for op 2's WAL (re-)append (append-before-ack), so it
  // arrives after two sequential storage steps (durable-view → submit append; append → PrepareOk).
  let mut acked_op2 = false;
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb);
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg() {
        if ok.op() == OpNumber::with(2) {
          acked_op2 = true;
        }
      }
    }
    if acked_op2 {
      break;
    }
  }
  assert!(
    acked_op2,
    "held uncommitted ops re-acked once the new view AND their WAL append are durable"
  );
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "op 2 is durable in the WAL before its PrepareOk (R6-F1 append-before-ack)"
  );
}

#[test]
fn reack_suppressed_for_committed_op_not_durably_appended_locally() {
  // codex vopr seed 17 (append-before-ack): the `pop <= self.op` re-ack branch must consult the WAL
  // for durability, NOT just the `appending` set. A view change / catch-up clears `appending` (to
  // keep it in lockstep with `pending`); with an ASYNC WAL an append abandoned in the old generation
  // is still in flight, and once that op is COMMITTED (commit_min advances past it) the view-change
  // re-append range `(commit_min+1 ..= op]` never re-marks it. So `appending` is empty for an op the
  // replica has NOT durably appended — and a retransmitted current-view Prepare(pop) would re-ack it,
  // claiming a durability this replica does not have (it could lose the op on crash). We reproduce
  // that exact divergent state directly: op 5 committed + at the head, but ABSENT from the WAL (a
  // not-yet-durable slot, exactly like an in-flight async append) and not in `appending`.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // view 0 (primary is replica 0, so replica 2 is a backup), op 5 = commit_min (committed + at head),
  // checkpoint_op 0, no repair holes. `appending` is empty (fresh) and the WAL holds nothing — the
  // post-async-view-change divergence where op 5's local append never became durable.
  e.force_state_for_test(
    /*view*/ 0,
    /*op*/ 5,
    /*commit_min*/ 5,
    /*checkpoint_op*/ 0,
    &[],
  );
  assert_eq!(
    wal.status(OpNumber::with(5)),
    SlotStatus::Empty,
    "precondition: op 5 not durable"
  );

  // The primary RETRANSMITS the current-view Prepare(5) (its PREPARE_RETRANSMIT). pop=5 <= self.op=5
  // → the re-ack branch. It must NOT ack: op 5 is not durably appended on THIS replica.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(5, 5));
  let mut premature = 0;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.into_msg() {
      if ok.op() == OpNumber::with(5) {
        premature += 1;
      }
    }
  }
  assert_eq!(
    premature, 0,
    "append-before-ack: must not re-ack op 5 while it is not durably appended locally (pre-fix the \
     `appending`-only guard let this through → premature PrepareOk(5))"
  );

  // Legitimacy check: once op 5 IS durably appended locally, the same retransmitted Prepare(5) DOES
  // re-ack it — the fix suppresses only the non-durable case, preserving lost-PrepareOk recovery.
  let h = Header::new(
    OpNumber::with(5),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(5),
    &[5u8],
  );
  wal.submit_append(
    OpId::new(5),
    OpNumber::with(5),
    h,
    Bytes::copy_from_slice(&[5u8]),
  );
  let _ = wal.poll(); // TestWal is synchronous: op 5 is now durable (Clean).
  assert_eq!(wal.status(OpNumber::with(5)), SlotStatus::Clean);
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(5, 5));
  let mut reacked = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.into_msg() {
      if ok.op() == OpNumber::with(5) {
        reacked = true;
      }
    }
  }
  assert!(
    reacked,
    "a durable committed op is still re-acked on retransmit (legitimate lost-PrepareOk recovery)"
  );
}

#[test]
fn new_prepare_not_acked_while_view_write_pending() {
  // Durable-view completeness: after adopting a StartView the backup is Normal in the new view but
  // the view is not yet durable (pending_sb armed). A new prepare arriving in this window must NOT
  // be acked until the view is durable; the primary retransmits it afterward.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Adopt a StartView for view 1 with op 1 fully committed (no held re-acks to muddy the assertion).
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(1),
    ReplicaId::new(1),
    std::vec![PreparedEntry::new(
      OpNumber::with(1),
      ClientId::new(7),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"a"),
    )],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.status(), Status::Normal);
  let prep2 = || {
    Message::Prepare(Prepare::new(
      View::with(1),
      OpNumber::with(2),
      OpNumber::with(1),
      OpNumber::with(0),
      ClientId::new(7),
      RequestNumber::with(2),
      bytes::Bytes::from_static(b"b"),
    ))
  };
  // A new prepare (op 2) arrives BEFORE the durable-view write is pumped (pending_sb still armed).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    prep2(),
  );
  e.handle_storage(now, &mut wal, &mut sb); // drains the StartView write; would pump op 2 if accepted
  let mut acked_op2 = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.into_msg() {
      if ok.op() == OpNumber::with(2) {
        acked_op2 = true;
      }
    }
  }
  assert!(
    !acked_op2,
    "a new prepare must NOT be acked while the view-change write is pending"
  );
  // Re-deliver (as the primary retransmits) now that the view is durable → it is acked.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    prep2(),
  );
  e.handle_storage(now, &mut wal, &mut sb); // append-before-ack: pump the WAL append
  let mut acked_after = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.into_msg() {
      if ok.op() == OpNumber::with(2) {
        acked_after = true;
      }
    }
  }
  assert!(
    acked_after,
    "once the view is durable, the retransmitted prepare is acked"
  );
}

/// Drive replica 1 to become the NEW PRIMARY of view 1 (via a DVC quorum) over an ASYNC superblock
/// (`StepSb`), leaving it `Normal` with the durable-view write STILL inflight (`pending_sb` armed) —
/// the exact durable-view-before-participate window codex R8-F1 is about. The adopted canonical log
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
    "the durable-view write must still be pending (the R8-F1 window is open)"
  );
  assert!(
    sb.has_inflight(),
    "the superblock view write is inflight (not yet durable)"
  );
  (e, wal, sb)
}

#[test]
fn new_primary_does_not_answer_get_view_while_its_view_write_is_pending() {
  // codex R8-F1 (REGRESSION, durable-view-before-participate, CONSENSUS-CRITICAL). A replica that
  // just became primary of a new view but has not yet PERSISTED that view (the StartView broadcast
  // is deferred to `on_sb_done`) must NOT answer a delayed/duplicate `GetView` with a `StartView`
  // for the not-yet-durable view: on crash it could regress out of a view it had already vouched
  // for, double-participating across views. FAIL-BEFORE: a `StartView` appears in the pending_sb
  // window. PASS-AFTER: silent in the window; the deferred `StartView` fires once the view is
  // durable, and a later `GetView` is then answered.
  let (mut e, mut wal, mut sb) = primed_new_primary_in_pending_view_window();
  let now = Instant::ZERO;
  // A peer solicits the canonical head for view 1 — delivered WHILE the view write is pending.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::GetView(GetView::new(View::with(1), ReplicaId::new(2), 9)),
  );
  let mut sv_in_window = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::StartView(_)) {
      sv_in_window = true;
    }
  }
  assert!(
    !sv_in_window,
    "a primary must NOT hand out a StartView for a view that is not yet durable"
  );
  // Make the view durable: the deferred StartView broadcast fires now (start_view_participate).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(
    !e.pending_sb_for_test(),
    "the view is now durable (pending_sb cleared)"
  );
  let mut sv_after = false;
  while let Some(out) = e.poll_message() {
    if let Message::StartView(s) = out.msg_ref() {
      assert_eq!(s.op(), OpNumber::with(2));
      sv_after = true;
    }
  }
  assert!(
    sv_after,
    "once the view is durable the deferred StartView broadcast fires"
  );
  // And a fresh GetView is now answered (the gate has lifted).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::GetView(GetView::new(View::with(1), ReplicaId::new(2), 10)),
  );
  let mut answered = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::StartView(_)) {
      answered = true;
    }
  }
  assert!(
    answered,
    "after the view is durable, a GetView is answered with a StartView"
  );
}

#[test]
fn new_primary_does_not_answer_recovery_while_its_view_write_is_pending() {
  // codex R8-F1 (REGRESSION): same window, the Recovery-solicitation path. A primary in the
  // pending_sb window must NOT answer a peer's `Recovery` with its canonical `(op, commit, log)` in
  // the not-yet-durable view. FAIL-BEFORE: a `RecoveryResponse` appears in the window. PASS-AFTER:
  // silent in the window; once the view is durable a Recovery is answered normally.
  let (mut e, mut wal, mut sb) = primed_new_primary_in_pending_view_window();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::Recovery(Recovery::new(ReplicaId::new(2), 4242)),
  );
  let mut rr_in_window = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::RecoveryResponse(_)) {
      rr_in_window = true;
    }
  }
  assert!(
    !rr_in_window,
    "a primary must NOT answer a Recovery in a view that is not yet durable"
  );
  // Make the view durable, then a fresh Recovery IS answered (with the canonical head).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {} // discard the deferred StartView broadcast
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::Recovery(Recovery::new(ReplicaId::new(2), 4243)),
  );
  let mut answered = false;
  while let Some(out) = e.poll_message() {
    if let Message::RecoveryResponse(rr) = out.msg_ref() {
      assert_eq!(rr.op(), OpNumber::with(2), "the canonical head op");
      assert_eq!(rr.nonce(), 4243, "the echoed nonce");
      answered = true;
    }
  }
  assert!(
    answered,
    "after the view is durable, a Recovery is answered with a RecoveryResponse"
  );
}

#[test]
fn new_primary_does_not_heartbeat_or_retransmit_while_its_view_write_is_pending() {
  // codex R8-F1 (REGRESSION): the timer path. A primary in the pending_sb window must NOT emit a
  // `Commit` heartbeat nor retransmit `Prepare`s — those assert its authority in a view that is not
  // yet durable. FAIL-BEFORE: a `Commit`/`Prepare` appears when `primary_timeouts` fires in the
  // window. PASS-AFTER: silent in the window; heartbeats resume once the view is durable.
  let (mut e, mut wal, mut sb) = primed_new_primary_in_pending_view_window();
  // Tick the primary TWICE while the view write is still pending: the first tick would BOOTSTRAP the
  // commit/prepare timers (the deferred `start_view_participate` has not armed them yet), the second
  // — well past those deadlines — would FIRE the heartbeat/retransmit if the gate were absent. Both
  // ticks happen entirely inside the pending_sb window (we never flush the superblock between them),
  // exactly the multi-tick window a real driver leaves open. Nothing must be emitted in either.
  let later = Instant::ZERO + core::time::Duration::from_secs(5);
  e.handle_timeout(later, &mut wal, &mut sb);
  let later_fire = later + core::time::Duration::from_secs(1); // >> COMMIT_HEARTBEAT/PREPARE_RETRANSMIT
  e.handle_timeout(later_fire, &mut wal, &mut sb);
  let mut emitted_in_window = false;
  while let Some(out) = e.poll_message() {
    if matches!(
      out.msg_ref(),
      Message::Commit(_) | Message::Prepare(_) | Message::StartView(_)
    ) {
      emitted_in_window = true;
    }
  }
  assert!(
    !emitted_in_window,
    "a primary must not heartbeat/retransmit/StartView in a not-yet-durable view"
  );
  assert!(
    e.pending_sb_for_test(),
    "the ticks must not have force-completed the view write"
  );
  // Once the view is durable, the heartbeat resumes (start_view_participate arms the timers).
  sb.flush();
  e.handle_storage(later_fire, &mut wal, &mut sb);
  while e.poll_message().is_some() {} // discard the deferred StartView
  let later2 = later_fire + core::time::Duration::from_secs(5);
  e.handle_timeout(later2, &mut wal, &mut sb);
  let mut heartbeat_after = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::Commit(_)) {
      heartbeat_after = true;
    }
  }
  assert!(
    heartbeat_after,
    "once the view is durable the primary heartbeats normally"
  );
}

#[test]
fn checkpoint_envelope_round_trips_sessions_and_snapshot() {
  let mut sessions = BTreeMap::new();
  sessions.insert(
    7u128,
    Session {
      request: RequestNumber::with(3),
      reply: Some((RequestNumber::with(3), Bytes::from_static(b"r3"))),
    },
  );
  sessions.insert(
    9u128,
    Session {
      request: RequestNumber::with(1),
      reply: None,
    },
  );
  let snap = Bytes::from_static(b"SM-SNAPSHOT");
  let env = Endpoint::<NoopSm>::encode_checkpoint(OpNumber::with(42), &sessions, &snap);
  let (decoded_op, decoded_sessions, decoded_snap) =
    Endpoint::<NoopSm>::decode_checkpoint(&env).expect("a well-formed envelope decodes");
  assert_eq!(
    decoded_op,
    OpNumber::with(42),
    "the bound checkpoint op round-trips (F3)"
  );
  assert_eq!(decoded_snap, &b"SM-SNAPSHOT"[..]);
  assert_eq!(decoded_sessions.len(), 2);
  assert_eq!(decoded_sessions[&7].request, RequestNumber::with(3));
  assert_eq!(
    decoded_sessions[&7].reply.as_ref().unwrap().1,
    Bytes::from_static(b"r3")
  );
  assert_eq!(decoded_sessions[&9].reply, None);
  // The bound op is part of the content hash: encoding the SAME sessions+snapshot under a DIFFERENT
  // op yields a DIFFERENT checkpoint_id (so an overstated advertised op cannot reuse stale bytes' id).
  let env_other_op = Endpoint::<NoopSm>::encode_checkpoint(OpNumber::with(43), &sessions, &snap);
  assert_ne!(
    crate::checkpoint_id(&env),
    crate::checkpoint_id(&env_other_op),
    "the checkpoint op is bound into the content hash"
  );
  // empty sessions + empty snapshot is a valid envelope (op 0)
  let empty =
    Endpoint::<NoopSm>::encode_checkpoint(OpNumber::new(), &BTreeMap::new(), &Bytes::new());
  let (eop, es, esnap) =
    Endpoint::<NoopSm>::decode_checkpoint(&empty).expect("the empty envelope decodes");
  assert_eq!(eop, OpNumber::new());
  assert!(es.is_empty());
  assert!(esnap.is_empty());

  // A truncated / malformed envelope decodes to None (fault-not-panic), never an out-of-range panic.
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&[]).is_none(),
    "an empty buffer (missing the leading op) is malformed → None"
  );
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&[0, 0, 0, 0, 0, 0, 0]).is_none(),
    "a buffer too short for the 8-byte leading op is malformed → None"
  );
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none(),
    "the op is present but the buffer is too short for the 4-byte session count → None"
  );
  // The op + a count of 1 session but with no session bytes following → None (not a panic).
  let mut count1 = std::vec::Vec::new();
  count1.extend_from_slice(&7u64.to_be_bytes()); // bound op
  count1.extend_from_slice(&1u32.to_be_bytes()); // 1 session, no payload follows
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&count1).is_none(),
    "a count of 1 with no session payload is truncated → None"
  );
  // A reply-length field that overruns the remaining bytes → None (the bounds check on the body).
  let mut overrun = std::vec::Vec::new();
  overrun.extend_from_slice(&7u64.to_be_bytes()); // bound op
  overrun.extend_from_slice(&1u32.to_be_bytes()); // 1 session
  overrun.extend_from_slice(&7u128.to_be_bytes()); // client
  overrun.extend_from_slice(&3u64.to_be_bytes()); // request
  overrun.push(1); // has_reply
  overrun.extend_from_slice(&3u64.to_be_bytes()); // reply request number
  overrun.extend_from_slice(&999u32.to_be_bytes()); // reply len 999 (but no body follows)
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&overrun).is_none(),
    "a reply length that overruns the buffer is malformed → None (no panic)"
  );
}

#[test]
fn recover_restores_a_nonzero_durable_view() {
  // A replica that advanced its view persists it; recover() restores it (no regression to view 0,
  // which would risk a cross-view double-vote). Drive a backup into ViewChange(view 1) so it writes
  // the durable view, pump the write, then crash + recover from the SAME wal/sb.
  use crate::StartViewChange;
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let later = Instant::ZERO + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb); // primary_idle → propose view 1 (own SVC bit)
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
  ); // SVC quorum → ViewChange(view 1) → durable-view write submitted
  e.handle_storage(later, &mut wal, &mut sb); // make the durable-view write complete
  assert_eq!(
    sb.state().view(),
    View::with(1),
    "view 1 is durable before the crash"
  );
  assert_eq!(
    sb.state().log_view(),
    View::new(),
    "the view change did not complete: the durable log_view is still 0 (mid-view-change)"
  );
  drop(e); // crash

  let recovered = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  assert_eq!(
    recovered.view(),
    View::with(1),
    "recover() restores the advanced durable view (no regression to view 0)"
  );
  // The durable root is `view 1 / log_view 0` — the replica crashed MID-VIEW-CHANGE (it had
  // escalated to ViewChange(1) and persisted the view, but never installed a view-1 log). Per the
  // R4-F1 fix (TigerBeetle replica.zig open()), recovery RE-DRIVES the in-progress view change
  // rather than resuming Normal: `log_view < view` → ViewChange at `view` (NOT Normal, which would
  // wrongly resume a never-completed view change). No op was appended (op_head == 0) and there is no
  // checkpoint, so the empty-WAL fast path settles the terminal status directly in recover().
  assert_eq!(
    recovered.status(),
    Status::ViewChange,
    "a mid-view-change recovery re-drives the view change, it does not resume Normal"
  );
}

#[test]
fn primary_checkpoints_after_interval_ops_via_two_superblock_writes() {
  // Single-replica cluster (quorum 1): the primary commits each op as soon as its append is
  // durable. With checkpoint_ops=2, committing op 2 makes commit_min=2 >= checkpoint_op(0)+2 →
  // the checkpoint sequence runs (TWO superblock writes), and checkpoint_op advances to 2 ONLY
  // after BOTH writes are durable. `StepSb` completes writes lazily (`flush` between rounds) so
  // each of the three steps is observed in isolation.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };

  // Commit op 1: not yet at the interval; no checkpoint, nothing inflight on the superblock.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    req(1),
  );
  e.handle_storage(now, &mut wal, &mut sb); // append durable → commit op 1
  assert_eq!(e.commit(), OpNumber::with(1));
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "no checkpoint before the interval"
  );
  assert!(
    !sb.has_inflight(),
    "no superblock write before the interval"
  );

  // Commit op 2: commit_min reaches checkpoint_op(0)+checkpoint_ops(2)=2 → step 1: the snapshot
  // write is submitted (inflight) but NOT yet durable.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    req(2),
  );
  e.handle_storage(now, &mut wal, &mut sb); // append durable → commit op 2 → submit_write_checkpoint
  assert_eq!(e.commit(), OpNumber::with(2));
  assert!(sb.has_inflight(), "step 1: the snapshot write is inflight");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "checkpoint not durable until BOTH sb writes complete"
  );
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(0),
    "the durable root still names the OLD checkpoint after only step 1's submit"
  );

  // Flush step 1 (snapshot durable) → step 2: the VsrState root write is submitted (inflight).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(sb.has_inflight(), "step 2: the root write is inflight");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "still not durable after only the snapshot write completed"
  );

  // Flush step 2 (root durable) → step 3: the checkpoint officially advances in-memory.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(!sb.has_inflight(), "the sequence is complete");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint durable after both writes"
  );
  // The durable root now names the new checkpoint, with a non-zero content id (hash of envelope).
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(2));
  assert_ne!(sb.state().checkpoint_id(), 0);
}

#[test]
fn checkpoint_does_not_double_trigger_while_in_flight() {
  // While a checkpoint's superblock writes are pending, commit_min may keep advancing; a second
  // overlapping checkpoint must NOT start. checkpoint_ops=2: after op 2 triggers a checkpoint,
  // committing ops 3,4 (which also cross a 2-op boundary) must not arm a second checkpoint while
  // the first is in flight — only ONE checkpoint completes, landing at the op it staged (2).
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };

  // Commit ops 1,2 → checkpoint triggers (step 1: snapshot write inflight, NOT durable).
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(e.commit(), OpNumber::with(2));
  assert_eq!(e.checkpoint_op(), OpNumber::with(0));
  assert!(
    sb.has_inflight(),
    "the first checkpoint's snapshot write is inflight"
  );

  // Send requests 3,4 WHILE the first checkpoint's snapshot write is still in flight. The M3.5
  // op-reset DEFENSE (`on_request` short-circuits while `pending_checkpoint.is_some()`) DROPS them —
  // a primary must not assign new ops while a checkpoint-persist is in flight (an op-reuse hazard).
  // So commit stays at 2, and (a fortiori) no second checkpoint is armed.
  for rn in 3..=4 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "requests are dropped while a checkpoint-persist is in flight (the op-reset defense) — commit held at 2"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "the first checkpoint is still in flight"
  );

  // Drive the first (and only) in-flight checkpoint — staged at target_op=2 — to completion by
  // flushing its two writes. It advances checkpoint_op to 2 exactly (no second checkpoint started).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb); // step 1 done → step 2 (root write) inflight
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb); // step 2 done → checkpoint advances to 2
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "exactly one checkpoint completed at its staged op (2), no double-trigger"
  );
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(2));

  // Now the checkpoint is durable (no persist in flight), so the primary serves again. Resending
  // 3,4 commits them; commit_min reaches 4 → the boundary re-evaluates (4 >= checkpoint_op(2)+2) and
  // a SECOND checkpoint triggers at op 4 and completes. This proves the gate only suppressed the
  // OVERLAP, and that the serve-defense releases the moment the persist finishes.
  for rn in 3..=4 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "the primary serves again once the persist is durable (3,4 now commit)"
  );
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb); // snapshot done → root write
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb); // root done → checkpoint advances
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "a fresh checkpoint runs once the prior one is durable (boundary re-evaluated at commit_min=4)"
  );
}

#[test]
fn checkpoint_completes_in_one_drain_with_synchronous_superblock() {
  // The sim's real `InMemorySuperblock` completes ALL queued writes (including ones submitted
  // mid-drain) in a single `handle_storage`. `TestSb` models that. Confirm the whole 3-step
  // sequence completes in the single drain that commits the boundary op — this is the path the
  // sim `Cluster` exercises each tick, so a long-enough sim run checkpoints.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(e.commit(), OpNumber::with(2));
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "synchronous superblock completes both checkpoint writes in the boundary-commit drain"
  );
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(2));
  assert_ne!(sb.state().checkpoint_id(), 0);
}

#[test]
fn checkpoint_gcs_wal_and_maps_below_the_quorum_checkpoint() {
  // M3.4b GC: once a checkpoint is durable, the WAL slots + in-memory caches below the prune floor
  // are freed. Single replica (quorum 1) → quorum_checkpoint_op == self.checkpoint_op, so the floor
  // is the checkpoint op (2): ops <= 2 are pruned from the WAL and the log/inflight caches, while a
  // NEW request still commits (apply reads from commit_min, not from a pruned op).
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb); // append durable → commit; on op 2, checkpoint completes
  }
  assert_eq!(e.checkpoint_op(), OpNumber::with(2));
  // Quorum=1 → prune floor = checkpoint_op = 2 → ops <= 2 are freed from the WAL.
  assert!(
    wal.header(OpNumber::with(1)).is_none(),
    "op 1 pruned from the WAL"
  );
  assert!(
    wal.header(OpNumber::with(2)).is_none(),
    "op 2 pruned from the WAL"
  );
  // The in-memory log + inflight caches are trimmed to (floor .. head] = empty here (head == 2).
  assert_eq!(
    e.min_log_op(),
    None,
    "log cache trimmed entirely below the checkpoint (nothing above op 2 yet)"
  );
  assert_eq!(e.log_len(), 0, "log cache empty after the prune");
  assert_eq!(
    e.inflight_len(),
    0,
    "inflight cache trimmed below the checkpoint"
  );
  // A NEW request still commits (op 3) — the SM applies from commit_min, not from a pruned op.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    req(3),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.commit(),
    OpNumber::with(3),
    "commit continues past the pruned checkpoint"
  );
  assert_eq!(
    e.min_log_op(),
    Some(3),
    "op 3 is cached above the floor; the pruned prefix stays gone"
  );
}

#[test]
fn backup_gcs_below_its_own_checkpoint_even_without_quorum_reports() {
  // A backup never collects PrepareOks, so its `quorum_checkpoint_op` would be 0 (peers default 0)
  // — if GC used the quorum floor on a backup, the backup would never prune and its WAL/log would
  // grow unbounded. M3.4b's asymmetric floor lets a BACKUP prune below its OWN durable checkpoint
  // (those ops are in its snapshot; a laggard below it state-syncs). This test drives a backup
  // (replica 1 of 3) to a durable checkpoint via Prepares + Commits and asserts it pruned.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // The backup has heard from no peers → its quorum_checkpoint_op is 0 (conservative).
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::with(0));
  // Append ops 1,2 via Prepares from the primary (replica 0, view 0), pumping the durable append.
  for op in 1..=2u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::Prepare(Prepare::new(
        View::new(),
        OpNumber::with(op),
        OpNumber::with(op - 1), // commit lags by one so each Prepare also commits the prior op
        OpNumber::new(),        // primary's checkpoint_op (0; irrelevant here)
        ClientId::new(7),
        RequestNumber::with(op),
        Bytes::from(std::vec![op as u8]),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
  }
  // Commit op 2 so the backup's commit_min reaches the boundary and it checkpoints.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.commit(), OpNumber::with(2), "backup committed op 2");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "backup took a durable checkpoint at op 2"
  );
  // The backup's quorum floor is STILL 0: N=3 needs 2 replicas to report a checkpoint, but only
  // self reports 2 (peers default 0) → the quorum-th-highest is 0. This is exactly why a backup
  // cannot use the quorum floor (it would never prune). It pruned below its OWN checkpoint instead.
  assert_eq!(
    e.quorum_checkpoint_op(),
    OpNumber::with(0),
    "the backup's quorum floor is 0 (only self reports a checkpoint) — yet it still pruned"
  );
  assert!(
    wal.header(OpNumber::with(1)).is_none() && wal.header(OpNumber::with(2)).is_none(),
    "a backup prunes its WAL below its own checkpoint (boundedness), no quorum reports needed"
  );
  assert_eq!(
    e.log_len(),
    0,
    "backup log cache trimmed below its own checkpoint"
  );
}

#[test]
fn recover_restores_from_the_durable_checkpoint_not_op_zero() {
  // A single-replica primary commits past a checkpoint (checkpoint_ops=2), so the checkpoint is
  // durable; then it "crashes". recover() MUST restore the SM from the checkpoint snapshot and set
  // commit_min == checkpoint_op (NOT 0) — re-applying [1..=checkpoint_op] would double-apply.
  // (M3.2a never prunes the WAL — Task 5/GC is deferred — so the WAL still holds ops [1..=head];
  //  the log cache is rebuilt for the tail (checkpoint_op..=head] only, the snapshot owns the rest.)
  let cfg = || Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  let mut e = Endpoint::new(cfg(), 0, CountSm::default());
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb); // append durable → commit → (at op 2) checkpoint
  }
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint is durable"
  );
  assert_eq!(
    e.state_machine().applied().len(),
    2,
    "the live SM applied ops 1,2 before the crash"
  );
  drop(e); // crash

  // recover() restores from the checkpoint snapshot, NOT by replaying from op 0. The consensus
  // metadata (commit/checkpoint/op) is set synchronously in Phase 1; the SM snapshot restore
  // happens in the Recovering handle_storage loop (Phase 2), so pump it before the SM asserts.
  let mut recovered = Endpoint::recover(cfg(), 0, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(recovered.status(), Status::Recovering);
  assert_eq!(
    recovered.commit(),
    OpNumber::with(2),
    "commit_min restored to the checkpoint op, not 0"
  );
  assert_eq!(
    recovered.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint_op restored from the durable root"
  );
  assert_eq!(
    recovered.op(),
    OpNumber::with(2),
    "op restored from the WAL head (head >= commit_min == checkpoint_op)"
  );
  // commit_max is restored to checkpoint_op too (monotone bounds: op >= commit_max >= commit_min).
  assert_eq!(recovered.commit_max(), OpNumber::with(2));
  recovered.handle_storage(now, &mut wal, &mut sb); // restore the SM snapshot + tail bodies → Normal
  assert_eq!(recovered.status(), Status::Normal);
  // The SM was restored from the snapshot: it already reflects ops 1,2 (NOT re-applied → exactly 2).
  assert_eq!(
    recovered.state_machine().applied().len(),
    2,
    "SM restored from the checkpoint snapshot (no double-apply)"
  );
  assert_eq!(
    recovered.state_machine().applied(),
    &[(1u64, std::vec![1u8]), (2u64, std::vec![2u8])],
    "the restored SM reflects exactly the checkpointed applied prefix"
  );
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

#[test]
fn recover_rejects_a_mismatched_checkpoint_read_and_retries_then_restores() {
  // SAFETY REGRESSION (recover trusted an unverified checkpoint read): a `CheckpointRead` matching the
  // read id but whose CONTENT does not match the durable root (`sb.state()`) — wrong content hash or
  // wrong op — must be REJECTED (not restored) and retried within the recover budget, exactly like a
  // transient fault. Restoring a stale/corrupt snapshot while `commit_min == checkpoint_op` would be
  // silent committed-prefix loss. Here the FIRST read returns corrupt bytes (hash mismatch), the
  // SECOND returns bytes with the wrong op, and only the THIRD is the genuine snapshot.
  // The SM tail must be a VALID CountSm snapshot (an empty one = 8 zero bytes for the count), so the
  // restore on the genuine read succeeds; the verify logic under test is independent of the payload.
  let good_snap = CountSm::default().snapshot();
  let good_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
  let good_id = crate::checkpoint_id(&good_env);
  // Durable root: checkpoint at op 2, naming the GOOD envelope's content id.
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    good_id,
    std::vec::Vec::new(),
  )
  .unwrap();
  let mut sb = ScriptedCheckpointSb::new(
    state,
    VecDeque::from(std::vec![
      // (1) right op, WRONG bytes (hash mismatch) → rejected.
      (OpNumber::with(2), Bytes::from_static(b"CORRUPT")),
      // (2) right bytes, WRONG op (2 expected) → rejected.
      (OpNumber::with(99), good_env.clone()),
      // (3) the genuine snapshot → accepted.
      (OpNumber::with(2), good_env.clone()),
    ]),
  );
  // An empty WAL with head == checkpoint_op (2): the recover tail range (3..=2) is empty, so the ONLY
  // outstanding read is the checkpoint read — isolating the verify-and-retry behaviour.
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let now = Instant::ZERO;
  let mut e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(e.status(), Status::Recovering);
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "commit_min set to the checkpoint op"
  );

  // Drain #1: the corrupt-bytes read is REJECTED — SM not restored, still Recovering, a new read armed.
  sb.flush(); // release the Phase-1 checkpoint read (the corrupt one)
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.state_machine().applied().len(),
    0,
    "a hash-mismatched read must NOT restore the SM"
  );
  assert_eq!(
    e.status(),
    Status::Recovering,
    "still recovering after rejecting the corrupt read (retry armed)"
  );

  // Drain #2: the wrong-op read is REJECTED too — still no restore, still Recovering.
  sb.flush(); // release the retry read submitted in drain #1 (the wrong-op one)
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.state_machine().applied().len(),
    0,
    "a wrong-op read must NOT restore the SM"
  );
  assert_eq!(
    e.status(),
    Status::Recovering,
    "still recovering after the wrong-op read"
  );

  // Drain #3: the genuine read is accepted → SM restored, recovery completes to Normal.
  sb.flush(); // release the retry read submitted in drain #2 (the genuine one)
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.status(),
    Status::Normal,
    "recovery completes once a VERIFIED checkpoint read lands"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "recovered at the durable checkpoint"
  );
}

#[test]
fn recover_does_not_panic_on_a_truncated_checkpoint_read() {
  // SAFETY: a truncated/malformed snapshot whose bytes pass NEITHER the hash nor parse must be
  // treated as a fault (decode → None), NOT panic recovery. We script a single garbage read followed
  // by the genuine one: the garbage is rejected (no panic, no restore), then recovery completes.
  // The SM tail must be a VALID CountSm snapshot (an empty one = 8 zero bytes for the count), so the
  // restore on the genuine read succeeds; the verify logic under test is independent of the payload.
  let good_snap = CountSm::default().snapshot();
  let good_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
  let good_id = crate::checkpoint_id(&good_env);
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    good_id,
    std::vec::Vec::new(),
  )
  .unwrap();
  let mut sb = ScriptedCheckpointSb::new(
    state,
    VecDeque::from(std::vec![
      // A 2-byte garbage snapshot: too short even for the 8-byte leading op → decode returns None.
      (OpNumber::with(2), Bytes::from_static(&[0xAB, 0xCD])),
      (OpNumber::with(2), good_env.clone()),
    ]),
  );
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let now = Instant::ZERO;
  let mut e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  // Drain #1: the truncated read does NOT panic — it is rejected; still Recovering.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.status(),
    Status::Recovering,
    "a truncated snapshot is a fault (decode None), not a panic"
  );
  assert_eq!(
    e.state_machine().applied().len(),
    0,
    "nothing restored from garbage bytes"
  );
  // Drain #2: the genuine read completes recovery.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.status(),
    Status::Normal,
    "recovery completes on the valid read"
  );
}

#[test]
fn recover_escalates_to_a_peer_fetch_when_its_own_checkpoint_is_permanently_unreadable() {
  // F1 REGRESSION (a permanently-corrupt own checkpoint must NOT panic recovery): when this replica's
  // OWN durable checkpoint snapshot read back unreadable/mismatched on EVERY attempt, the OLD code hit
  // an `assert!` once the per-op retry budget exhausted — crashing the replica on storage-controlled
  // bytes (a faulty/malicious superblock could do this at will). The fix ESCALATES to fetching the
  // checkpoint from a peer via state-sync (a forced sync + a `RequestSync`), staying in a recoverable
  // fault state, and completes recovery once a verified peer `SyncCheckpoint` restores the SM.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
  let now = Instant::ZERO;
  // Durable root: a checkpoint at op 2 naming SOME id. The scripted superblock has an EMPTY read
  // script, so EVERY `submit_read_checkpoint` FAULTS — a permanently-unreadable snapshot.
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    0xDEAD_BEEF,
    std::vec::Vec::new(),
  )
  .unwrap();
  let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new()); // empty → always faults
  // Empty WAL with head == checkpoint_op (2): the tail range is empty, isolating the checkpoint path.
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let mut e = Endpoint::recover(cfg, 5, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(e.status(), Status::Recovering);

  // Drive well past the per-op retry budget (RECOVER_READ_RETRIES). Each round: flush the inflight
  // fault, then drain. The CORE property: this NEVER panics (the old `assert!` is gone).
  for _ in 0..(RECOVER_READ_RETRIES as usize + 4) {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
  }
  // After exhaustion the replica escalated to a peer fetch: still Recovering (SM not yet restored —
  // never silently Normal with a fresh SM at commit_min == 2), awaiting a peer checkpoint, with a
  // FORCED sync armed at our own checkpoint op and a RequestSync emitted.
  assert_eq!(
    e.status(),
    Status::Recovering,
    "a permanently-unreadable own checkpoint does NOT complete recovery (and does NOT panic)"
  );
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "the replica escalated to fetching the checkpoint from a peer"
  );
  assert!(
    e.sync_is_forced_for_test(),
    "a FORCED sync was armed for the peer fetch"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(2),
    "the forced sync targets our own checkpoint op (a peer >= it answers)"
  );
  assert_eq!(
    e.state_machine().applied().len(),
    0,
    "nothing restored from the unreadable snapshot"
  );
  let mut saw_request_sync = false;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSync(_) = out.msg_ref() {
      saw_request_sync = true;
    }
  }
  assert!(
    saw_request_sync,
    "the replica solicited a peer checkpoint (RequestSync)"
  );

  // A peer answers with a VALID SyncCheckpoint (op 2, the genuine snapshot, matching nonce). The
  // recovering replica accepts it (the relaxed guard), restores the SM, durably re-persists, and
  // completes recovery to Normal.
  let good_snap = CountSm::default().snapshot();
  let good_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
  let good_id = crate::checkpoint_id(&good_env);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      ReplicaId::new(0),
      nonce,
      good_env.clone(),
    )),
  );
  // apply_sync staged the durable re-persist (two superblock writes); drive them to completion.
  for _ in 0..3 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "a verified peer SyncCheckpoint completes recovery to Normal"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "recovered at the peer's checkpoint op"
  );
  assert!(
    !e.awaiting_peer_checkpoint_for_test(),
    "the peer-fetch latch is cleared on success"
  );
  assert_eq!(
    e.sync_target_for_test(),
    None,
    "the sync is cleared once the synced checkpoint is durable"
  );
  assert_eq!(
    e.forced_syncs_applied(),
    1,
    "the recovery peer-fetch routed through apply_sync as a FORCED state-sync"
  );
}

#[test]
fn recover_does_not_panic_when_a_mismatched_checkpoint_read_always_faults_then_a_peer_serves() {
  // F1 REGRESSION (variant): the checkpoint read MATCHES our read id but its CONTENT is permanently
  // wrong (hash mismatch on every attempt) — the verify-failure path, not a raw Fault. It must route
  // to the SAME budget→peer-fetch escalation (no panic), then a peer's good SyncCheckpoint completes.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
  let now = Instant::ZERO;
  let good_snap = CountSm::default().snapshot();
  let good_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
  let good_id = crate::checkpoint_id(&good_env);
  // Durable root names the GOOD id at op 2, but every scripted read returns CORRUPT bytes (wrong
  // hash) — a permanently-inconsistent snapshot. Provide many corrupt reads (more than the budget).
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    good_id,
    std::vec::Vec::new(),
  )
  .unwrap();
  let corrupt_reads: VecDeque<(OpNumber, Bytes)> = (0..(RECOVER_READ_RETRIES as usize + 6))
    .map(|_| (OpNumber::with(2), Bytes::from_static(b"CORRUPT")))
    .collect();
  let mut sb = ScriptedCheckpointSb::new(state, corrupt_reads);
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let mut e = Endpoint::recover(cfg, 5, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..(RECOVER_READ_RETRIES as usize + 8) {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb); // must NOT panic on the verify-failure exhaustion
  }
  assert_eq!(
    e.status(),
    Status::Recovering,
    "no panic; escalated to peer fetch"
  );
  assert!(e.awaiting_peer_checkpoint_for_test());
  let nonce = e.sync_nonce_for_test();
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      ReplicaId::new(0),
      nonce,
      good_env.clone(),
    )),
  );
  for _ in 0..3 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "recovery completes once a peer serves the genuine checkpoint"
  );
}

#[test]
fn recover_with_no_checkpoint_is_unchanged() {
  // Backward-compat guard: with checkpoint_op == 0 (no checkpoint yet), recover() behaves EXACTLY
  // as the M3.1b path — commit_min == commit_max == 0, a fresh SM (0 applied), log cache [1..=head].
  let cfg = || Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let mut e = Endpoint::new(cfg(), 0, CountSm::default());
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.checkpoint_op(), OpNumber::with(0), "no checkpoint taken");
  drop(e);

  let mut recovered = Endpoint::recover(cfg(), 0, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(recovered.status(), Status::Recovering);
  recovered.handle_storage(now, &mut wal, &mut sb); // drain the tail reads → Normal
  assert_eq!(recovered.status(), Status::Normal);
  assert_eq!(recovered.op(), OpNumber::with(2), "op from the WAL head");
  assert_eq!(
    recovered.commit(),
    OpNumber::with(0),
    "no checkpoint → commit_min stays 0 (M3.1b behavior)"
  );
  assert_eq!(recovered.commit_max(), OpNumber::with(0));
  assert_eq!(recovered.checkpoint_op(), OpNumber::with(0));
  assert_eq!(
    recovered.state_machine().applied().len(),
    0,
    "no checkpoint → fresh SM, nothing restored/applied"
  );
}

#[test]
fn recover_bounds_the_read_window_for_a_huge_op_head() {
  // F3 REGRESSION (unbounded read submission): a corrupt/buggy `Wal` reporting an enormous
  // `op_head` must NOT make `recover()` bookkeep + submit a read per slot from `checkpoint_op+1`
  // up to that head (billions of inserts/reads/allocations before any async fault-handling runs).
  // With the fix, the per-recover window is capped at `RECOVER_TAIL_WINDOW`, so at most that many
  // reads are submitted regardless of the claimed head. (Before the fix this loops ~u64::MAX times
  // and never returns.)
  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: u64::MAX, // a pathological / bit-rotted head
    done: VecDeque::new(),
  };
  let mut sb = TestSb::default(); // no checkpoint (checkpoint_op == 0) → no checkpoint read
  let e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(e.status(), Status::Recovering);
  // `recover()` submits exactly one read per materialized tail slot, each queued in the WAL's
  // `done` buffer. The count must be bounded by the window, never the claimed head.
  assert!(
    wal.done.len() as u64 <= RECOVER_TAIL_WINDOW,
    "recover submitted {} reads — must be capped at RECOVER_TAIL_WINDOW ({RECOVER_TAIL_WINDOW})",
    wal.done.len()
  );
  assert_eq!(
    wal.done.len() as u64,
    RECOVER_TAIL_WINDOW,
    "with a head far above the window, exactly RECOVER_TAIL_WINDOW slots are materialized"
  );
}

#[test]
fn recover_does_not_overflow_with_a_checkpoint_op_near_u64_max() {
  // F3 REGRESSION (overflow): `checkpoint_op + 1` and `checkpoint_op + RECOVER_TAIL_WINDOW` must use
  // SATURATING arithmetic so a `checkpoint_op` near `u64::MAX` (a corrupt durable root) cannot
  // overflow-panic while computing the tail window. Here the durable root claims a checkpoint at
  // `u64::MAX - 1` and the WAL head equals it, so the tail range is empty — recovery must construct
  // cleanly (no panic) with no tail reads. (The checkpoint READ itself faults — no snapshot — which
  // the budget/peer-fetch path handles; we only assert the constructor does not overflow.)
  let near_max = u64::MAX - 1;
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(near_max),
    OpNumber::with(near_max),
    0,
    std::vec::Vec::new(),
  )
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None, // the checkpoint read will fault (no snapshot) — not under test here
  };
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: near_max, // head == checkpoint_op → empty tail range
    done: VecDeque::new(),
  };
  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  // The CORE assertion is simply that this does not overflow-panic.
  let e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(e.status(), Status::Recovering);
  assert_eq!(
    wal.done.len(),
    0,
    "head == checkpoint_op → the tail range is empty, no tail reads submitted"
  );
}

#[test]
fn recover_op_stays_at_the_verified_frontier_not_the_raw_head() {
  // F1 REGRESSION (a SAFETY regression introduced by the R2 read-window cap): the R2 fix capped the
  // recover READ window at `checkpoint_op + RECOVER_TAIL_WINDOW` but still set `self.op =
  // head.max(checkpoint_op)` (the RAW head). When `head` is far above the window, ops in `(frontier,
  // head]` are "held" per `self.op` yet were NEVER read/verified/cached — so `on_prepare`'s `pop <=
  // self.op` branch would BLIND-RE-ACK them without consulting `self.log`, voting for ops never
  // durably appended (append-before-ack broken → a committed op can be lost if the primary counted
  // that false ack and then died). With the fix `self.op` is the VERIFIED read frontier `hi`, so an
  // op above it is NOT held and a later `Prepare` for it APPENDS (idempotent re-send) before any ack.
  let checkpoint_op = 2u64;
  let frontier = checkpoint_op + RECOVER_TAIL_WINDOW;
  let head = frontier + 1000; // a pathological / bit-rotted head FAR above the read window
  // A CountSm checkpoint at op 2 (applied ops 1,2) + its envelope, with the durable root naming it.
  let mut donor_sm = CountSm::default();
  donor_sm.apply(OpNumber::with(1), &[1]);
  donor_sm.apply(OpNumber::with(2), &[2]);
  let env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(checkpoint_op),
    &BTreeMap::new(),
    &donor_sm.snapshot(),
  );
  let id = crate::checkpoint_id(&env);
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(checkpoint_op),
    OpNumber::with(checkpoint_op),
    id,
    std::vec::Vec::new(),
  )
  .unwrap();
  // A WAL whose head is the pathological value, but which actually HOLDS only the in-window tail
  // `(checkpoint_op ..= frontier]` (reads above the frontier are never submitted). Each tail header is
  // a current-view (view 0) entry so a later Prepare at `frontier+1` is contiguous with the frontier.
  let mut entries = BTreeMap::new();
  for op in (checkpoint_op + 1)..=frontier {
    let h = Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    );
    entries.insert(op, (h, Bytes::from(std::vec![op as u8])));
  }
  let mut wal = TestWal {
    entries,
    head,
    done: VecDeque::new(),
  };
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: Some((OpNumber::with(checkpoint_op), env)),
  };
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, RECOVER_TAIL_WINDOW).unwrap();
  let now = Instant::ZERO;
  let mut e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  // THE core assertion: the recovered head is the VERIFIED read frontier, NOT the raw head.
  assert_eq!(
    e.op(),
    OpNumber::with(frontier),
    "recover holds the verified read frontier, never the raw (pathological) head"
  );
  assert_ne!(e.op(), OpNumber::with(head), "must NOT hold the raw head");
  // Drive the in-window tail reads + the checkpoint read to completion → Normal.
  while e.status() != Status::Normal {
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(
    e.op(),
    OpNumber::with(frontier),
    "frontier preserved into Normal"
  );
  while e.poll_message().is_some() {} // drain everything emitted during recovery

  // A `Prepare` for an op in `(frontier, head]` (here `frontier+1`) must be APPENDED, not blind
  // re-acked: it is `== self.op + 1`, so it takes the append branch. Observable: `self.op` ADVANCES
  // to it (a re-ack would leave op unchanged) and the durable WAL gains the entry; the PrepareOk is
  // DEFERRED to the append completion (no immediate PrepareOk is emitted before the WAL append lands).
  let danger = frontier + 1;
  let p = Prepare::new(
    View::new(),
    OpNumber::with(danger),
    OpNumber::with(frontier), // commit (does not advance past held)
    OpNumber::with(checkpoint_op),
    ClientId::new(7),
    RequestNumber::with(danger),
    Bytes::from(std::vec![0xAB]),
  );
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), Message::Prepare(p));
  assert_eq!(
    e.op(),
    OpNumber::with(danger),
    "a Prepare above the frontier is APPENDED (op advances), not blind-re-acked",
  );
  assert!(
    wal.entries.contains_key(&danger),
    "the durable WAL gained the appended op (append-before-ack honored)",
  );
  // No PrepareOk for `danger` is emitted yet — it is deferred until the WAL append completes (a blind
  // re-ack would have emitted one INLINE, before the op was durable).
  let premature_ack = {
    let mut found = false;
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.msg_ref() {
        if ok.op() == OpNumber::with(danger) {
          found = true;
        }
      }
    }
    found
  };
  assert!(
    !premature_ack,
    "no PrepareOk before the append is durable — the false-re-ack path is closed",
  );
}

#[test]
fn view_change_preserves_the_durable_checkpoint_pointer() {
  // SAFETY REGRESSION GUARD: a view-change durable-view write must NOT regress the durable
  // checkpoint_op to 0 (that would, once the WAL below it is GC'd in Task 5, lose committed ops on
  // recovery). Drive a single-replica primary to a durable checkpoint at op 2, then force a view
  // change (escalate to view 1) and let its durable-view write land; the durable root must still
  // name checkpoint_op=2 with its original id.
  use crate::StartViewChange;
  // N=3 so a view change is reachable, but checkpoint_ops=2 and we commit 2 ops as primary first.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  // Commit 2 ops with a 2-of-3 quorum (replica 1 acks), so commit_min reaches 2 and a checkpoint
  // is taken. The primary's own append + replica 1's PrepareOk = quorum 2.
  for rn in 1..=2 {
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
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb); // drain any checkpoint writes
  }
  assert_eq!(e.commit(), OpNumber::with(2));
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint is durable at op 2"
  );
  let id_before = sb.state().checkpoint_id();
  assert_ne!(id_before, 0);

  // Force a view change: two peers send StartViewChange(view 1) → SVC quorum → ViewChange(1),
  // which submits a durable-view write. Pump it.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(1))),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
  );
  assert_eq!(e.status(), Status::ViewChange);
  e.handle_storage(now, &mut wal, &mut sb); // the durable-view write completes
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(2),
    "the view-change durable-view write must PRESERVE the checkpoint_op (not regress to 0)"
  );
  assert_eq!(
    sb.state().checkpoint_id(),
    id_before,
    "and preserve the matching checkpoint id"
  );
  // The in-memory checkpoint_op is likewise unchanged by the view change.
  assert_eq!(e.checkpoint_op(), OpNumber::with(2));
}

#[test]
fn primary_tracks_quorum_checkpoint_op() {
  // N=3, quorum=2. Primary self.checkpoint_op=0. Backups report checkpoints 5 and 3 via PrepareOk.
  // self(0)=0, r1=5, r2=3 → sorted desc [5,3,0]; the quorum(2)-th highest (index 1) is 3 — the
  // highest op a quorum (2 of 3) has reported checkpointing.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // A fresh primary in Normal view 0 with no peers heard from has quorum_checkpoint_op == 0.
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::new());
  // Quorum-checkpoint tracking is independent of inflight: the ok is recorded for its replica even
  // without a matching inflight op (the replica-id range check is the only guard).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::with(5),
    )),
  );
  // Only one backup heard from: self(0)=0, r1=5, r2=unheard(0) → desc [5,0,0] → index 1 = 0.
  assert_eq!(
    e.quorum_checkpoint_op(),
    OpNumber::new(),
    "one backup is not yet a quorum-checkpoint above 0"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(2),
      OpNumber::with(3),
    )),
  );
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::with(3));
}

#[test]
fn quorum_checkpoint_op_single_replica_is_self() {
  // N=1, quorum=1 → the quorum checkpoint is exactly self's checkpoint (no peers to wait for).
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::new());
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(e.checkpoint_op(), OpNumber::with(2));
  assert_eq!(
    e.quorum_checkpoint_op(),
    OpNumber::with(2),
    "single-replica quorum checkpoint follows self's checkpoint"
  );
}

// ── M3.5 T1: monotone peer_checkpoint ──

#[test]
fn peer_checkpoint_is_monotone_under_reordering() {
  // A primary records a peer's checkpoint_op, then a REORDERED older report arrives. The recorded
  // value must NOT regress — the GC floor + the force-sync trigger that read `quorum_checkpoint_op`
  // all rely on monotone per-peer checkpoints (a regressing floor could un-fire the escalation).
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 1, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary(), "replica 0 is the view-0 primary");
  // A PrepareOk from replica 1 reporting checkpoint_op = 8.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::with(8),
    )),
  );
  assert_eq!(ep.peer_checkpoint_for_test(1), 8);
  // A REORDERED older PrepareOk from replica 1 reporting checkpoint_op = 4 — must NOT regress.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::with(4),
    )),
  );
  assert_eq!(
    ep.peer_checkpoint_for_test(1),
    8,
    "a reordered older report must not regress the recorded peer checkpoint"
  );
}

#[test]
fn on_commit_records_the_primary_checkpoint_monotonically() {
  // The backup-side record path (`on_commit`) is likewise monotone: a reordered older Commit from
  // the primary must not lower the recorded primary checkpoint.
  let mut e = sync_backup(); // replica 1 of 3, primary is replica 0
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(0),
      OpNumber::with(6),
    )),
  );
  assert_eq!(e.peer_checkpoint_for_test(0), 6);
  // A reordered older Commit (checkpoint 2) must not regress the recorded value.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(0),
      OpNumber::with(2),
    )),
  );
  assert_eq!(
    e.peer_checkpoint_for_test(0),
    6,
    "a reordered older Commit must not regress the recorded primary checkpoint"
  );
}

// ── State-sync (M3.4a) ──

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

#[test]
fn stale_checkpoint_commit_triggers_request_sync() {
  // replica 1 of 3, Normal, head op 0, checkpoint 0. A Commit advertising checkpoint_op=8 (> our
  // head) means the cluster checkpointed past our entire WAL → we must state-sync.
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(10),
      OpNumber::with(8),
    )),
  );
  let mut saw = None;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSync(r) = out.msg_ref() {
      saw = Some(*r);
    }
  }
  let r = saw.expect("a stale-checkpoint replica broadcasts RequestSync");
  assert_eq!(
    r.checkpoint_op(),
    OpNumber::with(0),
    "advertises our stale checkpoint"
  );
  assert_eq!(r.replica(), ReplicaId::new(1));
  assert_eq!(
    e.status(),
    Status::Normal,
    "still Normal (sync is in-band, not a status)"
  );
}

#[test]
fn stale_checkpoint_prepare_triggers_request_sync() {
  // A `Prepare` (not just a Commit) carrying checkpoint_op > our head also triggers the sync — the
  // A2 signal closes the last trigger gap for a backup that only ever hears Prepares.
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare_ck(9, 8, 8));
  let mut saw_sync = false;
  while let Some(out) = e.poll_message() {
    saw_sync |= out.msg_ref().is_request_sync();
  }
  assert!(
    saw_sync,
    "a Prepare advertising a far-ahead checkpoint triggers state-sync"
  );
}

#[test]
fn in_reach_checkpoint_does_not_trigger_sync() {
  // checkpoint_op == our head (8) and we hold the tail → ordinary catch-up suffices, NO sync.
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  for op in 1..=8 {
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(op, 0));
    e.handle_storage(now, &mut wal, &mut sb);
  }
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(8),
      OpNumber::with(8),
    )),
  );
  let mut saw_sync = false;
  while let Some(out) = e.poll_message() {
    saw_sync |= out.msg_ref().is_request_sync();
  }
  assert!(!saw_sync, "checkpoint within our held log → no state-sync");
}

#[test]
fn already_syncing_does_not_emit_a_second_handshake_per_heartbeat() {
  // Once a sync is outstanding, a second Commit only RAISES the target — it does not emit a fresh
  // RequestSync per heartbeat (only the timer re-solicits).
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(10),
      OpNumber::with(8),
    )),
  );
  let first: usize = {
    let mut n = 0;
    while let Some(out) = e.poll_message() {
      n += usize::from(out.msg_ref().is_request_sync());
    }
    n
  };
  assert_eq!(first, 1, "the trigger emits exactly one RequestSync");
  // A second heartbeat (even a higher checkpoint) must NOT emit another handshake immediately.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(12),
      OpNumber::with(10),
    )),
  );
  let second: usize = {
    let mut n = 0;
    while let Some(out) = e.poll_message() {
      n += usize::from(out.msg_ref().is_request_sync());
    }
    n
  };
  assert_eq!(
    second, 0,
    "a second heartbeat raises the target but emits no fresh handshake"
  );
}

#[test]
fn primary_answers_request_sync_with_sync_checkpoint() {
  // A donor primary with a durable checkpoint at op 2 answers a lagging replica's RequestSync by
  // shipping a SyncCheckpoint with the right op/id/snapshot/nonce, addressed back to the requester.
  let (mut e, mut wal, mut sb) = donor_primary_at_checkpoint(2);
  let now = Instant::ZERO;
  while e.poll_message().is_some() {} // drain prepares/replies from the warm-up
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      e.view(),
      OpNumber::with(0),
      ReplicaId::new(2),
      0xCAFE,
      false, // ordinary state-sync (not a recovery peer-fetch)
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // the checkpoint read completes → ship SyncCheckpoint
  let mut shipped = None;
  while let Some(out) = e.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      shipped = Some((out.to(), s.clone()));
    }
  }
  let (to, s) = shipped.expect("primary ships a SyncCheckpoint");
  assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(2))));
  assert_eq!(s.checkpoint_op(), OpNumber::with(2));
  assert_eq!(s.checkpoint_id(), sb.state().checkpoint_id());
  assert_eq!(s.nonce(), 0xCAFE);
  assert_eq!(
    crate::checkpoint_id(s.snapshot()),
    s.checkpoint_id(),
    "shipped snapshot provably matches its advertised id"
  );
}

#[test]
fn peer_without_newer_checkpoint_does_not_answer_request_sync() {
  // A replica whose checkpoint == requester's (or 0) ships nothing (no megabyte for a no-op).
  let mut e = sync_backup(); // checkpoint 0
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::RequestSync(crate::RequestSync::new(
      e.view(),
      OpNumber::with(0),
      ReplicaId::new(0),
      1,
      false, // ordinary state-sync (not a recovery peer-fetch)
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(e.poll_message().is_none(), "nothing newer → silent");
}

#[test]
fn recovery_request_sync_is_served_by_a_peer_at_the_same_checkpoint() {
  // F2 REGRESSION (recovery peer-fetch livelock): a recovering replica whose OWN checkpoint snapshot
  // is permanently corrupt solicits a RECOVERY RequestSync advertising its (known) checkpoint_op. The
  // R2 escalation only got served by a STRICTLY-newer peer (`>`), so on an idle cluster where every
  // healthy peer holds EXACTLY the same checkpoint_op, the request was ignored forever → the recovery
  // livelocked (the cluster could stay unavailable if that replica is needed for quorum). With the
  // fix, a `recovery` request is served by a peer at an EQUAL checkpoint_op; an ordinary one is not.
  let now = Instant::ZERO;
  // A donor that is Normal at checkpoint op 2.
  let (mut donor, mut wal, mut sb) = donor_primary_at_checkpoint(2);
  while donor.poll_message().is_some() {} // drain warm-up

  // (a) A RECOVERY request at the SAME checkpoint (op 2) IS served.
  donor.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      donor.view(),
      OpNumber::with(2), // EQUAL to the donor's checkpoint
      ReplicaId::new(2),
      0xF00D,
      true, // recovery peer-fetch
    )),
  );
  donor.handle_storage(now, &mut wal, &mut sb); // checkpoint read completes → ship SyncCheckpoint
  let mut served = None;
  while let Some(out) = donor.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      served = Some((out.to(), s.clone()));
    }
  }
  let (to, s) = served.expect("a recovery request at an EQUAL checkpoint IS served");
  assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(2))));
  assert_eq!(s.checkpoint_op(), OpNumber::with(2));
  assert_eq!(s.nonce(), 0xF00D);

  // (b) An ORDINARY (non-recovery) request at the SAME checkpoint is NOT served (strict `>`).
  donor.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      donor.view(),
      OpNumber::with(2), // EQUAL to the donor's checkpoint
      ReplicaId::new(2),
      0xBEEF,
      false, // ordinary state-sync
    )),
  );
  donor.handle_storage(now, &mut wal, &mut sb);
  let mut ordinary_served = false;
  while let Some(out) = donor.poll_message() {
    if matches!(out.msg_ref(), Message::SyncCheckpoint(_)) {
      ordinary_served = true;
    }
  }
  assert!(
    !ordinary_served,
    "an ordinary RequestSync at an equal checkpoint is NOT served (no megabyte for a no-op)",
  );
}

#[test]
fn recovery_peer_fetch_converges_against_an_equal_checkpoint_peer() {
  // F2 REGRESSION (end-to-end convergence): a replica whose OWN durable checkpoint snapshot is
  // permanently unreadable escalates to a recovery peer-fetch; a Normal peer at the SAME checkpoint
  // op serves it; delivering that SyncCheckpoint converges the recovering replica to Normal. (Before
  // the fix the equal-checkpoint peer ignored the request and the replica never left Recovering.)
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
  let now = Instant::ZERO;
  // Durable root names a checkpoint at op 2; the scripted SB has an EMPTY read script → every
  // checkpoint read FAULTS (permanently-unreadable own snapshot).
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    0xDEAD_BEEF,
    std::vec::Vec::new(),
  )
  .unwrap();
  let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2, // head == checkpoint_op → empty tail; isolates the checkpoint path
    done: VecDeque::new(),
  };
  let mut e = Endpoint::recover(cfg, 5, CountSm::default(), &mut wal, &mut sb);
  // Drive past the per-op retry budget so it escalates to a peer fetch.
  for _ in 0..(RECOVER_READ_RETRIES as usize + 4) {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(e.status(), Status::Recovering);
  assert!(e.awaiting_peer_checkpoint_for_test());
  // The escalation emits a RequestSync flagged `recovery` and advertising our own checkpoint op (2).
  let mut req = None;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSync(r) = out.msg_ref() {
      req = Some(*r);
    }
  }
  let req = req.expect("a RequestSync was solicited");
  assert!(req.recovery(), "the recovery escalation flags the request");
  assert_eq!(
    req.checkpoint_op(),
    OpNumber::with(2),
    "advertises its own checkpoint op"
  );

  // A peer that is Normal at the SAME checkpoint op (2) serves this exact request.
  let (mut peer, mut pwal, mut psb) = donor_primary_at_checkpoint(2);
  while peer.poll_message().is_some() {}
  peer.handle_message(
    now,
    &mut pwal,
    &mut psb,
    Peer::Replica(ReplicaId::new(1)),
    Message::RequestSync(req),
  );
  peer.handle_storage(now, &mut pwal, &mut psb);
  let mut answer = None;
  while let Some(out) = peer.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      answer = Some(s.clone());
    }
  }
  let answer = answer.expect("the equal-checkpoint peer SERVES the recovery request (F2)");

  // Deliver the peer's SyncCheckpoint back to the recovering replica → it applies + re-persists +
  // converges to Normal at the synced point.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(answer),
  );
  e.handle_storage(now, &mut wal, &mut sb); // drive the durable re-persist
  assert_eq!(
    e.status(),
    Status::Normal,
    "the recovering replica converged via the equal-checkpoint peer fetch",
  );
  assert_eq!(e.checkpoint_op(), OpNumber::with(2));
  assert!(
    !e.awaiting_peer_checkpoint_for_test(),
    "no longer awaiting a peer checkpoint"
  );
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

#[test]
fn sync_checkpoint_restores_and_resumes_at_the_synced_point() {
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  // Trigger sync (Commit advertising checkpoint_op=4), capture the nonce it used.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // Deliver the SyncCheckpoint.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      nonce,
      env.clone(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // drive the durable re-persist (TestSb synchronous)
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.commit_max(), OpNumber::with(4));
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(
    e.state_machine().applied().len(),
    4,
    "SM restored from the snapshot, not replayed"
  );
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "synced checkpoint is now durable"
  );
  assert_eq!(sb.state().checkpoint_id(), id);
}

#[test]
fn a_primary_does_not_apply_a_state_sync_it_steps_down_instead() {
  // codex vopr seed 8 (REGRESSION). A `Normal` PRIMARY that receives a valid `SyncCheckpoint` for an
  // outstanding sync must NOT apply it in place (that would reset commit_min to the checkpoint and
  // clear the commit pipeline while it stays primary → a wedge: `try_commit` can never advance past
  // the checkpoint, and a recovered/op-reset primary can REUSE committed op numbers — the seed-52
  // divergence). Instead it STEPS DOWN: flags the deferred forfeit and drops the sync, unchanged. A
  // caught-up replica then leads.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, 1_000).unwrap(); // huge interval: no checkpoint
  let mut e = Endpoint::new(cfg, 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Drive the primary to op 4, commit 4 (no checkpoint — interval is huge).
  for rn in 1..=4u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb); // own append durable → own vote
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
      )),
    );
  }
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.checkpoint_op(), OpNumber::with(0));
  while e.poll_message().is_some() {}
  // A valid checkpoint envelope at op 6 (from a donor), and an outstanding FORCED sync to it.
  let (_d, _dw, dsb) = donor_primary_at_checkpoint(6);
  let (env, id) = donor_envelope(&dsb);
  e.arm_forced_sync_for_test(6);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(6),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  // It must NOT have applied the sync: op/commit/checkpoint unchanged, SM not restored.
  assert_eq!(e.op(), OpNumber::with(4), "op unchanged (no apply)");
  assert_eq!(e.commit(), OpNumber::with(4), "commit unchanged (no apply)");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "checkpoint unchanged (no apply)"
  );
  assert_eq!(
    e.state_machine().applied().len(),
    4,
    "SM still reflects its own 4 applied ops — the peer snapshot was NOT restored"
  );
  // It stepped down instead: the deferred forfeit is flagged and the sync was dropped.
  assert!(
    e.pending_forfeit_for_test(),
    "the primary flagged the deferred forfeit (it abdicates rather than apply a sync)"
  );
  assert_eq!(
    e.sync_target_for_test(),
    None,
    "the sync was dropped (the primary is stepping down, not syncing)"
  );
}

#[test]
fn a_forfeiting_primary_drops_client_requests_no_op_reuse() {
  // codex vopr seed 52 (REGRESSION). A primary that has FLAGGED a forfeit (decided to step down)
  // must NOT assign new ops to client requests: a primary reaches this state after an op-resetting
  // recovery/state-sync left it primary of a view the cluster has moved PAST, so a fresh
  // op-assignment would REUSE a committed op number with DIFFERENT bytes (the stale-primary op-reuse
  // divergence). We reuse the sync-step-down path to arm the forfeit cleanly (NO repair hole and
  // commit_max == commit_min, so the only guard that can drop the request is the `pending_forfeit`
  // one — not the R5-F2 unapplied-prefix guard).
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, 1_000).unwrap();
  let mut e = Endpoint::new(cfg, 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  for rn in 1..=4u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
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
      )),
    );
  }
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.commit_max(), OpNumber::with(4), "no unapplied prefix");
  assert!(!e.has_repair_hole_for_test(3), "no repair hole");
  // Arm the forfeit via the sync-step-down path (primary receiving a valid forced SyncCheckpoint).
  let (_d, _dw, dsb) = donor_primary_at_checkpoint(6);
  let (env, id) = donor_envelope(&dsb);
  e.arm_forced_sync_for_test(6);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(6),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  assert!(
    e.pending_forfeit_for_test(),
    "the primary is now forfeiting"
  );
  while e.poll_message().is_some() {}
  // A fresh client request arrives while the forfeit is pending: it MUST be dropped (no op assigned).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from_static(b"x"),
    )),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(4),
    "a forfeiting primary must NOT assign a new op to a client request (op-reuse guard)"
  );
  let mut saw_prepare = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::Prepare(_)) {
      saw_prepare = true;
    }
  }
  assert!(
    !saw_prepare,
    "a forfeiting primary emits no Prepare for a new request"
  );
}

#[test]
fn sync_checkpoint_with_mismatched_id_is_rejected_not_restored() {
  // A corrupt/forged snapshot whose bytes don't hash to the advertised id MUST NOT be restored.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  let bad_env = Bytes::from_static(b"not the real envelope");
  let advertised = 0xDEAD_BEEF_u128; // != checkpoint_id(bad_env)
  assert_ne!(advertised, crate::checkpoint_id(&bad_env));
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      advertised,
      ReplicaId::new(0),
      nonce,
      bad_env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "rejected: checkpoint not advanced"
  );
  assert_eq!(
    e.state_machine().applied().len(),
    0,
    "rejected: SM untouched"
  );
  // sync stays armed → it re-solicits on the timer.
  assert!(
    e.poll_timeout().is_some(),
    "sync remains armed to re-solicit"
  );
}

#[test]
fn sync_checkpoint_with_op_not_bound_to_the_snapshot_is_rejected_not_restored() {
  // F3 REGRESSION (overstated checkpoint op over stale-but-consistent bytes): a faulty peer ships a
  // snapshot whose REAL frontier is op A=2 but advertises `checkpoint_op = B=4`. The snapshot's bytes
  // hash to the advertised `checkpoint_id` (so the existing integrity gate PASSES — the id is
  // consistent with the OLD bytes), yet B > A. Before binding the op into the hash, the receiver
  // restored the op-2 SM but advanced `commit_min`/`commit_max`/`op` to 4 — SILENTLY DROPPING the
  // committed ops in (A, B] = (2, 4]. With the fix, the op bound INSIDE the envelope (2) is compared
  // to the advertised op (4) and the mismatch REJECTS the snapshot: no restore, no commit advance.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  // Trigger a sync targeting op 4 (the overstated op).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // Build a STALE-BUT-CONSISTENT envelope: a genuine snapshot bound to op A=2, with the matching id.
  let mut stale_sm = CountSm::default();
  stale_sm.apply(OpNumber::with(1), &[1]);
  stale_sm.apply(OpNumber::with(2), &[2]);
  let stale_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    &BTreeMap::new(),
    &stale_sm.snapshot(),
  );
  let real_id = crate::checkpoint_id(&stale_env); // the id IS consistent with these (op-2) bytes
  // Deliver it advertising the OVERSTATED op B=4 but the bytes' REAL id → the hash gate passes, the
  // op-binding gate must reject (bound op 2 != advertised op 4).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4), // OVERSTATED — does not match the op bound (2) inside the snapshot
      real_id,           // matches checkpoint_id(stale_env), so the integrity gate PASSES
      ReplicaId::new(0),
      nonce,
      stale_env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // (no re-persist should have been staged)
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "rejected: checkpoint op not advanced to the overstated value",
  );
  // The APPLIED frontier (`commit_min`) is the safety-critical one: it must NOT advance past the
  // snapshot's real frontier — that is precisely the committed-op drop the binding prevents. (The
  // cluster-wide `commit_max` legitimately becomes 4 from the learned Commit; that is just a watermark
  // we have NOT caught up to, not an applied/durable advance — the replica still lacks ops (2, 4].)
  assert_eq!(
    e.commit(),
    OpNumber::with(0),
    "rejected: applied frontier (commit_min) NOT advanced past the snapshot's real content",
  );
  assert_eq!(
    e.op(),
    OpNumber::with(0),
    "rejected: head not advanced to the overstated op"
  );
  assert_eq!(
    e.state_machine().applied().len(),
    0,
    "rejected: SM untouched (the op-2 snapshot was NOT restored under op 4)",
  );
  assert_eq!(e.state_syncs_applied(), 0, "no state-sync was applied",);
  // sync stays armed → it re-solicits on the timer (another peer answers).
  assert!(
    e.poll_timeout().is_some(),
    "sync remains armed to re-solicit"
  );
}

#[test]
fn stale_nonce_sync_checkpoint_is_ignored() {
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // Deliver a SyncCheckpoint with the WRONG nonce — must be ignored.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      nonce.wrapping_add(1),
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "wrong nonce → ignored"
  );
  assert_eq!(e.state_machine().applied().len(), 0);
}

#[test]
fn sync_checkpoint_below_target_is_ignored() {
  // A SyncCheckpoint whose checkpoint_op does not even reach the target we learned the cluster has
  // committed (an out-of-date peer answering with an OLDER checkpoint) → ignored: it would not
  // advance us past the committed frontier. (Target 6; a reply at op 4 is dropped.)
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let (_d, _dw, dsb) = donor_primary_at_checkpoint(4);
  let (env4, id4) = donor_envelope(&dsb);
  let now = Instant::ZERO;
  // Trigger a sync targeting 6 (the cluster's known checkpoint).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(6),
      OpNumber::with(6),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // A stale peer answers with checkpoint 4 (< target 6): must be ignored.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id4,
      ReplicaId::new(0),
      nonce,
      env4,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "a SyncCheckpoint below the learned target is ignored (would not reach the committed frontier)"
  );
  assert!(
    e.poll_timeout().is_some(),
    "sync stays armed to await a checkpoint >= target"
  );
}

#[test]
fn sync_checkpoint_without_an_outstanding_sync_is_ignored() {
  // A SyncCheckpoint arriving with NO sync outstanding (never triggered, or already applied) is
  // dropped — never an unsolicited restore. This also covers the "duplicate after apply" case (the
  // first apply clears `sync`, so a re-delivery finds no outstanding sync).
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let (_d, _dw, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let now = Instant::ZERO;
  // No trigger fired → sync is None. Deliver a (valid) SyncCheckpoint anyway.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      0xABCD,
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "an unsolicited SyncCheckpoint (no outstanding sync) is ignored"
  );
  assert_eq!(e.state_machine().applied().len(), 0);
}

#[test]
fn lower_sync_checkpoint_is_ignored_after_a_higher_one() {
  // Monotonicity: after syncing to checkpoint 4, a later SyncCheckpoint advertising a LOWER
  // checkpoint must never regress us. (We forge a stale reply at the same nonce/below our point.)
  let (mut e, mut wal, mut sb, env4, id4) = sync_apply_harness(4);
  let (_d2, _dw2, dsb2) = donor_primary_at_checkpoint(2);
  let (env2, id2) = donor_envelope(&dsb2);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id4,
      ReplicaId::new(0),
      nonce,
      env4,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  // A stale lower SyncCheckpoint (op 2) arriving now: sync is already cleared, and even if it
  // weren't, `> self.checkpoint_op` fails. It must be ignored — no regression.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      id2,
      ReplicaId::new(0),
      nonce,
      env2,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "a lower SyncCheckpoint never regresses us"
  );
  assert_eq!(e.commit(), OpNumber::with(4));
}

#[test]
fn sync_checkpoint_clears_a_pending_repair_hole_below_the_synced_point() {
  // A replica with a `repair` hole at op 2 that then syncs a checkpoint at op 5 drops the hole
  // (subsumed by the snapshot) and stops the repair timer.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(6);
  // Use a checkpoint at 6 so it is strictly above the hole at 2 and the head.
  let (env, id) = donor_envelope(&dsb);
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Manufacture a pending-repair hole at op 2 (as the recover loop would).
  e.request_repair(now, 2);
  assert!(e.repair.contains(&2), "hole registered");
  assert!(e.timers.repair_retry.is_some(), "repair timer armed");
  // Trigger + apply a sync to checkpoint 6 (above the hole).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(6),
      OpNumber::with(6),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(6),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.checkpoint_op(), OpNumber::with(6));
  assert!(
    e.repair.is_empty(),
    "the hole below the synced point is subsumed + cleared"
  );
  assert!(e.timers.repair_retry.is_none(), "repair timer stopped");
}

// ── M3.5 T2: force-state-sync escalation ───────────────────────────────────────────────────────

#[test]
fn a_pruned_committed_hole_forces_a_state_sync() {
  // A Normal BACKUP (replica 1 of 3) holds a repair hole at op N=2 with a head ABOVE it (op=4),
  // where a QUORUM has checkpointed past N (so RequestPrepare is futile — the op is pruned on the
  // quorum). It must (a) clear the doomed hole, (b) emit a RequestSync (not just RequestPrepare),
  // (c) record a FORCED sync targeting the quorum checkpoint.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  // Normal-backup state: head op 4, commit held at 1, own checkpoint 0, a committed hole at op 2.
  ep.force_state_for_test(0, 4, 1, 0, &[2]);
  assert!(!ep.is_primary());
  assert!(ep.has_repair_hole_for_test(2), "the hole is registered");
  // Teach it a QUORUM (2 of 3) has checkpointed past N=2: peers 0 and 2 report checkpoint_op = 4.
  // (self reports 0; the 2nd-highest of {0,4,4} = 4 >= N=2 → the hole is snapshot-only.)
  ep.inject_peer_checkpoint_for_test(0, 4);
  ep.inject_peer_checkpoint_for_test(2, 4);
  assert_eq!(
    ep.quorum_checkpoint_op(),
    OpNumber::with(4),
    "the quorum-checkpoint floor is 4 (>= the hole at 2)"
  );
  // Drive a real checkpoint report (a Commit from the primary, replica 0) so the production
  // `on_commit` → `maybe_force_sync` path runs the escalation.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::with(4),
    )),
  );
  // (a) the doomed hole is cleared, and its retry timer stopped.
  assert!(
    !ep.has_repair_hole_for_test(2),
    "the snapshot-only hole at N=2 is cleared"
  );
  assert!(
    ep.timers.repair_retry.is_none(),
    "the futile repair retransmit is stopped"
  );
  // (c) a FORCED sync to the quorum checkpoint (4) is recorded.
  assert_eq!(
    ep.sync_target_for_test(),
    Some(4),
    "the forced sync targets the quorum checkpoint"
  );
  assert!(
    ep.sync_is_forced_for_test(),
    "the sync is marked forced (the assert-relaxation path)"
  );
  // (b) a RequestSync was emitted (not merely a RequestPrepare).
  let mut saw_request_sync = false;
  let mut saw_request_prepare = false;
  while let Some(out) = ep.poll_message() {
    match out.msg_ref() {
      Message::RequestSync(_) => saw_request_sync = true,
      Message::RequestPrepare(_) => saw_request_prepare = true,
      _ => {}
    }
  }
  assert!(
    saw_request_sync,
    "a RequestSync is solicited instead of looping RequestPrepare"
  );
  let _ = saw_request_prepare; // an earlier futile RequestPrepare may have been emitted before the escalation
  // SAFETY: the commit frontier did NOT advance past the hole — it stays at N-1 until the snapshot
  // (>= N) is applied. No committed op is abandoned; it is recovered from the synced snapshot.
  assert_eq!(
    ep.commit(),
    OpNumber::with(1),
    "no commit advances past the hole until the forced snapshot lands"
  );
}

#[test]
fn force_sync_does_not_fire_when_the_op_is_still_peer_repairable() {
  // The escalation must NOT pre-empt the cheap single-op repair when the hole is still IN-REACH —
  // i.e. NO peer has checkpointed past it, so every reporter may still hold it as a servable prepare.
  // Here the only peer report (replica 0) is a checkpoint BELOW the hole (N=4, primary checkpoint=3),
  // so the max-peer floor stays below N → no force-sync.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  // Head op 6, commit held at 3, own checkpoint 0, a committed hole at op 4.
  ep.force_state_for_test(0, 6, 3, 0, &[4]);
  // The primary (replica 0) reports a checkpoint of 3 — BELOW the hole at 4. The max-peer floor is
  // max{self=0, r0=3} = 3 < N=4 → the hole is still in-reach (the primary has NOT pruned op 4, so a
  // RequestPrepare can still be answered) → no force-sync.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::with(3),
    )),
  );
  assert_eq!(
    ep.max_peer_checkpoint_op(),
    OpNumber::with(3),
    "the max-peer floor (3) stays below the hole (4)"
  );
  // The hole is RETAINED (still peer-repairable) and NO sync is armed.
  assert!(
    ep.has_repair_hole_for_test(4),
    "an in-reach hole keeps using ordinary RequestPrepare repair"
  );
  assert_eq!(
    ep.sync_target_for_test(),
    None,
    "no forced sync is armed while no peer has pruned the op (it may still be served)"
  );
  assert!(
    ep.timers.repair_retry.is_some(),
    "the repair retransmit timer stays armed"
  );
}

#[test]
fn force_sync_fires_on_a_backup_that_only_hears_the_primary() {
  // REGRESSION (the backup-visibility bug): a Normal BACKUP only ever records the PRIMARY's
  // checkpoint (PrepareOks flow to the primary, never between backups), so `quorum_checkpoint_op`
  // is structurally pinned at ~0 on a backup. The escalation MUST key on the max single-peer
  // checkpoint instead — otherwise a backup stuck on a pruned committed hole below the cluster
  // checkpoint (head above it) hangs at `commit_min == N-1` forever. Here a SINGLE peer report (the
  // primary's Commit, checkpoint=8) past the hole (N=2) is enough to force the sync.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  // Head op 10 (ABOVE the cluster checkpoint, so the ORDINARY `> self.op` sync stays FALSE — this is
  // the precise force-sync regime), commit held at 1, own checkpoint 0, a committed hole at op 2.
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
  assert!(!ep.is_primary());
  // Only the primary (replica 0) reports — exactly a backup's real visibility. quorum_checkpoint_op
  // is still 0 here (only self + one peer report), proving the OLD quorum-gated trigger could never
  // have fired; the max-peer floor (8) is what rescues it. The primary's checkpoint (8) is BELOW the
  // head (10), so `maybe_request_sync` (`8 > 10`?) does NOT fire — ONLY the forced path can.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::with(8),
    )),
  );
  assert_eq!(
    ep.quorum_checkpoint_op(),
    OpNumber::with(0),
    "the quorum-th floor is 0 on a backup (only the primary reports) — the OLD trigger was dead here"
  );
  assert!(
    !ep.has_repair_hole_for_test(2),
    "the snapshot-only hole is cleared via the max-peer floor (the backup no longer hangs)"
  );
  assert_eq!(
    ep.sync_target_for_test(),
    Some(8),
    "the forced sync targets the primary's reported checkpoint"
  );
  assert!(ep.sync_is_forced_for_test(), "the sync is marked forced");
}

#[test]
fn force_sync_stays_dormant_until_a_quorum_floor_is_known() {
  // Empty repair set, or no quorum-checkpoint floor → the escalation is a no-op (it must never fire
  // spuriously). With a hole but a zero floor (partitioned: no peers heard), it stays dormant.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  // No holes at all → maybe_force_sync is a no-op.
  ep.maybe_force_sync(Instant::ZERO);
  assert_eq!(ep.sync_target_for_test(), None);
  // A hole but no quorum floor (no peer reports) → still dormant.
  ep.force_state_for_test(0, 4, 1, 0, &[2]);
  ep.maybe_force_sync(Instant::ZERO);
  assert!(
    ep.has_repair_hole_for_test(2),
    "the hole survives — no floor means no escalation"
  );
  assert_eq!(
    ep.sync_target_for_test(),
    None,
    "no sync armed without a quorum floor"
  );
}

#[test]
fn forced_sync_preserves_a_held_tail_above_the_checkpoint_without_panic() {
  // SAFETY (VOPR seed 164): a forced sync where checkpoint_op (3) <= self.op (5). The held tail
  // (3..5] is ops this replica already durably appended + ACKED, so the cluster may have COMMITTED
  // them off its vote. The OLD code discarded the tail (rewound the head to 3 + truncated the WAL),
  // destroying its only durable copy while keeping `log_view` — a later view change then took its
  // (log_view, op) as the canonical head and dropped those committed ops, the loss `adopt_canonical_
  // head`'s `op >= commit_min` assert trips on. The forced path must instead apply WITHOUT panic,
  // PRESERVE the above-floor tail (keep op 5 + its log entries), restore the SM at the snapshot, and
  // subsume the doomed hole at 2.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(3);
  let (env, id) = donor_envelope(&dsb);
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 1, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  // A backup holding a tail at op 5, commit at 1, a committed hole at 2, own checkpoint 0. Seed the
  // in-memory tail entries (4, 5) it holds above the synced checkpoint (force_state_for_test leaves
  // the cache empty); these must survive the forced sync.
  ep.force_state_for_test(0, 5, 1, 0, &[2]);
  ep.seed_log_entry_for_test(4);
  ep.seed_log_entry_for_test(5);
  ep.arm_forced_sync_for_test(3); // self.sync = Some { target: 3, forced: true }
  let nonce = ep.sync_nonce_for_test();
  // A valid SyncCheckpoint at op 3 (id matches its bytes) — must apply, not panic.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(3),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  ep.handle_storage(Instant::ZERO, &mut wal, &mut sb); // drive the durable re-persist
  assert_eq!(
    ep.op(),
    OpNumber::with(5),
    "the held tail above the synced checkpoint is PRESERVED — the head is NOT rewound to 3"
  );
  assert!(
    ep.has_log_entry_for_test(4) && ep.has_log_entry_for_test(5),
    "the above-floor tail entries (4, 5) survive the forced sync"
  );
  assert_eq!(
    ep.commit(),
    OpNumber::with(3),
    "the applied frontier advanced to the synced point (past the old hole at 2)"
  );
  assert_eq!(
    ep.checkpoint_op(),
    OpNumber::with(3),
    "synced checkpoint adopted"
  );
  assert!(
    !ep.has_repair_hole_for_test(2),
    "the pruned committed hole at/below the floor is subsumed by the snapshot"
  );
  assert_eq!(
    ep.state_syncs_applied(),
    1,
    "the forced sync routed through apply_sync → the durable re-persist completed"
  );
}

#[test]
fn a_primary_in_the_force_sync_strand_forfeits_instead_of_resetting_op() {
  // SAFETY REGRESSION (op-number reuse → divergence): a PRIMARY that reaches the force-sync strand (a
  // committed-op repair hole at/below `max_peer_checkpoint_op`) must NOT force-sync. Force-sync resets
  // `self.op` to the checkpoint (BELOW the primary's head) and clears the log/inflight; the primary
  // would then assign NEW client requests at REUSED op numbers in the same view, which backups re-ack
  // from their old entries WITHOUT comparing bodies → the primary commits body B while backups applied
  // body A for the same op (committed-state divergence). The fix: the primary flags a deferred forfeit
  // and steps down on its next tick — `self.op` is NEVER rewound, and no forced sync is armed.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary(), "replica 0 at view 0 is the primary");
  // The primary holds a head at op 10 with a committed-op hole at op 2 (commit held at 1 below it).
  // (A recovered primary with a rotted committed slot the cluster long since checkpointed+pruned.)
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
  assert_eq!(ep.op(), OpNumber::with(10));
  // A backup's PrepareOk reports checkpoint_op = 8 — ABOVE the hole at 2, so the hole is snapshot-only
  // on that peer (pruned: RequestPrepare is futile). This drives the production `on_prepare_ok` →
  // `maybe_force_sync` path on the PRIMARY (the exact strand the finding flagged as reachable).
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(2),
      ReplicaId::new(1),
      OpNumber::with(8),
    )),
  );
  assert_eq!(
    ep.max_peer_checkpoint_op(),
    OpNumber::with(8),
    "the peer-checkpoint floor (8) is above the hole (2) → the force-sync strand is entered"
  );
  // The CORE assertion: the primary flagged a deferred forfeit and did NOT touch its op or arm a sync.
  assert!(
    ep.pending_forfeit_for_test(),
    "the primary flags a deferred forfeit instead of force-syncing"
  );
  assert_eq!(
    ep.op(),
    OpNumber::with(10),
    "the primary's op is NOT rewound to the checkpoint (no op-number reuse)"
  );
  assert_eq!(
    ep.sync_target_for_test(),
    None,
    "no forced sync is armed on the primary (it steps down, it does not reset its state)"
  );
  assert!(
    ep.has_repair_hole_for_test(2),
    "the hole is NOT cleared by a force-sync — the primary abdicates rather than subsume it locally"
  );
  // No RequestSync was emitted (a primary never force-syncs).
  let mut saw_request_sync = false;
  while let Some(out) = ep.poll_message() {
    if let Message::RequestSync(_) = out.msg_ref() {
      saw_request_sync = true;
    }
  }
  assert!(
    !saw_request_sync,
    "a primary in the force-sync strand emits NO RequestSync (no self-reset)"
  );
  // The next primary tick ACTS on the flag: it forfeits by proposing the next view (StartViewChange).
  // The flag PERSISTS (F2) — the lone SVC has not yet formed a quorum, so the view has not changed;
  // the latch keeps the primary re-proposing + not heartbeating until it does. The op is unchanged.
  ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
  assert!(
    ep.pending_forfeit_for_test(),
    "the forfeit PERSISTS until the view actually changes (not one-shot — a dropped SVC must not let \
     the primary resume heartbeating and wedge the cluster)"
  );
  assert_eq!(
    ep.op(),
    OpNumber::with(10),
    "op remains unchanged across the forfeit (never reset)"
  );
  let mut saw_svc_view1 = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(svc) = out.into_msg() {
      if svc.view().get() == 1 {
        saw_svc_view1 = true;
      }
    }
  }
  assert!(
    saw_svc_view1,
    "the flagged primary forfeits on its next tick (proposes view 1 via StartViewChange)"
  );
}

#[test]
fn a_primary_in_the_force_sync_strand_never_reuses_an_op_number() {
  // SAFETY (the heart of the finding): the op-reuse divergence happens ONLY if the primary's `op` is
  // REWOUND below its head (force-sync resets it to the checkpoint, then new requests land at the
  // vacated op numbers that backups still hold under old bodies). The forfeit fix guarantees `op` is
  // NEVER rewound. We drive the full strand→forfeit→serve sequence and assert `op` is monotone
  // non-decreasing throughout: a request the (still-Normal, lone-SVC) primary serves lands at a FRESH
  // op ABOVE the old head (11), never at a reused number. Under the OLD force-sync behaviour `op`
  // would have collapsed to the checkpoint floor, and the next request would have reused op 9/10.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
  let head_at_strand = ep.op().get();
  assert_eq!(head_at_strand, 10);
  // Enter the force-sync strand (flag the deferred forfeit) via a peer PrepareOk above the hole.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(2),
      ReplicaId::new(1),
      OpNumber::with(8),
    )),
  );
  assert!(ep.pending_forfeit_for_test());
  assert!(
    ep.op().get() >= head_at_strand,
    "entering the strand did NOT rewind op (no force-sync reset)"
  );
  while ep.poll_message().is_some() {}
  // The forfeit fires on the next tick → the primary proposes view 1 (a lone SVC; view stays 0 until a
  // real SVC quorum forms, so it may still be primary-of-view-0 and serve).
  ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
  assert!(
    ep.op().get() >= head_at_strand,
    "the forfeit did NOT rewind op (it steps down, it does not reset state)"
  );
  while ep.poll_message().is_some() {}
  // A fresh client request: whatever the primary does with it, it must NOT assign it an op number
  // at/below the head it held at the strand (that would be a reuse). If it serves at all, it serves
  // STRICTLY ABOVE the old head.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from(std::vec![42u8]),
    )),
  );
  assert!(
    ep.op().get() >= head_at_strand,
    "op is never rewound across the whole sequence → no op number is ever reused"
  );
  // Any Prepare the primary broadcast for the new request carries an op STRICTLY above the old head —
  // never a reused op number that a backup still holds under a different body.
  while let Some(out) = ep.poll_message() {
    if let Message::Prepare(p) = out.msg_ref() {
      assert!(
        p.op().get() > head_at_strand,
        "a served request lands at a FRESH op (> old head {head_at_strand}), never a reused number"
      );
    }
  }
}

#[test]
fn on_request_is_dropped_while_a_sync_or_checkpoint_persist_is_in_flight() {
  // DEFENSE (Codex): a primary must NOT serve a client while a state-sync OR a checkpoint-persist is
  // in flight — either can reset `self.op` (a sync via `apply_sync`; a checkpoint completion advances
  // checkpoint_op + GCs), so assigning a new request an op now risks op-number reuse. Both an
  // outstanding `sync` and an outstanding `pending_checkpoint` must short-circuit `on_request`.
  let serve = |arm: fn(&mut Endpoint<NoopSm>)| -> bool {
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 7, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(ep.is_primary());
    let head_before = ep.op();
    arm(&mut ep);
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(9)),
      Message::Request(Request::new(
        ClientId::new(9),
        RequestNumber::with(1),
        Bytes::from(std::vec![1u8]),
      )),
    );
    ep.op() != head_before // true ⇒ the request was served (op advanced)
  };
  // With a sync outstanding → dropped (op does not advance).
  assert!(
    !serve(|ep| ep.arm_forced_sync_for_test(0)),
    "a request is dropped while a state-sync is outstanding (op-reset risk)"
  );
  // With a checkpoint-persist staged → dropped.
  assert!(
    !serve(|ep| ep.stage_pending_checkpoint_for_test()),
    "a request is dropped while a checkpoint-persist is in flight (op-reset risk)"
  );
  // Control: a clean primary (nothing in flight) DOES serve the request (op advances) — proving the
  // guard is specific to the in-flight-reset states, not a blanket block.
  assert!(
    serve(|_| {}),
    "a clean primary serves the request (the guard does not over-block)"
  );
}

#[test]
fn on_request_waits_for_the_committed_prefix_to_apply_before_serving_clients() {
  // R5-F2 (at-most-once / sessions-caught-up): a primary must NOT assign a fresh op to a client while
  // its committed prefix is unapplied (`commit_max > commit_min` — a committed op is KNOWN but held by
  // a B4 repair hole). The session/dedup table (`self.clients`) is only updated as ops APPLY, so during
  // the gap a just-committed client request is ABSENT from the table → a retry would be mis-seen as NEW
  // and assigned an op ABOVE the gap → when the hole fills, the apply loop (which has no dedup) would
  // execute BOTH the original AND the duplicate → divergence. The primary must catch up first; the
  // client retries.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 8).unwrap();
  let mut ep = Endpoint::new(cfg, 7, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  // Primary holding a committed-op GAP: head op 4, commit HELD at 1 by a hole at op 2, but commit_max
  // = 4 (ops 2..=4 are known committed cluster-wide, merely unapplied here). Ops 3 + 4 are present in
  // the log; only op 2 is the unreadable hole. (`force_state_for_test` keeps commit_max == commit_min,
  // so raise it directly to model the known-but-unapplied committed suffix.)
  ep.force_state_for_test(0, 4, 1, 0, &[2]);
  ep.commit_max = OpNumber::with(4);
  for op in [3u64, 4u64] {
    ep.log.insert(
      op,
      LogEntry {
        client: ClientId::new(7),
        request: RequestNumber::with(op),
        body: Bytes::copy_from_slice(&[op as u8]),
      },
    );
  }
  assert!(ep.is_primary());
  assert!(
    ep.commit_max().get() > ep.commit().get(),
    "precondition: a committed op is known but not yet applied (commit_max > commit_min)"
  );
  let head_before = ep.op();

  // A FRESH client request (client 9, request 1) arrives DURING the gap → must be DROPPED: no Prepare,
  // no Reply, and the head op does NOT advance (no fresh op assigned that could later double-execute).
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from(std::vec![1u8]),
    )),
  );
  assert_eq!(
    ep.op(),
    head_before,
    "no fresh op is assigned while the committed prefix is unapplied (sessions stale)"
  );
  assert!(
    ep.poll_message().is_none(),
    "no Prepare and no Reply is emitted during the committed gap"
  );

  // Close the gap: the hole at op 2 is filled (a vouching repair Prepare, commit >= op), so
  // `advance_commit` applies ops 2,3,4 in order → commit_min catches up to commit_max == 4, and the
  // repair set empties.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 4),
  );
  assert_eq!(
    ep.commit(),
    OpNumber::with(4),
    "the gap closed: the committed prefix is fully applied (commit_min == commit_max)"
  );
  assert!(
    !ep.has_repair_hole_for_test(2),
    "the repair hole is cleared once the committed value fills it"
  );
  while ep.poll_message().is_some() {} // discard catch-up output (Committed/etc.)

  // Now the SAME fresh request IS served — the primary assigns it a fresh op and broadcasts a Prepare.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from(std::vec![1u8]),
    )),
  );
  assert!(
    ep.op().get() > head_before.get(),
    "once the committed prefix is applied, the primary serves the request (op advances)"
  );
  let mut saw_prepare = false;
  while let Some(out) = ep.poll_message() {
    if let Message::Prepare(p) = out.msg_ref() {
      assert!(
        p.op().get() > 4,
        "the served request lands at a fresh op above the (now-applied) committed prefix"
      );
      saw_prepare = true;
    }
  }
  assert!(
    saw_prepare,
    "the primary broadcasts a Prepare for the request once it has caught up"
  );
}

// ── M3.5 T3: forfeit — a lagging primary steps down via a view change ───────────────────────────

#[test]
fn a_lagging_primary_forfeits_after_the_grace_period() {
  // Primary (replica 0 of 3), checkpoint_ops=4 ⇒ forfeit lag bound = 4. A quorum reports
  // checkpoint_op = 8 while the primary's own checkpoint_op stays 0 (it is stuck — repairing/
  // syncing while the cluster raced ahead). After the grace period the primary must FORFEIT by
  // PROPOSING a view change (broadcast StartViewChange for view 1) via the SVC machinery — NOT a
  // unilateral view jump (it stays in its own view until a real SVC quorum forms).
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 1, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary());
  // Two peers report checkpoint_op = 8 (a quorum of 2-of-3 incl. neither self) → the primary's
  // own checkpoint (0) lags the quorum checkpoint (8) by 8 >= the bound 4.
  ep.inject_peer_checkpoint_for_test(1, 8);
  ep.inject_peer_checkpoint_for_test(2, 8);
  assert_eq!(
    ep.quorum_checkpoint_op(),
    OpNumber::with(8),
    "the quorum-checkpoint floor is 8, a full interval beyond the primary's 0"
  );
  // First primary timeout ARMS the grace timer but does NOT forfeit yet (anti-storm: a transient
  // lag must persist for the grace window before the primary steps down).
  ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
  assert!(
    ep.forfeit_armed_for_test(),
    "the lagging primary armed the forfeit grace timer"
  );
  assert_eq!(
    ep.view().get(),
    0,
    "no forfeit before the grace period elapses (no SVC yet)"
  );
  let mut saw_svc_before_grace = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(svc) = out.into_msg() {
      if svc.view().get() == 1 {
        saw_svc_before_grace = true;
      }
    }
  }
  assert!(
    !saw_svc_before_grace,
    "the primary must NOT propose a view change before the grace period elapses"
  );
  // Advance past the grace period (300ms) and tick again → forfeit: it proposes view 1 (SVC).
  let later = Instant::ZERO + core::time::Duration::from_millis(400);
  ep.handle_timeout(later, &mut wal, &mut sb);
  let mut saw_svc_view1 = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(svc) = out.into_msg() {
      if svc.view().get() == 1 {
        saw_svc_view1 = true;
      }
    }
  }
  assert!(
    saw_svc_view1,
    "a stuck primary forfeits by PROPOSING the next view (StartViewChange for view 1), not a unilateral jump"
  );
  assert!(
    !ep.forfeit_armed_for_test(),
    "the grace timer is disarmed once the forfeit fires (no same-view re-forfeit)"
  );
}

#[test]
fn a_healthy_primary_never_forfeits() {
  // The primary keeps pace: its own checkpoint advances in step with the quorum's. The forfeit
  // condition (lag >= a full checkpoint interval) is never satisfied, so the grace timer never
  // arms and no view change is ever proposed — the anti-storm guarantee in steady state.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 1, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary());
  ep.set_own_checkpoint_for_test(8); // the primary's own checkpoint is current
  ep.inject_peer_checkpoint_for_test(1, 8);
  ep.inject_peer_checkpoint_for_test(2, 8); // quorum checkpoint 8 == own 8 → lag 0 < bound 4
  for ms in [0u64, 400, 800] {
    ep.handle_timeout(
      Instant::ZERO + core::time::Duration::from_millis(ms),
      &mut wal,
      &mut sb,
    );
    assert!(
      !ep.forfeit_armed_for_test(),
      "forfeit grace is never armed for a healthy primary (ms={ms})"
    );
  }
  assert_eq!(ep.view().get(), 0, "a healthy primary never forfeits");
  let mut saw_svc = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(_) = out.into_msg() {
      saw_svc = true;
    }
  }
  assert!(
    !saw_svc,
    "a healthy primary never proposes a forfeit-driven view change"
  );
}

#[test]
fn a_backup_never_forfeits_even_when_behind() {
  // A BACKUP (replica 1) far behind the quorum checkpoint must NOT forfeit — forfeit is a PRIMARY
  // stepping aside; a behind backup catches up via state-sync/force-sync. The forfeit check lives
  // only on the primary path (primary_timeouts), so the backup never arms it.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 1, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(!ep.is_primary());
  ep.inject_peer_checkpoint_for_test(0, 8);
  ep.inject_peer_checkpoint_for_test(2, 8);
  for ms in [0u64, 400, 800] {
    ep.handle_timeout(
      Instant::ZERO + core::time::Duration::from_millis(ms),
      &mut wal,
      &mut sb,
    );
  }
  assert!(
    !ep.forfeit_armed_for_test(),
    "a backup never arms forfeit (forfeit is exclusively a primary stepping aside)"
  );
}

#[test]
fn a_transiently_lagging_primary_recovers_and_disarms_without_forfeiting() {
  // Anti-storm: a primary that briefly lags (arming the grace timer) but CATCHES UP before the
  // grace elapses must DISARM and never forfeit. Models a primary that was momentarily behind on
  // checkpoint, then checkpointed in step with the cluster within the grace window.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 1, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary());
  ep.inject_peer_checkpoint_for_test(1, 8);
  ep.inject_peer_checkpoint_for_test(2, 8); // quorum 8, own 0 → lag 8 >= 4 → arms
  ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
  assert!(ep.forfeit_armed_for_test(), "the lag armed the grace timer");
  // The primary catches its own checkpoint up to the quorum BEFORE the grace elapses.
  ep.set_own_checkpoint_for_test(8); // lag now 0 < bound 4
  let mid = Instant::ZERO + core::time::Duration::from_millis(100); // still within the 300ms grace
  ep.handle_timeout(mid, &mut wal, &mut sb);
  assert!(
    !ep.forfeit_armed_for_test(),
    "catching up disarms the grace timer (the transient lag does not forfeit)"
  );
  // Even well past the original grace deadline, no forfeit fires.
  let later = Instant::ZERO + core::time::Duration::from_millis(400);
  ep.handle_timeout(later, &mut wal, &mut sb);
  assert_eq!(
    ep.view().get(),
    0,
    "a primary that caught up never forfeits"
  );
  let mut saw_svc = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(_) = out.into_msg() {
      saw_svc = true;
    }
  }
  assert!(!saw_svc, "no forfeit-driven view change after catch-up");
}

#[test]
fn a_primary_stuck_on_an_unfillable_committed_hole_forfeits_after_the_grace_period() {
  // LIVENESS REGRESSION (VOPR seed 36): a new primary can adopt a canonical head with a COMMITTED
  // interior hole the offset-union could not carry (a committed op a holder checkpointed + pruned
  // past, so it lives only inside a peer's checkpoint snapshot — unservable via `RequestPrepare`).
  // Such a primary is stuck: its commit is HELD below the hole, it cannot serve clients, it cannot
  // fill the hole (no peer can answer), and — holding none of the band above its commit — it
  // retransmits nothing, so backups never ack and no reactive check re-fires. It must FORFEIT so a
  // caught-up replica (the checkpoint holder) leads. Here: primary (replica 0 of 3), commit held at
  // 1 with a committed `repair` hole at op 2 that NO peer answers; after the grace window it must
  // forfeit by PROPOSING view 1 (StartViewChange) — even though its checkpoint does NOT lag (the
  // OTHER forfeit condition is off), so this isolates the unfillable-hole trigger.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 1, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary());
  // Head 10, commit 1, a committed hole at op 2, own checkpoint 8 == quorum (no checkpoint-lag).
  ep.force_state_for_test(0, 10, 1, 8, &[2]);
  ep.set_own_checkpoint_for_test(8);
  ep.inject_peer_checkpoint_for_test(1, 8);
  ep.inject_peer_checkpoint_for_test(2, 8); // quorum 8 == own 8 → lag 0 (the lag trigger is OFF)
  // First primary tick ARMS the grace timer (the hole is outstanding) but does NOT forfeit yet.
  ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
  assert!(
    ep.forfeit_armed_for_test(),
    "an outstanding committed repair hole arms the forfeit grace timer"
  );
  assert_eq!(ep.view().get(), 0, "no forfeit before the grace elapses");
  while ep.poll_message().is_some() {}
  // Past the grace window, with the hole STILL unfilled (no peer answered) → forfeit (propose view 1).
  let later = Instant::ZERO + core::time::Duration::from_millis(400);
  ep.handle_timeout(later, &mut wal, &mut sb);
  let mut saw_svc_view1 = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(svc) = out.into_msg() {
      if svc.view().get() == 1 {
        saw_svc_view1 = true;
      }
    }
  }
  assert!(
    saw_svc_view1,
    "a primary stuck on an unfillable committed hole forfeits (proposes view 1) after the grace window"
  );
}

#[test]
fn a_primary_whose_committed_hole_fills_within_grace_does_not_forfeit() {
  // ANTI-STORM complement of the above: a committed repair hole that a peer CAN serve is filled by
  // the answering `Prepare` well within the grace window, emptying `repair` and DISARMING the
  // forfeit — so a FILLABLE hole (the ordinary B4 repair case) never triggers a view change. Primary
  // (replica 0 of 3), commit held at 1 with a hole at op 2; a peer answers with op 2's
  // committed-vouching Prepare (commit 2 >= op 2) before the grace elapses.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 1, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary());
  // Head 2, commit 1, a committed hole at op 2, own checkpoint 0 (no checkpoint-lag peers injected).
  ep.force_state_for_test(0, 2, 1, 0, &[2]);
  // First tick arms the grace timer (the hole is outstanding).
  ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
  assert!(
    ep.forfeit_armed_for_test(),
    "the outstanding committed hole arms the grace timer"
  );
  while ep.poll_message().is_some() {}
  // A peer answers our RequestPrepare with op 2's committed-vouching Prepare → fills the hole.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );
  assert!(
    !ep.has_repair_hole_for_test(2),
    "the committed-vouching Prepare fills the hole"
  );
  // Next tick within the grace window: the hole is gone → the grace timer DISARMS, no forfeit.
  let mid = Instant::ZERO + core::time::Duration::from_millis(100);
  ep.handle_timeout(mid, &mut wal, &mut sb);
  assert!(
    !ep.forfeit_armed_for_test(),
    "filling the hole disarms the grace timer (a fillable hole does not forfeit)"
  );
  let later = Instant::ZERO + core::time::Duration::from_millis(400);
  ep.handle_timeout(later, &mut wal, &mut sb);
  let mut saw_svc = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(_) = out.into_msg() {
      saw_svc = true;
    }
  }
  assert!(
    !saw_svc && ep.view().get() == 0,
    "a primary whose committed hole filled in time never forfeits"
  );
}

#[test]
fn a_forfeiting_primary_keeps_proposing_and_stops_heartbeating_until_the_view_changes() {
  // F2 REGRESSION (a one-shot forfeit can be LOST → the cluster wedges): when the FIRST forfeit
  // StartViewChange is dropped/partitioned, the OLD code cleared `pending_forfeit` one-shot and the
  // primary RESUMED heartbeating — so every backup kept resetting its `primary_idle` (none started
  // its own VC) and the SVC retransmit timer was never serviced while Normal, wedging the cluster
  // below the unrepairable hole. The fix keeps forfeiting until the view actually changes: each
  // primary tick RE-PROPOSES view+1 AND skips the commit heartbeat + prepare retransmit, so backups
  // stop hearing the primary and join the SVC. Here we DROP every emitted SVC and tick repeatedly:
  // the primary must (a) re-broadcast the SVC each tick, (b) NEVER emit a Commit heartbeat, and
  // (c) keep `pending_forfeit` latched — none of which the one-shot code did.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary(), "replica 0 at view 0 is the primary");
  // Enter the force-sync strand → the primary flags a deferred forfeit (a committed hole at op 2 a
  // peer has already checkpointed+pruned past).
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(2),
      ReplicaId::new(1),
      OpNumber::with(8),
    )),
  );
  assert!(
    ep.pending_forfeit_for_test(),
    "the strand flagged a deferred forfeit"
  );
  while ep.poll_message().is_some() {} // discard anything emitted on entry

  // Tick the primary repeatedly at advancing times, DROPPING every emitted message (the SVC is
  // partitioned away). Across EVERY tick: an SVC for view 1 is re-proposed, and NO Commit heartbeat
  // is ever emitted. The view never changes (the lone SVC forms no quorum), and the flag persists.
  for i in 0..5u64 {
    let now = Instant::ZERO + core::time::Duration::from_millis(100 * (i + 1));
    ep.handle_timeout(now, &mut wal, &mut sb);
    let mut saw_svc_view1 = false;
    let mut saw_commit_heartbeat = false;
    while let Some(out) = ep.poll_message() {
      match out.into_msg() {
        Message::StartViewChange(svc) if svc.view().get() == 1 => saw_svc_view1 = true,
        Message::Commit(_) => saw_commit_heartbeat = true,
        _ => {}
      }
    }
    assert!(
      saw_svc_view1,
      "tick {i}: the forfeiting primary RE-PROPOSES view 1 each tick (idempotent re-broadcast under loss)"
    );
    assert!(
      !saw_commit_heartbeat,
      "tick {i}: the forfeiting primary must NOT heartbeat (so backups idle-out and join the SVC) — \
       the one-shot code resumed heartbeating here and wedged the cluster"
    );
    assert_eq!(
      ep.view().get(),
      0,
      "tick {i}: view unchanged while the lone SVC forms no quorum"
    );
    assert!(
      ep.pending_forfeit_for_test(),
      "tick {i}: the forfeit latch PERSISTS until the view actually changes"
    );
  }

  // Now a backup's StartViewChange for view 1 ARRIVES → with the primary's own bit, an SVC quorum
  // (2-of-3) forms → the view changes. Leaving Normal-primary CLEARS the latch (the new generation
  // re-evaluates from scratch), so the cluster is unwedged.
  let now = Instant::ZERO + core::time::Duration::from_millis(700);
  ep.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(1),
    )),
  );
  assert_eq!(
    ep.view().get(),
    1,
    "an SVC quorum (primary + one backup) forms → the view changes (the cluster is NOT wedged)"
  );
  assert!(
    ep.status().is_view_change(),
    "the primary transitioned into the view change for view 1"
  );
  assert!(
    !ep.pending_forfeit_for_test(),
    "leaving Normal-primary clears the forfeit latch (no cross-view leak)"
  );
}

#[test]
fn recover_after_state_sync_restores_the_synced_checkpoint() {
  // Durability-before-resume: after a sync goes durable, a crash + recover() must come back at the
  // synced checkpoint (the durable root names it), not the stale one.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
  drop(e); // crash
  // Recover from the same wal/sb: the synced checkpoint is the durable root.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
  let mut recovered = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(
    recovered.checkpoint_op(),
    OpNumber::with(4),
    "recovered at the synced checkpoint"
  );
  assert_eq!(recovered.commit(), OpNumber::with(4));
  assert_eq!(
    recovered.op(),
    OpNumber::with(4),
    "op >= commit_min must hold after recover (the synced head, not a sub-checkpoint WAL head)"
  );
  recovered.handle_storage(now, &mut wal, &mut sb); // restore SM from the synced snapshot → Normal
  assert_eq!(recovered.status(), Status::Normal);
  assert_eq!(
    recovered.state_machine().applied().len(),
    4,
    "recovered SM reflects the synced checkpoint prefix"
  );
}

// ── State-sync (M3.4a) — A6: view-change / B3-interaction safety (regression guards) ──

#[test]
fn synced_replica_reports_its_checkpoint_in_view_change() {
  // After syncing to checkpoint 4, force the replica into a view change and inspect its DVC: it must
  // report commit == 4 (the synced point) with log_view <= view and a tail that does NOT start at
  // op 1 — exactly the recover-from-checkpoint shape (this is the B3 interaction; no B3 code here).
  // Use replica 2 of 3 as the laggard: in view 1 the primary is replica 1 (not itself), so it sends
  // a DoViewChange we can capture (a replica that is itself the next primary would form the
  // canonical log directly instead of sending a DVC).
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let mut e = Endpoint::new(
    Config::with_checkpoint_ops(1, ReplicaId::new(2), 3, 2).unwrap(),
    0,
    CountSm::default(),
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = {
    let mut nonce = None;
    while let Some(out) = e.poll_message() {
      if let Message::RequestSync(r) = out.msg_ref() {
        nonce = Some(r.nonce());
      }
    }
    nonce.expect("a RequestSync was emitted")
  };
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.status(), Status::Normal);
  while e.poll_message().is_some() {}

  // Force a view change to view 1 (primary = replica 1): replica 2 proposes view 1 on idle, a peer
  // SVC completes the quorum → ViewChange(1) → it sends a DoViewChange to replica 1.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb); // primary_idle → propose view 1 (own bit)
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  assert_eq!(e.status(), Status::ViewChange);
  assert_eq!(e.view(), View::with(1));
  e.handle_storage(later, &mut wal, &mut sb); // durable-view write completes → DVC is sent
  let mut dvc = None;
  while let Some(out) = e.poll_message() {
    if let Message::DoViewChange(d) = out.msg_ref() {
      dvc = Some(d.clone());
    }
  }
  let dvc = dvc.expect("a synced backup sends a DoViewChange");
  assert_eq!(
    dvc.commit(),
    OpNumber::with(4),
    "reports the synced checkpoint as commit, not a sparse log"
  );
  assert_eq!(
    dvc.op(),
    OpNumber::with(4),
    "head is the synced point (tail-empty)"
  );
  assert!(dvc.log_view().get() <= dvc.view().get(), "log_view <= view");
  // The carried log is the (empty) tail above the checkpoint — it does NOT fabricate ops [1..=4].
  assert!(
    dvc.log_slice().iter().all(|e| e.op().get() > 4),
    "the DVC log is the tail above the synced checkpoint (no fabricated sub-checkpoint ops)"
  );
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

#[test]
fn canonical_selection_with_a_checkpoint_offset_log_is_safe() {
  // A canonical generation where one DVC's log starts above op 1 (its donor was state-synced to
  // checkpoint 4, commit 4) must not be mis-truncated, and the commit* <= op_head fail-stop must not
  // trip for a synced participant (its commit == op_head == checkpoint when tail-empty).
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
  // r0: a full-from-1 log (head 5, commit 4). r1: the SAME generation but state-synced — its log
  // starts at op 5 (checkpoint 4), head 5, commit 4. Same log_view → both canonical.
  e.dvc_from.insert(0, dvc(0, 1, 5, 4));
  e.dvc_from.insert(1, dvc_offset(1, 1, 4, 5, 4));
  let (log, op_head, commit_star) = e.select_canonical_log();
  assert_eq!(
    op_head, 5,
    "the offset log does not shorten the canonical head"
  );
  assert_eq!(commit_star, 4, "commit* preserved");
  assert!(
    commit_star <= op_head,
    "the fail-stop invariant holds for an offset-log participant"
  );
  // The UNION covers [1..=5]: r0 supplies the prefix the offset r1 omits, so no op is dropped.
  let present: std::collections::BTreeSet<u64> = log.iter().map(|e| e.op().get()).collect();
  assert_eq!(
    present,
    (1..=5u64).collect::<std::collections::BTreeSet<u64>>(),
    "the union of r0's full log and r1's offset log covers ops 1..=5"
  );
}

#[test]
fn view_change_abandons_an_outstanding_sync() {
  // State-sync and view change are mutually exclusive by status: a higher-view message arriving
  // while a sync is outstanding takes the replica into ViewChange and clears the stale sync (so the
  // sync_solicit timer does not linger). The replica re-triggers state-sync from Normal if still
  // behind.
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Trigger a sync (in view 0).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(8),
      OpNumber::with(8),
    )),
  );
  while e.poll_message().is_some() {}
  assert!(e.poll_timeout().is_some(), "sync armed");
  // A higher-view Commit arrives → catch_up_to_view → ViewChange, which must clear the sync.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::Commit(Commit::new(
      View::with(1),
      OpNumber::with(8),
      OpNumber::with(8),
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  assert!(
    e.sync.is_none(),
    "the outstanding sync is abandoned on entering a view change"
  );
  assert!(
    e.timers.sync_solicit.is_none(),
    "the sync solicit timer is cleared"
  );
}

#[test]
fn canonical_selection_with_a_fully_checkpoint_synced_participant_is_safe() {
  // The extreme: a state-synced participant whose tail is EMPTY (head == commit == checkpoint 4, no
  // log entries at all). select_canonical_log must handle commit == op_head with an empty offset log
  // without panicking or fabricating ops.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
  e.dvc_from.insert(0, dvc(0, 1, 5, 4));
  e.dvc_from.insert(1, dvc_offset(1, 1, 4, 4, 4)); // tail-empty synced participant
  let (_log, op_head, commit_star) = e.select_canonical_log();
  assert_eq!(op_head, 5);
  assert_eq!(commit_star, 4);
  assert!(commit_star <= op_head);
}

// ── B3: offset-aware canonical-log selection (UNION committed entries across DVCs) ──

#[test]
fn select_canonical_log_unions_committed_ops_across_different_floor_dvcs() {
  // The reviewer's reproduction (the heart of B3): TWO different-floor offset DVCs in the SAME
  // canonical generation, both head op 10 commit 8. r0 (floor 4) holds ops 5..=10; r1 (floor 8) holds
  // only 9,10. Both tie at op 10, so the OLD `max_by_key(op)` (ties → highest replica id) picks r1's
  // log [9,10] and SILENTLY DROPS committed ops 5,6,7 — which only r0 holds. The `commit* <= op_head`
  // fail-stop does NOT trip (the dropped ops are interior). select_canonical_log MUST instead UNION:
  // the returned canonical log must cover EVERY committed op (5..=8) that ANY canonical DVC holds.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
  e.dvc_from.insert(0, dvc_offset(0, 1, 4, 10, 8)); // floor 4: holds 5,6,7,8,9,10
  e.dvc_from.insert(1, dvc_offset(1, 1, 8, 10, 8)); // floor 8: holds 9,10 only
  let (log, op_head, commit_star) = e.select_canonical_log();
  assert_eq!(op_head, 10, "canonical head is the generation's head");
  assert_eq!(commit_star, 8, "commit* is the greatest commit");
  // The committed band the union MUST cover: ops 5..=8 (above the lowest floor 4, up to commit*).
  // Without the union fix the log would be just [9,10] and these would be absent.
  let present: std::collections::BTreeSet<u64> = log.iter().map(|e| e.op().get()).collect();
  for op in 5..=8u64 {
    assert!(
      present.contains(&op),
      "committed op {op} (held only by r0's offset log) must be in the canonical log, not dropped"
    );
  }
  // And the uncommitted tail r0 holds (9,10) is included too (no nack quorum truncates it here).
  assert!(
    present.contains(&9) && present.contains(&10),
    "the head ops are present"
  );
  // The entries are the real ones (op-tagged bodies), not fabricated.
  for entry in &log {
    assert_eq!(
      entry.body(),
      &entry.op().get().to_be_bytes()[..],
      "each unioned entry carries the donor's real body"
    );
  }
}

#[test]
fn select_canonical_log_stitches_the_band_across_three_offset_donors() {
  // Three canonical-generation donors with staggered floors must be STITCHED so the committed band
  // is fully covered even though NO single donor holds it all. N=5, quorum_view_change=3.
  //   r0: floor 0, holds 1,2,3 (head 3)         — the prefix
  //   r1: floor 3, holds 4,5,6 (head 6)         — the middle
  //   r2: floor 6, holds 7,8 (head 8, commit 8) — the suffix + the committed frontier
  // commit* = 8, op_head = 8. The union must produce a dense [1..=8] — dropping any of 1..=8 would
  // lose a committed op some lower-floor adopter needs.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
  e.dvc_from.insert(0, dvc_offset(0, 1, 0, 3, 3));
  e.dvc_from.insert(1, dvc_offset(1, 1, 3, 6, 6));
  e.dvc_from.insert(2, dvc_offset(2, 1, 6, 8, 8));
  let (log, op_head, commit_star) = e.select_canonical_log();
  assert_eq!(op_head, 8);
  assert_eq!(commit_star, 8);
  let present: std::collections::BTreeSet<u64> = log.iter().map(|e| e.op().get()).collect();
  assert_eq!(
    present,
    (1..=8u64).collect::<std::collections::BTreeSet<u64>>(),
    "the union stitches all three offset donors into a gapless committed band 1..=8"
  );
}

/// Build a MALFORMED DVC that CLAIMS head `claimed_op` but carries only `present` real entries
/// (`1..=present`). Models a peer (or fuzzed wire input) advertising an enormous op far above its
/// actual log — the F4 attack shape.
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

#[test]
fn select_canonical_log_bounds_a_dvc_claiming_a_huge_op() {
  // F4 REGRESSION (unbounded nack-scan + overflow): DoViewChanges whose CLAIMED `op` is enormous
  // (here `u64::MAX`) but whose `log_slice()` carries only a few real entries must NOT make the
  // nack-truncation loop scan `commit*+1 ..= u64::MAX` op-by-op. The UNBOUNDED case is when a NACK
  // quorum's worth of donors claim a huge op: then the loop's nack count never reaches the threshold
  // for any finite op, so the OLD `while op <= op_head { ...; op += 1 }` would iterate ~u64::MAX
  // times and finally OVERFLOW `op += 1` at `u64::MAX`. With the fix the scan is derived from the
  // sorted donor ops (bounded by the DVC count) and `op_head` is bounded to the represented log.
  // N=3 → quorum_nack_prepare = 2, so we make TWO donors claim the phantom head.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
  // r0: honest — holds ops 1,2,3 (head 3, commit 2).
  e.dvc_from.insert(0, dvc(0, 1, 3, 2));
  // r1, r2 (SAME generation): MALFORMED — each claims op == u64::MAX but carries only ops 1..=3.
  e.dvc_from.insert(1, dvc_claiming(1, 1, u64::MAX, 2, 3));
  e.dvc_from.insert(2, dvc_claiming(2, 1, u64::MAX, 2, 3));
  // Must return PROMPTLY (no unbounded scan, no overflow panic) and bound op_head to the represented
  // log: the max op actually present across the canonical donors is 3, so op_head <= 3.
  let (log, op_head, commit_star) = e.select_canonical_log();
  assert!(
    op_head <= 3,
    "op_head must be bounded to the represented log (<= 3), not the claimed u64::MAX, got {op_head}"
  );
  assert_eq!(commit_star, 2, "commit* is the greatest claimed commit");
  assert!(
    commit_star <= op_head,
    "the fail-stop invariant still holds"
  );
  // The merged log contains only real, present entries — never a phantom op near u64::MAX.
  for entry in &log {
    assert!(
      entry.op().get() <= 3,
      "no fabricated entry above the represented log"
    );
  }
}

#[test]
fn adopt_canonical_head_keeps_committed_ops_an_offset_canonical_log_omits() {
  // B3 gate, CORRECTED to the safe semantics (this is a correctness CORRECTION, not a weakening — see
  // below). A backup holds committed ops 5..=8 in its OFFSET log; the lower band 5,6 it has APPLIED
  // (commit_min == 6), the upper band 7,8 it has NOT (committed by a prior-view quorum but unapplied;
  // op == 8). It adopts a StartView whose canonical log is itself OFFSET, starts at op 9 (does NOT
  // carry 5..=8), commit 8. The two bands are now handled DIFFERENTLY, and that distinction is the fix:
  //
  //   * APPLIED & omitted (5,6, `op <= commit_min`): a committed op the adopter ITSELF applied is
  //     immutable (VSR committed-op survival ⇒ no other view committed a different value), so its local
  //     copy is canonical. It is PRESERVED directly from `self.log` (kept, never re-fetched).
  //   * UNAPPLIED & omitted (7,8, `op in (commit_min, commit]`): the held body is unapplied and may be a
  //     STALE superseded proposal (VOPR seed 24) — `LogEntry` has no per-entry view to tell. It is
  //     therefore DROPPED and REPAIRED: `advance_commit` HOLDS the commit at the first such op and
  //     `request_repair`s the CANONICAL value from a committed-vouching peer.
  //
  // Why this is a CORRECTION, not a weakening of the original B3 safety property: B3's invariant is "no
  // committed op an offset canonical log omits is ever LOST." That still holds end-to-end here — the
  // omitted committed band ends up correct (applied to the SM after repair), never silently skipped. The
  // ONLY change is the SOURCE for the UNAPPLIED band: a possibly-stale local copy (which diverged the
  // committed log under seed 24) is replaced by the quorum's canonical value fetched via peer-repair.
  // The original B3 bug (clearing the whole log + then `repair.clear()` stranding the op) stays fixed:
  // the omitted committed op is never forgotten — it is a held hole until its canonical value arrives.
  let mut e = Endpoint::new(
    Config::try_new(1, ReplicaId::new(2), 3).unwrap(),
    0,
    CountSm::default(),
  );
  // Hand-build the offset-backup state: checkpoint 4, applied through 6 (commit_min == commit_max == 6;
  // the [1..=6] prefix lives in the checkpoint, not the empty CountSm), head 8, offset tail 5..=8 held.
  e.checkpoint_op = OpNumber::with(4);
  e.commit_min = OpNumber::with(6);
  e.commit_max = OpNumber::with(6);
  e.op = OpNumber::with(8);
  for op in 5..=8u64 {
    e.log.insert(
      op,
      LogEntry {
        client: ClientId::new(7),
        request: RequestNumber::with(op),
        body: Bytes::copy_from_slice(&op.to_be_bytes()),
      },
    );
  }
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // The canonical StartView for view 1 from primary 1: an OFFSET log starting at op 9 (head 10),
  // commit 8. It does NOT carry ops 5..=8.
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(10),
    OpNumber::with(8),
    ReplicaId::new(1),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(9),
        ClientId::new(7),
        RequestNumber::with(9),
        Bytes::copy_from_slice(&9u64.to_be_bytes()),
      ),
      PreparedEntry::new(
        OpNumber::with(10),
        ClientId::new(7),
        RequestNumber::with(10),
        Bytes::copy_from_slice(&10u64.to_be_bytes()),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.status(), Status::Normal, "adoption completes");
  // APPLIED & omitted (5,6): PRESERVED directly — still in the log cache, never turned into a hole.
  assert!(
    e.log.contains_key(&5) && e.log.contains_key(&6),
    "an omitted committed op the adopter HAS applied is preserved directly from its own log"
  );
  assert!(
    !e.has_repair_hole_for_test(5) && !e.has_repair_hole_for_test(6),
    "the applied-and-preserved ops are not repaired"
  );
  // UNAPPLIED & omitted (7,8): REPAIRED. The commit is HELD at the first (6) until the canonical value
  // arrives; op 7 is a registered hole (op 8 becomes one after 7 fills). The held copy was DROPPED.
  assert_eq!(
    e.commit(),
    OpNumber::with(6),
    "commit is HELD at the unapplied omitted band until the canonical value is repaired"
  );
  assert!(
    e.has_repair_hole_for_test(7) && !e.log.contains_key(&7),
    "the first unapplied omitted committed op (7) is a repair hole, its held body dropped"
  );
  // A committed-vouching peer (commit 8 >= op) supplies the canonical value for the repaired band.
  for op in [7u64, 8] {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      repair_prepare(1, op, 8),
    );
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(8),
    "commit reaches 8: the omitted committed band is repaired, not lost (the B3 safety property holds)"
  );
  // The SM applied exactly the unapplied band 7,8 (5,6 lived below commit_min, never re-applied; 1..=4
  // in the checkpoint). SAFETY: no committed op the offset StartView omitted was lost.
  let applied: std::vec::Vec<u64> = e.sm.applied().iter().map(|(op, _)| *op).collect();
  assert_eq!(
    applied,
    std::vec![7, 8],
    "the unapplied omitted committed band 7..=8 is repaired to the SM (canonical value, not stale local)"
  );
  assert!(
    e.repair.is_empty(),
    "no committed op is left stranded in the repair set"
  );
}

#[test]
fn adopt_log_does_not_preserve_a_stale_unapplied_held_copy_for_a_committed_op() {
  // SAFETY REGRESSION (VOPR seed 24): the B3 "preserve the omitted committed op from the adopter's
  // own log" rule is only sound for ops the adopter has APPLIED (`op <= commit_min`) — those are
  // committed+immutable. For a committed op in `(commit_min .. adopted_commit]` the adopter holds a
  // body it has NOT applied: it can be a STALE UNCOMMITTED proposal from an earlier view that a later
  // view overwrote with a DIFFERENT committed value (`LogEntry` carries no per-entry view, so the
  // proto cannot tell a canonical-lineage held op from a superseded one). Preserving it diverges the
  // adopter's committed log from the quorum's. The fix: preserve ONLY `op <= commit_min`; the omitted
  // committed band `(commit_min .. adopted_commit]` becomes repair holes whose CANONICAL value is
  // fetched from a committed-vouching peer (commit HELD until then) — never trusted from local.
  //
  // Setup mirrors seed 24: the adopter holds the two committed ops 5,6 TRANSPOSED (op 5 -> body[6],
  // op 6 -> body[5] — stale superseded proposals), while the cluster committed op 5 -> body[5], op 6
  // -> body[6]. checkpoint == commit_min == 4 (those held bodies are UNAPPLIED), op == 8. The adopted
  // offset StartView (head 10, commit 8) OMITS 5,6 (its log starts at op 7).
  let mut e = Endpoint::new(
    Config::try_new(1, ReplicaId::new(2), 3).unwrap(),
    0,
    CountSm::default(),
  );
  e.checkpoint_op = OpNumber::with(4);
  e.commit_min = OpNumber::with(4);
  e.commit_max = OpNumber::with(4);
  e.op = OpNumber::with(8);
  // The STALE, TRANSPOSED held copies for the (commit_min .. commit] band: op 5 holds op 6's body and
  // vice-versa. (Bodies are single-byte `[op]`, matching `repair_prepare`'s canonical encoding, so the
  // post-repair canonical value `[5]`/`[6]` is provably DIFFERENT from the preserved-stale `[6]`/`[5]`.)
  e.log.insert(
    5,
    LogEntry {
      client: ClientId::new(7),
      request: RequestNumber::with(5),
      body: Bytes::copy_from_slice(&[6u8]),
    },
  );
  e.log.insert(
    6,
    LogEntry {
      client: ClientId::new(7),
      request: RequestNumber::with(6),
      body: Bytes::copy_from_slice(&[5u8]),
    },
  );
  // op 7,8 are also in the (commit_min .. commit] band and OMITTED below; they ride the same repair
  // path. Give the adopter NO held copy for them, so they are pure holes filled only from the peer.
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // The canonical offset StartView for view 1 (head 10, commit 8) starts at op 9 — it OMITS 5,6,7,8.
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(10),
    OpNumber::with(8),
    ReplicaId::new(1),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(9),
        ClientId::new(7),
        RequestNumber::with(9),
        Bytes::copy_from_slice(&[9u8]),
      ),
      PreparedEntry::new(
        OpNumber::with(10),
        ClientId::new(7),
        RequestNumber::with(10),
        Bytes::copy_from_slice(&[10u8]),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.status(), Status::Normal, "adoption completes");
  // The stale held copies are DROPPED, not preserved: op 5 is a repair hole and the commit is HELD at
  // the first omitted op (4) — never advanced past op 5 with the stale `[6]` body. (Fail-before: the
  // old rule kept 5->[6] and 6->[5], APPLIED both, and commit jumped to 6 — the transposition — before
  // holding at op 7, with NO hole at 5 or 6.)
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "commit is HELD at the first omitted committed op (the stale body is not applied)"
  );
  // `advance_commit` registers a hole at the FIRST unfetched committed op (op 5) and HOLDS there —
  // ops 6,7,8 become holes lazily as each fill resumes the apply loop. The decisive safety fact is
  // that op 5's STALE held body `[6]` was DROPPED, so the commit could not advance past it. (Fail-
  // before: the old rule kept 5->[6], 6->[5], applied them, and commit jumped to 6 with NO hole at 5.)
  assert!(
    e.has_repair_hole_for_test(5),
    "the first omitted, unapplied committed op (5) becomes a repair hole (canonical value to be fetched)"
  );
  assert!(
    !e.log.contains_key(&5) && !e.log.contains_key(&6),
    "neither stale transposed body survives in the log cache"
  );
  assert!(
    e.sm.applied().is_empty(),
    "NOTHING is applied yet — no stale transposed body reached the SM"
  );
  // A committed-vouching peer Prepare (commit 8 >= op) supplies the CANONICAL value for each hole in
  // order: op 5 -> body[5], op 6 -> body[6] (the un-transposed quorum values), then op 7,8. Each fill
  // resumes the apply loop, which then registers + we fill the next hole.
  for op in [5u64, 6, 7, 8] {
    assert!(
      e.has_repair_hole_for_test(op),
      "op {op} is a registered repair hole before its canonical Prepare arrives"
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      repair_prepare(1, op, 8),
    );
  }
  assert!(
    e.repair.is_empty(),
    "every committed hole is filled from the peer's canonical value"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(8),
    "commit resumes to 8 once the canonical band is repaired"
  );
  // The applied log matches the QUORUM (op 5 -> [5], op 6 -> [6]) — NOT the adopter's stale transpose.
  // This is the exact equality `check_safety` enforces; fail-before it would be [(5,[6]),(6,[5]),...].
  assert_eq!(
    e.sm.applied(),
    &[
      (5, std::vec![5u8]),
      (6, std::vec![6u8]),
      (7, std::vec![7u8]),
      (8, std::vec![8u8]),
    ],
    "the repaired committed band carries the canonical (un-transposed) quorum values"
  );
}

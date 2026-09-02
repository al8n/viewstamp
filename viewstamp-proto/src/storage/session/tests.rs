use std::{collections::VecDeque, vec::Vec};

use bytes::Bytes;

use super::{AppendSubmission, CheckpointSubmission, RootRole, Storage};
use crate::{
  ClientId, JobId, OpNumber, RequestNumber, View,
  block_job::{BlockJobDone, BlockJobKind, BlockJobOutput, BlockJobTag, WalkPurpose},
  block_store::{BlockAddress, BlockStore},
  endpoint::block_sync::BlockWalks,
  state_machine::StateMachine,
  storage::{
    Header, ReadId, SlotStatus, Superblock, SuperblockDone, VsrState, Wal, WalDone, WriteId,
  },
};

/// The minimal state machine the session needs to be generic over: block jobs carry the SM's image
/// type, so the lane front is parameterized by one.
struct MockSm;

impl StateMachine for MockSm {
  type Image = ();

  fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> Bytes {
    Bytes::new()
  }

  fn checkpoint_image(&self) -> Self::Image {}

  fn materialize(_image: &Self::Image, store: &mut dyn BlockStore) -> BlockAddress {
    store.put(Bytes::new())
  }

  fn restore_seed(&self) -> Self {
    Self
  }

  fn restore(
    &mut self,
    root: BlockAddress,
    store: &crate::VerifiedView<'_>,
  ) -> Result<(), crate::RestoreError> {
    store
      .read_block(root)
      .map(|_| ())
      .ok_or(crate::RestoreError::new(root))
  }
}

/// A staging WAL: appends park until the test lands them, truncate/prune cancel whatever is staged
/// in range — the minimal medium the session's ledger semantics are exercised against.
struct MockWal {
  capacity: u64,
  staged: Vec<(WriteId, u64)>,
  done: VecDeque<WalDone>,
}

impl MockWal {
  fn unbounded() -> Self {
    Self {
      capacity: u64::MAX,
      staged: Vec::new(),
      done: VecDeque::new(),
    }
  }

  fn bounded(capacity: u64) -> Self {
    Self {
      capacity,
      ..Self::unbounded()
    }
  }

  fn land(&mut self, id: WriteId) {
    let at = self
      .staged
      .iter()
      .position(|(sid, _)| *sid == id)
      .expect("landing a write that is staged");
    let (id, _) = self.staged.remove(at);
    self.done.push_back(WalDone::Appended(id));
  }
}

impl Wal for MockWal {
  fn op_head(&self) -> OpNumber {
    OpNumber::new()
  }
  fn header(&self, _op: OpNumber) -> Option<Header> {
    None
  }
  fn status(&self, _op: OpNumber) -> SlotStatus {
    SlotStatus::Empty
  }
  fn capacity(&self) -> u64 {
    self.capacity
  }
  fn submit_append(&mut self, id: WriteId, op: OpNumber, _header: Header, _body: Bytes) {
    self.staged.push((id, op.get()));
  }
  fn submit_read(&mut self, _id: ReadId, _op: OpNumber) {}
  fn truncate(&mut self, above: OpNumber) -> Vec<WriteId> {
    let (cancelled, kept) = self.staged.drain(..).partition(|&(_, op)| op > above.get());
    self.staged = kept;
    cancelled.into_iter().map(|(id, _)| id).collect()
  }
  fn prune(&mut self, below: OpNumber) -> Vec<WriteId> {
    let (cancelled, kept) = self.staged.drain(..).partition(|&(_, op)| op < below.get());
    self.staged = kept;
    cancelled.into_iter().map(|(id, _)| id).collect()
  }
  fn poll(&mut self) -> Option<WalDone> {
    self.done.pop_front()
  }
}

/// A staging superblock: root writes land in submission order on demand, each landing installing
/// its submitted state as the durable one.
struct MockSb {
  state: VsrState,
  staged_roots: VecDeque<(WriteId, VsrState)>,
  staged_checkpoints: VecDeque<WriteId>,
  done: VecDeque<SuperblockDone>,
}

impl MockSb {
  fn new() -> Self {
    Self {
      state: VsrState::new(),
      staged_roots: VecDeque::new(),
      staged_checkpoints: VecDeque::new(),
      done: VecDeque::new(),
    }
  }

  fn land_root(&mut self) {
    let (id, state) = self
      .staged_roots
      .pop_front()
      .expect("landing a root that is staged");
    self.state = state;
    self.done.push_back(SuperblockDone::Wrote(id));
  }

  fn land_checkpoint(&mut self) {
    let id = self
      .staged_checkpoints
      .pop_front()
      .expect("landing an envelope that is staged");
    self.done.push_back(SuperblockDone::Wrote(id));
  }
}

impl Superblock for MockSb {
  fn state(&self) -> VsrState {
    self.state.clone()
  }
  fn submit_write(&mut self, id: WriteId, state: VsrState) {
    self.staged_roots.push_back((id, state));
  }
  fn submit_write_checkpoint(&mut self, id: WriteId, _op: OpNumber, _snapshot: Bytes) {
    self.staged_checkpoints.push_back(id);
  }
  fn submit_read_checkpoint(&mut self, _id: ReadId) {}
  fn poll(&mut self) -> Option<SuperblockDone> {
    self.done.pop_front()
  }
}

fn header(op: u64) -> Header {
  Header::new(
    OpNumber::with(op),
    View::with(0),
    ClientId::new(1),
    RequestNumber::with(1),
    &[op as u8],
  )
}

fn root(checkpoint_op: u64, checkpoint_id: u128) -> VsrState {
  root_at_view(1, checkpoint_op, checkpoint_id)
}

fn root_at_view(view: u64, checkpoint_op: u64, checkpoint_id: u128) -> VsrState {
  VsrState::try_new(
    View::with(view),
    View::with(view),
    OpNumber::with(checkpoint_op),
    OpNumber::with(checkpoint_op),
    checkpoint_id,
    Vec::new(),
  )
  .expect("a well-formed test root")
}

fn submit(s: &mut Storage<MockWal, MockSb, MockSm>, id: WriteId, op: u64) -> AppendSubmission {
  s.submit_append(id, OpNumber::with(op), header(op), Bytes::from_static(&[1]))
}

#[test]
fn a_second_append_to_a_fenced_slot_is_refused_until_the_slot_quiesces() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let first = WriteId::new(1, 1);
  assert_eq!(submit(&mut s, first, 7), AppendSubmission::Submitted);
  assert_eq!(s.appends_slot_fenced(), 0, "nothing refused yet");
  assert!(
    matches!(
      submit(&mut s, WriteId::new(1, 2), 7),
      AppendSubmission::SlotFenced { .. }
    ),
    "an un-quiesced older write holds the slot"
  );
  assert_eq!(
    s.appends_slot_fenced(),
    1,
    "the refusal is counted, so a fence that stopped firing is observable rather than silent"
  );

  s.wal_mut().land(first);
  let polled = s.poll_wal().expect("the landing completes");
  assert_eq!(
    polled.freed_slot,
    Some(7),
    "the completion settles the ledger and reports the freed slot"
  );
  assert_eq!(
    submit(&mut s, WriteId::new(1, 3), 7),
    AppendSubmission::Submitted,
    "the quiesced slot admits the replacement"
  );
  assert_eq!(
    s.appends_slot_fenced(),
    1,
    "an ADMITTED submission never counts — the counter measures refusals, not attempts"
  );
}

#[test]
fn the_fence_holds_across_incarnations_and_ring_aliases() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::bounded(4), MockSb::new());
  // A dead incarnation's write to op 1 is still with the device.
  let dead = WriteId::new(1, 1);
  assert_eq!(submit(&mut s, dead, 1), AppendSubmission::Submitted);

  // The successor (a later incarnation, sequences restarted) is fenced off op 1's slot AND its
  // ring alias op 5, but not off op 6.
  assert!(
    matches!(
      submit(&mut s, WriteId::new(2, 1), 1),
      AppendSubmission::SlotFenced { .. }
    ),
    "the dead incarnation's write fences the same op"
  );
  assert!(
    matches!(
      submit(&mut s, WriteId::new(2, 2), 5),
      AppendSubmission::SlotFenced { .. }
    ),
    "the dead incarnation's write fences the ring alias"
  );
  assert_eq!(
    submit(&mut s, WriteId::new(2, 3), 6),
    AppendSubmission::Submitted,
    "an unrelated slot is unfenced"
  );

  // The dead write's landing frees the slot — delivered to whichever endpoint is current, the
  // session settles it regardless.
  s.wal_mut().land(dead);
  assert_eq!(s.poll_wal().expect("landed").freed_slot, Some(1));
  assert_eq!(
    submit(&mut s, WriteId::new(2, 4), 5),
    AppendSubmission::Submitted,
    "the alias is admitted once the old write quiesced"
  );
}

#[test]
fn settlement_is_keyed_by_the_full_id_never_the_sequence() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  // Two incarnations, SAME sequence number, different ops — the aliasing shape seq-only keying
  // would corrupt.
  let dead = WriteId::new(1, 1);
  let live = WriteId::new(2, 1);
  assert_eq!(submit(&mut s, dead, 3), AppendSubmission::Submitted);
  assert_eq!(submit(&mut s, live, 4), AppendSubmission::Submitted);

  s.wal_mut().land(dead);
  assert_eq!(
    s.poll_wal().expect("landed").freed_slot,
    Some(3),
    "the dead incarnation's landing frees ITS op"
  );
  assert!(
    s.slot_write_in_flight(4),
    "the live write's witness survives its sequence twin's settlement"
  );
}

#[test]
fn truncate_settles_a_dead_incarnations_cancellations() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let dead = WriteId::new(1, 1);
  let kept = WriteId::new(2, 1);
  assert_eq!(submit(&mut s, dead, 5), AppendSubmission::Submitted);
  assert_eq!(submit(&mut s, kept, 2), AppendSubmission::Submitted);

  let settled = s.truncate(OpNumber::with(3));
  assert_eq!(settled.len(), 1, "only the above-truncation write cancels");
  assert_eq!(settled[0].id, dead);
  assert_eq!(
    settled[0].freed_slot,
    Some(5),
    "a foreign cancellation still frees its slot in the ledger"
  );
  assert!(
    s.slot_write_in_flight(2),
    "the below-truncation write stays in flight"
  );
  assert!(!s.slot_write_in_flight(5), "the cancelled slot is free");
}

#[test]
fn the_effective_pair_reads_the_last_submitted_root_on_one_timeline() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  assert_eq!(
    s.effective_checkpoint_pair(),
    (OpNumber::new(), 0),
    "with nothing in flight the durable root is effective"
  );

  let a = WriteId::new(1, 1);
  s.submit_root(RootRole::Checkpoint, a, root(4, 40));
  assert_eq!(
    s.effective_checkpoint_pair(),
    (OpNumber::with(4), 40),
    "an in-flight root is the effective timeline"
  );

  let b = WriteId::new(1, 2);
  s.submit_root(RootRole::DurableView, b, root(8, 80));
  assert_eq!(
    s.effective_checkpoint_pair(),
    (OpNumber::with(8), 80),
    "the LAST submitted root wins while several are in flight"
  );

  s.sb_mut().land_root();
  let polled = s.poll_sb().expect("the first root lands");
  let (landed_role, landed_id, landed_state) =
    polled.landed_root.expect("a root landing is reported");
  assert_eq!(
    landed_role,
    RootRole::Checkpoint,
    "the landing carries the role its write was submitted under"
  );
  assert_eq!(landed_id, a);
  assert_eq!(landed_state.checkpoint_op(), OpNumber::with(4));
  assert_eq!(
    s.effective_checkpoint_pair(),
    (OpNumber::with(8), 80),
    "the landed root does not eclipse the newer submitted one"
  );

  s.sb_mut().land_root();
  let polled = s.poll_sb().expect("the second root lands");
  let (landed_role, landed_id, _) = polled.landed_root.expect("reported");
  assert_eq!(landed_role, RootRole::DurableView);
  assert_eq!(landed_id, b);
  assert_eq!(
    s.effective_checkpoint_pair(),
    (OpNumber::with(8), 80),
    "with the timeline drained, the durable root IS the last submitted"
  );
  assert!(!s.has_inflight(), "the root timeline is drained");
}

#[test]
fn the_effective_root_is_the_latest_submitted_root_else_the_durable_one() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  assert_eq!(
    s.effective_root(),
    VsrState::new(),
    "with nothing in flight the durable root is effective"
  );

  let submitted = root_at_view(3, 4, 40);
  s.submit_root(RootRole::DurableView, WriteId::new(1, 1), submitted.clone());
  assert_eq!(
    s.effective_root(),
    submitted,
    "an in-flight root is the state the medium converges to — a rebuilt endpoint baselines here"
  );

  s.sb_mut().land_root();
  let (_, _, landed) = s
    .poll_sb()
    .expect("the root lands")
    .landed_root
    .expect("a root landing is reported");
  assert_eq!(landed, submitted);
  assert_eq!(
    s.effective_root(),
    submitted,
    "the drained timeline's effective root IS the durable one — the value never moved"
  );
}

#[test]
fn a_successors_root_parks_behind_a_dead_predecessors_outstanding_one() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  // A dead incarnation's root write is still with the device.
  let dead = WriteId::new(1, 1);
  let dead_state = root_at_view(2, 0, 0);
  s.submit_root(RootRole::DurableView, dead, dead_state.clone());

  // The successor's own root write PARKS: it enters the timeline (the effective root moves, and
  // quiescence waits for it) but the backend does not see it while the predecessor's is
  // outstanding — the superblock analogue of the append fence. The role cell is REUSED across
  // the rebuild: the predecessor's write occupies the front, so the successor's first same-role
  // submission takes the very cell the predecessor's would have parked in.
  let own = WriteId::new(2, 1);
  let own_state = root_at_view(3, 0, 0);
  s.submit_root(RootRole::DurableView, own, own_state.clone());
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "the parked root was not handed to the backend"
  );
  assert_eq!(
    s.effective_root(),
    own_state,
    "a parked root is a committed point on the timeline"
  );
  assert!(s.has_inflight(), "a parked root is still owed");

  // The predecessor's landing releases the fence: the session itself submits the parked root.
  // The role rides the landing even though the submitting incarnation is dead — it is the
  // session's record, not the endpoint's.
  s.sb_mut().land_root();
  let (role, id, state) = s
    .poll_sb()
    .expect("the predecessor's root lands")
    .landed_root
    .expect("reported");
  assert_eq!((role, id, state), (RootRole::DurableView, dead, dead_state));
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "the landing handed the parked root to the backend"
  );

  s.sb_mut().land_root();
  let (role, id, state) = s
    .poll_sb()
    .expect("the released root lands")
    .landed_root
    .expect("reported");
  assert_eq!(
    (role, id, state),
    (RootRole::DurableView, own, own_state.clone())
  );
  assert_eq!(s.effective_root(), own_state, "the medium converged to it");
  assert!(!s.has_inflight());
}

#[test]
fn a_slow_backend_never_holds_more_than_one_outstanding_root() {
  // A conforming backend may be arbitrarily slow, so the session must not hand it a second root
  // while one is outstanding: the physical pipeline is one deep, and everything behind it parks.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(1, 1),
    root_at_view(2, 0, 0),
  );
  s.submit_root(
    RootRole::Checkpoint,
    WriteId::new(1, 2),
    root_at_view(3, 0, 0),
  );
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(1, 3),
    root_at_view(4, 0, 0),
  );
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "an outstanding root gates every later submission into the parked cells"
  );
  assert_eq!(
    s.roots_in_flight(),
    3,
    "every submission is on the timeline"
  );
  assert_eq!(
    s.effective_root(),
    root_at_view(4, 0, 0),
    "the latest submission is still the effective root while parked"
  );

  // Each landing hands exactly the lowest-stamp parked root to the backend — an endpoint's own
  // stacking still lands last-submitted-wins, with the order enforced by the stamps rather than
  // trusted to the backend's serialization.
  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("first landing").landed_root.is_some());
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "the landing released ONE parked root"
  );
  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("second landing").landed_root.is_some());
  s.sb_mut().land_root();
  let (_, id, state) = s
    .poll_sb()
    .expect("third landing")
    .landed_root
    .expect("reported");
  assert_eq!(id, WriteId::new(1, 3));
  assert_eq!(
    state,
    root_at_view(4, 0, 0),
    "the latest submitted root became durable"
  );
  assert!(!s.has_inflight());
}

#[test]
fn a_same_role_resubmission_supersedes_the_parked_root_it_replaces() {
  // Supersession is the submission itself: writing the role's cell replaces whatever parked root
  // the same correlation staged before, in the same act that records the replacement — there is
  // no removal call to pair with the submission and none to miss. The submitted front stays owed
  // to the medium.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let outstanding = WriteId::new(1, 1);
  let superseded = WriteId::new(1, 2);
  let newest = WriteId::new(1, 3);
  s.submit_root(RootRole::DurableView, outstanding, root_at_view(2, 0, 0));
  s.submit_root(RootRole::DurableView, superseded, root_at_view(3, 0, 0));
  assert_eq!(
    s.roots_superseded(),
    0,
    "parking in a free cell replaces nothing"
  );
  s.submit_root(RootRole::DurableView, newest, root_at_view(4, 0, 0));
  assert_eq!(
    s.roots_superseded(),
    1,
    "the overwrite is counted — no depth arm can see it, so this is its only trace"
  );
  assert_eq!(
    s.roots_in_flight(),
    2,
    "the superseded parked root left the timeline; the front and its successor remain"
  );
  assert_eq!(
    s.effective_root(),
    root_at_view(4, 0, 0),
    "the newest submission is the effective root"
  );

  // The superseded root never lands: the drain goes front → newest, nothing in between.
  s.sb_mut().land_root();
  let (_, id, _) = s
    .poll_sb()
    .expect("the front lands")
    .landed_root
    .expect("reported");
  assert_eq!(id, outstanding);
  s.sb_mut().land_root();
  let (_, id, state) = s
    .poll_sb()
    .expect("the successor lands")
    .landed_root
    .expect("reported");
  assert_eq!(id, newest);
  assert_eq!(state, root_at_view(4, 0, 0));
  assert!(!s.has_inflight(), "no superseded entry is left owed");
}

#[test]
fn abandoning_the_submitted_front_or_a_mismatched_call_is_a_no_op() {
  // An outstanding write is owed to the medium — abandonment must not touch it, and it occupies
  // no parked cell to be touched through — and a call whose id or role does not match the cell
  // clears nothing: the guard is what makes every mis-call (stale, re-ordered, mis-roled)
  // degrade to one stale parked entry that lands safely, instead of clearing a root some live
  // correlation still awaits and stranding its await.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let outstanding = WriteId::new(1, 1);
  s.submit_root(RootRole::DurableView, outstanding, root_at_view(2, 0, 0));
  s.abandon_root(RootRole::DurableView, outstanding);
  assert_eq!(
    s.roots_in_flight(),
    1,
    "the submitted front survives its submitter's abandonment"
  );
  let parked = WriteId::new(1, 2);
  s.submit_root(RootRole::DurableView, parked, root_at_view(3, 0, 0));
  s.abandon_root(RootRole::DurableView, WriteId::new(9, 9));
  assert_eq!(s.roots_in_flight(), 2, "a mismatched id clears nothing");
  s.abandon_root(RootRole::Checkpoint, parked);
  assert_eq!(s.roots_in_flight(), 2, "a mis-stated role clears nothing");
  assert_eq!(s.roots_abandoned(), 0, "a no-op is never counted");

  // The un-cleared entry is the safe degradation the guard buys: promoted and landed, monotone —
  // one wasted write, nothing stranded.
  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("the front lands").landed_root.is_some());
  s.sb_mut().land_root();
  let (_, id, _) = s
    .poll_sb()
    .expect("the stale entry lands")
    .landed_root
    .expect("reported");
  assert_eq!(id, parked);
  assert!(!s.has_inflight());
}

#[test]
fn an_abandoned_parked_root_steps_the_effective_root_to_the_previous_entry() {
  // Abandonment without a successor (the catch-up shape): the parked entry leaves its cell, the
  // effective root steps back to the previous timeline point, and the medium converges there.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let abandoned = WriteId::new(1, 2);
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(1, 1),
    root_at_view(2, 0, 0),
  );
  s.submit_root(RootRole::DurableView, abandoned, root_at_view(3, 0, 0));
  s.abandon_root(RootRole::DurableView, abandoned);
  assert_eq!(
    s.roots_abandoned(),
    1,
    "the matching clear is counted — the efficiency witness for the abandonment sites"
  );
  assert_eq!(
    s.effective_root(),
    root_at_view(2, 0, 0),
    "the effective root stepped back to the state still owed to the medium"
  );

  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("the front lands").landed_root.is_some());
  assert!(!s.has_inflight(), "the abandoned entry is not owed");
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    0,
    "nothing was ever handed to the backend for the abandoned root"
  );
}

#[test]
fn endpoint_construction_collapses_every_parked_root_keeping_the_owed_front() {
  // The rebuild collapse: at endpoint construction every parked root belongs to a dead
  // incarnation and nothing awaits it, so every parked cell empties while the submitted front —
  // owed to the medium — stays. The effective root steps back to the front, which is what the
  // successor soundly baselines on: everything above it was promised only by writes the medium
  // never saw.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let front = WriteId::new(1, 1);
  let front_state = root_at_view(2, 0, 0);
  s.submit_root(RootRole::DurableView, front, front_state.clone());
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(1, 2),
    root_at_view(3, 0, 0),
  );
  s.submit_root(
    RootRole::Checkpoint,
    WriteId::new(1, 3),
    root_at_view(4, 0, 0),
  );
  assert_eq!(s.roots_in_flight(), 3, "front + the dead pair");

  s.collapse_parked_roots();
  assert_eq!(
    s.roots_in_flight(),
    1,
    "the parked cells collapsed; the submitted front is still owed"
  );
  assert_eq!(
    s.effective_root(),
    front_state,
    "the effective root stepped back to the state the medium still owes"
  );
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "the backend still holds exactly the front — no collapsed entry was ever submitted"
  );

  // The successor's own submissions then run against the collapsed timeline as usual.
  let successor = WriteId::new(2, 1);
  let successor_state = root_at_view(5, 0, 0);
  s.submit_root(RootRole::DurableView, successor, successor_state.clone());
  s.sb_mut().land_root();
  let (_, id, state) = s
    .poll_sb()
    .expect("the front lands")
    .landed_root
    .expect("reported");
  assert_eq!((id, state), (front, front_state));
  s.sb_mut().land_root();
  let (_, id, state) = s
    .poll_sb()
    .expect("the successor lands")
    .landed_root
    .expect("reported");
  assert_eq!((id, state), (successor, successor_state));
  assert!(!s.has_inflight(), "no collapsed entry is left owed");
}

#[test]
fn collapsing_an_all_parked_or_empty_timeline_is_safe() {
  // No submitted front (nothing ever submitted): collapse is a no-op on empty, and after a full
  // drain it leaves the quiesced session quiesced.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.collapse_parked_roots();
  assert_eq!(s.roots_in_flight(), 0);
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(1, 1),
    root_at_view(2, 0, 0),
  );
  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("lands").landed_root.is_some());
  s.collapse_parked_roots();
  assert_eq!(s.roots_in_flight(), 0, "a drained timeline stays drained");
  assert!(!s.has_inflight());
}

#[test]
fn the_timeline_holds_one_front_and_one_parked_root_per_role() {
  // The depth bound, read off the containers: one front cell plus one parked cell per role, so a
  // fourth concurrent root is UNREPRESENTABLE rather than asserted away. Where a leaked
  // correlation once met a fail-stop at the fourth entry — a deterministic panic on an otherwise
  // healthy replica — the same schedule is now absorbed as one supersession, and the depth stays
  // at the constant the containers embody.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(1, 1),
    root_at_view(2, 0, 0),
  );
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(1, 2),
    root_at_view(3, 0, 0),
  );
  s.submit_root(
    RootRole::Checkpoint,
    WriteId::new(1, 3),
    root_at_view(4, 0, 0),
  );
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(1, 4),
    root_at_view(5, 0, 0),
  );
  assert_eq!(
    s.roots_in_flight(),
    3,
    "four submissions, three cells: the same-role pair collapsed to its latest"
  );
  assert_eq!(s.roots_superseded(), 1, "and the overwrite left its trace");

  // The drain is stamp-ordered across what survived: the front, the checkpoint root, then the
  // replacement — every landing monotone, the overwritten root never among them, and each
  // landing carrying the role its cell recorded.
  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("the front lands").landed_root.is_some());
  s.sb_mut().land_root();
  let (role, id, _) = s
    .poll_sb()
    .expect("second landing")
    .landed_root
    .expect("reported");
  assert_eq!(role, RootRole::Checkpoint);
  assert_eq!(id, WriteId::new(1, 3));
  s.sb_mut().land_root();
  let (role, id, state) = s
    .poll_sb()
    .expect("third landing")
    .landed_root
    .expect("reported");
  assert_eq!(role, RootRole::DurableView);
  assert_eq!(id, WriteId::new(1, 4));
  assert_eq!(state, root_at_view(5, 0, 0));
  assert!(!s.has_inflight());
}

#[test]
fn parked_roots_release_in_stamp_order_across_generations() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  // Three incarnations' roots: the first submitted, each later one parked behind the foreign
  // write ahead of it. The stamps are the session's, so submission order spans the rebuilds —
  // sequences restart at 1 in each incarnation, which is why the ids cannot carry this order
  // and the stamp does.
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(1, 1),
    root_at_view(2, 0, 0),
  );
  s.submit_root(
    RootRole::Checkpoint,
    WriteId::new(2, 1),
    root_at_view(3, 0, 0),
  );
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(3, 1),
    root_at_view(4, 0, 0),
  );
  assert_eq!(s.sb_mut().staged_roots.len(), 1);

  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("first landing").landed_root.is_some());
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "only the SECOND generation released — the third is still fenced behind it"
  );

  s.sb_mut().land_root();
  let (role, id, _) = s
    .poll_sb()
    .expect("second landing")
    .landed_root
    .expect("reported");
  assert_eq!(
    role,
    RootRole::Checkpoint,
    "the role survives to a landing another incarnation drains"
  );
  assert_eq!(id, WriteId::new(2, 1), "the lower stamp released first");
  assert_eq!(s.sb_mut().staged_roots.len(), 1, "the third released");

  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("third landing").landed_root.is_some());
  assert!(!s.has_inflight(), "the timeline drained in stamp order");
}

#[test]
#[should_panic(expected = "rewind the durable view")]
fn a_root_below_the_effective_view_is_refused() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(1, 1),
    root_at_view(3, 0, 0),
  );
  // A writer that baselined below the timeline (the landed root, a stale scalar) is a bug the
  // choke catches: landings arrive in stamp order, so this root would regress the durable view.
  // The refusal runs BEFORE the cell write, so not even the parked entry is replaced.
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(2, 1),
    root_at_view(2, 0, 0),
  );
}

/// A v4 root at `(view, epoch)` — its membership carries three voters and chains from `config_id`.
fn root_at_epoch(view: u64, epoch: u64, config_id: u128) -> VsrState {
  let membership = crate::Membership::from_durable_parts(
    crate::Epoch::new(epoch),
    3,
    0,
    (0..3).map(crate::MemberId::new).collect(),
    config_id,
  )
  .expect("a well-formed test membership");
  VsrState::try_new_v4(
    View::with(view),
    View::with(view),
    OpNumber::new(),
    OpNumber::new(),
    0,
    Vec::new(),
    crate::Epoch::new(epoch),
    crate::Epoch::new(epoch.saturating_sub(1)),
    membership,
    Vec::new(),
    OpNumber::new(),
  )
  .expect("a well-formed test root")
}

#[test]
#[should_panic(expected = "rewind the durable epoch")]
fn a_root_below_the_effective_epoch_is_refused() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  // An in-flight SwapEpoch root carries the successor configuration at epoch 1.
  s.submit_root(
    RootRole::DurableView,
    WriteId::new(1, 1),
    root_at_epoch(2, 1, 7),
  );
  // A root sourcing its configuration from state that lags the timeline (the writer's memory
  // before the swap installed, or a recovery baselined on a stale root) would land AFTER the swap
  // and republish the predecessor epoch — the durable-membership rewind. The view RISES here, so
  // only the epoch check can refuse it.
  s.submit_root(
    RootRole::Checkpoint,
    WriteId::new(1, 2),
    root_at_epoch(3, 0, 3),
  );
}

// The assertions below the violation inspect the storage AFTER the panic surfaced, so the test
// has to catch the unwind and resume — `catch_unwind` is a `std` facility with no `core`
// counterpart, and a build without `std` has no unwinding runtime to resume from at all.
#[cfg(feature = "std")]
#[test]
fn a_parked_completion_is_settled_before_the_violation_surfaces() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let front = WriteId::new(1, 1);
  s.submit_root(RootRole::DurableView, front, root_at_view(2, 0, 0));
  let parked = WriteId::new(2, 1);
  s.submit_root(RootRole::DurableView, parked, root_at_view(3, 0, 0));
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "the successor's root is parked behind the foreign one"
  );
  // A parked root was never handed to the backend, so no completion can legitimately name it:
  // deliver one anyway — the violating-backend shape the settle-then-panic arm exists for.
  s.sb_mut().done.push_back(SuperblockDone::Wrote(parked));
  let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.poll_sb()));
  assert!(
    polled.is_err(),
    "the parked landing surfaces the contract violation"
  );
  // The violating completion was settled BEFORE the panic surfaced it: the parked entry left its
  // cell — no completion could ever name it again, so without the settle `has_inflight` would
  // hold (and `into_parts` refuse) forever — while the front stays the one write with the
  // backend, still owed and still staged.
  assert_eq!(s.roots_in_flight(), 1, "the parked entry was settled out");
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "the front is still the one write with the backend"
  );
  // The remaining ledger drains normally: the front lands and the session quiesces.
  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("the front lands").landed_root.is_some());
  assert!(!s.has_inflight(), "the ledger drained");
}

#[test]
#[should_panic(expected = "a superblock write completed that the session never submitted")]
fn a_completion_the_session_never_submitted_is_refused_fail_stop() {
  // The same untrusted-medium fail-stop as an invented cancellation: a backend inventing write
  // facts is a medium whose ledger can no longer be trusted.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.sb_mut()
    .done
    .push_back(SuperblockDone::Wrote(WriteId::new(9, 9)));
  s.poll_sb();
}

#[test]
fn an_envelope_landing_settles_without_claiming_the_root_timeline() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  assert_eq!(
    s.submit_checkpoint(
      WriteId::new(1, 1),
      OpNumber::with(4),
      Bytes::from_static(&[9]),
    ),
    CheckpointSubmission::Submitted,
  );
  s.submit_root(RootRole::Checkpoint, WriteId::new(1, 2), root(4, 40));
  assert!(s.has_inflight());

  s.sb_mut().land_checkpoint();
  let polled = s.poll_sb().expect("the envelope lands");
  assert!(
    polled.landed_root.is_none(),
    "an envelope landing is not a root landing"
  );
  assert!(s.has_inflight(), "the root write is still owed");

  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("the root lands").landed_root.is_some());
  assert!(!s.has_inflight());
}

#[test]
fn a_second_envelope_is_fenced_until_the_outstanding_one_completes() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  assert_eq!(
    s.submit_checkpoint(
      WriteId::new(1, 1),
      OpNumber::with(4),
      Bytes::from_static(&[9]),
    ),
    CheckpointSubmission::Submitted,
  );
  // The submitter's correlation may since have ended (a dropped re-persist, a rebuild) — the
  // session cannot see that, and it does not matter: the medium holds one envelope write, so a
  // second submission is refused whole, whoever submits it.
  assert_eq!(
    s.submit_checkpoint(
      WriteId::new(2, 1),
      OpNumber::with(6),
      Bytes::from_static(&[8]),
    ),
    CheckpointSubmission::EnvelopeFenced,
  );
  assert_eq!(
    s.sb_mut().staged_checkpoints.len(),
    1,
    "the fenced envelope never reached the backend"
  );
  assert_eq!(s.checkpoints_in_flight(), 1);
  assert_eq!(
    s.envelopes_fenced(),
    1,
    "the refusal is counted, so a fence that stopped firing is observable rather than silent"
  );

  // The refusal is deferral: the outstanding write completes, the lane empties, and the deferred
  // checkpoint's re-forced submission is admitted.
  s.sb_mut().land_checkpoint();
  assert!(
    s.poll_sb()
      .expect("the envelope lands")
      .landed_root
      .is_none()
  );
  assert_eq!(s.checkpoints_in_flight(), 0);
  assert_eq!(
    s.submit_checkpoint(
      WriteId::new(2, 2),
      OpNumber::with(6),
      Bytes::from_static(&[8]),
    ),
    CheckpointSubmission::Submitted,
  );
  s.sb_mut().land_checkpoint();
  assert!(s.poll_sb().is_some());
  assert!(!s.has_inflight(), "the drained lane quiesces the session");
  assert_eq!(
    s.envelopes_fenced(),
    1,
    "an ADMITTED submission never counts — the counter measures refusals, not attempts"
  );
}

#[test]
fn an_envelope_fence_holds_across_the_submitting_correlations_end() {
  // The rebuild shape: incarnation 1 submits an envelope and dies (its correlation state dies with
  // it — the session cannot observe that); incarnation 2 stages its own checkpoint. The fence
  // holds on the SESSION ledger, which survived the rebuild, so the successor's submission defers
  // until the orphan drains — the medium never holds two envelope writes.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  assert_eq!(
    s.submit_checkpoint(
      WriteId::new(1, 7),
      OpNumber::with(4),
      Bytes::from_static(&[9]),
    ),
    CheckpointSubmission::Submitted,
  );
  assert_eq!(
    s.submit_checkpoint(
      WriteId::new(2, 1),
      OpNumber::with(4),
      Bytes::from_static(&[9]),
    ),
    CheckpointSubmission::EnvelopeFenced,
  );
  // The orphan's completion drains the ledger even though no live correlation awaits it.
  s.sb_mut().land_checkpoint();
  assert!(s.poll_sb().is_some());
  assert_eq!(s.checkpoints_in_flight(), 0);
  assert_eq!(
    s.submit_checkpoint(
      WriteId::new(2, 2),
      OpNumber::with(4),
      Bytes::from_static(&[9]),
    ),
    CheckpointSubmission::Submitted,
  );
}

#[test]
fn into_parts_refuses_while_the_medium_owes_completions() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let id = WriteId::new(1, 1);
  assert_eq!(submit(&mut s, id, 1), AppendSubmission::Submitted);

  let mut s = match s.into_parts() {
    Ok(_) => panic!("the handles must not come out over an un-quiesced medium"),
    Err(s) => s,
  };

  s.wal_mut().land(id);
  assert!(s.poll_wal().is_some());
  assert!(
    s.into_parts().is_ok(),
    "a quiesced session releases its handles"
  );
}

/// A `Gc` sweep over an empty live-root set: the one kind with no endpoint correlation, so the lane
/// resolves a collision on its slot itself rather than fail-stopping.
fn sweep() -> BlockJobKind<MockSm> {
  sweep_over(Vec::new())
}

/// A `Gc` sweep naming `sm_roots` as the live SM roots — what a coalesce replaces.
fn sweep_over(sm_roots: Vec<BlockAddress>) -> BlockJobKind<MockSm> {
  BlockJobKind::Gc {
    sm_roots,
    session_roots: Vec::new(),
  }
}

/// The live SM roots a queued sweep names, for the coalescing tests.
fn sweep_roots(job: &crate::BlockJob<MockSm>) -> Vec<BlockAddress> {
  match &job.kind {
    BlockJobKind::Gc { sm_roots, .. } => sm_roots.clone(),
    _ => panic!("not a sweep"),
  }
}

/// A `Serve` answer for `addr` — the one kind admitted against the counted cap.
fn serve(addr: BlockAddress) -> BlockJobKind<MockSm> {
  BlockJobKind::Serve {
    to: crate::Peer::Replica(crate::ReplicaId::new(0)),
    addr,
  }
}

/// One frontier step over a two-root DAG — the walk slot.
fn walk(addr: BlockAddress) -> BlockJobKind<MockSm> {
  BlockJobKind::Walk {
    walks: BlockWalks::new(addr, addr),
    fetched: None,
    purpose: WalkPurpose::Arq,
  }
}

/// An image capture of the empty mock state machine — the materialize slot.
fn capture() -> BlockJobKind<MockSm> {
  BlockJobKind::Materialize {
    image: (),
    sessions: crate::endpoint::SessionImage(std::collections::BTreeMap::new()),
  }
}

/// A durability barrier over `addr`'s two DAG roots — the flush slot.
fn barrier(addr: BlockAddress) -> BlockJobKind<MockSm> {
  BlockJobKind::Flush {
    sm_root: addr,
    sessions_root: addr,
  }
}

/// A reconstruct of a synced checkpoint from `addr`'s two DAG roots — the restore slot.
fn reconstruct(addr: BlockAddress) -> BlockJobKind<MockSm> {
  BlockJobKind::Restore {
    sm_root: addr,
    sessions_root: addr,
    seed: MockSm,
    purpose: crate::block_job::RestorePurpose::SyncedCheckpoint,
  }
}

/// The completion of a job whose kind is `tag`, echoing `id`.
fn done(id: JobId, tag: BlockJobTag, addr: BlockAddress) -> BlockJobDone<MockSm> {
  let output = match tag {
    BlockJobTag::Materialize => BlockJobOutput::Materialized {
      sm_root: addr,
      sessions_root: addr,
      flush: Ok(()),
    },
    BlockJobTag::Flush => BlockJobOutput::Flushed(Ok(())),
    BlockJobTag::Gc => BlockJobOutput::Gced,
    BlockJobTag::Serve => BlockJobOutput::Served {
      to: crate::Peer::Replica(crate::ReplicaId::new(0)),
      addr,
      block: None,
    },
    BlockJobTag::Restore => BlockJobOutput::Restored {
      purpose: crate::block_job::RestorePurpose::SyncedCheckpoint,
      result: Err(crate::state_machine::RestoreError::new(addr)),
    },
    BlockJobTag::Walk => BlockJobOutput::Walked(crate::block_job::WalkDone {
      walks: BlockWalks::new(addr, addr),
      accepted: false,
      next: Ok(None),
      purpose: WalkPurpose::Arq,
    }),
  };
  BlockJobDone { id, output }
}

fn addr() -> BlockAddress {
  crate::block_address(b"a block the lane front's tests name")
}

#[test]
fn a_job_queued_but_never_polled_outlives_the_endpoint_that_issued_it() {
  // The whole point of the front: an un-polled job is the LANE's, so replacing the endpoint that
  // issued it takes nothing away. The session cannot be replaced while it holds one either — that
  // is the same seal the append ledger has.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let queued = JobId::new(1, 1);
  s.enqueue_block_job(queued, serve(addr()));
  assert!(s.has_inflight(), "the lane owes the queued job");

  let mut s = match s.into_parts() {
    Ok(_) => panic!("the handles must not come out while the lane still owes a job"),
    Err(s) => s,
  };
  // A rebuild happens here, and it can do nothing to the queue: the successor polls what the
  // predecessor queued.
  let polled = s.poll_block_job().expect("the queued job is still there");
  assert_eq!(polled.id(), queued);
  s.settle_block_job(&done(queued, BlockJobTag::Serve, addr()));
  assert!(!s.has_inflight(), "the delivery retired it");
  assert!(s.into_parts().is_ok());
}

#[test]
fn a_slot_releases_on_the_delivery_of_the_job_that_took_it() {
  // The slot is taken at QUEUE time and released at DELIVERY, both on the lane's own books — so the
  // window in which it is held is exactly the window in which the job exists.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let first = JobId::new(1, 1);
  let second = JobId::new(2, 1); // a SUCCESSOR incarnation's id, aliasing the sequence
  s.enqueue_block_job(first, serve(addr()));
  s.enqueue_block_job(second, walk(addr()));
  assert_eq!(s.serves_outstanding(), 1);
  assert!(s.walk_owed(), "one frontier step per lane");

  s.settle_block_job(&done(first, BlockJobTag::Serve, addr()));
  assert_eq!(s.serves_outstanding(), 0, "the serve's cap entry is free");
  assert!(s.walk_owed(), "the walk is still owed");
  s.settle_block_job(&done(second, BlockJobTag::Walk, addr()));
  assert!(!s.walk_owed(), "and its delivery frees the walk slot");
}

#[test]
fn the_lane_holds_one_job_of_every_kind_at_once() {
  // THE DEPTH BOUND, read off the containers. One cell per kind but `Serve`, plus a serve set
  // checked against the cap — so the lane's depth is a cardinality of what it holds, not a claim
  // about the state that issued the jobs. That distinction is the point: the endpoint fields a
  // barrier, a sweep and a reconstruct used to be "bounded by" are reset when the endpoint is
  // rebuilt over the store, while these cells are the session's.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.enqueue_block_job(JobId::new(1, 1), capture());
  s.enqueue_block_job(JobId::new(1, 2), barrier(addr()));
  s.enqueue_block_job(JobId::new(1, 3), sweep());
  s.enqueue_block_job(JobId::new(1, 4), reconstruct(addr()));
  s.enqueue_block_job(JobId::new(1, 5), walk(addr()));
  s.enqueue_block_job(JobId::new(1, 6), serve(addr()));
  s.enqueue_block_job(JobId::new(1, 7), serve(addr()));
  assert!(s.materialize_owed());
  assert!(s.flush_owed());
  assert!(s.restore_owed());
  assert!(s.walk_owed());
  assert_eq!(s.serves_outstanding(), 2);
  assert_eq!(s.block_jobs_in_flight(), 7);
  assert_eq!(
    s.block_jobs_bound(),
    5 + 128,
    "one cell per single-slot kind plus the outstanding-serve cap"
  );
}

#[test]
#[should_panic(expected = "a second frontier walk was queued")]
fn one_lane_admits_one_frontier_walk() {
  // The walk slot is the lane's, so a transfer abandoned by a rebuild (or a re-pin, or a view
  // transition) cannot leave its walk queued and admit another behind it.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.enqueue_block_job(JobId::new(1, 1), walk(addr()));
  s.enqueue_block_job(JobId::new(2, 1), walk(addr()));
}

#[test]
#[should_panic(expected = "a second image capture was queued")]
fn one_lane_admits_one_image_capture() {
  // A capture carries a full state-machine image, and the checkpoint a view transition abandons
  // cannot retract the job — so the capture site reads THIS slot before it captures anything.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.enqueue_block_job(JobId::new(1, 1), capture());
  s.enqueue_block_job(JobId::new(2, 1), capture());
}

#[test]
#[should_panic(expected = "a second durability barrier was queued")]
fn one_lane_admits_one_durability_barrier() {
  // The barrier used to be admitted on the strength of the endpoint's owed install alone, which a
  // rebuild resets while the queued barrier stays the lane's. The slot is what a rebuild cannot
  // reset, and the staging site now reads it.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.enqueue_block_job(JobId::new(1, 1), barrier(addr()));
  s.enqueue_block_job(JobId::new(2, 1), barrier(addr()));
}

#[test]
#[should_panic(expected = "a second reconstruct was queued")]
fn one_lane_admits_one_reconstruct() {
  // Same shape as the barrier, on the obligation that owes the SM's content: the two reconstruct
  // sites (a synced checkpoint's, and cold start's own) issue from different bookkeeping, and only
  // this slot spans both — and spans the incarnation that issued one of them and then died.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.enqueue_block_job(JobId::new(1, 1), reconstruct(addr()));
  s.enqueue_block_job(JobId::new(2, 1), reconstruct(addr()));
}

#[test]
fn the_serve_cap_is_released_by_the_exact_serve_that_completes() {
  // The cap is the ONE bound here that counts rather than names: a serve's correlatum is an inbound
  // request, so there is no finite key space to carve. What keeps the count honest is that release
  // is exact — the completion removes the id it answers, so a cap entry can only be freed by the
  // completion of a serve the lane genuinely admitted. A bare counter would take any mis-tagged
  // completion as a release and re-open the cap by one for each one it absorbed.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let cap = crate::endpoint::MAX_OUTSTANDING_BLOCK_SERVES;
  for seq in 1..=cap {
    s.enqueue_block_job(JobId::new(1, seq as u64), serve(addr()));
  }
  assert_eq!(s.serves_outstanding(), cap, "the lane is at its cap");
  s.settle_block_job(&done(JobId::new(1, 1), BlockJobTag::Serve, addr()));
  assert_eq!(s.serves_outstanding(), cap - 1, "exactly one entry freed");
  s.enqueue_block_job(JobId::new(1, cap as u64 + 1), serve(addr()));
  assert_eq!(s.serves_outstanding(), cap, "and exactly one refilled it");
}

#[test]
#[should_panic(expected = "past the lane's outstanding-serve cap")]
fn a_serve_past_the_cap_is_refused_by_the_lane() {
  // The endpoint drops the request before it ever reaches here (a dropped `RequestBlock` is re-sent
  // by the requester's ARQ, which is what keeps its frontier intact), so this is the backstop that
  // makes the cap the container's property rather than the caller's discipline.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  for seq in 1..=crate::endpoint::MAX_OUTSTANDING_BLOCK_SERVES as u64 + 1 {
    s.enqueue_block_job(JobId::new(1, seq), serve(addr()));
  }
}

#[test]
fn a_sweep_offered_over_a_queued_one_takes_the_newer_live_roots() {
  // The sweep is the one kind with no endpoint correlation, so a second offer cannot be refused
  // into an obligation and must not fail-stop either. While the queued sweep is still the lane's,
  // its root list is REPLACED: nothing awaits the absorbed id, and marking from the newer roots is
  // what the next sweep would have done anyway (over-marking retains, so it is the safe direction).
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let queued = JobId::new(1, 1);
  let newer = crate::block_address(b"a root the newer sweep list names");
  s.enqueue_block_job(queued, sweep_over(Vec::new()));
  s.enqueue_block_job(JobId::new(2, 1), sweep_over(std::vec![newer]));
  assert_eq!(s.sweeps_coalesced(), 1);
  assert_eq!(s.block_jobs_in_flight(), 1, "one sweep, not two");

  let job = s.poll_block_job().expect("the queued sweep is still there");
  assert_eq!(job.id(), queued, "under the id the lane already owes");
  assert_eq!(sweep_roots(&job), std::vec![newer], "with the newer roots");
  assert!(s.poll_block_job().is_none(), "and nothing behind it");
  s.settle_block_job(&done(queued, BlockJobTag::Gc, addr()));
  assert!(!s.has_inflight());
}

#[test]
fn a_sweep_offered_over_an_executing_one_is_dropped() {
  // Past the poll the payload can no longer be reached, so there is nothing to coalesce into. The
  // offer is dropped whole rather than queued behind: a sweep leaves no obligation owed, retention
  // is unaffected by one that does not run, and the next checkpoint's sweep re-drives it.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let executing = JobId::new(1, 1);
  s.enqueue_block_job(executing, sweep());
  let taken = s.poll_block_job().expect("the driver takes it");
  assert_eq!(taken.id(), executing);

  s.enqueue_block_job(JobId::new(2, 1), sweep());
  assert_eq!(s.sweeps_dropped(), 1);
  assert_eq!(s.sweeps_coalesced(), 0);
  assert!(s.poll_block_job().is_none(), "nothing was queued behind it");
  assert_eq!(s.block_jobs_in_flight(), 1, "the lane still owes only one");

  // The delivery frees the slot, and the next sweep is admitted normally.
  s.settle_block_job(&done(executing, BlockJobTag::Gc, addr()));
  s.enqueue_block_job(JobId::new(2, 2), sweep());
  assert_eq!(s.block_jobs_in_flight(), 1);
  assert_eq!(s.sweeps_dropped(), 1, "the counter is session-lifetime");
}

#[test]
#[should_panic(expected = "block job completion out of issue order")]
fn a_completion_out_of_issue_order_is_refused_by_the_lanes_witness() {
  // The order witness judges EVERY completion, whichever incarnation minted it: a predecessor's job
  // and its successor's sit in one queue, so the witness has to span both or the successor's own
  // completion would find a stale front.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let dead = JobId::new(1, 1);
  let live = JobId::new(2, 1);
  s.enqueue_block_job(dead, serve(addr()));
  s.enqueue_block_job(live, serve(addr()));
  s.settle_block_job(&done(live, BlockJobTag::Serve, addr()));
}

#[test]
fn the_append_quota_is_the_doubled_implied_ring_of_the_recorded_interval() {
  // The unstamped fixture root records no checkpoint interval, so the quota derives the
  // pipeline-only floor: `2 × (IMPLIED_RING_INTERVALS × 0 + MAX_PIPELINE)`. A stamped store
  // scales with its recorded interval — asserted through the same accessor the simulation
  // boundedness checker reads, so the checker's bound and the session's gate can never diverge.
  let s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  assert_eq!(s.append_quota(), 2048, "the pipeline-only floor (2 × 1024)");

  let mut stamped = MockSb::new();
  stamped.state = root(0, 0).with_wal_geometry(2, u64::MAX);
  let s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), stamped);
  assert_eq!(
    s.append_quota(),
    2 * (4 * 2 + 1024),
    "a recorded interval widens the implied ring the quota doubles"
  );
}

#[test]
fn a_ring_less_append_backlog_is_refused_at_the_session_quota() {
  // The default backend is ring-less (`capacity == u64::MAX`), where the slot-quiescence fence
  // bounds NOTHING: distinct ops never alias, so before the quota every submission was admitted
  // and the ledger grew one entry per op with no time-independent bound — the append → lag →
  // sync-forward accumulation shape, since state-sync abandons append ownership while these
  // physical facts survive and truncate/prune may cancel none of them. The quota is the
  // capacity-independent ceiling that refuses the backlog at the choke, retryably.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let quota = s.append_quota();
  for op in 1..=quota {
    assert_eq!(
      submit(&mut s, WriteId::new(1, op), op),
      AppendSubmission::Submitted,
      "a healthy in-flight window is never deferred (op {op} of quota {quota})"
    );
  }
  assert_eq!(s.wal_appends_in_flight() as u64, quota);
  assert_eq!(
    s.appends_quota_refused(),
    0,
    "a full window at the ceiling is still a healthy window — nothing refused"
  );
  assert!(
    matches!(
      submit(&mut s, WriteId::new(1, quota + 1), quota + 1),
      AppendSubmission::QuotaExhausted { .. }
    ),
    "the submission past the quota is refused with its bytes handed back"
  );
  assert_eq!(
    s.wal_appends_in_flight() as u64,
    quota,
    "a refused submission enters neither the ledger nor the backend"
  );
  assert_eq!(
    s.appends_quota_refused(),
    1,
    "the refusal is counted, so the sweeps can assert the ceiling stays clear of healthy windows"
  );
}

#[test]
fn any_quiescence_frees_quota_headroom_for_a_deferred_append() {
  // The quota's release trigger is AGGREGATE headroom — any in-flight append quiescing — not the
  // refused op's own slot: the blockers are arbitrary older writes, so slot-keyed release could
  // never fire for a quota-refused op whose slot was free all along.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let quota = s.append_quota();
  for op in 1..=quota {
    assert_eq!(
      submit(&mut s, WriteId::new(1, op), op),
      AppendSubmission::Submitted
    );
  }
  assert!(matches!(
    submit(&mut s, WriteId::new(1, quota + 1), quota + 1),
    AppendSubmission::QuotaExhausted { .. }
  ));
  // One arbitrary old write completes — headroom appears, and the retried submission is admitted.
  s.wal_mut().land(WriteId::new(1, 3));
  let polled = s.poll_wal().expect("the landed completion drains");
  assert_eq!(
    polled.freed_slot,
    Some(3),
    "the quiesced slot rides the completion"
  );
  assert_eq!(
    submit(&mut s, WriteId::new(1, quota + 2), quota + 1),
    AppendSubmission::Submitted,
    "the freed headroom admits the retried append"
  );
  assert!(
    matches!(
      submit(&mut s, WriteId::new(1, quota + 3), quota + 2),
      AppendSubmission::QuotaExhausted { .. }
    ),
    "the ledger is back at the quota, so the next submission waits for the next quiescence"
  );
}

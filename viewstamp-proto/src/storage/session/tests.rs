use std::collections::VecDeque;
use std::vec::Vec;

use bytes::Bytes;

use super::{AppendSubmission, CheckpointSubmission, Storage};
use crate::block_job::{BlockJobDone, BlockJobKind, BlockJobOutput, BlockJobTag, WalkPurpose};
use crate::block_store::{BlockAddress, BlockStore};
use crate::endpoint::block_sync::BlockWalks;
use crate::state_machine::StateMachine;
use crate::storage::{
  Header, ReadId, SlotStatus, Superblock, SuperblockDone, VsrState, Wal, WalDone, WriteId,
};
use crate::{ClientId, JobId, OpNumber, RequestNumber, View};

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
  assert!(
    matches!(
      submit(&mut s, WriteId::new(1, 2), 7),
      AppendSubmission::SlotFenced { .. }
    ),
    "an un-quiesced older write holds the slot"
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
  s.submit_root(a, root(4, 40));
  assert_eq!(
    s.effective_checkpoint_pair(),
    (OpNumber::with(4), 40),
    "an in-flight root is the effective timeline"
  );

  let b = WriteId::new(1, 2);
  s.submit_root(b, root(8, 80));
  assert_eq!(
    s.effective_checkpoint_pair(),
    (OpNumber::with(8), 80),
    "the LAST submitted root wins while several are in flight"
  );

  s.sb_mut().land_root();
  let polled = s.poll_sb().expect("the first root lands");
  let (landed_id, landed_state) = polled.landed_root.expect("a root landing is reported");
  assert_eq!(landed_id, a);
  assert_eq!(landed_state.checkpoint_op(), OpNumber::with(4));
  assert_eq!(
    s.effective_checkpoint_pair(),
    (OpNumber::with(8), 80),
    "the landed root does not eclipse the newer submitted one"
  );

  s.sb_mut().land_root();
  let polled = s.poll_sb().expect("the second root lands");
  assert_eq!(polled.landed_root.expect("reported").0, b);
  assert_eq!(
    s.effective_checkpoint_pair(),
    (OpNumber::with(8), 80),
    "with the timeline drained, the durable root IS the last submitted"
  );
  assert!(!s.has_inflight(), "the root timeline is drained");
}

#[test]
fn the_effective_root_is_the_back_of_the_timeline_else_the_durable_one() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  assert_eq!(
    s.effective_root(),
    VsrState::new(),
    "with nothing in flight the durable root is effective"
  );

  let submitted = root_at_view(3, 4, 40);
  s.submit_root(WriteId::new(1, 1), submitted.clone());
  assert_eq!(
    s.effective_root(),
    submitted,
    "an in-flight root is the state the medium converges to — a rebuilt endpoint baselines here"
  );

  s.sb_mut().land_root();
  let (_, landed) = s
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
  s.submit_root(dead, dead_state.clone());

  // The successor's own root write PARKS: it enters the timeline (the effective root moves, and
  // quiescence waits for it) but the backend does not see it while the predecessor's is
  // outstanding — the superblock analogue of the append fence.
  let own = WriteId::new(2, 1);
  let own_state = root_at_view(3, 0, 0);
  s.submit_root(own, own_state.clone());
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
  s.sb_mut().land_root();
  let (id, state) = s
    .poll_sb()
    .expect("the predecessor's root lands")
    .landed_root
    .expect("reported");
  assert_eq!((id, state), (dead, dead_state));
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "the landing handed the parked root to the backend"
  );

  s.sb_mut().land_root();
  let (id, state) = s
    .poll_sb()
    .expect("the released root lands")
    .landed_root
    .expect("reported");
  assert_eq!((id, state), (own, own_state.clone()));
  assert_eq!(s.effective_root(), own_state, "the medium converged to it");
  assert!(!s.has_inflight());
}

#[test]
fn a_slow_backend_never_holds_more_than_one_outstanding_root() {
  // A conforming backend may be arbitrarily slow, so the session must not hand it a second root
  // while one is outstanding: the physical pipeline is one deep, and everything behind it parks.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.submit_root(WriteId::new(1, 1), root_at_view(2, 0, 0));
  s.submit_root(WriteId::new(1, 2), root_at_view(3, 0, 0));
  s.submit_root(WriteId::new(1, 3), root_at_view(4, 0, 0));
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "an outstanding root gates every later submission into the parked tail"
  );
  assert_eq!(
    s.roots_in_flight(),
    3,
    "every submission is on the timeline"
  );
  assert_eq!(
    s.effective_root(),
    root_at_view(4, 0, 0),
    "the back of the queue is still the effective root while parked"
  );

  // Each landing hands exactly the next queued root to the backend, in queue order — an
  // endpoint's own stacking still lands last-submitted-wins, with the order enforced by the
  // queue rather than trusted to the backend's serialization.
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
  let (id, state) = s
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
fn a_forfeited_parked_root_leaves_the_timeline() {
  // The submitter superseded (or abandoned) its parked root: forfeiture removes the entry — the
  // backend never saw the write, so nothing physical remains to wait for — while the submitted
  // front stays owed to the medium.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let outstanding = WriteId::new(1, 1);
  let superseded = WriteId::new(1, 2);
  let newest = WriteId::new(1, 3);
  s.submit_root(outstanding, root_at_view(2, 0, 0));
  s.submit_root(superseded, root_at_view(3, 0, 0));
  s.forfeit_root(superseded);
  s.submit_root(newest, root_at_view(4, 0, 0));
  assert_eq!(
    s.roots_in_flight(),
    2,
    "the superseded parked root left the queue; the front and its successor remain"
  );
  assert_eq!(
    s.effective_root(),
    root_at_view(4, 0, 0),
    "the newest submission is the effective root"
  );

  // The forfeited root never lands: the drain goes front → newest, nothing in between.
  s.sb_mut().land_root();
  let (id, _) = s
    .poll_sb()
    .expect("the front lands")
    .landed_root
    .expect("reported");
  assert_eq!(id, outstanding);
  s.sb_mut().land_root();
  let (id, state) = s
    .poll_sb()
    .expect("the successor lands")
    .landed_root
    .expect("reported");
  assert_eq!(id, newest);
  assert_eq!(state, root_at_view(4, 0, 0));
  assert!(!s.has_inflight(), "no forfeited entry is left owed");
}

#[test]
fn forfeiting_the_submitted_front_or_an_unknown_id_is_a_no_op() {
  // An outstanding write is owed to the medium — forfeiture must not touch it — and an id the
  // queue no longer holds (landed, or never submitted) has nothing to remove.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let outstanding = WriteId::new(1, 1);
  s.submit_root(outstanding, root_at_view(2, 0, 0));
  s.forfeit_root(outstanding);
  assert_eq!(
    s.roots_in_flight(),
    1,
    "the submitted front survives its submitter's abandonment"
  );
  s.forfeit_root(WriteId::new(9, 9));
  assert_eq!(s.roots_in_flight(), 1, "an unknown id removes nothing");

  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("the front lands").landed_root.is_some());
  assert!(!s.has_inflight());
}

#[test]
fn forfeiting_the_parked_back_steps_the_effective_root_to_the_previous_entry() {
  // Abandonment without a successor (the catch-up shape): the parked back leaves, the effective
  // root steps back to the previous timeline point, and the medium converges there.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let abandoned = WriteId::new(1, 2);
  s.submit_root(WriteId::new(1, 1), root_at_view(2, 0, 0));
  s.submit_root(abandoned, root_at_view(3, 0, 0));
  s.forfeit_root(abandoned);
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
    "nothing was ever handed to the backend for the forfeited root"
  );
}

#[test]
fn parked_roots_release_in_queue_order_across_generations() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  // Three incarnations' roots: the first submitted, each later one parked behind the foreign
  // writes ahead of it (a rebuild-of-a-rebuild leaves exactly this queue).
  s.submit_root(WriteId::new(1, 1), root_at_view(2, 0, 0));
  s.submit_root(WriteId::new(2, 1), root_at_view(3, 0, 0));
  s.submit_root(WriteId::new(3, 1), root_at_view(4, 0, 0));
  assert_eq!(s.sb_mut().staged_roots.len(), 1);

  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("first landing").landed_root.is_some());
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "only the SECOND generation released — the third is still fenced behind it"
  );

  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("second landing").landed_root.is_some());
  assert_eq!(s.sb_mut().staged_roots.len(), 1, "the third released");

  s.sb_mut().land_root();
  assert!(s.poll_sb().expect("third landing").landed_root.is_some());
  assert!(!s.has_inflight(), "the timeline drained in queue order");
}

#[test]
#[should_panic(expected = "rewind the durable view")]
fn a_root_below_the_effective_view_is_refused() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.submit_root(WriteId::new(1, 1), root_at_view(3, 0, 0));
  // A writer that baselined below the timeline (the landed root, a stale scalar) is a bug the
  // choke catches: landings arrive in queue order, so this root would regress the durable view.
  s.submit_root(WriteId::new(2, 1), root_at_view(2, 0, 0));
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
  s.submit_root(WriteId::new(1, 1), root_at_epoch(2, 1, 7));
  // A root sourcing its configuration from state that lags the timeline (the writer's memory
  // before the swap installed, or a recovery baselined on a stale root) would land AFTER the swap
  // and republish the predecessor epoch — the durable-membership rewind. The view RISES here, so
  // only the epoch check can refuse it.
  s.submit_root(WriteId::new(1, 2), root_at_epoch(3, 0, 3));
}

#[test]
fn an_out_of_order_landing_still_releases_the_parked_tail() {
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let dead = WriteId::new(1, 1);
  s.submit_root(dead, root_at_view(2, 0, 0));
  let parked = WriteId::new(2, 1);
  s.submit_root(parked, root_at_view(3, 0, 0));
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    1,
    "the successor's root is parked behind the foreign one"
  );
  // A single out-of-order completion always leaves the parked tail's blocker in the queue (the
  // front retires through the in-order arm), so the stranding shape needs the COMPOUND violation:
  // a backend that already desynced the submitted count. Construct that state directly — it is
  // exactly what the settle-anyway branch exists to drain.
  s.roots_submitted = 0;
  s.sb_mut().done.push_back(SuperblockDone::Wrote(dead));
  let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.poll_sb()));
  assert!(
    polled.is_err(),
    "the out-of-order landing surfaces the contract violation"
  );
  // The violating landing was settled BEFORE the panic surfaced it, and the settlement released
  // the parked root to the backend — without the release nothing else ever would (the parked
  // entry has no completion of its own to arrive), so `has_inflight` would hold forever.
  assert_eq!(
    s.sb_mut().staged_roots.len(),
    2,
    "settling the out-of-order landing released the parked tail"
  );
  // Drop the violating landing's stale stage entry (its completion already arrived above), then
  // land the released root: it completes in order and drains the ledger.
  let stale = s
    .sb_mut()
    .staged_roots
    .pop_front()
    .expect("the stale stage entry");
  assert_eq!(stale.0, dead);
  s.sb_mut().land_root();
  assert!(
    s.poll_sb()
      .expect("the released root lands")
      .landed_root
      .is_some()
  );
  assert!(!s.has_inflight(), "the ledger drained");
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
  s.submit_root(WriteId::new(1, 2), root(4, 40));
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

/// A `Gc` sweep: the job kind that claims no lane quota.
fn sweep() -> BlockJobKind<MockSm> {
  BlockJobKind::Gc {
    sm_roots: Vec::new(),
    session_roots: Vec::new(),
  }
}

/// A `Serve` answer for `addr` — the counted quota.
fn serve(addr: BlockAddress) -> BlockJobKind<MockSm> {
  BlockJobKind::Serve {
    to: crate::Peer::Replica(crate::ReplicaId::new(0)),
    addr,
  }
}

/// One frontier step over a two-root DAG — the single-slot walk quota.
fn walk(addr: BlockAddress) -> BlockJobKind<MockSm> {
  BlockJobKind::Walk {
    walks: BlockWalks::new(addr, addr),
    fetched: None,
    purpose: WalkPurpose::Arq,
  }
}

/// The completion of a job whose kind is `tag`, echoing `id`.
fn done(id: JobId, tag: BlockJobTag, addr: BlockAddress) -> BlockJobDone<MockSm> {
  let output = match tag {
    BlockJobTag::Gc => BlockJobOutput::Gced,
    BlockJobTag::Serve => BlockJobOutput::Served {
      to: crate::Peer::Replica(crate::ReplicaId::new(0)),
      addr,
      block: None,
    },
    BlockJobTag::Walk => BlockJobOutput::Walked(crate::block_job::WalkDone {
      walks: BlockWalks::new(addr, addr),
      accepted: false,
      next: Ok(None),
      purpose: WalkPurpose::Arq,
    }),
    other => panic!("no completion fixture for {other}"),
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
fn a_quota_releases_on_the_delivery_of_the_job_that_claimed_it() {
  // The claim is made at QUEUE time and released at DELIVERY, both on the lane's own books — so the
  // window in which the claim exists is exactly the window in which the job exists.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  let first = JobId::new(1, 1);
  let second = JobId::new(2, 1); // a SUCCESSOR incarnation's id, aliasing the sequence
  s.enqueue_block_job(first, serve(addr()));
  s.enqueue_block_job(second, walk(addr()));
  assert_eq!(s.serves_outstanding(), 1);
  assert!(s.walk_owed(), "one frontier step per lane");

  s.settle_block_job(&done(first, BlockJobTag::Serve, addr()));
  assert_eq!(s.serves_outstanding(), 0, "the serve's cap slot is free");
  assert!(s.walk_owed(), "the walk is still owed");
  s.settle_block_job(&done(second, BlockJobTag::Walk, addr()));
  assert!(!s.walk_owed(), "and its delivery frees the walk slot");
}

#[test]
#[should_panic(expected = "a second frontier walk was queued")]
fn one_lane_admits_one_frontier_walk() {
  // The walk quota is the lane's, so a transfer abandoned by a rebuild (or a re-pin, or a view
  // transition) cannot leave its walk queued and admit another behind it.
  let mut s = Storage::<_, _, MockSm>::new(MockWal::unbounded(), MockSb::new());
  s.enqueue_block_job(JobId::new(1, 1), walk(addr()));
  s.enqueue_block_job(JobId::new(2, 1), walk(addr()));
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
  s.enqueue_block_job(dead, sweep());
  s.enqueue_block_job(live, sweep());
  s.settle_block_job(&done(live, BlockJobTag::Gc, addr()));
}

//! The block lane's front: the queue an endpoint issues into, the per-kind slots that bound the
//! lane's depth, and the issue-order witness.
//!
//! Everything here describes what the LANE still owes, whichever endpoint incarnation issued it, so
//! all of it has the lane's lifetime rather than any endpoint's. That is why it lives in the
//! [`Storage`](super::Storage) session: an un-polled job and the slot it occupies are ONE object,
//! so they cannot come apart across an endpoint rebuild — the successor polls what its predecessor
//! queued and the (refused) completion releases the slot that admitted it. Keeping the queue on
//! the endpoint while relaying the slot is what let a rebuild inherit a claim no lane could ever
//! release.
//!
//! # The depth bound is the slot table's cardinality
//!
//! Every kind but `Serve` holds ONE cell of the lane's slot table, and every `Serve` holds one
//! entry of a set the admission point checks against [`MAX_OUTSTANDING_BLOCK_SERVES`]. So the lane
//! owes at most [`MAX_BLOCK_JOBS_IN_FLIGHT`] completions, and that number is a property of the
//! CONTAINERS rather than of whatever issued the jobs. The distinction is the whole point: the
//! state an endpoint issues from (an owed install, an owed reconstruct obligation, a checkpoint
//! step) is reset when the endpoint is rebuilt over the store, so a bound resting on it bounds
//! nothing across incarnations — while these cells belong to the session and outlive every
//! endpoint that writes through it.
//!
//! Each single-slot kind's issue site reads its cell before it builds a payload — through
//! `Storage::materialize_owed`, `flush_owed`, `restore_owed` and `walk_owed` — and defers while it
//! is occupied, leaving whatever obligation owed it re-driven on its own cadence. Those gates read
//! the LANE, so they are unaffected by a rebuild that resets the obligation; admission therefore
//! fail-stops only on a caller that issued without consulting its gate at all. The sweep is the
//! exception in both directions: it is the one kind with no endpoint correlation to consult, so it
//! is admitted unconditionally and the lane resolves the collision itself (see [`LaneFront::enqueue`]).
//!
//! The serve set is the one CAP-CHECKED container here, and it has to be: a serve's correlatum is
//! an inbound peer request, so the things that may be named are not enumerable and no key space
//! can be carved out of them. What compensates is that its release is EXACT — a completion removes
//! the very id it answers, so the count can only fall by a serve the lane genuinely admitted.

use std::{collections::VecDeque, vec::Vec};

use crate::{
  JobId,
  block_job::{BlockJob, BlockJobDone, BlockJobKind, BlockJobTag},
  endpoint::MAX_OUTSTANDING_BLOCK_SERVES,
  state_machine::StateMachine,
};

/// The slot the un-consumed image capture occupies.
const MATERIALIZE_SLOT: usize = 0;
/// The slot the owed durability barrier occupies.
const FLUSH_SLOT: usize = 1;
/// The slot the un-drained sweep occupies.
const GC_SLOT: usize = 2;
/// The slot the owed reconstruct occupies.
const RESTORE_SLOT: usize = 3;
/// The slot the owed frontier walk occupies.
const WALK_SLOT: usize = 4;
/// How many job kinds take a single lane slot: every kind but `Serve`.
const SINGLETON_KINDS: usize = 5;

/// The CONSTANT depth cap of the whole lane: one job of each single-slot kind, plus the outstanding
/// serves the cap admits. Unconditional — both terms are compile-time constants, so the bound holds
/// in every configuration, for every backend, and independently of how many endpoints have been
/// built over the store.
pub(crate) const MAX_BLOCK_JOBS_IN_FLIGHT: usize = SINGLETON_KINDS + MAX_OUTSTANDING_BLOCK_SERVES;

/// The lane slot `tag` occupies together with the name the admission and settle asserts call it by,
/// or `None` for `Serve` — the one kind admitted against a counted cap instead of a slot.
///
/// Matched exhaustively rather than by a wildcard: a new job kind must be classified here, which is
/// also where it either takes a slot of its own (raising [`MAX_BLOCK_JOBS_IN_FLIGHT`]) or is
/// deliberately put on the serve cap's footing.
const fn singleton(tag: BlockJobTag) -> Option<(usize, &'static str)> {
  match tag {
    BlockJobTag::Materialize => Some((MATERIALIZE_SLOT, "image capture")),
    BlockJobTag::Flush => Some((FLUSH_SLOT, "durability barrier")),
    BlockJobTag::Gc => Some((GC_SLOT, "sweep")),
    BlockJobTag::Restore => Some((RESTORE_SLOT, "reconstruct")),
    BlockJobTag::Walk => Some((WALK_SLOT, "frontier walk")),
    BlockJobTag::Serve => None,
  }
}

/// The lane's front. Owned by the [`Storage`](super::Storage) session, so it is opened once per
/// store and can only be replaced by proving the medium quiet.
pub(crate) struct LaneFront<S: StateMachine> {
  /// Jobs issued and not yet taken by the driver, in issue order. An endpoint rebuild leaves these
  /// untouched: they were never the endpoint's to lose, and the lane executes them next.
  jobs: VecDeque<BlockJob<S>>,
  /// The ids of every issued job whose completion is still owed — queued-but-undrained AND
  /// executing — in ISSUE order. Two duties: it is the lane's drain witness, and its front is the
  /// ONLY completion the lane accepts, which is how a driver that executes or delivers out of issue
  /// order is CAUGHT rather than silently tolerated.
  outstanding: VecDeque<JobId>,
  /// One cell per single-slot kind, indexed by [`singleton`]: the id of the job of that kind the
  /// lane still owes a completion for, if any. THE lane's depth bound for everything but serves —
  /// five cells hold five jobs, whatever state issued them and however many endpoints have come and
  /// gone over the store.
  ///
  /// A slot is what each kind's payload weight argues for: an image capture carries a full
  /// state-machine image plus a session projection, a frontier walk carries the transfer's
  /// frontiers, a sweep carries a live-root list, a reconstruct carries a detached seed. But the
  /// bound does not rest on any of that — it is a COUNT, one per kind, so a kind whose payload
  /// later grows or shrinks changes nothing about how deep the lane can get.
  singletons: [Option<JobId>; SINGLETON_KINDS],
  /// The ids of the `Serve` jobs the lane still owes completions for, in issue order. A serve names
  /// an inbound peer request rather than anything enumerable, so this is the one container bounded
  /// by a checked CAP ([`MAX_OUTSTANDING_BLOCK_SERVES`]) instead of by a key space: without it an
  /// inbound `RequestBlock` rate above the lane's drain rate would grow the queue without limit.
  ///
  /// Holding the IDS rather than a count is what makes the cap tight. A settle removes the exact id
  /// it answers, so the only thing that can free a cap slot is the completion of a serve the lane
  /// admitted; a bare counter would take any mis-tagged completion as a release and re-open the cap
  /// by one for every one it absorbed.
  serves: Vec<JobId>,
  /// Observability counter: how many sweeps were COALESCED into one still queued — the newer
  /// live-root list replacing the older one in place, under the queued job's own id. Sound because
  /// a sweep answers no endpoint correlation and a newer root list is strictly the better one to
  /// run: nothing awaits the id that was absorbed, and marking from more roots retains more.
  /// Exposed via [`Storage::sweeps_coalesced`](super::Storage::sweeps_coalesced).
  sweeps_coalesced: u64,
  /// Observability counter: how many sweeps were DROPPED because the one holding the slot had
  /// already been handed to the driver. An executing job's payload cannot be replaced, and the
  /// sweep has no obligation to leave owed, so the offer is simply refused — the next checkpoint's
  /// sweep re-drives it. Retention safety is unaffected either way (a sweep that does not run frees
  /// nothing). Exposed via [`Storage::sweeps_dropped`](super::Storage::sweeps_dropped).
  sweeps_dropped: u64,
}

impl<S: StateMachine> LaneFront<S> {
  /// The front of a lane that has been handed nothing.
  pub(crate) const fn new() -> Self {
    Self {
      jobs: VecDeque::new(),
      outstanding: VecDeque::new(),
      singletons: [None; SINGLETON_KINDS],
      serves: Vec::new(),
      sweeps_coalesced: 0,
      sweeps_dropped: 0,
    }
  }

  /// Whether the lane owes any completion — queued or executing.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn owes_completion(&self) -> bool {
    !self.outstanding.is_empty()
  }

  /// How many completions the lane owes — queued or executing, every kind.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn outstanding_len(&self) -> usize {
    self.outstanding.len()
  }

  /// Whether the lane already holds an un-consumed image capture.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn materialize_owed(&self) -> bool {
    self.singletons[MATERIALIZE_SLOT].is_some()
  }

  /// Whether the lane already holds a durability barrier.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn flush_owed(&self) -> bool {
    self.singletons[FLUSH_SLOT].is_some()
  }

  /// Whether the lane already holds a reconstruct.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn restore_owed(&self) -> bool {
    self.singletons[RESTORE_SLOT].is_some()
  }

  /// Whether the lane already holds a frontier walk.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn walk_owed(&self) -> bool {
    self.singletons[WALK_SLOT].is_some()
  }

  /// How many `Serve` jobs the lane holds.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn serves_outstanding(&self) -> usize {
    self.serves.len()
  }

  /// How many sweeps were coalesced into a still-queued one (see the field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn sweeps_coalesced(&self) -> u64 {
    self.sweeps_coalesced
  }

  /// How many sweeps were dropped behind an already-executing one (see the field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn sweeps_dropped(&self) -> u64 {
    self.sweeps_dropped
  }

  /// Queue `id`'s job: take the slot its kind occupies, record the completion as owed, and append
  /// to the queue. The single admission point, so no job can be queued without being ordered and
  /// accounted, and no slot can be taken by a job that is not queued.
  ///
  /// A kind whose cell is already full is a caller that issued without consulting the gate its
  /// issue site owes — the same fail-stop the rest of the session's chokes use, because the state
  /// is then inconsistent rather than merely contended. The SWEEP is the exception: it answers no
  /// correlation, so there is no gate for its site to consult and the collision is resolved here
  /// instead. While the queued sweep is still in the queue its root list is REPLACED by the newer
  /// one — nothing awaits the absorbed id, and marking from the newer roots is what the next sweep
  /// would have done anyway; once the driver has taken it, its payload can no longer be reached, so
  /// the offer is dropped and the next checkpoint's sweep re-drives it.
  pub(crate) fn enqueue(&mut self, id: JobId, kind: BlockJobKind<S>) {
    let job = BlockJob { id, kind };
    match singleton(job.tag()) {
      None => {
        assert!(
          self.serves.len() < MAX_OUTSTANDING_BLOCK_SERVES,
          "a serve was queued past the lane's outstanding-serve cap \
           ({MAX_OUTSTANDING_BLOCK_SERVES})",
        );
        self.serves.push(id);
        self.queue(job);
      }
      Some((GC_SLOT, _)) => match self.singletons[GC_SLOT] {
        None => {
          self.singletons[GC_SLOT] = Some(id);
          self.queue(job);
        }
        Some(queued) => match self.jobs.iter_mut().find(|j| j.id == queued) {
          Some(waiting) => {
            waiting.kind = job.kind;
            self.sweeps_coalesced = self.sweeps_coalesced.saturating_add(1);
          }
          None => self.sweeps_dropped = self.sweeps_dropped.saturating_add(1),
        },
      },
      Some((slot, noun)) => {
        assert!(
          self.singletons[slot].is_none(),
          "a second {noun} was queued while the lane still owes one ({:?})",
          self.singletons[slot],
        );
        self.singletons[slot] = Some(id);
        self.queue(job);
      }
    }
  }

  /// Record `job` as owed and append it to the queue — the tail every admitted job passes through,
  /// so the order witness and the queue can never disagree about what the lane holds.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn queue(&mut self, job: BlockJob<S>) {
    self.outstanding.push_back(job.id);
    self.jobs.push_back(job);
  }

  /// Take the next queued job, or `None` when the lane has been handed everything issued so far.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn poll(&mut self) -> Option<BlockJob<S>> {
    self.jobs.pop_front()
  }

  /// Settle a completion against the lane's own books, BEFORE any endpoint correlation is judged:
  /// check it against the issue-order witness and free the slot (or cap entry) its job held.
  ///
  /// Runs for every completion, whichever incarnation minted it. Both facts belong to the lane —
  /// the order it must execute in, and the depth it is holding — so a completion the endpoint's
  /// incarnation choke goes on to refuse still settles here: the refusal publishes nothing, but it
  /// is the lane's own delivery proving the job (and the cell it occupied) has left the queue.
  ///
  /// The release is EXACT and fail-stop in every profile: a completion the lane never admitted
  /// cannot quietly free a cell that some other job is still holding. It is also unreachable past
  /// the order witness above, which judges the same completion against the same books one step
  /// earlier — the checks are two readings of one obligation, kept separate so the message names
  /// which one a violating backend broke.
  pub(crate) fn settle(&mut self, done: &BlockJobDone<S>) {
    let id = done.id();
    let expected = self.outstanding.pop_front();
    assert_eq!(
      expected,
      Some(id),
      "block job completion out of issue order (expected {expected:?}) — the storage lane must \
       execute jobs serially in issue order and deliver completions in that same order",
    );
    match singleton(done.tag()) {
      Some((slot, noun)) => {
        assert_eq!(
          self.singletons[slot],
          Some(id),
          "the lane never admitted the {noun} this completion answers",
        );
        self.singletons[slot] = None;
      }
      None => {
        let held = self
          .serves
          .iter()
          .position(|&serve| serve == id)
          .expect("the lane never admitted the serve this completion answers");
        self.serves.remove(held);
      }
    }
  }
}

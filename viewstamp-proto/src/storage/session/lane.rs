//! The block lane's front: the queue an endpoint issues into, the admission quotas that bound the
//! lane's depth, and the issue-order witness.
//!
//! Everything here describes what the LANE still owes, whichever endpoint incarnation issued it, so
//! all of it has the lane's lifetime rather than any endpoint's. That is why it lives in the
//! [`Storage`](super::Storage) session: an un-polled job and the quota it occupies are ONE object,
//! so they cannot come apart across an endpoint rebuild — the successor polls what its predecessor
//! queued and the (refused) completion releases the quota that admitted it. Keeping the queue on
//! the endpoint while relaying the quota is what let a rebuild inherit a claim no lane could ever
//! release.

use std::collections::VecDeque;

use crate::{
  JobId,
  block_job::{BlockJob, BlockJobDone, BlockJobKind, BlockJobTag},
  state_machine::StateMachine,
};

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
  /// The `Materialize` the lane still owes a completion for, if any. At most one image capture may
  /// be on the lane at a time: each carries a full state-machine image plus a session projection,
  /// and a view transition (or a rebuild) that abandons the checkpoint it belonged to cannot
  /// retract the job, so a second capture admitted behind it would grow the queue by one full image
  /// per abandonment.
  materializing: Option<JobId>,
  /// How many `Serve` jobs the lane still owes completions for, counted against
  /// `MAX_OUTSTANDING_BLOCK_SERVES` at admission so an inbound `RequestBlock` rate above the lane's
  /// drain rate cannot grow the queue without limit.
  serves: usize,
  /// The `Walk` the lane still owes a completion for, if any. One frontier step per lane: a walk
  /// carries the transfer's frontiers, bounded only by the reachable-block cap, and every arming of
  /// a fresh transfer issues one — so without this quota each abandoned transfer (a view
  /// transition, a re-pin, a rebuild) would leave its walk queued and add another.
  walk: Option<JobId>,
}

impl<S: StateMachine> LaneFront<S> {
  /// The front of a lane that has been handed nothing.
  pub(crate) const fn new() -> Self {
    Self {
      jobs: VecDeque::new(),
      outstanding: VecDeque::new(),
      materializing: None,
      serves: 0,
      walk: None,
    }
  }

  /// Whether the lane owes any completion — queued or executing.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn owes_completion(&self) -> bool {
    !self.outstanding.is_empty()
  }

  /// Whether the lane already holds an un-consumed image capture.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn materialize_owed(&self) -> bool {
    self.materializing.is_some()
  }

  /// How many `Serve` jobs the lane holds.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn serves_outstanding(&self) -> usize {
    self.serves
  }

  /// Whether the lane already holds a frontier walk.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn walk_owed(&self) -> bool {
    self.walk.is_some()
  }

  /// Queue `id`'s job: claim the quota its kind occupies, record the completion as owed, and append
  /// to the queue. The single admission point, so no job can be queued without being ordered and
  /// accounted, and no quota can be claimed for a job that is not queued.
  pub(crate) fn enqueue(&mut self, id: JobId, kind: BlockJobKind<S>) {
    let job = BlockJob { id, kind };
    match job.tag() {
      BlockJobTag::Materialize => {
        assert!(
          self.materializing.is_none(),
          "a second image capture was queued while the lane still owes one ({:?})",
          self.materializing,
        );
        self.materializing = Some(id);
      }
      BlockJobTag::Serve => self.serves += 1,
      BlockJobTag::Walk => {
        assert!(
          self.walk.is_none(),
          "a second frontier walk was queued while the lane still owes one ({:?})",
          self.walk,
        );
        self.walk = Some(id);
      }
      // Sweeps, barriers and reconstructs are bounded by the state that issues them (one owed
      // install, one owed obligation, one sweep per checkpoint), so they claim no lane quota. Named
      // rather than matched by a wildcard: a new kind that DOES need bounding must be classified
      // here instead of silently falling through.
      BlockJobTag::Flush | BlockJobTag::Gc | BlockJobTag::Restore => {}
    }
    self.outstanding.push_back(id);
    self.jobs.push_back(job);
  }

  /// Take the next queued job, or `None` when the lane has been handed everything issued so far.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn poll(&mut self) -> Option<BlockJob<S>> {
    self.jobs.pop_front()
  }

  /// Settle a completion against the lane's own books, BEFORE any endpoint correlation is judged:
  /// check it against the issue-order witness and release the quota its job occupied.
  ///
  /// Runs for every completion, whichever incarnation minted it. Both facts belong to the lane —
  /// the order it must execute in, and the depth it is holding — so a completion the endpoint's
  /// incarnation choke goes on to refuse still settles here: the refusal publishes nothing, but it
  /// is the lane's own delivery proving the job (and the image or cap slot it occupied) has left
  /// the queue.
  pub(crate) fn settle(&mut self, done: &BlockJobDone<S>) {
    let id = done.id();
    let expected = self.outstanding.pop_front();
    assert_eq!(
      expected,
      Some(id),
      "block job completion out of issue order (expected {expected:?}) — the storage lane must \
       execute jobs serially in issue order and deliver completions in that same order",
    );
    match done.tag() {
      BlockJobTag::Materialize => {
        debug_assert_eq!(
          self.materializing,
          Some(id),
          "an image capture completed that the lane never admitted",
        );
        self.materializing = None;
      }
      BlockJobTag::Serve => {
        debug_assert!(
          self.serves > 0,
          "a serve completed that the lane never admitted",
        );
        self.serves = self.serves.saturating_sub(1);
      }
      BlockJobTag::Walk => {
        debug_assert_eq!(
          self.walk,
          Some(id),
          "a frontier walk completed that the lane never admitted",
        );
        self.walk = None;
      }
      BlockJobTag::Flush | BlockJobTag::Gc | BlockJobTag::Restore => {}
    }
  }
}

//! The driver-level reconfiguration executor: `reconfigure_to` and its types. It drives the pure proto
//! planner (`plan_next_step` / `shrink_candidates`) one Tier B `propose_membership` at a time, re-planning
//! from the live membership each step, with a health-aware fail-closed shrink ordering. Adds ZERO proto
//! consensus surface.

use std::{
  collections::BTreeSet,
  future::Future,
  pin::Pin,
  sync::{Arc, Mutex},
  time::Duration,
  vec::Vec,
};

use viewstamp_proto::{
  Epoch, Instant, MemberId, Membership, MembershipTarget, OpNumber, PlanError,
  ProposeMembershipError, SingleVoterDelta,
};

/// An OPTIONAL operator-supplied liveness hint for the shrink phase, split into a NEGATIVE set and a
/// POSITIVE set that play DISTINCT roles. The AUTHORITATIVE health source (the automatic responsiveness
/// oracle cannot prove survival and is blind on an idle cluster). Both fields are LIVENESS hints ONLY,
/// NEVER a safety input: a wrong entry can only stall or re-order a (still-individually-safe) removal.
///
/// - `known_down` is NEGATIVE-only: a voter listed here is treated as down — disqualified from any
///   successor quorum, prioritized for removal first. ABSENCE from `known_down` is NOT evidence of life.
/// - `known_up` is POSITIVE-only: a voter listed here is operator-CONFIRMED alive and counts toward a
///   successor quorum's positive evidence.
///
/// `Default` (both empty) means "no operator hint — rely on the automatic oracle", which on an idle
/// cluster makes the shrink STALL fail-closed rather than guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthHint {
  known_down: BTreeSet<MemberId>,
  known_up: BTreeSet<MemberId>,
}

impl HealthHint {
  /// No operator hint (both sets empty) — rely on the automatic oracle alone.
  #[must_use]
  pub const fn new() -> Self {
    Self {
      known_down: BTreeSet::new(),
      known_up: BTreeSet::new(),
    }
  }

  /// NEGATIVE: voters the operator KNOWS are down (disqualified from any successor quorum, removed
  /// first). Absence from the set is NOT evidence of life.
  #[must_use]
  pub fn with_known_down(mut self, members: BTreeSet<MemberId>) -> Self {
    self.known_down = members;
    self
  }

  /// POSITIVE: voters the operator CONFIRMS are alive (counted toward a successor quorum's positive
  /// evidence).
  #[must_use]
  pub fn with_known_up(mut self, members: BTreeSet<MemberId>) -> Self {
    self.known_up = members;
    self
  }

  /// The operator-declared down set.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn known_down(&self) -> &BTreeSet<MemberId> {
    &self.known_down
  }

  /// The operator-confirmed alive set.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn known_up(&self) -> &BTreeSet<MemberId> {
    &self.known_up
  }
}

impl Default for HealthHint {
  fn default() -> Self {
    Self::new()
  }
}

/// What the plan reached when a bounded-loop outcome fired. The cluster is NOT necessarily back at
/// `current`: the grow/promote steps commit before the shrink branch, so a stall on a `RemoveVoter` leaves
/// the intermediate config those steps produced. `live` is the membership the loop last observed.
///
/// INVARIANT: exactly one of `(remaining, reason)` is populated — `remaining: Some(NON-empty valid plan)`
/// with `reason: None` (the plan toward the target is STILL VALID from `live`), OR `remaining: None` with
/// `reason: Some(PlanError)` (a post-start re-plan FAILED). `remaining: Some(vec![])` with `reason: None` is
/// FORBIDDEN (an empty Some reads as "done"); the executor never constructs it (the empty/done case returns
/// `Ok(())` before any progress is built).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconfigureProgress {
  live: Membership,
  remaining: Option<Vec<SingleVoterDelta>>,
  reason: Option<PlanError>,
}

impl ReconfigureProgress {
  /// The live membership the loop reached.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn live(&self) -> &Membership {
    &self.live
  }

  /// The still-pending plan suffix from [`Self::live`] when the plan is STILL VALID — always a
  /// NON-empty slice for a stall; `None` only when a post-start re-plan FAILED (then
  /// [`Self::reason`] holds the `PlanError`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn remaining(&self) -> Option<&[SingleVoterDelta]> {
    self.remaining.as_deref()
  }

  /// WHY the loop stopped: `Some(PlanError)` for a post-start planning failure (paired with
  /// `remaining == None`), or `None` for a deadline/oscillation stall with a valid remaining plan.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn reason(&self) -> Option<&PlanError> {
    self.reason.as_ref()
  }
}

impl ReconfigureProgress {
  /// A deadline/oscillation STALL with a still-valid, NON-EMPTY remaining plan (`reason: None`). The caller
  /// passes the plan it already validated this iteration; this never re-plans, so it cannot swallow a fresh
  /// `PlanError` into a defaulted-empty Vec.
  pub(crate) fn stall(live: Membership, remaining: Vec<SingleVoterDelta>) -> Self {
    debug_assert!(
      !remaining.is_empty(),
      "a stall carries a NON-EMPTY remaining plan"
    );
    Self {
      live,
      remaining: Some(remaining),
      reason: None,
    }
  }

  /// A post-start PLANNING FAILURE: no valid remaining plan exists from `live`, so carry `None` + the
  /// reason (do NOT re-invoke the failing planner nor fabricate a plan).
  pub(crate) fn failed(live: Membership, reason: PlanError) -> Self {
    Self {
      live,
      remaining: None,
      reason: Some(reason),
    }
  }
}

/// An error from the driver-level `reconfigure_to` executor.
///
/// A bare [`Self::InvalidTarget`] means PREFLIGHT — nothing was committed, the cluster is at `current`.
/// Every post-start outcome ([`Self::PlanConflict`], [`Self::Timeout`]) carries [`ReconfigureProgress`] so
/// the operator learns the durable partial state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReconfigureError {
  /// The PREFLIGHT plan (the first step, before any proposal) returned a `PlanError`, OR a pre-commit
  /// `MemberConcurrentlyRemoved`. NOTHING was committed — the cluster is provably at `current`. Not retried.
  #[error("the reconfiguration target is invalid: {0}")]
  InvalidTarget(PlanError),
  /// A COMPETING concurrent reconfiguration changed the live config under this one (the plan oscillates to
  /// the cap), OR a re-plan AFTER ≥1 committed step found the target unreachable. Carries the progress
  /// reached so the operator learns the durable intermediate. EXPECTED, not a hang.
  #[error("the reconfiguration plan conflicts with a concurrent change (resumable)")]
  PlanConflict(ReconfigureProgress),
  /// The attempt/deadline cap elapsed while the plan could not make progress (a fail-closed shrink stall, or
  /// a learner that never caught up). RESUMABLE PARTIAL PROGRESS — re-issue `reconfigure_to(same target)`.
  #[error("the reconfiguration timed out before converging (resumable)")]
  Timeout(ReconfigureProgress),
  /// This driver is no longer the primary; redirect to the new primary (a driver-ergonomics policy).
  #[error("this replica is no longer the primary")]
  NotPrimary,
  /// The driver task has stopped; the channel is permanently closed. TERMINAL — do NOT retry against
  /// this handle. Distinct from `Propose(Busy)` (a full-but-open channel) so callers cannot livelock
  /// polling a dead driver.
  #[error("the driver is gone; redirect to a live replica")]
  DriverGone,
  /// This node removed itself from the configuration and is terminally retired — no longer a cluster
  /// member, so it cannot drive a reconfiguration. TERMINAL — do NOT retry against this handle;
  /// redirect to a live replica. Mirrors [`crate::DriverError::Retired`] for the reconfiguration path.
  #[error("node {local} is retired at epoch {epoch}; redirect to a live replica")]
  Retired {
    /// The local member id the active membership no longer contains.
    local: viewstamp_proto::MemberId,
    /// The configuration epoch this node was retired at.
    epoch: viewstamp_proto::Epoch,
  },
  /// A non-retryable proto proposal verdict (the retryable ones — `ProofPending`/`AlreadyInFlight`/`Busy`/
  /// `AtCapacity` — are handled internally as backoff).
  #[error("the reconfiguration proposal was rejected: {0}")]
  Propose(ProposeMembershipError),
}

/// The I/O surface the executor loop needs, behind a trait so the loop is testable over a mock proto +
/// mock clock without a real runtime. The real driver task implements it against the owned `Endpoint`.
// `async fn` in public trait: all implementations are crate-internal; Send bounds are irrelevant here.
#[allow(async_fn_in_trait)]
pub trait ReconfigureBackend {
  /// The live active membership (re-read every iteration).
  fn live_membership(&self) -> Membership;
  /// The proto responsiveness oracle (the uncommitted-tail recent-ack voter set).
  fn recently_acked_voters(&self, window: u64) -> BTreeSet<MemberId>;
  /// Propose ONE delta and await its commit + epoch-swap install. `Ok(())` once installed; the retryable
  /// proto verdicts are handled by the implementer as backoff and surfaced as a transient retry; a
  /// non-retryable verdict is the `Err`.
  async fn propose_and_await_install(&self, step: SingleVoterDelta)
  -> Result<(), ReconfigureError>;
  /// True once the attempt/deadline cap is exhausted (the mock advances a virtual clock; the real driver
  /// checks `now() > deadline || attempts.exceeded()`).
  fn cap_exhausted(&self) -> bool;
  /// Sleep one backoff quantum (counts against the cap). A no-op tick on the mock.
  async fn backoff(&self);
}

/// Among `candidates` (each a `RemoveVoter(X)` of a departing voter), return one whose successor config
/// `voters(live) \ {X}` holds `>= quorum` voters with POSITIVE evidence of life — a voter counts ALIVE iff
/// it is NOT in `known_down` AND it has a POSITIVE witness (in `known_up` OR in the `responsive` recent-ack
/// set). NEGATIVE-only `known_down` can never CONFIRM the quorum (absence is not a positive witness). Prefer
/// removing an `X` that is apparently down (in `known_down`, or absent from both `known_up` and
/// `responsive`). Self (`local_member`) is ranked LAST unconditionally — not merely as a tie-break within
/// the same liveness bucket — because a local node without positive evidence would otherwise sort before
/// peers that ARE known_up, retiring the driver while peers still need removing.
/// `None` (→ STALL fail-closed) when NO candidate's successor has a positively-confirmed quorum — never a
/// removal on a guess.
fn pick_fresh_quorum_preserving_removal(
  live: &Membership,
  candidates: &[SingleVoterDelta],
  health: &HealthHint,
  responsive: &BTreeSet<MemberId>,
  local_member: MemberId,
) -> Option<SingleVoterDelta> {
  let live_voters: BTreeSet<MemberId> = {
    let n = live.replica_count() as usize;
    live.members_slice()[..n].iter().copied().collect()
  };
  let is_alive = |m: &MemberId| -> bool {
    !health.known_down().contains(m) && (health.known_up().contains(m) || responsive.contains(m))
  };
  // Rank: self LAST (primary sort key — retiring the local driver mid-plan ends the plan),
  // then apparently-DOWN before live (remove unresponsive peers before live ones), then
  // ascending id for determinism.  The self-last key is unconditional: it must not be
  // subordinate to liveness, because otherwise a local node that has no positive evidence
  // (apparently_down) sorts BEFORE peers that ARE known_up and would be retired first.
  let mut ordered: Vec<&SingleVoterDelta> = candidates.iter().collect();
  ordered.sort_by_key(|d| {
    let m = d.member();
    let apparently_down = health.known_down().contains(&m) || !is_alive(&m);
    (m == local_member, !apparently_down, m.get())
  });
  for cand in ordered {
    let x = cand.member();
    let successor: BTreeSet<MemberId> = live_voters.iter().copied().filter(|m| *m != x).collect();
    // quorum of the SUCCESSOR config (floor(n/2)+1).
    let quorum = successor.len() / 2 + 1;
    let confirmed = successor.iter().filter(|m| is_alive(m)).count();
    if confirmed >= quorum {
      return Some(cand.clone());
    }
  }
  None
}

/// Execute the goal as a per-step RE-PLANNING loop. After every installed step it re-derives the next delta
/// from the THEN-LIVE membership, so a concurrent change can never stale a precomputed plan. Honors the
/// proto's retryable verdicts internally (via the backend) and bounds the loop with the attempt/deadline
/// cap, surfacing `PlanConflict`/`Timeout` carrying the live intermediate rather than looping forever.
///
/// PRECONDITIONS: SOLE-DRIVER + every target member ABSENT from `live` MUST be a FRESH, reachable node.
/// The `members_seen` rule (passive observation) refuses to re-add an OBSERVED-then-removed member.
pub async fn run_reconfigure<B: ReconfigureBackend>(
  backend: B,
  target: MembershipTarget,
  health: HealthHint,
  ack_window: u64,
  local_member: MemberId,
) -> Result<(), ReconfigureError> {
  use viewstamp_proto::{plan_reconfiguration, shrink_candidates};

  let target_members = target.members();
  // Seed members_seen with target members already present at the start.
  let mut members_seen: BTreeSet<MemberId> = {
    let live = backend.live_membership();
    live
      .members_slice()
      .iter()
      .copied()
      .filter(|m| target_members.contains(m))
      .collect()
  };
  let mut committed_any = false;

  loop {
    let live = backend.live_membership();

    // (1) PASSIVE OBSERVE: record every target member currently present so a concurrent add is
    // tracked for the concurrent-removal check below.
    members_seen.extend(
      live
        .members_slice()
        .iter()
        .copied()
        .filter(|m| target_members.contains(m)),
    );

    // (2) CONCURRENT-REMOVAL CHECK: a members_seen target member now absent from live was
    // concurrently retired — refuse rather than phantom-re-add.
    let phantom: BTreeSet<MemberId> = members_seen
      .iter()
      .copied()
      .filter(|m| target_members.contains(m) && live.slot_of(*m).is_none())
      .collect();
    if !phantom.is_empty() {
      let err = PlanError::MemberConcurrentlyRemoved { members: phantom };
      return Err(if !committed_any {
        ReconfigureError::InvalidTarget(err)
      } else {
        ReconfigureError::PlanConflict(ReconfigureProgress::failed(live, err))
      });
    }

    // Re-plan from the CURRENT live membership every iteration.
    let plan = plan_reconfiguration(&live, &target);

    // COMPLETION CHECK FIRST — before the cap: an empty plan means sets(live) == target => Ok(()).
    if let Ok(ref p) = plan
      && p.is_empty()
    {
      return Ok(());
    }

    // Cap fires only after completion is ruled out.
    if backend.cap_exhausted() {
      return match plan {
        Ok(p) => Err(ReconfigureError::Timeout(ReconfigureProgress::stall(
          live, p,
        ))),
        Err(e) if !committed_any => Err(ReconfigureError::InvalidTarget(e)),
        Err(e) => Err(ReconfigureError::PlanConflict(ReconfigureProgress::failed(
          live, e,
        ))),
      };
    }

    // Extract the next planned step (or surface a plan error).
    let next = match plan {
      Ok(ref p) => p.first().cloned(),
      Err(e) if !committed_any => return Err(ReconfigureError::InvalidTarget(e)),
      Err(e) => {
        return Err(ReconfigureError::PlanConflict(ReconfigureProgress::failed(
          live, e,
        )));
      }
    };

    match next {
      None => return Ok(()),
      Some(step) if !step.is_remove_voter() => {
        // Phases 0/1/2/4: follow plan order verbatim.
        backend.propose_and_await_install(step.clone()).await?;
        committed_any = true;
        // Track newly-staged or promoted target members in members_seen.
        if step.is_add_learner() || step.is_promote_learner() {
          members_seen.insert(step.member());
        }
      }
      Some(_) => {
        // Phase 3 (shrink): choose the removal HEALTH-AWARE rather than the plan's first removal.
        let candidates = match shrink_candidates(&live, &target) {
          Ok(c) => c,
          Err(e) if !committed_any => return Err(ReconfigureError::InvalidTarget(e)),
          Err(e) => {
            return Err(ReconfigureError::PlanConflict(ReconfigureProgress::failed(
              live, e,
            )));
          }
        };
        if candidates.is_empty() {
          // No removals due yet (grow phase still pending after re-plan diverged — safety net).
          backend.backoff().await;
          continue;
        }
        let acked = backend.recently_acked_voters(ack_window);
        match pick_fresh_quorum_preserving_removal(
          &live,
          &candidates,
          &health,
          &acked,
          local_member,
        ) {
          Some(rm) => {
            backend.propose_and_await_install(rm).await?;
            committed_any = true;
          }
          // STALL fail-closed: no removal has positive successor-quorum evidence — count against cap.
          None => backend.backoff().await,
        }
      }
    }
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// LoopBackend / LoopController / ReconfigureJob
// ──────────────────────────────────────────────────────────────────────────────

/// The type carried in the one-slot proposal channel: the delta to propose plus the completion
/// channel the driver uses to answer the backend with a [`StepOutcome`].
type ProposalSlot = Arc<
  Mutex<
    Option<(
      SingleVoterDelta,
      futures_channel::oneshot::Sender<StepOutcome>,
    )>,
  >,
>;

/// The driver's verdict after executing a proposal that `LoopBackend::propose_and_await_install`
/// posted. The driver loop resolves the `oneshot::Sender<StepOutcome>` it received via
/// `LoopController::take_proposal`.
///
/// - `Installed` — the epoch swap that committed the step has been detected; the backend advances to
///   the next planned step.
/// - `Retry` — a retryable proto verdict (`ProofPending` / `AlreadyInFlight` / `Busy` /
///   `AtCapacity`); the backend backs off via `backoff().await` then re-posts the same delta.
/// - `Failed(e)` — a non-retryable terminal error; the backend propagates it as `Err(e)` and the
///   job resolves with that error.
#[derive(Debug)]
pub enum StepOutcome {
  /// The epoch swap is confirmed; the step is installed.
  Installed,
  /// A retryable proto verdict; back off then re-propose.
  Retry,
  /// A non-retryable terminal error.
  Failed(ReconfigureError),
}

/// The snapshot the driver loop writes and `LoopBackend` reads. `Arc<Mutex<>>` so the boxed
/// `run_reconfigure` future is `Send` (the reactor driver spawns it on a multi-thread runtime).
struct Snapshot {
  live: Membership,
  acked: BTreeSet<MemberId>,
  cap_exhausted: bool,
}

/// The shared tick state. Bundled in one `Mutex` so that `tick()` can atomically install the
/// receiver AND wake any parked `backoff()` without a TOCTOU gap.
struct TickState {
  /// A resolved oneshot receiver the backoff future consumes on the next poll.
  rx: Option<futures_channel::oneshot::Receiver<()>>,
  /// Waker registered by `backoff()` when the slot was empty; cleared by `tick()` after waking.
  waker: Option<std::task::Waker>,
}

/// The backend half of the loop-controller pair. Implements [`ReconfigureBackend`] entirely via the
/// shared snapshot + the two channels; it NEVER touches the `Endpoint` or the WAL directly.
///
/// `Send + Sync` because the shared state uses `Arc<Mutex<>>` (not `Rc<RefCell<>>`), which means
/// the boxed `run_reconfigure` future is `Send` and is spawnable on the reactor's multi-thread runtime.
pub struct LoopBackend {
  snapshot: Arc<Mutex<Snapshot>>,
  /// One-slot proposal channel: the backend posts `(delta, reply_tx)` here, the controller drains it.
  /// `Mutex<Option<...>>` gives a non-blocking post + drain without requiring an async runtime.
  proposal: ProposalSlot,
  /// Shared tick state. `tick()` atomically installs a ready receiver AND wakes any parked
  /// `backoff()` future so there is no gap where the wake fires before the receiver is installed.
  tick: Arc<Mutex<TickState>>,
}

/// The controller half — owned by the driver loop. The driver calls its methods once per iteration
/// to feed the `LoopBackend` with fresh state and drain any pending proposal.
pub struct LoopController {
  snapshot: Arc<Mutex<Snapshot>>,
  proposal: ProposalSlot,
  tick: Arc<Mutex<TickState>>,
}

impl LoopBackend {
  /// Construct a matched `(LoopBackend, LoopController)` pair.
  fn new_pair(initial: Snapshot) -> (Self, LoopController) {
    let snapshot = Arc::new(Mutex::new(initial));
    let proposal = Arc::new(Mutex::new(None));
    let tick = Arc::new(Mutex::new(TickState {
      rx: None,
      waker: None,
    }));
    let backend = LoopBackend {
      snapshot: Arc::clone(&snapshot),
      proposal: Arc::clone(&proposal),
      tick: Arc::clone(&tick),
    };
    let controller = LoopController {
      snapshot,
      proposal,
      tick,
    };
    (backend, controller)
  }
}

impl ReconfigureBackend for LoopBackend {
  fn live_membership(&self) -> Membership {
    self
      .snapshot
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .live
      .clone()
  }

  fn recently_acked_voters(&self, _window: u64) -> BTreeSet<MemberId> {
    // The driver loop pre-computes the window-filtered acked set into the snapshot on each refresh.
    self
      .snapshot
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .acked
      .clone()
  }

  fn cap_exhausted(&self) -> bool {
    self
      .snapshot
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .cap_exhausted
  }

  async fn propose_and_await_install(
    &self,
    step: SingleVoterDelta,
  ) -> Result<(), ReconfigureError> {
    loop {
      let (tx, rx) = futures_channel::oneshot::channel();
      {
        // One critical section: assert the slot is drained, then post.
        // A driver that polls without first calling take_proposal() would
        // silently overwrite and orphan the prior oneshot; this catches that in debug.
        let mut slot = self.proposal.lock().unwrap_or_else(|e| e.into_inner());
        debug_assert!(
          slot.is_none(),
          "proposal slot must be drained (take_proposal) before re-posting"
        );
        *slot = Some((step.clone(), tx));
      }
      match rx.await {
        Ok(StepOutcome::Installed) => return Ok(()),
        Ok(StepOutcome::Retry) => {
          self.backoff().await;
          // Re-post after backoff.
          continue;
        }
        Ok(StepOutcome::Failed(e)) => return Err(e),
        Err(_canceled) => {
          // The driver dropped the sender — treat as a non-retryable terminal: the driver is gone.
          return Err(ReconfigureError::DriverGone);
        }
      }
    }
  }

  async fn backoff(&self) {
    // Await the next driver tick. Protocol:
    //   1. Lock `tick`, register the waker, take any already-installed receiver.
    //   2. If a receiver is available: drop the lock, await it, done.
    //   3. If not: return Pending with the waker stored. `tick()` will atomically install a
    //      receiver AND call `waker.wake()`, which re-polls this future.
    //   4. On re-poll: the receiver is now in the slot; take it, drop the lock, await it.
    //
    // The lock is dropped BEFORE any await so the driver can always call `tick()` from its loop
    // without blocking on the backend.
    use std::{future::poll_fn, task::Poll};

    let tick = Arc::clone(&self.tick);
    let mut rx_opt: Option<futures_channel::oneshot::Receiver<()>> = None;

    poll_fn(move |cx| {
      // If we already hold a receiver (from a previous poll), drive it to completion.
      if let Some(ref mut rx) = rx_opt {
        return match Pin::new(rx).poll(cx) {
          Poll::Ready(_) => Poll::Ready(()),
          Poll::Pending => Poll::Pending,
        };
      }
      // Check the tick state. Take any already-installed receiver FIRST; only register
      // the waker when there is no receiver yet. This prevents a concurrent tick() from
      // clearing a freshly-registered waker before we take its receiver.
      let taken = {
        let mut state = tick.lock().unwrap_or_else(|e| e.into_inner());
        let rx = state.rx.take();
        if rx.is_none() {
          // No tick yet — park the waker so tick() can wake us.
          state.waker = Some(cx.waker().clone());
        }
        rx
      };
      if let Some(rx) = taken {
        // A tick has already fired; no waker registration needed.
        rx_opt = Some(rx);
        if let Some(ref mut rx) = rx_opt {
          return match Pin::new(rx).poll(cx) {
            Poll::Ready(_) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
          };
        }
      }
      // No receiver yet; waker is registered. `tick()` will wake us.
      Poll::Pending
    })
    .await
  }
}

impl LoopController {
  /// Overwrite the snapshot with the latest state from the driver's `Endpoint`. Called once per
  /// driver-loop iteration, BEFORE polling the future.
  ///
  /// `ack_window` filtering is done by the DRIVER (which calls `endpoint.recently_acked_voters(ack_window)`
  /// and passes the result directly); the backend's `recently_acked_voters` ignores its own window
  /// argument and returns the pre-filtered set verbatim.
  pub fn refresh(&self, live: Membership, acked: BTreeSet<MemberId>, cap_exhausted: bool) {
    let mut snap = self.snapshot.lock().unwrap_or_else(|e| e.into_inner());
    snap.live = live;
    snap.acked = acked;
    snap.cap_exhausted = cap_exhausted;
  }

  /// Drain the one-slot proposal the backend may have posted. Returns `Some((delta, reply_tx))` if
  /// a proposal is pending; the driver MUST resolve `reply_tx` with a `StepOutcome` at the
  /// appropriate time (immediately for `Retry`/`Failed`, later for `Installed` once the epoch swap
  /// is detected).
  pub fn take_proposal(
    &self,
  ) -> Option<(
    SingleVoterDelta,
    futures_channel::oneshot::Sender<StepOutcome>,
  )> {
    self
      .proposal
      .lock()
      .unwrap_or_else(|e| e.into_inner())
      .take()
  }

  /// Fire the backoff signal. The backend's parked `backoff()` call will be woken and unblocked.
  /// Call once per driver-loop iteration so the backend re-proposes at the loop's natural cadence.
  ///
  /// Creates a new already-resolved oneshot (sender dropped immediately so the receiver is ready)
  /// and atomically installs it in the shared slot, then wakes any registered waker.
  pub fn tick(&self) {
    let (tx, rx) = futures_channel::oneshot::channel::<()>();
    // Drop `tx` immediately; `rx` is now in the `Ready(Err(Canceled))` state, which our
    // `backoff()` poll treats as a successful tick (any resolution unblocks the backoff).
    drop(tx);
    let waker = {
      let mut state = self.tick.lock().unwrap_or_else(|e| e.into_inner());
      state.rx = Some(rx);
      state.waker.take()
    };
    if let Some(w) = waker {
      w.wake();
    }
  }
}

/// The driver field that owns one active reconfiguration job. Constructed by `ReconfigureJob::start`
/// when the driver receives `Command::Reconfigure`; dropped (and `reply` dropped → caller gets
/// `DriverGone`) when the driver tears down with a job in flight.
///
/// The `fut` field is the boxed `run_reconfigure` future driven by the driver loop via `poll`.
/// `Send` bound is satisfied because `LoopBackend` uses `Arc<Mutex<>>` (not `Rc`).
pub struct ReconfigureJob {
  /// The boxed executor future, driven by the driver's poll-once-per-iteration strategy.
  fut: Pin<Box<dyn Future<Output = Result<(), ReconfigureError>> + Send>>,
  /// The controller the driver uses to feed state + drain proposals.
  controller: LoopController,
  /// Completion channel: the driver sends the `run_reconfigure` result here when the future resolves.
  reply: futures_channel::oneshot::Sender<Result<(), ReconfigureError>>,
  /// The op number of the in-flight `propose_membership` call, set once the driver issues it; `None`
  /// when no proposal is outstanding. Carried for the operator-visible diagnostic of which op the
  /// step minted; the install is detected by `expected_config_id`, not this.
  pending_op: Option<OpNumber>,
  /// The config_id the outstanding proposal's successor membership WILL carry once installed, or
  /// `None` when no proposal is outstanding. It is a deterministic function of the predecessor + the
  /// proposed delta (`predecessor.apply_delta(step).config_id()`), so matching the live membership's
  /// `config_id` against it detects the EXACT successor's install — precise where an epoch-advance
  /// check is not (a cross-epoch state-sync install bumps the epoch without installing THIS step).
  expected_config_id: Option<u128>,
  /// The reply channel from `take_proposal`: the driver holds this until the successor's epoch swap
  /// is confirmed (its `config_id` becomes live), then sends `StepOutcome::Installed`.
  pending_step_reply: Option<futures_channel::oneshot::Sender<StepOutcome>>,
  /// The deadline this job's cap fires at: armed `reconfigure_timeout` ahead of the FIRST advance
  /// (`None` until then). Each advance feeds `now >= deadline` to the executor as `cap_exhausted`, so
  /// a stalled plan resolves `Timeout` carrying its durable partial progress rather than spinning.
  deadline: Option<Instant>,
  /// The configured per-call deadline band, used to arm `deadline` on the first advance.
  reconfigure_timeout: Duration,
  /// The reconfiguration goal, stored so the advance-level Timeout path can re-plan and build
  /// accurate `ReconfigureProgress` without re-entering the executor future.
  target: MembershipTarget,
}

/// Outcome of one [`ReconfigureJob::advance`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::Display, derive_more::IsVariant)]
#[display("{}", self.as_str())]
pub enum AdvanceOutcome {
  /// The job is still in progress; continue on the next loop iteration.
  InFlight,
  /// The job completed (ok or err). The reply has already been sent; drop the job.
  Done,
}

impl AdvanceOutcome {
  /// The stable string name of this outcome (snake_case, serialization-stable).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::InFlight => "in_flight",
      Self::Done => "done",
    }
  }
}

impl ReconfigureJob {
  /// Drive one iteration of the reconfiguration loop. Call after `pump_outputs` each iteration.
  ///
  /// `live` and `acked` are snapshotted from the coordinator BEFORE this call (disjoint borrow:
  /// the coordinator is read first, then this method holds `&mut self`). `propose` is a closure
  /// that calls `coord.propose_membership(now, wal, delta)`. Returns [`AdvanceOutcome::InFlight`]
  /// while running, [`AdvanceOutcome::Done`] when the reply has been sent.
  ///
  /// `now` arms the per-call deadline on the first advance and drives the executor's `cap_exhausted`
  /// signal (`now >= deadline`), so a plan that cannot make progress resolves `Timeout` rather than
  /// spinning forever.
  pub fn advance(
    &mut self,
    now: Instant,
    live: Membership,
    acked: std::collections::BTreeSet<MemberId>,
    propose: &mut impl FnMut(SingleVoterDelta) -> Result<OpNumber, ProposeMembershipError>,
  ) -> AdvanceOutcome {
    use std::task::Poll;

    // Arm the deadline on the FIRST advance (not at `start`: the wall clock the job is paced against
    // is the driver's, threaded in here as `now`). From then on the cap fires once it elapses.
    let deadline = *self
      .deadline
      .get_or_insert_with(|| now + self.reconfigure_timeout);
    let cap_exhausted = now >= deadline;

    // Hard-cancel at the advance level BEFORE polling the future. The executor future's own
    // `cap_exhausted` check fires only at the TOP of its loop — if it is parked inside
    // `propose_and_await_install` (waiting on a Retry backoff) or inside `backoff().await` the
    // deadline never fires via the inner path alone. Resolving here guarantees the Timeout is
    // delivered regardless of where the future is parked.
    if cap_exhausted {
      use viewstamp_proto::plan_reconfiguration;
      let progress = match plan_reconfiguration(&live, &self.target) {
        Ok(remaining) if !remaining.is_empty() => ReconfigureProgress::stall(live, remaining),
        Ok(_) => {
          // The re-plan says the target is already reached — race between the cap and the last
          // install completing. Surface Ok(()) rather than a spurious Timeout.
          let (dummy_tx, _dummy_rx) = futures_channel::oneshot::channel();
          let reply = std::mem::replace(&mut self.reply, dummy_tx);
          let _ = reply.send(Ok(()));
          return AdvanceOutcome::Done;
        }
        Err(e) => ReconfigureProgress::failed(live, e),
      };
      let (dummy_tx, _dummy_rx) = futures_channel::oneshot::channel();
      let reply = std::mem::replace(&mut self.reply, dummy_tx);
      let _ = reply.send(Err(ReconfigureError::Timeout(progress)));
      return AdvanceOutcome::Done;
    }

    // Capture the live config_id before moving `live` into refresh: the install check below compares
    // it against the successor config_id the outstanding proposal is awaiting.
    let live_config_id = live.config_id();

    // 1. Install detection: the outstanding step committed once the live membership's config_id
    //    equals the successor's predicted id. This is EXACT — an epoch advance alone is not (a
    //    cross-epoch state-sync install bumps the epoch without installing THIS step's successor).
    if let Some(expected) = self.expected_config_id
      && live_config_id == expected
    {
      self.expected_config_id = None;
      self.pending_op = None;
      if let Some(sr) = self.pending_step_reply.take() {
        let _ = sr.send(StepOutcome::Installed);
      }
    }

    // 2. Refresh the controller snapshot with the latest state.
    self.controller.refresh(live.clone(), acked, cap_exhausted);

    // 3. Poll the future once with a noop waker (the driver loop's timer cadence re-polls at the
    //    50ms fallback, which is the natural reconfigure advancement cadence). We construct the
    //    noop waker manually to avoid a dependency on `futures-util` in this non-dev context.
    use std::task::{RawWaker, RawWakerVTable, Waker};
    const NOOP_VTABLE: RawWakerVTable =
      RawWakerVTable::new(|p| RawWaker::new(p, &NOOP_VTABLE), |_| {}, |_| {}, |_| {});
    // SAFETY: the vtable no-ops are correct for a waker that never actually wakes anything; the
    // data pointer is never dereferenced by these fns.
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &NOOP_VTABLE)) };
    let mut cx = std::task::Context::from_waker(&waker);
    match self.fut.as_mut().poll(&mut cx) {
      Poll::Ready(result) => {
        // Consume `reply` by swapping in a dummy inert sender (its receiver is dropped immediately
        // so the send has no observable effect) and sending on the real one.
        let (dummy_tx, _dummy_rx) = futures_channel::oneshot::channel();
        let reply = std::mem::replace(&mut self.reply, dummy_tx);
        let _ = reply.send(result); // receiver may already be gone; ignore
        return AdvanceOutcome::Done;
      }
      Poll::Pending => {}
    }

    // 4. Drain any proposal the future posted during the poll and act on it.
    if let Some((delta, step_reply)) = self.controller.take_proposal() {
      // The future planned this delta from the snapshot just refreshed (`live`), so `live` is the
      // predecessor: predict the successor's config_id (a deterministic function of predecessor +
      // delta) for the EXACT install detection above. A delta the predecessor rejects yields `None`,
      // and the proto's propose gate then surfaces the same rejection as the proposal verdict.
      let expected = live.apply_delta(&delta).ok().map(|m| m.config_id());
      match propose(delta) {
        Ok(op) => {
          self.pending_op = Some(op);
          self.expected_config_id = expected;
          self.pending_step_reply = Some(step_reply);
        }
        Err(
          ProposeMembershipError::ProofPending
          | ProposeMembershipError::AlreadyInFlight
          | ProposeMembershipError::Busy
          | ProposeMembershipError::AtCapacity
          | ProposeMembershipError::NotNormal,
        ) => {
          // Transient: signal the backend to back off and re-post on the next iteration.
          let _ = step_reply.send(StepOutcome::Retry);
        }
        Err(ProposeMembershipError::NotPrimary) => {
          let _ = step_reply.send(StepOutcome::Failed(ReconfigureError::NotPrimary));
        }
        Err(e) => {
          let _ = step_reply.send(StepOutcome::Failed(ReconfigureError::Propose(e)));
        }
      }
    }

    // Advance the executor's backoff every iteration: when it parks on `backoff().await` — whether
    // after a retryable proposal OR a fail-closed shrink stall (no witness, no proposal posted) — the
    // tick is what re-polls it so its loop re-checks `cap_exhausted`. Without a per-iteration tick a
    // stall would park forever and never observe the deadline, so the `Timeout` path would be dead.
    // The pacing is the driver loop's own cadence (one advance per wake), not a blocking backoff.
    self.controller.tick();

    AdvanceOutcome::InFlight
  }

  /// Build a `ReconfigureJob` for `target`. Boxes `run_reconfigure` into a `Send` pinned future,
  /// initialises the controller with the initial snapshot (the driver still calls
  /// `controller.refresh(...)` before each poll), and stores `reply` for the job's completion.
  ///
  /// The deadline is not armed here — it is armed `reconfigure_timeout` ahead of the FIRST advance,
  /// against the driver's clock threaded in as `now` — so the initial snapshot's `cap_exhausted` is
  /// `false`.
  #[allow(clippy::too_many_arguments)] // all params are load-bearing; a builder struct adds indirection without clarity
  pub fn start(
    target: MembershipTarget,
    health: HealthHint,
    ack_window: u64,
    reconfigure_timeout: Duration,
    reply: futures_channel::oneshot::Sender<Result<(), ReconfigureError>>,
    initial_live: Membership,
    initial_acked: BTreeSet<MemberId>,
    local_member: MemberId,
  ) -> Self {
    let (backend, controller) = LoopBackend::new_pair(Snapshot {
      live: initial_live,
      acked: initial_acked,
      cap_exhausted: false,
    });
    let fut: Pin<Box<dyn Future<Output = Result<(), ReconfigureError>> + Send>> = Box::pin(
      run_reconfigure(backend, target.clone(), health, ack_window, local_member),
    );
    ReconfigureJob {
      fut,
      controller,
      reply,
      pending_op: None,
      expected_config_id: None,
      pending_step_reply: None,
      deadline: None,
      reconfigure_timeout,
      target,
    }
  }

  /// Terminally finish this job because the local endpoint has RETIRED — either it removed itself as
  /// this job's final step, or a CONCURRENT configuration change removed it while this job still held
  /// an outstanding proposal. Consumes the job (its outstanding step is DISCARDED — a retired endpoint
  /// installs nothing further) and resolves the caller's future.
  ///
  /// The outcome distinguishes the two facts a retirement can carry, reusing the executor's own goal
  /// test (`plan_reconfiguration(live, target)` yielding an EMPTY plan):
  /// - GOAL ALREADY REACHED — the reconfiguration actually completed (`sets(live) == target`): resolve
  ///   `Ok(())`. The local removal is a SEPARATE fact the caller reads from the terminal driver state.
  /// - OTHERWISE — the goal is unreachable from here (the concurrent removal displaced it): resolve the
  ///   terminal [`ReconfigureError::Retired`], carrying the same `(local, epoch)` the [`crate::retire`]
  ///   latch records.
  ///
  /// Without this the driver leaves the job parked: [`Self::advance`] resolves an outstanding step only
  /// once the live `config_id` reaches the awaited successor, which a competing removal makes
  /// unreachable — so the caller would wait out the whole `reconfigure_timeout` and receive a
  /// misleading (resumable) [`ReconfigureError::Timeout`] instead of the terminal `Retired`.
  pub fn finish_on_retire(self, live: Membership, local: MemberId, epoch: Epoch) {
    use viewstamp_proto::plan_reconfiguration;
    let result = match plan_reconfiguration(&live, &self.target) {
      Ok(plan) if plan.is_empty() => Ok(()),
      _ => Err(ReconfigureError::Retired { local, epoch }),
    };
    let _ = self.reply.send(result);
  }
}

/// Finish an in-flight reconfiguration [`ReconfigureJob`] when the local endpoint retires, then EMPTY
/// the slot — the companion to [`crate::retire`] for the STARTED-job case. The run loop calls this at
/// its `StatusChanged(Retired)` site right after `retire`: `retire` fails the in-flight SUBMITS, this
/// finishes the in-flight reconfiguration JOB. A `None` slot (no job in flight) is a no-op.
///
/// See [`ReconfigureJob::finish_on_retire`] for the resolution rule (goal reached → `Ok(())`, else the
/// terminal [`ReconfigureError::Retired`]).
pub fn finish_reconfigure_on_retire(
  reconfigure: &mut Option<ReconfigureJob>,
  live: Membership,
  local: MemberId,
  epoch: Epoch,
) {
  if let Some(job) = reconfigure.take() {
    job.finish_on_retire(live, local, epoch);
  }
}

#[cfg(test)]
mod tests;

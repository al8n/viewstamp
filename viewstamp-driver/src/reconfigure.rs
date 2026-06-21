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
  Instant, MemberId, Membership, MembershipTarget, OpNumber, PlanError, ProposeMembershipError,
  SingleVoterDelta,
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthHint {
  /// NEGATIVE: voters the operator KNOWS are down (disqualify from any successor quorum + remove first).
  pub known_down: BTreeSet<MemberId>,
  /// POSITIVE: voters the operator CONFIRMS are alive (count toward a successor quorum's positive evidence).
  pub known_up: BTreeSet<MemberId>,
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
  /// The live membership the loop reached.
  pub live: Membership,
  /// The still-pending plan suffix from `live` when the plan is STILL VALID — always `Some(NON-empty)` for
  /// a stall; `None` only when a post-start re-plan FAILED (then `reason` holds the `PlanError`).
  pub remaining: Option<Vec<SingleVoterDelta>>,
  /// WHY the loop stopped: `Some(PlanError)` for a post-start planning failure (paired with
  /// `remaining == None`), or `None` for a deadline/oscillation stall with a valid `remaining`.
  pub reason: Option<PlanError>,
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
/// `responsive`). Self (`local_member`) is ranked LAST among candidates at equal liveness: removing the
/// local driver node mid-plan terminates the driver, so a peer removal is always preferred when available.
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
    !health.known_down.contains(m) && (health.known_up.contains(m) || responsive.contains(m))
  };
  // Rank: apparently-DOWN first, then self LAST (removing the local driver node mid-plan terminates
  // the driver, so a peer removal is always preferred), then ascending id for determinism.
  let mut ordered: Vec<&SingleVoterDelta> = candidates.iter().collect();
  ordered.sort_by_key(|d| {
    let m = d.member();
    let apparently_down = health.known_down.contains(&m) || !is_alive(&m);
    (!apparently_down, m == local_member, m.get())
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
        // A chunk-C driver that polls without first calling take_proposal() would
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
  pub fut: Pin<Box<dyn Future<Output = Result<(), ReconfigureError>> + Send>>,
  /// The controller the driver uses to feed state + drain proposals.
  pub controller: LoopController,
  /// Completion channel: the driver sends the `run_reconfigure` result here when the future resolves.
  pub reply: futures_channel::oneshot::Sender<Result<(), ReconfigureError>>,
  /// The op number of the in-flight `propose_membership` call, set once the driver issues it; `None`
  /// when no proposal is outstanding. Carried for the operator-visible diagnostic of which op the
  /// step minted; the install is detected by `expected_config_id`, not this.
  pub pending_op: Option<OpNumber>,
  /// The config_id the outstanding proposal's successor membership WILL carry once installed, or
  /// `None` when no proposal is outstanding. It is a deterministic function of the predecessor + the
  /// proposed delta (`predecessor.apply_delta(step).config_id()`), so matching the live membership's
  /// `config_id` against it detects the EXACT successor's install — precise where an epoch-advance
  /// check is not (a cross-epoch state-sync install bumps the epoch without installing THIS step).
  pub expected_config_id: Option<u128>,
  /// The reply channel from `take_proposal`: the driver holds this until the successor's epoch swap
  /// is confirmed (its `config_id` becomes live), then sends `StepOutcome::Installed`.
  pub pending_step_reply: Option<futures_channel::oneshot::Sender<StepOutcome>>,
  /// The deadline this job's cap fires at: armed `reconfigure_timeout` ahead of the FIRST advance
  /// (`None` until then). Each advance feeds `now >= deadline` to the executor as `cap_exhausted`, so
  /// a stalled plan resolves `Timeout` carrying its durable partial progress rather than spinning.
  pub deadline: Option<Instant>,
  /// The configured per-call deadline band, used to arm `deadline` on the first advance.
  reconfigure_timeout: Duration,
  /// The reconfiguration goal, stored so the advance-level Timeout path can re-plan and build
  /// accurate `ReconfigureProgress` without re-entering the executor future.
  target: MembershipTarget,
}

/// Outcome of one [`ReconfigureJob::advance`] call.
pub enum AdvanceOutcome {
  /// The job is still in progress; continue on the next loop iteration.
  InFlight,
  /// The job completed (ok or err). The reply has already been sent; drop the job.
  Done,
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
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::{cell::RefCell, rc::Rc};

  // ── helpers ──────────────────────────────────────────────────────────────

  fn member_set(ids: &[u128]) -> BTreeSet<MemberId> {
    ids.iter().copied().map(MemberId::new).collect()
  }

  fn membership_of(voters: &[u128]) -> Membership {
    let m: Vec<MemberId> = voters.iter().copied().map(MemberId::new).collect();
    Membership::genesis(voters.len() as u8, 0, m).unwrap()
  }

  fn sets_of(m: &Membership) -> (BTreeSet<MemberId>, BTreeSet<MemberId>) {
    let n = m.replica_count() as usize;
    let v: BTreeSet<MemberId> = m.members_slice()[..n].iter().copied().collect();
    let l: BTreeSet<MemberId> = m.members_slice()[n..].iter().copied().collect();
    (v, l)
  }

  // ── mock backend ─────────────────────────────────────────────────────────

  type Injector = Box<dyn FnMut(&mut MockState, &[SingleVoterDelta])>;

  struct MockState {
    live: Membership,
    acked: BTreeSet<MemberId>,
    issued: Vec<SingleVoterDelta>,
    steps_left: u32,
    inject: Option<Injector>,
  }

  struct Mock(RefCell<MockState>);

  fn mock(voters: &[u128], acked: &[u128]) -> Rc<Mock> {
    Rc::new(Mock(RefCell::new(MockState {
      live: membership_of(voters),
      acked: acked.iter().copied().map(MemberId::new).collect(),
      issued: Vec::new(),
      steps_left: 64,
      inject: None,
    })))
  }

  fn mock_with_injector(voters: &[u128], acked: &[u128], inject: Injector) -> Rc<Mock> {
    let m = mock(voters, acked);
    m.0.borrow_mut().inject = Some(inject);
    m
  }

  fn install_into(state: &mut MockState, step: &SingleVoterDelta) {
    state.live = state
      .live
      .apply_delta(step)
      .expect("a planned step installs on the mock");
  }

  impl ReconfigureBackend for Rc<Mock> {
    fn live_membership(&self) -> Membership {
      self.0.borrow().live.clone()
    }

    fn recently_acked_voters(&self, _window: u64) -> BTreeSet<MemberId> {
      self.0.borrow().acked.clone()
    }

    async fn propose_and_await_install(
      &self,
      step: SingleVoterDelta,
    ) -> Result<(), ReconfigureError> {
      let mut state = self.0.borrow_mut();
      state.steps_left = state.steps_left.saturating_sub(1);
      state.issued.push(step.clone());
      install_into(&mut state, &step);
      // Run the competitor injector AFTER this step installs.
      if let Some(mut inj) = state.inject.take() {
        let trace = state.issued.clone();
        inj(&mut state, &trace);
        state.inject = Some(inj);
      }
      Ok(())
    }

    fn cap_exhausted(&self) -> bool {
      self.0.borrow().steps_left == 0
    }

    async fn backoff(&self) {
      let mut state = self.0.borrow_mut();
      state.steps_left = state.steps_left.saturating_sub(1);
    }
  }

  /// Drive the executor loop to completion using a no-op waker: the mock's futures resolve
  /// synchronously, so repeated polls always terminate (bounded by the attempt cap).
  fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut fut = std::pin::pin!(f);
    let waker = futures_util::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    loop {
      match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => return v,
        std::task::Poll::Pending => continue,
      }
    }
  }

  /// Injector: once `id` is promoted to a voter, a competitor removes it.
  fn remove_after_promote(id: MemberId) -> Injector {
    Box::new(move |state, _trace| {
      if let Some(slot) = state.live.slot_of(id)
        && state.live.is_voter(slot)
        && state.live.replica_count() > 1
      {
        state.live = state
          .live
          .apply_delta(&SingleVoterDelta::RemoveVoter(id))
          .unwrap();
      }
    })
  }

  /// Injector: toggle `id` in/out of the voter set each step (opposing-target oscillation).
  fn oscillate_voter(id: MemberId) -> Injector {
    Box::new(move |state, _trace| match state.live.slot_of(id) {
      Some(slot) if state.live.is_voter(slot) && state.live.replica_count() > 1 => {
        state.live = state
          .live
          .apply_delta(&SingleVoterDelta::RemoveVoter(id))
          .unwrap();
      }
      None => {
        state.live = state
          .live
          .apply_delta(&SingleVoterDelta::AddLearner(id))
          .and_then(|m| m.apply_delta(&SingleVoterDelta::PromoteLearner(id)))
          .unwrap();
      }
      _ => {}
    })
  }

  // ── T5 regression tests (pre-existing) ───────────────────────────────────

  #[test]
  fn health_hint_default_is_empty() {
    let h = HealthHint::default();
    assert!(h.known_down.is_empty() && h.known_up.is_empty());
  }

  #[test]
  fn stall_progress_carries_a_valid_remaining_plan_and_no_reason() {
    let live = membership_of(&[1, 2, 3]);
    let plan = std::vec![SingleVoterDelta::RemoveVoter(MemberId::new(3))];
    let p = ReconfigureProgress::stall(live.clone(), plan.clone());
    assert_eq!(p.remaining, Some(plan));
    assert_eq!(p.reason, None);
    assert_eq!(p.live, live);
  }

  #[test]
  fn failed_progress_carries_the_reason_and_no_remaining() {
    let live = membership_of(&[1, 2, 3]);
    let p = ReconfigureProgress::failed(live.clone(), PlanError::VoterLearnerOverlap);
    assert_eq!(p.remaining, None);
    assert_eq!(p.reason, Some(PlanError::VoterLearnerOverlap));
  }

  #[test]
  fn reconfigure_error_display_renders_for_each_variant() {
    let live = membership_of(&[1]);
    let errs = [
      ReconfigureError::InvalidTarget(PlanError::EmptyVoterSet),
      ReconfigureError::PlanConflict(ReconfigureProgress::failed(
        live.clone(),
        PlanError::VoterLearnerOverlap,
      )),
      ReconfigureError::Timeout(ReconfigureProgress::stall(
        live.clone(),
        std::vec![SingleVoterDelta::RemoveVoter(MemberId::new(1))],
      )),
      ReconfigureError::NotPrimary,
      ReconfigureError::DriverGone,
      ReconfigureError::Propose(ProposeMembershipError::NotPrimary),
    ];
    for e in &errs {
      assert!(!std::format!("{e}").is_empty());
    }
  }

  // ── T6 executor tests ─────────────────────────────────────────────────────

  #[test]
  fn grow_converges_add_one_replica() {
    // {1,2,3} -> {1,2,3,4}: AddLearner(4) then PromoteLearner(4).
    let backend = mock(&[1, 2, 3], &[1, 2, 3]);
    let target = MembershipTarget::new(member_set(&[1, 2, 3, 4]), BTreeSet::new());
    let r = block_on(run_reconfigure(
      backend.clone(),
      target,
      HealthHint::default(),
      64,
      MemberId::new(1),
    ));
    assert!(r.is_ok());
    assert_eq!(
      backend.0.borrow().issued,
      std::vec![
        SingleVoterDelta::AddLearner(MemberId::new(4)),
        SingleVoterDelta::PromoteLearner(MemberId::new(4)),
      ]
    );
  }

  #[test]
  fn shrink_removes_the_dead_voter_first_via_known_down_and_known_up() {
    // {1,2,3} -> {1}, node 3 down. known_down={3}, known_up={1,2} => RemoveVoter(3) BEFORE RemoveVoter(2).
    let backend = mock(&[1, 2, 3], &[]); // idle oracle
    let target = MembershipTarget::new(member_set(&[1]), BTreeSet::new());
    let health = HealthHint {
      known_down: member_set(&[3]),
      known_up: member_set(&[1, 2]),
    };
    let r = block_on(run_reconfigure(
      backend.clone(),
      target,
      health,
      64,
      MemberId::new(1),
    ));
    assert!(r.is_ok());
    let issued = backend.0.borrow();
    let rm3 = issued
      .issued
      .iter()
      .position(|d| *d == SingleVoterDelta::RemoveVoter(MemberId::new(3)));
    let rm2 = issued
      .issued
      .iter()
      .position(|d| *d == SingleVoterDelta::RemoveVoter(MemberId::new(2)));
    assert!(
      rm3.unwrap() < rm2.unwrap(),
      "the DOWN voter 3 is removed before the live voter 2"
    );
  }

  #[test]
  fn idle_cluster_with_no_witness_stalls_to_timeout_unperturbed() {
    // Shrink-only {1,2,3} -> {1}, idle oracle, NO known_up: stalls on the FIRST removal.
    let backend = mock(&[1, 2, 3], &[]);
    let target = MembershipTarget::new(member_set(&[1]), BTreeSet::new());
    let r = block_on(run_reconfigure(
      backend.clone(),
      target,
      HealthHint::default(),
      8,
      MemberId::new(1),
    ));
    match r {
      Err(ReconfigureError::Timeout(p)) => {
        assert!(
          p.remaining.as_ref().is_some_and(|v| !v.is_empty()) && p.reason.is_none(),
          "stall carries a non-empty remaining plan and no reason"
        );
      }
      other => panic!("expected Timeout, got {other:?}"),
    }
    assert!(
      backend.0.borrow().issued.is_empty(),
      "no RemoveVoter was issued (fail-closed)"
    );
  }

  #[test]
  fn known_down_only_on_idle_cluster_stalls_negative_is_not_life_evidence() {
    // {1,2,3} -> {1}, ONLY known_down={3}, NO known_up, idle oracle: stalls (no positive evidence).
    let backend = mock(&[1, 2, 3], &[]);
    let target = MembershipTarget::new(member_set(&[1]), BTreeSet::new());
    let health = HealthHint {
      known_down: member_set(&[3]),
      known_up: BTreeSet::new(),
    };
    let r = block_on(run_reconfigure(
      backend.clone(),
      target,
      health,
      8,
      MemberId::new(1),
    ));
    assert!(matches!(r, Err(ReconfigureError::Timeout(_))));
    assert!(backend.0.borrow().issued.is_empty());
  }

  #[test]
  fn concurrent_removal_of_a_needed_member_surfaces_member_concurrently_removed() {
    // {1,2,3} -> {1,2,3,4}: stage+promote 4 (committed_any), then competitor RemoveVoter(4).
    let backend = mock_with_injector(
      &[1, 2, 3],
      &[1, 2, 3],
      remove_after_promote(MemberId::new(4)),
    );
    let target = MembershipTarget::new(member_set(&[1, 2, 3, 4]), BTreeSet::new());
    let r = block_on(run_reconfigure(
      backend.clone(),
      target,
      HealthHint::default(),
      64,
      MemberId::new(1),
    ));
    match r {
      Err(ReconfigureError::PlanConflict(p)) => {
        assert_eq!(
          p.reason,
          Some(PlanError::MemberConcurrentlyRemoved {
            members: member_set(&[4])
          })
        );
        assert_eq!(p.remaining, None);
      }
      other => panic!("expected PlanConflict(MemberConcurrentlyRemoved), got {other:?}"),
    }
    let issued = backend.0.borrow();
    assert_eq!(
      issued
        .issued
        .iter()
        .filter(|d| d.is_add_learner() && d.member() == MemberId::new(4))
        .count(),
      1,
      "AddLearner(4) issued ONCE — never re-issued after the concurrent removal"
    );
  }

  #[test]
  fn competing_planner_oscillation_surfaces_plan_conflict_within_the_cap() {
    // Opposing targets via an injector toggling voter 4 in/out each step.
    let backend = mock_with_injector(&[1, 2, 3], &[1, 2, 3], oscillate_voter(MemberId::new(4)));
    let target = MembershipTarget::new(member_set(&[1, 2, 3, 4]), BTreeSet::new());
    let r = block_on(run_reconfigure(
      backend.clone(),
      target,
      HealthHint::default(),
      16,
      MemberId::new(1),
    ));
    assert!(
      matches!(
        r,
        Err(ReconfigureError::PlanConflict(_)) | Err(ReconfigureError::Timeout(_))
      ),
      "expected PlanConflict or Timeout under oscillation"
    );
    assert!(
      backend.0.borrow().issued.len() <= 16,
      "the loop is BOUNDED by the 16-attempt cap"
    );
  }

  #[test]
  fn resumable_progress_after_committed_grow_steps() {
    // {1,2,3} -> {1,2,4}: grow steps commit (4 staged+promoted), then shrink stalls (no witness).
    let backend = mock(&[1, 2, 3], &[]); // idle: the shrink stalls
    let target = MembershipTarget::new(member_set(&[1, 2, 4]), BTreeSet::new());
    let r = block_on(run_reconfigure(
      backend.clone(),
      target,
      HealthHint::default(),
      16,
      MemberId::new(1),
    ));
    match r {
      Err(ReconfigureError::Timeout(p)) => {
        let (v, _) = sets_of(&p.live);
        assert_eq!(
          v,
          member_set(&[1, 2, 3, 4]),
          "the durable INTERMEDIATE, not the original"
        );
        assert_eq!(
          p.remaining,
          Some(std::vec![SingleVoterDelta::RemoveVoter(MemberId::new(3))])
        );
        assert!(p.reason.is_none());
      }
      other => panic!("expected resumable Timeout, got {other:?}"),
    }
  }

  #[test]
  fn completion_before_cap_returns_ok_never_timeout_empty_some() {
    // A grow that installs both steps before the cap returns Ok(()), never Timeout(Some(vec![])).
    let backend = mock(&[1, 2, 3], &[1, 2, 3]);
    let target = MembershipTarget::new(member_set(&[1, 2, 3, 4]), BTreeSet::new());
    let r = block_on(run_reconfigure(
      backend.clone(),
      target,
      HealthHint::default(),
      64,
      MemberId::new(1),
    ));
    assert!(matches!(r, Ok(())));
  }

  // ── LoopBackend / LoopController / ReconfigureJob protocol tests ─────────────
  //
  // These validate the shared-memory backend protocol WITHOUT a real driver or runtime.
  // The "mock driver loop" polls the future manually, calls controller.refresh/take_proposal/tick,
  // and answers StepOutcome in a tight synchronous spin — the same protocol the concrete drivers run.

  /// A tiny genesis membership with one learner to promote. `replica_count` = number of voters;
  /// the learner sits in slot `replica_count`.
  fn membership_with_learner(voters: &[u128], learner: u128) -> Membership {
    let voter_ids: Vec<MemberId> = voters.iter().copied().map(MemberId::new).collect();
    let learner_id = MemberId::new(learner);
    let n = voter_ids.len() as u8;
    let mut all = voter_ids;
    all.push(learner_id);
    // replica_count = n voters, learner_count = 1
    Membership::genesis(n, 1, all).unwrap()
  }

  /// Simulate an epoch bump by re-creating the membership after applying a delta.
  fn apply_to(m: &Membership, step: &SingleVoterDelta) -> Membership {
    m.apply_delta(step)
      .expect("step must be valid on this membership")
  }

  /// (a) The backend reads the live membership and acked set from the snapshot after refresh.
  #[test]
  fn loop_backend_reads_the_refreshed_snapshot() {
    let live = membership_of(&[1, 2, 3]);
    let acked = member_set(&[1, 2]);
    let (backend, controller) = LoopBackend::new_pair(Snapshot {
      live: live.clone(),
      acked: acked.clone(),
      cap_exhausted: false,
    });
    assert_eq!(backend.live_membership(), live);
    assert_eq!(backend.recently_acked_voters(64), acked);
    assert!(!backend.cap_exhausted());

    // After refresh the snapshot changes.
    let live2 = membership_of(&[1, 2, 3, 4]);
    let acked2 = member_set(&[1, 2, 3]);
    controller.refresh(live2.clone(), acked2.clone(), true);
    assert_eq!(backend.live_membership(), live2);
    assert_eq!(backend.recently_acked_voters(64), acked2);
    assert!(backend.cap_exhausted());
  }

  /// (b) A posted proposal is visible via take_proposal; a second take finds None.
  #[test]
  fn loop_backend_posts_proposal_controller_drains_it() {
    use std::task::Poll;

    let initial = membership_of(&[1, 2, 3]);
    let (backend, controller) = LoopBackend::new_pair(Snapshot {
      live: initial.clone(),
      acked: BTreeSet::new(),
      cap_exhausted: false,
    });

    // Poll propose_and_await_install once: it should post into the slot and park.
    let step = SingleVoterDelta::AddLearner(MemberId::new(4));
    let mut propose_fut = std::pin::pin!(backend.propose_and_await_install(step.clone()));
    let waker = futures_util::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    // First poll: posts the proposal, parks on rx.await.
    assert!(matches!(propose_fut.as_mut().poll(&mut cx), Poll::Pending));

    // The controller drains the proposal.
    let (drained_step, reply_tx) = controller.take_proposal().expect("proposal must be posted");
    assert_eq!(drained_step, step);
    // A second drain finds nothing.
    assert!(controller.take_proposal().is_none());

    // Answer Installed: the future resolves Ok.
    let _ = reply_tx.send(StepOutcome::Installed);
    assert!(matches!(
      propose_fut.as_mut().poll(&mut cx),
      Poll::Ready(Ok(()))
    ));
  }

  /// (c) A Retry answer causes the backend to backoff then re-post the same step.
  #[test]
  fn loop_backend_retries_after_retry_outcome() {
    use std::task::Poll;

    let initial = membership_of(&[1, 2, 3]);
    let (backend, controller) = LoopBackend::new_pair(Snapshot {
      live: initial.clone(),
      acked: BTreeSet::new(),
      cap_exhausted: false,
    });

    let step = SingleVoterDelta::AddLearner(MemberId::new(4));
    let mut propose_fut = std::pin::pin!(backend.propose_and_await_install(step.clone()));
    let waker = futures_util::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);

    // First poll: proposal is posted.
    assert!(matches!(propose_fut.as_mut().poll(&mut cx), Poll::Pending));
    let (_, reply_tx) = controller.take_proposal().unwrap();

    // Answer Retry: the backend will re-post after backoff.
    let _ = reply_tx.send(StepOutcome::Retry);

    // The future now parks on backoff. Tick to unblock it.
    assert!(matches!(propose_fut.as_mut().poll(&mut cx), Poll::Pending));
    controller.tick();

    // After tick the future re-posts the same step.
    assert!(matches!(propose_fut.as_mut().poll(&mut cx), Poll::Pending));
    let (reposted_step, reply_tx2) = controller
      .take_proposal()
      .expect("step is re-posted after Retry + tick");
    assert_eq!(reposted_step, step, "re-posted step is the same delta");

    // Answer Installed: converges.
    let _ = reply_tx2.send(StepOutcome::Installed);
    assert!(matches!(
      propose_fut.as_mut().poll(&mut cx),
      Poll::Ready(Ok(()))
    ));
  }

  /// (d) Installed after a simulated epoch advance: ReconfigureJob converges Ok and the reply fires.
  #[test]
  fn reconfigure_job_installed_advances_and_reply_fires() {
    use std::task::Poll;

    // Genesis: 1 voter + learner 2 to promote. Target: {1, 2} voters.
    let live = membership_with_learner(&[1], 2);
    let acked = member_set(&[1]);
    let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();

    let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
    let mut job = ReconfigureJob::start(
      target,
      HealthHint {
        known_up: member_set(&[1]),
        ..HealthHint::default()
      },
      64,
      Duration::from_secs(30),
      reply_tx,
      live.clone(),
      acked.clone(),
      MemberId::new(1),
    );

    let waker = futures_util::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);

    // The job needs PromoteLearner(2) — which requires a LearnerProof. Since our mock live
    // membership has no proof gate, AddLearner isn't needed (learner 2 is already present).
    // The planner should emit PromoteLearner(2). We simulate: poll -> proposal posted -> Installed.

    // Poll 1: refresh snapshot (already set), poll future, take proposal.
    job.controller.refresh(live.clone(), acked.clone(), false);
    assert!(matches!(job.fut.as_mut().poll(&mut cx), Poll::Pending));

    let (step, step_reply) = job
      .controller
      .take_proposal()
      .expect("PromoteLearner(2) must be proposed");
    // Verify the step is sensible (PromoteLearner(2)).
    assert_eq!(step.member(), MemberId::new(2));
    assert!(
      step.is_promote_learner() || step.is_add_learner(),
      "expected PromoteLearner or AddLearner for new voter 2, got {step:?}"
    );

    // Hold the step reply the way the driver loop does between propose and the install detection.
    job.pending_step_reply = Some(step_reply);

    // Simulate epoch advance: apply the step to get a new membership, refresh.
    let new_live = apply_to(&live, &step);
    job
      .controller
      .refresh(new_live.clone(), acked.clone(), false);

    // Send Installed from pending_step_reply.
    if let Some(sr) = job.pending_step_reply.take() {
      let _ = sr.send(StepOutcome::Installed);
    }

    // Poll 2: the future advances. If the plan now has more steps, it posts another proposal.
    // Drive to completion using the block_on spin.
    let result = {
      let fut = &mut job.fut;
      let mut remaining_polls = 256usize;
      loop {
        match fut.as_mut().poll(&mut cx) {
          Poll::Ready(r) => break r,
          Poll::Pending => {
            remaining_polls -= 1;
            if remaining_polls == 0 {
              panic!("future did not complete within poll budget");
            }
            // If there's a pending proposal, answer it as Installed immediately.
            if let Some((next_step, sr)) = job.controller.take_proposal() {
              let newer_live = apply_to(&new_live, &next_step);
              job.controller.refresh(newer_live, acked.clone(), false);
              let _ = sr.send(StepOutcome::Installed);
            } else {
              // No pending proposal: fire a tick so backoff unblocks (if any).
              job.controller.tick();
            }
          }
        }
      }
    };

    assert!(
      result.is_ok(),
      "job resolves Ok after all steps installed: {result:?}"
    );

    // (e) The reply channel carries the same Ok(()).
    let _ = job.reply.send(result);
    assert!(
      matches!(reply_rx.try_recv(), Ok(Some(Ok(())))),
      "reply resolves Ok(())"
    );
  }

  /// (f) A Failed outcome propagates the error and the reply fires Err.
  #[test]
  fn reconfigure_job_failed_outcome_resolves_err() {
    use std::task::Poll;

    let live = membership_of(&[1, 2, 3]);
    let acked = member_set(&[1, 2, 3]);
    let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();

    // Target: remove voter 3. The shrink needs a known_up quorum.
    let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
    let mut job = ReconfigureJob::start(
      target,
      HealthHint {
        known_up: member_set(&[1, 2]),
        ..HealthHint::default()
      },
      64,
      Duration::from_secs(30),
      reply_tx,
      live.clone(),
      acked.clone(),
      MemberId::new(1),
    );

    let waker = futures_util::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);

    job.controller.refresh(live.clone(), acked.clone(), false);
    assert!(matches!(job.fut.as_mut().poll(&mut cx), Poll::Pending));

    let (_, step_reply) = job
      .controller
      .take_proposal()
      .expect("RemoveVoter(3) must be proposed");

    // Answer Failed with a terminal error.
    let terminal = ReconfigureError::NotPrimary;
    let _ = step_reply.send(StepOutcome::Failed(terminal.clone()));

    // A pre-sent Failed must resolve in exactly one poll — no backoff, no retry.
    // Asserting Poll::Ready here makes that "one poll suffices" invariant explicit.
    let result = match job.fut.as_mut().poll(&mut cx) {
      Poll::Ready(r) => r,
      Poll::Pending => panic!("fut must resolve in one poll after a Failed outcome"),
    };
    assert!(
      matches!(result, Err(ReconfigureError::NotPrimary)),
      "poll result must be Poll::Ready(Err(NotPrimary)), got: {result:?}"
    );
    let _ = job.reply.send(result);
    assert!(
      matches!(
        reply_rx.try_recv(),
        Ok(Some(Err(ReconfigureError::NotPrimary)))
      ),
      "reply receives the terminal error"
    );
  }

  // ── FIX 1 tests: advance-level deadline hard-cancel ──────────────────────

  /// The deadline hard-cancels at the advance level even when the executor future is stuck in a
  /// Retry loop. With `reconfigure_timeout = Duration::ZERO` the deadline fires on the FIRST
  /// advance call (deadline = now + 0 = now; cap_exhausted = now >= now = true), before the future
  /// is ever polled.
  #[test]
  fn advance_deadline_fires_when_future_parked_in_retry_loop() {
    let live = membership_of(&[1, 2, 3]);
    let acked = member_set(&[1, 2, 3]);
    let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
    let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();

    // Zero timeout: deadline = now + 0 = now; cap_exhausted = now >= now = true on the first advance.
    let mut job = ReconfigureJob::start(
      target,
      HealthHint {
        known_up: member_set(&[1, 2]),
        ..HealthHint::default()
      },
      64,
      Duration::ZERO,
      reply_tx,
      live.clone(),
      acked.clone(),
      MemberId::new(1),
    );

    // The propose closure always returns ProofPending (simulates executor stuck on Retry).
    let mut propose = |_: SingleVoterDelta| -> Result<OpNumber, ProposeMembershipError> {
      Err(ProposeMembershipError::ProofPending)
    };

    let outcome = job.advance(Instant::ZERO, live, acked, &mut propose);

    assert!(
      matches!(outcome, AdvanceOutcome::Done),
      "advance must return Done when the deadline fires immediately"
    );
    assert!(
      matches!(
        reply_rx.try_recv(),
        Ok(Some(Err(ReconfigureError::Timeout(_))))
      ),
      "reply must carry Timeout when the deadline fires before any proposal"
    );
  }

  /// When the install never arrives (stuck install scenario), a second advance call with `now` past
  /// the deadline resolves Timeout before polling the future again.
  #[test]
  fn advance_deadline_fires_when_install_never_arrives() {
    let live = membership_of(&[1, 2, 3]);
    let acked = member_set(&[1, 2, 3]);
    let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
    let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();

    // 5-second timeout: first advance at ZERO arms deadline = ZERO + 5s, not yet exhausted.
    let mut job = ReconfigureJob::start(
      target,
      HealthHint {
        known_up: member_set(&[1, 2]),
        ..HealthHint::default()
      },
      64,
      Duration::from_secs(5),
      reply_tx,
      live.clone(),
      acked.clone(),
      MemberId::new(1),
    );

    // First advance: not yet exhausted. The propose closure succeeds; we capture the step reply
    // but deliberately never send Installed, simulating a stuck install.
    let mut propose =
      |_: SingleVoterDelta| -> Result<OpNumber, ProposeMembershipError> { Ok(OpNumber::new()) };
    let outcome1 = job.advance(Instant::ZERO, live.clone(), acked.clone(), &mut propose);
    assert!(
      matches!(outcome1, AdvanceOutcome::InFlight),
      "first advance before deadline is InFlight"
    );
    // Drain the proposal so the slot is empty; drop the step reply without answering (simulates
    // the install never arriving — the driver task would normally wait for the config_id match).
    drop(job.controller.take_proposal());

    // Second advance at t = ZERO + 10s, past the 5s deadline — must fire the advance-level Timeout.
    let t1 = Instant::ZERO + Duration::from_secs(10);
    let mut propose2 =
      |_: SingleVoterDelta| -> Result<OpNumber, ProposeMembershipError> { Ok(OpNumber::new()) };
    let outcome2 = job.advance(t1, live, acked, &mut propose2);
    assert!(
      matches!(outcome2, AdvanceOutcome::Done),
      "advance past deadline must return Done"
    );
    assert!(
      matches!(
        reply_rx.try_recv(),
        Ok(Some(Err(ReconfigureError::Timeout(_))))
      ),
      "reply must carry Timeout when deadline fires with install outstanding"
    );
  }

  // ── FIX 2 test: self-removal ranked last ─────────────────────────────────

  /// When both the local node and a peer are valid removal candidates (both have surviving
  /// confirmed quorums after their removal), the peer is picked first. This prevents the driver
  /// from retiring itself mid-plan when another safe removal exists.
  #[test]
  fn self_removal_is_ranked_last_when_another_safe_removal_exists() {
    // live = {1, 2, 3}, target = {2}: must remove both 1 and 3.
    // local_member = 1 (the local driver node is a removal candidate).
    // known_up = {1, 2, 3}: all three confirmed alive, so liveness is equal for all candidates;
    // the self-last tie-break alone must distinguish them.
    // Removing 1 → successor {2, 3}, quorum = 1, confirmed = 2 ✓
    // Removing 3 → successor {1, 2}, quorum = 1, confirmed = 2 ✓
    // Without self-last: ascending-id order picks 1 first. With self-last: 3 is picked first.
    let live = membership_of(&[1, 2, 3]);
    let health = HealthHint {
      known_up: member_set(&[1, 2, 3]),
      known_down: BTreeSet::new(),
    };
    let responsive = member_set(&[1, 2, 3]);
    let local_member = MemberId::new(1);

    let candidates = std::vec![
      SingleVoterDelta::RemoveVoter(MemberId::new(1)),
      SingleVoterDelta::RemoveVoter(MemberId::new(3)),
    ];

    let result =
      pick_fresh_quorum_preserving_removal(&live, &candidates, &health, &responsive, local_member);

    assert_eq!(
      result,
      Some(SingleVoterDelta::RemoveVoter(MemberId::new(3))),
      "RemoveVoter(3) must be chosen before RemoveVoter(1) (self) even though id 1 < 3"
    );
  }
}

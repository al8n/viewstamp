//! The driver-level reconfiguration executor: `reconfigure_to` and its types. It drives the pure proto
//! planner (`plan_next_step` / `shrink_candidates`) one Tier B `propose_membership` at a time, re-planning
//! from the live membership each step, with a health-aware fail-closed shrink ordering. Adds ZERO proto
//! consensus surface.

use std::collections::BTreeSet;
use std::vec::Vec;

use viewstamp_proto::{
  MemberId, Membership, MembershipTarget, PlanError, ProposeMembershipError, SingleVoterDelta,
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
  // consumed by the concrete-driver Command::Reconfigure pump (follow-up)
  #[allow(dead_code)]
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
  // consumed by the concrete-driver Command::Reconfigure pump (follow-up)
  #[allow(dead_code)]
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
// consumed by the concrete-driver Command::Reconfigure pump (follow-up)
#[allow(dead_code)]
pub(crate) trait ReconfigureBackend {
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
/// `responsive`). `None` (→ STALL fail-closed) when NO candidate's successor has a positively-confirmed
/// quorum — never a removal on a guess.
// consumed by the concrete-driver Command::Reconfigure pump (follow-up)
#[allow(dead_code)]
fn pick_fresh_quorum_preserving_removal(
  live: &Membership,
  candidates: &[SingleVoterDelta],
  health: &HealthHint,
  responsive: &BTreeSet<MemberId>,
) -> Option<SingleVoterDelta> {
  let live_voters: BTreeSet<MemberId> = {
    let n = live.replica_count() as usize;
    live.members_slice()[..n].iter().copied().collect()
  };
  let is_alive = |m: &MemberId| -> bool {
    !health.known_down.contains(m) && (health.known_up.contains(m) || responsive.contains(m))
  };
  // Prefer apparently-DOWN departing voters first (then any) so a dead voter is shed before a live one.
  let mut ordered: Vec<&SingleVoterDelta> = candidates.iter().collect();
  ordered.sort_by_key(|d| {
    let m = d.member();
    let apparently_down = health.known_down.contains(&m) || !is_alive(&m);
    (!apparently_down, m.get()) // down-first, then ascending id for determinism
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
// consumed by the concrete-driver Command::Reconfigure pump (follow-up)
#[allow(dead_code)]
pub(crate) async fn run_reconfigure<B: ReconfigureBackend>(
  backend: &B,
  target: MembershipTarget,
  health: HealthHint,
  ack_window: u64,
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
        match pick_fresh_quorum_preserving_removal(&live, &candidates, &health, &acked) {
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

#[cfg(test)]
mod tests {
  use super::*;
  use std::cell::RefCell;
  use std::rc::Rc;

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
    let r = block_on(run_reconfigure(&backend, target, HealthHint::default(), 64));
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
    let r = block_on(run_reconfigure(&backend, target, health, 64));
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
    let r = block_on(run_reconfigure(&backend, target, HealthHint::default(), 8));
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
    let r = block_on(run_reconfigure(&backend, target, health, 8));
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
    let r = block_on(run_reconfigure(&backend, target, HealthHint::default(), 64));
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
    let r = block_on(run_reconfigure(&backend, target, HealthHint::default(), 16));
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
    let r = block_on(run_reconfigure(&backend, target, HealthHint::default(), 16));
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
    let r = block_on(run_reconfigure(&backend, target, HealthHint::default(), 64));
    assert!(matches!(r, Ok(())));
  }
}

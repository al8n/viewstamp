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

/// The operator's fault-tolerance-reduction acknowledgement, for the tests whose goal reduces `f`.
fn ack() -> Option<AcceptReducedFaultTolerance> {
  Some(AcceptReducedFaultTolerance)
}

// ── mock backend ─────────────────────────────────────────────────────────

type Injector = Box<dyn FnMut(&mut MockState, &[SingleVoterDelta])>;
/// A per-backoff hook: the evidence-arrival tests use it to grow `fresh` (the proven-live set)
/// over stall iterations — modelling liveness evidence that lands only after the shrink has begun
/// waiting (a probe answer arriving a few driver ticks after the round is solicited).
type BackoffHook = Box<dyn FnMut(&mut MockState)>;

struct MockState {
  live: Membership,
  /// The set `proven_live_voters` returns — models the active liveness probe's proven-live voters
  /// (self included), exactly as the real driver snapshots `endpoint.proven_live_voters` into it.
  fresh: BTreeSet<MemberId>,
  issued: Vec<SingleVoterDelta>,
  steps_left: u32,
  inject: Option<Injector>,
  backoff_hook: Option<BackoffHook>,
  /// The last value `note_shrink_stall` recorded (the unproven-voter diagnostic), for assertions.
  stall_note: Option<BTreeSet<MemberId>>,
}

struct Mock(RefCell<MockState>);

fn mock(voters: &[u128], fresh: &[u128]) -> Rc<Mock> {
  Rc::new(Mock(RefCell::new(MockState {
    live: membership_of(voters),
    fresh: fresh.iter().copied().map(MemberId::new).collect(),
    issued: Vec::new(),
    steps_left: 64,
    inject: None,
    backoff_hook: None,
    stall_note: None,
  })))
}

fn mock_with_injector(voters: &[u128], fresh: &[u128], inject: Injector) -> Rc<Mock> {
  let m = mock(voters, fresh);
  m.0.borrow_mut().inject = Some(inject);
  m
}

/// A mock whose live membership carries a learner (for the GC-lane tests).
fn mock_with_learner(voters: &[u128], learner: u128, fresh: &[u128]) -> Rc<Mock> {
  Rc::new(Mock(RefCell::new(MockState {
    live: membership_with_learner(voters, learner),
    fresh: fresh.iter().copied().map(MemberId::new).collect(),
    issued: Vec::new(),
    steps_left: 64,
    inject: None,
    backoff_hook: None,
    stall_note: None,
  })))
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

  fn proven_live_voters(&self) -> BTreeSet<MemberId> {
    self.0.borrow().fresh.clone()
  }

  fn note_shrink_stall(&self, unproven: Option<BTreeSet<MemberId>>) {
    self.0.borrow_mut().stall_note = unproven;
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
    // Run the per-backoff evidence hook (used by the evidence-arrival test to make liveness evidence arrive after N
    // stall iterations).
    if let Some(mut hook) = state.backoff_hook.take() {
      hook(&mut state);
      state.backoff_hook = Some(hook);
    }
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

/// Injector: once `id` is promoted to a voter, a competitor fully EJECTS it (demote-first: demote out
/// of the voting set, then GC the learner), so `id` becomes absent from the membership.
fn remove_after_promote(id: MemberId) -> Injector {
  Box::new(move |state, _trace| {
    if let Some(slot) = state.live.slot_of(id)
      && state.live.is_voter(slot)
      && state.live.replica_count() > 1
    {
      state.live = state
        .live
        .apply_delta(&SingleVoterDelta::DemoteVoter(id))
        .and_then(|m| m.apply_delta(&SingleVoterDelta::RemoveLearner(id)))
        .unwrap();
    }
  })
}

/// Injector: toggle `id` in/out of the voter set each step (opposing-target oscillation). A removal is
/// the demote-first ejection (demote then GC); an add is the learner-first promotion.
fn oscillate_voter(id: MemberId) -> Injector {
  Box::new(move |state, _trace| match state.live.slot_of(id) {
    Some(slot) if state.live.is_voter(slot) && state.live.replica_count() > 1 => {
      state.live = state
        .live
        .apply_delta(&SingleVoterDelta::DemoteVoter(id))
        .and_then(|m| m.apply_delta(&SingleVoterDelta::RemoveLearner(id)))
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

// ── progress and error type tests ───────────────────────────────────

#[test]
fn health_hint_default_is_empty() {
  let h = HealthHint::default();
  assert!(h.known_down.is_empty());
}

#[test]
fn stall_progress_carries_a_valid_remaining_plan_and_no_reason() {
  let live = membership_of(&[1, 2, 3]);
  let plan = std::vec![SingleVoterDelta::DemoteVoter(MemberId::new(3))];
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
      std::vec![SingleVoterDelta::DemoteVoter(MemberId::new(1))],
    )),
    ReconfigureError::InsufficientLiveness {
      progress: ReconfigureProgress::stall(
        live.clone(),
        std::vec![SingleVoterDelta::DemoteVoter(MemberId::new(1))],
      ),
      unproven: member_set(&[2, 3]),
    },
    ReconfigureError::ReducedFaultToleranceUnacknowledged {
      from_voters: 3,
      to_voters: 2,
    },
    ReconfigureError::DemotedSelf {
      progress: ReconfigureProgress::stall(
        live.clone(),
        std::vec![SingleVoterDelta::RemoveLearner(MemberId::new(1))],
      ),
    },
    ReconfigureError::NotPrimary,
    ReconfigureError::DriverGone,
    ReconfigureError::Retired {
      local: MemberId::new(1),
      epoch: viewstamp_proto::Epoch::new(2),
    },
    ReconfigureError::Propose(ProposeMembershipError::NotPrimary),
  ];
  for e in &errs {
    assert!(!std::format!("{e}").is_empty());
  }
}

// ── executor convergence tests ─────────────────────────────────────────────────────

#[test]
fn grow_converges_add_one_replica() {
  // {1,2,3} -> {1,2,3,4}: AddLearner(4) then PromoteLearner(4). A grow never reduces f: ack is None.
  let backend = mock(&[1, 2, 3], &[1, 2, 3]);
  let target = MembershipTarget::new(member_set(&[1, 2, 3, 4]), BTreeSet::new());
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    None,
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
fn shrink_demotes_the_dead_voter_first_via_known_down_and_fresh() {
  // {1,2,3} -> {1}, node 3 down. known_down={3}, fresh (proven live) = {1,2} => DemoteVoter(3) BEFORE
  // DemoteVoter(2). The goal reduces f (1 -> 0), so the operator acknowledges it.
  let backend = mock(&[1, 2, 3], &[1, 2]); // 1 and 2 proven live by the probe
  let target = MembershipTarget::new(member_set(&[1]), BTreeSet::new());
  let health = HealthHint::new().with_known_down(member_set(&[3]));
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    health,
    MemberId::new(1),
    ack(),
  ));
  assert!(r.is_ok());
  let issued = backend.0.borrow();
  let dm3 = issued
    .issued
    .iter()
    .position(|d| *d == SingleVoterDelta::DemoteVoter(MemberId::new(3)));
  let dm2 = issued
    .issued
    .iter()
    .position(|d| *d == SingleVoterDelta::DemoteVoter(MemberId::new(2)));
  assert!(
    dm3.unwrap() < dm2.unwrap(),
    "the DOWN voter 3 is demoted before the live voter 2"
  );
}

#[test]
fn idle_cluster_with_no_proof_stalls_to_insufficient_liveness() {
  // Shrink-only {1,2,3} -> {1}. Only self (1) is proven live (the peers never answer the probe): NO
  // successor quorum is proven, so the shrink stalls fail-closed to InsufficientLiveness, naming the
  // unproven successor voter of the most-preferred demotion (DemoteVoter(2) -> successor {1,3} -> {3}).
  let backend = mock(&[1, 2, 3], &[1]);
  let target = MembershipTarget::new(member_set(&[1]), BTreeSet::new());
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    ack(),
  ));
  match r {
    Err(ReconfigureError::InsufficientLiveness { progress, unproven }) => {
      assert!(
        progress.remaining.as_ref().is_some_and(|v| !v.is_empty()) && progress.reason.is_none(),
        "stall carries a non-empty remaining plan and no reason"
      );
      assert_eq!(
        unproven,
        member_set(&[3]),
        "names the unproven successor voter blocking the most-preferred demotion"
      );
    }
    other => panic!("expected InsufficientLiveness, got {other:?}"),
  }
  assert!(
    backend.0.borrow().issued.is_empty(),
    "no DemoteVoter was issued (fail-closed)"
  );
}

#[test]
fn known_down_only_stalls_to_insufficient_liveness_negative_is_not_life_evidence() {
  // {1,2,3} -> {1}, ONLY known_down={3}, only self (1) proven live: stalls (a negative veto is not
  // positive evidence, and no probe proved 2 alive).
  let backend = mock(&[1, 2, 3], &[1]);
  let target = MembershipTarget::new(member_set(&[1]), BTreeSet::new());
  let health = HealthHint::new().with_known_down(member_set(&[3]));
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    health,
    MemberId::new(1),
    ack(),
  ));
  assert!(matches!(
    r,
    Err(ReconfigureError::InsufficientLiveness { .. })
  ));
  assert!(backend.0.borrow().issued.is_empty());
}

#[test]
fn concurrent_removal_of_a_needed_member_surfaces_member_concurrently_removed() {
  // {1,2,3} -> {1,2,3,4}: stage+promote 4 (committed_any), then a competitor fully ejects 4.
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
    MemberId::new(1),
    None,
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
    MemberId::new(1),
    None,
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
  // {1,2,3} -> {1,2,4}: a rotation (f stays 1, no acknowledgement needed). The grow steps commit (4
  // staged+promoted), then the shrink stalls (only self is proven live, so the successor {1,2,4} quorum
  // is not proven). The stall is a missing-witness InsufficientLiveness carrying the durable intermediate
  // + the still-valid DemoteVoter(3) suffix.
  let backend = mock(&[1, 2, 3], &[1]); // only self proven live: the shrink stalls
  let target = MembershipTarget::new(member_set(&[1, 2, 4]), BTreeSet::new());
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    None,
  ));
  match r {
    Err(ReconfigureError::InsufficientLiveness { progress, unproven }) => {
      let (v, _) = sets_of(&progress.live);
      assert_eq!(
        v,
        member_set(&[1, 2, 3, 4]),
        "the durable INTERMEDIATE, not the original"
      );
      assert_eq!(
        progress.remaining,
        Some(std::vec![
          SingleVoterDelta::DemoteVoter(MemberId::new(3)),
          SingleVoterDelta::RemoveLearner(MemberId::new(3)),
        ]),
        "the still-valid demote-then-GC suffix from the durable intermediate"
      );
      assert!(progress.reason.is_none());
      assert_eq!(
        unproven,
        member_set(&[2, 4]),
        "names the unproven successor voters of DemoteVoter(3): successor is 1,2,4 and only 1 is proven"
      );
    }
    other => panic!("expected resumable InsufficientLiveness, got {other:?}"),
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
    MemberId::new(1),
    None,
  ));
  assert!(matches!(r, Ok(())));
}

// ── fresh-liveness-probe fail-closed falsifiers ─────────────────────────────

#[test]
fn shrink_completes_once_the_probe_proves_the_successor_quorum() {
  // A HEALTHY but idle 3-voter cluster {1,2,3} -> {1,2}. Initially only self (1) is proven live,
  // so the shrink STALLS (successor {1,2} needs 2 proven). After a few stall iterations voter 2's probe
  // answer lands (fresh grows to {1,2}) and the shrink COMPLETES — the demote is proposed ONLY after
  // that evidence exists, then its GC follows. The goal reduces f (1 -> 0), so it is acknowledged.
  let backend = mock(&[1, 2, 3], &[1]); // only self proven live at first
  let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
  // Record how many steps had been issued at the moment evidence arrived (must be zero).
  let issued_at_evidence: Rc<RefCell<Option<usize>>> = Rc::new(RefCell::new(None));
  let sink = Rc::clone(&issued_at_evidence);
  let mut ticks = 0u32;
  backend.0.borrow_mut().backoff_hook = Some(Box::new(move |state| {
    ticks += 1;
    if ticks == 3 {
      *sink.borrow_mut() = Some(state.issued.len());
      state.fresh = member_set(&[1, 2]); // voter 2's probe answer lands
    }
  }));
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    ack(),
  ));
  assert!(
    r.is_ok(),
    "the shrink completes once the probe proves the quorum: {r:?}"
  );
  assert_eq!(
    backend.0.borrow().issued,
    std::vec![
      SingleVoterDelta::DemoteVoter(MemberId::new(3)),
      SingleVoterDelta::RemoveLearner(MemberId::new(3)),
    ],
    "the due demotion, then its race-free GC"
  );
  assert_eq!(
    *issued_at_evidence.borrow(),
    Some(0),
    "no step was issued BEFORE the liveness evidence arrived (fail-closed until proven)"
  );
}

#[test]
fn a_voter_that_never_proves_blocks_demoting_its_partner_into_an_outage() {
  // {1,2,3} -> {1,2}. The probe proves 1 and 3 live, but voter 2 NEVER answers (it crashed after
  // the reconfigure call). The sole candidate DemoteVoter(3) is NEVER issued — demoting 3 would leave
  // {1,2} where 2 is not proven live, an outage — and the shrink stalls fail-closed with 2 named
  // unproven. The deleted `known_up` vouch (a stale operator hint 2's crash could not retract) would
  // have demoted 3 into that outage; the fresh probe closes the door.
  let backend = mock(&[1, 2, 3], &[1, 3]); // 2 never proves
  let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    ack(),
  ));
  match r {
    Err(ReconfigureError::InsufficientLiveness { unproven, .. }) => {
      assert!(
        unproven.contains(&MemberId::new(2)),
        "voter 2 (never proved) is named unproven"
      );
    }
    other => panic!("expected InsufficientLiveness, got {other:?}"),
  }
  assert!(
    backend.0.borrow().issued.is_empty(),
    "DemoteVoter(3) is NEVER issued — the successor 1,2 has no proven quorum"
  );
}

#[test]
fn no_negative_hint_substitutes_for_a_fresh_proof() {
  // With `known_up` deleted, NO HealthHint input can force a demotion absent a fresh proof of the
  // SURVIVORS. Here the operator vetoes the departing voter 3 (known_down={3}) — which prioritizes its
  // demotion — but the survivor 2 is not proven live (only self is), so DemoteVoter(3) still stalls: a
  // negative veto is never a positive substitute.
  let backend = mock(&[1, 2, 3], &[1]);
  let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
  let health = HealthHint::new().with_known_down(member_set(&[3]));
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    health,
    MemberId::new(1),
    ack(),
  ));
  assert!(matches!(
    r,
    Err(ReconfigureError::InsufficientLiveness { .. })
  ));
  assert!(
    backend.0.borrow().issued.is_empty(),
    "no demotion on a negative-only hint"
  );
}

#[test]
fn grow_phase_cap_exhaustion_is_timeout_not_insufficient_liveness() {
  // Variant discrimination: a cap exhausted during the GROW phase (no shrink stall was ever recorded)
  // resolves the generic Timeout, NOT the missing-witness InsufficientLiveness. Grow {1,2,3} ->
  // {1,2,3,4} needs AddLearner(4)+PromoteLearner(4); a cap of one step exhausts after the first.
  let backend = mock(&[1, 2, 3], &[1, 2, 3]);
  backend.0.borrow_mut().steps_left = 1;
  let target = MembershipTarget::new(member_set(&[1, 2, 3, 4]), BTreeSet::new());
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    None,
  ));
  assert!(
    matches!(r, Err(ReconfigureError::Timeout(_))),
    "a grow-phase cap is Timeout, never InsufficientLiveness: {r:?}"
  );
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

/// (a) The backend reads the live membership and proven-live voter set from the snapshot after refresh.
#[test]
fn loop_backend_reads_the_refreshed_snapshot() {
  let live = membership_of(&[1, 2, 3]);
  let fresh = member_set(&[1, 2]);
  let (backend, controller) = LoopBackend::new_pair(Snapshot {
    live: live.clone(),
    fresh: fresh.clone(),
    cap_exhausted: false,
    shrink_stall: None,
  });
  assert_eq!(backend.live_membership(), live);
  assert_eq!(backend.proven_live_voters(), fresh);
  assert!(!backend.cap_exhausted());

  // After refresh the snapshot changes.
  let live2 = membership_of(&[1, 2, 3, 4]);
  let fresh2 = member_set(&[1, 2, 3]);
  controller.refresh(live2.clone(), fresh2.clone(), true);
  assert_eq!(backend.live_membership(), live2);
  assert_eq!(backend.proven_live_voters(), fresh2);
  assert!(backend.cap_exhausted());
}

/// (b) A posted proposal is visible via take_proposal; a second take finds None.
#[test]
fn loop_backend_posts_proposal_controller_drains_it() {
  use std::task::Poll;

  let initial = membership_of(&[1, 2, 3]);
  let (backend, controller) = LoopBackend::new_pair(Snapshot {
    live: initial.clone(),
    fresh: BTreeSet::new(),
    cap_exhausted: false,
    shrink_stall: None,
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
    fresh: BTreeSet::new(),
    cap_exhausted: false,
    shrink_stall: None,
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
  let fresh = member_set(&[1]);
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();

  let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
  let mut job = ReconfigureJob::start(
    target,
    HealthHint::default(),
    Duration::from_secs(30),
    reply_tx,
    live.clone(),
    fresh.clone(),
    MemberId::new(1),
    None,
  );

  let waker = futures_util::task::noop_waker();
  let mut cx = std::task::Context::from_waker(&waker);

  // The job needs PromoteLearner(2) — which requires a LearnerProof. Since our mock live
  // membership has no proof gate, AddLearner isn't needed (learner 2 is already present).
  // The planner should emit PromoteLearner(2). We simulate: poll -> proposal posted -> Installed.

  // Poll 1: refresh snapshot (already set), poll future, take proposal.
  job.controller.refresh(live.clone(), fresh.clone(), false);
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
    .refresh(new_live.clone(), fresh.clone(), false);

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
            job.controller.refresh(newer_live, fresh.clone(), false);
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
  let fresh = member_set(&[1, 2, 3]);
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();

  // Target: demote voter 3. The shrink needs a proven-live successor quorum, and it reduces f, so the
  // job carries the operator acknowledgement (else the goal-level preflight would refuse it up front).
  let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
  let mut job = ReconfigureJob::start(
    target,
    HealthHint::default(),
    Duration::from_secs(30),
    reply_tx,
    live.clone(),
    fresh.clone(),
    MemberId::new(1),
    ack(),
  );

  let waker = futures_util::task::noop_waker();
  let mut cx = std::task::Context::from_waker(&waker);

  job.controller.refresh(live.clone(), fresh.clone(), false);
  assert!(matches!(job.fut.as_mut().poll(&mut cx), Poll::Pending));

  let (_, step_reply) = job
    .controller
    .take_proposal()
    .expect("DemoteVoter(3) must be proposed");

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

// ── advance-level deadline hard-cancel tests ──────────────────────

/// The deadline hard-cancels at the advance level even when the executor future is stuck in a
/// Retry loop. With `reconfigure_timeout = Duration::ZERO` the deadline fires on the FIRST
/// advance call (deadline = now + 0 = now; cap_exhausted = now >= now = true), before the future
/// is ever polled.
#[test]
fn advance_deadline_fires_when_future_parked_in_retry_loop() {
  let live = membership_of(&[1, 2, 3]);
  let fresh = member_set(&[1, 2, 3]);
  let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();

  // Zero timeout: deadline = now + 0 = now; cap_exhausted = now >= now = true on the first advance.
  let mut job = ReconfigureJob::start(
    target,
    HealthHint::default(),
    Duration::ZERO,
    reply_tx,
    live.clone(),
    fresh.clone(),
    MemberId::new(1),
    ack(),
  );

  // The propose closure always returns ProofPending (simulates executor stuck on Retry).
  let mut propose =
    |_: SingleVoterDelta,
     _: Option<AcceptReducedFaultTolerance>|
     -> Result<OpNumber, ProposeMembershipError> { Err(ProposeMembershipError::ProofPending) };

  let outcome = job.advance(Instant::ZERO, live, fresh, &mut propose);

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
  let fresh = member_set(&[1, 2, 3]);
  let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();

  // 5-second timeout: first advance at ZERO arms deadline = ZERO + 5s, not yet exhausted.
  let mut job = ReconfigureJob::start(
    target,
    HealthHint::default(),
    Duration::from_secs(5),
    reply_tx,
    live.clone(),
    fresh.clone(),
    MemberId::new(1),
    ack(),
  );

  // First advance: not yet exhausted. The propose closure succeeds; we capture the step reply
  // but deliberately never send Installed, simulating a stuck install.
  let mut propose = |_: SingleVoterDelta,
                     _: Option<AcceptReducedFaultTolerance>|
   -> Result<OpNumber, ProposeMembershipError> { Ok(OpNumber::new()) };
  let outcome1 = job.advance(Instant::ZERO, live.clone(), fresh.clone(), &mut propose);
  assert!(
    matches!(outcome1, AdvanceOutcome::InFlight),
    "first advance before deadline is InFlight"
  );
  // Drain the proposal so the slot is empty; drop the step reply without answering (simulates
  // the install never arriving — the driver task would normally wait for the config_id match).
  drop(job.controller.take_proposal());

  // Second advance at t = ZERO + 10s, past the 5s deadline — must fire the advance-level Timeout.
  let t1 = Instant::ZERO + Duration::from_secs(10);
  let mut propose2 = |_: SingleVoterDelta,
                      _: Option<AcceptReducedFaultTolerance>|
   -> Result<OpNumber, ProposeMembershipError> { Ok(OpNumber::new()) };
  let outcome2 = job.advance(t1, live, fresh, &mut propose2);
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

// ── self-removal ranked-last test ─────────────────────────────────

/// When both the local node and a peer are valid demotion candidates (both have surviving
/// confirmed quorums after their demotion), the peer is picked first. This prevents the driver
/// from demoting itself out of the voting set mid-plan when another safe demotion exists.
#[test]
fn self_demotion_is_ranked_last_when_another_safe_demotion_exists() {
  // live = {1, 2, 3}, target = {2}: must demote both 1 and 3.
  // local_member = 1 (the local driver node is a demotion candidate).
  // fresh = {1, 2, 3}: all three proven live, so liveness is equal for all candidates;
  // the self-last tie-break alone must distinguish them.
  // Demoting 1 → successor {2, 3}, quorum = 1, confirmed = 2 ✓
  // Demoting 3 → successor {1, 2}, quorum = 1, confirmed = 2 ✓
  // Without self-last: ascending-id order picks 1 first. With self-last: 3 is picked first.
  let live = membership_of(&[1, 2, 3]);
  let health = HealthHint::new();
  let fresh = member_set(&[1, 2, 3]);
  let local_member = MemberId::new(1);

  let candidates = std::vec![
    SingleVoterDelta::DemoteVoter(MemberId::new(1)),
    SingleVoterDelta::DemoteVoter(MemberId::new(3)),
  ];

  let result =
    pick_fresh_quorum_preserving_demotion(&live, &candidates, &health, &fresh, local_member);

  assert_eq!(
    result,
    Ok(SingleVoterDelta::DemoteVoter(MemberId::new(3))),
    "DemoteVoter(3) must be chosen before DemoteVoter(1) (self) even though id 1 < 3"
  );
}

/// The self-last ordering is unconditional: it must hold even when the local node has NO
/// positive evidence (apparently_down) and a peer IS proven live.  Under the old key
/// `(!apparently_down, m == local_member, m.get())`, local (1) and peer (3) both land in the
/// apparently_down bucket (local=not-proven, peer=not-proven), so the secondary key
/// `m == local_member` would fire: local=true > peer=false → local wins the descending sort
/// and is demoted first, demoting the driver out of the voting set.  Under the correct key
/// `(m == local_member, ...)` local always sorts last regardless of its liveness.
///
/// live = {1,2,3,4,5}, local_member = 1, candidates = DemoteVoter(1) + DemoteVoter(3).
/// fresh = {2,4,5}; local (1) and candidate (3) are BOTH absent → both apparently_down.
/// Demoting 3 → successor {1,2,4,5}, len=4, quorum=3, confirmed={2,4,5}=3 ≥ 3 ✓
/// Demoting 1 → successor {2,3,4,5}, len=4, quorum=3, confirmed={2,4,5}=3 ≥ 3 ✓
/// Both pass the fail-closed gate; self-last must select DemoteVoter(3) even though local is
/// apparently_down (same liveness bucket).
#[test]
fn self_demotion_is_ranked_last_even_when_local_has_no_positive_evidence() {
  let live = membership_of(&[1, 2, 3, 4, 5]);
  let health = HealthHint::new();
  let fresh = member_set(&[2, 4, 5]); // local (1) and peer (3) both absent → apparently_down
  let local_member = MemberId::new(1);

  let candidates = std::vec![
    SingleVoterDelta::DemoteVoter(MemberId::new(1)),
    SingleVoterDelta::DemoteVoter(MemberId::new(3)),
  ];

  let result =
    pick_fresh_quorum_preserving_demotion(&live, &candidates, &health, &fresh, local_member);

  assert_eq!(
    result,
    Ok(SingleVoterDelta::DemoteVoter(MemberId::new(3))),
    "DemoteVoter(3) must be chosen before DemoteVoter(1) (self) even when both are apparently_down"
  );
}

// ── finish-on-retire (displaced in-flight job) tests ──────────────

/// A job whose target is NOT yet reached, held in the slot when the endpoint retires (a concurrent
/// removal), is finished with the terminal `Retired` and its slot emptied — never left parked for
/// `advance` to spin out to a misleading resumable `Timeout`.
#[test]
fn finish_reconfigure_on_retire_resolves_retired_when_the_goal_is_unreached() {
  let live = membership_of(&[1, 2, 3]);
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  let target = MembershipTarget::new(member_set(&[1, 2, 3, 4]), BTreeSet::new());
  let job = ReconfigureJob::start(
    target,
    HealthHint::default(),
    Duration::from_secs(30),
    reply_tx,
    live.clone(),
    member_set(&[1, 2, 3]),
    MemberId::new(1),
    None,
  );
  let mut slot = Some(job);

  let local = MemberId::new(1);
  let epoch = viewstamp_proto::Epoch::new(7);
  finish_reconfigure_on_retire(&mut slot, live, local, epoch);

  assert!(slot.is_none(), "the job slot is emptied");
  assert!(
    matches!(
      reply_rx.try_recv(),
      Ok(Some(Err(ReconfigureError::Retired { local: l, epoch: e }))) if l == local && e == epoch
    ),
    "an unreached goal resolves the terminal Retired carrying the retirement identity"
  );
}

/// A job whose target EQUALS the live membership — its reconfiguration actually completed (e.g. its
/// final step removed the local node) — resolves `Ok(())` on retirement, not `Retired`: the local
/// removal is a separate fact the caller reads from the terminal driver state.
#[test]
fn finish_reconfigure_on_retire_resolves_ok_when_the_goal_is_already_reached() {
  let live = membership_of(&[1, 2, 3]);
  let (reply_tx, mut reply_rx) = futures_channel::oneshot::channel();
  let target = MembershipTarget::new(member_set(&[1, 2, 3]), BTreeSet::new());
  let job = ReconfigureJob::start(
    target,
    HealthHint::default(),
    Duration::from_secs(30),
    reply_tx,
    live.clone(),
    member_set(&[1, 2, 3]),
    MemberId::new(1),
    None,
  );
  let mut slot = Some(job);

  finish_reconfigure_on_retire(
    &mut slot,
    live,
    MemberId::new(1),
    viewstamp_proto::Epoch::new(7),
  );

  assert!(slot.is_none(), "the job slot is emptied");
  assert!(
    matches!(reply_rx.try_recv(), Ok(Some(Ok(())))),
    "a reached goal resolves Ok(()), never Retired"
  );
}

// ── H2 goal-level preflight matrix ────────────────────────────────

#[test]
fn preflight_refuses_a_tolerance_reducing_goal_without_the_acknowledgement() {
  // {1,2,3} -> {1,2} drops f from 1 to 0. Without the token the goal is refused at PREFLIGHT — before
  // any step commits — naming the voter-count drop.
  let backend = mock(&[1, 2, 3], &[1, 2]);
  let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    None,
  ));
  assert!(
    matches!(
      r,
      Err(ReconfigureError::ReducedFaultToleranceUnacknowledged {
        from_voters: 3,
        to_voters: 2
      })
    ),
    "a tolerance-reducing goal without the token is refused: {r:?}"
  );
  assert!(
    backend.0.borrow().issued.is_empty(),
    "nothing is committed at preflight"
  );
}

#[test]
fn preflight_admits_a_tolerance_reducing_goal_with_the_acknowledgement() {
  // The same {1,2,3} -> {1,2}, WITH the token and a proven-live successor quorum: it proceeds and
  // completes (demote then GC).
  let backend = mock(&[1, 2, 3], &[1, 2]);
  let target = MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new());
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    ack(),
  ));
  assert!(r.is_ok(), "an acknowledged reduction proceeds: {r:?}");
  assert_eq!(
    backend.0.borrow().issued,
    std::vec![
      SingleVoterDelta::DemoteVoter(MemberId::new(3)),
      SingleVoterDelta::RemoveLearner(MemberId::new(3)),
    ]
  );
}

#[test]
fn preflight_admits_an_f_neutral_shrink_without_the_acknowledgement() {
  // {1,2,3,4} -> {1,2,3} demotes ONE voter but f stays 1 (an even-n demote is f-neutral): no token
  // needed, and the goal completes.
  let backend = mock(&[1, 2, 3, 4], &[1, 2, 3, 4]);
  let target = MembershipTarget::new(member_set(&[1, 2, 3]), BTreeSet::new());
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    None,
  ));
  assert!(
    r.is_ok(),
    "an f-neutral shrink needs no acknowledgement: {r:?}"
  );
  assert_eq!(
    backend.0.borrow().issued,
    std::vec![
      SingleVoterDelta::DemoteVoter(MemberId::new(4)),
      SingleVoterDelta::RemoveLearner(MemberId::new(4)),
    ]
  );
}

// ── per-step acknowledgement attach matrix (advance level) ────────

/// Drive one `advance` and return the `(delta, ack_attached)` the propose closure received.
fn first_proposal_ack(
  live: Membership,
  fresh: BTreeSet<MemberId>,
  target: MembershipTarget,
  job_ack: Option<AcceptReducedFaultTolerance>,
) -> (SingleVoterDelta, bool) {
  let (reply_tx, _reply_rx) = futures_channel::oneshot::channel();
  let mut job = ReconfigureJob::start(
    target,
    HealthHint::default(),
    Duration::from_secs(30),
    reply_tx,
    live.clone(),
    fresh.clone(),
    MemberId::new(1),
    job_ack,
  );
  let captured: Rc<RefCell<Option<(SingleVoterDelta, bool)>>> = Rc::new(RefCell::new(None));
  let sink = Rc::clone(&captured);
  let mut propose = |delta: SingleVoterDelta,
                     a: Option<AcceptReducedFaultTolerance>|
   -> Result<OpNumber, ProposeMembershipError> {
    *sink.borrow_mut() = Some((delta, a.is_some()));
    Ok(OpNumber::new())
  };
  let _ = job.advance(Instant::ZERO, live, fresh, &mut propose);
  captured
    .borrow()
    .clone()
    .expect("a proposal was posted and drained in one advance")
}

#[test]
fn advance_attaches_the_ack_only_to_an_odd_n_demote() {
  // {1,2,3} -> {1,2}: the demote fires at n=3 (odd), the forced f-reducing step — the token is attached.
  let (delta, attached) = first_proposal_ack(
    membership_of(&[1, 2, 3]),
    member_set(&[1, 2, 3]),
    MembershipTarget::new(member_set(&[1, 2]), BTreeSet::new()),
    ack(),
  );
  assert_eq!(delta, SingleVoterDelta::DemoteVoter(MemberId::new(3)));
  assert!(
    attached,
    "an odd-n demote is the forced f-reducing step: the acknowledgement is attached"
  );
}

#[test]
fn advance_withholds_the_ack_from_an_even_n_demote_and_from_a_grow() {
  // {1,2,3,4} -> {1,2,3}: the demote fires at n=4 (even), f-neutral — the token is withheld even though
  // the job holds one.
  let (delta, attached) = first_proposal_ack(
    membership_of(&[1, 2, 3, 4]),
    member_set(&[1, 2, 3, 4]),
    MembershipTarget::new(member_set(&[1, 2, 3]), BTreeSet::new()),
    ack(),
  );
  assert_eq!(delta, SingleVoterDelta::DemoteVoter(MemberId::new(4)));
  assert!(
    !attached,
    "an even-n demote is f-neutral: no token attached"
  );

  // {1,2,3} -> {1,2,3,4}: the first step is a grow (AddLearner), never f-reducing — token withheld.
  let (delta, attached) = first_proposal_ack(
    membership_of(&[1, 2, 3]),
    member_set(&[1, 2, 3]),
    MembershipTarget::new(member_set(&[1, 2, 3, 4]), BTreeSet::new()),
    ack(),
  );
  assert_eq!(delta, SingleVoterDelta::AddLearner(MemberId::new(4)));
  assert!(
    !attached,
    "a grow step is not f-reducing: no token attached"
  );
}

// ── GC-lane pre-probe fail-closed ─────────────────────────────────

#[test]
fn gc_pre_probe_stalls_when_the_current_voter_quorum_is_unproven() {
  // {1,2,3}v + {8}L -> {1,2,3}v: the only step is RemoveLearner(8) (an obsolete-learner prune). Its op
  // must commit under the current voting quorum, but only self (1) is proven live, so the GC pre-probe
  // stalls fail-closed rather than proposing a removal that cannot commit.
  let backend = mock_with_learner(&[1, 2, 3], 8, &[1]);
  let target = MembershipTarget::new(member_set(&[1, 2, 3]), BTreeSet::new());
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    None,
  ));
  match r {
    Err(ReconfigureError::InsufficientLiveness { unproven, .. }) => {
      assert_eq!(
        unproven,
        member_set(&[2, 3]),
        "names the current voters lacking a fresh proof"
      );
    }
    other => panic!("expected InsufficientLiveness from the GC pre-probe, got {other:?}"),
  }
  assert!(
    backend.0.borrow().issued.is_empty(),
    "no RemoveLearner issued (GC pre-probe fail-closed)"
  );
}

#[test]
fn gc_pre_probe_proceeds_once_the_current_voter_quorum_is_proven() {
  // The same shape, but with the current voter quorum proven live: the GC proceeds.
  let backend = mock_with_learner(&[1, 2, 3], 8, &[1, 2, 3]);
  let target = MembershipTarget::new(member_set(&[1, 2, 3]), BTreeSet::new());
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    None,
  ));
  assert!(r.is_ok(), "a proven voter quorum admits the GC: {r:?}");
  assert_eq!(
    backend.0.borrow().issued,
    std::vec![SingleVoterDelta::RemoveLearner(MemberId::new(8))]
  );
}

// ── self-demote handoff (DemotedSelf) ─────────────────────────────

#[test]
fn self_demote_then_gc_surfaces_demoted_self_for_handoff() {
  // {1,2,3} -> {2,3}, driven by self (1), which leaves ENTIRELY. Self demotes itself (the last departing
  // voter), then the only step left is its own GC — which self, now a learner, cannot drive. The executor
  // surfaces DemotedSelf carrying the remaining RemoveLearner(self) for a surviving voter to finish. The
  // goal reduces f (1 -> 0), so it is acknowledged.
  let backend = mock(&[1, 2, 3], &[1, 2, 3]);
  let target = MembershipTarget::new(member_set(&[2, 3]), BTreeSet::new());
  let r = block_on(run_reconfigure(
    backend.clone(),
    target,
    HealthHint::default(),
    MemberId::new(1),
    ack(),
  ));
  match r {
    Err(ReconfigureError::DemotedSelf { progress }) => {
      let (v, _) = sets_of(progress.live());
      assert_eq!(
        v,
        member_set(&[2, 3]),
        "self has already demoted itself out of the voting set"
      );
      assert_eq!(
        progress.remaining().map(<[_]>::to_vec),
        Some(std::vec![SingleVoterDelta::RemoveLearner(MemberId::new(1))]),
        "only self's own GC remains, for a surviving voter to run"
      );
    }
    other => panic!("expected DemotedSelf, got {other:?}"),
  }
  // Self demoted itself (committed) but did NOT issue its own RemoveLearner.
  assert_eq!(
    backend.0.borrow().issued,
    std::vec![SingleVoterDelta::DemoteVoter(MemberId::new(1))],
    "self issued only its own demote, never its own GC"
  );
}

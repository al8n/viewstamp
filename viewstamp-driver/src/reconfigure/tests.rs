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

// ── progress and error type tests ───────────────────────────────────

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

// ── advance-level deadline hard-cancel tests ──────────────────────

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

// ── self-removal ranked-last test ─────────────────────────────────

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

/// The self-last ordering is unconditional: it must hold even when the local node has NO
/// positive evidence (apparently_down) and a peer IS known_up.  Under the old key
/// `(!apparently_down, m == local_member, m.get())`, local (1) and peer (3) both land in the
/// apparently_down bucket (local=not-witnessed, peer=not-witnessed), so the secondary key
/// `m == local_member` would fire: local=true > peer=false → local wins the descending sort
/// and is removed first, retiring the driver.  Under the correct key `(m == local_member, ...)`
/// local always sorts last regardless of its liveness.
///
/// live = {1,2,3,4,5}, local_member = 1, candidates = RemoveVoter(1) + RemoveVoter(3).
/// known_up = {2,4,5}; local (1) and candidate (3) are BOTH absent → both apparently_down.
/// Removing 3 → successor {1,2,4,5}, len=4, quorum=3, confirmed={2,4,5}=3 ≥ 3 ✓
/// Removing 1 → successor {2,3,4,5}, len=4, quorum=3, confirmed={2,4,5}=3 ≥ 3 ✓
/// Both pass the fail-closed gate; self-last must select RemoveVoter(3) even though local is
/// apparently_down (same liveness bucket).
#[test]
fn self_removal_is_ranked_last_even_when_local_has_no_positive_evidence() {
  let live = membership_of(&[1, 2, 3, 4, 5]);
  let health = HealthHint {
    known_up: member_set(&[2, 4, 5]), // local (1) and peer (3) both absent from known_up
    known_down: BTreeSet::new(),
  };
  let responsive = BTreeSet::new(); // no recent acks — neither local nor peer is witnessed
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
    "RemoveVoter(3) must be chosen before RemoveVoter(1) (self) even when both are apparently_down"
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
    64,
    Duration::from_secs(30),
    reply_tx,
    live.clone(),
    member_set(&[1, 2, 3]),
    MemberId::new(1),
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
    64,
    Duration::from_secs(30),
    reply_tx,
    live.clone(),
    member_set(&[1, 2, 3]),
    MemberId::new(1),
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

use super::*;

fn ids(xs: &[u128]) -> BTreeSet<MemberId> {
  xs.iter().copied().map(MemberId::new).collect()
}

fn genesis(voters: &[u128], learners: &[u128]) -> Membership {
  let mut members: Vec<MemberId> = voters.iter().copied().map(MemberId::new).collect();
  members.extend(learners.iter().copied().map(MemberId::new));
  Membership::genesis(voters.len() as u8, learners.len() as u16, members).unwrap()
}

fn target(voters: &[u128], learners: &[u128]) -> MembershipTarget {
  MembershipTarget::new(ids(voters), ids(learners))
}

/// Fold `apply_delta` over a plan and return the resulting voter/learner SETS.
fn apply_plan(
  start: &Membership,
  plan: &[SingleVoterDelta],
) -> (BTreeSet<MemberId>, BTreeSet<MemberId>) {
  let mut m = start.clone();
  for d in plan {
    m = m
      .apply_delta(d)
      .expect("each planned delta applies in sequence");
  }
  let voters: BTreeSet<MemberId> = (0..m.replica_count())
    .map(|s| m.member_at(crate::id::ReplicaId::new(s as u16)).unwrap())
    .collect();
  let all: BTreeSet<MemberId> = m.members_slice().iter().copied().collect();
  let learners: BTreeSet<MemberId> = all.difference(&voters).copied().collect();
  (voters, learners)
}

#[test]
fn end_state_set_equivalence_for_canonical_rotation() {
  // {1,2,3} -> {3,4,5}: stage 4,5 as learners, promote, remove 1,2.
  let c = genesis(&[1, 2, 3], &[]);
  let t = target(&[3, 4, 5], &[]);
  let plan = plan_reconfiguration(&c, &t).unwrap();
  let (v, l) = apply_plan(&c, &plan);
  assert_eq!(v, ids(&[3, 4, 5]), "the final voter SET equals the target");
  assert_eq!(l, BTreeSet::new(), "no residual learners");
}

#[test]
fn a_pure_reorder_yields_the_empty_plan() {
  // Same voter+learner sets as `current` (any slot order) => no reconfiguration.
  let c = genesis(&[1, 2, 3], &[8]);
  let t = target(&[3, 1, 2], &[8]);
  assert!(plan_reconfiguration(&c, &t).unwrap().is_empty());
}

#[test]
fn every_emitted_delta_applies_in_sequence_and_never_raw_add_voter() {
  let c = genesis(&[1, 2, 3], &[8]);
  let t = target(&[2, 3, 4, 5], &[9]);
  let plan = plan_reconfiguration(&c, &t).unwrap();
  // Each delta applies against its immediate predecessor (the apply_plan unwrap proves it).
  let _ = apply_plan(&c, &plan);
  assert!(
    !plan.iter().any(SingleVoterDelta::is_add_voter),
    "the planner grows the voting set ONLY via AddLearner+PromoteLearner, never raw AddVoter"
  );
}

#[test]
fn grow_before_shrink_prefix_keeps_a_structural_majority() {
  let c = genesis(&[1, 2, 3], &[]);
  let t = target(&[1], &[]); // shrink {1,2,3} -> {1}
  let plan = plan_reconfiguration(&c, &t).unwrap();
  // At every prefix the voter count stays at or above |Vt| = 1 (the shrink target floor).
  let mut m = c.clone();
  assert!(m.replica_count() as usize >= 3); // initial: max(|Vt|, |Vc|) = 3
  for d in &plan {
    m = m.apply_delta(d).unwrap();
    assert!(
      m.replica_count() as usize >= 1,
      "a structural majority always exists"
    );
  }
}

#[test]
fn phase_0_prunes_obsolete_learner_before_phase_4_adds() {
  // Swap a learner: {1,2,3}+learner{8} -> {1,2,3}+learner{9}.
  let c = genesis(&[1, 2, 3], &[8]);
  let t = target(&[1, 2, 3], &[9]);
  let plan = plan_reconfiguration(&c, &t).unwrap();
  let rm = plan
    .iter()
    .position(|d| matches!(d, SingleVoterDelta::RemoveLearner(m) if *m == MemberId::new(8)));
  let add = plan
    .iter()
    .position(|d| matches!(d, SingleVoterDelta::AddLearner(m) if *m == MemberId::new(9)));
  assert!(
    rm.is_some() && add.is_some(),
    "both the prune and the add are emitted"
  );
  assert!(
    rm.unwrap() < add.unwrap(),
    "Phase 0 prune precedes the Phase 4 add"
  );
}

#[test]
fn overlap_demotion_empty_and_oversize_reject_at_preflight_with_zero_steps() {
  let c = genesis(&[1, 2, 3], &[]);
  // Overlap: 4 in BOTH sets — checked FIRST.
  assert_eq!(
    plan_reconfiguration(&c, &target(&[1, 2, 4], &[4])),
    Err(PlanError::VoterLearnerOverlap)
  );
  // Demotion: current voter 3 becomes a target learner.
  assert_eq!(
    plan_reconfiguration(&c, &target(&[1, 2], &[3])),
    Err(PlanError::VoterToLearnerDemotionUnsupported)
  );
  // Empty voter set.
  assert_eq!(
    plan_reconfiguration(&c, &target(&[], &[1])),
    Err(PlanError::EmptyVoterSet)
  );
}

#[test]
fn plan_reconfiguration_rejects_a_target_voter_set_above_the_64_voter_cap() {
  // Checked before the union-peak simulation: the target SIZE alone (65 voters, independent of
  // `current`) is already over the cap.
  let c = genesis(&[1], &[]);
  let too_many: Vec<u128> = (1..=65).collect();
  assert_eq!(
    plan_reconfiguration(&c, &target(&too_many, &[])),
    Err(PlanError::TooManyVoters { count: 65 })
  );
}

#[test]
fn peak_cap_admits_remove_then_add_the_union_overestimates() {
  // The closed-form union |Vc∪Vt| is the VOTER peak; a 4→4 disjoint swap with a real 4-cap is rejected,
  // but a remove-then-add target whose UNION over-estimates the node peak is admitted.
  // Voter peak rejection (use the real 64-cap shape scaled): a disjoint swap that peaks past 64.
  let big_v: Vec<u128> = (1..=64).collect();
  let c = genesis(&big_v, &[]);
  let disjoint: Vec<u128> = (65..=128).collect();
  assert_eq!(
    plan_reconfiguration(&c, &target(&disjoint, &[])),
    Err(PlanError::IntermediatePeakExceedsCap { peak: 128 }),
    "a 64->64 disjoint swap peaks at |Vc∪Vt| = 128 > 64"
  );
  // Node peak admits a remove-then-add: current voters {1,2,3,4} + a few learners; target keeps {1}
  // and adds exactly as many learners as it removes voters (3). The all-members union counts the
  // removed voters AND the new learners together; the real running peak frees the slot first.
  let c2 = genesis(&[1, 2, 3, 4], &[10, 11]);
  let t2 = target(&[1], &[10, 11, 20, 21, 22]); // removes 2,3,4; adds 20,21,22 (3 == 3)
  let plan =
    plan_reconfiguration(&c2, &t2).expect("the exact node peak admits the remove-then-add");
  let (v, _l) = apply_plan(&c2, &plan);
  assert_eq!(v, ids(&[1]));
}

#[test]
fn membership_target_well_formedness_and_accessors() {
  let t = MembershipTarget::new(ids(&[1, 2, 3]), ids(&[4]));
  assert!(
    t.is_well_formed(),
    "disjoint voter/learner sets are well-formed"
  );
  assert_eq!(
    t.members(),
    ids(&[1, 2, 3, 4]),
    "members() is the voter∪learner union"
  );

  let overlap = MembershipTarget::new(ids(&[1, 2, 4]), ids(&[4]));
  assert!(
    !overlap.is_well_formed(),
    "an id in BOTH voters and learners is not well-formed"
  );
}

#[test]
fn plan_error_as_str_is_stable_for_every_variant() {
  use PlanError::*;
  assert_eq!(EmptyVoterSet.as_str(), "empty_voter_set");
  assert_eq!(TooManyVoters { count: 65 }.as_str(), "too_many_voters");
  assert_eq!(
    IntermediatePeakExceedsCap { peak: 128 }.as_str(),
    "intermediate_peak_exceeds_cap"
  );
  assert_eq!(
    IntermediateNodePeakExceedsCap { peak: 65_600 }.as_str(),
    "intermediate_node_peak_exceeds_cap"
  );
  assert_eq!(RemovesLastVoter.as_str(), "removes_last_voter");
  assert_eq!(VoterLearnerOverlap.as_str(), "voter_learner_overlap");
  assert_eq!(
    VoterToLearnerDemotionUnsupported.as_str(),
    "voter_to_learner_demotion_unsupported"
  );
  assert_eq!(
    MemberConcurrentlyRemoved { members: ids(&[4]) }.as_str(),
    "member_concurrently_removed"
  );
}

#[test]
fn plan_error_display_is_non_empty() {
  // thiserror `#[error("…")]` renders for every variant (no empty/`{:?}`-only message).
  let e = PlanError::TooManyVoters { count: 65 };
  assert!(!std::format!("{e}").is_empty());
}

#[test]
fn plan_next_step_equals_first_element_for_random_shapes() {
  let cases = [
    (genesis(&[1, 2, 3], &[]), target(&[3, 4, 5], &[])),
    (genesis(&[1, 2, 3], &[8]), target(&[1, 2, 3], &[9])),
    (genesis(&[1, 2, 3, 4], &[]), target(&[1, 2, 3], &[])),
    (genesis(&[1, 2, 3], &[]), target(&[1, 2, 3], &[])), // done
  ];
  for (c, t) in &cases {
    let whole = plan_reconfiguration(c, t).unwrap();
    assert_eq!(plan_next_step(c, t).unwrap(), whole.first().cloned());
  }
}

#[test]
fn plan_next_step_propagates_preflight_errors() {
  let c = genesis(&[1, 2, 3], &[]);
  assert_eq!(
    plan_next_step(&c, &target(&[1, 2], &[3])),
    Err(PlanError::VoterToLearnerDemotionUnsupported)
  );
}

#[test]
fn shrink_candidates_is_empty_until_the_grow_prefix_is_done() {
  // Replace a dead node: {1,2,3} -> {1,2,4}. Before 4 is promoted there is still a grow step, so the
  // shrink set is empty; only once all of Vt is present is the RemoveVoter(3) due.
  let c = genesis(&[1, 2, 3], &[]);
  let t = target(&[1, 2, 4], &[]);
  assert!(
    shrink_candidates(&c, &t).unwrap().is_empty(),
    "no removal is due while 4 still needs staging+promoting"
  );
  // Once 4 is a voter (simulate the grow prefix), the departing voter 3 is the candidate.
  let grown = c
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(4)))
    .unwrap()
    .apply_delta(&SingleVoterDelta::PromoteLearner(MemberId::new(4)))
    .unwrap();
  assert_eq!(
    shrink_candidates(&grown, &t).unwrap(),
    std::vec![SingleVoterDelta::RemoveVoter(MemberId::new(3))]
  );
}

#[test]
fn shrink_candidates_is_empty_when_the_plan_has_no_removals_at_all() {
  // Pure growth: {1,2,3} -> {1,2,3,4} adds a voter without removing any existing one, so the plan
  // never emits a RemoveVoter at all (distinct from the grow-prefix-pending case above, where a
  // RemoveVoter IS in the plan but not yet due).
  let c = genesis(&[1, 2, 3], &[]);
  let t = target(&[1, 2, 3, 4], &[]);
  let plan = plan_reconfiguration(&c, &t).unwrap();
  assert!(
    !plan.iter().any(SingleVoterDelta::is_remove_voter),
    "sanity: pure growth emits no RemoveVoter"
  );
  assert!(shrink_candidates(&c, &t).unwrap().is_empty());
}

#[test]
fn shrink_candidates_returns_the_full_phase3_set_when_all_of_vt_present() {
  // {1,2,3,4,5} -> {1,2}: all of Vt present, so the candidates are RemoveVoter(3),(4),(5) ascending.
  let c = genesis(&[1, 2, 3, 4, 5], &[]);
  let t = target(&[1, 2], &[]);
  assert_eq!(
    shrink_candidates(&c, &t).unwrap(),
    std::vec![
      SingleVoterDelta::RemoveVoter(MemberId::new(3)),
      SingleVoterDelta::RemoveVoter(MemberId::new(4)),
      SingleVoterDelta::RemoveVoter(MemberId::new(5)),
    ]
  );
}

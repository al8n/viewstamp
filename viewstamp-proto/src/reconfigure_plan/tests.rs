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

/// `f(n) = n − quorum(n) = ⌊(n−1)/2⌋` — the simultaneous voter crashes a config of `n` voters survives.
fn f_of(n: usize) -> usize {
  n.saturating_sub(1) / 2
}

/// Fold the plan and return the voter-count trajectory (start count included) plus the count of FORCED
/// demotes — a `DemoteVoter` applied at an ODD voter count, the only step that reduces `f`.
fn trajectory(start: &Membership, plan: &[SingleVoterDelta]) -> (Vec<usize>, usize) {
  let mut m = start.clone();
  let mut counts = std::vec![m.replica_count() as usize];
  let mut forced = 0usize;
  for d in plan {
    if d.is_demote_voter() && m.replica_count() % 2 == 1 {
      forced += 1;
    }
    m = m
      .apply_delta(d)
      .expect("each planned delta applies in sequence");
    counts.push(m.replica_count() as usize);
  }
  (counts, forced)
}

/// Assert EVERY parity-planner invariant for an admitted `(current, target)`: end-state equivalence,
/// the forced-descent count, the tolerance floor, the `f`-drops-only-on-an-odd-n-demote rule, the voter
/// peak, and memoryless re-planning. A rejected target is skipped (not a property case).
fn check_properties(c: &Membership, t: &MembershipTarget) {
  let Ok(plan) = plan_reconfiguration(c, t) else {
    return;
  };
  let (vc, _lc) = voter_learner_sets(c);
  let vt = t.voters();
  let n0 = vc.len();
  let nt = vt.len();

  // End-state equivalence: the plan reaches EXACTLY the target voter and learner sets.
  let (v_end, l_end) = apply_plan(c, &plan);
  assert_eq!(v_end, *vt, "the final voter set equals the target");
  assert_eq!(
    l_end,
    *t.learners(),
    "the final learner set equals the target"
  );

  // Forced-descent count = max(0, f0 − fT); forced demotes occur ONLY at odd n by `trajectory`'s count.
  let (counts, forced) = trajectory(c, &plan);
  assert_eq!(
    forced,
    f_of(n0).saturating_sub(f_of(nt)),
    "forced descents == max(0, f0 − fT)"
  );

  // Tolerance floor: f ≥ min(f0, fT) at every step of the trajectory.
  let floor = f_of(n0).min(f_of(nt));
  for &n in &counts {
    assert!(f_of(n) >= floor, "f dipped below min(f0, fT)");
  }

  // f decreases ONLY on a forced (odd-n) demote; every other step holds or grows f.
  let mut m = c.clone();
  for d in &plan {
    let f_before = f_of(m.replica_count() as usize);
    let odd = m.replica_count() % 2 == 1;
    m = m.apply_delta(d).unwrap();
    if f_of(m.replica_count() as usize) < f_before {
      assert!(
        d.is_demote_voter() && odd,
        "f drops only on a demote from an odd voter count"
      );
    }
  }

  // Voter peak ≤ max(n0, nT) + 1.
  let peak = counts.iter().copied().max().unwrap();
  assert!(peak <= n0.max(nt) + 1, "voter peak within max(n0, nT) + 1");

  // MEMORYLESS: re-planning from the membership left by executing plan[0] reproduces plan[1..] exactly.
  if let Some(first) = plan.first() {
    let next = c.apply_delta(first).expect("plan[0] applies to current");
    let replanned = plan_reconfiguration(&next, t).expect("the re-plan admits");
    assert_eq!(
      replanned.as_slice(),
      &plan[1..],
      "the memoryless re-plan equals the plan suffix"
    );
  }
}

#[test]
fn end_state_set_equivalence_for_canonical_rotation() {
  // {1,2,3} -> {3,4,5}: stage 4,5 as learners, then interleave promoting them with demoting+GC'ing 1,2.
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
fn every_emitted_delta_applies_in_sequence() {
  let c = genesis(&[1, 2, 3], &[8]);
  let t = target(&[2, 3, 4, 5], &[9]);
  let plan = plan_reconfiguration(&c, &t).unwrap();
  // Each delta applies against its immediate predecessor (the apply_plan unwrap proves it). That the
  // plan grows the voting set ONLY via AddLearner+PromoteLearner needs no runtime assert anymore:
  // the `SingleVoterDelta` vocabulary has no raw voter add to emit.
  let _ = apply_plan(&c, &plan);
}

#[test]
fn demote_first_shrink_keeps_a_structural_majority() {
  let c = genesis(&[1, 2, 3], &[]);
  let t = target(&[1], &[]); // shrink {1,2,3} -> {1}
  let plan = plan_reconfiguration(&c, &t).unwrap();
  // At every prefix the voter count stays at or above |Vt| = 1 (the shrink target floor).
  let mut m = c.clone();
  assert!(m.replica_count() as usize >= 3); // initial: |Vc| = 3
  for d in &plan {
    m = m.apply_delta(d).unwrap();
    assert!(
      m.replica_count() as usize >= 1,
      "a structural majority always exists"
    );
  }
}

#[test]
fn p0_prunes_obsolete_learner_before_p3_adds() {
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
    "the P0 prune precedes the P3 residual add"
  );
}

#[test]
fn overlap_empty_and_oversize_reject_at_preflight_with_zero_steps() {
  let c = genesis(&[1, 2, 3], &[]);
  // Overlap: 4 in BOTH sets — checked FIRST.
  assert_eq!(
    plan_reconfiguration(&c, &target(&[1, 2, 4], &[4])),
    Err(PlanError::VoterLearnerOverlap)
  );
  // Empty voter set.
  assert_eq!(
    plan_reconfiguration(&c, &target(&[], &[1])),
    Err(PlanError::EmptyVoterSet)
  );
}

#[test]
fn a_current_voter_demoted_to_a_target_learner_plans_as_a_demote() {
  // What was rejected as an unsupported voter→learner demotion is now a first-class demote: voter 3
  // becomes a KEPT learner. The plan demotes 3 and does NOT GC it (the target keeps it as a learner).
  let c = genesis(&[1, 2, 3], &[]);
  let t = target(&[1, 2], &[3]);
  let plan = plan_reconfiguration(&c, &t).unwrap();
  assert_eq!(
    plan,
    std::vec![SingleVoterDelta::DemoteVoter(MemberId::new(3))]
  );
  let (v, l) = apply_plan(&c, &plan);
  assert_eq!(v, ids(&[1, 2]));
  assert_eq!(
    l,
    ids(&[3]),
    "the demoted voter is kept as a learner, not GC'd"
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
fn a_large_disjoint_swap_admits_because_demote_first_caps_the_voter_peak() {
  // The OLD grow-before-shrink rejected a 64→64 disjoint swap (all old+new voters coexisted, peak 128).
  // Demote-first interleaves demotions and promotions, so the voter count oscillates at/below 64 and the
  // swap ADMITS — the transient node peak (128 seated members) is well under u16::MAX.
  let big_v: Vec<u128> = (1..=64).collect();
  let c = genesis(&big_v, &[]);
  let disjoint: Vec<u128> = (65..=128).collect();
  let plan =
    plan_reconfiguration(&c, &target(&disjoint, &[])).expect("demote-first admits the swap");
  let (v, _l) = apply_plan(&c, &plan);
  assert_eq!(v, ids(&disjoint), "the swap reaches the target voter set");
  let mut m = c.clone();
  let mut peak = m.replica_count() as usize;
  for d in &plan {
    m = m.apply_delta(d).unwrap();
    peak = peak.max(m.replica_count() as usize);
  }
  assert!(
    peak <= 64,
    "demote-first keeps the voter peak at the cap, got {peak}"
  );
}

#[test]
fn the_node_peak_admits_a_remove_then_add() {
  // Current voters {1,2,3,4} + learners {10,11}; target keeps {1} and adds learners. Demote-first frees
  // each demoted voter's slot as it GCs, so the node peak stays modest and the plan admits.
  let c2 = genesis(&[1, 2, 3, 4], &[10, 11]);
  let t2 = target(&[1], &[10, 11, 20, 21, 22]);
  let plan = plan_reconfiguration(&c2, &t2).expect("the node peak admits the remove-then-add");
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
    plan_next_step(&c, &target(&[1, 2, 4], &[4])),
    Err(PlanError::VoterLearnerOverlap)
  );
}

#[test]
fn shrink_candidates_is_empty_while_the_parity_core_leads_with_a_promote() {
  // Replace a dead node: {1,2,3} -> {1,2,4}. The parity core stages+promotes 4 before demoting 3 (an
  // odd-n promote leads), so no demotion is due yet and the candidate set is empty.
  let c = genesis(&[1, 2, 3], &[]);
  let t = target(&[1, 2, 4], &[]);
  assert!(
    shrink_candidates(&c, &t).unwrap().is_empty(),
    "no demotion is due while 4 still needs staging+promoting"
  );
  // Once 4 is a voter (simulate the grow prefix), the departing voter 3 is the demotion candidate.
  let grown = c
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(4)))
    .unwrap()
    .apply_delta(&SingleVoterDelta::PromoteLearner(MemberId::new(4)))
    .unwrap();
  assert_eq!(
    shrink_candidates(&grown, &t).unwrap(),
    std::vec![SingleVoterDelta::DemoteVoter(MemberId::new(3))]
  );
}

#[test]
fn shrink_candidates_is_empty_when_the_plan_has_no_demotions_at_all() {
  // Pure growth: {1,2,3} -> {1,2,3,4} promotes a new voter without demoting any existing one, so the
  // plan never emits a DemoteVoter at all (distinct from the promote-leads case above, where a
  // DemoteVoter IS in the plan but not yet due).
  let c = genesis(&[1, 2, 3], &[]);
  let t = target(&[1, 2, 3, 4], &[]);
  let plan = plan_reconfiguration(&c, &t).unwrap();
  assert!(
    !plan.iter().any(SingleVoterDelta::is_demote_voter),
    "sanity: pure growth emits no DemoteVoter"
  );
  assert!(shrink_candidates(&c, &t).unwrap().is_empty());
}

#[test]
fn shrink_candidates_returns_the_full_demotion_set_when_a_demote_leads() {
  // {1,2,3,4,5} -> {1,2}: a pure shrink, so the plan leads with a demote and the candidates are
  // DemoteVoter(3),(4),(5) ascending (the executor reorders them health-aware).
  let c = genesis(&[1, 2, 3, 4, 5], &[]);
  let t = target(&[1, 2], &[]);
  assert_eq!(
    shrink_candidates(&c, &t).unwrap(),
    std::vec![
      SingleVoterDelta::DemoteVoter(MemberId::new(3)),
      SingleVoterDelta::DemoteVoter(MemberId::new(4)),
      SingleVoterDelta::DemoteVoter(MemberId::new(5)),
    ]
  );
}

#[test]
fn parity_planner_invariants_hold_across_many_shapes() {
  // Enumerate current voter counts and targets spanning pure grows, pure shrinks (odd and even n),
  // rotations, rotation+shrink, rotation+grow, and demote-and-keep-as-learner goals. `check_properties`
  // asserts end-state equivalence, forced-count, the tolerance floor, the peak, and memorylessness.
  for n0 in 1usize..=6 {
    let cur_voters: Vec<u128> = (1..=n0 as u128).collect();
    for keep in 0..=n0 {
      for add in 0..=3usize {
        let mut tv: Vec<u128> = cur_voters[..keep].to_vec();
        tv.extend((100..100 + add as u128).collect::<Vec<_>>());
        if tv.is_empty() {
          continue; // an empty voter target is a preflight rejection, not a property case
        }
        // Route a prefix of the dropped voters into the target learner set (demote-and-keep).
        let dropped: Vec<u128> = cur_voters[keep..].to_vec();
        for keep_as_learner in 0..=dropped.len() {
          let tl: Vec<u128> = dropped[..keep_as_learner].to_vec();
          check_properties(&genesis(&cur_voters, &[]), &target(&tv, &tl));
        }
      }
    }
  }
}

#[test]
fn parity_planner_invariants_hold_with_existing_learners() {
  // Shapes carrying learners at the start exercise the P0 prune and the promote-existing-learner lane.
  check_properties(&genesis(&[1, 2, 3], &[8, 9]), &target(&[1, 2, 9], &[]));
  check_properties(&genesis(&[1, 2, 3], &[8]), &target(&[1, 2, 3], &[9]));
  check_properties(&genesis(&[1, 2, 3, 4, 5], &[8]), &target(&[1, 8], &[2]));
  check_properties(&genesis(&[1, 2, 3], &[4, 5]), &target(&[4, 5], &[1, 2, 3]));
}

#[test]
fn rotations_and_grows_force_zero_gated_steps() {
  // A pure rotation (nT = n0) and a pure grow (nT > n0) never reduce f, so no forced descent occurs.
  for (cv, tv) in [
    (std::vec![1u128, 2, 3], std::vec![3u128, 4, 5]), // rotate, n stays 3 (odd)
    (std::vec![1u128, 2, 3, 4], std::vec![1u128, 2, 5, 6]), // rotate, n stays 4 (even)
    (std::vec![1u128, 2, 3], std::vec![1u128, 2, 3, 4, 5]), // grow 3 -> 5
    (std::vec![1u128, 2], std::vec![1u128, 2, 3]),    // grow 2 -> 3
  ] {
    let c = genesis(&cv, &[]);
    let t = target(&tv, &[]);
    let plan = plan_reconfiguration(&c, &t).unwrap();
    let (_counts, forced) = trajectory(&c, &plan);
    assert_eq!(forced, 0, "rotations/grows force zero gated demotes");
  }
}

#[test]
fn forced_descent_count_equals_the_tolerance_drop() {
  // Pure shrinks: the count of odd-n (forced) demotes equals max(0, f0 − fT).
  for (cv, tv, expect) in [
    (std::vec![1u128, 2, 3], std::vec![1u128], 1usize), // f 1 -> 0
    (std::vec![1u128, 2, 3], std::vec![1u128, 2], 1),   // f 1 -> 0
    (std::vec![1u128, 2, 3, 4, 5], std::vec![1u128, 2, 3], 1), // f 2 -> 1
    (std::vec![1u128, 2, 3, 4, 5], std::vec![1u128], 2), // f 2 -> 0
    (std::vec![1u128, 2, 3, 4], std::vec![1u128, 2, 3], 0), // f 1 -> 1 (an even-n demote is neutral)
  ] {
    let c = genesis(&cv, &[]);
    let t = target(&tv, &[]);
    let plan = plan_reconfiguration(&c, &t).unwrap();
    let (_counts, forced) = trajectory(&c, &plan);
    assert_eq!(forced, expect, "forced count for {cv:?} -> {tv:?}");
    assert_eq!(forced, f_of(cv.len()).saturating_sub(f_of(tv.len())));
  }
}

#[test]
fn a_demotee_kept_as_a_target_learner_is_never_gc_d() {
  // {1,2,3,4,5} -> voters {1,2,3}, learners {4,5}: 4 and 5 are demoted and KEPT as learners (no GC).
  let c = genesis(&[1, 2, 3, 4, 5], &[]);
  let t = target(&[1, 2, 3], &[4, 5]);
  let plan = plan_reconfiguration(&c, &t).unwrap();
  assert!(
    !plan.iter().any(SingleVoterDelta::is_remove_learner),
    "a demotee the target keeps as a learner is never GC'd"
  );
  let (v, l) = apply_plan(&c, &plan);
  assert_eq!(v, ids(&[1, 2, 3]));
  assert_eq!(l, ids(&[4, 5]));
}

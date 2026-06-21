//! The pure reconfiguration PLANNER: lower an arbitrary `MembershipTarget` set-goal to a bounded
//! grow-before-shrink sequence of proven Tier B `SingleVoterDelta` steps. PURE — no I/O, no `self`, no
//! consensus state; it constructs no op, touches no durable state, sends no wire message. Per-step
//! safety is inherited from Tier B unchanged.

use std::collections::BTreeSet;
use std::vec::Vec;

use crate::id::MemberId;
use crate::membership::{Membership, SingleVoterDelta};

/// The SET-only reconfiguration goal: WHO votes and WHO learns, as two `MemberId` sets. NOT a full
/// [`Membership`] — the slot order, `epoch`, and `config_id` are DERIVED by `apply_delta` and are not an
/// operator's to choose (a pure reorder is not a reconfiguration). The planner targets this.
///
/// WELL-FORMEDNESS: `voters` and `learners` MUST be disjoint. A single [`MemberId`] cannot be BOTH a
/// voter and a learner in any [`Membership`] (a member occupies one slot; every constructor rejects a
/// duplicated id). An overlapping target is UNREPRESENTABLE as an end state; the planner rejects it
/// statically as [`PlanError::VoterLearnerOverlap`].
///
/// OPERATOR PRECONDITIONS (scoped member identity): `reconfigure_to` is the SOLE reconfiguration driver
/// for the cluster, and every target member ABSENT from the current membership MUST be a FRESH, reachable,
/// newly-bootstrapped node (a previously-retired id MUST NOT be reused for a new physical node without
/// rebootstrapping it). The planner cannot distinguish a fresh id from a retired tombstone for an
/// absent-from-`current` id (a set carries no history), so it adds it via `AddLearner` trusting the
/// operator provisioned a fresh node. A violation is a liveness/observability gap (a dead voter target
/// stalls visibly; a dead learner-only target false-completes), never a committed-op loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipTarget {
  /// The target VOTING set.
  pub voters: BTreeSet<MemberId>,
  /// The target non-voting LEARNER set. MUST be disjoint from `voters`.
  pub learners: BTreeSet<MemberId>,
}

impl MembershipTarget {
  /// A target from its voter and learner sets.
  pub fn new(voters: BTreeSet<MemberId>, learners: BTreeSet<MemberId>) -> Self {
    Self { voters, learners }
  }

  /// Whether `voters` and `learners` are disjoint — the structural well-formedness an overlapping
  /// target violates (rejected as [`PlanError::VoterLearnerOverlap`]).
  pub fn is_well_formed(&self) -> bool {
    self.voters.is_disjoint(&self.learners)
  }

  /// The union `voters ∪ learners` — every member the target names. The executor intersects this with a
  /// live snapshot to track `members_seen`.
  pub fn members(&self) -> BTreeSet<MemberId> {
    self.voters.union(&self.learners).copied().collect()
  }
}

/// An error rejecting a statically-impossible reconfiguration target, returned by the pure planner —
/// PLUS the one executor-constructed dynamic variant [`Self::MemberConcurrentlyRemoved`] (the pure
/// planner never returns it; it shares this type because the executor carries it in its progress payload).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
  /// The target voter set is empty; a configuration needs at least one voter.
  #[error("the target voter set is empty: a configuration needs at least one voter")]
  EmptyVoterSet,
  /// The target voter set exceeds the 64-voter cap (the prepare-ok bitset width).
  #[error("too many target voters: {count} (the cap is 64)")]
  TooManyVoters {
    /// The rejected target voter count.
    count: usize,
  },
  /// The grow-before-shrink VOTER peak `|Vc ∪ Vt|` would exceed the 64-voter cap mid-plan (a near-cap
  /// disjoint replacement). Batch the change SHRINK-FIRST into remove-only then grow-only sub-targets.
  #[error("the intermediate voter peak {peak} would exceed the 64-voter cap (batch shrink-first)")]
  IntermediatePeakExceedsCap {
    /// The simulated running voter-count maximum that exceeded the cap.
    peak: usize,
  },
  /// The phase-ordered NODE peak (`replica_count + learner_count`) would exceed `u16::MAX` mid-plan.
  #[error("the intermediate node peak {peak} would exceed the maximum of 65535")]
  IntermediateNodePeakExceedsCap {
    /// The simulated running `node_count` maximum that exceeded the cap.
    peak: u32,
  },
  /// The plan would transit through a zero-voter configuration (defensive; unreachable under
  /// grow-before-shrink for a non-empty target).
  #[error("the plan would remove the last voter")]
  RemovesLastVoter,
  /// The target lists an id as BOTH a voter and a learner — unrepresentable (a member holds one slot).
  #[error("a target id is both a voter and a learner (a member holds one slot)")]
  VoterLearnerOverlap,
  /// The target asks a CURRENT voter to become a LEARNER (a voter→learner DEMOTION). Not achievable
  /// online — `RemoveVoter` retires the live node before the follow-up `AddLearner` can reach it.
  /// Recover the node as a learner by OUT-OF-BAND rebootstrap (start it fresh).
  #[error(
    "voter→learner demotion is not supported online (rebootstrap the node as a fresh learner)"
  )]
  VoterToLearnerDemotionUnsupported,
  /// A target member that was OBSERVED present was concurrently removed/retired, so it is a dead endpoint
  /// not online-re-addable. Executor-constructed (the pure planner never returns it). Recover the node by
  /// OUT-OF-BAND rebootstrap, or a Tier C offline path.
  #[error("a needed target member was concurrently removed (rebootstrap it out-of-band)")]
  MemberConcurrentlyRemoved {
    /// The members observed present then concurrently retired.
    members: BTreeSet<MemberId>,
  },
}

impl PlanError {
  /// The stable snake_case name of this variant (serialization-stable).
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::EmptyVoterSet => "empty_voter_set",
      Self::TooManyVoters { .. } => "too_many_voters",
      Self::IntermediatePeakExceedsCap { .. } => "intermediate_peak_exceeds_cap",
      Self::IntermediateNodePeakExceedsCap { .. } => "intermediate_node_peak_exceeds_cap",
      Self::RemovesLastVoter => "removes_last_voter",
      Self::VoterLearnerOverlap => "voter_learner_overlap",
      Self::VoterToLearnerDemotionUnsupported => "voter_to_learner_demotion_unsupported",
      Self::MemberConcurrentlyRemoved { .. } => "member_concurrently_removed",
    }
  }
}

/// The 64-voter cap (matches `MAX_VOTING_REPLICAS` in `membership.rs`; the prepare-ok bitset width).
const MAX_VOTERS: usize = 64;

/// Split a membership into its voter SET and learner SET (by slot kind).
fn voter_learner_sets(m: &Membership) -> (BTreeSet<MemberId>, BTreeSet<MemberId>) {
  let voters = m.replica_count() as usize;
  let members = m.members_slice();
  let v: BTreeSet<MemberId> = members[..voters].iter().copied().collect();
  let l: BTreeSet<MemberId> = members[voters..].iter().copied().collect();
  (v, l)
}

/// Lower a set goal to a bounded grow-before-shrink sequence of proven Tier B deltas, from `current`'s
/// voter/learner SETS to `target` (Phase 0 prune obsolete learners → Phase 1 stage new-voter learners →
/// Phase 2 promote → Phase 3 remove old voters → Phase 4 add residual target learners). PURE — no I/O, no
/// `self`. The peak caps are validated by SIMULATION: it BUILDS the ordered `Vec`, folds `apply_delta`
/// along it, and returns `IntermediatePeakExceedsCap` / `IntermediateNodePeakExceedsCap` iff the running
/// max exceeds the 64-voter / `u16::MAX`-node cap — so it never hands back a sequence a later `apply_delta`
/// would reject mid-plan. The set-only prechecks (disjointness, demotion, empty/oversize) are pure
/// properties of `(current, target)`, checked before the sequence is built.
///
/// The returned Phase-3 removals (`Vc \ Vt`) are emitted in a deterministic ascending-`MemberId` order
/// purely for a stable output; safety is order-independent, so the executor reorders that SET health-aware.
pub fn plan_reconfiguration(
  current: &Membership,
  target: &MembershipTarget,
) -> Result<Vec<SingleVoterDelta>, PlanError> {
  let (vc, lc) = voter_learner_sets(current);
  let vt = &target.voters;
  let lt = &target.learners;

  // PREFLIGHT set-only admission (overlap → empty → demotion → oversize → voter-union peak).
  if !vt.is_disjoint(lt) {
    return Err(PlanError::VoterLearnerOverlap);
  }
  if vt.is_empty() {
    return Err(PlanError::EmptyVoterSet);
  }
  // A current voter the target wants as a LEARNER — an online voter→learner DEMOTION.
  if vc.difference(vt).any(|x| lt.contains(x)) {
    return Err(PlanError::VoterToLearnerDemotionUnsupported);
  }
  if vt.len() > MAX_VOTERS {
    return Err(PlanError::TooManyVoters { count: vt.len() });
  }
  // The grow-before-shrink voter peak is |Vc ∪ Vt| (all current voters stay through Phase 2 while new
  // voters are promoted). Check this BEFORE building the plan so the reported peak is the union size,
  // not the simulation failure point — which matches the expectation a remove-then-grow batch would fix.
  let voter_union_peak = vc.union(vt).count();
  if voter_union_peak > MAX_VOTERS {
    return Err(PlanError::IntermediatePeakExceedsCap {
      peak: voter_union_peak,
    });
  }

  let mut plan: Vec<SingleVoterDelta> = Vec::new();

  // Phase 0 — PRUNE every obsolete learner first (a current learner kept as NEITHER a learner nor a
  // to-be-promoted voter). Always safe (non-voting) and it frees node-cap headroom before any add.
  for &x in lc.iter() {
    if !lt.contains(&x) && !vt.contains(&x) {
      plan.push(SingleVoterDelta::RemoveLearner(x));
    }
  }
  // Phase 1 — stage every new voter as a learner first (skip those already learners).
  for &x in vt.iter() {
    if !vc.contains(&x) && !lc.contains(&x) {
      plan.push(SingleVoterDelta::AddLearner(x));
    }
  }
  // Phase 2 — promote every new voter (the proto promote-time challenge gates each).
  for &x in vt.iter() {
    if !vc.contains(&x) {
      plan.push(SingleVoterDelta::PromoteLearner(x));
    }
  }
  // Phase 3 — remove every departing voter (deterministic ascending order; executor reorders).
  for &x in vc.iter() {
    if !vt.contains(&x) {
      plan.push(SingleVoterDelta::RemoveVoter(x));
    }
  }
  // Phase 4 — add the residual target learners (the genuinely-new ones; Phase 0 pruned the obsolete).
  for &x in lt.iter() {
    if !lc.contains(&x) {
      plan.push(SingleVoterDelta::AddLearner(x));
    }
  }

  // VALIDATE by simulation: fold apply_delta along the built plan and take the running voter/node maxima.
  // This is the exact trajectory the executor installs, so it is correct-by-construction. apply_delta
  // also rejects any structurally-invalid delta (e.g. a last-voter removal or a cap overflow from a
  // PromoteLearner that would push voter count past 64) — map each to the appropriate PlanError.
  let mut sim = current.clone();
  let mut max_voters = sim.replica_count() as usize;
  let mut max_nodes = sim.node_count() as u32;
  for d in &plan {
    sim = match sim.apply_delta(d) {
      Ok(next) => next,
      Err(crate::membership::MembershipError::WouldRemoveLastVoter) => {
        return Err(PlanError::RemovesLastVoter);
      }
      Err(crate::membership::MembershipError::TooManyReplicas { count }) => {
        // A PromoteLearner pushed the voter count past 64 mid-plan.
        return Err(PlanError::IntermediatePeakExceedsCap {
          peak: count as usize,
        });
      }
      Err(crate::membership::MembershipError::TooManyNodes { count }) => {
        return Err(PlanError::IntermediateNodePeakExceedsCap { peak: count });
      }
      // No other apply_delta error is reachable for a well-formed built plan.
      Err(_) => return Err(PlanError::RemovesLastVoter),
    };
    max_voters = max_voters.max(sim.replica_count() as usize);
    max_nodes = max_nodes.max(sim.node_count() as u32);
  }
  if max_voters > MAX_VOTERS {
    return Err(PlanError::IntermediatePeakExceedsCap { peak: max_voters });
  }
  if max_nodes > u16::MAX as u32 {
    return Err(PlanError::IntermediateNodePeakExceedsCap { peak: max_nodes });
  }
  Ok(plan)
}

/// The FIRST delta of [`plan_reconfiguration`], or `None` when `current`'s SETS already equal `target`
/// (the plan is empty / done). PURE. The executor calls this each iteration so it always plans from the
/// LIVE membership; it is exactly `plan_reconfiguration(..)?.first().cloned()`, so the loop driver and the
/// whole-plan testable core cannot diverge.
pub fn plan_next_step(
  current: &Membership,
  target: &MembershipTarget,
) -> Result<Option<SingleVoterDelta>, PlanError> {
  Ok(plan_reconfiguration(current, target)?.first().cloned())
}

/// The Phase-3 removal SET for the live config: the departing voters `voters(current) \ target.voters`,
/// each as a `RemoveVoter`, as an UNORDERED set (a stable ascending order for testing). EMPTY until all of
/// `target.voters` is present (the grow/promote prefix is not yet done, so no removal is due) and when the
/// voter set already equals `target.voters`. PURE — the executor orders the result health-aware. Exists so
/// the executor's health-aware ordering and the pure planner share one definition of "which voters leave".
pub fn shrink_candidates(
  current: &Membership,
  target: &MembershipTarget,
) -> Result<Vec<SingleVoterDelta>, PlanError> {
  let plan = plan_reconfiguration(current, target)?;
  // A removal is due only once the grow/promote PREFIX is exhausted: if any AddLearner or PromoteLearner
  // appears before the first RemoveVoter, the grow phase is still pending for this live config.
  let first_remove = plan.iter().position(SingleVoterDelta::is_remove_voter);
  let Some(first_remove) = first_remove else {
    return Ok(Vec::new()); // no voter removals in this plan at all
  };
  let grow_before_remove = plan[..first_remove]
    .iter()
    .any(|d| d.is_add_learner() || d.is_promote_learner());
  if grow_before_remove {
    return Ok(Vec::new());
  }
  Ok(
    plan
      .into_iter()
      .filter(SingleVoterDelta::is_remove_voter)
      .collect(),
  )
}

#[cfg(test)]
mod tests {
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
}

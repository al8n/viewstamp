//! The pure reconfiguration PLANNER: lower an arbitrary `MembershipTarget` set-goal to a bounded
//! grow-before-shrink sequence of proven Tier B `SingleVoterDelta` steps. PURE — no I/O, no `self`, no
//! consensus state; it constructs no op, touches no durable state, sends no wire message. Per-step
//! safety is inherited from Tier B unchanged.

use std::{collections::BTreeSet, vec::Vec};

use crate::{
  id::MemberId,
  membership::{Membership, SingleVoterDelta},
};

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
  voters: BTreeSet<MemberId>,
  /// The target non-voting LEARNER set. MUST be disjoint from `voters`.
  learners: BTreeSet<MemberId>,
}

impl MembershipTarget {
  /// A target from its voter and learner sets.
  pub fn new(voters: BTreeSet<MemberId>, learners: BTreeSet<MemberId>) -> Self {
    Self { voters, learners }
  }

  /// The target VOTING set.
  pub const fn voters(&self) -> &BTreeSet<MemberId> {
    &self.voters
  }

  /// The target non-voting LEARNER set.
  pub const fn learners(&self) -> &BTreeSet<MemberId> {
    &self.learners
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
  let vt = target.voters();
  let lt = target.learners();

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
mod tests;

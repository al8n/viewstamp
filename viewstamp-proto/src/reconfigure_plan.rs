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

/// Lower a set goal to a bounded grow-before-shrink delta sequence. PURE. (Implemented in a later task.)
pub fn plan_reconfiguration(
  current: &Membership,
  target: &MembershipTarget,
) -> Result<Vec<SingleVoterDelta>, PlanError> {
  let _ = (current, target);
  unimplemented!("plan_reconfiguration is implemented in Task 2")
}

/// The first delta of [`plan_reconfiguration`], or `None` when `current`'s sets already equal `target`.
pub fn plan_next_step(
  current: &Membership,
  target: &MembershipTarget,
) -> Result<Option<SingleVoterDelta>, PlanError> {
  let _ = (current, target);
  unimplemented!("plan_next_step is implemented in Task 3")
}

/// The Phase-3 removal SET for the live config (the departing voters), unordered. PURE.
pub fn shrink_candidates(
  current: &Membership,
  target: &MembershipTarget,
) -> Result<Vec<SingleVoterDelta>, PlanError> {
  let _ = (current, target);
  unimplemented!("shrink_candidates is implemented in Task 3")
}

#[cfg(test)]
mod tests {
  use super::*;

  fn ids(xs: &[u128]) -> BTreeSet<MemberId> {
    xs.iter().copied().map(MemberId::new).collect()
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
}

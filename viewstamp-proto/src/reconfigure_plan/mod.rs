//! The pure reconfiguration PLANNER: lower an arbitrary `MembershipTarget` set-goal to a bounded
//! grow-before-shrink sequence of proven Tier B `SingleVoterDelta` steps. PURE — no I/O, no `self`, no
//! consensus state; it constructs no op, touches no durable state, sends no wire message. Per-step
//! safety is inherited from Tier B unchanged.
//!
//! # Growing the voting set, and bootstrapping a new member
//!
//! A learner is a NON-VOTING member occupying a slot in `[replica_count, node_count)`. It receives the
//! replicated log like any backup and catches up (by ordinary replication, or by state-sync when it is
//! far behind), but it casts no counted vote and is never an active view-change participant. A learner
//! becomes a voter only through `PromoteLearner`, which the primary admits only after a PROMOTE-TIME
//! CHALLENGE: a fresh durable-prefix proof, re-grounded in the learner's storage at propose time, showing
//! it durably holds the committed head. So the planner grows the voting set ONLY as
//! `AddLearner` → catch up → `PromoteLearner`.
//!
//! A DIRECT voter addition is UNREPRESENTABLE (the [`SingleVoterDelta`] vocabulary has no such delta):
//! a brand-new voter holds no committed prefix — it was never a member and never committed a prior op —
//! so it would count toward the successor's view-change quorum without having caught up, which can drop
//! a committed op. Stage the member as a learner, let it catch up, then promote it.
//!
//! # Shrinking the voting set, DEMOTE-FIRST
//!
//! Symmetrically, a voter never leaves the voting set by a direct ejection. It is DEMOTED to a learner
//! first (`DemoteVoter`), keeping its seat and its durable copy of the committed prefix, and only once
//! its successor certifies is it GC'd (`RemoveLearner`) — the mirror of the `AddLearner` → `PromoteLearner`
//! grow path. So a voter→learner demotion is a first-class goal (the planner emits `[DemoteVoter(x)]`),
//! and a full removal is `DemoteVoter(x)` then `RemoveLearner(x)`. The planner interleaves the demotions
//! with any promotions so the crash tolerance `f(n) = n − quorum(n) = ⌊(n−1)/2⌋` never dips below the
//! smaller of the current and target tolerances; `f` falls only on a demote from an ODD voter count, and
//! such a forced descent is gated at propose time by the operator's `AcceptReducedFaultTolerance`.
//!
//! A new member's endpoint requires its slot to ALREADY be in the membership at construction (the genesis
//! constructor asserts the local member occupies a slot). That constrains how a new physical process
//! bootstraps:
//!
//! - A learner present in the GENESIS membership bootstraps cleanly from an EMPTY process: it constructs
//!   at genesis (its slot is in the genesis membership), catches up to the committed frontier over the
//!   mesh, and is promoted once it durably holds the head. No prior durable state is needed — a freshly
//!   formatted store carrying only the genesis root suffices.
//! - A learner ADDED to a RUNNING cluster (via a committed `AddLearner`) currently has NO in-repo join
//!   protocol. The added slot exists in the cluster's live membership, but the new physical process cannot
//!   construct its endpoint until it already holds that membership and its `config_id` / epoch lineage.
//!   Until a join protocol exists, the operator must supply the new process with the current membership +
//!   lineage OUT OF BAND before it starts. A full authenticated join protocol — a non-participating
//!   Joining mode that admits a new process from a signed join ticket, then transitions it to a learner —
//!   is a planned follow-up.

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
  /// The plan's running VOTER count would exceed the 64-voter cap mid-plan — detected by the plan
  /// simulation (a `PromoteLearner` that would seat a 65th voter). Demote-first sequencing keeps the
  /// voter peak at `max(|Vc|, |Vt|) + 1`, so a well-formed target within the cap never trips this; it
  /// is retained as a defensive simulation surface.
  #[error("the intermediate voter peak {peak} would exceed the 64-voter cap")]
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

/// Lower a set goal to a bounded DEMOTE-FIRST sequence of proven Tier B deltas, from `current`'s
/// voter/learner SETS to `target`. PURE — no I/O, no `self`. The phases:
///
/// - P0 PRUNE obsolete learners (`Lc \ (Vt ∪ Lt)` → `RemoveLearner`): the GC lane. Always safe
///   (non-voting) and it frees node-cap headroom before any add.
/// - P1 STAGE future voters (`Vt \ (Vc ∪ Lc)` → `AddLearner`): a new voter is seated as a learner
///   first, so the promote-time challenge can prove it holds the committed prefix before it votes.
/// - P2 PARITY CORE — interleave the promotions (`Vt \ Vc`) and demotions (`Vc \ Vt`) so the crash
///   tolerance `f(n) = n − quorum(n) = ⌊(n−1)/2⌋` never dips below `min(f(|Vc|), f(|Vt|))`. `f` drops
///   only on a demote from an ODD voter count, so: at EVEN `n` prefer a demote (even→odd is f-neutral);
///   at ODD `n` prefer a promote (odd→even is f-neutral); when only demotes remain an odd-`n` demote is
///   the FORCED descent (the operator's `AcceptReducedFaultTolerance` gates it at propose time); when
///   only promotes remain an even-`n` promote grows `f`. Each `DemoteVoter(x)` whose `x` the target does
///   NOT keep as a learner is followed IMMEDIATELY by `RemoveLearner(x)` (the race-free GC), so the
///   advisory plan matches the trajectory the executor installs (which re-plans and prunes the
///   freshly-demoted obsolete learner in P0).
/// - P3 ADD the residual target learners last (`Lt \ (Lc ∪ Vc)` → `AddLearner`; a voter the target
///   keeps as a learner is seated by its P2 demote, not re-added here).
///
/// The peak caps are validated by SIMULATION: it BUILDS the ordered `Vec`, folds `apply_delta` along it,
/// and returns `IntermediatePeakExceedsCap` / `IntermediateNodePeakExceedsCap` iff the running max
/// exceeds the 64-voter / `u16::MAX`-node cap — so it never hands back a sequence a later `apply_delta`
/// would reject mid-plan. The set-only prechecks (disjointness, empty, oversize) are pure properties of
/// `(current, target)`, checked before the sequence is built; a voter→learner demotion is a first-class
/// goal, no longer rejected.
///
/// The demotions and their GC removals are emitted in a deterministic ascending-`MemberId` order purely
/// for a stable output; safety is order-independent among the departing voters (each demote makes the
/// same `f` transition), so the executor reorders that SET health-aware.
///
/// MEMORYLESS: the greedy parity choice depends only on the CURRENT voter count and the remaining
/// promote/demote sets, so re-planning from the membership left by executing `plan[0]` reproduces
/// `plan[1..]` exactly — the property the per-step executor loop relies on.
pub fn plan_reconfiguration(
  current: &Membership,
  target: &MembershipTarget,
) -> Result<Vec<SingleVoterDelta>, PlanError> {
  let (vc, lc) = voter_learner_sets(current);
  let vt = target.voters();
  let lt = target.learners();

  // PREFLIGHT set-only admission (overlap → empty → oversize). A voter→learner demotion is now a
  // feature, and the demote-first voter peak (`max(|Vc|, |Vt|) + 1`) can never exceed the cap for a
  // target within it, so neither the demotion precheck nor the union-peak precheck exists any more.
  if !vt.is_disjoint(lt) {
    return Err(PlanError::VoterLearnerOverlap);
  }
  if vt.is_empty() {
    return Err(PlanError::EmptyVoterSet);
  }
  if vt.len() > MAX_VOTERS {
    return Err(PlanError::TooManyVoters { count: vt.len() });
  }

  let mut plan: Vec<SingleVoterDelta> = Vec::new();

  // P0 — PRUNE every obsolete learner first (a current learner kept as NEITHER a learner nor a
  // to-be-promoted voter). Always safe (non-voting) and it frees node-cap headroom before any add.
  for &x in lc.iter() {
    if !lt.contains(&x) && !vt.contains(&x) {
      plan.push(SingleVoterDelta::RemoveLearner(x));
    }
  }
  // P1 — stage every future voter as a learner first (skip those already voters or learners).
  for &x in vt.iter() {
    if !vc.contains(&x) && !lc.contains(&x) {
      plan.push(SingleVoterDelta::AddLearner(x));
    }
  }
  // P2 — the PARITY CORE. Interleave promotions and demotions to hold `f` at or above the smaller of
  // the current and target tolerances. `promotes` (`Vt \ Vc`) and `demotes` (`Vc \ Vt`) are ascending
  // (BTreeSet difference); each step takes the smallest remaining of the chosen kind, so the sequence
  // is deterministic and memoryless. `n` tracks the running voter count.
  let promotes: Vec<MemberId> = vt.difference(&vc).copied().collect();
  let demotes: Vec<MemberId> = vc.difference(vt).copied().collect();
  let mut pi = 0usize;
  let mut di = 0usize;
  let mut n = vc.len();
  while pi < promotes.len() || di < demotes.len() {
    // Both remain → parity chooses the f-neutral move (promote at odd `n`, demote at even `n`). Only
    // one remains → take it; an odd-`n` demote is then the forced descent, an even-`n` promote grows f.
    let promote_now = match (pi < promotes.len(), di < demotes.len()) {
      (true, true) => n % 2 == 1,
      (true, false) => true,
      (false, true) => false,
      (false, false) => unreachable!("the loop condition guarantees at least one remains"),
    };
    if promote_now {
      plan.push(SingleVoterDelta::PromoteLearner(promotes[pi]));
      pi += 1;
      n += 1;
    } else {
      let x = demotes[di];
      di += 1;
      plan.push(SingleVoterDelta::DemoteVoter(x));
      n -= 1;
      // GC a departing demotee immediately (the target keeps it as neither a voter nor a learner);
      // a demotee the target keeps as a learner is left seated. Matches the executor's re-plan, which
      // prunes the now-obsolete learner in P0.
      if !lt.contains(&x) {
        plan.push(SingleVoterDelta::RemoveLearner(x));
      }
    }
  }
  // P3 — add the residual target learners last (genuinely-new ones; a demotee kept as a learner is
  // already seated by its P2 demote, and P0 pruned the obsolete current learners).
  for &x in lt.iter() {
    if !lc.contains(&x) && !vc.contains(&x) {
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

/// The DEMOTION SET for the live config: the departing voters `voters(current) \ target.voters`, each as
/// a `DemoteVoter`, as an UNORDERED set (a stable ascending order for testing). EMPTY when a demotion is
/// not yet DUE — either the plan's leading step is a stage/promote (the parity core wants a promote
/// first, so the shrink is not this iteration's move) or the voter set already equals `target.voters`.
/// PURE — the executor orders the result health-aware. Exists so the executor's health-aware ordering and
/// the pure planner share one definition of "which voters leave".
pub fn shrink_candidates(
  current: &Membership,
  target: &MembershipTarget,
) -> Result<Vec<SingleVoterDelta>, PlanError> {
  let plan = plan_reconfiguration(current, target)?;
  // A demotion is DUE only when the plan leads with one: if any AddLearner or PromoteLearner appears
  // before the first DemoteVoter, the parity core scheduled a grow/promote ahead of it, so no demote is
  // this live config's next move (the executor takes that leading step instead).
  let first_demote = plan.iter().position(SingleVoterDelta::is_demote_voter);
  let Some(first_demote) = first_demote else {
    return Ok(Vec::new()); // no voter demotions in this plan at all
  };
  let grow_before_demote = plan[..first_demote]
    .iter()
    .any(|d| d.is_add_learner() || d.is_promote_learner());
  if grow_before_demote {
    return Ok(Vec::new());
  }
  Ok(
    plan
      .into_iter()
      .filter(SingleVoterDelta::is_demote_voter)
      .collect(),
  )
}

#[cfg(test)]
mod tests;

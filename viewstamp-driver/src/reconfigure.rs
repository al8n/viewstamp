//! The driver-level reconfiguration executor: `reconfigure_to` and its types. It drives the pure proto
//! planner (`plan_next_step` / `shrink_candidates`) one Tier B `propose_membership` at a time, re-planning
//! from the live membership each step, with a health-aware fail-closed shrink ordering. Adds ZERO proto
//! consensus surface.

use std::collections::BTreeSet;
use std::vec::Vec;

use viewstamp_proto::{MemberId, Membership, PlanError, ProposeMembershipError, SingleVoterDelta};

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
  /// A non-retryable proto proposal verdict (the retryable ones — `ProofPending`/`AlreadyInFlight`/`Busy`/
  /// `AtCapacity` — are handled internally as backoff).
  #[error("the reconfiguration proposal was rejected: {0}")]
  Propose(ProposeMembershipError),
}

#[cfg(test)]
mod tests {
  use super::*;

  fn membership(voters: &[u128]) -> Membership {
    let m: Vec<MemberId> = voters.iter().copied().map(MemberId::new).collect();
    Membership::genesis(voters.len() as u8, 0, m).unwrap()
  }

  #[test]
  fn health_hint_default_is_empty() {
    let h = HealthHint::default();
    assert!(h.known_down.is_empty() && h.known_up.is_empty());
  }

  #[test]
  fn stall_progress_carries_a_valid_remaining_plan_and_no_reason() {
    let live = membership(&[1, 2, 3]);
    let plan = std::vec![SingleVoterDelta::RemoveVoter(MemberId::new(3))];
    let p = ReconfigureProgress::stall(live.clone(), plan.clone());
    assert_eq!(p.remaining, Some(plan));
    assert_eq!(p.reason, None);
    assert_eq!(p.live, live);
  }

  #[test]
  fn failed_progress_carries_the_reason_and_no_remaining() {
    let live = membership(&[1, 2, 3]);
    let p = ReconfigureProgress::failed(live.clone(), PlanError::VoterLearnerOverlap);
    assert_eq!(p.remaining, None);
    assert_eq!(p.reason, Some(PlanError::VoterLearnerOverlap));
  }

  #[test]
  fn reconfigure_error_display_renders_for_each_variant() {
    let live = membership(&[1]);
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
      ReconfigureError::Propose(ProposeMembershipError::NotPrimary),
    ];
    for e in &errs {
      assert!(!std::format!("{e}").is_empty());
    }
  }
}

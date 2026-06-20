//! The live single-member reconfiguration PROPOSAL path.
//!
//! [`Endpoint::propose_membership`] is the single-writer entry point a [`SingleChange`] primary uses
//! to drive one membership change through consensus. It validates the [`SingleVoterDelta`] against the
//! current [`Membership`](crate::Membership) (which also yields the successor), mints a
//! `Body::Reconfigure` op exactly as a client request is minted — assign `self.op + 1`, append to the
//! WAL, broadcast a `Prepare` — and latches `reconfigure_inflight` so a second change cannot start
//! until this one commits. The capability is a COMPILE-TIME type-state: this surface lives on
//! `Endpoint<S, SingleChange>` only, so a [`RestartOnly`](crate::RestartOnly) endpoint has no
//! `propose_membership` at all.
//!
//! The commit-time epoch swap (installing the successor membership) is a later task; this module owns
//! only the proposal mint + the single-writer latch.

use super::*;
use crate::SingleVoterDelta;
use crate::message::ReconfigurePayload;

impl<S> Endpoint<S, SingleChange>
where
  S: StateMachine,
{
  /// Proposes a single-member reconfiguration: validates `delta` against the current configuration,
  /// mints the resulting `Body::Reconfigure` op on the primary, and returns the op number minted.
  ///
  /// The change is driven through consensus like a client op — committed under the OLD epoch, with the
  /// epoch swap firing at commit (a later task). Exactly one reconfiguration is in flight at a time:
  /// the single-writer latch (`reconfigure_inflight`) refuses a second proposal until the first
  /// commits, so the cluster never has two overlapping configuration changes racing.
  ///
  /// The op carries a reserved `(client, request)` identity for content-addressing/dedup —
  /// [`ClientId::RECONFIGURATION`] (the high sentinel, never a real client) and a request number equal
  /// to the op number (monotone and never reused, since op numbers are). It content-addresses on the
  /// successor membership exactly as a client op does on its body.
  ///
  /// # Errors
  ///
  /// - [`ProposeMembershipError::NotPrimary`] if this replica is not the primary.
  /// - [`ProposeMembershipError::NotNormal`] if its status is not `Normal`.
  /// - [`ProposeMembershipError::AlreadyInFlight`] if a reconfiguration op is already in flight.
  /// - [`ProposeMembershipError::Invalid`] if `delta` is structurally invalid for the current
  ///   configuration (an unknown/duplicate member, a non-learner promotion, the last voter removed) —
  ///   carries the underlying [`MembershipError`](crate::MembershipError).
  /// - [`ProposeMembershipError::TargetNotCaughtUp`] for a `PromoteLearner` whose target has not
  ///   durably caught up to the current head (`peer_progress[target] < self.op`, or no report yet) —
  ///   catch-up-then-promote, so the promoted learner provably holds the full E-committed prefix.
  ///
  /// [`ProposeMembershipError::TwoVoterJump`] is defined for the capability ladder but is NOT returned
  /// here: a [`SingleVoterDelta`] cannot express a multi-voter jump (every variant moves the voter count
  /// by at most one).
  pub fn propose_membership<W>(
    &mut self,
    now: Instant,
    wal: &mut W,
    delta: SingleVoterDelta,
  ) -> Result<OpNumber, ProposeMembershipError>
  where
    W: Wal,
  {
    if !self.is_primary() {
      return Err(ProposeMembershipError::NotPrimary);
    }
    if !self.status.is_normal() {
      return Err(ProposeMembershipError::NotNormal);
    }
    if self.reconfigure_inflight.is_some() {
      return Err(ProposeMembershipError::AlreadyInFlight);
    }
    // Validate the delta AND derive the successor in one step: `apply_delta` rejects an invalid delta
    // (unknown/duplicate member, non-learner promotion, last-voter removal) and otherwise returns the
    // successor configuration whose membership the op replicates. A `SingleVoterDelta` moves the voter
    // count by at most one by construction, so the defensive `TwoVoterJump` verdict is unreachable from
    // here — no ±1 check is performed (it could only ever pass).
    let successor = self.membership.apply_delta(&delta)?;

    // CATCH-UP-THEN-PROMOTE (a SAFETY gate, not merely liveness): a `PromoteLearner` is refused until
    // the target learner has DURABLY caught up. The Reconfigure op this proposal mints will occupy
    // `self.op + 1`, so the full E-committed prefix it sits on is `[1..=self.op]` (the current head).
    // Require the target's recorded durable frontier (`peer_progress`, fed only by its non-voting
    // `LearnerStatus`) to COVER `self.op`: then by commit-first, once the learner durably commits the
    // Reconfigure op to become a voter it provably holds the ENTIRE E-committed prefix — closing the
    // hazard where a behind new-voter's low-frontier `DoViewChange` pushes the nack-truncation crossing
    // down and truncates a committed-but-not-widely-replicated op at the next view change. The gate is
    // EXACT (no lag bound): a lag bound would leave a window where the new voter is in a DVC quorum
    // WITHOUT some committed op `o`, re-opening committed-loss. Absent (`None`, the learner never
    // reported) OR below the head → `TargetNotCaughtUp`.
    if let SingleVoterDelta::PromoteLearner(target) = &delta
      && self
        .peer_progress
        .get(target)
        .is_none_or(|durable| durable.get() < self.op.get())
    {
      return Err(ProposeMembershipError::TargetNotCaughtUp);
    }

    let payload = ReconfigurePayload::from_membership(&successor);

    // The reserved reconfiguration identity: the high-sentinel pseudo-client (never a real client, so
    // no client session collides) and a request number equal to the op number (monotone, never reused).
    let op = self.op.next();
    let client = ClientId::RECONFIGURATION;
    let request = RequestNumber::with(op.get());
    // The WAL/Prepare body is the canonical successor-membership encoding; its `fnv1a_128` equals the
    // op's `body_checksum` by construction, so the Reconfigure op content-addresses uniformly with a
    // client op through the shared mint path. The in-memory log entry is `Body::Reconfigure` (the
    // successor membership), distinguishing it from a client op.
    let body_bytes = payload.encode_body();
    self.mint_op(
      now,
      wal,
      client,
      request,
      body_bytes,
      Body::Reconfigure(payload),
    );

    // Latch the single-writer in-flight change: the minted op is the head (`self.op == op` after the
    // mint), and `mint_op` advances `self.op` to it.
    self.reconfigure_inflight = Some(self.op);
    Ok(self.op)
  }
}

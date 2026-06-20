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

use super::normal::NewOpReject;
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
  /// - [`ProposeMembershipError::AlreadyInFlight`] if a reconfiguration is already in flight — either
  ///   PROPOSED-but-not-committed (`reconfigure_inflight`) or COMMITTED-but-not-installed (a staged
  ///   `pending_swap` / an in-flight `SwapEpoch` root). One change is in flight from propose through
  ///   install, including across a view change that interrupts the swap window.
  /// - [`ProposeMembershipError::Invalid`] if `delta` is structurally invalid for the current
  ///   configuration (an unknown/duplicate member, a non-learner promotion, the last voter removed) —
  ///   carries the underlying [`MembershipError`](crate::MembershipError).
  /// - [`ProposeMembershipError::TargetNotCaughtUp`] for a `PromoteLearner` whose target has not
  ///   durably caught up to the current head (`peer_progress[target] < self.op`, or no report yet) —
  ///   catch-up-then-promote, so the promoted learner provably holds the full E-committed prefix.
  /// - [`ProposeMembershipError::AddVoterBreaksQuorumIntersection`] for an `AddVoter` whose successor
  ///   has a one-member view-change quorum (the predecessor is a SINGLE voter): the brand-new voter
  ///   holds no committed prefix yet could form the E+1 view-change quorum alone and drop the old
  ///   committed prefix — an XI-b violation. The SAFE way to add a voter to a tiny cluster is
  ///   `AddLearner` then `PromoteLearner` once the learner durably holds the head (the prefix-held
  ///   path). For a predecessor of 2+ voters `AddVoter` is admitted (the successor view-change quorum
  ///   always includes a predecessor write-quorum member).
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
    // ONE change in flight from propose THROUGH install — gated on the STRUCTURAL truth derived from the
    // log ([`Endpoint::has_pending_reconfigure`]), not the `reconfigure_inflight` latch alone. The latch
    // covers the proposed-but-not-committed phase but is CLEARED by a view-change reset, so an uncommitted
    // `Reconfigure` op carried canonical into a new view would no longer count as in-flight — and a new
    // primary could mint a SECOND one before the first re-commits, overlapping two changes across the
    // epoch boundary. `has_pending_reconfigure` instead reads the uncommitted log tail (which carries the
    // carried op) OR a committed-but-not-installed swap (`swap_in_flight`, which survives a view change),
    // so the gate holds through a view change that interrupts the proposal window too. If a second change
    // committed before the first installed, `stage_epoch_swap` would clobber the first's staged successor
    // and the first `on_sb_done` would clear the second — losing the second committed swap; this gate is
    // what forecloses that.
    if self.has_pending_reconfigure() {
      return Err(ProposeMembershipError::AlreadyInFlight);
    }
    // The SHARED new-op admission gate — the IDENTICAL backpressure/safety fences a client request hits
    // in `on_request` before minting, applied here too so a proposal cannot mint straight through a
    // pending durable-view write (the durable-view-before-participate violation), a state-sync/checkpoint
    // reset, a flagged forfeit, a commit gap, a full pipeline, or a WAL/carrier-band stall. The explicit
    // primary/Normal checks above already foreclose `NotNormalPrimary`; every other verdict is TRANSIENT,
    // mapped to a RETRYABLE `ProposeMembershipError` so the operator/driver retries rather than treating it
    // as a permanent rejection.
    match self.check_new_op_admission(wal) {
      Ok(()) | Err(NewOpReject::NotNormalPrimary) => {}
      // Capacity backpressure (a full pipeline OR a WAL-ring/carrier-band stall) → `AtCapacity`.
      Err(NewOpReject::PipelineFull | NewOpReject::AtCapacity) => {
        return Err(ProposeMembershipError::AtCapacity);
      }
      // A transient-state fence (a pending durable-view/sync/checkpoint write, a flagged step-down, or a
      // committed-but-unapplied prefix) → `Busy`.
      Err(NewOpReject::Busy | NewOpReject::SteppingDown | NewOpReject::CommitGap) => {
        return Err(ProposeMembershipError::Busy);
      }
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

    // XI-b ADMISSION for `AddVoter` (the sibling hazard to the catch-up-then-promote gate above): an
    // `AddVoter` admits a brand-new member DIRECTLY as a voter with NO durable prefix — unlike
    // `PromoteLearner`, whose target durably caught up before promotion. A new voter is NOT a
    // prefix-holder, so a successor VIEW-CHANGE quorum that can be formed WITHOUT any predecessor
    // WRITE-quorum member breaks the old-write-quorum / new-view-change-quorum intersection (committed-op
    // loss). The successor's only guaranteed non-prefix-holder is the new voter itself; the structural
    // overlap lemma `quorum(n) + quorum_view_change(n+1) > n` (XI-b, the spec proof) guarantees that ANY
    // successor view-change quorum which includes even one predecessor voter intersects every E-committed
    // write quorum within the retained voters. So the ONLY unsafe case is the one where a successor
    // view-change quorum can EXCLUDE every predecessor voter — i.e. the new voter ALONE satisfies it:
    // `quorum_view_change(successor) == 1`. With `quorum()` = `floor(n/2)+1` and `quorum_view_change(n)`
    // = `n − quorum(n) + 1`, that holds for a grow EXACTLY when the predecessor has ONE voter (successor
    // 2 → `quorum_view_change(2) == 1`); for every predecessor of 2+ voters `quorum_view_change >= 2`
    // forces at least one predecessor voter into the quorum, so the lemma preserves the prefix and the
    // change is admitted. (The single-voter cluster's SAFE way to add a voter is `AddLearner` then
    // `PromoteLearner` once the learner durably holds the head — the catch-up-held-prefix path above.)
    if let SingleVoterDelta::AddVoter(_) = &delta
      && successor.quorum_view_change() == 1
    {
      return Err(ProposeMembershipError::AddVoterBreaksQuorumIntersection);
    }

    // Pin the PREDECESSOR `config_id` (this proposer's current configuration) into the op: every
    // committer derives the successor by chaining off this exact predecessor, so the commit-time gate
    // (`self.membership.config_id() == prev_config_id`) admits the swap exactly once, off the right
    // configuration, on every replica — never a forked grand-successor from a re-commit at a later epoch.
    let payload = ReconfigurePayload::from_membership(&successor, self.membership.config_id());

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

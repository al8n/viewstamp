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

use super::{normal::NewOpReject, *};
use crate::{SingleVoterDelta, message::ReconfigurePayload};

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
  /// - [`ProposeMembershipError::ProofPending`] for a `PromoteLearner` with no fresh validated proof
  ///   yet — the gate solicits a `RequestLearnerProof` from the target and returns this RETRYABLE
  ///   verdict; the caller retries, and once the matching `LearnerProof` reports a frontier covering the
  ///   head the retry mints the op (catch-up-then-promote, so the promoted learner provably holds the
  ///   full E-committed prefix). A regressed / stale / cross-epoch / missing reply keeps the gate
  ///   returning `ProofPending` (fail-closed). The freshness re-grounds the safety input in the
  ///   learner's durable storage at propose time rather than trusting an accumulated self-report.
  /// - [`ProposeMembershipError::AddVoterBreaksQuorumIntersection`] for an `AddVoter` whose successor
  ///   has a one-member view-change quorum (the predecessor is a SINGLE voter): the brand-new voter
  ///   holds no committed prefix yet could form the E+1 view-change quorum alone and drop the old
  ///   committed prefix — an XI-b violation. The SAFE way to add a voter to a tiny cluster is
  ///   `AddLearner` then `PromoteLearner` once the learner durably holds the head (the prefix-held
  ///   path). For a predecessor of 2+ voters `AddVoter` is admitted (the successor view-change quorum
  ///   always includes a predecessor write-quorum member).
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
    // (unknown/duplicate member, non-learner promotion, last-voter removal) and returns the successor
    // configuration whose membership the op replicates.
    let successor = self.membership.apply_delta(&delta)?;

    // CATCH-UP-THEN-PROMOTE (a SAFETY gate, not merely liveness): a `PromoteLearner` is admitted only on
    // a FRESH proof the primary solicits at propose time, NOT on the target's accumulated self-report.
    // The Reconfigure op this proposal mints will occupy `self.op + 1`, so the full E-committed prefix it
    // sits on is `[1..=self.op]` (the current head); the promoted learner must DURABLY hold that whole
    // prefix, or once it becomes a voter its low-frontier `DoViewChange` pushes the nack-truncation
    // crossing down and truncates a committed-but-not-widely-replicated op at the next view change. The
    // accumulated `peer_progress` is UNSOUND as this safety input: it banks a stale-high value that
    // survives a crash/disk-fault that honestly REGRESSED the learner's frontier. So instead of reading
    // it, this is a TWO-PHASE, Sans-I/O, non-blocking gate:
    //
    //   Phase 1 (a fresh validated proof is present) — `learner_proof` is `Some` for THIS `target` with
    //     `at_op >= self.op` (the proof is for at least the current head) and `proof == Some(f)` with
    //     `f >= self.op` (the learner's freshly-recomputed frontier covers the head): CONSUME the proof
    //     (set `learner_proof = None`) and fall through to the mint. By commit-first, once the learner
    //     durably commits the Reconfigure op to become a voter it provably holds the ENTIRE E-committed
    //     prefix. The gate is EXACT (no lag bound): a lag bound would leave a window where the new voter
    //     is in a DVC quorum WITHOUT some committed op `o`, re-opening committed-loss. Re-validating
    //     `at_op >= self.op` here closes the head-advanced-past-the-proof race (the proof proved an older
    //     head) — it falls through to Phase 2 to re-challenge.
    //
    //   Phase 2 (no fresh proof) — EMIT a `RequestLearnerProof{at_op: self.op, nonce, epoch,
    //     config_id}` to the target's slot and return the RETRYABLE `ProofPending`. The driver/operator
    //     retries; the matching `LearnerProof` fills `proof`, and the retry takes Phase 1. The challenge
    //     is IDEMPOTENT in its head: while a reply is still IN FLIGHT (an outstanding challenge for THIS
    //     target + head with `proof == None`), a re-propose REUSES the same `nonce` and merely
    //     retransmits — it does NOT re-draw, which would supersede its own challenge and drop the in-flight
    //     reply, so a caller retrying faster than the round-trip would never converge. A NEW target, an
    //     ADVANCED head, or an already-arrived (stale, below-head) reply draws a FRESH `nonce` to
    //     re-solicit a current frontier. A crash between challenge and reply leaves `proof = None` →
    //     `ProofPending` persists → no unsafe promotion (fail-closed). The `(epoch, config_id)` reply
    //     binding + the per-challenge `nonce` are the freshness backstops (a replayed / cross-epoch /
    //     wrong-target reply never validates).
    if let SingleVoterDelta::PromoteLearner(target) = &delta {
      let fresh = self.learner_proof.is_some_and(|c| {
        c.target == *target
          && c.at_op.get() >= self.op.get()
          && c.proof.is_some_and(|f| f.get() >= self.op.get())
      });
      if fresh {
        // Consume the single-shot proof token; the mint below proceeds.
        self.learner_proof = None;
      } else {
        // `apply_delta` already validated `target` is a current learner, so its slot resolves.
        let slot = self
          .membership
          .slot_of(*target)
          .expect("a validated PromoteLearner target occupies a slot");
        // Reuse an IN-FLIGHT challenge (same target + head, no reply yet) so an unpaced re-propose
        // retransmits the same `nonce` instead of superseding its own outstanding challenge.
        let reuse = self.learner_proof.is_some_and(|c| {
          c.target == *target && c.at_op.get() == self.op.get() && c.proof.is_none()
        });
        let nonce = if reuse {
          self
            .learner_proof
            .expect("reuse implies an outstanding challenge")
            .nonce
        } else {
          self.nonce = self.nonce.wrapping_add(1);
          self.learner_proof = Some(LearnerProofState {
            target: *target,
            at_op: self.op,
            nonce: self.nonce,
            proof: None,
          });
          self.nonce
        };
        self.emit(Outgoing::new(
          Recipient::To(Peer::Replica(slot)),
          Message::RequestLearnerProof(crate::RequestLearnerProof::new(
            self.local_slot(),
            self.op,
            nonce,
            self.membership.epoch(),
            self.membership.config_id(),
          )),
        ));
        return Err(ProposeMembershipError::ProofPending);
      }
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

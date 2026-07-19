//! The LIVE single-change reconfiguration lane: a single-voter membership change proposed through
//! consensus on a RUNNING cluster (no offline stop), with the live-reconfiguration checkers asserting
//! the committed `Reconfigure` op installs its durable epoch swap exactly once per replica and the
//! committed `config_id` lineage stays an unbroken chain.
//!
//! Unlike the offline-reconfiguration lane (`recovering_head_reformation.rs`, which stops the whole
//! cluster and drives the all-`RecoveringHead` wedge), this lane keeps every node UP and moves a member
//! WITHIN the genesis node set via [`Cluster::propose_reconfigure_single_change`]: the committed
//! `Reconfigure` op's durable `SwapEpoch` root installs the successor membership and fires
//! `Event::MembershipChanged`, captured by the cluster into the per-replica swap stream the checkers
//! fold.
//!
//! ## A note on cluster-wide convergence
//!
//! The proto's commit-first epoch swap installs the new configuration on a replica only once that
//! replica has DURABLY committed the `Reconfigure` op (the durable-epoch-before-participate fence). The
//! proposing primary commits + swaps first; it then keeps participating at its current epoch through
//! the swap window, so every backup commits the `Reconfigure` op and installs the successor epoch — a
//! live single change CONVERGES cluster-wide. This focused test verifies the swap MECHANICS and the
//! swap-correctness invariants on the FIRST installed swap (applied exactly once per replica, an
//! unbroken `config_id` chain, no committed-op loss across the epoch boundary) — the load-bearing
//! SAFETY properties of the change — stopping once the proposing primary has swapped. The cluster-wide
//! CONVERGENCE of a live single change (every non-crashed voter installs the successor under an
//! adversarial schedule) is driven and asserted by the live-reconfig VOPR axis (`VOPR_RECONFIG_LIVE` /
//! `run_vopr_with_reconfig_live`), which runs the full liveness/convergence suite plus a per-voter
//! install check at end-of-run.

use viewstamp_proto::{
  AcceptReducedFaultTolerance, MemberId, MembershipError, MembershipTarget, ProposeMembershipError,
  SingleVoterDelta, plan_reconfiguration,
};
use viewstamp_simulation::{
  Cluster, ConfigLineageChecker, DurabilityChecker, Faults, ReconfigureAppliedOnceChecker,
  StorageFaults,
};

/// Tick the cluster once and fold the three live-reconfiguration checkers, panicking on any violation
/// with the tick. The checkers must hold THROUGHOUT the change (the swap straddle is the load-bearing
/// window), not merely at the end.
fn tick_checked(
  c: &mut Cluster,
  dur: &mut DurabilityChecker,
  once: &mut ReconfigureAppliedOnceChecker,
  lin: &mut ConfigLineageChecker,
  t: u64,
) {
  c.tick();
  assert!(dur.observe(c).is_ok(), "durability violated at tick {t}");
  assert!(
    once.observe(c).is_ok(),
    "reconfigure-applied-once violated at tick {t}"
  );
  assert!(
    lin.observe(c).is_ok(),
    "config-lineage violated at tick {t}"
  );
}

#[test]
fn live_single_change_swap_is_applied_once_and_chains_under_fault() {
  // 3 voters (0,1,2) + 1 genesis learner (3). A finite client load (2 clients × 30 = 60 ops, a
  // multiple of the checkpoint interval 10) so the head settles ON a checkpoint boundary — the proto's
  // catch-up-then-promote gate is measured on the learner's DURABLE frontier, which only reaches the
  // head when the head is checkpoint-aligned and the load has drained.
  let seed = 0x5EED_1234;
  let mut c = Cluster::with_members(3, 1, 2, 30, seed, 10);
  // Drive the change UNDER a lossy network (reorder + duplicate) — the proposal + commit + durable
  // swap survive a realistic schedule, not a quiet happy path.
  c.set_faults(Faults {
    latency: core::time::Duration::from_millis(1),
    jitter: core::time::Duration::from_millis(2),
    drop_per_mille: 0,
    duplicate_per_mille: 80,
    hold_per_mille: 0,
  });
  c.set_storage_faults(StorageFaults::none());
  // Async superblock: the durable `SwapEpoch` root takes several polls to land — the realistic fsync
  // window the durable-epoch-before-participate fence must survive.
  c.set_async_superblock_delay(Some(4));

  let mut dur = DurabilityChecker::new(c.replica_count());
  let mut once = ReconfigureAppliedOnceChecker::new(c.replica_count());
  let mut lin = ConfigLineageChecker::new(c.replica_count());

  let learner = MemberId::new(3);

  // (1) Settle: drain the client load and let the genesis learner (node 3) catch up to the durable
  // checkpoint at the head, so the promote's catch-up gate becomes satisfiable.
  for t in 0..60_000 {
    if (0..c.client_count()).all(|i| c.client(i).is_done())
      && c.serving_primary().is_some()
      && c.replica_durable_commit(3) >= c.primary_head().unwrap_or(u64::MAX)
    {
      break;
    }
    tick_checked(&mut c, &mut dur, &mut once, &mut lin, t);
  }
  assert!(
    c.serving_primary().is_some(),
    "a serving primary exists after the load settles"
  );
  assert!(
    c.replica_is_learner(3),
    "node 3 starts as a non-voting learner"
  );
  assert_eq!(
    c.replica_voter_count(0),
    Some(3),
    "the cluster starts at 3 voters"
  );

  // (2) Propose a single-voter GROW (promote the caught-up learner) on the serving primary. The
  // catch-up-then-promote gate is now a PROMOTE-TIME CHALLENGE: the first propose with no fresh proof
  // emits a `RequestLearnerProof` to the target and returns the RETRYABLE `ProofPending`; the network
  // delivers that challenge + the target's `LearnerProof` reply over the next few ticks, and a later
  // re-propose finds the fresh proof (frontier >= head) and mints. The retry is PACED (every
  // `RETRY_EVERY` ticks) so a challenge's round-trip completes before the next propose re-draws the
  // nonce — a propose every tick would supersede each outstanding challenge before its reply lands (one
  // outstanding challenge at a time, by the proto's single-writer reconfigure contract). A
  // `ProofPending` / `NotPrimary` / `AlreadyInFlight` verdict just means "not yet, retry". Then keep
  // ticking so the committed `Reconfigure` op's durable `SwapEpoch` root lands and the swap installs.
  const RETRY_EVERY: u64 = 64;
  let mut proposed = None;
  let mut saw_proof_pending = false;
  for t in 0..60_000 {
    if proposed.is_none() && t % RETRY_EVERY == 0 {
      match c.propose_reconfigure_single_change(SingleVoterDelta::PromoteLearner(learner), None) {
        Ok(op) => proposed = Some(op),
        Err(ProposeMembershipError::ProofPending) => saw_proof_pending = true,
        Err(_) => {}
      }
    }
    tick_checked(&mut c, &mut dur, &mut once, &mut lin, t);
    // Stop once the committed swap has installed somewhere (the proposing primary swaps first).
    if proposed.is_some() && c.membership_swaps_observed() >= 1 {
      break;
    }
  }
  assert!(
    saw_proof_pending,
    "the catch-up-then-promote challenge was genuinely exercised (the first propose solicited a fresh \
     `RequestLearnerProof` and returned `ProofPending` before the target's `LearnerProof` validated) — \
     the gate is load-bearing, not vacuous"
  );
  assert!(
    proposed.is_some(),
    "the caught-up learner promote was eventually admitted (the fresh proof's frontier reached the head)"
  );

  // (3) The committed reconfiguration installed its epoch swap: at least one replica observed
  // `MembershipChanged` (the proposing primary swaps first — the non-vacuity witness that the live
  // change genuinely committed + installed its durable epoch swap), and that replica now participates
  // under the new 4-voter configuration at epoch 1.
  assert!(
    c.membership_swaps_observed() >= 1,
    "at least one live membership swap was observed (the change committed + installed its durable epoch \
     swap) — got {}",
    c.membership_swaps_observed()
  );
  // The proposing primary is the replica that swapped (it commits + installs the new configuration
  // first). It now participates under the new 4-voter configuration at epoch 1, with the promoted
  // member (node 3) a voter in THAT configuration.
  let swapped = (0..c.replica_count())
    .find(|&i| c.replica_durable_epoch(i).get() == 1)
    .expect("a replica swapped to the new epoch");
  assert_eq!(
    c.replica_voter_count(swapped),
    Some(4),
    "the swapped replica grew to the 4-voter configuration (the promoted learner is now a voter)"
  );
  // The committed swap event names the successor epoch (1) and the committed `Reconfigure` op the
  // primary proposed — the config_id lineage chained from genesis (epoch 0) to the successor.
  let swap = c.replica_membership_swaps(swapped)[0].1;
  assert_eq!(swap.epoch().get(), 1, "the swap installed epoch 1");
  assert!(
    swap.self_is_voter(),
    "the proposing primary is a voter in the new configuration (it was not the removed member)"
  );
  assert_eq!(
    swap.op().get(),
    proposed.unwrap().get(),
    "the swap names the committed Reconfigure op the primary proposed"
  );

  // (4) The three checkers pass on the swaps that occurred: every committed reconfiguration applied
  // exactly once per replica, the committed config_id lineage is an unbroken chain, and no committed
  // op was lost across the epoch boundary.
  assert!(
    once.check(&c).is_ok(),
    "reconfigure-applied-once holds across the live single change"
  );
  assert!(
    lin.check(&c).is_ok(),
    "the committed config_id lineage is an unbroken chain across the change"
  );
  assert!(
    dur.check(&c).is_ok(),
    "no committed op was lost across the reconfiguration epoch boundary"
  );
}

#[test]
fn propose_reconfigure_surfaces_the_proto_gate_verdicts() {
  // The driver surfaces the proto's proposal-gate verdicts rather than panicking: an invalid delta is
  // rejected `Invalid`, and an uncaught-up learner promote returns the retryable `ProofPending` (the
  // promote-time challenge solicited a fresh `RequestLearnerProof` but no validated proof covers the
  // head yet). A 2-voter cluster (quorum 2) with a genesis learner.
  let seed = 7u64;
  let mut c = Cluster::with_members(2, 1, 2, 50, seed, 8);
  // Warm up to a serving primary with the head advancing under load.
  for _ in 0..3_000 {
    c.tick();
    if c.serving_primary().is_some() && c.replica_commit(0).get() >= 1 {
      break;
    }
  }
  assert!(c.serving_primary().is_some(), "a serving primary exists");

  // An invalid delta — promote a member that is not a learner (the primary's own voting slot) — is
  // rejected `Invalid`, surfaced from the driver.
  assert!(
    matches!(
      c.propose_reconfigure_single_change(SingleVoterDelta::PromoteLearner(MemberId::new(0)), None),
      Err(ProposeMembershipError::Invalid(_))
    ),
    "promoting a non-learner is an invalid delta"
  );

  // The first promote of the genesis learner returns the retryable `ProofPending`: the promote-time
  // challenge has no fresh validated proof yet, so it solicits a `RequestLearnerProof` from the target
  // and defers the mint (fail-closed). This holds whether or not the learner is already caught up — the
  // gate re-grounds freshly via the round-trip rather than gating on an accumulated self-report. While
  // the head is still advancing under load (the learner's durable frontier provably lags) the deferral
  // is also a genuine catch-up refusal: a `LearnerProof` answered now would report a frontier below the
  // head, so even a re-propose after the round-trip would not mint until the learner catches up.
  assert_eq!(
    c.propose_reconfigure_single_change(SingleVoterDelta::PromoteLearner(MemberId::new(2)), None),
    Err(ProposeMembershipError::ProofPending),
    "the first promote solicits a fresh proof and returns the retryable ProofPending"
  );
}

#[test]
fn promote_stalls_when_the_target_crashes_between_challenge_and_reply() {
  // The load-bearing falsifier of the promote-time challenge (the design's "crash between challenge and
  // reply"): a caught-up learner is challenged, then CRASHES before it can answer — so the
  // `RequestLearnerProof` is never answered and the gate must FAIL CLOSED (the promotion stalls at
  // `ProofPending`, no swap installs, the 3-voter cluster never wedges) until the target recovers and
  // answers a FRESH challenge whose frontier reaches the head. The old monotone-`peer_progress` gate
  // could promote on a banked self-report here; the challenge cannot, because the proof is re-grounded
  // in the target's live storage and a crashed target never answers.
  //
  // 3 voters (0,1,2) + 1 genesis learner (3); a finite client load drains so the learner reaches the
  // head in a lull (the gate is satisfiable once the target is up + caught up).
  let seed = 0x5EED_C2A5;
  let mut c = Cluster::with_members(3, 1, 2, 30, seed, 10);
  c.set_faults(Faults {
    latency: core::time::Duration::from_millis(1),
    jitter: core::time::Duration::from_millis(2),
    drop_per_mille: 0,
    duplicate_per_mille: 0,
    hold_per_mille: 0,
  });
  c.set_storage_faults(StorageFaults::none());

  let mut dur = DurabilityChecker::new(c.replica_count());
  let mut once = ReconfigureAppliedOnceChecker::new(c.replica_count());
  let mut lin = ConfigLineageChecker::new(c.replica_count());
  let learner = MemberId::new(3);

  // (1) Settle: drain the load + let the learner catch the head, so a challenge answered NOW would
  // report a frontier covering the head (the promote is genuinely admissible — the stall below is the
  // crash, not a not-yet-caught-up refusal).
  for t in 0..60_000 {
    if (0..c.client_count()).all(|i| c.client(i).is_done())
      && c.serving_primary().is_some()
      && c.replica_durable_commit(3) >= c.primary_head().unwrap_or(u64::MAX)
    {
      break;
    }
    tick_checked(&mut c, &mut dur, &mut once, &mut lin, t);
  }
  assert!(c.serving_primary().is_some(), "a serving primary exists");
  assert!(
    c.replica_is_learner(3),
    "node 3 starts as a non-voting learner"
  );
  let head_at_challenge = c.primary_head().expect("a serving primary");

  // (2) Propose: the challenge is solicited (`ProofPending`) and a `RequestLearnerProof` is queued for
  // the target. Then CRASH the target before the next tick routes/delivers that challenge — so it is
  // never delivered and the `LearnerProof` never comes back (a crashed replica is not polled, and its
  // in-flight storage is discarded). The proof stays `None`.
  assert_eq!(
    c.propose_reconfigure_single_change(SingleVoterDelta::PromoteLearner(learner), None),
    Err(ProposeMembershipError::ProofPending),
    "the first promote solicits a fresh challenge"
  );
  c.crash(3);

  // (3) STALL: keep re-proposing (paced) while the target is down. The promotion must NEVER mint — a
  // re-challenge to a crashed target is never answered, so the gate fail-closes at `ProofPending` every
  // time. The 3-voter cluster keeps full quorum (the learner is a non-voter), so it never wedges: it
  // stays LIVE (a serving primary persists) throughout the stall, and no swap may install.
  const RETRY_EVERY: u64 = 64;
  let mut stalled_at_proof_pending = 0u64;
  for t in 0..8_000 {
    if t % RETRY_EVERY == 0 {
      let verdict =
        c.propose_reconfigure_single_change(SingleVoterDelta::PromoteLearner(learner), None);
      if matches!(verdict, Err(ProposeMembershipError::ProofPending)) {
        stalled_at_proof_pending += 1;
      }
      assert!(
        matches!(
          verdict,
          Err(ProposeMembershipError::ProofPending)
            | Err(ProposeMembershipError::NotPrimary)
            | Err(ProposeMembershipError::AlreadyInFlight)
        ),
        "while the target is crashed the promote must fail closed (ProofPending), never mint — got \
         {verdict:?}"
      );
    }
    tick_checked(&mut c, &mut dur, &mut once, &mut lin, t);
  }
  // Non-vacuity of the falsifier: the gate genuinely RE-CHALLENGED a serving primary and got
  // `ProofPending` back (not merely `NotPrimary` the whole window) — a re-challenge to the crashed
  // target that fail-closes is exactly what is under test.
  assert!(
    stalled_at_proof_pending > 0,
    "the stall window must have re-challenged a serving primary and observed ProofPending (else the \
     fail-closed property is vacuously satisfied) — got {stalled_at_proof_pending} ProofPending verdicts"
  );
  assert_eq!(
    c.membership_swaps_observed(),
    0,
    "NO swap may install while the target is crashed (the unsafe-promote falsifier) — the promotion \
     stalls fail-closed"
  );
  assert!(
    c.replica_is_learner(3),
    "the target is still a non-voting learner (never promoted on a crashed/unanswered challenge)"
  );

  // (4) RECOVER the target and let it catch back up to the head (its durable frontier reaches the head
  // again in the lull). The cluster stayed live throughout, so the head is unchanged.
  c.restart(3);
  for t in 0..60_000 {
    if c.serving_primary().is_some()
      && c.replica_durable_commit(3) >= c.primary_head().unwrap_or(u64::MAX)
    {
      break;
    }
    tick_checked(&mut c, &mut dur, &mut once, &mut lin, t);
  }
  assert!(
    c.replica_durable_commit(3) >= head_at_challenge,
    "the recovered target caught back up to at least the challenged head"
  );

  // (5) Re-propose (paced): now the recovered, caught-up target answers a FRESH challenge with a
  // frontier reaching the head, so the promote MINTS and the swap installs — the gate releases exactly
  // when (and only when) the live proof covers the head.
  let mut proposed = None;
  for t in 0..60_000 {
    if proposed.is_none()
      && t % RETRY_EVERY == 0
      && let Ok(op) =
        c.propose_reconfigure_single_change(SingleVoterDelta::PromoteLearner(learner), None)
    {
      proposed = Some(op);
    }
    tick_checked(&mut c, &mut dur, &mut once, &mut lin, t);
    if proposed.is_some() && c.membership_swaps_observed() >= 1 {
      break;
    }
  }
  assert!(
    proposed.is_some(),
    "after the target recovered + caught up, a fresh challenge minted the promote"
  );
  assert!(
    c.membership_swaps_observed() >= 1,
    "the promotion committed + installed its durable epoch swap once the target answered a fresh \
     challenge covering the head"
  );
  // The whole sequence — stall, recover, mint — preserved every safety invariant.
  assert!(once.check(&c).is_ok(), "reconfigure-applied-once holds");
  assert!(
    lin.check(&c).is_ok(),
    "the config_id lineage is an unbroken chain"
  );
  assert!(
    dur.check(&c).is_ok(),
    "no committed op was lost across the change"
  );
}

#[test]
fn a_shrink_holds_uncommitted_until_a_successor_voter_quorum_acks_it() {
  // 3 voters {0,1,2}, no learners. After the load settles, CRASH one SURVIVOR of the intended
  // 2-voter successor, then propose the demotion of the OTHER non-primary voter. The demote's
  // successor quorum is {primary, crashed survivor} — 2-of-2 — so the op can assemble a bare
  // predecessor quorum (primary + the DEMOTEE) but never a successor one: it must sit
  // UNCOMMITTED (no commit, no swap anywhere, the 3-voter set still authoritative) for as long as
  // the survivor is down. Restarting the survivor releases it: the recovered voter acks the
  // retransmitted op, the successor quorum witnesses the commit, and the swap installs — the
  // successor is seated only once a quorum of it has demonstrably processed the change.
  let seed = 0x5EED_2321;
  let mut c = Cluster::with_members(3, 0, 1, 10, seed, 10);
  c.set_faults(Faults {
    latency: core::time::Duration::from_millis(1),
    jitter: core::time::Duration::ZERO,
    drop_per_mille: 0,
    duplicate_per_mille: 0,
    hold_per_mille: 0,
  });
  c.set_storage_faults(StorageFaults::none());

  let mut dur = DurabilityChecker::new(c.replica_count());
  let mut once = ReconfigureAppliedOnceChecker::new(c.replica_count());
  let mut lin = ConfigLineageChecker::new(c.replica_count());

  // (1) Settle: drain the client load under a serving primary.
  for t in 0..60_000 {
    if (0..c.client_count()).all(|i| c.client(i).is_done()) && c.serving_primary().is_some() {
      break;
    }
    tick_checked(&mut c, &mut dur, &mut once, &mut lin, t);
  }
  let p = c
    .serving_primary()
    .expect("a serving primary after the load settles");
  let mut others = (0..3usize).filter(|&i| i != p);
  let removed = others.next().expect("two non-primary voters");
  let survivor = others.next().expect("two non-primary voters");

  // (2) Crash the successor-critical survivor FIRST, then propose demoting the other voter: the
  // successor {primary, survivor} can never assemble its quorum while the survivor is down.
  c.crash(survivor);
  c.propose_reconfigure_single_change(
    SingleVoterDelta::DemoteVoter(MemberId::new(removed as u128)),
    // A 3 → 2 shrink reduces the cluster's crash tolerance; the test plays the operator accepting it.
    Some(AcceptReducedFaultTolerance),
  )
  .expect("the serving primary admits the demote proposal");

  // (3) HELD: the predecessor quorum {primary, demotee} exists the whole time, yet the demote must
  // never commit or swap — no successor quorum has processed it.
  for t in 0..4_000 {
    tick_checked(&mut c, &mut dur, &mut once, &mut lin, 100_000 + t);
    assert_eq!(
      c.membership_swaps_observed(),
      0,
      "no swap may install while the successor quorum is unacked (tick {t})"
    );
    assert!(
      c.committed_reconfigure_ops().is_empty(),
      "the demote must stay uncommitted while the successor quorum is unacked (tick {t})"
    );
  }
  assert_eq!(
    c.replica_voter_count(p),
    Some(3),
    "the predecessor voter set stays authoritative while the demote is held"
  );

  // (4) RELEASED: restart the survivor; it recovers, acks the retransmitted demote, and the swap
  // installs under a successor quorum's witness.
  c.restart(survivor);
  let mut installed = false;
  for t in 0..120_000 {
    tick_checked(&mut c, &mut dur, &mut once, &mut lin, 200_000 + t);
    if c.membership_swaps_observed() > 0 {
      installed = true;
      break;
    }
  }
  assert!(
    installed,
    "the demote commits and installs once the restarted survivor acks it"
  );
  assert!(
    !c.committed_reconfigure_ops().is_empty(),
    "the demote is committed after the successor quorum acked"
  );

  // (5) Settle the swap cluster-wide, then pin the successor shape: 2 voters, the demotee retained
  // as the learner, the restarted survivor seated.
  for t in 0..20_000 {
    if c
      .serving_primary()
      .is_some_and(|sp| c.replica_voter_count(sp) == Some(2))
    {
      break;
    }
    tick_checked(&mut c, &mut dur, &mut once, &mut lin, 400_000 + t);
  }
  let m = c.serving_primary_membership();
  assert_eq!(m.replica_count(), 2, "the successor is the 2-voter config");
  let demotee_slot = m
    .slot_of(MemberId::new(removed as u128))
    .expect("the demotee keeps a seat in the successor");
  assert!(
    m.is_learner(demotee_slot),
    "the demotee is retained as the successor's learner"
  );
  assert!(
    m.slot_of(MemberId::new(survivor as u128)).is_some(),
    "the restarted survivor is a seated successor voter"
  );
}

#[test]
fn planner_rotation_0_1_2_to_2_3_4_preserves_committed_continuity_under_load() {
  // 3 voters {MemberId(0), MemberId(1), MemberId(2)} + 2 genesis learners {MemberId(3), MemberId(4)}.
  // The genesis learners are the target voters-to-be, and MemberId(0)/MemberId(1) are the departing
  // voters (MemberId(2) stays). The demote-first planner interleaves promotions and demotions to hold
  // the crash tolerance at parity: PromoteLearner(3), DemoteVoter(0) + RemoveLearner(0),
  // PromoteLearner(4), DemoteVoter(1) + RemoveLearner(1) — 6 committed steps, each its own epoch swap,
  // bumping the durable epoch from 0 to 6.
  let seed = 0x5EED_3450;
  let mut c = Cluster::with_members(3, 2, 2, 40, seed, 10);
  c.set_faults(Faults {
    latency: core::time::Duration::from_millis(1),
    jitter: core::time::Duration::from_millis(2),
    drop_per_mille: 0,
    duplicate_per_mille: 40,
    hold_per_mille: 0,
  });
  c.set_storage_faults(StorageFaults::none());
  c.set_async_superblock_delay(Some(2));

  let mut dur = DurabilityChecker::new(c.replica_count());
  let mut once = ReconfigureAppliedOnceChecker::new(c.replica_count());
  let mut lin = ConfigLineageChecker::new(c.replica_count());

  // (1) Settle: drain the client load and let the genesis learners (nodes 3, 4) catch up to the
  // durable head so the promote-time challenge finds a frontier covering the head on first answer.
  for t in 0..80_000 {
    let learners_caught = c.replica_durable_commit(3) >= c.primary_head().unwrap_or(u64::MAX)
      && c.replica_durable_commit(4) >= c.primary_head().unwrap_or(u64::MAX);
    if (0..c.client_count()).all(|i| c.client(i).is_done())
      && c.serving_primary().is_some()
      && learners_caught
    {
      break;
    }
    tick_checked(&mut c, &mut dur, &mut once, &mut lin, t);
  }
  assert_eq!(c.replica_voter_count(0), Some(3), "starts at 3 voters");
  assert!(
    c.serving_primary().is_some(),
    "a serving primary exists after the load settles"
  );

  // (2) Drive the full plan {MemberId(0),1,2} -> {MemberId(2),3,4}: per outer iteration, plan from the
  // serving primary's LIVE durable membership and propose the FIRST delta. The promote-time challenge
  // gates each PromoteLearner step, so retries are PACED (every RETRY_EVERY ticks) to let the challenge
  // round-trip complete before re-drawing the nonce. A round completes when ITS OWN proposed op is
  // witnessed installed (its `MembershipChanged` appears in some replica's swap stream) — not the
  // CLUSTER-WIDE swap count, which the previous step's still-fanning-out installs would trip early:
  // that would end the round before its own step ever landed and leave the next round re-planning from
  // a stale membership, re-proposing a step the cluster already applied. The outer loop runs until the
  // plan is empty (the live membership already matches the target), bounded by a global tick budget
  // rather than a fixed round count (an already-committed step resolves in one round with no new op, so
  // the number of rounds needed is not exactly the plan length).
  let target = MembershipTarget::new(
    [2u128, 3, 4].into_iter().map(MemberId::new).collect(),
    Default::default(),
  );
  const RETRY_EVERY: u64 = 64;
  const TICK_BUDGET: u64 = 700_000;
  let mut t = 0u64;
  loop {
    assert!(
      t < TICK_BUDGET,
      "the rotation exhausted its {TICK_BUDGET}-tick budget before reaching the target membership"
    );
    // After a voter removal installs, the cluster may re-elect a primary in the new config. Wait
    // for a serving primary before re-reading the live membership and planning the next step.
    for _ in 0..20_000 {
      if c.serving_primary().is_some() {
        break;
      }
      tick_checked(&mut c, &mut dur, &mut once, &mut lin, t);
      t += 1;
    }

    // Plan from the LIVE membership: an empty plan means the live config already matches the target.
    let plan = plan_reconfiguration(&c.serving_primary_membership(), &target)
      .expect("the rotation plans cleanly from every intermediate membership");
    let Some(step) = plan.first().cloned() else {
      break;
    };

    // Propose the step (paced), tolerating the transient verdicts and the already-committed
    // staleness mirrors, until it mints a fresh op or is found already applied.
    let mut op = None;
    let mut already_done = false;
    while op.is_none() && !already_done {
      assert!(
        t < TICK_BUDGET,
        "the rotation exhausted its {TICK_BUDGET}-tick budget proposing {step:?}"
      );
      if t.is_multiple_of(RETRY_EVERY) {
        // The executor plays an operator that accepts whatever the plan requires; the token is
        // ignored for the non-reducing steps.
        match c.propose_reconfigure_single_change(step.clone(), Some(AcceptReducedFaultTolerance)) {
          Ok(o) => op = Some(o),
          // Retryable transient: the propose gate deferred this round; re-propose next paced tick.
          Err(ProposeMembershipError::ProofPending)
          | Err(ProposeMembershipError::AlreadyInFlight)
          | Err(ProposeMembershipError::NotPrimary)
          | Err(ProposeMembershipError::Busy)
          | Err(ProposeMembershipError::AtCapacity)
          | Err(ProposeMembershipError::NotNormal) => {}
          // NotALearner for a PromoteLearner step means the member committed into the voting set
          // in-memory (a prior iteration already committed it) but the durable epoch root has not
          // yet landed. Treat it as already-proposed and wait for the durable swap below.
          Err(ProposeMembershipError::Invalid(MembershipError::NotALearner)) => {
            already_done = true;
          }
          // NotAVoter for a DemoteVoter step, and UnknownMember for a RemoveLearner step, are the
          // demote/remove mirrors of the same staleness: the primary this round happens to query
          // already reflects the step (the member is a learner, or gone entirely) even though the
          // plan was computed before that install was witnessed — a view change between this round's
          // plan read and its propose attempt can hand the propose to a primary more advanced than
          // the one just read. There is nothing further to wait for; the step already applied.
          Err(ProposeMembershipError::Invalid(MembershipError::NotAVoter))
            if step.is_demote_voter() =>
          {
            already_done = true;
          }
          Err(ProposeMembershipError::Invalid(MembershipError::UnknownMember))
            if step.is_remove_learner() =>
          {
            already_done = true;
          }
          // Any other Invalid variant is unexpected in this healthy rotation; convert it to an
          // immediate failure rather than a silent spin.
          Err(ProposeMembershipError::Invalid(e)) => {
            panic!("unexpected Invalid for {step:?}: {e:?}")
          }
          Err(e) => panic!("unexpected propose verdict for {step:?}: {e:?}"),
        }
      }
      tick_checked(&mut c, &mut dur, &mut once, &mut lin, t);
      t += 1;
    }
    if let Some(op) = op {
      // Wait for THIS round's own op to install: its `MembershipChanged` witnessed in some
      // replica's swap stream — not any cluster-wide swap count, which an earlier step's
      // still-fanning-out installs would trip early.
      while !(0..c.replica_count()).any(|i| {
        c.replica_membership_swaps(i)
          .iter()
          .any(|(_, mc)| mc.op().get() == op.get())
      }) {
        assert!(
          t < TICK_BUDGET,
          "the rotation exhausted its {TICK_BUDGET}-tick budget installing {step:?}"
        );
        tick_checked(&mut c, &mut dur, &mut once, &mut lin, t);
        t += 1;
      }
    }
  }

  // (3) The rotation reached {MemberId(2), MemberId(3), MemberId(4)}: find a replica that has
  // installed the final 3-voter config at the expected epoch (6 steps from epoch 0 = epoch 6).
  let final_replica = (0..c.replica_count())
    .find(|&i| {
      c.replica_voter_count(i) == Some(3)
        && c.replica_is_voter(i)
        && c.replica_durable_epoch(i).get() == 6
    })
    .expect("a replica installed the final 3-voter rotation at the expected epoch");
  let final_voters: std::collections::BTreeSet<MemberId> = (0..3u8)
    .filter_map(|s| c.replica_member_at(final_replica, s))
    .collect();
  assert_eq!(
    final_voters,
    [2u128, 3, 4]
      .into_iter()
      .map(MemberId::new)
      .collect::<std::collections::BTreeSet<_>>(),
    "the voting set rotated to {{MemberId(2), MemberId(3), MemberId(4)}}"
  );

  // (4) Committed continuity across the WHOLE plan: every reconfiguration applied exactly once,
  // the config_id lineage is an unbroken chain, no committed op was lost across the 6-step rotation.
  assert!(
    once.check(&c).is_ok(),
    "every reconfiguration applied exactly once across the rotation"
  );
  assert!(
    lin.check(&c).is_ok(),
    "the config_id lineage is an unbroken chain across the rotation"
  );
  assert!(
    dur.check(&c).is_ok(),
    "no committed op was lost across the 6-step rotation"
  );
}

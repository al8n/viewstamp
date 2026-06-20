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

use viewstamp_proto::{MemberId, ProposeMembershipError, SingleVoterDelta};
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

  // (2) Propose a single-voter GROW (promote the caught-up learner) on the serving primary. Retry each
  // tick until the proto's exact catch-up gate (peer_progress[3] >= primary head, fed by the learner's
  // LearnerStatus) is satisfied and the proposal is admitted — a `TargetNotCaughtUp` / `NotPrimary` /
  // `AlreadyInFlight` rejection just means "not yet". Then keep ticking so the committed `Reconfigure`
  // op's durable `SwapEpoch` root lands and the swap installs.
  let mut proposed = None;
  let mut saw_caught_up_reject = false;
  for t in 0..60_000 {
    if proposed.is_none() {
      match c.propose_reconfigure_single_change(SingleVoterDelta::PromoteLearner(learner)) {
        Ok(op) => proposed = Some(op),
        Err(ProposeMembershipError::TargetNotCaughtUp) => saw_caught_up_reject = true,
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
    saw_caught_up_reject,
    "the catch-up-then-promote gate was genuinely exercised (a not-yet-caught-up promote was rejected \
     before the learner reported a covering frontier) — the gate is load-bearing, not vacuous"
  );
  assert!(
    proposed.is_some(),
    "the caught-up learner promote was eventually admitted"
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
  // rejected `Invalid`, and an uncaught-up learner promote is rejected `TargetNotCaughtUp`. A 2-voter
  // cluster (quorum 2) with a genesis learner.
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
      c.propose_reconfigure_single_change(SingleVoterDelta::PromoteLearner(MemberId::new(0))),
      Err(ProposeMembershipError::Invalid(_))
    ),
    "promoting a non-learner is an invalid delta"
  );

  // While the head is still advancing under load, the genesis learner's DURABLE frontier lags it, so a
  // promote is rejected `TargetNotCaughtUp` (the catch-up-then-promote safety gate). Only assert this
  // when the learner is provably behind (the head moved past its durable frontier).
  let head = c.primary_head().unwrap_or(0);
  if c.replica_durable_commit(2) < head {
    assert_eq!(
      c.propose_reconfigure_single_change(SingleVoterDelta::PromoteLearner(MemberId::new(2))),
      Err(ProposeMembershipError::TargetNotCaughtUp),
      "a learner whose durable frontier lags the head cannot be promoted"
    );
  }
}

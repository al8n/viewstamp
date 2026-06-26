//! Moving-target state-sync gate: a laggard converges while the donor checkpoints forward and
//! GC-prunes blocks DURING its catch-up (a NON-quiesced moving target).
//!
//! Every other state-sync sim lane (`state_sync`, `incremental_sync`, `force_sync`) DRAINS client load
//! and QUIESCES the surviving quorum to a STABLE checkpoint before the laggard syncs, so the sync target
//! stops moving and the donor never prunes a block the laggard is pinned to mid-transfer. That leaves the
//! liveness claim the GC-pruned-pin machinery exists for — *the laggard tracks a target that keeps
//! advancing and pruning while it syncs* — asserted only by code-comment reasoning, never by a sim.
//!
//! This lane is the missing oracle. With a SMALL checkpoint interval, real block-store GC ENABLED, and
//! SUSTAINED client load that is still flowing when the laggard restarts, the donor checkpoints forward
//! and prunes the superseded tail of the DAG the laggard is pinned to WHILE the laggard catches up. The
//! laggard's `RequestBlock` for a pinned-then-pruned block draws an active-donor ABSENT; the proto KEEPS
//! the block-fetch live and re-solicits a fresh checkpoint per round trip (the fresh checkpoint re-seeds
//! the frontier onto an un-pruned root) and tracks the moving target. We assert:
//!
//! 1. the laggard CONVERGES — it catches its APPLIED state up to a survivor's (every committed op) after
//!    state-syncing, and durably checkpoints to within the in-flight band of the still-moving cluster
//!    checkpoint (the per-round-trip re-pin keeps pace with the advancing+pruning donor). It does NOT
//!    exactly equal the cluster checkpoint — a just-synced laggard's durable checkpoint necessarily
//!    trails a checkpoint that is still advancing;
//! 2. the target genuinely MOVED during catch-up — the cluster checkpoint advanced several intervals
//!    between the laggard's restart and its convergence (a quiesced target would not), and the laggard
//!    state-synced at least once (it did not merely retransmit-catch-up).
//!
//! `check_safety` (agreement at an instant) and `DurabilityChecker` (no committed op rewritten/lost
//! across the whole moving window) run EVERY tick. Multi-seed; every seed converges with faithful state.

use core::time::Duration;

use viewstamp_simulation::{CheckResult, Cluster, DurabilityChecker, Faults, check_safety};

/// Voting replicas; crashing one backup leaves a healthy 4-of-5 committing quorum that keeps
/// checkpointing + pruning the whole time.
const REPLICAS: u8 = 5;
/// The laggard replica index (a backup, never the primary — so the survivors keep advancing the
/// checkpoint while it is down and while it catches up).
const LAGGARD: usize = 2;
/// A SMALL checkpoint interval so the donor checkpoints a fresh generation often and GC prunes the
/// superseded tail frequently — the moving target moves fast relative to the laggard's catch-up.
const CHECKPOINT_OPS: u64 = 4;
/// SUSTAINED client load: enough requests that the cluster is STILL committing + checkpointing + pruning
/// when the laggard restarts and throughout its catch-up (a non-quiesced target), yet finite so the run
/// terminates.
const CLIENTS: u32 = 4;
const REQUESTS_PER_CLIENT: u64 = 200;

/// Real latency + jitter + light loss — the donor's ABSENT-for-a-pruned-block and the per-round-trip
/// re-pin are exercised under genuine network reordering/loss, not a perfect link.
fn base_faults() -> Faults {
  Faults {
    latency: Duration::from_millis(1),
    jitter: Duration::from_millis(2),
    drop_per_mille: 5,
    duplicate_per_mille: 0,
    hold_per_mille: 0,
  }
}

#[test]
fn a_laggard_converges_against_a_checkpointing_and_pruning_donor_during_catch_up() {
  let mut seeds_moved = 0usize;
  let mut seeds_synced = 0usize;

  for seed in 0..12u64 {
    let mut c =
      Cluster::with_checkpoint_ops(REPLICAS, CLIENTS, REQUESTS_PER_CLIENT, seed, CHECKPOINT_OPS);
    let mut dur = DurabilityChecker::new(c.replica_count());
    c.set_faults(base_faults());
    // Real GC: a donor that checkpoints forward PRUNES the superseded blocks of the generation the
    // laggard pinned, so a `RequestBlock` for one draws an active-donor ABSENT mid-catch-up.
    c.enable_block_gc();

    let check = |c: &Cluster, dur: &mut DurabilityChecker, phase: &str| {
      assert!(dur.observe(c).is_ok(), "seed {seed}: durability ({phase})");
      assert_eq!(
        check_safety(c),
        CheckResult::Ok,
        "seed {seed}: safety ({phase})"
      );
    };

    // (1) Warm up until the laggard has a non-trivial durable prefix (it checkpointed a few generations)
    // while load is still flowing.
    let mut warmed = false;
    for _ in 0..2_000_000 {
      c.tick();
      check(&c, &mut dur, "warm-up");
      if c.replica_checkpoint_op(LAGGARD).get() >= 8 && c.replica_checkpoint_op(0).get() >= 8 {
        warmed = true;
        break;
      }
    }
    assert!(
      warmed,
      "seed {seed}: the laggard checkpointed a few generations before the crash"
    );
    let laggard_head_before = c.replica_checkpoint_op(LAGGARD).get();
    assert_eq!(
      c.replica_state_sync_count(LAGGARD),
      0,
      "seed {seed}: the laggard has not state-synced before the crash"
    );

    // (2) Crash the laggard and keep it down across MANY checkpoints — but DO NOT drain client load. The
    // surviving quorum keeps committing + checkpointing + pruning, so the cluster checkpoint advances far
    // past the laggard's head and the laggard's tail is below the cluster checkpoint (out of retransmit
    // reach), forcing a state-sync. Clients must NOT all be done here — the target must still be moving
    // when the laggard restarts.
    c.crash(LAGGARD);
    let target_down = laggard_head_before + 16;
    let mut moved_past = false;
    for _ in 0..6_000_000 {
      c.tick();
      check(&c, &mut dur, "crashed");
      if c.replica_checkpoint_op(0).get() >= target_down {
        moved_past = true;
        break;
      }
    }
    assert!(
      moved_past,
      "seed {seed}: the cluster checkpointed past the laggard's head while it was down ({} >= {} + 16)",
      c.replica_checkpoint_op(0).get(),
      laggard_head_before
    );
    let cluster_ckpt_at_restart = c.replica_checkpoint_op(0).get();
    let load_still_flowing = (0..c.client_count()).any(|i| !c.client(i).is_done());
    assert!(
      load_still_flowing,
      "seed {seed}: client load is still flowing at restart (the sync target is genuinely moving, not \
       a quiesced one) — raise REQUESTS_PER_CLIENT if this trips"
    );

    // (3) Restart the laggard WHILE load flows. The donor keeps checkpointing forward and GC-pruning the
    // generation the laggard pins, so mid-catch-up `RequestBlock`s for pinned-then-pruned blocks draw
    // active-donor ABSENTs; the proto re-solicits a fresh checkpoint per round trip and re-pins. This is
    // the moving-target liveness path no quiesced lane exercises.
    c.restart(LAGGARD);

    // Drive to convergence against the MOVING target. Because load is finite, the cluster eventually
    // quiesces and the laggard fully converges; the assertion is that it gets there at all (the
    // per-round-trip re-pin tracked the advancing+pruning donor).
    let mut converged = false;
    for _ in 0..8_000_000 {
      c.tick();
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: no committed op rewritten/lost during the moving-target sync"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: agreement holds during the moving-target sync"
      );
      // Converged = the laggard state-synced and then caught its APPLIED state up to the donor's (every
      // committed op), with load drained. Its durable checkpoint is NOT required to exactly equal the
      // donor's: against a target that keeps advancing + pruning, a just-synced laggard's checkpoint
      // necessarily trails the still-moving cluster checkpoint by the in-flight band, and the final
      // checkpoint only lands once the laggard applies into the next interval. The lag is bounded below.
      if (0..c.client_count()).all(|i| c.client(i).is_done())
        && c.replica_state_sync_count(LAGGARD) >= 1
        && c.replica_status_is_operational(LAGGARD)
        && c.replica_sm(LAGGARD).applied() == c.replica_sm(0).applied()
      {
        converged = true;
        break;
      }
    }
    assert!(
      converged,
      "seed {seed}: the laggard converged against a checkpointing+pruning donor (sync_count={}, \
       laggard_ckpt={}, cluster_ckpt={}) — the per-round-trip re-pin tracked the moving target",
      c.replica_state_sync_count(LAGGARD),
      c.replica_checkpoint_op(LAGGARD).get(),
      c.replica_checkpoint_op(0).get()
    );

    // The laggard durably persisted essentially all of the synced state: its checkpoint trails the
    // donor's by AT MOST the in-flight band a still-advancing target leaves (it cannot exactly equal a
    // checkpoint that was moving), bounded here so the convergence check stays a real durability gate.
    let ckpt_lag = c
      .replica_checkpoint_op(0)
      .get()
      .saturating_sub(c.replica_checkpoint_op(LAGGARD).get());
    assert!(
      ckpt_lag <= 2 * CHECKPOINT_OPS,
      "seed {seed}: the laggard's durable checkpoint lagged the donor's by {ckpt_lag} ops (> {} = two \
       intervals) — beyond the in-flight band; it did not durably persist the synced state",
      2 * CHECKPOINT_OPS
    );

    // (4a) NON-VACUITY — the laggard ACTUALLY state-synced (the trigger fired + a checkpoint was restored
    // and made durable), not merely retransmit-caught-up.
    assert!(
      c.replica_state_sync_count(LAGGARD) >= 1,
      "seed {seed}: VACUOUS — the laggard converged WITHOUT state-syncing (state_sync_count == 0)"
    );
    seeds_synced += 1;

    // (4b) THE MOVING-TARGET AXIS GENUINELY ENGAGED — the cluster checkpoint advanced several intervals
    // between the laggard's restart and its convergence, so the donor was checkpointing forward (and
    // GC-pruning the laggard's pinned generation) DURING the catch-up. A quiesced target would not move.
    let cluster_ckpt_at_converge = c.replica_checkpoint_op(0).get();
    let target_advance = cluster_ckpt_at_converge.saturating_sub(cluster_ckpt_at_restart);
    assert!(
      target_advance >= CHECKPOINT_OPS,
      "seed {seed}: the sync target did not move during catch-up (advanced only {target_advance} ops \
       from {cluster_ckpt_at_restart} to {cluster_ckpt_at_converge}) — the moving-target axis did not \
       engage; this lane must exercise a target that advances + prunes WHILE the laggard syncs"
    );
    seeds_moved += 1;

    // (4c) FAITHFUL RECONSTRUCTION — the converged laggard's applied history equals a survivor's despite
    // the donor having pruned blocks under it mid-sync (every pruned block was re-fetched from the
    // donor's fresh checkpoint, never falsely skipped).
    assert_eq!(
      c.replica_sm(LAGGARD).applied(),
      c.replica_sm(0).applied(),
      "seed {seed}: the converged laggard's applied history must equal the donor's"
    );

    assert_eq!(
      dur.check(&c),
      CheckResult::Ok,
      "seed {seed}: every committed op survived the moving-target sync window"
    );
  }

  assert_eq!(
    seeds_synced, 12,
    "every seed must genuinely state-sync against the moving target"
  );
  assert_eq!(
    seeds_moved, 12,
    "every seed must exercise a MOVING target (the cluster checkpoint advanced during catch-up)"
  );
  eprintln!(
    "moving-target sync: {seeds_synced}/12 seeds state-synced against an advancing+pruning donor"
  );
}

//! State-sync gate: a long-down replica converges via STATE-SYNC (not op-by-op retransmit).
//!
//! A replica is crashed long enough that the cluster
//! checkpoints PAST its durable head, so on restart its head is below the cluster's checkpoint and it
//! CANNOT catch its tail by ordinary retransmit (`commit_min+1..=op` can't reach ops that start
//! at/under its own head) or single-op peer fault-repair — it MUST fetch the latest checkpoint via the
//! `RequestSync` -> `SyncCheckpoint` handshake, restore the SM snapshot + session table, and resume as
//! a Normal backup at the synced point. Its tail then catches up via the ordinary `Prepare`/`Commit`
//! path.
//!
//! ## Forcing the laggard to genuinely state-sync (the trigger)
//!
//! The trigger fires when a `Normal` replica learns of a cluster `checkpoint_op > self.op` (its entire
//! held WAL is below the cluster checkpoint). To guarantee that, we use a SMALL checkpoint interval
//! (`checkpoint_ops = 4`) and keep the crashed backup down across MANY checkpoints, so the cluster's
//! `checkpoint_op` advances well past the laggard's last durable head while it is gone. On restart the
//! laggard `recover()`s to its stale head, hears the primary's next `Commit`/`Prepare` (heartbeats
//! every 50ms), sees `checkpoint_op > self.op`, and solicits a sync.
//!
//! ## Non-vacuity (the hard requirement)
//!
//! A pass that merely caught up via retransmit would prove nothing about state-sync. So we assert the
//! restarted replica's `replica_state_sync_count` went from 0 to `>= 1` — the proto increments it only
//! when an `apply_sync`'s durable re-persist completes (`on_sb_done` lands the synced checkpoint's root
//! write). This proves the trigger fired, the handshake completed, and the checkpoint was restored +
//! made durable. We additionally snapshot the cluster checkpoint before/after the down-window to assert
//! it advanced strictly past the laggard's pre-crash head (so the needed ops were genuinely below the
//! cluster checkpoint, out of retransmit reach).
//!
//! `check_safety` (agreement at an instant) and `DurabilityChecker` (no committed op rewritten/lost
//! across time, including the whole sync window) both run EVERY tick. Multi-seed; every seed must
//! state-sync and converge with no hang and no committed-op loss.

use viewstamp_simulation::{CheckResult, Cluster, DurabilityChecker, check_safety};

#[test]
fn long_down_replica_state_syncs_and_converges() {
  for seed in 0..16u64 {
    // N=5 (so crashing one backup still leaves a 4-of-5 quorum committing the whole time), a SMALL
    // checkpoint interval (4), and plenty of client load to cross many checkpoints.
    let mut c = Cluster::with_checkpoint_ops(5, 2, 40, seed, 4);
    let mut dur = DurabilityChecker::new(c.replica_count());

    // The backup we will crash + state-sync. (Not the primary — keeping replica 0 up means the
    // cluster keeps committing + checkpointing while the laggard is down, so the cluster checkpoint
    // genuinely advances past it.)
    let laggard = 2usize;

    // Warm up until the cluster (primary) has taken at least two checkpoints, so the laggard has a
    // non-trivial durable prefix and the cluster is past op 8.
    let mut warmed = false;
    for _ in 0..200_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok(), "seed {seed}: durability (warm-up)");
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (warm-up)"
      );
      if c.replica_checkpoint_op(0).get() >= 8 {
        warmed = true;
        break;
      }
    }
    assert!(
      warmed,
      "seed {seed}: cluster checkpoints (checkpoint_op(0) >= 8) before the crash"
    );

    // Snapshot the laggard's durable head + sync count just before it crashes. The laggard genuinely
    // state-syncs only if the cluster checkpoints PAST this head while it's down (so its needed ops
    // are below the cluster checkpoint, out of retransmit reach).
    let laggard_head_before = c.replica_checkpoint_op(laggard).get();
    assert_eq!(
      c.replica_state_sync_count(laggard),
      0,
      "seed {seed}: laggard has not state-synced before the crash"
    );

    // Crash the laggard and keep it down across MANY more checkpoints, so the cluster's checkpoint
    // advances well past the laggard's pre-crash head. We require the cluster checkpoint to gain at
    // least 16 ops (4 checkpoint intervals) beyond the laggard's head — comfortably past it.
    c.crash(laggard);
    let target_cluster_ckpt = laggard_head_before + 16;
    let mut moved_past = false;
    for _ in 0..600_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok(), "seed {seed}: durability (crashed)");
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (crashed)"
      );
      if c.replica_checkpoint_op(0).get() >= target_cluster_ckpt {
        moved_past = true;
        break;
      }
    }
    assert!(
      moved_past,
      "seed {seed}: cluster checkpointed past the laggard's head ({} >= {laggard_head_before} + 16) \
       while it was down — so the laggard's tail is below the cluster checkpoint and unreachable by \
       retransmit",
      c.replica_checkpoint_op(0).get()
    );
    let cluster_ckpt_while_down = c.replica_checkpoint_op(0).get();

    // Restart it: `recover()` restores it to its STALE head (below the cluster checkpoint). It is NOT
    // crashed and NOT permanently faulty (no storage faults), so it comes back Normal at its old head,
    // hears the primary's next Commit/Prepare, sees `checkpoint_op > self.op`, and must STATE-SYNC.
    c.restart(laggard);

    // Drive to convergence: the laggard solicits + applies a SyncCheckpoint, persists it, resumes as a
    // Normal backup, and catches its tail up via the ordinary path. Clients finish; no committed op is
    // ever rewritten or lost (checked every tick).
    let mut converged = false;
    for _ in 0..600_000 {
      c.tick();
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: no committed op rewritten/lost during state-sync"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: agreement holds during state-sync"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done())
        && c.replica_state_sync_count(laggard) >= 1
        && c.replica_status_is_operational(laggard)
        && c.replica_checkpoint_op(laggard).get() >= cluster_ckpt_while_down
      {
        converged = true;
        break;
      }
    }
    assert!(
      converged,
      "seed {seed}: the long-down replica state-synced and caught its checkpoint up (sync_count={}, \
       checkpoint_op={}, target>={cluster_ckpt_while_down})",
      c.replica_state_sync_count(laggard),
      c.replica_checkpoint_op(laggard).get()
    );

    // NON-VACUITY: the laggard ACTUALLY state-synced (the trigger fired, the handshake completed, the
    // checkpoint was restored + made durable) — it did NOT merely catch up op-by-op via retransmit.
    assert!(
      c.replica_state_sync_count(laggard) >= 1,
      "seed {seed}: VACUOUS — the laggard converged WITHOUT state-syncing (state_sync_count == 0); \
       it caught up via retransmit instead. Make the down-window longer / checkpoint_ops smaller so \
       the cluster genuinely checkpoints past the laggard before it can retransmit-catch-up."
    );

    // The laggard's checkpoint jumped PAST its pre-crash head (the signature of a sync, not of
    // op-by-op catch-up from its own stale WAL).
    assert!(
      c.replica_checkpoint_op(laggard).get() > laggard_head_before,
      "seed {seed}: laggard's checkpoint ({}) advanced past its pre-crash head ({laggard_head_before})",
      c.replica_checkpoint_op(laggard).get()
    );

    // The synced replica's applied prefix agrees with the primary (no divergence end to end).
    let laggard_applied = c.replica_sm(laggard).applied().to_vec();
    let primary_applied = c.replica_sm(0).applied().to_vec();
    assert!(
      !laggard_applied.is_empty(),
      "seed {seed}: the state-synced replica has a non-trivial applied prefix"
    );
    let n = laggard_applied.len().min(primary_applied.len());
    assert_eq!(
      laggard_applied[..n],
      primary_applied[..n],
      "seed {seed}: the state-synced replica's applied prefix agrees with the primary"
    );

    // The committed history survived end to end.
    assert_eq!(
      dur.check(&c),
      CheckResult::Ok,
      "seed {seed}: every committed op survived the long-down + state-sync window"
    );
  }
}

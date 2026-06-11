//! Checkpoint gate: checkpoints + recover-from-checkpoint + view change after checkpoint-recovery.
//!
//! With a small checkpoint interval, replicas checkpoint repeatedly (snapshotting the SM + the
//! client sessions to the superblock and advancing `checkpoint_op`). A replica that checkpointed,
//! then crashed, recovers from its DURABLE checkpoint (`sm.restore` + `commit_min = checkpoint_op`)
//! with a DENSE in-memory log, and can then participate in a view change (when the primary later
//! crashes) WITHOUT divergence — committed ops survive crash+restart THROUGH a checkpoint, and
//! checkpoint-recovery does not strand the replica.
//!
//! (GC/prune is ENABLED: a replica frees its WAL + per-op caches below its prune floor
//! once a checkpoint is durable, so the recovered log is the OFFSET tail `(floor .. head]`, not dense
//! from op 1. This gate still validates the checkpoint mechanism + checkpoint-based recovery + the
//! recovered replica's view-change participation; the dedicated boundedness + through-the-prune
//! state-sync gate is `boundedness.rs`.)

use viewstamp_simulation::{CheckResult, Cluster, ViewMonotonicChecker, check_safety};

#[test]
fn committed_ops_survive_crash_restart_and_view_change_through_a_checkpoint() {
  for seed in 0..16u64 {
    // Small checkpoint interval (4) so a backup checkpoints within a short run.
    let mut c = Cluster::with_checkpoint_ops(5, 2, 12, seed, 4);
    let mut vm = ViewMonotonicChecker::new(5);

    // Warm up until the backup we will crash (replica 2) has taken at least one checkpoint.
    let survivor = 2usize;
    let mut checkpointed = false;
    for _ in 0..80_000 {
      c.tick();
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (warm-up)"
      );
      assert_eq!(
        vm.observe(&c),
        CheckResult::Ok,
        "seed {seed}: view monotonic (warm-up)"
      );
      if c.replica_checkpoint_op(survivor).get() >= 4 {
        checkpointed = true;
        break;
      }
    }
    assert!(
      checkpointed,
      "seed {seed}: replica {survivor} took a checkpoint (checkpoint_op >= 4)"
    );

    // Crash + restart the checkpointed replica → recover() restores from the durable checkpoint with
    // a DENSE log.
    c.crash(survivor);
    for _ in 0..1_000 {
      c.tick();
    }
    c.restart(survivor);
    for _ in 0..5_000 {
      c.tick();
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety after checkpoint-recovery"
      );
    }

    // Now crash the PRIMARY → a view change among the survivors {1,2,3,4}, in which the
    // checkpoint-recovered replica participates with its dense log (a sparse log would strand it).
    c.crash(0);
    let mut done = false;
    for _ in 0..300_000 {
      c.tick();
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety during failover after recovery"
      );
      assert_eq!(
        vm.observe(&c),
        CheckResult::Ok,
        "seed {seed}: view monotonic during failover"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        done = true;
        break;
      }
    }
    assert!(
      done,
      "seed {seed}: clients finish after checkpoint-recovery + view change"
    );
    // The recovered replica re-applied a committed prefix that agrees with the cluster (check_safety
    // enforced agreement every tick); a non-empty prefix makes the gate non-vacuous.
    assert!(
      !c.replica_sm(survivor).applied().is_empty(),
      "seed {seed}: recovered replica has a non-trivial applied prefix"
    );
  }
}

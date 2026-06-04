//! Transient-fault gate: committed ops survive crash + STORAGE-FAULT + restart (TRANSIENT faults only).
//!
//! Every replica's WAL runs under seeded TRANSIENT read-faults the whole time. We crash a caught-up
//! backup, let the surviving quorum keep committing, then restart it so it recovers from its OWN
//! faulty durable WAL via the async `Status::Recovering` loop (which retries faulted reads within the
//! proto's `RECOVER_READ_RETRIES` budget). The recovered replica must re-apply its committed prefix
//! with NO divergence and NO lost committed op.
//!
//! ## Why the fault model is strictly transient (the safety invariant for this gate)
//!
//! `bit_rot = 0`, `torn = 0`: a faulted read re-rolls and a retry succeeds, so a recovering replica
//! always reaches `Normal` from its own disk — no peer fetch needed. This is exactly the transient-fault
//! guarantee. PERMANENT corruption of a committed op or the head would strand the replica in
//! `RecoveringHead` (terminal until peer-repair via `StartView` adoption) or trip the proto's "committed
//! op present in log" expectation in `advance_commit` (closed by peer fault-repair). Both are
//! deliberately out of scope here, so the gate keeps `bit_rot = torn = 0`.
//!
//! ## Why the survivor is chosen dynamically
//!
//! There is no state-transfer / get-prepare path yet (that is a later gate): a backup that drops Prepares
//! under network faults and then sees the cluster go quiescent can stay permanently behind. Crashing
//! such a laggard would be a degenerate (near-empty) recovery. So we crash the backup with the MOST
//! applied ops at crash time — a backup that genuinely holds the committed prefix — making every
//! seed's recovery non-vacuous. (This selects a valid crash target; it does not weaken the fault
//! exercise — the full crash + transient-fault + restart + recover-from-own-WAL path still runs.)
//!
//! `check_safety` (agreement at an instant) and `DurabilityChecker` (no committed op lost across the
//! crash + storage-fault + restart) both run every tick.

use core::time::Duration;

use viewstamp_simulation::{
  CheckResult, Cluster, DurabilityChecker, Faults, StorageFaults, check_safety,
};

/// The non-primary replica (≠ 0) with the most applied ops — the caught-up backup to crash.
fn most_caught_up_backup(c: &Cluster) -> usize {
  (1..c.replica_count())
    .max_by_key(|&i| c.replica_sm(i).applied().len())
    .expect("at least one backup")
}

#[test]
fn committed_ops_survive_crash_storage_fault_and_restart() {
  for seed in 0..32u64 {
    let mut c = Cluster::new(5, 2, 12, seed);
    c.set_faults(Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(3),
      drop_per_mille: 10,
      duplicate_per_mille: 0,
    });
    // TRANSIENT read-faults on every replica's WAL; NO torn writes, NO permanent bit-rot.
    c.set_storage_faults(StorageFaults {
      read_fault_per_mille: 80,
      torn_write_per_mille: 0,
      bit_rot_per_mille: 0,
      misdirect_read_per_mille: 0,
      corrupt_checkpoint_read_per_mille: 0,
    });
    let mut dur = DurabilityChecker::new(5);

    // Warm up until SOME backup has a non-trivial durable prefix to recover. (We crash whichever
    // backup is most caught up, so we only need one backup to have committed >= 4 ops.)
    let mut warm = false;
    for _ in 0..200_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok(), "seed {seed}: durability (warm-up)");
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (warm-up)"
      );
      if c.replica_sm(most_caught_up_backup(&c)).applied().len() >= 4 {
        warm = true;
        break;
      }
    }
    assert!(
      warm,
      "seed {seed}: a backup commits >= 4 ops before the crash"
    );

    // Crash the most-caught-up backup: the primary (replica 0) stays up ⇒ no view change ⇒ this
    // isolates fault-recovery. Snapshot its pre-crash prefix to assert recovery is non-vacuous.
    let survivor = most_caught_up_backup(&c);
    let pre_crash_len = c.replica_sm(survivor).applied().len();
    c.crash(survivor);
    for _ in 0..3_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok(), "seed {seed}: durability (crashed)");
    }
    // Recover via the async Recovering loop, which retries the faulted reads from its own WAL.
    c.restart(survivor);
    // Right after restart the replica must be operational (Normal/ViewChange), never stranded in
    // Recovering — the transient faults cleared within the retry budget.
    assert!(
      c.replica_status_is_operational(survivor),
      "seed {seed}: restart drove the Recovering loop to a participating state under transient faults"
    );

    let mut done = false;
    for _ in 0..400_000 {
      c.tick();
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: durability across fault-recovery"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: no divergence across fault-recovery"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done())
        && c.replica_sm(survivor).applied().len() >= pre_crash_len
      {
        done = true;
        break;
      }
    }
    assert!(
      done,
      "seed {seed}: clients finish and the fault-recovered replica re-applies its prefix"
    );
    assert_eq!(
      dur.check(&c),
      CheckResult::Ok,
      "seed {seed}: every committed op durably survived crash + storage-fault + restart"
    );

    // Non-vacuous: the recovered replica genuinely re-applied a real committed prefix (>= what it had
    // before the crash), agreeing with the primary — the fault-recovery exercised the WAL read path.
    let recovered = c.replica_sm(survivor).applied().to_vec();
    let primary = c.replica_sm(0).applied().to_vec();
    assert!(
      recovered.len() >= pre_crash_len && recovered.len() >= 4,
      "seed {seed}: recovered replica re-applied its prefix ({} >= {pre_crash_len})",
      recovered.len()
    );
    let n = recovered.len().min(primary.len());
    assert_eq!(
      recovered[..n],
      primary[..n],
      "seed {seed}: recovered prefix agrees with the primary"
    );
  }
}

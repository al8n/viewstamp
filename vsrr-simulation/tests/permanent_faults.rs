//! M3.3b gate: committed ops survive crash + PERMANENT storage-fault + restart (bit-rot / torn).
//!
//! This is the M3.3 spec gate ("committed ops survive crash + STORAGE-FAULT + restart") with the
//! PERMANENT fault model that M3.3b's peer fault-repair lifts (M3.3a kept `bit_rot = torn = 0`). A
//! caught-up backup runs under seeded PERMANENT WAL corruption — `bit_rot_per_mille` (every read of
//! the slot faults forever) and `torn_write_per_mille` (the body fails `Header::verify` forever). We
//! crash it, let the surviving quorum keep committing, then restart it so it rebuilds its cache from
//! its OWN permanently-corrupt WAL. Unlike a transient fault, a rotted committed slot can NEVER be
//! re-read clean from local disk, so the replica MUST repair it from a peer:
//!
//! - a permanently-faulty **head** slot ⇒ `RecoveringHead`, then the canonical head is re-established
//!   by a `RecoveryResponse` / `StartView` from the primary (B1);
//! - a permanently-faulty **non-head committed** slot ⇒ the replica returns to `Normal` holding a
//!   peer-repair hole, solicits the op via `RequestPrepare`, and a peer answers with the `Prepare`
//!   (B4). The commit is HELD strictly below the hole until the op arrives — the op is NEVER skipped
//!   or applied with a wrong/empty body, and the two former `expect("committed op present in log")`
//!   panics are now this fault-tolerant repair.
//!
//! The cluster must converge with NO committed op lost. `check_safety` (agreement at an instant) and
//! `DurabilityChecker` (no committed op lost across the crash + permanent-fault + restart, every tick)
//! both run throughout. Multi-seed; every seed must finish without hang or panic.
//!
//! ## Why the primary stays up (no view change)
//!
//! Keeping replica 0 (the primary) up isolates *fault-repair*: the primary holds the full committed
//! log in memory and answers `RequestPrepare`/`Recovery`, so the restarted backup always has a live
//! source for every rotted committed op. (View-change-under-fault — repairing a canonical log that is
//! itself missing an op via present/nack bitsets — is the separate B3 surface, deliberately out of
//! this gate.)

use core::time::Duration;

use vsrr_simulation::{
  CheckResult, Cluster, DurabilityChecker, Faults, StorageFaults, check_safety,
};

/// The non-primary replica (≠ 0) with the most applied ops — the caught-up backup to crash.
fn most_caught_up_backup(c: &Cluster) -> usize {
  (1..c.replica_count())
    .max_by_key(|&i| c.replica_sm(i).applied().len())
    .expect("at least one backup")
}

#[test]
fn committed_ops_survive_crash_permanent_fault_and_restart() {
  // Aggregate non-vacuity: across the whole seed sweep, the crashed backup must, on at least some
  // seeds, actually read back a permanently-corrupt COMMITTED slot (forcing a peer repair). A gate
  // that never rotted a committed slot would prove nothing about fault-repair.
  let mut seeds_with_corrupt_committed_slot = 0usize;
  for seed in 0..24u64 {
    let mut c = Cluster::new(5, 2, 12, seed);
    c.set_faults(Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(3),
      drop_per_mille: 10,
      duplicate_per_mille: 0,
    });
    // PERMANENT corruption on every replica's WAL: bit-rot + torn writes (NO transient read fault —
    // a transient could mask the permanent path by clearing on retry). A high rate makes it near
    // certain that some COMMITTED slot on the crashed backup rots, so the recovery is non-vacuous;
    // even if a seed rots nothing, the gate still proves no hang / no panic / no committed-op loss.
    //
    // A non-crashed replica reads its WAL only on restart, so rot on the (up) primary + the other
    // backups is harmless — they serve repairs from their intact in-memory log. Only the crashed +
    // restarted backup actually exercises the read-back-permanently-faulty path.
    c.set_storage_faults(StorageFaults {
      read_fault_per_mille: 0,
      torn_write_per_mille: 200,
      bit_rot_per_mille: 200,
      misdirect_read_per_mille: 0,
      corrupt_checkpoint_read_per_mille: 0,
    });
    let mut dur = DurabilityChecker::new(5);

    // Warm up until some backup has a non-trivial durable prefix to recover under fault.
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

    // Crash the most-caught-up backup; the primary (replica 0) stays up ⇒ no view change ⇒ this
    // isolates permanent-fault peer-repair. Snapshot its pre-crash prefix to assert non-vacuity.
    let survivor = most_caught_up_backup(&c);
    let pre_crash_len = c.replica_sm(survivor).applied().len();
    // How many of the survivor's COMMITTED slots are permanently corrupt — these are exactly the ops
    // it cannot read from its own disk and must repair from a peer. (Non-vacuity, aggregated below.)
    let corrupt_committed =
      c.wal_corrupt_slots_at_or_below_for_test(survivor, pre_crash_len as u64);
    if corrupt_committed > 0 {
      seeds_with_corrupt_committed_slot += 1;
    }
    c.crash(survivor);
    for _ in 0..3_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok(), "seed {seed}: durability (crashed)");
    }
    // Restart: rebuild from the OWN permanently-corrupt WAL. A rotted committed slot cannot clear on
    // disk — the replica must repair it from a peer (RecoveringHead+StartView for the head;
    // RequestPrepare for a non-head committed slot). This MUST NOT panic (the former expect sites) or
    // hang (the recover loop no longer spins on a permanent non-head fault).
    c.restart(survivor);

    // Drive to convergence. The restarted backup repairs every rotted committed op from the primary
    // and re-applies its committed prefix; clients finish. No committed op is ever lost or reordered.
    let mut done = false;
    for _ in 0..600_000 {
      c.tick();
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: durability across permanent-fault recovery"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: no divergence across permanent-fault recovery"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done())
        && c.replica_sm(survivor).applied().len() >= pre_crash_len
        && c.replica_status_is_operational(survivor)
      {
        done = true;
        break;
      }
    }
    assert!(
      done,
      "seed {seed}: clients finish and the permanently-faulted replica peer-repairs + re-applies its \
       prefix (no hang: repair terminates against the live quorum)"
    );
    assert_eq!(
      dur.check(&c),
      CheckResult::Ok,
      "seed {seed}: every committed op durably survived crash + PERMANENT fault + restart"
    );

    // Non-vacuous: the recovered replica genuinely re-applied a real committed prefix (>= what it had
    // before the crash), agreeing with the primary — peer fault-repair restored the rotted ops.
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
      "seed {seed}: recovered prefix agrees with the primary (rotted ops repaired, not lost)"
    );
  }
  // The gate must be non-vacuous: across the sweep, the permanent fault genuinely struck committed
  // slots on the crashed backup, so peer fault-repair (the head adoption / RequestPrepare paths and
  // the converted expect panics) was actually exercised — not bypassed by a lucky run.
  assert!(
    seeds_with_corrupt_committed_slot >= 1,
    "no seed rotted a committed slot on the crashed backup — the fault model is not exercising \
     peer fault-repair (raise the corruption rate or the warm-up threshold)"
  );
}

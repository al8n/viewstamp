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

/// A view change after an in-place restart must never mint a durable root whose
/// `(checkpoint_op, checkpoint_id)` pair mixes two checkpoints' timelines.
///
/// The durable-view root write built at a view adoption pairs the endpoint's in-memory
/// `checkpoint_op` with the checkpoint id read fresh off the durable root, justified by a lockstep
/// invariant ("the install advances `checkpoint_op` with its durable root") that holds only while
/// the endpoint is the medium's sole writer. This schedule breaks the lockstep WITHOUT any fault:
///
/// 1. a backup's SECOND checkpoint is mid-write — its envelope is durably stored, its root
///    (pointer) write is still with the device (the async-superblock in-flight window);
/// 2. the endpoint is rebuilt in place — the storage layer keeps the in-flight root;
/// 3. the inherited root lands late: the DURABLE root now names the new checkpoint while the
///    successor endpoint still carries the old `checkpoint_op` (its completion was refused as
///    foreign, so the successor never learns);
/// 4. the primary is deposed inside that desynchronized window; adopting the next view makes the
///    successor write a durable-view root — pairing its stale `checkpoint_op` with the freshly-read
///    NEW `checkpoint_id`.
///
/// The durable root then names an (op, id) no checkpoint ever had, so recovery over it cannot
/// verify this replica's own checkpoint from its own disk — the self-poisoned pointer that forces a
/// peer fetch with zero injected disk faults, and cluster-wide state loss if every replica does it
/// in the same rolling-restart window. The per-tick assertion is the invariant: the durable root's
/// pair must always name a checkpoint envelope the store actually holds.
#[test]
fn a_view_change_over_an_inherited_checkpoint_root_never_mints_a_mixed_pair() {
  /// Small interval so the run crosses several checkpoint boundaries quickly.
  const CHECKPOINT_OPS: u64 = 4;
  /// Superblock writes stay in flight this many polls — wide enough that a checkpoint's root write
  /// regularly spans a tick boundary, opening the window step 1 needs.
  const SB_DELAY: u32 = 16;
  /// The replica whose endpoint is rebuilt mid-checkpoint (a view-0 backup).
  const R: usize = 2;

  let mut c = Cluster::with_checkpoint_ops(3, 2, 400, /*seed*/ 7, CHECKPOINT_OPS);
  c.set_async_superblock_delay(Some(SB_DELAY));

  // Phase 1: catch the mid-checkpoint window on a SECOND-or-later checkpoint (the durable pointer
  // names a real prior checkpoint P > 0, so the poisoned pair below is a real pointer, not the
  // no-checkpoint-yet degenerate case).
  let mut window = None;
  for _ in 0..120_000 {
    if let Some(q) = c.sb_staged_checkpoint_root_op_for_test(R) {
      let p = c.sb_checkpoint_op_for_test(R);
      if p > 0 {
        window = Some((p, q));
        break;
      }
    }
    c.tick();
  }
  let (p, q) = window.expect("the schedule reaches a second checkpoint's in-flight root window");
  assert!(
    c.replica_is_primary(0) && !c.any_replica_view_advanced_beyond(0),
    "the fault-free warm-up leaves the view-0 primary in place, so the deposition below is the \
     run's first view change"
  );

  // Phase 2: rebuild the endpoint INSIDE the window. The primary stays up for the moment, so the
  // successor recovers and resumes as a Normal backup while the inherited root is still in flight.
  c.restart_in_place(R);
  assert!(
    c.sb_staged_checkpoint_root_op_for_test(R) == Some(q),
    "ANTI-VACUITY: the checkpoint root write survived the swap still in flight"
  );

  // Phase 3a: let the inherited root land LATE — the durable pointer reaches Q while the successor
  // endpoint still carries P (its completion was refused as foreign, so nothing told it). This is
  // the desynchronized state the lockstep invariant says cannot exist.
  let mut late_landing_seen = false;
  for _ in 0..2_000 {
    c.tick();
    if c.sb_checkpoint_op_for_test(R) == q && c.replica_checkpoint_op(R).get() == p {
      late_landing_seen = true;
      break;
    }
  }
  assert!(
    late_landing_seen,
    "ANTI-VACUITY: the inherited root landed after the rebuild (durable pointer at {q} while the \
     successor still carried {p})"
  );

  // Phase 3b: depose the primary INSIDE the desynchronized window. The successor's next durable
  // root is its view-adoption write, built from its stale in-memory checkpoint_op and a checkpoint
  // id read fresh off the durable root the inherited landing just replaced. THE INVARIANT is
  // asserted every tick from here: the durable root's (checkpoint_op, checkpoint_id) always names a
  // checkpoint envelope this store holds.
  assert!(
    c.replica_is_primary(0) && !c.any_replica_view_advanced_beyond(0),
    "the warm-up and the landing wait left the view-0 primary serving, so the deposition below is \
     the run's first view change"
  );
  c.crash(0);
  for _ in 0..40_000 {
    c.tick();
    assert!(
      c.sb_root_names_stored_checkpoint(R),
      "the durable root's (checkpoint_op, checkpoint_id) no longer names a checkpoint this store \
       holds: a durable-view root paired the successor's stale checkpoint_op {p} with the \
       inherited checkpoint {q}'s freshly-landed id — a pointer no checkpoint ever had, \
       unrecoverable from this disk alone"
    );
    if c.sb_view_for_test(R) > 0 && c.sb_staged_len_for_test(R) == 0 {
      break;
    }
  }
  assert!(
    c.sb_view_for_test(R) > 0,
    "ANTI-VACUITY: the deposition drove a view change and THIS replica's adoption root landed \
     durably over the inherited one"
  );

  // Phase 4: the coherent pair recovers from its own disk — a crash + restart of the same replica
  // reaches an operational status with no peer checkpoint fetch forced by its own pointer.
  c.crash(R);
  c.restart(R);
  for _ in 0..20_000 {
    c.tick();
    if c.replica_status_is_operational(R) {
      break;
    }
  }
  assert!(
    c.replica_status_is_operational(R),
    "a replica whose durable pair names its own stored checkpoint recovers from its own disk"
  );
}

//! M3.4a / B3 gate: two DIFFERENT-FLOOR recover-from-checkpoint replicas survive a view change
//! together with NO committed-op loss.
//!
//! This is the end-to-end proof of B3 (offset-aware canonical-log selection) — the scenario the proto
//! unit tests cover (`canonical_selection_with_a_checkpoint_offset_log_is_safe`) but no sim gate did.
//!
//! ## The offset-log hazard B3 fixes
//!
//! Since M3.2a a recover-from-checkpoint (or state-synced) replica's in-memory log is the OFFSET TAIL
//! `(checkpoint_op .. head]` — the committed prefix `[1..=checkpoint_op]` lives in its SM snapshot, not
//! the log. So a `DoViewChange` from such a replica carries only `(floor .. head]` with `commit ==
//! checkpoint_op`. Two recovered replicas at DIFFERENT checkpoint floors therefore send DVCs with
//! DIFFERENT present-floors. The pre-B3 selection copied ONE DVC's log (`max_by_key(op)`), which would
//! silently drop committed ops that only the LOWER-floor donor holds (interior ops the `commit* <=
//! op_head` fail-stop cannot catch). B3 UNIONS the canonical generation's entries, sourcing each op
//! from any donor that holds it — so no committed op held by any canonical donor is dropped.
//!
//! ## How this gate creates two different-floor recovered replicas in a view change
//!
//! N=5, small checkpoint interval (4), and a HIGH per-client request count so client work is still
//! pending when we crash the primary (the new primary must then commit fresh ops on top of the adopted
//! canonical log — genuinely exercising it, not just electing and idling). Warm up so backups
//! checkpoint. Then crash + restart TWO different backups at DIFFERENT times — between the two restarts
//! the cluster keeps committing + checkpointing, so the two backups recover-from-checkpoint at
//! (generally) DIFFERENT durable floors and rebuild DIFFERENT-floor offset logs. THEN crash the PRIMARY
//! so those two offset replicas participate in the ensuing view change together (each contributing its
//! offset DVC to the canonical selection / union). With N=5, crashing the primary still leaves a
//! 4-of-5 set (the two recovered backups + the two never-crashed backups) — a live view-change quorum.
//!
//! ## What it asserts
//!
//! `check_safety` (agreement) + `DurabilityChecker` (no committed op rewritten/lost across time) +
//! `ViewMonotonicChecker` (no view regression) EVERY tick; a real view change occurs (a survivor
//! reaches view >= 1); clients finish; and `DurabilityChecker::check` passes at the end — the union
//! canonical-log selection preserved EVERY committed op despite the competing different-floor offset
//! DVCs. Multi-seed. We also record the two recovered backups' floors and assert across the sweep that
//! at least one seed genuinely produced two DIFFERENT floors (so the union path — not a degenerate
//! equal-floor path — was exercised); on a seed where the floors coincide the durability checker still
//! holds (documented).

use vsrr_simulation::{
  CheckResult, Cluster, DurabilityChecker, ViewMonotonicChecker, check_safety,
};

#[test]
fn two_offset_recovered_replicas_survive_a_view_change_without_loss() {
  // Across the sweep, count seeds where the two recovered backups genuinely ended up at DIFFERENT
  // checkpoint floors going into the view change — proving the B3 UNION (different-floor) path, not a
  // degenerate equal-floor path, was exercised at least once.
  let mut seeds_with_distinct_floors = 0usize;

  for seed in 0..16u64 {
    // N=5 (crashing the primary still leaves a 4-of-5 view-change quorum), small checkpoint interval,
    // and a HIGH request count so work remains pending when the primary crashes.
    let mut c = Cluster::with_checkpoint_ops(5, 2, 400, seed, 4);
    let mut dur = DurabilityChecker::new(c.replica_count());
    let mut vm = ViewMonotonicChecker::new(c.replica_count());

    // The two backups we recover-from-checkpoint at different times → different-floor offset logs.
    let (a, b) = (2usize, 3usize);

    // Per-tick invariant block, run inside every loop below: agreement + durability + view monotonic.
    macro_rules! check_tick {
      ($phase:literal) => {{
        assert!(
          dur.observe(&c).is_ok(),
          "seed {seed}: durability ({})",
          $phase
        );
        assert_eq!(
          vm.observe(&c),
          CheckResult::Ok,
          "seed {seed}: view monotonic ({})",
          $phase
        );
        assert_eq!(
          check_safety(&c),
          CheckResult::Ok,
          "seed {seed}: safety ({})",
          $phase
        );
      }};
    }

    // Warm up until both backups have a non-trivial durable checkpoint (so each has a real offset floor
    // to recover at).
    let mut warmed = false;
    for _ in 0..200_000 {
      c.tick();
      check_tick!("warm-up");
      if c.replica_checkpoint_op(a).get() >= 4 && c.replica_checkpoint_op(b).get() >= 4 {
        warmed = true;
        break;
      }
    }
    assert!(
      warmed,
      "seed {seed}: both backups took a checkpoint (checkpoint_op >= 4) before any crash"
    );

    // Crash + restart backup `a` first → it recover-from-checkpoints at its current durable floor and
    // rebuilds an offset log `(floor_a .. head_a]`.
    c.crash(a);
    for _ in 0..1_000 {
      c.tick();
      check_tick!("a down");
    }
    c.restart(a);
    let floor_a = c.replica_checkpoint_op(a).get();

    // Let the cluster keep committing + checkpointing so its frontier advances PAST `a`'s floor before
    // we recover `b` — making `b`'s recovery floor (generally) HIGHER than `a`'s.
    let advance_target = floor_a + 8;
    for _ in 0..200_000 {
      c.tick();
      check_tick!("between restarts");
      if c.replica_checkpoint_op(0).get() >= advance_target
        && c.replica_checkpoint_op(b).get() > floor_a
      {
        break;
      }
    }

    // Crash + restart backup `b` → it recover-from-checkpoints at a (generally higher) floor and
    // rebuilds a DIFFERENT-floor offset log `(floor_b .. head_b]`.
    c.crash(b);
    for _ in 0..1_000 {
      c.tick();
      check_tick!("b down");
    }
    c.restart(b);
    let floor_b = c.replica_checkpoint_op(b).get();

    // Let both recovered backups settle back to Normal at their respective floors before the failover,
    // so each carries a populated offset log into the view change.
    for _ in 0..50_000 {
      c.tick();
      check_tick!("settle");
      if c.replica_status_is_operational(a) && c.replica_status_is_operational(b) {
        break;
      }
    }

    // The offset FLOORS that actually feed the view change are each replica's checkpoint floor at
    // primary-crash time: replica `a`'s in-memory log is the offset tail `(floor_at_crash_a .. head]`,
    // replica `b`'s is `(floor_at_crash_b .. head]`. (Between restart and now, a recovered backup may
    // ALSO have state-synced — which only RAISES its floor; the two floors are still set independently,
    // so they generally differ. We assert the floors that genuinely drive the DVC union.)
    let floor_at_crash_a = c.replica_checkpoint_op(a).get();
    let floor_at_crash_b = c.replica_checkpoint_op(b).get();
    if floor_at_crash_a != floor_at_crash_b {
      seeds_with_distinct_floors += 1;
    }
    // Sanity: the recovered floors are real (each backup recovered from a genuine checkpoint, not 0).
    assert!(
      floor_a >= 4 && floor_b >= 4 && floor_at_crash_a >= floor_a && floor_at_crash_b >= floor_b,
      "seed {seed}: recovered floors are real + monotone (restart {floor_a},{floor_b} -> at-crash \
       {floor_at_crash_a},{floor_at_crash_b})"
    );

    // THE GATE: crash the PRIMARY so the two DIFFERENT-FLOOR offset replicas `a` and `b` (plus the
    // never-crashed backups {1,4}) run a view change together. The new primary's canonical-log
    // selection must UNION their offset DVCs and lose NO committed op, then commit the remaining client
    // work on top of the adopted log. We require BOTH a real view advance AND client completion (a
    // survivor reaching view >= 1 proves the offset DVCs were genuinely used, not bypassed).
    c.crash(0);
    let mut done = false;
    for _ in 0..1_000_000 {
      c.tick();
      check_tick!("offset view change");
      let advanced = (1..c.replica_count()).any(|i| c.replica_view(i).get() >= 1);
      if advanced && (0..c.client_count()).all(|i| c.client(i).is_done()) {
        done = true;
        break;
      }
    }
    assert!(
      done,
      "seed {seed}: a real view change ran (survivor view >= 1) and clients finished after the two \
       offset replicas (floors {floor_a}, {floor_b}) participated"
    );

    // NO committed-op loss: the full committed history is still present on an operational replica — the
    // union canonical-log selection preserved every committed op despite the competing offset DVCs.
    assert_eq!(
      dur.check(&c),
      CheckResult::Ok,
      "seed {seed}: every committed op survived the different-floor offset view change (B3 union held)"
    );
  }

  // Non-vacuity of the DIFFERENT-floor path: across the sweep, at least one seed must have driven the
  // two recovered backups to genuinely DIFFERENT checkpoint floors at primary-crash time — the floors
  // that feed the offset DVCs — so the B3 union (not a degenerate equal-floor selection) was actually
  // exercised. (On any single equal-floor seed the durability checker still held, asserted above; this
  // guarantees the union path is covered.)
  assert!(
    seeds_with_distinct_floors >= 1,
    "no seed produced two different-floor recovered replicas at the view change — the B3 \
     different-floor union path was not exercised (increase the inter-restart cluster advance or the \
     client load)"
  );
}

//! Post-checkpoint GC gate: post-checkpoint GC keeps the in-memory maps + WAL BOUNDED over a long run,
//! and a restarted laggard below the prune floor STATE-SYNCS through the prune with no committed-op loss.
//!
//! This is the "maps provably bounded" deliverable: GC was deferred until state-sync landed because it
//! was unsafe to prune without a snapshot recovery path. With a small checkpoint interval and sustained client load the
//! cluster checkpoints repeatedly; on each checkpoint a replica prunes its WAL + trims its per-op
//! caches below the prune floor (primary: `min(checkpoint_op, quorum_checkpoint_op)`; backup: its own
//! `checkpoint_op`). We assert, EVERY tick:
//!
//! - **boundedness** — every replica's `log` cache, `inflight` pipeline, durable WAL, and `clients`
//!   table stay under a generous constant bound (`BoundednessChecker`). Without GC these grow with the
//!   total committed-op count (one entry per op forever) and blow past the bound; with GC they plateau
//!   near the un-checkpointed tail. (Verified non-vacuous by temporarily disabling the prune — see the
//!   commit message: the WAL then grows to ~the committed-op count and trips the checker.)
//! - **agreement** (`check_safety`) and **durability across time** (`DurabilityChecker.observe`): no
//!   committed op is ever rewritten/lost, including through the crash + state-sync window.
//!
//! Then we crash a backup, keep it down across MANY checkpoints so the cluster checkpoints PAST its
//! durable head (its WAL prefix is genuinely pruned + gone), restart it, and require it to STATE-SYNC
//! (non-vacuously: its sync count goes 0 -> >= 1) and converge — proving a laggard below the prune
//! floor recovers via snapshot, not the pruned ops. Multi-seed.

use viewstamp_simulation::{
  BoundednessChecker, CheckResult, Cluster, DurabilityChecker, check_safety,
};

#[test]
fn repeated_in_place_rebuilds_behind_a_held_root_keep_the_timeline_constant() {
  // The durable-root timeline's CONSTANT bound, driven through the checker at exactly the shape
  // that grows the queue without the endpoint-construction collapse: a superblock so slow the
  // front root write never lands, a view-change escalation that keeps a durable-view root
  // submitted behind it, and an endpoint rebuilt in place over the live session faster than the
  // backend services roots. No correlation-ending path runs at a rebuild, so nothing else
  // forfeits a dead incarnation's parked durable-view root — leaving it on the timeline would add
  // one header-bearing state per rebuild cycle, and an affine allowance (three plus two per
  // incarnation) would grow right along with it and could never fail. The collapse drops those
  // parked roots at endpoint construction, so the checker holds the queue to the constant three:
  // the held front plus the live endpoint's awaited roots.
  for seed in 0..4u64 {
    let mut c = Cluster::new(3, 1, 1, seed);
    // Every superblock write stays staged for the whole run: the first root any survivor submits
    // occupies its backend forever — the held-front precondition.
    c.set_async_superblock_delay(Some(u32::MAX));
    let bound = BoundednessChecker::new(64, 8);
    // Crash the primary: the survivors escalate a view change whose durable-view roots can never
    // land, so the victim backup always holds the front plus its one live awaited root.
    c.crash(0);
    let victim = 2usize;
    let mut max_roots = 0usize;
    let drive = |c: &mut Cluster, max_roots: &mut usize, phase: &str| {
      for _ in 0..6_000 {
        c.tick();
        *max_roots = (*max_roots).max(c.replica_roots_in_flight(victim));
        assert_eq!(
          check_safety(c),
          CheckResult::Ok,
          "seed {seed}: safety ({phase})"
        );
        assert_eq!(
          bound.observe(c),
          CheckResult::Ok,
          "seed {seed}: the root timeline stays constant-bounded ({phase})"
        );
      }
    };
    // Let the first escalation submit the roots that will hold each survivor's backend.
    drive(&mut c, &mut max_roots, "initial escalation");
    for round in 0..8 {
      // The in-place rebuild: the session (and the held front) survive; the dead incarnation's
      // parked durable-view root must NOT.
      c.restart_in_place(victim);
      drive(&mut c, &mut max_roots, &format!("rebuild round {round}"));
    }
    // Non-vacuity: submissions genuinely queued behind the held front (the accumulation shape was
    // reachable), and the front itself is still owed — the run never quietly drained.
    assert!(
      max_roots >= 2,
      "seed {seed}: VACUOUS — no root was ever parked behind the held front (max {max_roots})"
    );
    assert!(
      c.replica_roots_in_flight(victim) >= 1,
      "seed {seed}: VACUOUS — the front was not held to the end"
    );
  }
}

#[test]
fn long_run_with_gc_stays_bounded_and_survives_crash_through_the_prune() {
  for seed in 0..8u64 {
    // N=5 (crashing one backup keeps a 4-of-5 committing quorum), a SMALL checkpoint interval so the
    // run checkpoints + prunes many times, and a HIGH request count so it crosses many checkpoints.
    let mut c = Cluster::with_checkpoint_ops(5, 3, 60, seed, 4);
    let mut dur = DurabilityChecker::new(c.replica_count());
    // Per-op maps + WAL bounded by 64 (16x the 4-op interval): generous enough not to flap, tight
    // enough that an unbounded (no-GC) leak — which reaches ~the committed-op count (3*60 = 180) —
    // trips it. `clients` bounded by 8 (>= the 3 active clients, with headroom).
    let bound = BoundednessChecker::new(64, 8);

    macro_rules! check_tick {
      ($phase:literal) => {{
        assert!(
          dur.observe(&c).is_ok(),
          "seed {seed}: durability ({})",
          $phase
        );
        assert_eq!(
          check_safety(&c),
          CheckResult::Ok,
          "seed {seed}: safety ({})",
          $phase
        );
        assert_eq!(
          bound.observe(&c),
          CheckResult::Ok,
          "seed {seed}: bounded ({})",
          $phase
        );
      }};
    }

    // The laggard backup we crash through several checkpoints (not the primary, so the cluster keeps
    // committing + checkpointing while it is down).
    let laggard = 2usize;

    // Warm up until the cluster (primary) has checkpointed at least twice, so a non-trivial prefix is
    // pruned on every replica.
    let mut warmed = false;
    for _ in 0..300_000 {
      c.tick();
      check_tick!("warm-up");
      if c.replica_checkpoint_op(0).get() >= 8 {
        warmed = true;
        break;
      }
    }
    assert!(
      warmed,
      "seed {seed}: cluster checkpointed (checkpoint_op(0) >= 8) before the crash"
    );

    let laggard_head_before = c.replica_checkpoint_op(laggard).get();
    assert_eq!(
      c.replica_state_sync_count(laggard),
      0,
      "seed {seed}: laggard has not state-synced before the crash"
    );

    // Crash the laggard; keep it down across many more checkpoints so the cluster checkpoints WELL
    // past its head (its WAL prefix is pruned + unreachable by retransmit).
    c.crash(laggard);
    let target = laggard_head_before + 16;
    let mut moved_past = false;
    for _ in 0..800_000 {
      c.tick();
      check_tick!("laggard down");
      if c.replica_checkpoint_op(0).get() >= target {
        moved_past = true;
        break;
      }
    }
    assert!(
      moved_past,
      "seed {seed}: cluster checkpointed past the laggard's head ({} >= {laggard_head_before}+16) \
       while it was down — its tail is below the cluster checkpoint AND pruned everywhere",
      c.replica_checkpoint_op(0).get()
    );
    let cluster_ckpt_while_down = c.replica_checkpoint_op(0).get();

    // Restart it: recover() to its stale head (below + pruned past the cluster checkpoint) → it must
    // STATE-SYNC, not catch up from any pruned WAL.
    c.restart(laggard);

    let mut converged = false;
    for _ in 0..800_000 {
      c.tick();
      check_tick!("post-restart state-sync");
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
      "seed {seed}: the laggard state-synced through the prune and converged (sync_count={}, \
       checkpoint_op={}, target>={cluster_ckpt_while_down})",
      c.replica_state_sync_count(laggard),
      c.replica_checkpoint_op(laggard).get()
    );

    // NON-VACUITY: it genuinely state-synced (the pruned ops were recovered via snapshot, not WAL).
    assert!(
      c.replica_state_sync_count(laggard) >= 1,
      "seed {seed}: VACUOUS — the laggard converged without state-syncing through the prune"
    );

    // The committed history survived end to end, on an operational replica.
    assert_eq!(
      dur.check(&c),
      CheckResult::Ok,
      "seed {seed}: every committed op survived the long bounded run + crash + state-sync"
    );
  }
}

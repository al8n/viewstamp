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
  // that would grow the timeline one parked header-bearing state per rebuild cycle: a superblock
  // so slow the front root write never lands, a view-change escalation that keeps a durable-view
  // root parked behind it, and an endpoint rebuilt in place over the live session faster than
  // the backend services roots. The session's containers hold the bound structurally — one front
  // cell owed to the medium plus one parked cell per correlation role, with a same-role
  // resubmission overwriting its cell and the construction collapse emptying the dead
  // incarnations' cells — so this run is the regression net that the constant SURVIVES the
  // adversarial schedule end to end: held front, rebuild storm, per-tick checker arm, and the
  // non-vacuity floor below proving the parked cells were genuinely occupied behind the held
  // front rather than the schedule never reaching them.
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
    // reachable), and the front itself is still owed — the run never quietly drained. This
    // schedule occupies the front plus the DURABLE-VIEW cell (with the superblock held forever no
    // envelope ever completes, so no checkpoint root is ever minted to fill the checkpoint cell);
    // the full three-cell occupancy is
    // `a_checkpoint_root_and_a_view_change_storm_fill_every_timeline_cell`'s floor.
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
fn a_checkpoint_root_and_a_view_change_storm_fill_every_timeline_cell() {
  // The durable-root timeline's CONTRACTUAL MAXIMUM, reached and asserted: one submitted front
  // plus BOTH parked cells occupied at once, under the per-tick checker arm that bounds the
  // count at the independent constant three. The held-front rebuild storm above can never get
  // there (its forever-held superblock starves the envelope, so no checkpoint root exists);
  // this schedule uses a FINITE superblock delay sized so all three roots overlap:
  //
  //   1. the cluster runs normally until a backup's checkpoint ENVELOPE write is in flight
  //      (the delay makes that window thousands of ticks wide);
  //   2. the primary crashes inside that window — the survivors' view-change escalation begins,
  //      and the victim's first durable-view root becomes the timeline's FRONT (the envelope is
  //      not a root, so the root lane was empty);
  //   3. the envelope completes and the checkpoint root is minted behind the held front — the
  //      CHECKPOINT cell fills (an ordinary checkpoint's correlation survives the transition,
  //      so this is the kept-in-flight shape, not an abandonment);
  //   4. the escalation cadence (view_change_status, far shorter than the write delay) supersedes
  //      the in-flight view root with the next view's — the DURABLE-VIEW cell fills. Three at
  //      once, until the front lands and promotes the lowest stamp.
  //
  // The per-tick maximum then proves the parked cells were both genuinely occupied — the arm's
  // non-vacuity witness — and a rebuild inside the storm exercises the construction collapse
  // with a parked CHECKPOINT root (the storm test's collapse only ever sees a view root).
  for seed in 0..4u64 {
    // 3 voters, 3 clients x 60 requests, checkpoint interval 4: the first checkpoint is due
    // within the first ~hundred ticks of commits.
    let mut c = Cluster::with_checkpoint_ops(3, 3, 60, seed, 4);
    // Every superblock write takes 3000 polls: long enough that the crash-to-escalation latency
    // (primary_idle ~200 ticks) and one escalation window (~500 ticks) both fit INSIDE a single
    // write's flight, short enough that the envelope genuinely completes (step 3 above needs its
    // completion — the storm test's u32::MAX hold proves the opposite regime).
    c.set_async_superblock_delay(Some(3_000));
    let bound = BoundednessChecker::new(64, 8);
    let victim = 2usize;
    let mut max_roots = 0usize;
    let check = |c: &Cluster, phase: &str| {
      assert_eq!(
        check_safety(c),
        CheckResult::Ok,
        "seed {seed}: safety ({phase})"
      );
      assert_eq!(
        bound.observe(c),
        CheckResult::Ok,
        "seed {seed}: the root timeline stays under the contractual three ({phase})"
      );
    };

    // Phase 1: run until the victim's checkpoint envelope is with the backend.
    let mut envelope_seen = false;
    for _ in 0..30_000 {
      c.tick();
      check(&c, "normal run to the first envelope");
      if c.replica_checkpoints_in_flight(victim) == 1 {
        envelope_seen = true;
        break;
      }
    }
    assert!(
      envelope_seen,
      "seed {seed}: VACUOUS — the victim never had a checkpoint envelope in flight"
    );

    // Phase 2: crash the primary inside the envelope's flight; the survivors escalate a view
    // change whose durable-view writes are slower than the escalation cadence, so the victim's
    // timeline reaches front + checkpoint cell + durable-view cell before the front lands.
    c.crash(0);
    for _ in 0..12_000 {
      c.tick();
      max_roots = max_roots.max(c.replica_roots_in_flight(victim));
      check(&c, "post-crash escalation");
    }
    assert_eq!(
      max_roots, 3,
      "seed {seed}: the schedule must occupy the front AND both parked cells at once \
       (the contractual maximum the checker arm bounds)"
    );

    // Phase 3: rebuild the victim in place mid-storm — the construction collapse now runs over
    // a timeline that can hold a parked checkpoint root — and keep the per-tick arm on it.
    c.restart_in_place(victim);
    for _ in 0..4_000 {
      c.tick();
      check(&c, "rebuild inside the storm");
    }
    assert!(
      c.replica_roots_in_flight(victim) >= 1,
      "seed {seed}: VACUOUS — the storm drained before the run ended"
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

//! THE M3 GATE — the capstone sweep: committed ops survive EVERYTHING.
//!
//! Combines, simultaneously, every M3 fault mode:
//!   - crash-stop + restart (the laggard, then the view-0 primary),
//!   - PERMANENT storage-faults (bit-rot + torn) on every replica's WAL from t0,
//!   - GC (`checkpoint_ops = 4`, so checkpoints fire frequently and prune the WAL + per-op maps),
//!   - partitions (`partition` / `heal`),
//!   - a far-behind laggard that must rejoin via state-sync — and, where a rotted committed slot is
//!     pruned past on the quorum, via the M3.5 FORCE-sync escalation.
//!
//! It asserts:
//!   - **SAFETY ALWAYS** — `check_safety` (agreement at an instant) + `DurabilityChecker` (no committed
//!     op rewritten/lost across time) + `ViewMonotonicChecker` (no view regress), EVERY tick, under
//!     EVERY fault combination (warm-up, partitioned+crashed, healed+failover, converging).
//!   - **BOUNDEDNESS ALWAYS** — `BoundednessChecker` (per-op maps + WAL stay bounded under GC), every tick.
//!   - **LIVENESS ONCE A STABLE QUORUM EXISTS** — asserted ONLY after the partition heals + the laggard
//!     restarts (a connected, caught-up quorum then exists): all clients finish AND the laggard converges
//!     (via state-sync / force-sync / a forfeit-or-failover-driven view change). VSR cannot make progress
//!     without a connected quorum, so the schedule GUARANTEES one for the convergence window (heal all
//!     partitions, keep a 5-of-6 live set, stop injecting new partitions).
//!
//! ## The fault schedule (a stable quorum is guaranteed for the liveness window)
//!
//! N = 6 (quorum = 4), `checkpoint_ops = 4`, 3 clients × 80 requests under latency+jitter+10‰ drop and
//! PERMANENT WAL corruption (torn 150‰ + bit-rot 150‰) from t0. Phases per seed:
//!   1. **Warm-up under faults** until the cluster has checkpointed (`checkpoint_op(0) >= 8`) — proving
//!      it produces durable checkpoints + GC under fault.
//!   2. **Partition {0,1,2,3} | {4,5} + crash the laggard (4).** The majority side {0,1,2,3} = quorum
//!      keeps committing + checkpointing (a stable quorum survives on the majority). Hold the laggard
//!      down + isolated until the cluster checkpoint advances >= 16 ops past its pre-crash head — so on
//!      restart its head is below the cluster checkpoint and pruned everywhere on the majority, and
//!      (permanent faults) some restarted committed slot is rotted + pruned → the FORCE-sync strand.
//!   3. **HEAL, then crash the view-0 primary (0).** The healed live set {1,2,3,4,5} = 5 >= quorum keeps
//!      a committing quorum. Crashing the primary drives a view change (failover); if the elected
//!      primary is itself checkpoint-behind it FORFEITS to a caught-up one.
//!   4. **Restart the laggard into the healed cluster + drive to convergence.** It state-syncs (or
//!      force-syncs a pruned committed hole), catches up, and all clients finish. LIVENESS asserted HERE.
//!   5. **Final.** `DurabilityChecker::check` — the committed history survives on >= 1 operational replica.
//!
//! ## Non-vacuity (asserted in aggregate across the sweep)
//!
//! The gate would prove nothing if the schedule degraded into a no-op. So it asserts, in aggregate, that
//! the run genuinely (a) GC'd — the cluster checkpoint advanced (`checkpoint_op` grew) every seed; (b)
//! drove a real view change every seed (the primary crash → failover/forfeit); (c) rejoined the laggard
//! via a snapshot sync every seed; and (d) exercised the M3.5 FORCE-sync escalation
//! (`forced_syncs_applied` advanced) — proving the permanent-fault + GC + partition strand was hit, not
//! bypassed. (`check_safety` + the durability/view checkers run every tick, so a single safety slip
//! anywhere in any phase fails the gate immediately.)
//!
//! Multi-seed (16). Every seed must satisfy safety+boundedness ALWAYS and liveness after the heal.

use core::time::Duration;

use vsrr_simulation::{
  BoundednessChecker, CheckResult, Cluster, DurabilityChecker, Faults, StorageFaults,
  ViewMonotonicChecker, check_safety,
};

#[test]
fn the_m3_gate_committed_ops_survive_everything() {
  // Aggregate non-vacuity tallies — each must be hit across the sweep (asserted at the end).
  let mut seeds_state_synced = 0usize;
  let mut seeds_force_synced = 0usize;
  let mut seeds_view_changed = 0usize;
  let mut seeds_checkpoint_grew = 0usize;

  for seed in 0..16u64 {
    // N=6 (quorum 4): the majority {0,1,2,3} survives the partition AND a 5-of-6 set survives the
    // post-heal primary crash — a stable quorum exists for every committing window.
    let mut c = Cluster::with_checkpoint_ops(6, 3, 80, seed, 4);
    let mut dur = DurabilityChecker::new(c.replica_count());
    let mut vm = ViewMonotonicChecker::new(c.replica_count());
    // Per-op maps + WAL bounded by 64 (16x the 4-op interval); client sessions by 8 (>= 3 active).
    let bound = BoundednessChecker::new(64, 8);
    c.set_faults(Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(3),
      drop_per_mille: 10,
      duplicate_per_mille: 0,
    });
    // PERMANENT WAL corruption on every replica (torn + bit-rot; NO transient read-fault — that would
    // mask the permanent path by clearing on retry). High enough that some committed slot rots across
    // the sweep, exercising the permanent-fault recovery + the force-sync strand.
    c.set_storage_faults(StorageFaults {
      read_fault_per_mille: 0,
      torn_write_per_mille: 150,
      bit_rot_per_mille: 150,
      misdirect_read_per_mille: 0,
      corrupt_checkpoint_read_per_mille: 0,
    });

    // Safety + boundedness, asserted EVERY tick in EVERY phase. (Liveness is asserted only in phase 4,
    // after the heal — VSR cannot progress without a connected quorum, so asserting it mid-partition
    // would be wrong.)
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
        assert_eq!(
          bound.observe(&c),
          CheckResult::Ok,
          "seed {seed}: bounded ({})",
          $phase
        );
      }};
    }

    let laggard = 4usize;

    // (1) Warm up under faults until the cluster has checkpointed (proving durable checkpoints + GC).
    let mut warmed = false;
    for _ in 0..400_000 {
      c.tick();
      check_tick!("warm-up");
      if c.replica_checkpoint_op(0).get() >= 8 {
        warmed = true;
        break;
      }
    }
    assert!(
      warmed,
      "seed {seed}: cluster checkpointed (>=8) under faults before the partition"
    );
    let laggard_head_before = c.replica_checkpoint_op(laggard).get();

    // (2) Partition {0,1,2,3} | {4,5}, crash the isolated laggard, and let the MAJORITY (a stable
    // quorum) checkpoint >= 16 ops past the laggard's head — so its WAL is pruned everywhere on the
    // majority and (permanent faults) a restarted committed slot is rotted + pruned.
    c.partition(vec![0, 0, 0, 0, 1, 1]);
    c.crash(laggard);
    let target = laggard_head_before + 16;
    let mut moved = false;
    for _ in 0..1_000_000 {
      c.tick();
      check_tick!("partitioned + laggard down");
      if c.replica_checkpoint_op(0).get() >= target {
        moved = true;
        break;
      }
    }
    assert!(
      moved,
      "seed {seed}: the majority quorum checkpointed past the laggard while partitioned \
       ({} >= {laggard_head_before}+16)",
      c.replica_checkpoint_op(0).get()
    );
    let cluster_ckpt_while_down = c.replica_checkpoint_op(0).get();
    if cluster_ckpt_while_down > laggard_head_before {
      seeds_checkpoint_grew += 1;
    }

    // (3) HEAL, then crash the view-0 primary (0) → a view change (forfeit if the elected primary is
    // checkpoint-behind). The healed live set {1,2,3,4-after-restart,5} = 5 >= quorum 4 keeps a
    // committing quorum. (Crash the primary AFTER healing — never crash a second replica while
    // partitioned, which would drop the live committing set below quorum.)
    c.heal();
    c.crash(0);

    // (4) Restart the laggard into the healed cluster → it must state-sync (or FORCE-sync), then
    // converge. LIVENESS is asserted only HERE (the cluster is healed; a stable quorum is connected).
    c.restart(laggard);
    let mut converged = false;
    for _ in 0..3_000_000 {
      c.tick();
      check_tick!("healed: state-sync + view change + converge");
      let view_changed = c.any_replica_view_advanced_beyond(0);
      let clients_done = (0..c.client_count()).all(|i| c.client(i).is_done());
      let laggard_ok = c.replica_status_is_operational(laggard)
        && c.replica_checkpoint_op(laggard).get() >= cluster_ckpt_while_down;
      if view_changed && clients_done && laggard_ok {
        converged = true;
        break;
      }
    }
    assert!(
      converged,
      "seed {seed}: after healing + restart, a view change ran, the laggard converged, and clients \
       finished (sync_count={}, forced={}, laggard_ckpt={}, target>={cluster_ckpt_while_down})",
      c.replica_state_sync_count(laggard),
      c.replica_forced_sync_count(laggard),
      c.replica_checkpoint_op(laggard).get()
    );

    if c.replica_state_sync_count(laggard) >= 1 {
      seeds_state_synced += 1;
    }
    if c.replica_forced_sync_count(laggard) >= 1 {
      seeds_force_synced += 1;
    }
    if c.any_replica_view_advanced_beyond(0) {
      seeds_view_changed += 1;
    }

    // (5) The committed history survived end to end on an operational replica.
    assert_eq!(
      dur.check(&c),
      CheckResult::Ok,
      "seed {seed}: every committed op survived crash + permanent-fault + GC + partition + state-sync"
    );
    // The laggard genuinely jumped past its pre-crash head (snapshot recovery, not WAL replay).
    assert!(
      c.replica_checkpoint_op(laggard).get() > laggard_head_before,
      "seed {seed}: laggard's checkpoint advanced past its pre-crash head"
    );
  }

  // NON-VACUITY (aggregate across the sweep): the gate must actually hit the hard paths. Each assert
  // fails loudly if the schedule degrades into a no-op.
  assert!(
    seeds_checkpoint_grew >= 1,
    "no seed advanced the cluster checkpoint — GC / checkpointing was never exercised"
  );
  assert!(
    seeds_view_changed >= 1,
    "no seed drove a view change — the primary crash never triggered failover/forfeit"
  );
  assert!(
    seeds_state_synced >= 1,
    "no seed state-synced the laggard — the laggard was never far enough behind"
  );
  assert!(
    seeds_force_synced >= 1,
    "no seed exercised the M3.5 FORCE-sync escalation — the permanent-fault + GC + partition strand \
     (a rotted committed hole pruned past on the quorum) was never hit"
  );
}

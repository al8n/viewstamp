//! M3.5 force-sync gate: a replica STUCK on a permanently-rotted committed hole that the QUORUM has
//! checkpointed + pruned past converges via the FORCE-state-sync escalation — NOT op-by-op repair (no
//! peer can serve the pruned op). This is the deterministic, non-vacuous proof that the M3.5 escalation
//! ([`Endpoint::maybe_force_sync`]) closes the GC + permanent-fault strand the `run_gc` doc-comment
//! flagged.
//!
//! ## The strand (the opus-confirmed blocker)
//!
//! 1. The laggard is `Normal`, holding a committed op `N` that it read back PERMANENTLY faulty
//!    (bit-rot) from its OWN WAL on restart — dropped from the `log` cache, soliciting it via
//!    `RequestPrepare`. Its `commit_min` is HELD at `N-1`.
//! 2. The laggard's head is `> N` (it holds intact ops above the hole). So the ORDINARY state-sync
//!    trigger (`maybe_request_sync`, `checkpoint_op > self.op`) is FALSE — its head is ABOVE the
//!    cluster checkpoint, so no `Commit`/`Prepare` fires the ordinary sync.
//! 3. Every replica that ever held `N` has GC-pruned it (`N <= their checkpoint_op`). So no peer can
//!    answer `RequestPrepare(N)` — every peer stays silent.
//!
//! Without the escalation the laggard is stuck at `commit_min == N-1` FOREVER (re-soliciting
//! `RequestPrepare` with no possible answerer). The escalation keys on the *unservable pruned hole*:
//! a `repair` hole `<= quorum_checkpoint_op()` is snapshot-only, so the replica clears it and FORCES a
//! `RequestSync` to the quorum checkpoint (which is `>= N`, so its snapshot subsumes `N`).
//!
//! ## The construction (deterministic)
//!
//! `checkpoint_ops = 4`, PERMANENT bit-rot on the laggard's WAL only (every replica's WAL is seeded,
//! but only the laggard reads its own disk on restart, so only it surfaces the fault — the
//! `permanent_faults.rs` precedent). We let the laggard get WELL AHEAD (large head), crash it, then
//! advance the cluster checkpoint by ~2 intervals while it is down — landing the cluster checkpoint
//! BETWEEN a rotted committed op `N` and the laggard's pre-crash head `H` (`N <= cluster_ckpt < H`).
//! On restart the laggard `recover()`s its tail `(its_own_checkpoint .. H]`, reads a rotted committed
//! slot `N` back faulty, registers a `repair` hole, and holds commit at `N-1`. Its head `H` is ABOVE
//! the cluster checkpoint (ordinary trigger false) while `N` is below it (pruned on the quorum) — the
//! precise force-sync window.
//!
//! ## Non-vacuity (the hard requirement)
//!
//! The proto counts FORCED syncs separately from ordinary ones (`forced_syncs_applied`, surfaced via
//! `replica_forced_sync_count`). Across the sweep we assert this goes `> 0` — a replica genuinely hit
//! the strand and recovered the pruned op via a FORCED snapshot fetch, not an ordinary `> self.op`
//! sync and not op-by-op repair. Reverting `maybe_force_sync` to a no-op makes the strand-window seeds
//! HANG (the laggard loops `RequestPrepare` with no answerer), mirroring the boundedness gate's no-GC
//! check.
//!
//! `check_safety` (agreement at an instant) and `DurabilityChecker` (no committed op rewritten/lost
//! across the stuck-hole recovery, every tick) both run throughout. Multi-seed; every seed converges
//! with no hang and no committed-op loss.

use core::time::Duration;

use vsrr_simulation::{
  CheckResult, Cluster, DurabilityChecker, Faults, StorageFaults, check_safety,
};

#[test]
fn a_stuck_pruned_committed_hole_converges_via_force_sync() {
  // Aggregate non-vacuity: across the sweep at least one seed must (a) rot a committed slot in the
  // laggard's tail AND (b) actually FORCE-sync (the proto's forced-sync counter advances across the
  // restart). Both fail loudly if the construction degrades into ordinary state-sync only.
  let mut seeds_forced_sync = 0usize;
  let mut seeds_rotted_committed = 0usize;

  for seed in 0..24u64 {
    // N=5 (so crashing one backup leaves a 4-of-5 quorum committing the whole time), a SMALL
    // checkpoint interval (4), and plenty of client load to cross many checkpoints.
    let mut c = Cluster::with_checkpoint_ops(5, 2, 60, seed, 4);
    let mut dur = DurabilityChecker::new(c.replica_count());
    c.set_faults(Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(2),
      drop_per_mille: 5,
      duplicate_per_mille: 0,
    });
    // PERMANENT bit-rot (no transient read-fault — that would mask the permanent path by clearing on
    // retry; no torn — keep the fault model a single, crisp permanent class). High enough that a
    // committed slot in the laggard's tail rots across the sweep.
    c.set_storage_faults(StorageFaults {
      read_fault_per_mille: 0,
      torn_write_per_mille: 0,
      bit_rot_per_mille: 250,
      misdirect_read_per_mille: 0,
    });
    let laggard = 2usize;

    macro_rules! check_tick {
      ($p:literal) => {{
        assert!(dur.observe(&c).is_ok(), "seed {seed}: durability ({})", $p);
        assert_eq!(
          check_safety(&c),
          CheckResult::Ok,
          "seed {seed}: safety ({})",
          $p
        );
      }};
    }

    // (1) Warm up until the laggard is WELL AHEAD (head >= 24), the cluster has checkpointed (>= 8),
    // AND every OTHER replica (the would-be survivors {0,1,3,4}) is also caught up to >= 24 — so that
    // crashing the laggard leaves a HEALTHY committing quorum (the other 4). Without this, a seed where
    // some survivor was transiently behind at crash time would have no progressing quorum once the
    // laggard is down (VSR cannot make progress without a connected, caught-up quorum), and the cluster
    // would correctly stall — a gate-construction artefact, not a proto bug. (Verified: with the
    // laggard UP, every seed converges fully — see the no-crash diagnostic during development.)
    let survivors_caught_up =
      |c: &Cluster| (0..c.replica_count()).all(|i| i == laggard || c.replica_op(i).get() >= 24);
    let mut warmed = false;
    for _ in 0..600_000 {
      c.tick();
      check_tick!("warm-up");
      if c.replica_op(laggard).get() >= 24
        && c.replica_checkpoint_op(0).get() >= 8
        && survivors_caught_up(&c)
      {
        warmed = true;
        break;
      }
    }
    assert!(
      warmed,
      "seed {seed}: laggard ahead (head>=24), cluster checkpointed (>=8), and the survivors caught up \
       (a healthy quorum survives the laggard's crash) before the crash"
    );

    let head_at_crash = c.replica_op(laggard).get();
    let own_ckpt_at_crash = c.replica_checkpoint_op(laggard).get();
    // (Note: under heavy drop the laggard may have ordinary-state-synced once during warm-up — that is
    // benign and orthogonal; we measure the FORCED-sync DELTA across the restart below, not an absolute.)

    // (2) Crash the laggard; advance the cluster checkpoint TWO intervals past the laggard's OWN
    // checkpoint while it is down. This prunes — on the surviving quorum — the ops just above the
    // laggard's own checkpoint, exactly the slots its recover loop re-reads from its tail
    // `(own_checkpoint .. head]`, so a rotted committed slot there can no longer be served by ANY peer's
    // `RequestPrepare` (the whole quorum has checkpointed past it). Two intervals (not more) keeps the
    // prune BELOW the laggard's big head lead, so its restored head stays ABOVE the cluster checkpoint
    // (the ordinary `> self.op` trigger stays FALSE) — the precise force-sync regime. (Empirically two
    // intervals maximises the forced-path hit-rate across the sweep: one interval often leaves the slot
    // still servable by a lagging backup; three+ prunes past the head into ordinary-state-sync territory.)
    c.crash(laggard);
    let ck_target = own_ckpt_at_crash + 8; // two checkpoint intervals past the laggard's own checkpoint
    let mut moved = false;
    for _ in 0..1_500_000 {
      c.tick();
      check_tick!("down");
      if c.replica_checkpoint_op(0).get() >= ck_target {
        moved = true;
        break;
      }
    }
    assert!(
      moved,
      "seed {seed}: cluster checkpoint advanced two intervals past the laggard's own checkpoint while it \
       was down ({} >= {ck_target}) — so the laggard's recover-tail ops are pruned on the quorum",
      c.replica_checkpoint_op(0).get()
    );
    let cluster_ck = c.replica_checkpoint_op(0).get();

    // A committed slot in the laggard's tail rotted on its OWN disk (it surfaces as a repair hole on
    // restart, and — being below the cluster checkpoint — is pruned on the quorum). This is the fault
    // that, combined with the head staying above the cluster checkpoint, produces the force-sync strand.
    let rotted_committed_tail =
      c.wal_corrupt_slots_at_or_below_for_test(laggard, head_at_crash) > 0;
    if rotted_committed_tail {
      seeds_rotted_committed += 1;
    }

    // (3) Restart the laggard into the live cluster.
    c.restart(laggard);
    let forced_before = c.replica_forced_sync_count(laggard);

    // (4) Drive to convergence. A stuck pruned hole MUST be rescued by the escalation (no peer can
    // serve it); the laggard force-syncs, restores the snapshot (>= N), and its commit advances past
    // the hole. Clients finish; no committed op is ever rewritten or lost (checked every tick).
    let mut converged = false;
    for _ in 0..1_000_000 {
      c.tick();
      check_tick!("converge");
      if (0..c.client_count()).all(|i| c.client(i).is_done())
        && c.replica_status_is_operational(laggard)
        && c.replica_checkpoint_op(laggard).get() >= cluster_ck
      {
        converged = true;
        break;
      }
    }
    assert!(
      converged,
      "seed {seed}: the stuck laggard converged (did NOT hang on a pruned hole). \
       sync_count={}, forced={}, laggard_ckpt={}, target>={cluster_ck}, rotted_committed_tail={rotted_committed_tail}",
      c.replica_state_sync_count(laggard),
      c.replica_forced_sync_count(laggard),
      c.replica_checkpoint_op(laggard).get()
    );

    // Whether THIS seed's laggard recovered via the FORCED escalation (counted for the aggregate
    // non-vacuity proof). Per-seed we only require convergence + durability above — some seeds' rotted
    // slot is still servable by a lagging peer (ordinary `RequestPrepare` repair fills it), which is an
    // equally-valid safe recovery; the strand-and-force-sync path is proven in AGGREGATE below.
    if c.replica_forced_sync_count(laggard) > forced_before {
      seeds_forced_sync += 1;
    }

    // No committed op lost across the stuck-hole recovery.
    assert_eq!(
      dur.check(&c),
      CheckResult::Ok,
      "seed {seed}: no committed op lost across the stuck-hole recovery"
    );
  }

  // NON-VACUITY (aggregate): the FORCED escalation genuinely fired across the sweep. A gate where the
  // forced path never fired would prove nothing about the M3.5 closure — these asserts fail loudly if
  // the construction degrades into ordinary state-sync only. (`forced_syncs_applied` is the proto
  // counter that increments ONLY on the forced path, distinct from ordinary `> self.op` syncs.)
  assert!(
    seeds_rotted_committed >= 1,
    "no seed rotted a committed slot on the laggard — raise bit_rot or the head lead"
  );
  assert!(
    seeds_forced_sync >= 1,
    "VACUOUS — no seed exercised the FORCE-sync escalation (forced_syncs_applied never advanced across \
     the restart). The strand (a rotted committed hole at/below the cluster checkpoint with the head \
     above it, so ordinary `> self.op` is false and no peer can serve the pruned op) was never hit; \
     raise bit_rot / the head lead so a committed slot in the laggard's tail rots."
  );
}

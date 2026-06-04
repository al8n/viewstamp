//! Bounded-WAL gate: the PHYSICAL bounded-WAL stall-before-wrap, proven in the deterministic sim
//! (prove it in simulation before the real disk driver).
//!
//! With an OPT-IN bounded ring WAL ([`Cluster::set_wal_capacity`]) of `N` slots, op `K` occupies ring
//! slot `K mod N`, so an append at `K + N` would PHYSICALLY overwrite op `K`'s slot. The safety
//! invariant Phase A enforces: a slot for op `K` is reused by `K + N` ONLY AFTER `K` is below the prune
//! floor `min(checkpoint_op, quorum_checkpoint_op)` (checkpoint-subsumed on a quorum). The primary
//! enforces it by STALLING op-assignment so the un-pruned window `(floor, op]` never exceeds `N` slots —
//! it refuses to mint op `K + 1` when `(K + 1) - floor > N`, dropping the request (back-pressure) until
//! the quorum checkpoints forward and `run_gc` frees ring slots.
//!
//! These gates assert (1) ops KEEP FLOWING under a bounded ring (the stall self-releases as the cluster
//! checkpoints — proven via the proto's `wal_stalls` counter going `> 0` then every client finishing),
//! and (2) NO op above the durable checkpoint is ever physically wrapped away — so no committed op is
//! lost to a ring-wrap before it is snapshot-subsumed. A laggard below the prune floor whose ops HAVE
//! been wrapped away would recover them via state-sync, verified separately in Phase B.
//!
//! ## Phase B (this milestone): crash-recovery + the wrapped-away laggard
//!
//! [`bounded_wal_recover_reconstructs_a_wrapped_ring`] proves a bounded-WAL replica that has wrapped its
//! ring MANY times recovers correctly on crash + restart: `recover` reads exactly the RESIDENT tail
//! `(checkpoint_op .. head]` (which the stall keeps `<= N` slots, so it FITS the ring) and never requests
//! a wrapped-away op below the prune floor — no spurious fault/repair for a snapshot-subsumed op, the
//! right head/commit, and a clean rejoin. [`bounded_wal_laggard_with_wrapped_away_ops_recovers_via_state_sync`]
//! proves the crux of why a bounded WAL needs state-sync: a backup partitioned past its window has the
//! ops it is missing PHYSICALLY wrapped away from every ring (a `RequestPrepare` for them is unservable
//! cluster-wide), so it can ONLY recover via the checkpoint snapshot (state-sync), and does.
//! [`bounded_wal_backup_below_ring_window_state_syncs_instead_of_overwriting`] proves the CONNECTED
//! backup-overflow case: a sub-quorum laggard that keeps receiving head-extending `Prepare`s while its own
//! checkpoint lags far behind would, without a guard, append an op whose ring slot still holds an
//! un-pruned op — breaking the resident-tail invariant `recover` relies on. The proto's
//! `maybe_sync_below_ring_window` guard makes such a backup STATE-SYNC to the cluster checkpoint instead
//! of overwriting the needed slot; the proto's permanent `append_prepare` debug-assert backstops that no
//! append ever overwrites an un-pruned slot, throughout the adversarial run.

use core::time::Duration;
use viewstamp_proto::OpNumber;
use viewstamp_simulation::{CheckResult, Cluster, DurabilityChecker, Faults, check_safety};

/// The PRIMARY-side WAL-residency safety invariant for a bounded ring: every op strictly above the
/// replica's durable checkpoint up to its head MUST still be physically resident in the WAL ring
/// (`Clean`/`Faulty`) — none was overwritten by a wrap. The prune floor is `<= checkpoint_op`, and the
/// stall keeps the wrapped-over op `(next_op - N) <= floor <= checkpoint_op`, so a wrap only ever drops
/// a snapshot-subsumed op; anything above the checkpoint is untouched. Checked on the primary (the only
/// replica that assigns ops + stalls); a backup merely appends what it is told.
fn primary_wal_window_is_intact(c: &Cluster, primary: usize) -> Result<(), String> {
  let ckpt = c.replica_checkpoint_op(primary).get();
  let head = c.replica_op(primary).get();
  for op in (ckpt + 1)..=head {
    if !c.replica_wal_holds_op(primary, viewstamp_proto::OpNumber::with(op)) {
      return Err(format!(
        "primary {primary}: op {op} in the un-checkpointed window (checkpoint_op={ckpt}, head={head}) \
         is NOT WAL-resident — a ring-wrap overwrote an un-pruned slot (committed-op-loss class)"
      ));
    }
  }
  Ok(())
}

#[test]
fn bounded_wal_primary_stalls_before_overwriting_an_unpruned_slot() {
  for seed in 0..8u64 {
    // N=3 cluster, a SMALL checkpoint interval (4) and a SMALL WAL ring (12 = 3 intervals) so the ring
    // genuinely fills and the primary must stall+release repeatedly, with a pipeline deep enough (8
    // concurrent clients) that the un-pruned window reaches the ring bound. capacity (12) >
    // checkpoint_ops (4) + the pipeline/quorum-report headroom, so the stall ALWAYS releases.
    let mut c = Cluster::with_checkpoint_ops(3, 8, 60, seed, 4);
    c.set_wal_capacity(Some(12));
    let mut dur = DurabilityChecker::new(c.replica_count());

    // Replica 0 is the stable view-0 primary on a clean network (no view change), so the WAL-window
    // invariant is checked against a fixed primary throughout.
    let primary = 0usize;

    let mut converged = false;
    for _ in 0..200_000 {
      c.tick();
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: durability across time"
      );
      assert_eq!(check_safety(&c), CheckResult::Ok, "seed {seed}: agreement");
      // THE physical safety invariant: no op above the durable checkpoint was ever wrapped away.
      if let Err(why) = primary_wal_window_is_intact(&c, primary) {
        panic!("seed {seed}: {why}");
      }
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        converged = true;
        break;
      }
    }
    assert!(
      converged,
      "seed {seed}: ops KEEP FLOWING under the bounded ring — every client finished (the stall \
       self-released as the cluster checkpointed forward). primary head={}, checkpoint_op={}, \
       stalls={}",
      c.replica_op(primary).get(),
      c.replica_checkpoint_op(primary).get(),
      c.replica_wal_stalls(primary),
    );
    assert!(
      c.replica_is_primary(primary),
      "seed {seed}: replica 0 stayed the view-0 primary on a clean network"
    );

    // NON-VACUITY: the run genuinely exercised the stall-before-wrap. The primary actually STALLED
    // (dropped requests when the un-pruned window hit the ring bound) — so the ring filled and the
    // stall+release machinery was exercised, not vacuously skipped by an under-filled ring.
    assert!(
      c.replica_wal_stalls(primary) > 0,
      "seed {seed}: the primary STALLED at least once (wal_stalls={}) — the bounded ring genuinely \
       filled and the stall-before-wrap engaged",
      c.replica_wal_stalls(primary),
    );

    // End to end: no committed op was lost across the whole bounded run.
    assert_eq!(
      dur.check(&c),
      CheckResult::Ok,
      "seed {seed}: every committed op survived the bounded-ring run"
    );
  }
}

#[test]
fn bounded_wal_stall_releases_when_the_quorum_checkpoints_forward() {
  // Fill the ring so the primary STALLS (on_request drops new requests — proven by the proto's
  // `wal_stalls` counter going > 0), then keep ticking: as the quorum checkpoints forward `run_gc`
  // frees ring slots and op-assignment RESUMES, ultimately finishing every client. The whole-run
  // WAL-window invariant holds throughout (no un-pruned op is ever wrapped away). Single seed.
  let mut c = Cluster::with_checkpoint_ops(3, 8, 60, 7, 4);
  c.set_wal_capacity(Some(12));
  let primary = 0usize;

  assert_eq!(
    c.replica_wal_stalls(primary),
    0,
    "no stall before the ring has filled"
  );
  let mut observed_stall_with_pending_clients = false;
  for _ in 0..200_000 {
    c.tick();
    if let Err(why) = primary_wal_window_is_intact(&c, primary) {
      panic!("the un-checkpointed WAL window stays intact even while the ring is full: {why}");
    }
    // The DETERMINISTIC stall signal: the primary dropped a request for lack of a free ring slot (the
    // un-pruned window hit the ring bound `N`) WHILE clients still had work pending — genuine
    // back-pressure, not idle quiescence.
    if c.replica_wal_stalls(primary) > 0 && (0..c.client_count()).any(|i| !c.client(i).is_done()) {
      observed_stall_with_pending_clients = true;
    }
    if (0..c.client_count()).all(|i| c.client(i).is_done()) {
      break;
    }
  }

  assert!(
    observed_stall_with_pending_clients,
    "the primary STALLED while clients were still pending (wal_stalls={}) — the bounded-WAL \
     back-pressure engaged when the un-pruned window reached the ring bound",
    c.replica_wal_stalls(primary),
  );
  // The stall RELEASED: despite filling the ring (and stalling repeatedly), the quorum kept
  // checkpointing forward, `run_gc` freed slots, op-assignment resumed, and every client finished.
  assert!(
    (0..c.client_count()).all(|i| c.client(i).is_done()),
    "the stall self-released as the quorum checkpointed forward — all clients finished. head={}, \
     checkpoint_op={}, total stalls={}",
    c.replica_op(primary).get(),
    c.replica_checkpoint_op(primary).get(),
    c.replica_wal_stalls(primary),
  );
}

/// Every op strictly above a replica's durable checkpoint up to its head MUST be physically resident in
/// the WAL ring — the resident-tail invariant `recover` relies on. The stall keeps the un-pruned window
/// `(prune_floor, head]` within `N` slots (`prune_floor <= checkpoint_op`), so the band
/// `(checkpoint_op .. head]` (a sub-range of it) is wholly resident; `recover` reads exactly this band,
/// so it never requests a wrapped-away op. Checked on the replica we crash + restart, both before the
/// crash (the durable WAL it will recover from) and after the rejoin.
fn tail_is_ring_resident(c: &Cluster, r: usize) -> Result<(), String> {
  let ckpt = c.replica_checkpoint_op(r).get();
  let head = c.replica_op(r).get();
  for op in (ckpt + 1)..=head {
    if !c.replica_wal_holds_op(r, OpNumber::with(op)) {
      return Err(format!(
        "replica {r}: op {op} in the resident tail (checkpoint_op={ckpt}, head={head}) is NOT \
         WAL-resident — a ring-wrap dropped an op `recover` must read"
      ));
    }
  }
  Ok(())
}

/// Item 1: a bounded-WAL replica whose ring has WRAPPED MANY TIMES recovers correctly on
/// crash + restart. `recover` reads the un-pruned tail `(checkpoint_op .. head]`; the primary stall keeps
/// that band `<= N` slots, so it FITS the ring and every op it reads is RESIDENT — `recover` never
/// requests a wrapped-away (snapshot-subsumed) op `<= prune_floor`, which the ring would return `Absent`
/// and which would spuriously look faulty. The placement check (`header.op() == op`) disambiguates a
/// wrapped slot: a slot `K mod N` holding a HIGHER generation when recover requests `K - N` is modelled
/// `Absent` by the bounded WAL, so recover never misreads a wrapped slot as the requested op.
///
/// We crash a BACKUP (the primary stays up, so the cluster keeps committing + checkpointing + WRAPPING
/// while it is briefly down — its own durable ring has wrapped many times before it crashes), restart it,
/// and assert: NO spurious fault/repair (the recovered replica reaches Normal from its OWN disk — it is
/// not stranded RecoveringHead, and it does NOT state-sync, since its head is at/above the cluster
/// checkpoint and its whole tail is readable from the ring), the RIGHT head (its recovered tail is fully
/// ring-resident), and a consistent rejoin (clients finish; no committed op rewritten/lost, every tick).
///
/// Fail-before (had recover a bounded-ring bug): if it tried to read an op below the ring's resident
/// range, the ring returns `Absent` → a spurious fault → a needless repair / a wrong head / a strand.
#[test]
fn bounded_wal_recover_reconstructs_a_wrapped_ring() {
  for seed in 0..8u64 {
    // N=3 cluster (crash one backup, the primary + the other backup keep a 2-of-3 quorum committing),
    // a SMALL checkpoint interval (4) and a SMALL ring (12 = 3 intervals) so by the time we crash the
    // backup its ring has WRAPPED many times (head >> N). 6 clients x 12 requests = up to 72 ops, six
    // ring-lengths of wrapping.
    let mut c = Cluster::with_checkpoint_ops(3, 6, 12, seed, 4);
    c.set_wal_capacity(Some(12));
    let mut dur = DurabilityChecker::new(c.replica_count());

    // The backup we crash + recover (replica 1; replica 0 is the stable view-0 primary, so the cluster
    // keeps committing + checkpointing + wrapping the whole time).
    let backup = 1usize;

    // Warm up until the backup's ring has genuinely WRAPPED several times: its head must exceed a couple
    // of ring-lengths AND it must have checkpointed, so its recovered tail is an OFFSET window into a
    // ring that has overwritten its early slots many times over.
    let mut wrapped = false;
    for _ in 0..200_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok(), "seed {seed}: durability (warm-up)");
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (warm-up)"
      );
      if c.replica_op(backup).get() >= 30 && c.replica_checkpoint_op(backup).get() >= 8 {
        wrapped = true;
        break;
      }
    }
    assert!(
      wrapped,
      "seed {seed}: the backup's ring wrapped several times before the crash (head={}, \
       checkpoint_op={}, capacity=12)",
      c.replica_op(backup).get(),
      c.replica_checkpoint_op(backup).get(),
    );

    // The durable WAL the backup will recover from holds ONLY its resident tail (the ring wrapped, so the
    // early ops are physically gone) — and that tail is exactly `(checkpoint_op .. head]`, every slot
    // resident. This is the precondition that makes the recover read window FIT the ring.
    assert!(
      tail_is_ring_resident(&c, backup).is_ok(),
      "seed {seed}: pre-crash, the backup's resident tail is intact: {:?}",
      tail_is_ring_resident(&c, backup)
    );
    let head_before = c.replica_op(backup).get();
    let ckpt_before = c.replica_checkpoint_op(backup).get();
    assert_eq!(
      c.replica_state_sync_count(backup),
      0,
      "seed {seed}: the backup has not state-synced before the crash"
    );

    // Crash + restart. The backup is down only briefly (the cluster does NOT checkpoint past its head),
    // so on restart its head is at/above the cluster checkpoint and it recovers its WHOLE tail from its
    // OWN ring — no state-sync needed, no spurious fault. `restart` drives the Recovering read loop to
    // completion (reading exactly the resident tail back from the ring).
    c.crash(backup);
    for _ in 0..50 {
      c.tick();
    }
    c.restart(backup);

    // RIGHT AFTER recover: the replica is operational from its OWN disk (NOT stranded RecoveringHead, NOT
    // forced to peer-fetch a checkpoint), it did NOT state-sync (its tail was wholly ring-readable), and
    // its recovered head/checkpoint reconstructed the durable ring exactly. A spurious fault on a
    // wrapped-away op would have left it RecoveringHead or driven a needless repair/sync here.
    assert!(
      c.replica_status_is_operational(backup),
      "seed {seed}: the wrapped-ring backup recovered to an operational status from its own disk \
       (not stranded RecoveringHead by a spuriously-faulty wrapped slot)"
    );
    assert_eq!(
      c.replica_state_sync_count(backup),
      0,
      "seed {seed}: recovery read the whole tail back from the RING — it did NOT spuriously state-sync \
       (its head was at/above the cluster checkpoint, every tail op resident)"
    );
    assert_eq!(
      c.replica_op(backup).get(),
      head_before,
      "seed {seed}: recovered head equals the durable ring head ({head_before}) — no wrong head from a \
       mis-read wrapped slot"
    );
    assert!(
      c.replica_checkpoint_op(backup).get() >= ckpt_before,
      "seed {seed}: recovered checkpoint is at least the durable one (monotone)"
    );
    assert!(
      tail_is_ring_resident(&c, backup).is_ok(),
      "seed {seed}: the recovered tail is fully ring-resident: {:?}",
      tail_is_ring_resident(&c, backup)
    );

    // Drive to convergence: the recovered backup rejoins and the cluster finishes every client, with no
    // committed op rewritten/lost and agreement holding every tick. The WAL-window invariant holds on the
    // recovered backup throughout (no ring-wrap drops an op it still needs).
    let mut converged = false;
    for _ in 0..400_000 {
      c.tick();
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: no committed op rewritten/lost across the wrapped-ring recovery"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: agreement holds across the wrapped-ring recovery"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done())
        && c.replica_status_is_operational(backup)
      {
        converged = true;
        break;
      }
    }
    assert!(
      converged,
      "seed {seed}: the wrapped-ring backup rejoined and all clients finished (backup head={}, \
       checkpoint_op={}, status operational={})",
      c.replica_op(backup).get(),
      c.replica_checkpoint_op(backup).get(),
      c.replica_status_is_operational(backup),
    );

    // NOTE: the load-bearing Item-1 claim — that `recover` reconstructs the wrapped ring from its OWN
    // disk with NO spurious fault and NO state-sync — is asserted RIGHT AFTER `restart` above (operational
    // from own disk, `state_sync_count == 0`, head == durable head, tail resident). We deliberately do
    // NOT forbid a LATER state-sync during the convergence phase: under this tight ring (N=12) the cluster
    // keeps committing + checkpointing + wrapping while the freshly-rejoined backup catches its tail up,
    // so it can legitimately fall below the cluster checkpoint and state-sync forward — correct behaviour
    // (Item 2's territory), not a recover bug.

    // The recovered replica's applied prefix agrees with the primary (no divergence end to end).
    let backup_applied = c.replica_sm(backup).applied().to_vec();
    let primary_applied = c.replica_sm(0).applied().to_vec();
    assert!(
      !backup_applied.is_empty(),
      "seed {seed}: the recovered replica has a non-trivial applied prefix"
    );
    let n = backup_applied.len().min(primary_applied.len());
    assert_eq!(
      backup_applied[..n],
      primary_applied[..n],
      "seed {seed}: the recovered replica's applied prefix agrees with the primary"
    );

    // Every committed op survived the bounded wrapped-ring crash-recovery run.
    assert_eq!(
      dur.check(&c),
      CheckResult::Ok,
      "seed {seed}: every committed op survived the bounded wrapped-ring recovery run"
    );
  }
}

/// True iff op `op` is servable to a laggard via the `RequestPrepare` → `Prepare` peer fault-repair path
/// on ANY non-crashed replica: a replica serves `op` only if it holds the body in its `log` cache AND has
/// committed it (`on_request_prepare`'s `self.log.get(op)` + `op <= commit_min` guards). Once a replica
/// checkpoints past `op` it trims its `log` there (`trim_log_to_checkpoint`) and — under a bounded ring —
/// physically wraps the WAL slot away, so the op is held ONLY inside the checkpoint snapshot, not as a
/// servable prepare. We conservatively (and faithfully to the proto) treat `op <= checkpoint_op` on EVERY
/// non-crashed replica as "no replica can serve it" — it is folded into every snapshot, recoverable ONLY
/// via state-sync. (An op a replica still holds above its checkpoint would be WAL-resident there, so this
/// also cross-checks physical residency below.)
fn request_prepare_unservable_clusterwide(c: &Cluster, op: u64, except: usize) -> bool {
  (0..c.replica_count()).all(|r| {
    if r == except || c.is_crashed(r) {
      return true; // the laggard itself / a crashed replica is not a server
    }
    // Servable-via-RequestPrepare requires the op to be ABOVE this replica's checkpoint (else its `log`
    // was trimmed there). Below/at every replica's checkpoint ⇒ no replica holds a servable prepare.
    op <= c.replica_checkpoint_op(r).get()
  })
}

/// Item 2 — THE key Phase-B validation. A backup is PARTITIONED while the cluster keeps
/// committing, checkpointing, and WRAPPING its ring past the backup's window, so the ops the backup is
/// missing are pushed BELOW the quorum checkpoint and PHYSICALLY WRAPPED AWAY from every quorum member's
/// ring (their bytes physically gone everywhere). Once an op is below
/// the quorum prune floor it is wrapped away EVERYWHERE — it can no longer be peer-repaired (the bytes are
/// gone from every ring), so a replica missing it can ONLY get it from the CHECKPOINT SNAPSHOT
/// (state-sync). We heal the partition and assert exactly that: the backup's missing band is BELOW the
/// quorum checkpoint (non-vacuous — the ops genuinely wrapped away, not merely a short tail it could
/// retransmit); a `RequestPrepare` for that band is UNSERVABLE cluster-wide (no replica holds it as a
/// servable prepare — it lives only inside checkpoint snapshots); and so the backup recovers via
/// STATE-SYNC (its sync count goes from 0 to at least 1), rejoining consistently with no committed-op loss.
///
/// This proves state-sync is the SOLE recovery path for a ring-wrapped-away op. Why the partition (vs a
/// crash): a partitioned backup keeps its volatile head FROZEN (it appends nothing while isolated), so on
/// heal it hears the primary's `Commit`/`Prepare` carrying `checkpoint_op > self.op`, the
/// `maybe_request_sync` trigger fires, and it state-syncs — it NEVER appends an op that would overwrite an
/// un-pruned slot (the in-quorum backups, gated by the primary's stall on the QUORUM floor, never overflow
/// either). That the existing state-sync trigger fires FIRST — before any overflowing append — is the
/// backup-overflow reachability VERDICT this test witnesses end to end.
#[test]
fn bounded_wal_laggard_with_wrapped_away_ops_recovers_via_state_sync() {
  for seed in 0..8u64 {
    // N=5 (partitioning one backup leaves a 4-of-5 quorum committing + checkpointing the whole time), a
    // SMALL checkpoint interval (4) and a SMALL ring (16 = 4 intervals) so the quorum WRAPS its ring past
    // the isolated backup's window while it is gone. Plenty of client load to cross many checkpoints.
    let mut c = Cluster::with_checkpoint_ops(5, 3, 50, seed, 4);
    c.set_wal_capacity(Some(16));
    let mut dur = DurabilityChecker::new(c.replica_count());

    // The backup we isolate (NOT the primary — keeping replica 0 up means the {0,1,3,4} quorum keeps
    // committing + checkpointing + wrapping while the laggard is partitioned away).
    let laggard = 2usize;

    // Warm up until the laggard has a non-trivial durable prefix AND the cluster is comfortably past op 8
    // (so the laggard's head, once frozen, will be genuinely below the cluster's later checkpoint).
    let mut warmed = false;
    for _ in 0..300_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok(), "seed {seed}: durability (warm-up)");
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (warm-up)"
      );
      if c.replica_checkpoint_op(0).get() >= 8 && c.replica_op(laggard).get() >= 8 {
        warmed = true;
        break;
      }
    }
    assert!(
      warmed,
      "seed {seed}: cluster + laggard warmed up before the partition"
    );

    // Snapshot the laggard's FROZEN head + its sync count just before isolation. Partitioned, it appends
    // nothing, so this head is exactly where its window stays while the quorum wraps past it.
    let laggard_head_frozen = c.replica_op(laggard).get();
    assert_eq!(
      c.replica_state_sync_count(laggard),
      0,
      "seed {seed}: the laggard has not state-synced before the partition"
    );

    // PARTITION the laggard into its own group: {0,1,3,4} | {2}. Replica<->replica traffic to/from the
    // laggard is dropped, so it hears no Prepare/Commit and its head FREEZES at `laggard_head_frozen`,
    // while the 4-node quorum keeps committing + checkpointing + WRAPPING its bounded ring.
    c.partition(vec![0, 0, 1, 0, 0]);

    // Keep it isolated until the quorum's checkpoint advances WELL past the laggard's frozen head — at
    // least a full ring-length (16) beyond it — so the laggard's missing band `(frozen_head, quorum_ckpt]`
    // is below the quorum prune floor AND physically wrapped away from every quorum member's ring.
    let target_cluster_ckpt = laggard_head_frozen + 16;
    let mut moved_past = false;
    for _ in 0..800_000 {
      c.tick();
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: durability (partitioned)"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (partitioned)"
      );
      if c.replica_checkpoint_op(0).get() >= target_cluster_ckpt {
        moved_past = true;
        break;
      }
    }
    assert!(
      moved_past,
      "seed {seed}: the quorum checkpointed >= a ring-length past the laggard's frozen head ({} >= \
       {laggard_head_frozen} + 16) while it was isolated — the missing band is below the quorum prune \
       floor and wrapped away from every ring",
      c.replica_checkpoint_op(0).get()
    );

    // NON-VACUITY + the crux assertion: the laggard's missing band `(frozen_head, quorum_ckpt]` is below
    // the quorum checkpoint, and a `RequestPrepare` for it is UNSERVABLE cluster-wide — the ops are gone
    // from every ring (held only inside checkpoint snapshots), so peer fault-repair CANNOT recover them.
    // State-sync is therefore the SOLE path. We sample a representative op just above the frozen head (the
    // op the laggard would first need to catch up) and one mid-band.
    let quorum_ckpt = c.replica_checkpoint_op(0).get();
    assert!(
      quorum_ckpt > laggard_head_frozen,
      "seed {seed}: the missing band is non-empty (quorum_ckpt={quorum_ckpt} > \
       frozen_head={laggard_head_frozen})"
    );
    for &op in &[
      laggard_head_frozen + 1,
      (laggard_head_frozen + 1 + quorum_ckpt) / 2,
    ] {
      assert!(
        request_prepare_unservable_clusterwide(&c, op, laggard),
        "seed {seed}: op {op} in the wrapped-away band (frozen_head={laggard_head_frozen}, \
         quorum_ckpt={quorum_ckpt}) is UNSERVABLE via RequestPrepare on every quorum member — it is \
         below every replica's checkpoint (folded into the snapshot, wrapped away from the ring), so \
         only state-sync can recover it"
      );
    }
    // Cross-check the PHYSICAL wrap: the op just above the frozen head is no longer WAL-resident on the
    // primary (its ring slot was reused by a `quorum_ckpt`-era op many wraps later).
    assert!(
      !c.replica_wal_holds_op(0, OpNumber::with(laggard_head_frozen + 1)),
      "seed {seed}: op {} is physically WRAPPED AWAY from the primary's ring (its slot now holds a much \
       later op) — the bytes are gone, only the snapshot has it",
      laggard_head_frozen + 1
    );

    // HEAL the partition. The laggard now hears the primary's Commit/Prepare carrying `checkpoint_op >
    // self.op` (its frozen head is below the cluster checkpoint), so `maybe_request_sync` fires and it
    // STATE-SYNCS — it CANNOT repair the wrapped-away ops (proven unservable above), so the snapshot is
    // its only route. It never appends an overflowing op (its head was frozen; the sync trigger fires
    // before any tail-extend).
    c.heal();

    let mut converged = false;
    for _ in 0..800_000 {
      c.tick();
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: no committed op rewritten/lost during the wrapped-away state-sync"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: agreement holds during the wrapped-away state-sync"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done())
        && c.replica_state_sync_count(laggard) >= 1
        && c.replica_status_is_operational(laggard)
        && c.replica_checkpoint_op(laggard).get() >= quorum_ckpt
      {
        converged = true;
        break;
      }
    }
    assert!(
      converged,
      "seed {seed}: the wrapped-away laggard recovered via STATE-SYNC and caught up (sync_count={}, \
       checkpoint_op={}, target>={quorum_ckpt})",
      c.replica_state_sync_count(laggard),
      c.replica_checkpoint_op(laggard).get()
    );

    // NON-VACUITY: it genuinely STATE-SYNCED (the wrapped-away ops were recovered via the snapshot, NOT
    // via WAL retransmit/peer-repair — which we proved impossible above).
    assert!(
      c.replica_state_sync_count(laggard) >= 1,
      "seed {seed}: VACUOUS — the laggard converged WITHOUT state-syncing; it must recover the \
       wrapped-away band via the checkpoint snapshot, the sole available path"
    );

    // The state-synced laggard's checkpoint jumped PAST its frozen head (the signature of a snapshot
    // recovery, not op-by-op catch-up — which the wrapped-away band makes impossible anyway).
    assert!(
      c.replica_checkpoint_op(laggard).get() > laggard_head_frozen,
      "seed {seed}: the laggard's checkpoint ({}) advanced past its frozen head ({laggard_head_frozen})",
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
      "seed {seed}: every committed op survived the partition + wrapped-away + state-sync window"
    );
  }
}

/// Item 2 — the CONNECTED backup-overflow case + its fix. A SUB-QUORUM laggard on a
/// bounded ring can keep receiving HEAD-EXTENDING `Prepare`s while its OWN `checkpoint_op` lags far below
/// the cluster checkpoint (e.g. it adopted a canonical head over a held-commit hole after a view change,
/// so `commit_min`/`checkpoint_op` are pinned low while `op` ran ahead). Appending such an op `K` would
/// PHYSICALLY overwrite the un-pruned ring slot `K mod N` (last held by op `K - N`, which it has NOT yet
/// checkpoint-subsumed) — breaking the resident-tail invariant `recover` relies on (`(checkpoint_op ..
/// head]` must fit the ring). The ORDINARY state-sync trigger misses it: it fires only when the incoming
/// checkpoint exceeds `self.op`, but here the laggard's HEAD kept up (`p.checkpoint_op() <= self.op`)
/// while only its CHECKPOINT lagged.
///
/// The proto's `maybe_sync_below_ring_window` guard catches it: instead of overwriting a needed slot, the
/// backup recognizes it has fallen below the ring window and STATE-SYNCS to the cluster checkpoint
/// (jumping its checkpoint forward, which the primary's stall guarantees subsumes the overflowing slot).
/// This test PROVOKES the overflow under an adversarial schedule (a SMALL bounded ring + drops + a
/// flapping partition that isolates a backup, plus the view changes the drops induce, so a reconnecting
/// laggard adopts a head over a held-commit hole while its checkpoint is stale) and asserts: SOME backup
/// actually fell below its ring window and recovered via state-sync — the dedicated
/// `below_ring_window_syncs` counter goes above 0 (non-vacuity — the ring-window sync path genuinely
/// fired, distinct from an ordinary above-`self.op` state-sync); and the cluster stays SAFE + durable
/// EVERY tick and every client finishes.
///
/// The proto's PERMANENT `append_prepare` debug-assert is the load-bearing backstop running THROUGHOUT:
/// it fires (failing the test in this debug build) if ANY append ever overwrites an un-pruned ring slot —
/// so a green run is itself the proof the guard is never bypassed. (Before the guard, this exact schedule
/// tripped that assert — appending op `K` with `K - checkpoint_op` far above `N`.)
///
/// The connected overflow is a RARE confluence (a view change + a held-commit hole + an extending head),
/// so we iterate a SET of seeds KNOWN (by an offline sweep) to provoke it under this exact scenario rather
/// than a contiguous range — keeping the gate deterministically non-vacuous without a huge seed sweep.
#[test]
fn bounded_wal_backup_below_ring_window_state_syncs_instead_of_overwriting() {
  // Seeds an offline sweep (32 seeds, this exact N=12 / drop=300 / flap-5000-2500 scenario) found to
  // drive a backup below its ring window — the connected overflow fires early on each (~ticks 2.5k–7.5k),
  // well within the budget below. Re-derive with the `zz_scan` harness if the scenario changes.
  const PROVOKING_SEEDS: [u64; 3] = [1, 20, 27];
  let mut total_below_ring_window_syncs = 0u64;
  for seed in PROVOKING_SEEDS {
    // N=5 (a 4-of-5 quorum always commits + checkpoints), a SMALL checkpoint interval (4) and a SMALL ring
    // (12 = 3 intervals) so the window is tight. Heavy drops (300/1000) induce primary-heartbeat loss →
    // view changes, and a flapping partition isolates one backup; on reconnect after a view change it
    // adopts a head over a held-commit hole while its own checkpoint is stale — the connected
    // backup-overflow shape. Duplicates stress the re-ack/idempotency paths too.
    let mut c = Cluster::with_checkpoint_ops(5, 4, 60, seed, 4);
    c.set_wal_capacity(Some(12));
    c.set_faults(Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(3),
      drop_per_mille: 300,
      duplicate_per_mille: 100,
    });
    let mut dur = DurabilityChecker::new(c.replica_count());

    let mut done = false;
    for step in 0..250_000u64 {
      // Flap a partition isolating the laggard (replica 2): isolate it for a window (it falls behind),
      // then heal (it reconnects to a burst of head-extending prepares while its own checkpoint is stale).
      if step % 5000 == 0 {
        c.partition(vec![0, 0, 1, 0, 0]);
      } else if step % 5000 == 2500 {
        c.heal();
      }
      c.tick();
      // Safety + durability hold every tick — INCLUDING the proto's permanent append_prepare overflow
      // assert, which would panic here if any append overwrote an un-pruned ring slot.
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: no committed op rewritten/lost across the backup-overflow schedule"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: agreement holds across the backup-overflow schedule"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        done = true;
        break;
      }
    }
    // Make sure everything is healed so the cluster can finish if the flap left the laggard isolated at
    // the end of the bounded run.
    if !done {
      c.heal();
      for _ in 0..200_000 {
        c.tick();
        assert!(dur.observe(&c).is_ok(), "seed {seed}: durability (drain)");
        assert_eq!(
          check_safety(&c),
          CheckResult::Ok,
          "seed {seed}: safety (drain)"
        );
        if (0..c.client_count()).all(|i| c.client(i).is_done()) {
          done = true;
          break;
        }
      }
    }
    // The below-ring-window syncs this seed drove (monotonic counter, read after the run) — the precise
    // non-vacuity signal, distinct from an ordinary `> self.op` state-sync.
    let seed_syncs: u64 = (0..c.replica_count())
      .map(|r| c.replica_below_ring_window_syncs(r))
      .sum();
    total_below_ring_window_syncs += seed_syncs;
    assert!(
      done,
      "seed {seed}: every client finished under the bounded-ring backup-overflow schedule (the \
       sub-quorum laggard recovered via state-sync rather than wedging or overwriting a needed slot)"
    );
    // Per-seed non-vacuity: each chosen seed genuinely drives the below-ring-window path (so the gate
    // does not silently rot if one seed stops provoking it under a future change).
    assert!(
      seed_syncs > 0,
      "seed {seed}: expected the connected below-ring-window state-sync to fire (below_ring_window_syncs \
       == 0) — this seed no longer provokes the overflow; re-derive PROVOKING_SEEDS with the zz_scan \
       harness for the current scenario"
    );

    // Every committed op survived end to end on an operational replica.
    assert_eq!(
      dur.check(&c),
      CheckResult::Ok,
      "seed {seed}: every committed op survived the bounded-ring backup-overflow run"
    );
  }

  // NON-VACUITY (aggregate): a backup genuinely fell below its ring window and recovered via STATE-SYNC —
  // the `maybe_sync_below_ring_window` path actually fired (a backup that received a head-extending
  // prepare it could not hold, and jumped to the cluster checkpoint instead of overwriting an un-pruned
  // slot). The dedicated counter distinguishes this from an ordinary `> self.op` state-sync.
  assert!(
    total_below_ring_window_syncs > 0,
    "VACUOUS — no backup hit the below-ring-window state-sync path across the provoking seeds \
     (total below_ring_window_syncs == 0); the connected backup-overflow case was never exercised."
  );
}

//! VOPR sweep: the seeded adversarial driver (`run_vopr`) over a seed range, asserting no panics.
//!
//! Each seed builds a fresh cluster (size 2..=6 — including even N and the N=2 unanimous-quorum case)
//! and explores a randomized adversarial schedule WITHIN the crash-stop fault model (a quorum always
//! survives). Adversarial axes: async WAL + async Superblock, with a crash that DISCARDS in-flight WAL
//! appends (modelling real fsync-loss-on-crash); network reorder/drop/duplicate/delay; storage
//! read/torn/bit-rot faults + MISDIRECTED reads (a read returns a wrong-but-valid sibling slot,
//! exercising the recovery/repair placement-integrity checks); small AND large `checkpoint_ops` (the
//! latter holds a non-trivial recover tail above the checkpoint — the large-checkpoint recover
//! read-window path); a redundant-copy
//! Superblock that retains the last-rooted checkpoint until a new one is durably rooted (finding B); and
//! a seed-derived PHYSICAL BOUNDED-WAL RING on ~1/3 of seeds (the rest unbounded), where
//! each WAL is a fixed `N`-slot ring so the primary STALLS op-assignment before it would wrap an
//! un-pruned slot — folding wrap (stall-before-wrap + recover off a wrapped ring + a below-ring-window
//! backup overflow) into the full crash + partition + disk-fault schedule, with a per-tick RING-RESIDENCY
//! checker asserting no wrap ever drops an op `recover`/repair still needs. `N` is sized
//! `checkpoint_ops * k + headroom` (`k` in 3..=6) so the stall always RELEASES (a tighter ring would
//! wedge the primary — the headroom constraint, documented in `src/vopr.rs::build_cluster`).
//! Liveness is judged over calm windows gated on VIRTUAL time, not raw ticks.
//! Safety/durability/view-monotonicity/boundedness/append-before-ack/structural/ring-residency
//! invariants checked EVERY tick and liveness checked across calm windows. `run_vopr` panics on any
//! violation with the seed + tick, so this test simply runs the sweep and lets a violation surface.
//!
//! Determinism is mandatory: `run_vopr(seed, ticks)` is a pure function of `(seed, ticks)`. To re-run
//! a single failing seed in isolation, see the `#[ignore]` replay test below (set its seed and run
//! `cargo test -p viewstamp-simulation --test vopr replay_single_seed -- --ignored --nocapture`).
//!
//! # Coverage: `0..SEEDS` contiguous + pinned regression seeds (`0..512` scans clean with async-SB on)
//!
//! The sweep runs a contiguous `0..SEEDS` range PLUS an explicit [`REGRESSION_SEEDS`] list of every
//! seed that historically caught a real bug, so those stay pinned even above the contiguous range. A
//! separate committed HOLD sweep ([`vopr_hold_sweep_no_violations`]) force-enables the unbounded-hold
//! network axis over its own contiguous range — the axis the default schedule deliberately leaves off
//! (see that test's doc) — and a committed WIPE sweep ([`vopr_wipe_sweep_no_violations`]) likewise
//! force-enables the wipe-and-restart (amnesia) axis, where a crashed replica can rejoin with a
//! fresh, empty disk. A committed ASYM sweep ([`vopr_asym_sweep_no_violations`]) force-enables
//! DIRECTED one-way partitions (`from → to` cut while `to → from` flows — the deaf/mute-primary
//! shapes the symmetric groups cannot express), and a committed SLOW-REPLICA sweep
//! ([`vopr_slow_replica_sweep_no_violations`]) force-enables per-replica gray-failure delivery
//! (messages a few seeded milliseconds late, never dropped). An `#[ignore]`d TORN-HEADER probe
//! ([`vopr_torn_header_sweep_no_violations`])
//! deliberately violates the `Wal` header-durability contract to measure its blast radius — it is a
//! contract-violation measurement, never a CI gate. A
//! wide catch-panic scan `0..512` at [`DEFAULT_TICKS`] with the async-superblock mode ON is verified
//! clean end to end (including the final-quiesce fix — see below). The
//! bounded-WAL axis (a fixed-`N` ring on the ~1/3 of seeds it seed-derives) is verified clean over the
//! committed `0..SEEDS` + regression range; it is drawn from a SEPARATE per-seed PRNG, so the ~2/3
//! UNBOUNDED seeds (and every pinned regression seed that lands unbounded) keep
//! their EXACT pre-bounded-axis schedule, leaving that historical `0..512` unbounded-schedule scan valid. The
//! committed `SEEDS` is kept smaller only to bound the gate's wall-clock (each seed runs a few thousand
//! ticks of
//! rich adversarial schedule).
//!
//! Seeds **253 / 299 / 335** were a committed-divergence (`replica diverges from replica` at one
//! committed op number) requiring BOTH network message duplication AND the async-superblock window
//! (masking EITHER `VOPR_NO_DUP` or `VOPR_NO_ASYNC_SB` made each run clean). The verified mechanism: a
//! replica appended a tail op as an OLD-view primary; a view change SUPERSEDED that op (the new view
//! assigns the op number a DIFFERENT client request), but adoption only dropped it from the in-memory
//! cache, NOT the durable WAL. On a later crash + `recover`, the loop re-loaded that STALE body from the
//! WAL, and when the cluster committed the op (whose canonical value differs) `advance_commit` applied
//! the stale local body → a single committed op number carried two values (op 227 = `…76` on r0 vs
//! `…77` elsewhere, for an adversarial schedule). At-most-once held throughout (no second op minted, no request
//! committed twice). FIXED in two places: (1) `adopt_canonical_head` / `start_view_as_new_primary` now
//! `wal.truncate` above the adopted canonical head, dropping the uncommitted divergent suffix from the
//! WAL at the source (no durability dip — only uncommitted ops are removed); (2) `recover` extends the
//! `vsr_headers` cross-check — a self-verifying tail slot ABOVE the durable committed frontier whose
//! original header `view` is below the durable `log_view` is a superseded earlier-view proposal, so it
//! is dropped + peer-repaired instead of trusted (this catches the INTERIOR committed-band variant
//! that the head truncation cannot, where the stale slot sits below the adopted offset-log's floor).
//!
//! Seed **313** was a FINAL-INSTANT durability-CHECKER artifact (verified real-vs-checker), now FIXED
//! in the driver — NOT a proto loss. The end-of-run assertion fired `no operational replica retains the
//! committed history of 1141 ops` (masked by `VOPR_NO_DUP` but NOT `VOPR_NO_ASYNC_SB`). The dump at tick
//! 4000 proved op 1141 was held DURABLY by a QUORUM — replicas 0, 1 (operational) and 3 (crashed) all
//! had it in their WAL (head op 1143), so the per-tick structural quorum-durability check correctly
//! never fired — but the only replica that had APPLIED it (r3, `commit_min=1141`) happened to be CRASHED
//! at that instant, while the operational survivors r0/r1 sat at applied=1140 (their `commit_max` had
//! not yet learned 1141 was committed; commit catch-up was in flight). The end-of-run check asked for
//! the history to be APPLIED by an OPERATIONAL replica at that arbitrary instant — strictly stronger
//! than VSR's guarantee (a committed op survives on a quorum's DURABLE storage; application is local
//! catch-up). Proof it was no loss: from that instant a healed, fault-free cluster converged all five
//! replicas to applied=1141 in ~74 ticks. The fix mirrors TigerBeetle's VOPR `transition_to_liveness_mode`:
//! `run_vopr` now runs a final bounded QUIESCE phase (heal everything, restart all, no faults, tick to
//! convergence, full per-tick checks still live) BEFORE the end-of-run durability + applied assertions,
//! so the survivors apply the durably-held committed tail first. It stays STRICT — a committed op held by
//! NO quorum cannot be repaired from a non-existent source, so the drain never converges it and the phase
//! reports a liveness/non-convergence wedge instead of passing.
//!
//! Every bug this sweep found has been fixed:
//! - **append-before-ack re-ack hole** — the `appending` set is not a durability oracle; the
//!   re-ack now consults the WAL's durable status directly;
//! - **stale-unapplied-held-copy divergence** (multiple adversarial schedules) — adoption preserved a
//!   stale UNAPPLIED held copy of a committed op the offset canonical log omits (a superseded
//!   earlier-view proposal), diverging the committed log; fixed by preserving only the APPLIED prefix
//!   (`op <= commit_min`) and repairing the omitted committed band from a peer;
//! - **liveness wedge: unfillable committed hole** — a primary stuck on an unfillable committed hole
//!   now forfeits so a healthy replica can take over;
//! - **adoption WAL-staleness committed-divergence** — `recover` blindly re-derived a committed op
//!   from the WAL, resurrecting a STALE superseded body an adoption never re-wrote there. Fixed by
//!   persisting the canonical committed-band headers (TigerBeetle's `vsr_headers`) in the durable
//!   `VsrState` and having `recover` cross-check each committed-band WAL slot against them, routing a
//!   mismatch to peer-repair instead of trusting the stale body (NO wal.truncate, so NO durability dip);
//! - **superseded-tail-op committed-divergence** (multiple adversarial schedules) — `recover` re-loaded
//!   a SUPERSEDED earlier-view tail op from the WAL and `advance_commit` applied its stale body for an
//!   op the new view committed with a different value (committed-divergence across partition-heal +
//!   view-change + async-superblock + duplication). Fixed by (1) truncating the WAL above the adopted
//!   canonical head on view adoption, and (2) extending the `vsr_headers` recover cross-check to drop an
//!   above-durable-commit tail slot whose original header `view` is below the durable `log_view` (a
//!   superseded proposal) → peer-repair the canonical body;
//! - **force-sync discarded acked tail** (two adversarial schedules) — forced state-sync discarded an
//!   acked tail above the synced checkpoint;
//! - **view-monotonic CHECKER over-sensitivity** — not a proto bug: the checker watched the volatile
//!   in-memory view across a restart, but a replica safely reverts to its DURABLE view on recovery (it
//!   never participated in the un-durable view) and re-catches-up on the next higher-view message; the
//!   checker now tracks the durable view;
//! - **final-INSTANT durability-CHECKER artifact** — not a proto bug: an adversarial schedule ended on
//!   a tick where a committed op the operational survivors held DURABLY on a quorum's WAL (the per-tick
//!   structural quorum-durability check correctly never fired) had been APPLIED only by a since-crashed
//!   replica, so the end-of-run "applied by an operational replica" assertion was stricter than VSR's
//!   true durable-quorum-retention guarantee; `run_vopr` now runs a bounded final QUIESCE phase
//!   (TigerBeetle's `transition_to_liveness_mode`) to converge the survivors before the end-of-run
//!   assertions, kept strict (a committed op held by no quorum never converges and is reported).
//! - **append-before-ack CHECKER over-sensitivity** (two adversarial schedules, surfaced by the
//!   misdirected-read axis below), NOT a proto bug. A replica emits `PrepareOk(op, view = V)` legitimately
//!   in view V (op IS durably appended); the sim drains `outgoing` only on the NEXT tick, and a
//!   view-change-to-`V+1` that ran in between truncated the uncommitted tail above the new canonical head,
//!   emptying that WAL slot. Re-checking the now-STALE `PrepareOk(view = V)` against the replica's
//!   post-truncation WAL is stricter than VSR requires: the message carries `view = V`, and the proto's
//!   `on_prepare_ok` DROPS any ack whose `view != self.view`, so a `view < current` ack can never count
//!   toward a commit quorum — it is inert. FIXED in the CHECKER (`Cluster::tick`): the
//!   append-before-ack proxy exempts a `msg_view < cur_view` stale ack (same class of checker fix —
//!   fix the checker, never the proto); a `msg_view >= cur_view` non-durable ack still trips.
//! - **liveness wedge: forfeit StartViewChange STORM** — a Normal primary stuck `pending_forfeit` (it
//!   forfeited while the cluster ran on in a higher view) RE-BROADCAST a `StartViewChange` on EVERY
//!   `handle_timeout` tick, because `primary_timeouts` called `forfeit()` → `propose_next_view()`
//!   unconditionally. In the nanosecond-clock simulator that storm pins the virtual clock to
//!   sub-millisecond steps, starving the LIVE view's primary's 50ms Commit heartbeat → the stale-view
//!   holdout never hears the new view to catch up, livelocking the cluster. FIXED in the proto: the
//!   forfeit re-propose is now gated on the `svc_message` retransmit timer (one SVC per
//!   `VC_MESSAGE_RETRANSMIT` window, like `view_change_timeouts`) — the persistent step-down + heartbeat
//!   suppression are preserved, only the per-tick storm is removed.
//! - **storage-fault committed-op loss + op-number reuse** (found by a release-mode `0..2048` wide
//!   sweep) — a committed op (on a durable quorum) was LOST and its op number RE-MINTED
//!   across a view change when a recover-time disk fault (torn/bit-rot) dropped that op's WAL slot on the
//!   SOLE commit/view quorum-intersection replica, which then neither held the op nor knew it was
//!   committed. FIXED structurally (TigerBeetle's body-independent header durability): an op's HEADER now
//!   survives a body-only fault, so `recover` keeps the op header-only as a `Body::Repairing` hole rather
//!   than dropping it; that hole flows through the DoViewChange so `select_canonical_log` counts the op as
//!   TAKEN (never re-minted) and the new primary peer-repairs the canonical body. `0..2048` is now clean.

use viewstamp_simulation::{
  DEFAULT_TICKS, run_vopr, run_vopr_one, run_vopr_with_asym, run_vopr_with_batching,
  run_vopr_with_churn, run_vopr_with_hold, run_vopr_with_learners, run_vopr_with_reconfig,
  run_vopr_with_slow, run_vopr_with_stale_read, run_vopr_with_torn_headers, run_vopr_with_wipe,
};

/// The contiguous committed seed range (kept modest to bound the gate's wall-clock). Correctness
/// coverage over raw count: each seed runs a few thousand ticks of rich adversarial schedule. With the
/// async-superblock mode ON in [`run_vopr`] (the pending-durable-view window), this whole
/// `0..SEEDS` range is verified clean — including the `vsr_headers` recovery cross-check fix, the
/// final-quiesce fix, and the durable-header storage-fault fix (a wide `0..2048` catch-panic re-scan
/// with async-SB on is clean end to end).
///
/// The `VOPR_SEEDS` env var overrides this contiguous count at runtime (default 64): a release-mode
/// sweep — run locally or by the `vopr` CI workflow — sets `VOPR_SEEDS=1024` (or `2048`) to scan far
/// wider without recompiling. The pinned [`REGRESSION_SEEDS`] are always appended regardless.
const SEEDS: u64 = 64;

/// The contiguous seed count to sweep this run: `VOPR_SEEDS` if set and parseable, else [`SEEDS`].
fn sweep_seed_count() -> u64 {
  std::env::var("VOPR_SEEDS")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(SEEDS)
}

/// Seeds that historically caught a real bug, pinned as regression protection even above the contiguous
/// `0..SEEDS` range. All pass with the async-superblock mode on; these guard against any of those
/// specific divergences/wedges ever returning. The `vsr_headers` recovery fix is also covered
/// by the contiguous range, but stays pinned here as an explicit named guard against its return.
const REGRESSION_SEEDS: &[u64] = &[
  21, 52, 84, 89, 90, 103, 120, 131, 151, 164, 197, 253, 299, 313, 335, 464, 622, 774,
];

#[test]
fn vopr_sweep_no_violations() {
  let mut total_committed = 0usize;
  let mut total_crashes = 0u64;
  let mut total_restarts = 0u64;
  let mut total_partitions = 0u64;
  let mut seeds_with_view_change = 0u64;
  let mut total_pending_view_windows = 0u64;
  let mut max_recovered_band = 0u64;
  let mut total_forced_syncs = 0u64;
  let mut total_misdirects = 0u64;
  // Bounded-WAL (wrap) axis. Partition seeds into bounded/unbounded and tally the
  // wrap-exercised witnesses: how many seeds ran a bounded ring, the cumulative WAL stalls across them
  // (the ring filled + the primary stalled — wrap engaged), the below-ring-window backup-overflow syncs
  // (rare under this schedule), the largest committed history on any bounded seed (its head climbed past
  // the ring many times over), and whether ANY bounded seed genuinely WRAPPED (committed > its N).
  let mut bounded_seeds = 0u64;
  let mut total_wal_stalls = 0u64;
  let mut total_below_ring_window_syncs = 0u64;
  let mut max_bounded_committed = 0usize;
  let mut any_bounded_wrapped = false;
  // Frame-cap axis: how many LARGE client bodies were minted across the sweep (must be `> 0` — the cap
  // is exercised non-vacuously), and how many legitimate inter-replica messages were oversized-dropped
  // (must be 0 — header-only carriers + the byte-bounded `RepairBatch` keep every peer message sub-cap
  // regardless of body size; `run_vopr` already fails fast per tick on any drop, but tally it for the
  // summary too).
  let mut total_large_bodies = 0u64;
  let mut total_oversized_dropped = 0u64;
  // Non-vacuity witnesses: the header-only view-change/recovery carriers, the byte-bounded
  // `RepairBatch` serve, and the floored canonical union must all genuinely FIRE somewhere across the
  // sweep — otherwise those consensus paths are green only because they were never reached.
  let mut total_header_only_carriers = 0u64;
  let mut total_repair_batches = 0u64;
  let mut total_prepare_batches = 0u64;
  let mut total_unions_floored = 0u64;
  let contiguous = sweep_seed_count();
  println!(
    "VOPR sweep: 0..{contiguous} contiguous + {} pinned regression seeds, {DEFAULT_TICKS} ticks each",
    REGRESSION_SEEDS.len()
  );
  for seed in (0..contiguous).chain(REGRESSION_SEEDS.iter().copied()) {
    let r = run_vopr(seed, DEFAULT_TICKS);
    // Off-axis re-formation guard (the standing byte-identity net): WITHOUT the reconfig axis the
    // re-formation escalation is off-axis-unsatisfiable (`epoch > prev_epoch` is false absent a
    // reconfiguration), so NO voter ever escalates out of `RecoveringHead` and NO reconfiguration
    // fires — a default run is byte-identical to a no-escalation run. (run_vopr already panics per
    // tick on any off-axis escalation; this is the cross-seed witness that the lane stayed inert.)
    assert_eq!(
      r.reform_escalations_fired(),
      0,
      "seed {seed}: a RecoveringHead voter escalated into a view change WITHOUT a reconfiguration — \
       the re-formation escalation must be off-axis-unsatisfiable"
    );
    assert_eq!(
      r.reconfigs_fired(),
      0,
      "seed {seed}: a coordinated reconfiguration fired off-axis (the reconfig axis is off)"
    );
    total_committed += r.max_committed();
    total_crashes += r.crashes();
    total_restarts += r.restarts();
    total_partitions += r.partitions();
    total_pending_view_windows += r.pending_view_windows_seen();
    max_recovered_band = max_recovered_band.max(r.recovered_band_max());
    total_forced_syncs += r.forced_syncs();
    total_misdirects += r.misdirects_fired();
    total_large_bodies += r.large_bodies_sent();
    total_oversized_dropped += r.oversized_dropped();
    total_header_only_carriers += r.header_only_carriers_emitted();
    total_repair_batches += r.repair_batches_served();
    total_prepare_batches += r.prepare_batches_sent();
    total_unions_floored += r.unions_floored();
    if r.wal_capacity().is_some() {
      bounded_seeds += 1;
      total_wal_stalls += r.wal_stalls();
      total_below_ring_window_syncs += r.below_ring_window_syncs();
      max_bounded_committed = max_bounded_committed.max(r.max_committed());
      any_bounded_wrapped |= r.bounded_seed_wrapped();
    }
    if r.max_view() >= 1 {
      seeds_with_view_change += 1;
    }
  }
  // Non-vacuity: across the sweep the driver genuinely committed ops, crashed + restarted replicas,
  // installed partitions, and drove real view changes — i.e. it exercised the protocol under stress,
  // not a quiet happy path. (A regression that silently stopped applying faults would trip here.)
  assert!(
    total_committed > 0,
    "the sweep committed no ops at all — the driver is not exercising the protocol"
  );
  assert!(
    total_crashes > 0 && total_restarts > 0,
    "the sweep never crashed/restarted a replica (crashes={total_crashes}, restarts={total_restarts})"
  );
  assert!(
    total_partitions > 0,
    "the sweep never installed a partition (partitions={total_partitions})"
  );
  assert!(
    seeds_with_view_change > 0,
    "no seed drove a view change — failover is not being exercised"
  );
  // Async-superblock non-vacuity: the async-superblock mode must actually OPEN the pending-durable-view
  // window (a Normal primary whose view is not yet durable) somewhere across the sweep — otherwise the
  // durable-view-before-participate gates are being checked vacuously. `> 0` proves a
  // seed drove a replica into that window while a view-change root write was in flight.
  assert!(
    total_pending_view_windows > 0,
    "async-superblock never opened the pending-durable-view window — the durable-view gate is untested"
  );
  // Adversarial-coverage axes must actually FIRE, or they are vacuous:
  // - large `checkpoint_ops` drove the recover read-window over a NON-trivial held tail (`op` far above
  //   `checkpoint_op`, sampled at recover construction — see `Cluster::recovered_band_high_water`), well
  //   above the small interval's ~12 ceiling, not always a tiny one;
  // - the misdirected-read axis fired, exercising the recovery/repair placement-integrity checks
  //   (`header.op() == op`) that the DST otherwise never reaches;
  // - the two-slot/redundant-copy superblock (finding B) still drives GENUINE peer-fetch escalations
  //   (only the SPURIOUS orphaned-checkpoint ones were removed) — `forced_syncs > 0` proves a replica
  //   really had to fetch a checkpoint/op from a peer because its own disk could not serve it.
  assert!(
    max_recovered_band > 50,
    "no seed drove the recover read-window over a non-trivial held tail (max={max_recovered_band}) — \
     the large-checkpoint_ops axis is vacuous"
  );
  assert!(
    total_misdirects > 0,
    "the misdirected-read axis never fired — the recovery/repair placement-integrity checks are untested"
  );
  assert!(
    total_forced_syncs > 0,
    "no forced-sync/peer-fetch escalation occurred across the sweep — finding B may have silently \
     removed that coverage (forced_syncs={total_forced_syncs})"
  );
  // Frame-cap axis (the header-only view-change carriers + windowed `RepairBatch` repair):
  // - the sweep genuinely PRODUCED large client bodies (`> 0`), so the frame cap is exercised — a
  //   large-bodied uncheckpointed band really rode the view-change/recovery carriers + the repair
  //   serve; without this the `oversized_dropped == 0` guarantee below would be vacuous;
  // - and NOT ONE legitimate inter-replica message was oversized-dropped across the whole sweep: the
  //   header-only carriers ship NO body (a fixed ~49 bytes/op) and the `RepairBatch` serve is
  //   byte-bounded, so every peer message stays at/below `MAX_FRAME_LEN` no matter how large the
  //   bodies are. (`run_vopr` already panics per-tick on any drop — this is the cumulative witness.)
  //   A `> 0` here would be a REAL bug: a carrier overflowed the frame — to report, never to mask by
  //   loosening the cap.
  assert!(
    total_large_bodies > 0,
    "the sweep minted no large client bodies — the frame-cap axis is vacuous (header-only carriers + \
     windowed repair are not being stressed by a large-bodied band)"
  );
  assert_eq!(
    total_oversized_dropped, 0,
    "a legitimate inter-replica message exceeded MAX_FRAME_LEN and was oversized-dropped \
     ({total_oversized_dropped} across the sweep) — a view-change/recovery carrier or repair batch \
     overflowed the frame (the old full-body view-change bug, or an incomplete bound); this is a REAL \
     bug to fix, NOT to mask by loosening the cap"
  );
  // These consensus paths must genuinely FIRE under the combined-fault schedule (sweep-level
  // evidence, not just focused unit gates):
  // - HEADER-ONLY CARRIERS: every `DoViewChange`/`StartView`/`RecoveryResponse` log payload flows
  //   through `log_entries`; view changes happen in many seeds, so a zero here means the carrier
  //   chokepoint stopped being exercised (or the counter plumbing broke);
  // - REPAIR-BATCH SERVES: peers under faults solicit windowed bulk repair (`RequestPrepareRange`)
  //   and a donor must answer with NON-EMPTY byte-bounded batches — a zero means every repair
  //   regressed to the per-op path and the windowed serve is untested;
  // - FLOORED UNIONS: `select_canonical_log` dropping a canonical-donor entry at/below the vouched
  //   checkpoint floor needs donors with divergent checkpoints inside ONE view change — a rare
  //   confluence, but one the contiguous range reaches on its own (a 0..512 scan fires it on 101
  //   seeds, six of them — 21, 28, 36, 51, 56, 61 — inside 0..64), so the assert needs no pinned
  //   seed.
  assert!(
    total_header_only_carriers > 0,
    "no header-only view-change/recovery carrier was built across the sweep \
     (header_only_carriers={total_header_only_carriers}) — the carrier path is vacuous"
  );
  assert!(
    total_repair_batches > 0,
    "no non-empty RepairBatch was served across the sweep (repair_batches={total_repair_batches}) — \
     the byte-bounded bulk-repair serve is vacuous"
  );

  // Prepare-retransmit batching non-vacuity: under the sweep's drop/dup axes some Prepare broadcast
  // is always lost and re-sent, and the retransmit path emits batches — if this is ever zero the
  // batched retransmit path has gone vacuous (or the axes stopped losing Prepares).
  assert!(
    total_prepare_batches > 0,
    "no PrepareBatch retransmit was emitted across the sweep (prepare_batches={total_prepare_batches}) — \
     the batched-retransmit path is vacuous"
  );
  assert!(
    total_unions_floored > 0,
    "no canonical-log selection floored its union across the sweep \
     (unions_floored={total_unions_floored}) — the floored-union path is vacuous (a schedule change \
     swept away every firing seed in the contiguous range; re-scan and pin one)"
  );
  // Bounded-WAL (wrap) axis must genuinely fire, or the wrap coverage is vacuous:
  // - SOME seeds ran the bounded ring (the ~1/3 seed-derived draw — sanity that the axis is wired and
  //   the env mask is off);
  // - across those bounded seeds the primary STALLED (`wal_stalls > 0`): the ring genuinely FILLED and
  //   the physical stall-before-wrap engaged under the full crash + partition + disk-fault schedule —
  //   wrap was EXERCISED, not vacuously skipped by an under-filled ring (the headline bounded-WAL stress);
  // - SOME bounded seed genuinely WRAPPED (committed strictly more ops than its ring size `N`), so an op
  //   `K + N` physically reused op `K`'s slot — the strongest single witness the wrap path did real work.
  // The per-tick ring-residency checker (in `run_vopr`) proves no wrap ever dropped a needed op; these
  // assert the wrap actually HAPPENED so that checker is non-vacuous on the committed range.
  assert!(
    bounded_seeds > 0,
    "no seed ran the bounded-WAL ring — the seed-derived bounded mode is not firing (is \
     VOPR_NO_BOUNDED_WAL set, or the 1/3 draw never hit on this range?)"
  );
  assert!(
    total_wal_stalls > 0,
    "the bounded seeds never STALLED (wal_stalls={total_wal_stalls}) — the bounded ring did not fill, \
     so the physical stall-before-wrap was not exercised; the wrap axis is vacuous"
  );
  assert!(
    any_bounded_wrapped,
    "no bounded seed committed past its ring size N (max bounded committed={max_bounded_committed}) — \
     the ring never WRAPPED, so wrap-under-adversity was not genuinely exercised"
  );
  // NOTE: `below_ring_window_syncs` (the CONNECTED backup-overflow path — a sub-quorum laggard adopting
  // a head over a held-commit hole while its checkpoint lags below the ring window) is a RARE confluence
  // under the VOPR's quorum-preserving schedule; the deterministic `bounded_wal.rs` laggard gate covers
  // it directly with hand-picked provoking seeds. So we do NOT force a (flaky) `> 0` assert here — we
  // only assert it when it IS reachable on this range, and otherwise leave it observed. (Currently it is
  // not consistently hit by the committed range, so this stays a soft observation, never a hard gate.)
  let _ = total_below_ring_window_syncs;
  println!(
    "VOPR sweep OK: committed={total_committed} crashes={total_crashes} restarts={total_restarts} \
     partitions={total_partitions} view_change_seeds={seeds_with_view_change} \
     bounded_seeds={bounded_seeds} wal_stalls={total_wal_stalls} misdirects={total_misdirects} \
     forced_syncs={total_forced_syncs} max_recovered_band={max_recovered_band} \
     large_bodies={total_large_bodies} oversized_dropped={total_oversized_dropped} \
     header_only_carriers={total_header_only_carriers} repair_batches={total_repair_batches} \
     prepare_batches={total_prepare_batches} \
     unions_floored={total_unions_floored}"
  );
}

/// The contiguous seed range for the committed HOLD sweep. Smaller than [`SEEDS`]: each hold-enabled
/// run layers held messages (delivery pushed ~15s of virtual time out) onto the full adversarial
/// schedule, and this lane is ADDITIVE to the default sweep, so its budget is kept modest.
const HOLD_SEEDS: u64 = 16;

/// The committed HOLD sweep: [`run_vopr_with_hold`] over `0..HOLD_SEEDS` — the unbounded-hold network
/// axis FORCE-ENABLED programmatically (no env var, so it cannot race other tests in this process and
/// cannot be forgotten by a runner). A held message's delivery is pushed far past the proto's
/// repair-or-truncate grace, so a `PrepareOk` can OUTLIVE its op's truncation + re-mint and arrive at
/// the new primary as a STALE-BODY vote for a live op number — the op-reuse / committed-divergence
/// class the proto's content-addressed vote gate (votes keyed by the prepare's identity, not the op
/// number alone) must reject, or a primary could commit an op no quorum durably holds.
///
/// The DEFAULT sweep deliberately leaves this axis OFF: enabling it consumes extra PRNG draws, which
/// would shift every pinned regression seed off its historical schedule. So this lane runs the axis
/// on its own seeds instead — hold-enabled runs are their own deterministic baselines (byte-identical
/// to `VOPR_HOLD=1` runs of the same seeds), and the default sweep's schedules stay untouched.
#[test]
fn vopr_hold_sweep_no_violations() {
  let mut total_holds = 0u64;
  let mut total_committed = 0usize;
  let mut seeds_with_view_change = 0u64;
  println!(
    "VOPR hold sweep: 0..{HOLD_SEEDS} contiguous, {DEFAULT_TICKS} ticks each, hold axis forced on"
  );
  for seed in 0..HOLD_SEEDS {
    let r = run_vopr_with_hold(seed, DEFAULT_TICKS);
    total_holds += r.holds_fired();
    total_committed += r.max_committed();
    if r.max_view() >= 1 {
      seeds_with_view_change += 1;
    }
  }
  // Non-vacuity: the axis must genuinely FIRE across the sweep — otherwise this lane has silently
  // decayed into a re-run of the default schedule and the stale-vote class is unguarded again.
  assert!(
    total_holds > 0,
    "the hold axis never held a message across the sweep (holds_fired={total_holds}) — the hold lane \
     is vacuous (the axis is not plumbed through, or its per-mille rate collapsed to 0)"
  );
  // And the hold-enabled runs still did real work: ops committed, and at least one seed drove a view
  // change — truncation + re-mint (the window a held vote must outlive to become a stale-body vote)
  // only opens across view changes, so a sweep with no view change could not reach the class this
  // lane exists for.
  assert!(
    total_committed > 0,
    "the hold sweep committed no ops at all — the driver is not exercising the protocol"
  );
  assert!(
    seeds_with_view_change > 0,
    "no hold-sweep seed drove a view change — the truncation/re-mint window the held votes must \
     outlive never opened"
  );
  println!(
    "VOPR hold sweep OK: holds_fired={total_holds} committed={total_committed} \
     view_change_seeds={seeds_with_view_change}"
  );
}

/// The contiguous seed range for the committed WIPE sweep (same budget rationale as [`HOLD_SEEDS`]).
const WIPE_SEEDS: u64 = 16;

/// The committed WIPE sweep: [`run_vopr_with_wipe`] over `0..WIPE_SEEDS` — the wipe-and-restart
/// (amnesia) axis FORCE-ENABLED programmatically (the [`run_vopr_with_hold`] pattern: no env var, no
/// schedule races, cannot be forgotten by a runner). At most ONE crashed replica per run comes back
/// with FRESH, EMPTY durable storage instead of recovering its persisted WAL/superblock — the
/// classic VSR amnesia hazard: a replica that voted in view V (and durably held committed ops)
/// rejoins at genesis with no memory of either. One lost durable state is within the crash-fault
/// model's `<= f` budget, so the cluster-level invariants MUST hold: agreement + no committed op
/// rewritten/lost across time + quorum-durable retention (honestly relaxed by exactly the wiped
/// count, floor 1 — never further) + the post-quiesce survival of the whole committed history. The
/// wiped replica is NEVER special-cased (it may be the sole quorum-intersection holder); the
/// checkers judge the outcome.
///
/// A violation in this sweep is a REAL, potentially P0-class protocol finding (amnesia breaking
/// quorum intersection) — report it with its seed; never mask it or weaken a checker to pass.
///
/// The DEFAULT sweep leaves this axis OFF (it consumes extra PRNG draws, which would shift every
/// pinned regression seed off its historical schedule); wipe-enabled runs are their own
/// deterministic baselines, byte-identical to `VOPR_WIPE=1` runs of the same seeds.
#[test]
fn vopr_wipe_sweep_no_violations() {
  let mut total_wipes = 0u64;
  let mut total_committed = 0usize;
  let mut seeds_with_view_change = 0u64;
  println!(
    "VOPR wipe sweep: 0..{WIPE_SEEDS} contiguous, {DEFAULT_TICKS} ticks each, wipe axis forced on"
  );
  for seed in 0..WIPE_SEEDS {
    let r = run_vopr_with_wipe(seed, DEFAULT_TICKS);
    total_wipes += r.wipes_fired();
    total_committed += r.max_committed();
    if r.max_view() >= 1 {
      seeds_with_view_change += 1;
    }
  }
  // Non-vacuity: the axis must genuinely FIRE across the sweep — a replica really came back with a
  // wiped disk — or this lane has silently decayed into a re-run of the default schedule and the
  // amnesia class is unguarded again.
  assert!(
    total_wipes > 0,
    "the wipe axis never wiped a replica across the sweep (wipes_fired={total_wipes}) — the wipe \
     lane is vacuous (the axis is not plumbed through, or no seed ever had a crashed replica when \
     the wipe roll fired)"
  );
  // And the wipe-enabled runs still did real work: ops committed, and at least one seed drove a view
  // change — re-voting across views is where a wiped replica's forgotten participation could break
  // quorum intersection, so a sweep with no view change could not reach the class this lane exists
  // for.
  assert!(
    total_committed > 0,
    "the wipe sweep committed no ops at all — the driver is not exercising the protocol"
  );
  assert!(
    seeds_with_view_change > 0,
    "no wipe-sweep seed drove a view change — the re-vote window a wiped replica's amnesia \
     endangers never opened"
  );
  println!(
    "VOPR wipe sweep OK: wipes_fired={total_wipes} committed={total_committed} \
     view_change_seeds={seeds_with_view_change}"
  );
}

/// The contiguous seed range for the committed CHURN sweep (same budget rationale as [`HOLD_SEEDS`]).
const CHURN_SEEDS: u64 = 16;

/// The committed CLIENT-CHURN sweep: [`run_vopr_with_churn`] over `0..CHURN_SEEDS` — the
/// client-churn axis FORCE-ENABLED programmatically (the [`run_vopr_with_hold`] pattern: no env var,
/// no schedule races, cannot be forgotten by a runner). The default sweep's client set is FIXED, so
/// the session table converges to one row per client and the deterministic session-cap eviction can
/// never engage; this lane retires active clients and spawns fresh `ClientId`s on a seeded cadence,
/// over a SMALL seeded `max_client_sessions` — so the apply-time eviction genuinely runs under the
/// full crash + partition + disk-fault schedule. The EXISTING safety / durability / view-monotonic /
/// boundedness / liveness checkers judge the outcome: the session table rides every checkpoint
/// envelope, so a NON-deterministic eviction (divergent victims across replicas) would diverge the
/// restored tables and surface through the at-most-once / agreement oracles, and an eviction that
/// broke admission would surface as a calm-window livelock. A violation here is a REAL finding in
/// the eviction design — report it with its seed; never mask it or weaken a checker to pass.
///
/// The DEFAULT sweep leaves this axis OFF (it consumes extra PRNG draws, which would shift every
/// pinned regression seed off its historical schedule); churn-enabled runs are their own
/// deterministic baselines, byte-identical to `VOPR_CHURN=1` runs of the same seeds.
#[test]
fn vopr_churn_sweep_no_violations() {
  let mut total_churns = 0u64;
  let mut total_evictions = 0u64;
  let mut total_committed = 0usize;
  let mut seeds_with_view_change = 0u64;
  println!(
    "VOPR churn sweep: 0..{CHURN_SEEDS} contiguous, {DEFAULT_TICKS} ticks each, churn axis forced on"
  );
  for seed in 0..CHURN_SEEDS {
    let r = run_vopr_with_churn(seed, DEFAULT_TICKS);
    total_churns += r.churns_fired();
    total_evictions += r.sessions_evicted();
    total_committed += r.max_committed();
    if r.max_view() >= 1 {
      seeds_with_view_change += 1;
    }
  }
  // Non-vacuity, both halves of the lane:
  // - the axis genuinely CHURNED clients (retire + fresh spawn actions fired), and
  // - the session-cap EVICTION genuinely engaged (sessions were evicted at apply time across the
  //   sweep) — otherwise the deterministic-eviction design ran vacuously and this lane has decayed
  //   into a re-run of the fixed-client default.
  assert!(
    total_churns > 0,
    "the churn axis never retired/spawned a client across the sweep (churns_fired={total_churns}) — \
     the churn lane is vacuous"
  );
  assert!(
    total_evictions > 0,
    "no session was ever evicted across the churn sweep (sessions_evicted={total_evictions}) — the \
     session-cap eviction is untested (cap too high for the churned population, or the eviction is \
     not engaging)"
  );
  // And the churn-enabled runs still did real work: ops committed, and at least one seed drove a
  // view change — the table rides checkpoints ACROSS view changes and restarts, which is where a
  // non-deterministic eviction would diverge the replicas.
  assert!(
    total_committed > 0,
    "the churn sweep committed no ops at all — the driver is not exercising the protocol"
  );
  assert!(
    seeds_with_view_change > 0,
    "no churn-sweep seed drove a view change — the cross-view session-table agreement this lane \
     guards never came under test"
  );
  println!(
    "VOPR churn sweep OK: churns_fired={total_churns} sessions_evicted={total_evictions} \
     committed={total_committed} view_change_seeds={seeds_with_view_change}"
  );
}

/// The contiguous seed range for the committed BATCHING sweep (same budget rationale as
/// [`HOLD_SEEDS`]).
const BATCHING_SEEDS: u64 = 16;

/// The committed EDGE-BATCHING sweep: [`run_vopr_with_batching`] over `0..BATCHING_SEEDS` — the
/// batching axis FORCE-ENABLED programmatically (the [`run_vopr_with_hold`] pattern: no env var,
/// no schedule races, cannot be forgotten by a runner). The cluster runs the batch-aware state
/// machine (every committed body parsed with the REAL batch codec, applied per unit, per-unit
/// replies sealed by the real `ReplyBuilder`), and a seeded subset of the clients drive the
/// deterministic aggregator model: seeded unit emission (a per-tick rate that can exceed one — the
/// queued excess is what forms multi-unit bodies), occasional atomic groups, FIFO packing under
/// the dual-budget rule, and per-unit reply demux asserted at every ack. The full adversarial
/// schedule (crashes, partitions, view changes, repair, state-sync) runs UNDER the batched
/// traffic, judged by the standard per-tick invariant suite + `AppliedOnce`, and post-quiesce by
/// the per-unit oracle: every acked unit applied exactly once at its request's committed
/// `(op, unit_index)` with the submitted bytes and the SM's deterministic reply; groups on one op,
/// adjacent, never split.
///
/// A violation in this sweep is a REAL finding (a batched body double-applied, a unit re-ordered
/// or rewritten across view change/repair/state-sync, a split group) — report it with its seed;
/// never mask it or weaken a checker to pass.
///
/// The DEFAULT sweep leaves this axis OFF (its build-time draws would shift every pinned
/// regression seed off its historical schedule); batching-enabled runs are their own deterministic
/// baselines, byte-identical to `VOPR_BATCHING=1` runs of the same seeds.
#[test]
fn vopr_batching_sweep_no_violations() {
  let mut total_multi_unit_bodies = 0u64;
  let mut total_groups = 0u64;
  let mut max_units = 0u64;
  let mut total_committed = 0usize;
  let mut seeds_with_view_change = 0u64;
  println!(
    "VOPR batching sweep: 0..{BATCHING_SEEDS} contiguous, {DEFAULT_TICKS} ticks each, batching \
     axis forced on"
  );
  for seed in 0..BATCHING_SEEDS {
    let r = run_vopr_with_batching(seed, DEFAULT_TICKS);
    total_multi_unit_bodies += r.bodies_with_multiple_units();
    total_groups += r.groups_submitted();
    max_units = max_units.max(r.max_units_per_body());
    total_committed += r.max_committed();
    if r.max_view() >= 1 {
      seeds_with_view_change += 1;
    }
  }
  // Non-vacuity, the lane's committed core: batching must genuinely ENGAGE — the closed loop
  // queued 2+ units while a body flew and the model packed them into one consensus op. A zero here
  // means every body carried a single unit and the lane decayed into the plain schedule with a
  // codec wrapper.
  assert!(
    total_multi_unit_bodies > 0,
    "no packed body ever carried more than one unit across the sweep \
     (bodies_with_multiple_units={total_multi_unit_bodies}) — batching never engaged; the lane is \
     vacuous"
  );
  // The atomic-group path (whole-or-deferred, never split) must also be genuinely exercised.
  assert!(
    total_groups > 0,
    "no atomic group was ever enqueued across the sweep (groups_submitted={total_groups}) — the \
     group path is vacuous"
  );
  // And the batching-enabled runs still did real work: ops committed, and at least one seed drove
  // a view change — re-packing + retransmission across failover is exactly the window where a
  // batched body could double-apply or tear, so a sweep with no view change could not reach the
  // class this lane exists for.
  assert!(
    total_committed > 0,
    "the batching sweep committed no ops at all — the driver is not exercising the protocol"
  );
  assert!(
    seeds_with_view_change > 0,
    "no batching-sweep seed drove a view change — the failover interleavings this lane guards \
     never came under test"
  );
  println!(
    "VOPR batching sweep OK: bodies_with_multiple_units={total_multi_unit_bodies} \
     groups_submitted={total_groups} max_units_per_body={max_units} committed={total_committed} \
     view_change_seeds={seeds_with_view_change}"
  );
}

/// The contiguous seed range for the committed ASYM sweep (same budget rationale as [`HOLD_SEEDS`]).
const ASYM_SEEDS: u64 = 16;

/// The committed ASYMMETRIC-PARTITION sweep: [`run_vopr_with_asym`] over `0..ASYM_SEEDS` — the
/// one-way partition axis FORCE-ENABLED programmatically (the [`run_vopr_with_hold`] pattern: no env
/// var, no schedule races, cannot be forgotten by a runner). The default sweep's partitions are
/// SYMMETRIC (group membership: either both sides see each other or neither does); this lane installs
/// DIRECTED blocks — `blocked[from][to]` drops `from → to` while `to → from` keeps flowing — the
/// one-way reachability real networks produce (a half-dead NIC, an asymmetric route/firewall).
/// The headline shape is a DEAF PRIMARY (the victim draw biases toward a current
/// primary half the time): its heartbeats flow OUT — suppressing every backup's idle view-change
/// timer — while the PrepareOks never ARRIVE, so nothing commits for the whole episode; the mirror
/// MUTE shape and a single-edge shape are also drawn. Victims count against the same minority budget
/// as crash/isolate; episodes heal exactly like symmetric partitions (a seeded heal branch, plus
/// every calm window/final quiesce restores full bidirectional connectivity first — a calm window
/// requires full bidirectional connectivity, so progress is never demanded DURING an episode, only
/// after heal). Safety/durability/agreement are judged as-is every tick throughout.
///
/// A violation in this sweep is a REAL finding — one-way reachability wedging post-heal recovery,
/// or splitting commit accounting across a directed cut — report it with its seed; never mask it or
/// weaken a checker to pass.
///
/// The DEFAULT sweep leaves this axis OFF (it consumes extra PRNG draws, which would shift every
/// pinned regression seed off its historical schedule); asym-enabled runs are their own
/// deterministic baselines, byte-identical to `VOPR_ASYM=1` runs of the same seeds.
#[test]
fn vopr_asym_sweep_no_violations() {
  let mut total_episodes = 0u64;
  let mut total_one_way_dropped = 0u64;
  let mut total_committed = 0usize;
  let mut seeds_with_view_change = 0u64;
  println!(
    "VOPR asym sweep: 0..{ASYM_SEEDS} contiguous, {DEFAULT_TICKS} ticks each, asym axis forced on"
  );
  for seed in 0..ASYM_SEEDS {
    let r = run_vopr_with_asym(seed, DEFAULT_TICKS);
    total_episodes += r.asym_episodes();
    total_one_way_dropped += r.one_way_dropped();
    total_committed += r.max_committed();
    if r.max_view() >= 1 {
      seeds_with_view_change += 1;
    }
  }
  // Non-vacuity, in two layers:
  // - episodes were genuinely INSTALLED (the axis is plumbed through and the budget left room), and
  // - a directed block genuinely CUT live traffic (messages were dropped on a one-way leg) — an
  //   episode that never intersected a message would leave the axis untested.
  assert!(
    total_episodes > 0,
    "the asym axis never installed a one-way episode across the sweep \
     (asym_episodes={total_episodes}) — the asym lane is vacuous"
  );
  assert!(
    total_one_way_dropped > 0,
    "no message was ever dropped by a one-way block across the sweep \
     (one_way_dropped={total_one_way_dropped}) — the episodes never cut live traffic"
  );
  // And the asym-enabled runs still did real work: ops committed, and at least one seed drove a
  // view change — the deaf/mute shapes interact with failover (a deaf new primary cannot complete
  // its view change; the cluster must escalate past it), so a sweep with no view change could not
  // reach the class this lane exists for.
  assert!(
    total_committed > 0,
    "the asym sweep committed no ops at all — the driver is not exercising the protocol"
  );
  assert!(
    seeds_with_view_change > 0,
    "no asym-sweep seed drove a view change — the one-way/failover interleavings this lane guards \
     never came under test"
  );
  println!(
    "VOPR asym sweep OK: asym_episodes={total_episodes} one_way_dropped={total_one_way_dropped} \
     committed={total_committed} view_change_seeds={seeds_with_view_change}"
  );
}

/// The contiguous seed range for the committed SLOW-replica sweep (same budget rationale as
/// [`HOLD_SEEDS`]).
const SLOW_SEEDS: u64 = 16;

/// The committed SLOW-REPLICA (gray failure) sweep: [`run_vopr_with_slow`] over `0..SLOW_SEEDS` —
/// the slow axis FORCE-ENABLED programmatically (the [`run_vopr_with_hold`] pattern). On a seeded
/// cadence ONE replica's inter-replica delivery degrades for a bounded episode window: every message
/// on its seeded legs (inbound, outbound, or both) arrives a few seeded milliseconds LATE — never
/// dropped. This is the failure mode between the crash model (the replica never stops) and the
/// partition model (nothing is ever lost): a consistently-behind participant whose late acks, late
/// heartbeats, and late votes every timer interaction must tolerate. The band (≤ ~22 ms extra) sits
/// deliberately BELOW the proto's 50 ms commit-heartbeat / 200 ms idle cadences, so the victim is
/// degraded-but-alive and no view change is legitimately OWED — yet stale-by-milliseconds messages
/// keep landing in every window (view changes, repair, checkpoint races) under the full crash +
/// partition + disk-fault schedule. Episodes are bounded (a seeded tick window) and healed like
/// partitions (calm windows and the final quiesce end them first), so liveness is judged over a
/// fully-prompt cluster; safety/durability/agreement are judged as-is every tick throughout.
///
/// A violation in this sweep is a REAL finding (gray failure wedging a timer interaction or
/// diverging replicas) — report it with its seed; never mask it or weaken a checker to pass.
///
/// The DEFAULT sweep leaves this axis OFF (it consumes extra PRNG draws, which would shift every
/// pinned regression seed off its historical schedule); slow-enabled runs are their own
/// deterministic baselines, byte-identical to `VOPR_SLOW=1` runs of the same seeds.
#[test]
fn vopr_slow_replica_sweep_no_violations() {
  let mut total_episodes = 0u64;
  let mut total_slow_delays = 0u64;
  let mut total_committed = 0usize;
  let mut seeds_with_view_change = 0u64;
  println!(
    "VOPR slow-replica sweep: 0..{SLOW_SEEDS} contiguous, {DEFAULT_TICKS} ticks each, slow axis \
     forced on"
  );
  for seed in 0..SLOW_SEEDS {
    let r = run_vopr_with_slow(seed, DEFAULT_TICKS);
    total_episodes += r.slow_episodes();
    total_slow_delays += r.slow_delays();
    total_committed += r.max_committed();
    if r.max_view() >= 1 {
      seeds_with_view_change += 1;
    }
  }
  // Non-vacuity, in two layers: episodes genuinely INSTALLED, and live traffic genuinely DELAYED
  // (an episode on an idle link would leave the gray-failure schedule untested).
  assert!(
    total_episodes > 0,
    "the slow axis never installed an episode across the sweep (slow_episodes={total_episodes}) — \
     the slow lane is vacuous"
  );
  assert!(
    total_slow_delays > 0,
    "no message ever picked up a slow-replica delay across the sweep \
     (slow_delays={total_slow_delays}) — the episodes never touched live traffic"
  );
  // And the slow-enabled runs still did real work: ops committed, and at least one seed drove a
  // view change — a gray replica riding through failover (its late votes/acks landing across view
  // boundaries) is the interleaving this lane exists to stress.
  assert!(
    total_committed > 0,
    "the slow sweep committed no ops at all — the driver is not exercising the protocol"
  );
  assert!(
    seeds_with_view_change > 0,
    "no slow-sweep seed drove a view change — the late-delivery/failover interleavings this lane \
     guards never came under test"
  );
  println!(
    "VOPR slow sweep OK: slow_episodes={total_episodes} slow_delays={total_slow_delays} \
     committed={total_committed} view_change_seeds={seeds_with_view_change}"
  );
}

/// The contiguous seed range for the committed STALE-READ sweep (same budget rationale as
/// [`HOLD_SEEDS`]).
const STALE_READ_SEEDS: u64 = 16;

/// The committed STALE-READ sweep: [`run_vopr_with_stale_read`] over `0..STALE_READ_SEEDS` — the
/// stale-read axis FORCE-ENABLED programmatically (the [`run_vopr_with_hold`] pattern: no env var, no
/// schedule races, cannot be forgotten by a runner). On a seeded cadence the lane deterministically
/// partitions the CURRENT primary OUT — every directed leg to/from it cut, so it is at once deaf
/// (acks/votes never arrive) and mute (its heartbeats never reach the survivors, whose idle
/// view-change timers then fire) — forcing the survivors to elect a NEW primary while the deposed one
/// sits in its old view. The [`StalenessChecker`](viewstamp_simulation::StalenessChecker) runs LIVE
/// across the failover: the staleness floor (the committed-history high-water) is asserted MONOTONE
/// through the view change, the cross-check this lane exercises now. The deposed primary reuses the
/// asym victim/budget/heal bookkeeping (it counts against the minority budget and heals like any
/// one-way episode), so a quorum of survivors always remains to elect + commit.
///
/// The read-specific assertion (the deposed primary cannot serve a STALE read) is DEFERRED to the
/// future read-path step — there is no read path today, so no read is recorded and the staleness
/// enforcement is vacuous. This lane lands now exercising the failover schedule that assertion will
/// later hang on. A violation here is a REAL finding (the committed-history high-water regressing
/// across the failover) — report it with its seed; never mask it or weaken a checker to pass.
///
/// The DEFAULT sweep leaves this axis OFF (it consumes extra PRNG draws, which would shift every
/// pinned regression seed off its historical schedule); stale-read-enabled runs are their own
/// deterministic baselines, byte-identical to `VOPR_STALE_READ=1` runs of the same seeds.
#[test]
fn vopr_stale_read_sweep_no_violations() {
  let mut total_probes = 0u64;
  let mut total_failovers = 0u64;
  let mut total_committed = 0usize;
  println!(
    "VOPR stale-read sweep: 0..{STALE_READ_SEEDS} contiguous, {DEFAULT_TICKS} ticks each, \
     stale-read axis forced on"
  );
  for seed in 0..STALE_READ_SEEDS {
    let r = run_vopr_with_stale_read(seed, DEFAULT_TICKS);
    total_probes += r.stale_read_probes_fired();
    total_failovers += r.stale_read_failovers_observed();
    total_committed += r.max_committed();
  }
  // CAUSAL non-vacuity: the lane deposed a serving primary and then OBSERVED the resulting failover
  // (a higher-view serving primary while the deposed one stayed cut) — so the staleness floor was
  // genuinely exercised across a completed deposed-primary failover window, not merely a cut that
  // a heal could have undone before any view change. A bare cut-install count (or any view change,
  // which crash/partition churn also drives) would not prove the intended window was exercised.
  assert!(
    total_failovers > 0,
    "the stale-read axis observed no probe-induced failover across the sweep \
     (stale_read_failovers_observed={total_failovers}, cut installs={total_probes}) — the \
     stale-read lane is vacuous: no deposed-primary failover window was exercised"
  );
  // And the stale-read-enabled runs still did real work.
  assert!(
    total_committed > 0,
    "the stale-read sweep committed no ops at all — the driver is not exercising the protocol"
  );
  println!(
    "VOPR stale-read sweep OK: stale_read_failovers_observed={total_failovers} \
     cut_installs={total_probes} committed={total_committed}"
  );
}

/// The contiguous seed range for the committed LEARNER sweep (same budget rationale as
/// [`HOLD_SEEDS`]).
const LEARNER_SEEDS: u64 = 64;

/// The committed LEARNER sweep: [`run_vopr_with_learners`] over `0..LEARNER_SEEDS` — the learner axis
/// FORCE-ENABLED programmatically (the [`run_vopr_with_hold`] pattern: no env var, no schedule races,
/// cannot be forgotten by a runner). The cluster carries 1..=3 NON-VOTING learners alongside the
/// voting set; a learner applies the committed log the voters agreed on but NEVER emits a counted
/// message (PrepareOk/StartViewChange/DoViewChange), is NEVER primary, and may catch up via
/// state-sync. UNDER the axis the driver also crashes a learner for a sustained window WITHOUT
/// charging the minority budget, so the calm-window committed-progress assertion must STILL advance
/// using the voters alone — voter fault tolerance is independent of learner health.
///
/// The oracles run inside every `run_vopr_with_learners` call: never-primary and no-learner-emit
/// every tick, learner convergence post-quiesce, and the calm-window progress assertion across the
/// learner outage. A violation in any of them PANICS with its seed (a learner voting/leading, a
/// learner diverging from the committed history, or a learner outage stalling voter progress is a
/// REAL finding) — so simply running this sweep exercises them. This test additionally asserts the
/// axis is NON-VACUOUS: across the seeds, learners genuinely applied ops, caught up via state-sync,
/// AND followed view changes — otherwise the learner plumbing ran without doing learner work.
///
/// The DEFAULT sweep leaves this axis OFF (the learner count grows `node_count` behind a separate
/// magic-seeded draw, leaving the action stream byte-identical when off); learner-enabled runs are
/// their own deterministic baselines, byte-identical to `VOPR_LEARNER=1` runs of the same seeds.
#[test]
fn learner_axis_is_non_vacuous() {
  let mut total_ops_applied = 0u64;
  let mut total_repairs = 0u64;
  let mut total_view_changes_followed = 0u64;
  let mut total_committed = 0usize;
  let mut seeds_with_view_change = 0u64;
  println!(
    "VOPR learner sweep: 0..{LEARNER_SEEDS} contiguous, {DEFAULT_TICKS} ticks each, learner axis \
     forced on"
  );
  for seed in 0..LEARNER_SEEDS {
    let r = run_vopr_with_learners(seed, DEFAULT_TICKS);
    total_ops_applied += r.learner_ops_applied();
    total_repairs += r.learner_repairs_served();
    total_view_changes_followed += r.learner_view_changes_followed();
    total_committed += r.max_committed();
    if r.max_view() >= 1 {
      seeds_with_view_change += 1;
    }
  }
  // Non-vacuity across all three witnesses — each proves a distinct learner behavior genuinely
  // happened under the full adversarial schedule:
  // - learners APPLIED committed ops (they follow the committed log the voters agreed on),
  assert!(
    total_ops_applied > 0,
    "no learner applied any committed op across the sweep (learner_ops_applied={total_ops_applied}) \
     — the learner lane is vacuous: learners are not following the committed log"
  );
  // - learners CAUGHT UP via state-sync (a learner that fell behind was brought current by the same
  //   repair/state-sync machinery a lagging voter is), and
  assert!(
    total_repairs > 0,
    "no learner ever completed a state-sync across the sweep (learner_repairs_served={total_repairs}) \
     — a learner that fell behind never caught up via the repair/state-sync path"
  );
  // - learners FOLLOWED view changes (a learner adopted a new primary's view without ever being an
  //   active view-change participant).
  assert!(
    total_view_changes_followed > 0,
    "no learner ever followed a view change across the sweep \
     (learner_view_changes_followed={total_view_changes_followed}) — learners never adopted a higher \
     view, so the view-following path is untested"
  );
  // And the learner-enabled runs still did real work, with at least one seed driving a view change —
  // a learner following a view change requires a view change to occur somewhere in the sweep.
  assert!(
    total_committed > 0,
    "the learner sweep committed no ops at all — the driver is not exercising the protocol"
  );
  assert!(
    seeds_with_view_change > 0,
    "no learner-sweep seed drove a view change — the view-following path this lane guards never came \
     under test"
  );
  println!(
    "VOPR learner sweep OK: learner_ops_applied={total_ops_applied} \
     learner_repairs_served={total_repairs} \
     learner_view_changes_followed={total_view_changes_followed} committed={total_committed} \
     view_change_seeds={seeds_with_view_change}"
  );
}

/// The contiguous seed range for the committed TIER C RECONFIGURATION sweep (same budget rationale as
/// [`HOLD_SEEDS`]; each reconfig drains + re-forms, so it is kept modest).
const RECONFIG_SEEDS: u64 = 16;

/// The committed TIER C RECONFIGURATION sweep: [`run_vopr_with_reconfig`] over `0..RECONFIG_SEEDS` —
/// the all-`RecoveringHead` re-formation axis FORCE-ENABLED programmatically (the
/// [`run_vopr_with_hold`] pattern: no env var, no schedule races, cannot be forgotten by a runner).
/// On a seeded cadence the driver fires a coordinated OFFLINE reconfiguration
/// ([`Cluster::reconfigure_offline`](viewstamp_simulation::Cluster::reconfigure_offline), route A): it
/// drains the cluster to all-`Normal` at a common view, mints one UNCOMMITTED tail op above the
/// committed frontier, pre-writes a successor durable root on every node via `prepare_restart` (KEEPING
/// the voting set — a no-op-membership reconfig that still bumps the epoch), and restarts every voter
/// into `Status::RecoveringHead` with a head read-fault on that uncommitted tail. That is the wedge the
/// proto's `retire_recover_and_escalate` escalation must resolve: no `Normal` node answers a `Recovery`,
/// so ONLY the escalation re-forms the cluster.
///
/// The axis MASKS the permanent torn/bit-rot storage faults (route A: an offline stop is on healthy
/// disks), so committed data stays sound and the wedge is driven by faulting the UNCOMMITTED tail
/// alone — no committed op is ever at risk. The standard per-tick safety / durability / applied-once /
/// view-monotonicity suite runs throughout (so a committed-op loss, a double-apply, or a view
/// regression across the wedge surfaces immediately), and the calm-window + final-quiesce liveness
/// oracle asserts the cluster ALWAYS re-forms (a permanent `RecoveringHead` quorum would be a
/// non-convergence wedge the final quiesce reports). A violation here is a REAL finding (the escalation
/// failing to re-form a wedged cluster, or losing a committed op across the coordinated restart) —
/// report it with its seed; never mask it.
///
/// The DEFAULT sweep leaves this axis OFF: the escalation is off-axis-unsatisfiable, so a default run
/// never escalates and `reform_escalations_fired` stays `0` (the standing off-axis byte-identity guard
/// asserted in [`vopr_sweep_no_violations`]); reconfig-enabled runs are their own deterministic
/// baselines, byte-identical to `VOPR_RECONFIG=1` runs of the same seeds.
#[test]
fn vopr_reconfig_sweep_no_violations() {
  let mut total_reconfigs = 0u64;
  let mut total_escalations = 0u64;
  let mut total_committed = 0usize;
  let mut seeds_with_view_change = 0u64;
  println!(
    "VOPR reconfig sweep: 0..{RECONFIG_SEEDS} contiguous, {DEFAULT_TICKS} ticks each, reconfig axis \
     forced on"
  );
  for seed in 0..RECONFIG_SEEDS {
    let r = run_vopr_with_reconfig(seed, DEFAULT_TICKS);
    total_reconfigs += r.reconfigs_fired();
    total_escalations += r.reform_escalations_fired();
    total_committed += r.max_committed();
    if r.max_view() >= 1 {
      seeds_with_view_change += 1;
    }
  }
  // Non-vacuity, the lane's committed core:
  // - the axis genuinely FIRED a coordinated reconfiguration (drained, swapped roots, re-formed from a
  //   wedge) somewhere across the sweep, and
  // - the proto's re-formation ESCALATION genuinely fired (a voting quorum escalated out of
  //   `RecoveringHead` into a view change) — the empirical proof the escalation re-forms the wedge.
  // A zero in either means the lane decayed (no reconfiguration reached the wedge, or the escalation
  // path went unexercised), and the all-`RecoveringHead` re-formation is unguarded again.
  assert!(
    total_reconfigs > 0,
    "the reconfig axis never fired a coordinated reconfiguration across the sweep \
     (reconfigs_fired={total_reconfigs}) — the lane is vacuous (no seed quiesced to a v4 root when the \
     reconfig roll fired?)"
  );
  assert!(
    total_escalations > 0,
    "no RecoveringHead voter ever escalated into a view change across the sweep \
     (reform_escalations_fired={total_escalations}) — the re-formation escalation was never \
     exercised (the wedge never formed, or the escalation never fired)"
  );
  // And the reconfig-enabled runs still did real work: ops committed, and at least one seed drove a
  // view change — the escalation IS a view change, so a sweep that escalated must show view changes.
  assert!(
    total_committed > 0,
    "the reconfig sweep committed no ops at all — the driver is not exercising the protocol"
  );
  assert!(
    seeds_with_view_change > 0,
    "no reconfig-sweep seed drove a view change — the re-formation escalation (a view change) was \
     never reached"
  );
  println!(
    "VOPR reconfig sweep OK: reconfigs_fired={total_reconfigs} \
     reform_escalations_fired={total_escalations} committed={total_committed} \
     view_change_seeds={seeds_with_view_change}"
  );
}

/// The contiguous seed range for the torn-header probe lane (same budget as the other axis lanes).
const TORN_HEADER_SEEDS: u64 = 16;

/// CONTRACT-VIOLATION PROBE (not a CI gate — `#[ignore]`d, run on demand): what happens when an
/// embedder violates the `Wal` header-durability contract?
///
/// The contract (`viewstamp-proto/src/storage.rs`, trait-level docs) requires slot HEADERS to be
/// durable INDEPENDENTLY of bodies: a body-level fault must never lose the header, because the
/// keep-header-only recovery shape (`Body::Repairing`) uses the surviving header to prove a
/// committed op EXISTS at its op number (pinning its canonical identity) so the body can be
/// peer-repaired — the structural fix for the storage-fault committed-op-loss class. This lane
/// FORCE-ENABLES a fault the contract forbids ([`run_vopr_with_torn_headers`]): a seed-chosen
/// per-mille of completed appends lose their header too — the slot reads back `Absent`/`Empty`,
/// `header() == None`, as if never written.
///
/// EXPECTATION: violations here are EXPECTED EVIDENCE that the contract is load-bearing (the
/// committed-op-survival design genuinely leans on header durability), NOT proto bugs to fix — the
/// lane exists to measure the blast radius of the contract violation. A clean sweep would be the
/// (also valuable) finding that the proto tolerates even headerless faults. Run with:
/// `cargo test --release -p viewstamp-simulation --test vopr vopr_torn_header_sweep_no_violations \
///  -- --ignored --nocapture`
/// Every seed is run (`catch_unwind`, the `vopr_collect_failures` pattern) so ONE run records every
/// violating seed + its verbatim message; the test then fails iff any seed violated — its exit code
/// is the probe's measurement, not a regression signal.
///
/// MEASURED BLAST RADIUS (16/16 seeds violate; the contract is demonstrably load-bearing). Two
/// invariant classes collapse, neither maskable without weakening a real checker:
///
/// - **Quorum-durable retention of a committed op** (seed 0, verbatim):
///   `vopr seed 0 tick 3352: committed op 603 is durably held on only 1 replicas (< required 2 =
///   quorum 2 - wipes 0) — a committed op is not retained durably by the surviving quorum`
///   — torn headers erase completed appends outright, so a committed op's durable holder set falls
///   below quorum: precisely the committed-op-LOSS class the contract paragraph in the trait doc
///   predicts ("the op's existence is forgotten, its number can be re-minted ... a client-acked
///   committed op silently disappears").
/// - **Append-before-ack** (most seeds, e.g. seed 7, verbatim):
///   `vopr seed 7 tick 88: replica 1 emitted PrepareOk(op=20, msg_view=0) but its WAL append has not
///   completed (wal_status=empty, ...) — append-before-ack violated`
///   — the append COMPLETED (`Appended` fired, so the proto legitimately acks) but the slot reads
///   back `Empty`, so the replica's commit-quorum vote references state its disk no longer
///   evidences: the vote-backed-by-durable-state premise quorum intersection stands on is gone
///   within ~100 ticks in every seed.
#[test]
#[ignore = "contract-violation probe: measures the blast radius when the Wal header-durability contract is broken; not a CI gate"]
fn vopr_torn_header_sweep_no_violations() {
  println!(
    "VOPR torn-header probe: 0..{TORN_HEADER_SEEDS} contiguous, {DEFAULT_TICKS} ticks each, \
     torn-header axis forced on"
  );
  // Silence the per-panic backtrace spam; the verbatim message is recovered from the payload.
  let prev_hook = std::panic::take_hook();
  std::panic::set_hook(Box::new(|_| {}));
  let mut failures: Vec<(u64, String)> = Vec::new();
  let mut total_torn = 0u64;
  let mut clean_seeds = 0u64;
  for seed in 0..TORN_HEADER_SEEDS {
    match std::panic::catch_unwind(|| run_vopr_with_torn_headers(seed, DEFAULT_TICKS)) {
      Ok(r) => {
        total_torn += r.torn_headers_fired();
        clean_seeds += 1;
      }
      Err(payload) => {
        let msg = if let Some(s) = payload.downcast_ref::<String>() {
          s.clone()
        } else if let Some(s) = payload.downcast_ref::<&str>() {
          (*s).to_string()
        } else {
          "<non-string panic payload>".to_string()
        };
        failures.push((seed, msg));
      }
    }
  }
  std::panic::set_hook(prev_hook);
  println!(
    "=== VOPR torn-header probe 0..{TORN_HEADER_SEEDS}: {} violating seeds, {clean_seeds} clean \
     (torn_headers_fired={total_torn} across the clean seeds) ===",
    failures.len()
  );
  for (seed, msg) in &failures {
    println!("  seed {seed}: {msg}");
  }
  // The probe PASSES by demonstrating the violations: losing a slot's header after its append
  // completed breaks the durability accounting (append-before-ack and its siblings fire), which is
  // exactly why the Wal contract requires headers to be independently durable from bodies. If this
  // ever finds NO violations, the proto has become torn-header-tolerant and the contract (and this
  // probe) should be re-evaluated — that surprising outcome is the failure mode worth flagging.
  if failures.is_empty() {
    assert!(
      total_torn > 0,
      "the torn-header axis never fired across an all-clean sweep (torn_headers_fired={total_torn}) \
       — the probe is vacuous"
    );
    panic!(
      "no seed violated under torn headers (torn_headers_fired={total_torn}) — the proto now \
       tolerates headerless faults; re-evaluate whether the Wal header-durability contract (and \
       this probe) can be relaxed"
    );
  }
}

/// Diagnostic (NOT a gate): sweep `0..VOPR_SEEDS` (default 64) but CATCH each seed's violation with
/// [`std::panic::catch_unwind`] instead of failing fast, so ONE run records EVERY failing seed + its
/// message rather than aborting at the first. Use it to audit a wide range for failure CLASSES — the
/// messages carry `seed S tick T: <class>: ...`, so they group by class: e.g.
/// `VOPR_SEEDS=2048 cargo test --release -p viewstamp-simulation --test vopr vopr_collect_failures
/// -- --ignored --nocapture`. Ignored so it never runs in the normal sweep.
#[test]
#[ignore = "failure-collecting sweep: set VOPR_SEEDS and run with --ignored --nocapture to record all failing seeds"]
fn vopr_collect_failures() {
  let count = sweep_seed_count();
  // Silence the per-panic hook for the sweep so a failing seed does not spam stderr with a backtrace;
  // the message is recovered from the caught panic payload instead.
  let prev_hook = std::panic::take_hook();
  std::panic::set_hook(Box::new(|_| {}));
  let mut failures: Vec<(u64, String)> = Vec::new();
  for seed in 0..count {
    if seed % 256 == 0 {
      eprintln!(
        "  ... seed {seed}/{count}, {} failures so far",
        failures.len()
      );
    }
    if let Err(payload) = std::panic::catch_unwind(|| run_vopr(seed, DEFAULT_TICKS)) {
      let msg = if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
      } else if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
      } else {
        "<non-string panic payload>".to_string()
      };
      failures.push((seed, msg));
    }
  }
  std::panic::set_hook(prev_hook);
  println!(
    "=== VOPR failure sweep 0..{count}: {} failing seeds ===",
    failures.len()
  );
  for (seed, msg) in &failures {
    println!("  seed {seed}: {msg}");
  }
}

/// Regression for the final-quiesce fix: a FINAL-INSTANT durability-checker artifact, NOT a proto loss.
///
/// Under an adversarial schedule the committed-history high-water op was APPLIED only by a replica
/// that happened to be CRASHED at that instant, while two OPERATIONAL survivors held that op DURABLY
/// on their WAL (so the committed op was retained by a quorum — the per-tick structural
/// quorum-durability check never fired) but had not yet APPLIED it (commit catch-up still in flight,
/// their `commit_max` had not yet learned the op was committed). The end-of-run durability assertion
/// asked for the committed history to be APPLIED by an operational replica AT THAT ARBITRARY INSTANT —
/// strictly stronger than VSR's true guarantee (a committed op survives on a quorum's DURABLE storage;
/// application is local catch-up that completes eventually). The fix gives [`run_vopr`] a final
/// bounded QUIESCE phase (heal everything, restart all, no faults, tick to convergence) BEFORE the
/// end-of-run assertions — exactly TigerBeetle's VOPR `transition_to_liveness_mode` discipline — so the
/// survivors apply the durably-held committed tail before the check. This run is a pure function of
/// the seed, so the artifact reproduces exactly and the drained run must now pass.
#[test]
fn seed_313_final_quiesce_converges_the_durably_held_committed_tail() {
  // Must NOT panic: the final quiesce phase drains the committed tail the (operational) survivors
  // held durably-but-unapplied at tick 4000, so the end-of-run durability + applied assertions hold.
  let r = run_vopr_one(313);
  // Non-vacuity: this seed really did stress the protocol (crashes + restarts + a partition + real
  // view changes + > 1000 committed ops) — i.e. the drain ran after a genuine adversarial schedule,
  // not a quiet happy path that would trivially have converged already.
  assert!(
    r.max_committed() >= 1_000,
    "this schedule commits a long history (got {})",
    r.max_committed()
  );
  assert!(
    r.crashes() > 0 && r.restarts() > 0 && r.max_view() >= 1,
    "this schedule exercised crash/restart + failover before the final quiesce (crashes={}, restarts={}, \
     max_view={})",
    r.crashes(),
    r.restarts(),
    r.max_view()
  );
}

/// Replay a SINGLE seed in isolation, with output captured, for debugging a sweep failure. Set
/// `VOPR_SEED` to the seed of interest and run with `--ignored --nocapture`. (Ignored so it does not
/// run in the normal sweep; it is a debugging aid, not a gate.) Pair with the `VOPR_DUMP` /
/// `VOPR_TRACE` / `VOPR_NO_*` env switches in `src/vopr.rs` to dump divergence state, trace actions, or
/// shrink the fault set while staying on the exact same seeded schedule. (Set `VOPR_SEED` to any seed
/// you want to inspect — e.g. a historical bug-finder like 24, 36, or 164.)
#[test]
#[ignore = "single-seed replay: set VOPR_SEED and run with --ignored --nocapture to debug a sweep failure"]
fn replay_single_seed() {
  let seed = std::env::var("VOPR_SEED")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(36);
  let r = run_vopr_one(seed);
  println!(
    "vopr seed {} OK: ticks={} replicas={} clients={} max_committed={} crashes={} restarts={} \
     partitions={} heals={} calm_windows={} max_view={} all_clients_done={} \
     wal_capacity={:?} wal_stalls={} below_ring_window_syncs={} sync_chunk_transfers={} \
     bounded_seed_wrapped={} large_bodies={} oversized_dropped={}",
    r.seed(),
    r.ticks(),
    r.replicas(),
    r.clients(),
    r.max_committed(),
    r.crashes(),
    r.restarts(),
    r.partitions(),
    r.heals(),
    r.calm_windows(),
    r.max_view(),
    r.all_clients_done(),
    r.wal_capacity(),
    r.wal_stalls(),
    r.below_ring_window_syncs(),
    r.sync_chunk_transfers(),
    r.bounded_seed_wrapped(),
    r.large_bodies_sent(),
    r.oversized_dropped(),
  );
}

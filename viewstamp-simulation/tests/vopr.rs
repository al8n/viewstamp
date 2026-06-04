//! VOPR sweep: the seeded adversarial driver (`run_vopr`) over a seed range, asserting no panics.
//!
//! Each seed builds a fresh cluster (size 2..=6 — including even N and the N=2 unanimous-quorum case)
//! and explores a randomized adversarial schedule WITHIN the crash-stop fault model (a quorum always
//! survives). Adversarial axes: async WAL + async Superblock, with a crash that DISCARDS in-flight WAL
//! appends (modelling real fsync-loss-on-crash); network reorder/drop/duplicate/delay; storage
//! read/torn/bit-rot faults + MISDIRECTED reads (a read returns a wrong-but-valid sibling slot,
//! exercising the recovery/repair placement-integrity checks); small AND large `checkpoint_ops` (the
//! latter recovers a non-trivial committed band — the large-checkpoint recover read-window path); a redundant-copy
//! Superblock that retains the last-rooted checkpoint until a new one is durably rooted (finding B); and
//! a seed-derived PHYSICAL BOUNDED-WAL RING on ~1/3 of seeds (the rest unbounded), where
//! each WAL is a fixed `N`-slot ring so the primary STALLS op-assignment before it would wrap an
//! un-pruned slot — folding wrap (stall-before-wrap + recover off a wrapped ring + a below-ring-window
//! backup overflow) into the full crash + partition + disk-fault schedule, with a per-tick RING-RESIDENCY
//! checker asserting no wrap ever drops an op `recover`/repair still needs. `N` is sized
//! `checkpoint_ops * k + headroom` (`k` in 3..=6) so the stall always RELEASES (a tighter ring would
//! wedge the primary — the headroom constraint, documented in `src/vopr.rs::build_cluster`).
//! Liveness is judged over calm windows gated on VIRTUAL time, not raw ticks (the seed-622 lesson).
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

use viewstamp_simulation::{DEFAULT_TICKS, run_vopr, run_vopr_one};

/// The contiguous committed seed range (kept modest to bound the gate's wall-clock). Correctness
/// coverage over raw count: each seed runs a few thousand ticks of rich adversarial schedule. With the
/// async-superblock mode ON in [`run_vopr`] (the pending-durable-view window), this whole
/// `0..SEEDS` range is verified clean — including the `vsr_headers` recovery cross-check fix and
/// the final-quiesce fix (a wide `0..512` catch-panic re-scan with async-SB on is clean end to end).
const SEEDS: u64 = 64;

/// Seeds that historically caught a real bug, pinned as regression protection even above the contiguous
/// `0..SEEDS` range. All pass with the async-superblock mode on; these guard against any of those
/// specific divergences/wedges ever returning. The `vsr_headers` recovery fix is also covered
/// by the contiguous range, but stays pinned here as an explicit named guard against its return.
const REGRESSION_SEEDS: &[u64] = &[
  21, 52, 84, 89, 90, 103, 120, 131, 151, 164, 197, 253, 299, 313, 335, 464, 622,
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
  for seed in (0..SEEDS).chain(REGRESSION_SEEDS.iter().copied()) {
    let r = run_vopr(seed, DEFAULT_TICKS);
    total_committed += r.max_committed();
    total_crashes += r.crashes();
    total_restarts += r.restarts();
    total_partitions += r.partitions();
    total_pending_view_windows += r.pending_view_windows_seen();
    max_recovered_band = max_recovered_band.max(r.recovered_band_max());
    total_forced_syncs += r.forced_syncs();
    total_misdirects += r.misdirects_fired();
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
  // - large `checkpoint_ops` materialized a NON-trivial recovered committed band (well above the small
  //   interval's ~12 ceiling), so the large-checkpoint recover read-window path (`commit_max` far above
  //   `checkpoint_op`) is exercised over a real multi-hundred-op band, not always a tiny one;
  // - the misdirected-read axis fired, exercising the recovery/repair placement-integrity checks
  //   (`header.op() == op`) that the DST otherwise never reaches;
  // - the two-slot/redundant-copy superblock (finding B) still drives GENUINE peer-fetch escalations
  //   (only the SPURIOUS orphaned-checkpoint ones were removed) — `forced_syncs > 0` proves a replica
  //   really had to fetch a checkpoint/op from a peer because its own disk could not serve it.
  assert!(
    max_recovered_band > 50,
    "no seed recovered a non-trivial committed band (max={max_recovered_band}) — the \
     large-checkpoint_ops axis is vacuous"
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

/// Replay a SINGLE seed in isolation, with output captured, for debugging a sweep failure. Set `SEED`
/// to the seed of interest and run with `--ignored --nocapture`. (Ignored so it does not run in the
/// normal sweep; it is a debugging aid, not a gate.) Pair with the `VOPR_DUMP` / `VOPR_TRACE` /
/// `VOPR_NO_*` env switches in `src/vopr.rs` to dump divergence state, trace actions, or shrink the
/// fault set while staying on the exact same seeded schedule. (The sweep is currently clean to `0..256`;
/// set `SEED` to any seed you want to inspect — e.g. a historical bug-finder like 24, 36, or 164.)
#[test]
#[ignore = "single-seed replay: set SEED and run with --ignored --nocapture to debug a sweep failure"]
fn replay_single_seed() {
  const SEED: u64 = 36;
  let r = run_vopr_one(SEED);
  println!(
    "vopr seed {} OK: ticks={} replicas={} clients={} max_committed={} crashes={} restarts={} \
     partitions={} heals={} calm_windows={} max_view={} all_clients_done={} \
     wal_capacity={:?} wal_stalls={} below_ring_window_syncs={} bounded_seed_wrapped={}",
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
    r.bounded_seed_wrapped(),
  );
}

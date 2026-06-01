//! VOPR sweep: the seeded adversarial driver (`run_vopr`) over a seed range, asserting no panics.
//!
//! Each seed builds a fresh cluster (size 3 or 5, async WAL, seeded storage + network faults) and
//! explores a randomized adversarial schedule WITHIN the crash-stop fault model (a quorum always
//! survives), with safety/durability/view-monotonicity/boundedness/append-before-ack/structural
//! invariants checked EVERY tick and liveness checked across calm windows. `run_vopr` panics on any
//! violation with the seed + tick, so this test simply runs the sweep and lets a violation surface.
//!
//! Determinism is mandatory: `run_vopr(seed, ticks)` is a pure function of `(seed, ticks)`. To re-run
//! a single failing seed in isolation, see the `#[ignore]` replay test below (set its seed and run
//! `cargo test -p vsrr-simulation --test vopr replay_single_seed -- --ignored --nocapture`).
//!
//! # Coverage: `0..SEEDS` contiguous + pinned regression seeds (`0..512` scans clean with async-SB on)
//!
//! The sweep runs a contiguous `0..SEEDS` range PLUS an explicit [`REGRESSION_SEEDS`] list of every
//! seed that historically caught a real bug, so those stay pinned even above the contiguous range. A
//! wide catch-panic scan `0..512` at [`DEFAULT_TICKS`] with the async-superblock mode ON is verified
//! clean end to end (including seed 313, fixed by the final-quiesce phase — see below); the committed
//! `SEEDS` is kept smaller only to bound the gate's wall-clock (each seed runs a few thousand ticks of
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
//! `…77` elsewhere, for seed 253). At-most-once held throughout (no second op minted, no request
//! committed twice). FIXED in two places: (1) `adopt_canonical_head` / `start_view_as_new_primary` now
//! `wal.truncate` above the adopted canonical head, dropping the uncommitted divergent suffix from the
//! WAL at the source (no durability dip — only uncommitted ops are removed); (2) `recover` extends the
//! `vsr_headers` cross-check — a self-verifying tail slot ABOVE the durable committed frontier whose
//! original header `view` is below the durable `log_view` is a superseded earlier-view proposal, so it
//! is dropped + peer-repaired instead of trusted (this catches the INTERIOR committed-band variant — seed
//! 335 — that the head truncation cannot, where the stale slot sits below the adopted offset-log's floor).
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
//! - **seed 17** — append-before-ack re-ack hole (the `appending` set is not a durability oracle; the
//!   re-ack now consults the WAL's durable status directly);
//! - **seed 24** (+ 29, 49, 84, 89, 90, 120, 131, 197) — adoption preserved a stale UNAPPLIED held copy
//!   of a committed op the offset canonical log omits (a superseded earlier-view proposal), diverging
//!   the committed log; fixed by preserving only the APPLIED prefix (`op <= commit_min`) and repairing
//!   the omitted committed band from a peer;
//! - **seed 36** — liveness wedge: a primary stuck on an unfillable committed hole now forfeits so a
//!   healthy replica can take over;
//! - **seed 52** — adoption WAL-staleness committed-divergence: `recover` blindly re-derived a committed
//!   op from the WAL, resurrecting a STALE superseded body an adoption never re-wrote there. Fixed by
//!   persisting the canonical committed-band headers (TigerBeetle's `vsr_headers`) in the durable
//!   `VsrState` and having `recover` cross-check each committed-band WAL slot against them, routing a
//!   mismatch to peer-repair instead of trusting the stale body (NO wal.truncate, so NO durability dip);
//! - **seeds 253 + 299 + 335** — recover re-loaded a SUPERSEDED earlier-view tail op from the WAL and
//!   `advance_commit` applied its stale body for an op the new view committed with a different value
//!   (committed-divergence across partition-heal + view-change + async-superblock + duplication). Fixed by
//!   (1) truncating the WAL above the adopted canonical head on view adoption, and (2) extending the
//!   `vsr_headers` recover cross-check to drop an above-durable-commit tail slot whose original header
//!   `view` is below the durable `log_view` (a superseded proposal) → peer-repair the canonical body;
//! - **seeds 164 + 103** — forced state-sync discarded an acked tail above the synced checkpoint;
//! - **seed 151** — a view-monotonic CHECKER over-sensitivity, not a proto bug: it watched the volatile
//!   in-memory view across a restart, but a replica safely reverts to its DURABLE view on recovery (it
//!   never participated in the un-durable view) and re-catches-up on the next higher-view message; the
//!   checker now tracks the durable view;
//! - **seed 313** — a final-INSTANT durability-CHECKER artifact, not a proto bug: the run ended on a tick
//!   where a committed op the operational survivors held DURABLY on a quorum's WAL (the per-tick
//!   structural quorum-durability check correctly never fired) had been APPLIED only by a since-crashed
//!   replica, so the end-of-run "applied by an operational replica" assertion was stricter than VSR's
//!   true durable-quorum-retention guarantee; `run_vopr` now runs a bounded final QUIESCE phase
//!   (TigerBeetle's `transition_to_liveness_mode`) to converge the survivors before the end-of-run
//!   assertions, kept strict (a committed op held by no quorum never converges and is reported).

use vsrr_simulation::{DEFAULT_TICKS, run_vopr, run_vopr_one};

/// The contiguous committed seed range (kept modest to bound the gate's wall-clock). Correctness
/// coverage over raw count: each seed runs a few thousand ticks of rich adversarial schedule. With the
/// async-superblock mode ON in [`run_vopr`] (the pending-durable-view window, codex R8-F1), this whole
/// `0..SEEDS` range is verified clean — including seed 52, fixed by the `vsr_headers` recovery
/// cross-check (a wide `0..512` catch-panic re-scan with async-SB on is clean end to end, including
/// seed 313, fixed by the final-quiesce phase in [`run_vopr`]).
const SEEDS: u64 = 64;

/// Seeds that historically caught a real bug, pinned as regression protection even above the contiguous
/// `0..SEEDS` range. All pass with the async-superblock mode on; these guard against any of those
/// specific divergences/wedges ever returning. Seed 52 (the `vsr_headers` recovery fix) is also covered
/// by the contiguous range, but stays pinned here as an explicit named guard against its return.
const REGRESSION_SEEDS: &[u64] = &[
  52, 84, 89, 90, 103, 120, 131, 151, 164, 197, 253, 299, 313, 335,
];

#[test]
fn vopr_sweep_no_violations() {
  let mut total_committed = 0usize;
  let mut total_crashes = 0u64;
  let mut total_restarts = 0u64;
  let mut total_partitions = 0u64;
  let mut seeds_with_view_change = 0u64;
  let mut total_pending_view_windows = 0u64;
  for seed in (0..SEEDS).chain(REGRESSION_SEEDS.iter().copied()) {
    let r = run_vopr(seed, DEFAULT_TICKS);
    total_committed += r.max_committed();
    total_crashes += r.crashes();
    total_restarts += r.restarts();
    total_partitions += r.partitions();
    total_pending_view_windows += r.pending_view_windows_seen();
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
  // R8-F1 non-vacuity: the async-superblock mode must actually OPEN the pending-durable-view window
  // (a Normal primary whose view is not yet durable) somewhere across the sweep — otherwise the
  // durable-view-before-participate gates (codex R8-F1) are being checked vacuously. `> 0` proves a
  // seed drove a replica into that window while a view-change root write was in flight.
  assert!(
    total_pending_view_windows > 0,
    "async-superblock never opened the pending-durable-view window — the R8-F1 gate is untested"
  );
}

/// Regression for VOPR seed 313: a FINAL-INSTANT durability-checker artifact, NOT a proto loss.
///
/// At the run's last tick the committed-history high-water op (1141) was APPLIED only by a replica
/// that happened to be CRASHED at that instant, while two OPERATIONAL survivors held that op DURABLY
/// on their WAL (so the committed op was retained by a quorum — the per-tick structural
/// quorum-durability check never fired) but had not yet APPLIED it (commit catch-up still in flight,
/// their `commit_max` had not yet learned op 1141 was committed). The end-of-run durability assertion
/// asked for the committed history to be APPLIED by an operational replica AT THAT ARBITRARY INSTANT —
/// strictly stronger than VSR's true guarantee (a committed op survives on a quorum's DURABLE storage;
/// application is local catch-up that completes eventually). The fix gives [`run_vopr`] a final
/// bounded QUIESCE phase (heal everything, restart all, no faults, tick to convergence) BEFORE the
/// end-of-run assertions — exactly TigerBeetle's VOPR `transition_to_liveness_mode` discipline — so the
/// survivors apply the durably-held committed tail before the check. (Verified: from that final instant
/// a healed cluster converges all five replicas to applied=1141 in ~74 ticks.) This run is a pure
/// function of the seed, so the artifact reproduces exactly and the drained run must now pass.
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
    "seed 313 commits a long history (got {})",
    r.max_committed()
  );
  assert!(
    r.crashes() > 0 && r.restarts() > 0 && r.max_view() >= 1,
    "seed 313 exercised crash/restart + failover before the final quiesce (crashes={}, restarts={}, \
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
     partitions={} heals={} calm_windows={} max_view={} all_clients_done={}",
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
  );
}

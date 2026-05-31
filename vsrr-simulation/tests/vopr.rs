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
//! # Coverage: `0..SEEDS` contiguous + pinned regression seeds (a full `0..256` scan is clean)
//!
//! The sweep runs a contiguous `0..SEEDS` range PLUS an explicit [`REGRESSION_SEEDS`] list of every
//! seed that historically caught a real bug, so those stay pinned even above the contiguous range. A
//! full `0..256` scan at [`DEFAULT_TICKS`] is verified clean; the committed `SEEDS` is kept smaller
//! only to bound the gate's wall-clock (each seed runs a few thousand ticks of rich adversarial
//! schedule).
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
//! - **seeds 164 + 103** — forced state-sync discarded an acked tail above the synced checkpoint;
//! - **seed 151** — a view-monotonic CHECKER over-sensitivity, not a proto bug: it watched the volatile
//!   in-memory view across a restart, but a replica safely reverts to its DURABLE view on recovery (it
//!   never participated in the un-durable view) and re-catches-up on the next higher-view message; the
//!   checker now tracks the durable view.

use vsrr_simulation::{DEFAULT_TICKS, run_vopr, run_vopr_one};

/// The contiguous committed seed range (kept modest to bound the gate's wall-clock; a full `0..256`
/// scan is verified clean — see the module note). Correctness coverage over raw count: each seed runs a
/// few thousand ticks of rich adversarial schedule.
const SEEDS: u64 = 64;

/// Seeds that historically caught a real bug, pinned as regression protection even above the contiguous
/// `0..SEEDS` range. All now pass (the full `0..256` scan is clean); these guard against any of those
/// specific divergences/wedges ever returning.
const REGRESSION_SEEDS: &[u64] = &[84, 89, 90, 103, 120, 131, 151, 164, 197];

#[test]
fn vopr_sweep_no_violations() {
  let mut total_committed = 0usize;
  let mut total_crashes = 0u64;
  let mut total_restarts = 0u64;
  let mut total_partitions = 0u64;
  let mut seeds_with_view_change = 0u64;
  for seed in (0..SEEDS).chain(REGRESSION_SEEDS.iter().copied()) {
    let r = run_vopr(seed, DEFAULT_TICKS);
    total_committed += r.max_committed();
    total_crashes += r.crashes();
    total_restarts += r.restarts();
    total_partitions += r.partitions();
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

//! Byte-identity digest sweep: one stable line per seed, fingerprinting everything a seeded run
//! observably produces, so two checkouts can be run and their outputs diffed — identical lines prove
//! the seeds' schedules and applied histories are byte-identical across the checkouts.
//!
//! For each seed in `0..VOPR_SEEDS` (default 64, the same override as the committed sweep) one line
//! is printed:
//!
//! ```text
//! digest seed=<seed> applied=<hex> report=<hex> committed=<n>
//! ```
//!
//! - `applied` — an FNV-1a fold of a fixed deterministic [`Cluster`] schedule's full observable
//!   output: every replica's applied `(op, body)` log and every client's acked replies, across a
//!   crash + restart, a wipe-and-restart, and a final heal-drain. A single diverging applied byte,
//!   op number, or reply changes the hash.
//! - `report` — an FNV-1a fold of every [`VoprReport`] counter of `run_vopr(seed, DEFAULT_TICKS)`.
//!   The adversarial schedule is a pure function of the seed, so any extra/missing PRNG draw,
//!   message, or schedule perturbation cascades into these counters.
//!
//! Run with:
//! `cargo test --release -p viewstamp-simulation --test vopr_digest -- --ignored --nocapture`
//! (optionally `VOPR_SEEDS=<n>` for a wider range), capture the `digest ` lines, and diff them
//! across the two checkouts. The deterministic suites assert per-seed correctness; this harness only
//! asserts nothing about the values — its output IS the gate.

use core::time::Duration;

use viewstamp_simulation::{Cluster, DEFAULT_TICKS, Faults, VoprReport, run_vopr};

/// The default contiguous seed count, overridable via `VOPR_SEEDS` like the committed sweep.
const SEEDS: u64 = 64;

/// The FNV-1a 64-bit offset basis.
const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;

/// The contiguous seed count to sweep this run: `VOPR_SEEDS` if set and parseable, else [`SEEDS`].
fn sweep_seed_count() -> u64 {
  std::env::var("VOPR_SEEDS")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(SEEDS)
}

/// Folds `bytes` into the running FNV-1a hash `h`.
fn fnv1a_bytes(h: &mut u64, bytes: &[u8]) {
  for &b in bytes {
    *h ^= u64::from(b);
    *h = h.wrapping_mul(0x100_0000_01b3);
  }
}

/// Folds one scalar into the running FNV-1a hash `h` (big-endian, so widths are unambiguous).
fn fnv1a_u64(h: &mut u64, v: u64) {
  fnv1a_bytes(h, &v.to_be_bytes());
}

/// The applied-history digest of a FIXED deterministic cluster schedule for `seed`: a lossy network
/// (drops + duplicates + jitter), a crash + restart, a wipe-and-restart, then a fault-free
/// heal-drain — exercising commit, recovery, and amnesia re-replication — folded over every
/// replica's applied `(op, body)` log and every client's acked replies.
fn applied_digest(seed: u64) -> u64 {
  let mut c = Cluster::new(3, 2, 6, seed);
  c.set_faults(Faults {
    latency: Duration::from_millis(1),
    jitter: Duration::from_millis(2),
    drop_per_mille: 50,
    duplicate_per_mille: 100,
    hold_per_mille: 0,
  });
  for t in 0..3_000u32 {
    match t {
      600 => c.crash(1),
      1_000 => c.restart(1),
      1_600 => c.crash(2),
      2_000 => c.wipe_and_restart(2),
      _ => {}
    }
    c.tick();
  }
  c.set_faults(Faults::none());
  for _ in 0..4_000 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  let mut h = FNV_OFFSET;
  for i in 0..c.replica_count() {
    fnv1a_u64(&mut h, c.replica_sm(i).applied().len() as u64);
    for (op, body) in c.replica_sm(i).applied() {
      fnv1a_u64(&mut h, *op);
      fnv1a_u64(&mut h, body.len() as u64);
      fnv1a_bytes(&mut h, body);
    }
  }
  for i in 0..c.client_count() {
    fnv1a_u64(&mut h, c.client(i).replies().len() as u64);
    for (request, body) in c.client(i).replies() {
      fnv1a_u64(&mut h, *request);
      fnv1a_u64(&mut h, body.len() as u64);
      fnv1a_bytes(&mut h, body);
    }
  }
  h
}

/// Folds every [`VoprReport`] counter into one FNV-1a digest, in a fixed field order.
fn report_digest(r: &VoprReport) -> u64 {
  let mut h = FNV_OFFSET;
  for v in [
    r.seed(),
    r.ticks(),
    r.replicas() as u64,
    r.clients() as u64,
    r.max_committed() as u64,
    r.crashes(),
    r.restarts(),
    r.partitions(),
    r.heals(),
    r.calm_windows(),
    r.max_view(),
    u64::from(r.all_clients_done()),
    r.pending_view_windows_seen(),
    r.misdirects_fired(),
    r.recovered_band_max(),
    r.forced_syncs(),
    // `+ 1` keeps `None` (0) distinct from any bounded ring size.
    r.wal_capacity().map_or(0, |n| n + 1),
    r.wal_stalls(),
    r.below_ring_window_syncs(),
    r.sync_chunk_transfers(),
    u64::from(r.bounded_seed_wrapped()),
    r.large_bodies_sent(),
    r.oversized_dropped(),
    r.holds_fired(),
    r.unions_floored(),
    r.repair_batches_served(),
    r.prepare_batches_sent(),
    r.header_only_carriers_emitted(),
    r.wipes_fired(),
    r.torn_headers_fired(),
    r.churns_fired(),
    r.sessions_evicted(),
    r.asym_episodes(),
    r.one_way_dropped(),
    r.slow_episodes(),
    r.slow_delays(),
  ] {
    fnv1a_u64(&mut h, v);
  }
  h
}

#[test]
#[ignore = "digest sweep: prints one stable line per seed for cross-checkout byte-identity diffing"]
fn vopr_digest_sweep() {
  let count = sweep_seed_count();
  for seed in 0..count {
    let r = run_vopr(seed, DEFAULT_TICKS);
    let applied = applied_digest(seed);
    let report = report_digest(&r);
    println!(
      "digest seed={seed} applied={applied:016x} report={report:016x} committed={}",
      r.max_committed()
    );
  }
}

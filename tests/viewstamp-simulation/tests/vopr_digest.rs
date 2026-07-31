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
      // Wiping voter 2 now FAILS-STOP it (an empty-log voter must not rejoin the voting set); it stays
      // down and the cluster survives one voter short. (Before the wipe-amnesia fix it rejoined empty,
      // so this digest legitimately diverges from that history in the post-wipe portion.)
      2_000 => {
        c.wipe_and_restart(2);
      }
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
    // The batching witnesses: identically zero with the axis off, so default-lane digests are
    // unchanged by their presence — and a regression that accidentally engaged batching draws
    // perturbs the digest loudly.
    r.bodies_with_multiple_units(),
    r.max_units_per_body(),
    r.groups_submitted(),
    // The stale-read witnesses are deliberately NOT folded here: they are zero on the default
    // schedule, but folding a field changes this report hash's schema, which would make the report
    // column differ between checkouts for a reason other than a behavioral change. The report hash
    // stays a stable cross-checkout quantity; an accidental off-axis stale-read engagement would
    // depose a primary and so perturb the applied-history and committed digest columns regardless.
    // The learner witnesses (learner_ops_applied / learner_repairs_served /
    // learner_view_changes_followed) are likewise NOT folded, for the same reason: zero on the
    // default schedule, and folding them would change this hash's schema for a non-behavioral reason.
    // The learner axis only GROWS node_count behind a separate magic-seeded draw, so an off-axis run
    // never engages it and the applied/committed columns (over the no-learner default schedule) stay
    // identical regardless. The offline reconfig witnesses (reconfigs_fired / reform_escalations_fired)
    // are NOT folded for the same reason: both are zero on the default schedule (the reconfig axis is
    // off, and its escalation is off-axis-unsatisfiable), so folding them would change the report
    // hash's schema without any behavioral change — the off-axis `reform_escalations_fired == 0` guard
    // lives in the committed sweep instead (an accidental off-axis engagement would re-form a wedge and
    // so perturb the applied/committed columns regardless).
  ] {
    fnv1a_u64(&mut h, v);
  }
  h
}

/// Pinned baseline `(applied, report)` digests for the first few seeds, captured on `main` BEFORE the
/// live-reconfiguration axis landed. The opt-in live-reconfig axis (and its always-on checker
/// plumbing + `MembershipChanged` capture) must be byte-identical to `main` when OFF — the cluster's
/// replicas now carry the `SingleChange` capability marker (a zero-sized runtime-inert witness), the
/// per-tick swap-correctness checkers observe an EMPTY swap stream off-axis (no PRNG draw, no
/// mutation), and the live-reconfig firing is conditional on the axis (no draw consumed off-axis). So
/// the default-schedule applied history AND the report counters are unchanged. This is the committed
/// in-process guard for that: a future change that perturbs the off-axis schedule (an extra draw, a
/// reordered action, a captured-but-mutating observer) breaks one of these and fails here with the
/// exact seed. (The `#[ignore]`d [`vopr_digest_sweep`] above is the wider cross-checkout diff tool.)
/// The APPLIED-history digests are unchanged from `main` — the block-DAG state-sync migration is
/// behaviour-preserving (the consensus applied stream + replies are byte-identical). The REPORT
/// digests were re-pinned because the retired `sync_chunk_transfers` observability counter (always 0
/// off-axis, an artefact of the removed over-frame chunked path) was dropped from the report fold; its
/// removal shifts the FNV-folded report hash without any behavioural change.
const BASELINE_DIGESTS: &[(u64, u64, u64)] = &[
  (0, 0x3011_cd95_7970_09d6, 0x5310_fabf_544b_7a19),
  (1, 0x8180_484c_aaf2_15a4, 0x704d_dc76_945b_97c0),
  (2, 0x27fd_ef6b_3b83_c631, 0x07a5_5860_35bf_4bf9),
  (3, 0x94d1_3cab_40a7_0dc2, 0x0249_a3f9_dcb7_b704),
];

#[test]
fn off_axis_digest_is_byte_identical_to_the_pre_reconfig_baseline() {
  for &(seed, want_applied, want_report) in BASELINE_DIGESTS {
    let got_applied = applied_digest(seed);
    assert_eq!(
      got_applied, want_applied,
      "seed {seed}: the default-schedule APPLIED-history digest changed ({got_applied:#018x} vs \
       baseline {want_applied:#018x}) — the live-reconfig axis (or its off-axis plumbing) perturbed \
       the default schedule; it must be byte-identical when OFF"
    );
    let got_report = report_digest(&run_vopr(seed, DEFAULT_TICKS));
    assert_eq!(
      got_report, want_report,
      "seed {seed}: the default-schedule REPORT digest changed ({got_report:#018x} vs baseline \
       {want_report:#018x}) — an extra PRNG draw or schedule perturbation leaked into the default run"
    );
  }
}

/// A run's digests must not depend on how many endpoints the PROCESS built before it.
///
/// Storage correlation ids carry the incarnation of the endpoint that minted them, drawn from a
/// process-wide counter. That counter is deliberately outside the deterministic simulation: its value
/// depends on how many endpoints happen to have been constructed, so if it ever reached an applied
/// stream, a report counter, an `Event`, or the ordering of an id-keyed map, the same seed would
/// digest differently depending on what else ran first — test order would decide the result, and
/// every pinned baseline in this file would become a coin flip.
///
/// So: digest a seed, build a throwaway cluster to advance the counter by several endpoints, and
/// digest the same seed again. The two must be identical. The counter already advances during the
/// first run, so the second run would draw different incarnations regardless; the throwaway cluster
/// makes the gap between them large and unrelated to what either run consumes, so a leak cannot hide
/// behind the two runs happening to line up.
#[test]
fn digests_are_independent_of_the_process_wide_endpoint_incarnation() {
  const SEED: u64 = 1;
  let before_applied = applied_digest(SEED);
  let before_report = report_digest(&run_vopr(SEED, DEFAULT_TICKS));

  // Build and drop endpoints so the next cluster's replicas mint ids under different incarnations
  // than the first run's did. Ticking is what forces those endpoints to actually issue storage ops.
  let mut interfering = Cluster::new(5, 2, 40, /*seed*/ 999);
  for _ in 0..50 {
    interfering.tick();
  }
  drop(interfering);

  let after_applied = applied_digest(SEED);
  let after_report = report_digest(&run_vopr(SEED, DEFAULT_TICKS));
  assert_eq!(
    before_applied, after_applied,
    "the APPLIED-history digest for seed {SEED} changed after unrelated endpoints were constructed \
     ({before_applied:#018x} then {after_applied:#018x}) — the storage-correlation incarnation is \
     reaching the applied history, so the same seed no longer replays the same run"
  );
  assert_eq!(
    before_report, after_report,
    "the REPORT digest for seed {SEED} changed after unrelated endpoints were constructed \
     ({before_report:#018x} then {after_report:#018x}) — a report counter is observing the \
     process-wide incarnation instead of the seeded schedule"
  );
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

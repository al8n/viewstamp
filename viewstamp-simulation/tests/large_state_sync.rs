//! Large-snapshot state-sync gate: a checkpoint envelope PAST the one-frame budget converges a
//! long-down replica via the CHUNKED transfer (`SyncCheckpointMeta` → `RequestSyncChunk` →
//! `SyncChunk`), under a clean network, under drop/dup faults, across a donor crash mid-transfer,
//! and under sustained load that checkpoints the donor forward mid-transfer.
//!
//! ## The would-have-wedged precondition (what makes this gate non-vacuous)
//!
//! `LogSm::snapshot` is the FULL applied history, so fixed large client bodies grow the checkpoint
//! envelope linearly with committed ops. Each run first drives load until the DURABLE envelope
//! exceeds `max_unchunked_snapshot_len()` — the exact threshold past which a whole `SyncCheckpoint`
//! encodes over `MAX_FRAME_LEN` and the transport's send-path frame guard would drop it. Before the
//! chunked transfer, a laggard below such a checkpoint was a PERMANENT liveness wedge: it solicits
//! on the 100ms cadence, every serve is refused at the frame guard, and `on_prepare` drops
//! head-extends while `sync.is_some()`. The cluster.rs converse test pins that drop; this gate
//! proves the chunked path delivers the same envelope.
//!
//! ## Non-vacuity
//!
//! Convergence alone could be satisfied by the single-frame fast path on a small envelope, so every
//! run asserts: the envelope genuinely exceeded the threshold at sync time (the wedge
//! precondition); `replica_state_sync_count >= 1` (a sync genuinely installed);
//! `sync_chunk_transfers_completed >= 1` (the CHUNKED path carried it); and `oversized_dropped ==
//! 0` (no serve was ever refused at the frame guard — the chunked path never produces an oversized
//! frame).
//!
//! `check_safety` (agreement) and the `DurabilityChecker` (no committed op rewritten/lost across
//! the crash + sync window) run SAMPLED rather than per tick: both compare full applied CONTENT,
//! which at tens of MiB of bodies costs ~100 MB of comparison per call — per-tick they would
//! dominate the run. The per-tick full-fidelity nets remain the standing small-body gates; here the
//! sampled cadence still brackets every phase boundary plus the final no-loss check.

use core::time::Duration;
use viewstamp_proto::max_unchunked_snapshot_len;
use viewstamp_simulation::{CheckResult, Cluster, DurabilityChecker, Faults, check_safety};

/// Fixed per-request body size: 1/32 of the max deliverable body (~512 KiB), so ~33 committed ops
/// push the envelope past the ~16 MiB one-frame threshold within a short run.
fn big_body_len() -> usize {
  viewstamp_proto::max_request_body_len() / 32
}

/// Run the sampled safety + durability checks (content-comparing — see the module doc).
fn check(seed: u64, phase: &str, c: &Cluster, dur: &mut DurabilityChecker) {
  assert!(dur.observe(c).is_ok(), "seed {seed}: durability ({phase})");
  assert_eq!(
    check_safety(c),
    CheckResult::Ok,
    "seed {seed}: safety ({phase})"
  );
}

/// What one scenario run measured (for the cross-seed non-vacuity sums).
struct Outcome {
  /// The laggard's completed chunked transfers at convergence (>= 1 asserted per run).
  transfers: u64,
  /// The pinned donor was crashed mid-transfer (only in the donor-crash variant).
  donor_crashed: bool,
  /// The cluster checkpoint advanced between the transfer's first pin and the laggard's install —
  /// the donor checkpointed FORWARD mid-sync (the sustained-advance witness).
  advanced_mid_transfer: bool,
}

/// The shared scenario: grow the envelope past the one-frame threshold, crash a laggard across
/// checkpoints, restart it, and converge via the chunked transfer. `faults` shapes the network;
/// `crash_donor_mid_transfer` crashes the pinned donor the moment a transfer is observed;
/// `requests_per_client`/`checkpoint_ops` size the load and cadence per variant.
fn run_scenario(
  seed: u64,
  faults: Option<Faults>,
  crash_donor_mid_transfer: bool,
  requests_per_client: u64,
  checkpoint_ops: u64,
) -> Outcome {
  // N=5: one crashed laggard (plus, in the donor-crash variant, one crashed donor) still leaves a
  // committing majority.
  let mut c = Cluster::with_checkpoint_ops(5, 2, requests_per_client, seed, checkpoint_ops);
  c.set_fixed_client_body_len(big_body_len());
  if let Some(f) = faults {
    c.set_faults(f);
  }
  let mut dur = DurabilityChecker::new(c.replica_count());
  let laggard = 2usize;

  // Phase 1: drive load until the DURABLE envelope exceeds the one-frame threshold — from here on,
  // any state-sync serve of this checkpoint can only travel chunked.
  let mut warmed = false;
  for t in 0..200_000u64 {
    c.tick();
    if t % 128 == 0 {
      check(seed, "warm-up", &c, &mut dur);
    }
    if c
      .replica_durable_envelope_len(0)
      .is_some_and(|len| len > max_unchunked_snapshot_len())
    {
      warmed = true;
      break;
    }
  }
  assert!(
    warmed,
    "seed {seed}: the checkpoint envelope grew past max_unchunked_snapshot_len() (the \
     would-have-wedged precondition)"
  );
  check(seed, "warmed", &c, &mut dur);

  let laggard_head_before = c.replica_checkpoint_op(laggard).get();
  assert_eq!(
    c.replica_state_sync_count(laggard),
    0,
    "seed {seed}: laggard has not state-synced before the crash"
  );
  assert_eq!(
    c.replica_sync_chunk_transfers_completed(laggard),
    0,
    "seed {seed}: laggard has not chunk-transferred before the crash"
  );

  // Phase 2: crash the laggard and keep it down across further checkpoints, so its head falls
  // below the cluster checkpoint (state-sync is then its ONLY recovery) — and that checkpoint's
  // envelope stays past the threshold (only the CHUNKED path can deliver it).
  c.crash(laggard);
  let target_cluster_ckpt = laggard_head_before + 2 * checkpoint_ops;
  let mut moved_past = false;
  for t in 0..400_000u64 {
    c.tick();
    if t % 128 == 0 {
      check(seed, "crashed", &c, &mut dur);
    }
    if c.replica_checkpoint_op(0).get() >= target_cluster_ckpt {
      moved_past = true;
      break;
    }
  }
  assert!(
    moved_past,
    "seed {seed}: the cluster checkpointed past the laggard's head while it was down \
     (cluster {} >= {laggard_head_before} + {})",
    c.replica_checkpoint_op(0).get(),
    2 * checkpoint_ops,
  );
  let cluster_ckpt_while_down = c.replica_checkpoint_op(0).get();
  let env_at_sync = c
    .replica_durable_envelope_len(0)
    .expect("a rooted checkpoint exists");
  assert!(
    env_at_sync > max_unchunked_snapshot_len(),
    "seed {seed}: the envelope the laggard must fetch ({env_at_sync} bytes) exceeds the one-frame \
     threshold ({}) — a whole SyncCheckpoint would be refused at the frame guard",
    max_unchunked_snapshot_len(),
  );

  // The highest checkpoint on any live replica (the donor-crash variant may take replica 0 down).
  let max_live_ckpt = |c: &Cluster| {
    (0..c.replica_count())
      .filter(|&i| !c.is_crashed(i))
      .map(|i| c.replica_checkpoint_op(i).get())
      .max()
      .unwrap_or(0)
  };

  // Phase 3: restart the laggard; it recovers to its stale head, hears the cluster checkpoint past
  // its head, and must state-sync — over the chunked transfer, since the envelope is over-frame.
  c.restart(laggard);
  let mut donor_crashed = false;
  let mut ckpt_at_pin: Option<u64> = None;
  let mut advanced_mid_transfer = false;
  let mut converged = false;
  for t in 0..400_000u64 {
    c.tick();
    if t % 128 == 0 {
      check(seed, "syncing", &c, &mut dur);
    }
    if let Some(d) = c.replica_sync_transfer_donor(laggard) {
      if ckpt_at_pin.is_none() {
        ckpt_at_pin = Some(max_live_ckpt(&c));
      }
      // The donor-crash variant: kill the pinned donor the moment the transfer is observed —
      // forcing the dead-donor replacement (re-broadcast → a fresh announce re-pins; the staged
      // prefix survives the failover).
      if crash_donor_mid_transfer && !donor_crashed && !c.is_crashed(d as usize) {
        c.crash(d as usize);
        donor_crashed = true;
      }
    }
    if !advanced_mid_transfer
      && c.replica_state_sync_count(laggard) >= 1
      && ckpt_at_pin.is_some_and(|at_pin| max_live_ckpt(&c) > at_pin)
    {
      advanced_mid_transfer = true;
    }
    if (0..c.client_count()).all(|i| c.client(i).is_done())
      && c.replica_state_sync_count(laggard) >= 1
      && c.replica_sync_chunk_transfers_completed(laggard) >= 1
      && c.replica_status_is_operational(laggard)
      && c.replica_checkpoint_op(laggard).get() >= cluster_ckpt_while_down
    {
      converged = true;
      break;
    }
  }
  assert!(
    converged,
    "seed {seed}: the laggard converged via the chunked transfer (sync_count={}, transfers={}, \
     checkpoint_op={}, target>={cluster_ckpt_while_down}, donor_crashed={donor_crashed})",
    c.replica_state_sync_count(laggard),
    c.replica_sync_chunk_transfers_completed(laggard),
    c.replica_checkpoint_op(laggard).get(),
  );

  // NON-VACUITY: the CHUNKED path carried the sync (not the single-frame fast path), and no serve
  // was ever refused at the modelled frame guard — the chunked path never frames oversized.
  let transfers = c.replica_sync_chunk_transfers_completed(laggard);
  assert!(
    transfers >= 1,
    "seed {seed}: VACUOUS — the laggard synced without a chunked transfer"
  );
  assert_eq!(
    c.oversized_dropped(),
    0,
    "seed {seed}: no inter-replica message exceeded the frame cap (the chunked path is the only \
     way an over-threshold envelope travels)"
  );
  // The laggard's checkpoint jumped past its pre-crash head (the signature of a sync).
  assert!(
    c.replica_checkpoint_op(laggard).get() > laggard_head_before,
    "seed {seed}: laggard's checkpoint ({}) advanced past its pre-crash head ({laggard_head_before})",
    c.replica_checkpoint_op(laggard).get()
  );
  // The synced replica's applied prefix agrees with a live caught-up replica end to end.
  let donor_like = (0..c.replica_count())
    .filter(|&i| !c.is_crashed(i) && i != laggard)
    .max_by_key(|&i| c.replica_sm(i).applied().len())
    .expect("a live caught-up replica exists");
  let n = c
    .replica_sm(laggard)
    .applied()
    .len()
    .min(c.replica_sm(donor_like).applied().len());
  assert!(n > 0, "seed {seed}: a non-trivial applied prefix");
  assert_eq!(
    c.replica_sm(laggard).applied()[..n],
    c.replica_sm(donor_like).applied()[..n],
    "seed {seed}: the chunk-synced replica's applied prefix agrees"
  );
  // The committed history survived end to end (including the down + transfer window).
  assert_eq!(
    dur.check(&c),
    CheckResult::Ok,
    "seed {seed}: every committed op survived the crash + chunked-sync window"
  );
  Outcome {
    transfers,
    donor_crashed,
    advanced_mid_transfer,
  }
}

#[test]
fn over_frame_envelope_state_syncs_via_chunked_transfer() {
  for seed in 0..3u64 {
    let o = run_scenario(seed, None, false, 26, 4);
    assert!(o.transfers >= 1);
  }
}

#[test]
fn chunked_transfer_converges_under_drop_and_dup_faults() {
  // Lost pulls/chunks are re-driven by the solicit-cadence ARQ (re-pull the frontier + re-announce);
  // duplicated chunks are inert (only the exact staged frontier extends the assembly).
  for seed in 0..2u64 {
    let o = run_scenario(
      seed,
      Some(Faults {
        latency: Duration::from_millis(1),
        jitter: Duration::from_millis(2),
        drop_per_mille: 20,
        duplicate_per_mille: 20,
        hold_per_mille: 0,
      }),
      false,
      26,
      4,
    );
    assert!(o.transfers >= 1);
  }
}

#[test]
fn chunked_transfer_survives_a_donor_crash_mid_transfer() {
  // The pinned donor is crashed the moment a transfer is observed: the receiver's re-broadcast
  // finds another holder, the fresh announce re-pins (staged prefix kept), and the transfer
  // completes off the replacement donor. A small latency keeps the transfer spanning enough virtual
  // time that the crash genuinely lands mid-pull.
  let mut crashed_mid_transfer = 0u32;
  for seed in 0..2u64 {
    let o = run_scenario(
      seed,
      Some(Faults {
        latency: Duration::from_millis(2),
        jitter: Duration::from_millis(1),
        drop_per_mille: 0,
        duplicate_per_mille: 0,
        hold_per_mille: 0,
      }),
      true,
      26,
      4,
    );
    assert!(o.transfers >= 1);
    crashed_mid_transfer += u32::from(o.donor_crashed);
  }
  assert!(
    crashed_mid_transfer > 0,
    "non-vacuity: at least one seed genuinely crashed the pinned donor mid-transfer"
  );
}

#[test]
fn chunked_transfer_completes_under_sustained_checkpoint_advance() {
  // Sustained load + a SHORT checkpoint interval keep the donors checkpointing forward while the
  // laggard's transfer is in flight — the ordinary sync's raised target must NOT discard the pinned
  // transfer (it completes below the raised freshness floor; the next trigger chases the newer
  // checkpoint). This is the measured form of the transfer-restart hazard: convergence is asserted
  // per seed, and at least one seed must witness the cluster checkpoint advancing between the
  // transfer's pin and the laggard's install.
  let mut advanced = 0u32;
  for seed in 0..2u64 {
    let o = run_scenario(
      seed,
      Some(Faults {
        latency: Duration::from_millis(3),
        jitter: Duration::from_millis(2),
        drop_per_mille: 0,
        duplicate_per_mille: 0,
        hold_per_mille: 0,
      }),
      false,
      40,
      2,
    );
    assert!(o.transfers >= 1);
    advanced += u32::from(o.advanced_mid_transfer);
  }
  assert!(
    advanced > 0,
    "non-vacuity: at least one seed checkpointed the cluster forward during the laggard's sync \
     window (the sustained-advance hazard was genuinely exercised)"
  );
}

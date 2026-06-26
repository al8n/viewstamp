//! The incremental-snapshots end-to-end oracle: the lasting regression net proving the
//! content-addressed block-DAG state-sync delivers its value in the deterministic simulation.
//!
//! A laggard holding a PRIOR checkpoint that catches up to a NEWER one over a mostly-unchanged
//! append-only log MUST:
//!
//! 1. fetch ONLY what changed — strictly fewer blocks than the full reachable set, because the
//!    shared earlier leaves it already holds (the append-only log keeps each full leaf's content
//!    address stable) are recognized and never re-fetched ([`incrementality_witness`]);
//! 2. recover from a CORRUPTED served block — a donor that ships bytes whose hash does not match the
//!    requested address is rejected, re-requested, and the sync still completes with correct state
//!    ([`corrupted_block_is_rejected_and_resynced`]);
//! 3. recover from a CORRUPT LOCAL block — a laggard whose OWN persistent checkpoint block has rotted
//!    under a still-valid root does not trust it on presence: the local-DAG drain treats it as missing,
//!    re-fetches a clean copy, and the sync still completes with correct state
//!    ([`corrupt_local_block_is_re_fetched_not_restored`]);
//! 4. reconstruct FAITHFULLY — a synced laggard's applied history equals the donor's after catch-up
//!    (asserted across every sweep, not one seed).
//!
//! ## The construction (shared by every lane)
//!
//! `N=5` (crashing one backup leaves a healthy 4-of-5 committing quorum), a SMALL checkpoint interval
//! (4) so the laggard checkpoints EARLY (its persistent block store holds several DAG generations),
//! and a finite client load. We:
//!
//! - warm up until the laggard has checkpointed a few generations (`checkpoint_op >= 12`) AND the
//!   survivors are caught up (a healthy quorum survives the laggard's crash);
//! - crash the laggard, then DRAIN all client load and let the surviving quorum QUIESCE so its
//!   checkpoint is STABLE — a single, fixed sync target. The log grew append-only, so the cluster's
//!   newer checkpoint DAG SHARES the laggard's earlier full leaves verbatim;
//! - restart the laggard. Its head is far below the cluster checkpoint, so the ORDINARY state-sync
//!   trigger fires; it fetches the stable target's DAG, reusing every shared leaf already in its
//!   store. Exactly ONE state-sync runs (`state_sync_count == 1`), so the block-fetch count is the
//!   `missing` set of that single sync — not an accumulation across a moving target.
//!
//! `check_safety` (agreement at an instant) and `DurabilityChecker` (no committed op rewritten/lost)
//! run throughout every lane. Multi-seed; every seed converges with correct, faithful state.

use core::time::Duration;

use viewstamp_simulation::{CheckResult, Cluster, DurabilityChecker, Faults, check_safety};

/// Voting replicas; one becomes the laggard.
const REPLICAS: u8 = 5;
/// The laggard replica index (a backup, so the other four form a committing quorum).
const LAGGARD: usize = 2;
/// A small checkpoint interval so the laggard checkpoints early and often (its block store holds
/// several DAG generations, the earlier of which the newer cluster checkpoint shares verbatim).
const CHECKPOINT_OPS: u64 = 4;

/// The base network profile: real latency + jitter + light loss, no holds (the held-vote axis is
/// orthogonal to this oracle). Identical across lanes so only the block axis under test differs.
fn base_faults() -> Faults {
  Faults {
    latency: Duration::from_millis(1),
    jitter: Duration::from_millis(2),
    drop_per_mille: 5,
    duplicate_per_mille: 0,
    hold_per_mille: 0,
  }
}

/// Drives `c` to a held-prior-checkpoint laggard poised to sync to a STABLE cluster checkpoint:
/// warms up, crashes the laggard, drains client load + quiesces the survivors. Returns the stable
/// `(cluster_checkpoint_op, total_reachable_blocks)` — `total` is the full block set a from-empty
/// laggard would fetch, the denominator of the incrementality witness. `dur`/safety are checked every
/// tick. Panics with the seed on any stall.
fn warm_crash_and_stabilize(
  c: &mut Cluster,
  dur: &mut DurabilityChecker,
  seed: u64,
) -> (u64, usize) {
  let check = |c: &Cluster, dur: &mut DurabilityChecker, phase: &str| {
    assert!(dur.observe(c).is_ok(), "seed {seed}: durability ({phase})");
    assert_eq!(
      check_safety(c),
      CheckResult::Ok,
      "seed {seed}: safety ({phase})"
    );
  };

  // (1) Warm up: the laggard checkpoints a few generations; the survivors stay caught up so a
  // healthy quorum survives its crash.
  let mut warmed = false;
  for _ in 0..2_000_000 {
    c.tick();
    check(c, dur, "warm-up");
    let survivors_ok = (0..c.replica_count()).all(|i| i == LAGGARD || c.replica_op(i).get() >= 40);
    if c.replica_checkpoint_op(LAGGARD).get() >= 12 && survivors_ok {
      warmed = true;
      break;
    }
  }
  assert!(
    warmed,
    "seed {seed}: laggard checkpointed a few generations and the survivors stayed caught up"
  );
  let lag_ckpt_pre = c.replica_checkpoint_op(LAGGARD).get();

  // (2) Crash the laggard; drain ALL client load and let the surviving quorum QUIESCE so its
  // checkpoint is STABLE (one fixed sync target) and well past the laggard's prior checkpoint.
  c.crash(LAGGARD);
  let mut drained = false;
  for _ in 0..6_000_000 {
    c.tick();
    check(c, dur, "drain");
    if (0..c.client_count()).all(|i| c.client(i).is_done())
      && c.replica_op(0).get() > lag_ckpt_pre + 20
    {
      // Let the final checkpoint settle so the sync target stops moving.
      for _ in 0..2_000 {
        c.tick();
        check(c, dur, "settle");
      }
      drained = true;
      break;
    }
  }
  assert!(
    drained,
    "seed {seed}: client load drained and the surviving quorum advanced its checkpoint well past \
     the laggard's prior one (a stable, append-only-grown sync target)"
  );

  let cluster_ckpt = c.replica_checkpoint_op(0).get();
  let total = c.replica_reachable_block_count(0);
  assert!(
    total > 0,
    "seed {seed}: the cluster holds a settled checkpoint DAG to measure against"
  );
  assert!(
    cluster_ckpt > lag_ckpt_pre,
    "seed {seed}: the cluster checkpoint ({cluster_ckpt}) advanced past the laggard's prior one \
     ({lag_ckpt_pre}) — the held-prior-checkpoint precondition"
  );
  (cluster_ckpt, total)
}

#[test]
fn incrementality_witness() {
  // The headline non-vacuity proof: a laggard holding a prior checkpoint fetches SOME but strictly
  // FEWER blocks than the full reachable set (`0 < missing < total`). The `missing > 0` half guards
  // against a vacuous "synced nothing"; the `missing < total` half IS the incrementality claim — the
  // shared earlier leaves the laggard already holds are recognized by content address and skipped.
  // Aggregated across the sweep: every seed must be strictly incremental.
  let mut seeds_strict = 0usize;
  let mut tightest: Option<(u64, usize)> = None; // (missing, total) with the smallest missing/total.

  for seed in 0..16u64 {
    let mut c = Cluster::with_checkpoint_ops(REPLICAS, 3, 120, seed, CHECKPOINT_OPS);
    let mut dur = DurabilityChecker::new(c.replica_count());
    c.set_faults(base_faults());
    // Enable real block-store GC so each replica's store stays bounded over the long warm-up/drain
    // (a checkpoint every few ops across hundreds of thousands of ticks); a never-pruning store would
    // grow without bound and slow every per-tick `has_block`. GC pruning a donor's superseded blocks
    // does not affect the witness — the laggard reuses the shared earlier leaves it holds, and the
    // donor serves its CURRENT checkpoint DAG.
    c.enable_block_gc();

    let (cluster_ckpt, total) = warm_crash_and_stabilize(&mut c, &mut dur, seed);

    // (3) Restart the laggard; it state-syncs ONCE to the stable cluster checkpoint, reusing every
    // shared leaf already in its persistent store.
    let fetched_before = c.replica_blocks_fetched(LAGGARD);
    c.restart(LAGGARD);
    let mut converged = false;
    for _ in 0..3_000_000 {
      c.tick();
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: durability (converge)"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (converge)"
      );
      // Caught up = the state-sync INSTALLED its checkpoint AND the laggard then applied the
      // post-checkpoint committed tail via normal catch-up, so its applied history matches the
      // donor's. (The sync restores state up to the checkpoint op; the committed-but-not-yet-
      // checkpointed tail above it is re-learned from the primary.)
      if c.replica_checkpoint_op(LAGGARD).get() >= cluster_ckpt
        && c.replica_status_is_operational(LAGGARD)
        && c.replica_sm(LAGGARD).applied() == c.replica_sm(0).applied()
      {
        converged = true;
        break;
      }
    }
    let missing = c.replica_blocks_fetched(LAGGARD) - fetched_before;
    let sync_count = c.replica_state_sync_count(LAGGARD);
    assert!(
      converged,
      "seed {seed}: the laggard caught up to the stable cluster checkpoint via block fetch and then \
       applied the committed tail (missing={missing}, total={total}, sync_count={sync_count})"
    );

    // Exactly ONE state-sync ran, so `missing` is the missing-block set of that single sync to the
    // stable target — not an accumulation across a moving checkpoint.
    assert_eq!(
      sync_count, 1,
      "seed {seed}: the laggard synced exactly once to the stable target (missing={missing}, \
       total={total}) — a moving target would inflate the fetch count and void the comparison"
    );

    // NON-VACUITY: it fetched SOME blocks (not a vacuous no-op sync).
    assert!(
      missing > 0,
      "seed {seed}: VACUOUS — the laggard fetched no blocks at all; the sync did nothing (the \
       held-prior-checkpoint laggard must genuinely fetch the changed tail)"
    );
    // INCREMENTALITY: it fetched strictly FEWER than the full reachable set — the shared earlier
    // leaves were recognized by content address and NOT re-fetched.
    assert!(
      (missing as usize) < total,
      "seed {seed}: NOT INCREMENTAL — the laggard fetched {missing} blocks but the full reachable \
       set is only {total}; a held-prior-checkpoint laggard over a mostly-unchanged append-only log \
       must fetch strictly fewer (the shared earlier leaves are skipped)"
    );
    seeds_strict += 1;
    // Track the tightest (smallest missing/total) seen, comparing as a cross-multiplied u128 to
    // avoid float and overflow.
    tightest = Some(match tightest {
      Some((m, t)) if (m as u128) * (total as u128) <= (missing as u128) * (t as u128) => (m, t),
      _ => (missing, total),
    });

    // FAITHFUL RECONSTRUCTION: the synced laggard's applied history equals a survivor's. (The
    // convergence condition already required this equality; asserting it makes the reconstruction
    // claim explicit and independent of the loop's exit reason.)
    assert_eq!(
      c.replica_sm(LAGGARD).applied(),
      c.replica_sm(0).applied(),
      "seed {seed}: the synced laggard's applied history must equal the donor's"
    );
  }

  assert_eq!(
    seeds_strict, 16,
    "every sweep seed must be strictly incremental (0 < missing < total)"
  );
  let (m, t) = tightest.expect("the sweep ran at least one seed");
  eprintln!(
    "incrementality witness: {seeds_strict}/16 seeds strict; tightest seen missing={m} of total={t}"
  );
}

#[test]
fn corrupted_block_is_rejected_and_resynced() {
  // The corrupted-block axis: a donor serves a CORRUPTED block (bytes that no longer hash to the
  // requested address) during the laggard's sync. The proto's content-addressed block-fetch must
  // REJECT it (no write, no false-complete), re-request it, and the sync must still complete with
  // correct, faithful state. Off the main schedule (corruption is OFF by default and deterministic —
  // no PRNG draw), so the consensus digest is unperturbed.
  let mut seeds_corrupted = 0usize;
  let mut seeds_completed = 0usize;

  for seed in 0..16u64 {
    let mut c = Cluster::with_checkpoint_ops(REPLICAS, 3, 120, seed, CHECKPOINT_OPS);
    let mut dur = DurabilityChecker::new(c.replica_count());
    c.set_faults(base_faults());
    // Enable real block-store GC so each replica's store stays bounded over the long warm-up/drain
    // (a checkpoint every few ops across hundreds of thousands of ticks); a never-pruning store would
    // grow without bound and slow every per-tick `has_block`. GC pruning a donor's superseded blocks
    // does not affect the witness — the laggard reuses the shared earlier leaves it holds, and the
    // donor serves its CURRENT checkpoint DAG.
    c.enable_block_gc();

    let (cluster_ckpt, total) = warm_crash_and_stabilize(&mut c, &mut dur, seed);
    assert!(total > 0, "seed {seed}: a target DAG exists");

    // Arm corruption: the next several present block responses any donor serves are corrupted (one
    // byte flipped). The laggard must reject each (hash mismatch) and re-request — a re-request of a
    // corrupted block draws a FRESH (uncorrupted, once the budget drains) response, so the fetch
    // still drains. We corrupt a handful so the rejection path fires repeatedly within one sync.
    c.set_corrupt_block_responses(8);

    let fetched_before = c.replica_blocks_fetched(LAGGARD);
    c.restart(LAGGARD);
    let mut converged = false;
    for _ in 0..4_000_000 {
      c.tick();
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: durability (corrupt converge)"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (corrupt converge)"
      );
      if c.replica_checkpoint_op(LAGGARD).get() >= cluster_ckpt
        && c.replica_status_is_operational(LAGGARD)
        && c.replica_sm(LAGGARD).applied() == c.replica_sm(0).applied()
      {
        converged = true;
        break;
      }
    }
    let missing = c.replica_blocks_fetched(LAGGARD) - fetched_before;
    let corrupted = c.corrupted_blocks_served();
    assert!(
      converged,
      "seed {seed}: the laggard converged DESPITE corrupted served blocks \
       (corrupted={corrupted}, missing={missing}, total={total}) — a corrupted block must be \
       rejected + re-requested, never falsely completing the sync"
    );

    // The axis genuinely fired: at least one served block was corrupted (otherwise this proves
    // nothing about the rejection path).
    if corrupted > 0 {
      seeds_corrupted += 1;
    }
    if converged {
      seeds_completed += 1;
    }

    // FAITHFUL RECONSTRUCTION across the corruption: the rejected bytes were never written, so the
    // reconstructed history is byte-identical to the donor's.
    assert_eq!(
      c.replica_sm(LAGGARD).applied(),
      c.replica_sm(0).applied(),
      "seed {seed}: the synced laggard's applied history must equal the donor's even though a \
       corrupted block was served (the corrupted bytes must never have been written)"
    );
  }

  // NON-VACUITY (aggregate): corruption genuinely fired across the sweep, and every seed still
  // completed with faithful state.
  assert!(
    seeds_corrupted >= 1,
    "VACUOUS — no seed ever served a corrupted block across the sweep; the corrupted-block axis did \
     not engage (the laggard never fetched over the network while corruption was armed)"
  );
  assert_eq!(
    seeds_completed, 16,
    "every seed must complete the sync with correct state despite the corrupted block"
  );
  eprintln!("corrupted-block axis: corruption fired on {seeds_corrupted}/16 seeds, all completed");
}

#[test]
fn corrupt_local_block_is_re_fetched_not_restored() {
  // The corrupt-LOCAL-block axis: a laggard's OWN persistent checkpoint DAG has silently rotted — one
  // block reachable from its still-valid durable root is mis-stored (bytes that no longer hash to the
  // address they sit under, the disk-fault content-address violation). The newer cluster checkpoint
  // SHARES that block (the append-only log keeps earlier full leaves verbatim), so the laggard's
  // local-DAG drain reaches it. The drain must NOT trust the block on presence: it treats the corrupt
  // block as MISSING, re-fetches a clean copy from a donor, and the sync completes with correct,
  // faithful state. Off the main schedule (corruption is a direct store mutation, no PRNG draw), so the
  // consensus digest is unperturbed.
  let mut seeds_corrupted = 0usize;
  let mut seeds_completed = 0usize;

  for seed in 0..16u64 {
    let mut c = Cluster::with_checkpoint_ops(REPLICAS, 3, 120, seed, CHECKPOINT_OPS);
    let mut dur = DurabilityChecker::new(c.replica_count());
    c.set_faults(base_faults());
    c.enable_block_gc();

    let (cluster_ckpt, total) = warm_crash_and_stabilize(&mut c, &mut dur, seed);
    assert!(total > 0, "seed {seed}: a target DAG exists");

    // Rot ONE locally-present descendant of the laggard's durable checkpoint root (the laggard is
    // crashed and still holds its prior DAG). The block sits under a valid root, so only a
    // content-address check on the local read can catch it; a presence-only drain would restore it.
    let corrupted_addr = c.corrupt_local_block(LAGGARD);
    if corrupted_addr.is_some() {
      seeds_corrupted += 1;
    }

    let fetched_before = c.replica_blocks_fetched(LAGGARD);
    c.restart(LAGGARD);
    let mut converged = false;
    for _ in 0..4_000_000 {
      c.tick();
      assert!(
        dur.observe(&c).is_ok(),
        "seed {seed}: durability (corrupt-local converge)"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (corrupt-local converge)"
      );
      if c.replica_checkpoint_op(LAGGARD).get() >= cluster_ckpt
        && c.replica_status_is_operational(LAGGARD)
        && c.replica_sm(LAGGARD).applied() == c.replica_sm(0).applied()
      {
        converged = true;
        break;
      }
    }
    let missing = c.replica_blocks_fetched(LAGGARD) - fetched_before;
    assert!(
      converged,
      "seed {seed}: the laggard converged DESPITE a corrupt LOCAL block (corrupted={corrupted_addr:?}, \
       missing={missing}, total={total}) — a corrupt local block must be treated as missing and \
       re-fetched, never restored as committed state"
    );
    if converged {
      seeds_completed += 1;
    }

    // FAITHFUL RECONSTRUCTION: the corrupt local bytes were re-fetched (overwritten by the verified
    // donor block), so the reconstructed history is byte-identical to the donor's. Had the drain
    // trusted the corrupt block, the restored SM state would diverge here.
    assert_eq!(
      c.replica_sm(LAGGARD).applied(),
      c.replica_sm(0).applied(),
      "seed {seed}: the synced laggard's applied history must equal the donor's — a corrupt local \
       block must never be restored as state"
    );
  }

  // NON-VACUITY (aggregate): the laggard genuinely held a multi-block local DAG to corrupt on every
  // seed, and every seed still converged with faithful state.
  assert_eq!(
    seeds_corrupted, 16,
    "VACUOUS — some seed had no multi-block local checkpoint DAG to corrupt; the corrupt-local axis \
     did not engage"
  );
  assert_eq!(
    seeds_completed, 16,
    "every seed must complete the sync with correct state despite the corrupt local block"
  );
  eprintln!(
    "corrupt-local-block axis: corrupted a local block on {seeds_corrupted}/16 seeds, all converged"
  );
}

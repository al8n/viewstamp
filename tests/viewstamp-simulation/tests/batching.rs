//! Focused deterministic batching gates: scripted `Cluster` scenarios driving the batching client
//! model (the sim-side aggregator) and the batch-aware state machine through the specific windows
//! the VOPR lane covers statistically — a multi-unit commit, a group around a view change, the
//! session-dedupe path under a retransmitted batched body, state-sync over batched history, and a
//! restart replaying batched ops — each judged by the standard checkers plus the per-unit oracle
//! ([`check_batching`]).
//!
//! Every scenario runs the cluster in BATCH MODE: every committed body is codec-built (the model's
//! packed bodies, or the plain clients' single-unit wrap) and parsed by the `BatchSm` with the
//! real `BatchView`, so the wire layout under test is the production codec, never a sim re-encode.

use bytes::Bytes;
use viewstamp_simulation::{
  AppliedOnceChecker, BatchingConfig, CheckResult, Cluster, DurabilityChecker, Faults,
  check_batching, check_safety,
};

/// A scripted batching config: NO auto-emission (`auto_units: 0` — `step_emission` is a no-op, so
/// the gate fully controls the queue via `enqueue_unit` / `enqueue_group`).
fn scripted(seed: u64, client: u128) -> BatchingConfig {
  BatchingConfig {
    seed,
    client,
    max_rate: 0,
    group_denom: 8,
    max_unit_len: 64,
    auto_units: 0,
  }
}

/// A seeded auto-emitting batching config (the load-generator shape the longer gates use).
fn auto(seed: u64, client: u128, auto_units: u64) -> BatchingConfig {
  BatchingConfig {
    seed,
    client,
    max_rate: 2,
    group_denom: 5,
    max_unit_len: 32,
    auto_units,
  }
}

/// A 3-replica, one-scripted-batching-client cluster in batch mode.
fn scripted_cluster(seed: u64) -> Cluster {
  let mut c = Cluster::new(3, 1, 0, seed);
  c.set_batch_mode(true);
  c.enable_client_batching(0, scripted(seed, 1));
  c
}

/// A multi-unit body (two lone units + an atomic group) commits as ONE op and every unit acks with
/// the SM's deterministic per-unit reply, in order.
#[test]
fn multi_unit_body_commits_and_every_unit_acks() {
  let mut c = scripted_cluster(7);
  let mut once = AppliedOnceChecker::new(c.replica_count());
  {
    let b = c.client_batching_mut(0).expect("client 0 batches");
    b.enqueue_unit(Bytes::from_static(b"alpha"));
    b.enqueue_unit(Bytes::from_static(b""));
    b.enqueue_group(vec![
      Bytes::from_static(b"g-first"),
      Bytes::from_static(b"g-second"),
    ]);
  }
  let mut done = false;
  for _ in 0..20_000 {
    c.tick();
    assert!(once.observe(&c).is_ok(), "applied-once every tick");
    assert_eq!(check_safety(&c), CheckResult::Ok, "safety every tick");
    if c.is_quiescent() {
      done = true;
      break;
    }
  }
  assert!(done, "the batched client drains");

  // All four queued units packed into ONE body and committed as ONE op.
  assert_eq!(c.replica_sm(0).applied().len(), 1, "one consensus op");
  assert_eq!(c.replica_unit_history(0).len(), 4, "four units applied");
  assert_eq!(c.client(0).bodies_with_multiple_units(), 1);
  assert_eq!(c.client(0).max_units_per_body(), 4);
  assert_eq!(c.client(0).units_acked(), 4);

  // Each unit's acked reply is the deterministic per-unit count, in pack order.
  let bodies = c.client(0).batched_bodies();
  assert_eq!(bodies.len(), 1);
  let units = bodies[0].units();
  assert_eq!(units.len(), 4);
  for (k, unit) in units.iter().enumerate() {
    assert_eq!(
      unit.reply().map(|r| r.as_ref()),
      Some(&(k as u64 + 1).to_be_bytes()[..]),
      "unit {k} acked the SM's per-unit reply"
    );
  }
  // The group occupies adjacent trailing indices.
  assert_eq!(units[2].group(), units[3].group());
  assert!(units[2].group().is_some());
  assert_eq!(units[0].group(), None);

  assert_eq!(once.check(&c), CheckResult::Ok, "applied-once final");
  assert_eq!(check_batching(&c), CheckResult::Ok, "per-unit oracle");
}

/// A group submitted around a primary crash either fully applies or fully retries — never split,
/// never doubled. Two crash points are driven: before the request reaches the primary (pure
/// retry) and after a few ticks of replication (the canonical-log handoff may carry the op into
/// the new view); both must end with the group exactly once on one op, adjacent.
#[test]
fn group_around_a_view_change_applies_atomically() {
  for pre_crash_ticks in [1usize, 6] {
    let mut c = scripted_cluster(11);
    let mut once = AppliedOnceChecker::new(c.replica_count());
    let mut dur = DurabilityChecker::new(c.replica_count());
    {
      let b = c.client_batching_mut(0).expect("client 0 batches");
      b.enqueue_group(vec![
        Bytes::from_static(b"atomic-1"),
        Bytes::from_static(b"atomic-2"),
        Bytes::from_static(b"atomic-3"),
      ]);
    }
    // Let the packed body get in flight (and, for the deeper crash point, replicate), then crash
    // the view-0 primary mid-flight.
    for _ in 0..pre_crash_ticks {
      c.tick();
    }
    c.crash(0);
    let mut done = false;
    for _ in 0..400_000 {
      c.tick();
      assert!(once.observe(&c).is_ok(), "applied-once every tick");
      assert!(dur.observe(&c).is_ok(), "durability every tick");
      assert_eq!(check_safety(&c), CheckResult::Ok, "safety every tick");
      if c.client(0).is_done() {
        done = true;
        break;
      }
    }
    assert!(
      done,
      "pre_crash_ticks={pre_crash_ticks}: the group commits under the new primary"
    );
    assert!(
      c.any_replica_view_advanced_beyond(0),
      "pre_crash_ticks={pre_crash_ticks}: the crash genuinely drove a view change"
    );
    assert_eq!(
      c.client(0).units_acked(),
      3,
      "pre_crash_ticks={pre_crash_ticks}: every group unit acked exactly once"
    );
    assert_eq!(
      once.check(&c),
      CheckResult::Ok,
      "pre_crash_ticks={pre_crash_ticks}: applied-once final"
    );
    assert_eq!(
      check_batching(&c),
      CheckResult::Ok,
      "pre_crash_ticks={pre_crash_ticks}: the group is on one op, adjacent, exactly once"
    );
  }
}

/// A retransmitted/duplicated request whose body holds multiple units applies once: every message
/// is duplicated (the dedupe path sees each batched Request at least twice) and drops force the
/// client's own timeout retransmissions on top.
#[test]
fn retransmitted_multi_unit_body_applies_once() {
  let mut c = scripted_cluster(13);
  c.set_faults(Faults {
    latency: core::time::Duration::from_millis(1),
    jitter: core::time::Duration::from_millis(2),
    drop_per_mille: 200,
    duplicate_per_mille: 1000,
    hold_per_mille: 0,
  });
  let mut once = AppliedOnceChecker::new(c.replica_count());
  {
    let b = c.client_batching_mut(0).expect("client 0 batches");
    for tag in 0u8..6 {
      b.enqueue_unit(Bytes::from(vec![tag; 12]));
    }
    b.enqueue_group(vec![
      Bytes::from_static(b"dup-a"),
      Bytes::from_static(b"dup-b"),
    ]);
  }
  let mut done = false;
  for _ in 0..200_000 {
    c.tick();
    assert!(once.observe(&c).is_ok(), "no double-apply under dup + drop");
    assert_eq!(check_safety(&c), CheckResult::Ok, "safety every tick");
    if c.is_quiescent() {
      done = true;
      break;
    }
  }
  assert!(
    done,
    "duplicated batched requests still drain (idempotency)"
  );
  assert_eq!(c.client(0).units_acked(), 8);
  assert_eq!(once.check(&c), CheckResult::Ok, "applied-once final");
  assert_eq!(check_batching(&c), CheckResult::Ok, "per-unit oracle");
}

/// State-sync over batched history: a laggard crashed across many checkpoints restores the
/// checkpoint snapshot — which carries the unit-level history — and converges; its rebuilt unit
/// history agrees with the donor's byte for byte.
#[test]
fn state_sync_over_batched_history_carries_the_unit_history() {
  // N=5 so the crashed laggard leaves a committing 4-of-5 quorum; a SMALL checkpoint interval so
  // the cluster checkpoints PAST the laggard while it is down (the genuine sync trigger); a
  // batching client with an effectively-endless emission budget keeps ops flowing the whole run,
  // and a wrapped plain client adds the plain client's seeded body mix.
  let mut c = Cluster::with_checkpoint_ops(5, 2, 1_000, 17, 4);
  c.set_batch_mode(true);
  c.enable_client_batching(0, auto(17, 1, u64::MAX));
  c.wrap_client_bodies(1);
  let mut once = AppliedOnceChecker::new(c.replica_count());
  let mut dur = DurabilityChecker::new(c.replica_count());
  let laggard = 2usize;

  let mut warmed = false;
  for _ in 0..200_000 {
    c.tick();
    assert!(once.observe(&c).is_ok(), "applied-once (warm-up)");
    assert!(dur.observe(&c).is_ok(), "durability (warm-up)");
    if c.replica_checkpoint_op(0).get() >= 8 {
      warmed = true;
      break;
    }
  }
  assert!(warmed, "the cluster checkpoints over batched bodies");

  let laggard_head_before = c.replica_checkpoint_op(laggard).get();
  assert_eq!(c.replica_state_sync_count(laggard), 0);
  c.crash(laggard);
  let target = laggard_head_before + 16;
  let mut moved_past = false;
  for _ in 0..600_000 {
    c.tick();
    assert!(once.observe(&c).is_ok(), "applied-once (laggard down)");
    assert!(dur.observe(&c).is_ok(), "durability (laggard down)");
    if c.replica_checkpoint_op(0).get() >= target {
      moved_past = true;
      break;
    }
  }
  assert!(
    moved_past,
    "the cluster checkpointed past the laggard's head while it was down"
  );
  let cluster_ckpt_while_down = c.replica_checkpoint_op(0).get();

  c.restart(laggard);
  let mut converged = false;
  for _ in 0..600_000 {
    c.tick();
    assert!(once.observe(&c).is_ok(), "applied-once (state-sync)");
    assert!(dur.observe(&c).is_ok(), "durability (state-sync)");
    assert_eq!(check_safety(&c), CheckResult::Ok, "safety (state-sync)");
    if c.replica_state_sync_count(laggard) >= 1
      && c.replica_status_is_operational(laggard)
      && c.replica_checkpoint_op(laggard).get() >= cluster_ckpt_while_down
    {
      converged = true;
      break;
    }
  }
  assert!(
    converged,
    "the laggard state-synced past the batched history (sync_count={}, checkpoint_op={})",
    c.replica_state_sync_count(laggard),
    c.replica_checkpoint_op(laggard).get()
  );
  assert!(
    c.replica_checkpoint_op(laggard).get() > laggard_head_before,
    "the laggard's checkpoint jumped past its pre-crash head (a sync, not retransmit catch-up)"
  );

  // The restored snapshot carried the unit-level history: the synced replica's rebuilt unit log
  // agrees with the donor-side primary's, byte for byte, over their common prefix.
  let laggard_units = c.replica_unit_history(laggard);
  let primary_units = c.replica_unit_history(0);
  assert!(
    !laggard_units.is_empty(),
    "the synced replica rebuilt a non-trivial unit history from the snapshot"
  );
  let n = laggard_units.len().min(primary_units.len());
  assert_eq!(
    laggard_units[..n],
    primary_units[..n],
    "the snapshot round-tripped the unit history"
  );

  assert_eq!(once.check(&c), CheckResult::Ok, "applied-once final");
  assert_eq!(check_batching(&c), CheckResult::Ok, "per-unit oracle");
}

/// Restart over the durable store replays batched ops exactly once: a replica crashes after
/// applying batched bodies, restarts from its WAL + checkpoint, re-applies its recovered band in a
/// new incarnation, and the run drains with every unit applied once and the unit histories in
/// agreement.
#[test]
fn restart_over_durable_store_replays_batched_ops_once() {
  // A small checkpoint interval so the restart genuinely replays a recovered band over batched
  // ops (recovery re-applies `(checkpoint_op .. commit_max]` from the WAL).
  let mut c = Cluster::with_checkpoint_ops(3, 1, 0, 19, 4);
  c.set_batch_mode(true);
  c.enable_client_batching(0, auto(19, 1, 160));
  let mut once = AppliedOnceChecker::new(c.replica_count());
  let mut dur = DurabilityChecker::new(c.replica_count());

  // Warm up: commit a non-trivial batched history on all three replicas.
  let mut warmed = false;
  for _ in 0..100_000 {
    c.tick();
    assert!(once.observe(&c).is_ok(), "applied-once (warm-up)");
    assert!(dur.observe(&c).is_ok(), "durability (warm-up)");
    if c.replica_sm(1).applied().len() >= 10 {
      warmed = true;
      break;
    }
  }
  assert!(warmed, "replica 1 applied batched ops before the crash");

  let incarnation_before = c.replica_incarnation(1);
  c.crash(1);
  for _ in 0..2_000 {
    c.tick();
    assert!(once.observe(&c).is_ok(), "applied-once (crashed)");
    assert!(dur.observe(&c).is_ok(), "durability (crashed)");
  }
  c.restart(1);

  let mut done = false;
  for _ in 0..400_000 {
    c.tick();
    assert!(
      once.observe(&c).is_ok(),
      "the restarted replica re-applies its recovered batched band without double-applying"
    );
    assert!(dur.observe(&c).is_ok(), "durability (recovered)");
    assert_eq!(check_safety(&c), CheckResult::Ok, "safety (recovered)");
    if c.is_quiescent() {
      done = true;
      break;
    }
  }
  assert!(done, "the run drains after the restart");
  assert_eq!(
    c.replica_incarnation(1),
    incarnation_before + 1,
    "the restart began a new incarnation (the replay window genuinely opened)"
  );

  // The restarted replica's unit history agrees with the survivor's over the common prefix.
  let restarted = c.replica_unit_history(1);
  let survivor = c.replica_unit_history(0);
  assert!(
    !restarted.is_empty(),
    "the restart rebuilt the unit history"
  );
  let n = restarted.len().min(survivor.len());
  assert_eq!(restarted[..n], survivor[..n], "unit histories agree");

  assert_eq!(once.check(&c), CheckResult::Ok, "applied-once final");
  assert_eq!(dur.check(&c), CheckResult::Ok, "durability final");
  assert_eq!(check_batching(&c), CheckResult::Ok, "per-unit oracle");
}

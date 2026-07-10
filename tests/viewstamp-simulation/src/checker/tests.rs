use super::*;
use crate::Cluster;

#[test]
fn clean_run_is_ok() {
  let mut c = Cluster::new(3, 2, 3, 1);
  for _ in 0..2000 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  assert_eq!(check_safety(&c), CheckResult::Ok);
}

#[test]
fn durability_checker_flags_a_regressed_committed_prefix() {
  // A committed op that is rewritten (or vanishes) across observations is a durability violation.
  let mut dur = DurabilityChecker::new(2);
  // Observation 1: both replicas agree on [1,2,3] → committed history is 3 ops.
  let o1 = vec![
    vec![
      (1, Bytes::from_static(b"a")),
      (2, Bytes::from_static(b"b")),
      (3, Bytes::from_static(b"c")),
    ],
    vec![
      (1, Bytes::from_static(b"a")),
      (2, Bytes::from_static(b"b")),
      (3, Bytes::from_static(b"c")),
    ],
  ];
  assert!(dur.fold(&o1, &[0, 0]).is_ok());
  // Observation 2: replica 1's op 2 now reads back a DIFFERENT body → a committed op was rewritten.
  let o2 = vec![
    vec![
      (1, Bytes::from_static(b"a")),
      (2, Bytes::from_static(b"b")),
      (3, Bytes::from_static(b"c")),
    ],
    vec![
      (1, Bytes::from_static(b"a")),
      (2, Bytes::from_static(b"X")),
      (3, Bytes::from_static(b"c")),
    ],
  ];
  assert!(
    dur.fold(&o2, &[0, 0]).is_violation(),
    "a rewritten committed op must be flagged"
  );
}

#[test]
fn durability_checker_flags_a_regressed_checkpoint() {
  let mut dur = DurabilityChecker::new(1);
  assert!(dur.fold(&[vec![]], &[5]).is_ok());
  assert!(
    dur.fold(&[vec![]], &[4]).is_violation(),
    "a checkpoint_op that goes backwards must be flagged"
  );
}

#[test]
fn durability_checker_allows_a_lagging_recovered_replica() {
  // A replica that is BEHIND the committed history (e.g. just recovered, still catching up) is NOT
  // a violation — only a rewrite or cluster-wide loss is. observe must stay Ok.
  let mut dur = DurabilityChecker::new(2);
  let ahead = vec![
    vec![
      (1, Bytes::from_static(b"a")),
      (2, Bytes::from_static(b"b")),
      (3, Bytes::from_static(b"c")),
    ],
    vec![(1, Bytes::from_static(b"a"))], // replica 1 is behind, agrees on its (short) prefix
  ];
  assert!(
    dur.fold(&ahead, &[0, 0]).is_ok(),
    "a replica behind the committed history is fine as long as it agrees on its prefix"
  );
}

#[test]
fn durability_checker_clean_run_passes() {
  let mut c = Cluster::new(3, 2, 3, 9);
  let mut dur = DurabilityChecker::new(c.replica_count());
  for _ in 0..50_000 {
    c.tick();
    assert!(dur.observe(&c).is_ok());
    if (0..c.client_count()).all(|i| c.client(i).is_done()) {
      break;
    }
  }
  assert!(
    dur.check(&c).is_ok(),
    "a clean run loses no committed op and keeps checkpoints monotone"
  );
}

#[test]
fn durability_checker_final_assertion_stays_strict_when_no_operational_replica_retains_the_history()
{
  // The end-of-run durability assertion (which the VOPR driver's final QUIESCE phase runs AFTER
  // draining) must stay STRICT: if NO operational replica retains the committed history, it is a
  // Violation. This is the "a committed op held by no operational holder still FAILS" direction — it
  // pins that the quiesce fix (drain THEN assert) did not weaken the no-loss guarantee.
  let mut c = Cluster::new(3, 2, 3, 9);
  let mut dur = DurabilityChecker::new(c.replica_count());
  for _ in 0..50_000 {
    c.tick();
    assert!(dur.observe(&c).is_ok());
    if (0..c.client_count()).all(|i| c.client(i).is_done()) {
      break;
    }
  }
  // Sanity: a real committed history was recorded and (healthy) it passes.
  assert!(c.replica_commit(0).get() >= 1, "the cluster committed ops");
  assert!(
    dur.check(&c).is_ok(),
    "healthy: the history survives operational"
  );
  // Now crash EVERY replica: none is operational, so no replica retains the committed history in an
  // operational state → the strict no-loss assertion must fire (it is NOT silently satisfied).
  for i in 0..c.replica_count() {
    c.crash(i);
  }
  assert!(
    dur.check(&c).is_violation(),
    "with no operational replica retaining the committed history the final assertion must FAIL — \
     the quiesce fix drains before this check but never relaxes its strictness"
  );
}

/// One fabricated apply-stream entry: incarnation `inc` applied op `op` for `(client, request)`
/// producing `reply`.
fn applied(
  inc: u64,
  op: u64,
  client: u128,
  request: u64,
  reply: &'static [u8],
) -> (u64, AppliedEvent) {
  use viewstamp_proto::{ClientId, Committed, OpNumber, RequestNumber};
  (
    inc,
    AppliedEvent::Committed(Committed::new(
      OpNumber::with(op),
      ClientId::new(client),
      RequestNumber::with(request),
      Bytes::from_static(reply),
    )),
  )
}

#[test]
fn applied_once_clean_run_passes() {
  let mut c = Cluster::new(3, 2, 3, 9);
  let mut once = AppliedOnceChecker::new(c.replica_count());
  for _ in 0..50_000 {
    c.tick();
    assert!(once.observe(&c).is_ok());
    if (0..c.client_count()).all(|i| c.client(i).is_done()) {
      break;
    }
  }
  assert!(
    once.check(&c).is_ok(),
    "a clean run applies every acked request exactly once"
  );
}

#[test]
fn applied_once_checker_flags_a_double_applied_request() {
  // The same (client, request) applied at two ops within one incarnation: the session dedup
  // failed and the request committed twice — a double-apply.
  let mut once = AppliedOnceChecker::new(1);
  let s0 = vec![
    applied(0, 1, 7, 1, b"a"),
    applied(0, 2, 7, 2, b"b"),
    applied(0, 3, 7, 1, b"c"),
  ];
  assert!(
    once.fold(&[&s0], &HashSet::new()).is_violation(),
    "a request applied at two ops must be flagged"
  );
}

#[test]
fn applied_once_checker_flags_a_request_committed_twice_across_replicas() {
  // The injective-map direction: replica 1's stream carries the same (client, request) at a
  // DIFFERENT op than replica 0 recorded — the request committed twice cluster-wide.
  let mut once = AppliedOnceChecker::new(2);
  let s0 = vec![applied(0, 1, 7, 1, b"a")];
  let s1 = vec![applied(0, 2, 7, 1, b"a")];
  assert!(
    once.fold(&[&s0, &s1], &HashSet::new()).is_violation(),
    "one request at two different ops across replicas must be flagged"
  );
}

#[test]
fn applied_once_checker_flags_a_reused_op_number() {
  // The same op number carrying two DIFFERENT requests on two replicas: a committed op was lost
  // and its number re-minted for another request — the loss + re-mint divergence class.
  let mut once = AppliedOnceChecker::new(2);
  let s0 = vec![applied(0, 5, 1, 1, b"a")];
  let s1 = vec![applied(0, 5, 2, 1, b"a")];
  assert!(
    once.fold(&[&s0, &s1], &HashSet::new()).is_violation(),
    "an op number reused for a second request must be flagged"
  );
}

#[test]
fn applied_once_checker_flags_a_divergent_reply() {
  // The same (client, request) at the same op but with two different replies: the applies
  // diverged (non-deterministic apply or a corrupted body slipped through).
  let mut once = AppliedOnceChecker::new(2);
  let s0 = vec![applied(0, 5, 1, 1, b"a")];
  let s1 = vec![applied(0, 5, 1, 1, b"X")];
  assert!(
    once.fold(&[&s0, &s1], &HashSet::new()).is_violation(),
    "divergent replies for one request must be flagged"
  );
}

#[test]
fn applied_once_checker_flags_a_lost_acked_reply() {
  // A client holds an acked reply for a request NO replica's apply stream ever carried — a
  // client-acked committed op was lost. The matching acked reply passes; a divergent one trips.
  let mut once = AppliedOnceChecker::new(1);
  let s0 = vec![applied(0, 1, 7, 1, b"a")];
  assert!(once.fold(&[&s0], &HashSet::new()).is_ok());
  assert!(
    once
      .check_acked(&[(7, 2, Bytes::from_static(b"b"))], true)
      .is_violation(),
    "an acked-but-never-applied request must be flagged"
  );
  assert!(
    once
      .check_acked(&[(7, 1, Bytes::from_static(b"a"))], true)
      .is_ok(),
    "an acked reply matching the applied reply passes"
  );
  assert!(
    once
      .check_acked(&[(7, 1, Bytes::from_static(b"X"))], true)
      .is_violation(),
    "an acked reply disagreeing with the applied reply must be flagged"
  );
}

#[test]
fn applied_once_checker_final_check_is_non_vacuous() {
  // An empty map while the cluster committed ops means the capture recorded nothing — the oracle
  // would otherwise pass vacuously forever.
  let once = AppliedOnceChecker::new(1);
  assert!(
    once.check_acked(&[], true).is_violation(),
    "committed ops with an empty applied map must be flagged"
  );
  assert!(
    once.check_acked(&[], false).is_ok(),
    "nothing committed, nothing required"
  );
}

#[test]
fn applied_once_checker_allows_recovery_re_emission_in_a_new_incarnation() {
  // A restarted replica re-applies its recovered band: the same (client, request) pairs re-emit
  // at the SAME ops with the SAME replies — a new incarnation, not a double-apply. The new
  // incarnation may also start above op 1 (recovery never re-emits below its checkpoint).
  let mut once = AppliedOnceChecker::new(1);
  let s0 = vec![
    applied(0, 1, 7, 1, b"a"),
    applied(0, 2, 7, 2, b"b"),
    applied(1, 2, 7, 2, b"b"),
    applied(1, 3, 7, 3, b"c"),
  ];
  assert!(
    once.fold(&[&s0], &HashSet::new()).is_ok(),
    "re-emission across incarnations is recovery, not double-apply"
  );
}

#[test]
fn applied_once_checker_allows_a_state_sync_rebase_but_flags_a_bare_gap() {
  use viewstamp_proto::OpNumber;
  // A completed state-sync bulk-restores the skipped band: the marker justifies the jump and
  // commits resume contiguously above the synced point.
  let mut once = AppliedOnceChecker::new(1);
  let synced = vec![
    applied(0, 1, 7, 1, b"a"),
    applied(0, 2, 7, 2, b"b"),
    (0, AppliedEvent::SyncPoint(OpNumber::with(10))),
    applied(0, 11, 7, 11, b"k"),
    applied(0, 12, 7, 12, b"l"),
  ];
  assert!(
    once.fold(&[&synced], &HashSet::new()).is_ok(),
    "a synced jump is a rebase, not a skipped apply"
  );
  // A LATE marker (the recovery peer-fetch path installs eagerly, reporting only once the synced
  // root is durable) sits below the already-folded frontier: forward-only, it must not regress
  // the frontier and flag the next contiguous op.
  let mut once = AppliedOnceChecker::new(1);
  let late = vec![
    applied(0, 41, 7, 41, b"a"),
    applied(0, 42, 7, 42, b"b"),
    (0, AppliedEvent::SyncPoint(OpNumber::with(40))),
    applied(0, 43, 7, 43, b"c"),
  ];
  assert!(
    once.fold(&[&late], &HashSet::new()).is_ok(),
    "a late sync marker never regresses the frontier"
  );
  // The same jump WITHOUT a sync between is a skipped apply.
  let mut once = AppliedOnceChecker::new(1);
  let gap = vec![
    applied(0, 1, 7, 1, b"a"),
    applied(0, 2, 7, 2, b"b"),
    applied(0, 11, 7, 11, b"k"),
  ];
  assert!(
    once.fold(&[&gap], &HashSet::new()).is_violation(),
    "an op gap with no state-sync between must be flagged"
  );
}

#[test]
fn applied_once_checker_flags_a_regressed_op() {
  // An op below the incarnation's applied frontier is a re-apply (the recovered-band re-emission
  // lives in its own incarnation, never inline).
  let mut once = AppliedOnceChecker::new(1);
  let s0 = vec![applied(0, 5, 7, 5, b"a"), applied(0, 4, 7, 4, b"b")];
  assert!(
    once.fold(&[&s0], &HashSet::new()).is_violation(),
    "an op regression within an incarnation must be flagged"
  );
}

#[test]
fn staleness_checker_clean_run_passes() {
  // A clean run records no reads (there is no read path), so the staleness enforcement is
  // vacuously satisfied; the floor stays monotone and the acked set is non-empty (clients are
  // acked), so the non-vacuity guard passes.
  let mut c = Cluster::new(3, 2, 3, 9);
  let mut stale = StalenessChecker::new(c.replica_count(), c.client_count());
  for _ in 0..50_000 {
    c.tick();
    assert!(stale.observe(&c).is_ok());
    if (0..c.client_count()).all(|i| c.client(i).is_done()) {
      break;
    }
  }
  assert!(
    stale.check(&c).is_ok(),
    "a clean run keeps the floor monotone and records no stale read"
  );
}

#[test]
fn staleness_checker_flags_a_read_below_a_write_acked_before_it() {
  // A read issued at T=100 returns applied index 4, but a write committed at op 5 was acked at
  // T=50 (before the read issued) — the read is stale (it failed to reflect a completed write).
  let acked = [(5u64, Instant::from_nanos(50))];
  let reads = [(Instant::from_nanos(100), 4u64, Bytes::from_static(b"r"))];
  assert!(
    StalenessChecker::check_reads(&acked, &reads, true).is_violation(),
    "a read returning below a write acked before it issued must be flagged"
  );
}

#[test]
fn staleness_checker_passes_a_fresh_read() {
  // A read at or above every write acked before it issued is fresh. Op 5 acked at T=50; a read at
  // T=100 returning index 5 (== floor) and one returning 7 (> floor) both pass.
  let acked = [(5u64, Instant::from_nanos(50))];
  assert!(
    StalenessChecker::check_reads(
      &acked,
      &[(Instant::from_nanos(100), 5u64, Bytes::from_static(b"r"))],
      true,
    )
    .is_ok(),
    "a read returning exactly the floor is fresh"
  );
  assert!(
    StalenessChecker::check_reads(
      &acked,
      &[(Instant::from_nanos(100), 7u64, Bytes::from_static(b"r"))],
      true,
    )
    .is_ok(),
    "a read returning above the floor is fresh"
  );
  // A read that issued BEFORE the write was acked owes nothing to that write — only writes acked
  // strictly before the read constrain it. A read at T=40 (before the op-5 ack at T=50) returning
  // index 0 is fine.
  assert!(
    StalenessChecker::check_reads(
      &acked,
      &[(Instant::from_nanos(40), 0u64, Bytes::from_static(b"r"))],
      true,
    )
    .is_ok(),
    "a read that issued before a write was acked is not stale against it"
  );
}

#[test]
fn staleness_checker_flags_a_regressed_floor() {
  // The staleness floor is the committed history high-water; a committed op that reads back with a
  // DIFFERENT body across observations is a floor regression (a committed op was rewritten).
  let mut stale = StalenessChecker::new(2, 0);
  let o1: Vec<Vec<(u64, Bytes)>> = vec![
    vec![(1, Bytes::from_static(b"a")), (2, Bytes::from_static(b"b"))],
    vec![(1, Bytes::from_static(b"a")), (2, Bytes::from_static(b"b"))],
  ];
  assert!(stale.fold(&[&[], &[]], &o1, &[]).is_ok());
  let o2: Vec<Vec<(u64, Bytes)>> = vec![
    vec![(1, Bytes::from_static(b"a")), (2, Bytes::from_static(b"b"))],
    vec![(1, Bytes::from_static(b"a")), (2, Bytes::from_static(b"X"))],
  ];
  assert!(
    stale.fold(&[&[], &[]], &o2, &[]).is_violation(),
    "a rewritten committed op (floor regression) must be flagged"
  );
}

#[test]
fn staleness_checker_fails_closed_on_an_unresolved_ack() {
  // An ack whose op the apply streams never recorded must FAIL the resolution — never be dropped.
  // Dropping it would lower the floor: here client 7's request 2 (the higher op, acked later) is
  // missing from the map while request 1 (op 5) resolves; silently skipping request 2 would let a
  // later read returning index 5 pass even though a higher write was acked before it.
  let mut op_of = HashMap::new();
  op_of.insert((7u128, 1u64), 5u64);
  let acked = [
    (7u128, 1u64, Instant::from_nanos(50)),
    (7u128, 2u64, Instant::from_nanos(60)),
  ];
  assert_eq!(
    StalenessChecker::resolve_acks(&acked, &op_of),
    Err((7u128, 2u64)),
    "an acked request absent from the apply-stream map fails closed, not silently dropped"
  );
  // With the full map both resolve.
  op_of.insert((7u128, 2u64), 6u64);
  assert!(
    StalenessChecker::resolve_acks(&acked, &op_of).is_ok(),
    "a fully-mapped acked set resolves"
  );
}

#[test]
fn staleness_checker_final_check_is_non_vacuous() {
  // The cluster committed ops but no client was acked — the ack-time capture recorded nothing, so
  // the staleness oracle would otherwise pass vacuously.
  assert!(
    StalenessChecker::check_reads(&[], &[], true).is_violation(),
    "committed ops with an empty acked set must be flagged"
  );
  assert!(
    StalenessChecker::check_reads(&[], &[], false).is_ok(),
    "nothing committed, nothing required"
  );
}

#[test]
fn staleness_checker_resolves_acked_ops_from_the_apply_stream() {
  // End-to-end through the live `fold`: an apply stream records client 7's request 1 at op 5 and
  // request 2 at op 6; the client's ack record carries both with ack instants. After folding, a
  // read at T just after the op-6 ack that returns index 5 is stale (op 6 was acked before it).
  let mut stale = StalenessChecker::new(1, 1);
  let stream = vec![applied(0, 5, 7, 1, b"a"), applied(0, 6, 7, 2, b"b")];
  let applied_log: Vec<Vec<(u64, Bytes)>> = vec![vec![
    (5, Bytes::from_static(b"a")),
    (6, Bytes::from_static(b"b")),
  ]];
  let acks: &[(u64, Bytes, Instant)] = &[
    (1, Bytes::from_static(b"a"), Instant::from_nanos(50)),
    (2, Bytes::from_static(b"b"), Instant::from_nanos(60)),
  ];
  assert!(
    stale
      .fold(&[&stream], &applied_log, &[(7u128, acks)])
      .is_ok()
  );
  // Resolve the acked set the way `check` does, then drive a stale read against it.
  stale.record_read(Instant::from_nanos(70), 5, Bytes::from_static(b"stale"));
  let mut resolved: Vec<(u64, Instant)> = Vec::new();
  for (client, request, ack_instant) in &stale.acked {
    if let Some(&op) = stale.op_of.get(&(*client, *request)) {
      resolved.push((op, *ack_instant));
    }
  }
  assert!(
    StalenessChecker::check_reads(&resolved, &stale.reads, true).is_violation(),
    "a read returning op 5 after op 6 was acked is stale once acks resolve to their committed ops"
  );
}

#[test]
fn views_are_monotonic_across_a_crash() {
  let mut c = Cluster::new(3, 1, 2, 5);
  let mut vm = ViewMonotonicChecker::new(c.replica_count());
  for _ in 0..2000 {
    c.tick();
    assert!(vm.observe(&c).is_ok(), "no view regression");
    if c.is_quiescent() {
      break;
    }
  }
  c.crash(0);
  for _ in 0..200_000 {
    c.tick();
    assert!(vm.observe(&c).is_ok(), "no view regression after failover");
    if c.client(0).is_done() {
      break;
    }
  }
}

#[test]
fn view_checker_tracks_the_durable_view_across_an_undurable_catch_up_regression() {
  // A replica that caught its IN-MEMORY view up to a higher view via the higher-view rule
  // (`catch_up_to_view` — a non-binding GetView probe, NO durable write, NO participation), then
  // crashed and recovered to its (lower) DURABLE view, legitimately regresses its in-memory view.
  // That is SAFE (it acted in no higher view than it persisted), so the view-monotonic checker —
  // which tracks the DURABLE view — must stay Ok, even though a naive in-memory-view checker WOULD
  // have fired.
  //
  // Construction: a 5-node cluster, crash the primary (r0) so the survivors fail over to view 1. A
  // lagging backup catches its in-memory view up to 1 BEFORE persisting it (the un-durable window:
  // `replica_view > replica_durable_view`). We crash that backup IN that window and restart it — it
  // recovers to durable view 0, regressing its in-memory view. The durable-view checker stays Ok
  // throughout; we also assert the in-memory view actually regressed (non-vacuity: the bug this fixes
  // would have tripped here).
  use crate::Faults;
  use core::time::Duration;

  let mut c = Cluster::new(5, 2, 200, 151);
  // Lossy network: drops keep a behind backup in the `catch_up_to_view` GetView-probe state (its
  // in-memory view bumped via the higher-view rule, the StartView that would persist it delayed), so
  // the un-durable window `replica_view > replica_durable_view` stays open long enough to observe.
  c.set_faults(Faults {
    latency: Duration::from_millis(1),
    jitter: Duration::from_millis(2),
    drop_per_mille: 200,
    duplicate_per_mille: 0,
    hold_per_mille: 0,
  });
  let mut vm = ViewMonotonicChecker::new(c.replica_count());
  // Warm up.
  for _ in 0..5_000 {
    c.tick();
    assert!(vm.observe(&c).is_ok());
    if c.replica_commit(0).get() >= 3 {
      break;
    }
  }
  // Crash the view-0 primary; the survivors fail over toward higher views. Search (re-crashing the
  // rotating primary to force fresh catch-ups) for a replica in the un-durable catch-up window.
  c.crash(0);
  let mut victim = None;
  for step in 0..200_000usize {
    c.tick();
    assert!(
      vm.observe(&c).is_ok(),
      "durable view never regresses (pre-crash)"
    );
    if let Some(i) = (0..c.replica_count())
      .find(|&i| !c.is_crashed(i) && c.replica_view(i).get() > c.replica_durable_view(i).get())
    {
      victim = Some(i);
      break;
    }
    // Periodically crash whichever replica currently leads (the live primary) and restart a crashed
    // one, to churn views and repeatedly drive lagging backups through the catch-up probe.
    if step % 4_000 == 3_999 {
      let leader = (0..c.replica_count())
        .filter(|&i| !c.is_crashed(i))
        .max_by_key(|&i| c.replica_view(i).get());
      if let Some(l) = leader {
        let live = (0..c.replica_count()).filter(|&i| !c.is_crashed(i)).count();
        // Keep a quorum up (5 replicas → never knock the live set below 3).
        if live > 3 {
          c.crash(l);
        }
      }
      for i in 0..c.replica_count() {
        if c.is_crashed(i) {
          c.restart(i);
          break;
        }
      }
    }
  }
  let v =
    victim.expect("a replica entered the un-durable catch-up window (in-memory view > durable)");
  let inmem_before = c.replica_view(v).get();
  let durable_before = c.replica_durable_view(v).get();
  assert!(
    inmem_before > durable_before,
    "the victim's in-memory view {inmem_before} leads its durable view {durable_before}"
  );
  // Crash + restart the victim: it recovers to its DURABLE view, regressing the in-memory view.
  c.crash(v);
  c.restart(v);
  let inmem_after = c.replica_view(v).get();
  assert!(
    inmem_after <= durable_before,
    "after recovery the in-memory view ({inmem_after}) is back at the durable view (<= {durable_before})"
  );
  assert!(
    inmem_after < inmem_before,
    "non-vacuity: the in-memory view genuinely REGRESSED ({inmem_before} -> {inmem_after}) — a naive \
     in-memory-view checker would have fired here"
  );
  // The durable-view checker stays Ok across the regression and the subsequent re-convergence.
  assert!(
    vm.observe(&c).is_ok(),
    "the durable-view checker tolerates the in-memory regression (the higher view was never durable)"
  );
  // Heal + run on: the durable view must stay monotone as the recovered replica re-catches up.
  c.set_faults(Faults::none());
  for i in 0..c.replica_count() {
    if c.is_crashed(i) {
      c.restart(i);
    }
  }
  for _ in 0..50_000 {
    c.tick();
    assert!(
      vm.observe(&c).is_ok(),
      "durable view stays monotone as the recovered replica re-catches up"
    );
    if (0..c.client_count()).all(|i| c.client(i).is_done()) {
      break;
    }
  }
}

#[test]
fn epoch_view_checker_allows_a_per_epoch_view_reset_but_flags_a_same_epoch_view_drop() {
  let mut ev = EpochViewMonotonicChecker::new(1);
  // View climbs within epoch 0.
  assert!(ev.note(0, 0, 0).is_ok());
  assert!(ev.note(0, 0, 5).is_ok());
  // A view DROP at the SAME epoch is a split-brain regression.
  assert!(
    ev.note(0, 0, 4).is_violation(),
    "a view drop within an epoch must be flagged"
  );
  // A view drop is allowed when the EPOCH rose (the per-epoch view reset): epoch 1, view 0.
  let mut ev = EpochViewMonotonicChecker::new(1);
  assert!(ev.note(0, 0, 5).is_ok());
  assert!(
    ev.note(0, 1, 0).is_ok(),
    "a view reset to 0 at a higher epoch is the legitimate per-epoch reset"
  );
  // The pair is lexicographic: at the higher epoch the view climbs again.
  assert!(ev.note(0, 1, 3).is_ok());
  assert!(
    ev.note(0, 1, 2).is_violation(),
    "a view drop within the new epoch is still a regression"
  );
}

#[test]
fn epoch_view_checker_flags_an_epoch_regression() {
  let mut ev = EpochViewMonotonicChecker::new(1);
  assert!(ev.note(0, 2, 1).is_ok());
  // ANY epoch regression is a split-brain hazard, even with a higher view.
  assert!(
    ev.note(0, 1, 99).is_violation(),
    "an epoch regression (even to a higher view) must be flagged"
  );
}

#[test]
fn membership_checker_chains_a_lineage_and_flags_a_fork() {
  // Genesis seeds the lineage; a chained successor (prev_epoch == current) extends it.
  let mut m = MembershipMonotonicChecker::new();
  assert!(m.note(0, 0xAAAA, 0).is_ok()); // epoch 0, config A (genesis)
  assert!(m.note(0, 0xAAAA, 0).is_ok()); // the same config re-observed (another node) — fine
  assert!(
    m.note(1, 0xBBBB, 0).is_ok(),
    "epoch 1 chaining from prev_epoch 0 (the current tip) extends the lineage"
  );
  assert!(m.note(2, 0xCCCC, 1).is_ok(), "epoch 2 chains from epoch 1");
  // A FORK: a different config_id re-observed at a KNOWN epoch (two configs claim epoch 1).
  assert!(
    m.note(1, 0x9999, 0).is_violation(),
    "two different config_ids at the same epoch is a fork"
  );
}

#[test]
fn membership_checker_flags_a_non_chained_successor() {
  // A successor whose prev_epoch is NOT the current tip is a fork off a stale parent.
  let mut m = MembershipMonotonicChecker::new();
  assert!(m.note(0, 0xAAAA, 0).is_ok());
  assert!(m.note(1, 0xBBBB, 0).is_ok()); // current tip is now epoch 1
  assert!(
    m.note(2, 0xCCCC, 0).is_violation(),
    "epoch 2 chaining from prev_epoch 0 (not the current tip 1) is a non-chained successor"
  );
}

#[test]
fn durability_checker_excuses_a_removed_slot_from_the_survivor_scan() {
  // Two replicas agree on a 3-op committed history; then a reconfiguration REMOVES replica 1. With
  // replica 1 crashed (parked) and excused via `note_removed`, the final check must still pass
  // because the SURVIVOR (replica 0) retains the history — the removed node is no longer a required
  // holder. Without the excusal, a removed-then-crashed node could spuriously fail the check.
  use crate::Cluster;
  let mut c = Cluster::new(3, 2, 3, 9);
  let mut dur = DurabilityChecker::new(c.replica_count());
  for _ in 0..50_000 {
    c.tick();
    assert!(dur.observe(&c).is_ok());
    if (0..c.client_count()).all(|i| c.client(i).is_done()) {
      break;
    }
  }
  assert!(c.replica_commit(0).get() >= 1, "the cluster committed ops");
  // Model a removal: replica 2 is crashed (parked) AND excused. The survivors 0,1 still hold the
  // history, so the check passes — the removed node was correctly dropped from the required set.
  c.crash(2);
  dur.note_removed(2);
  assert!(
    dur.check(&c).is_ok(),
    "a removed (excused) crashed node does not break the no-loss check while survivors retain the \
     history"
  );
  // Crash a SURVIVOR too: now only replica 0 is operational and not removed — still holds the full
  // history, so the check passes (the removal did not relax the survivors' obligation).
  c.crash(1);
  assert!(
    dur.check(&c).is_ok(),
    "the surviving operational replica still retains the committed history"
  );
  // Crash the last survivor: NO operational non-removed replica retains the history → the check must
  // FAIL (removal excuses only the removed node, never the headline no-loss guarantee).
  c.crash(0);
  assert!(
    dur.check(&c).is_violation(),
    "with no operational non-removed replica retaining the history the no-loss check must fail"
  );
}

/// One fabricated membership-swap entry: incarnation `inc` installed the committed `Reconfigure`
/// op `op` producing configuration `(epoch, config_id)`.
fn swap(inc: u64, op: u64, epoch: u64, config_id: u128) -> (u64, MembershipChanged) {
  use viewstamp_proto::{Epoch, OpNumber};
  (
    inc,
    MembershipChanged::new(
      OpNumber::with(op),
      Epoch::new(epoch),
      config_id,
      true,
      false,
    ),
  )
}

#[test]
fn reconfigure_applied_once_empty_streams_pass() {
  // A run that never reconfigures emits no swaps — the checker is vacuously Ok.
  let mut once = ReconfigureAppliedOnceChecker::new(3);
  assert!(once.fold(&[&[], &[], &[]]).is_ok());
}

#[test]
fn reconfigure_applied_once_one_swap_per_replica_passes() {
  // Three replicas each install the SAME committed reconfiguration (op 10 -> epoch 1) once — the
  // convergent, once-per-replica case.
  let mut once = ReconfigureAppliedOnceChecker::new(3);
  let s0 = vec![swap(0, 10, 1, 0xAA)];
  let s1 = vec![swap(0, 10, 1, 0xAA)];
  let s2 = vec![swap(0, 10, 1, 0xAA)];
  assert!(
    once.fold(&[&s0, &s1, &s2]).is_ok(),
    "every replica installing the same committed swap once is the healthy case"
  );
}

#[test]
fn reconfigure_applied_once_flags_a_double_swap_in_one_incarnation() {
  // The same committed Reconfigure op installed TWICE within one incarnation — a double application
  // (the epoch would be double-bumped / abdication re-fired).
  let mut once = ReconfigureAppliedOnceChecker::new(1);
  let s0 = vec![swap(0, 10, 1, 0xAA), swap(0, 10, 1, 0xAA)];
  assert!(
    once.fold(&[&s0]).is_violation(),
    "a committed reconfiguration installed twice in one incarnation must be flagged"
  );
}

#[test]
fn reconfigure_applied_once_allows_a_swap_retry_in_a_new_incarnation() {
  // A replica committed the Reconfigure op but crashed before its SwapEpoch root went durable, so it
  // re-installs that op in a LATER incarnation — a legitimate retry, NOT a double-swap.
  let mut once = ReconfigureAppliedOnceChecker::new(1);
  let s0 = vec![swap(0, 10, 1, 0xAA), swap(1, 10, 1, 0xAA)];
  assert!(
    once.fold(&[&s0]).is_ok(),
    "re-installing a committed swap in a new incarnation is a crash retry, not a double-apply"
  );
}

#[test]
fn reconfigure_applied_once_flags_a_divergent_successor() {
  // Two replicas install the SAME committed op but record DIFFERENT successors — a forked swap of
  // one committed reconfiguration (two configurations from one change).
  let mut once = ReconfigureAppliedOnceChecker::new(2);
  let s0 = vec![swap(0, 10, 1, 0xAA)];
  let s1 = vec![swap(0, 10, 1, 0xBB)];
  assert!(
    once.fold(&[&s0, &s1]).is_violation(),
    "one committed op installing two different successors must be flagged"
  );
}

#[test]
fn config_lineage_empty_streams_pass() {
  let mut lin = ConfigLineageChecker::new(3);
  assert!(lin.fold(&[&[], &[], &[]]).is_ok());
}

#[test]
fn config_lineage_unbroken_chain_passes() {
  // A 3->4->3 reconfiguration installs epoch 1 then epoch 2, each chaining off the tip — an
  // unbroken committed lineage cluster-wide (every replica agrees on each epoch's config_id).
  let mut lin = ConfigLineageChecker::new(2);
  let s0 = vec![swap(0, 10, 1, 0xA1), swap(0, 20, 2, 0xB2)];
  let s1 = vec![swap(0, 10, 1, 0xA1), swap(0, 20, 2, 0xB2)];
  assert!(
    lin.fold(&[&s0, &s1]).is_ok(),
    "a one-epoch-at-a-time committed lineage every replica agrees on is unbroken"
  );
}

#[test]
fn config_lineage_flags_a_same_epoch_fork() {
  // Two replicas install epoch 1 with DIFFERENT config_ids — two configurations claiming one epoch
  // (the split-brain reconfiguration hazard).
  let mut lin = ConfigLineageChecker::new(2);
  let s0 = vec![swap(0, 10, 1, 0xA1)];
  let s1 = vec![swap(0, 10, 1, 0xFF)];
  assert!(
    lin.fold(&[&s0, &s1]).is_violation(),
    "divergent config_ids at the same committed epoch must be flagged as a fork"
  );
}

#[test]
fn config_lineage_flags_a_broken_chain() {
  // A swap installs epoch 3 directly after genesis (skipping 1 and 2) — a single-voter change bumps
  // the epoch by exactly one, so an epoch that skips ahead did not chain off its predecessor.
  let mut lin = ConfigLineageChecker::new(1);
  let s0 = vec![swap(0, 10, 3, 0xC3)];
  assert!(
    lin.fold(&[&s0]).is_violation(),
    "a committed epoch that skips the tip+1 successor must be flagged as a broken chain"
  );
}

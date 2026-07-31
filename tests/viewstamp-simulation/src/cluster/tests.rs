use super::*;

use crate::storage::StorageFaults;

#[test]
fn one_node_cluster_ticks() {
  let mut cluster = Cluster::new(1, 1, 1, /*seed*/ 7);
  let t0 = cluster.now();
  for _ in 0..50 {
    cluster.tick();
  }
  assert!(cluster.now() > t0, "virtual clock must advance");
}

#[test]
fn duplicate_delivery_preserves_safety_and_liveness() {
  // Every message duplicated (idempotency stress): a re-delivered Prepare must not double-apply and
  // a re-delivered PrepareOk must not double-count the quorum, so the cluster still commits cleanly.
  let mut c = Cluster::new(3, 2, 3, 4);
  c.set_faults(Faults {
    latency: Duration::from_millis(1),
    jitter: Duration::from_millis(2),
    drop_per_mille: 0,
    duplicate_per_mille: 1000,
    hold_per_mille: 0,
  });
  let mut done = false;
  for _ in 0..20_000 {
    c.tick();
    // contiguity/agreement holds under duplication.
    assert!(
      crate::check_safety(&c).is_ok(),
      "safety under duplicate delivery"
    );
    if (0..c.client_count()).all(|i| c.client(i).is_done()) {
      done = true;
      break;
    }
  }
  assert!(
    done,
    "duplicated messages still let clients finish (idempotency)"
  );
}

#[test]
fn duplicate_delivery_is_deterministic() {
  // Same seed + same duplicate fault plan ⇒ identical applied logs (the dup roll uses the seeded PRNG).
  let run = || {
    let mut c = Cluster::new(3, 2, 3, 9);
    c.set_faults(Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(2),
      drop_per_mille: 0,
      duplicate_per_mille: 1000,
      hold_per_mille: 0,
    });
    for _ in 0..20_000 {
      c.tick();
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        break;
      }
    }
    (0..c.replica_count())
      .map(|i| c.replica_sm(i).applied().to_vec())
      .collect::<Vec<_>>()
  };
  assert_eq!(
    run(),
    run(),
    "duplicate delivery is a pure function of the seed"
  );
}

#[test]
fn restart_recovers_through_the_recovering_loop_under_faults() {
  let mut c = Cluster::new(3, 1, 3, 5);
  // TRANSIENT read faults on every replica's WAL (no permanent corruption); the recover loop must
  // retry through them and reach Normal.
  c.set_storage_faults(StorageFaults {
    read_fault_per_mille: 100,
    ..StorageFaults::none()
  });
  let mut warm = false;
  for _ in 0..40_000 {
    c.tick();
    if !c.replica_sm(1).applied().is_empty() {
      warm = true;
      break;
    }
  }
  assert!(warm, "replica 1 commits >= 1 op before the crash");
  c.crash(1);
  for _ in 0..500 {
    c.tick();
  }
  c.restart(1); // metadata-only recover + bounded handle_storage pump (retries the faulted reads)
  // After restart the replica is operational (Normal or ViewChange) — never stranded in Recovering,
  // because the faults are transient and clear within the proto's retry budget.
  assert!(
    c.replica_status_is_operational(1),
    "restart drives the Recovering loop to Normal under transient faults"
  );
}

/// PINS A DEFECT THAT IS STILL UNFIXED. Every assertion below records DAMAGE and asserts that it
/// happens, so that closing the defect BREAKS this test and forces the rewrite described at the
/// bottom. Nothing here endorses the behaviour it observes.
///
/// # The defect
///
/// A storage correlation id ([`OpId`](viewstamp_proto::OpId)) is minted per `Endpoint` and the
/// sequence RESTARTS at `1` in each new one, so two endpoint incarnations over the same storage
/// mint the same ids. A completion produced for the PREVIOUS incarnation and delivered to the
/// CURRENT one therefore aliases onto whatever the current one happens to have in flight under that
/// id, and is dispatched as though the current one's own write had landed.
///
/// [`crash`](Cluster::crash) hides this: it models power loss, so it discards the staged writes and
/// undelivered completions — exactly the evidence that would alias.
/// [`restart_in_place`](Cluster::restart_in_place) retains them, which is what a supervised
/// endpoint rebuild over a still-running storage layer does.
///
/// # Why the schedule bends the id map before the swap
///
/// Two incarnations collide destructively only when their id → op maps DISAGREE. Recovery spends
/// one id per durable op in the recover window and then resumes appending, so a successor
/// recovering a log its predecessor wrote one-id-per-op re-derives the predecessor's own map: every
/// aliased completion then lands on the op it was already for, and nothing observable happens.
/// Deposing the view-0 primary bends the map — the view change makes the survivors mint ids that
/// are not plain head-extending appends (the durable-view root write) and re-append an adopted tail
/// out of op order — so the predecessor's ids run ahead of its op numbers while the successor's,
/// derived from the durable log alone, do not. With the constants below the predecessor leaves
/// eight appends in flight and the successor mints one of those same ids for a LATER op.
///
/// # The damage, read off the harness's own oracles
///
/// - the replica emits a `PrepareOk` for an op whose WAL slot is still `Dirty`
///   ([`take_append_before_ack_violation`](Cluster::take_append_before_ack_violation)): it has
///   voted for an op it does not hold durably, on the strength of a completion that belongs to a
///   different op of a dead endpoint; and, following from that vote,
/// - that op COMMITS while only one voter holds it durably
///   ([`DurableQuorumChecker`](crate::checker::DurableQuorumChecker)): the quorum-durable retention
///   that VSR recovery rests on is broken, so one further crash loses a committed op.
///
/// The control arm runs the IDENTICAL schedule through `crash` + `restart` — the same endpoint
/// rebuild, differing only in that the in-flight work is discarded — and stays clean on both
/// oracles. The damage is therefore attributable to the retained completions, not to the schedule.
///
/// # What the fix must turn this test into
///
/// Once a correlation id is scoped to its incarnation and foreign completions meet a single
/// rejection choke, the retaining arm must behave like the control: the foreign completion is
/// rejected wholesale instead of dispatched, a rejection counter is non-zero (proving a foreign
/// completion really was delivered and refused, so the lane has not silently gone vacuous), and the
/// replica casts no ack or vote for an op until its OWN incarnation's completion for that op
/// arrives. Both `expect`s below then become `is_none()` assertions, the rejection-counter
/// assertion joins them, and the retained-in-flight precondition stays exactly as it is.
#[test]
fn unfixed_defect_a_foreign_completion_forges_an_ack_across_an_in_place_restart() {
  use crate::checker::{CheckResult, DurableQuorumChecker};

  /// How the run replaces replica 2's endpoint — the ONLY difference between the two arms.
  #[derive(Clone, Copy, Debug)]
  enum Swap {
    /// `crash` then `restart`: the crash discards the staged writes and queued completions, so the
    /// successor endpoint is handed nothing its predecessor left behind.
    DiscardingInFlight,
    /// `restart_in_place`: the storage layer keeps everything it still owes, so the predecessor's
    /// completions are delivered into the successor.
    RetainingInFlight,
  }

  /// What one arm observed: how much in-flight work the successor inherited, and the first violation
  /// of each oracle after the swap.
  struct Observed {
    inherited: usize,
    forged_ack: Option<SmolStr>,
    lost_durable_quorum: Option<SmolStr>,
  }

  /// Appends stay in flight for this many WAL polls, holding the in-flight window open long enough
  /// for the successor to mint an id its predecessor is still using.
  const WAL_DELAY: u32 = 32;
  /// Far above anything this run commits, so no checkpoint fires: the successor's recover window is
  /// then the whole durable log, and the id map it derives is a function of that log alone.
  const NO_CHECKPOINT: u64 = 32_768;
  /// Enough closed-loop clients that several appends are outstanding at once — one endpoint
  /// incarnation must leave more than a single write with the device for an aliased id to exist.
  const CLIENTS: u32 = 8;
  /// Ticks of ordinary operation before the primary is deposed, and again before the swap.
  const PHASE_TICKS: u32 = 60;
  /// Ticks after the swap, comfortably past both violations (the forged ack lands well inside it, and
  /// the op it forged a vote for commits a while later).
  const OBSERVE_TICKS: u32 = 300;

  fn run(swap: Swap) -> Observed {
    let mut c = Cluster::with_checkpoint_ops(3, CLIENTS, 200, /*seed*/ 0, NO_CHECKPOINT);
    c.set_async_wal_delay(Some(WAL_DELAY));
    let mut quorum = DurableQuorumChecker::new();
    for _ in 0..PHASE_TICKS {
      c.tick();
      assert!(
        c.take_append_before_ack_violation().is_none(),
        "{swap:?}: the schedule violates append-before-ack before the primary is even deposed"
      );
    }
    // Depose the view-0 primary. The view change is what makes the two incarnations' id maps
    // disagree; it is not itself the thing under test.
    c.crash(0);
    for _ in 0..PHASE_TICKS {
      c.tick();
      assert!(
        c.take_append_before_ack_violation().is_none(),
        "{swap:?}: the schedule violates append-before-ack before the endpoint swap"
      );
    }
    match swap {
      Swap::DiscardingInFlight => {
        c.crash(2);
        c.restart(2);
      }
      Swap::RetainingInFlight => c.restart_in_place(2),
    }
    let inherited = c.wal_staged_len_for_test(2);
    let mut observed = Observed {
      inherited,
      forged_ack: None,
      lost_durable_quorum: None,
    };
    for _ in 0..OBSERVE_TICKS {
      c.tick();
      if let Some(v) = c.take_append_before_ack_violation() {
        observed.forged_ack.get_or_insert(v);
      }
      if let CheckResult::Violation(v) = quorum.observe(&c) {
        observed.lost_durable_quorum.get_or_insert(v);
      }
    }
    observed
  }

  // The control: the same endpoint rebuild with the in-flight work thrown away is clean, so nothing
  // in the schedule itself breaks either oracle.
  let control = run(Swap::DiscardingInFlight);
  assert_eq!(
    control.inherited, 0,
    "a crash must leave the successor endpoint nothing in flight — it models the fsync loss"
  );
  assert!(
    control.forged_ack.is_none(),
    "the discarding lane acked an op it had not durably appended: {:?}",
    control.forged_ack
  );
  assert!(
    control.lost_durable_quorum.is_none(),
    "the discarding lane lost a committed op's durable quorum: {:?}",
    control.lost_durable_quorum
  );

  let observed = run(Swap::RetainingInFlight);
  assert!(
    observed.inherited > 0,
    "the successor endpoint inherited no in-flight write, so no foreign completion could be \
     delivered — the lane is vacuous and proves nothing"
  );
  // DAMAGE, asserted as present on purpose: a completion minted by the dead endpoint for one of ITS
  // ops was dispatched as the successor's, and the successor voted for an op still `Dirty` on its
  // own disk.
  let forged = observed.forged_ack.expect(
    "no forged ack: the retained foreign completion no longer reaches the successor's in-flight \
     table. Either this schedule has drifted off the aliasing window (re-derive it), or correlation \
     ids are now incarnation-scoped and rejected — in which case flip this test to its green form \
     described in the doc comment above",
  );
  assert!(
    forged.contains("wal_status=dirty"),
    "the forged ack must be for a slot whose append is genuinely still in flight, not a slot the \
     harness merely failed to observe: {forged}"
  );
  // The consequence, and the reason the forged ack matters: the op it voted for then committed
  // without the durable quorum that lets a survivor recover it.
  let lost = observed.lost_durable_quorum.expect(
    "the forged ack did not cost a committed op its durable quorum — the run no longer reaches the \
     consequence this test exists to record; re-derive the schedule before weakening it",
  );
  assert!(
    lost.contains("is durably held on only 1 voters"),
    "the retention breach must be a committed op held by a single voter (the forged ack standing in \
     for the second durable copy): {lost}"
  );
}

#[test]
fn crashed_replica_stops_and_is_skipped() {
  let mut c = Cluster::new(3, 1, 1, 7);
  c.crash(0);
  assert!(c.is_crashed(0));
  // ticking must not panic and must not deliver to/from the crashed replica.
  for _ in 0..20 {
    c.tick();
  }
  // a crashed primary means no commits; the (single) client cannot finish without view change,
  // but the loop must run cleanly.
  assert!(c.now().as_nanos() > 0);
}

#[test]
fn gate_accessors_expose_op_commit_and_primary() {
  let mut c = Cluster::new(3, 1, 2, 11);
  for _ in 0..2000 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  // replica 0 is the view-0 primary; its op/commit advanced as the client's requests committed.
  assert!(c.replica_is_primary(0), "replica 0 is the view-0 primary");
  assert!(c.replica_op(0).get() >= 1, "primary head advanced");
  assert!(c.replica_commit(0).get() >= 1, "primary commit advanced");
  assert!(
    !c.any_replica_view_advanced_beyond(0),
    "no view change in a clean run"
  );
  // A clean run never force-syncs (no pruned-hole strand).
  assert_eq!(
    c.replica_forced_sync_count(0),
    0,
    "no forced sync in a clean run"
  );
}

#[test]
fn apply_stream_records_committed_ops_per_incarnation() {
  let mut c = Cluster::new(3, 1, 3, 11);
  for _ in 0..5_000 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  assert_eq!(c.replica_incarnation(0), 0, "no restart yet");
  // The view-0 primary's stream carries one Committed per apply, in apply order, all tagged with
  // incarnation 0 — exactly its state machine's applied ops.
  let ops: Vec<u64> = c
    .replica_applied_events(0)
    .iter()
    .filter_map(|(inc, e)| {
      assert_eq!(
        *inc, 0,
        "every entry of an unrestarted replica is incarnation 0"
      );
      match e {
        AppliedEvent::Committed(commit) => Some(commit.op().get()),
        AppliedEvent::SyncPoint(_) => None,
      }
    })
    .collect();
  let expect: Vec<u64> = (1..=c.replica_sm(0).applied().len() as u64).collect();
  assert!(!expect.is_empty(), "the run committed ops");
  assert_eq!(ops, expect, "one Committed per apply, in apply order");
  // A crash captures the queued event tail; a restart begins a new incarnation.
  let before = c.replica_applied_events(1).len();
  c.crash(1);
  assert!(
    c.replica_applied_events(1).len() >= before,
    "crash never drops recorded events"
  );
  c.restart(1);
  assert_eq!(c.replica_incarnation(1), 1, "restart bumps the incarnation");
}

#[test]
fn partition_groups_block_cross_group_traffic() {
  let mut c = Cluster::new(5, 1, 1, 3);
  assert!(!c.partitioned(0, 3), "no partition by default");
  c.partition(vec![0, 0, 0, 1, 1]); // {0,1,2} | {3,4}
  assert!(c.partitioned(0, 3), "cross-group is blocked");
  assert!(!c.partitioned(0, 1), "same-group is not blocked");
  assert!(!c.partitioned(3, 4), "same-group is not blocked");
  c.heal();
  assert!(!c.partitioned(0, 3), "heal removes all partitions");
}

#[test]
fn one_way_blocks_are_directed_counted_and_healed() {
  // The DIRECTED block: 0 → 1 is cut while 1 → 0 still flows — the asymmetric shape the
  // symmetric groups cannot express. The blocked leg is dropped + counted; the reverse leg and
  // client-bound traffic are untouched; `heal` restores full bidirectional connectivity.
  let mut c = Cluster::new(3, 1, 1, /*seed*/ 7);
  let now = c.now();
  c.block_one_way(0, 1);
  assert!(c.one_way_blocked(0, 1), "the installed leg is blocked");
  assert!(!c.one_way_blocked(1, 0), "the REVERSE leg still flows");
  let small = Message::Commit(viewstamp_proto::Commit::new(
    viewstamp_proto::View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    viewstamp_proto::Epoch::new(0),
    0,
  ));
  // Blocked leg: dropped + counted, never enqueued.
  c.schedule(
    now,
    Peer::Replica(ReplicaId::new(0)),
    Target::Replica(1),
    small.clone(),
  );
  assert_eq!(c.one_way_dropped(), 1, "the blocked leg drop is counted");
  assert!(
    c.net.is_empty(),
    "the blocked message never reached the wire"
  );
  // Reverse leg: delivered.
  c.schedule(
    now,
    Peer::Replica(ReplicaId::new(1)),
    Target::Replica(0),
    small.clone(),
  );
  assert_eq!(c.one_way_dropped(), 1, "the reverse leg is NOT blocked");
  assert!(!c.net.is_empty(), "the reverse-leg message was enqueued");
  // Heal: the leg flows again.
  c.heal();
  c.schedule(
    now,
    Peer::Replica(ReplicaId::new(0)),
    Target::Replica(1),
    small,
  );
  assert_eq!(c.one_way_dropped(), 1, "heal cleared the one-way block");
}

#[test]
fn partition_primary_out_deposes_the_primary_and_heals() {
  // The stale-read lane's partition mechanism: cut every leg to AND from the current primary
  // (deaf + mute), so the survivors stop hearing it. The witness advances, the deposed primary's
  // legs are blocked both ways, and `heal` restores connectivity.
  let mut c = Cluster::new(3, 1, 2, /*seed*/ 7);
  for _ in 0..2000 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  assert!(c.replica_is_primary(0), "replica 0 is the view-0 primary");
  assert_eq!(c.stale_read_probes_fired(), 0, "no probe yet");
  assert!(
    c.partition_primary_out(0),
    "replica 0 is a live primary the lane deposes"
  );
  assert_eq!(c.stale_read_probes_fired(), 1, "the probe witness advanced");
  // Targeting a non-primary is a no-op: no cut, no witness bump (a false witness would mask the
  // intended primary going unpartitioned).
  assert!(!c.partition_primary_out(1), "replica 1 is not a primary");
  assert_eq!(
    c.stale_read_probes_fired(),
    1,
    "the witness counts only genuine deposals"
  );
  // Both directions are cut for every peer.
  assert!(
    c.one_way_blocked(1, 0) && c.one_way_blocked(0, 1),
    "deaf + mute vs peer 1"
  );
  assert!(
    c.one_way_blocked(2, 0) && c.one_way_blocked(0, 2),
    "deaf + mute vs peer 2"
  );
  // The survivors stop hearing the old primary and fail over to a higher view.
  let mut failed_over = false;
  for _ in 0..200_000 {
    c.tick();
    if c.any_replica_view_advanced_beyond(0) {
      failed_over = true;
      break;
    }
  }
  assert!(
    failed_over,
    "deposing the primary (deaf + mute) forces the survivors to elect a new primary"
  );
  // A new primary now serves in a higher view; replica 0, still cut, is at best a STALE old-view
  // primary (or has forfeited) — NOT the cluster's serving primary. Re-targeting it must be a
  // no-op with the witness unchanged: a status-agnostic predicate would wrongly count the stale
  // primary and leave the real one unpartitioned.
  let mut serving = None;
  for _ in 0..200_000 {
    c.tick();
    if let Some(p) = c.serving_primary()
      && c.replica_view(p).get() > 0
    {
      serving = Some(p);
      break;
    }
  }
  let serving = serving.expect("a new serving primary stabilized in a higher view");
  assert_ne!(
    serving, 0,
    "the deposed primary 0 is not the new serving primary"
  );
  let witness = c.stale_read_probes_fired();
  assert!(
    !c.partition_primary_out(0),
    "the deposed old-view primary 0 is not the serving primary {serving}"
  );
  assert_eq!(
    c.stale_read_probes_fired(),
    witness,
    "no false witness for a stale old-view primary"
  );
  // Heal restores full connectivity; the witness is monotone (a heal never lowers it).
  c.heal();
  assert!(
    !c.one_way_blocked(1, 0) && !c.one_way_blocked(0, 1),
    "heal cleared the cut"
  );
  assert_eq!(
    c.stale_read_probes_fired(),
    1,
    "the witness is monotone across heal"
  );
}

#[test]
fn slow_profile_delays_but_delivers_and_clears() {
  // The GRAY-FAILURE profile: a slow replica's messages ARRIVE (never dropped), each at least
  // `min_extra` later than an unshaped message — late, not lost — and clearing the profile
  // restores prompt delivery (and stops consuming PRNG draws).
  let mut c = Cluster::new(3, 1, 1, /*seed*/ 7);
  let now = c.now();
  let small = Message::Commit(viewstamp_proto::Commit::new(
    viewstamp_proto::View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    viewstamp_proto::Epoch::new(0),
    0,
  ));
  let min_extra = Duration::from_millis(5);
  c.set_slow_replica(
    1,
    Some(SlowProfile {
      inbound: true,
      outbound: true,
      min_extra,
      max_extra: Duration::from_millis(20),
    }),
  );
  // Outbound leg (slow sender) and inbound leg (slow receiver): both delayed by >= min_extra over
  // the base latency; an unrelated 0 → 2 message is unshaped. No jitter in the default fault
  // plan, so the base delivery is exactly `now + latency`.
  let base = now + Faults::none().latency;
  c.schedule(
    now,
    Peer::Replica(ReplicaId::new(1)),
    Target::Replica(2),
    small.clone(),
  );
  c.schedule(
    now,
    Peer::Replica(ReplicaId::new(0)),
    Target::Replica(1),
    small.clone(),
  );
  c.schedule(
    now,
    Peer::Replica(ReplicaId::new(0)),
    Target::Replica(2),
    small.clone(),
  );
  let due = c.net.take_due(now + Duration::from_secs(3600));
  assert_eq!(due.len(), 3, "slow messages are DELIVERED, not dropped");
  let at = |from: u16, to: u16| {
    due
      .iter()
      .find(|m| m.from == Peer::Replica(ReplicaId::new(from)) && m.target == Target::Replica(to))
      .expect("the scheduled message is in flight")
      .deliver_at
  };
  assert!(
    at(1, 2) >= base + min_extra,
    "the slow sender's outbound message is late by at least the band floor"
  );
  assert!(
    at(0, 1) >= base + min_extra,
    "the slow receiver's inbound message is late by at least the band floor"
  );
  assert_eq!(
    at(0, 2),
    base,
    "a message not touching the slow replica is unshaped"
  );
  assert_eq!(c.slow_delays_applied(), 2, "both shaped legs are counted");
  // Clearing restores prompt delivery.
  c.clear_slow_replicas();
  c.schedule(
    now,
    Peer::Replica(ReplicaId::new(0)),
    Target::Replica(1),
    small,
  );
  let due = c.net.take_due(now + Duration::from_secs(3600));
  assert_eq!(
    due[0].deliver_at, base,
    "clearing the profile restores prompt delivery"
  );
  assert_eq!(
    c.slow_delays_applied(),
    2,
    "no further delays after the clear"
  );
}

#[test]
fn durable_view_checker_flags_a_sync_checkpoint_above_the_durable_view() {
  // CHECKER NON-VACUITY: the durable-view oracle must flag a `SyncCheckpoint` advertising a view
  // ABOVE the emitter's durable view — the state-sync serve participates like
  // StartView/RecoveryResponse/DoViewChange/Prepare/PrepareOk/Commit. A fresh cluster's durable
  // view is 0; a SyncCheckpoint(view=1) is therefore a participation in a not-yet-durable view and
  // MUST trip.
  let mut c = Cluster::new(3, 1, 1, 1);
  assert_eq!(
    c.replica_durable_view(0).get(),
    0,
    "fresh durable view is 0"
  );
  let serve = Outgoing::new(
    Recipient::To(Peer::Replica(ReplicaId::new(2))),
    Message::SyncCheckpoint(viewstamp_proto::SyncCheckpoint::new(
      viewstamp_proto::View::with(1), // above the durable view 0
      OpNumber::with(4),
      0,
      viewstamp_proto::Epoch::new(0),
      0,
      ReplicaId::new(0),
      0xD18F,
      bytes::Bytes::from_static(b"snapshot"),
      Bytes::new(),
    )),
  );
  c.record_durable_view_violation(0, &serve);
  let why = c
    .take_durable_view_violation()
    .expect("a SyncCheckpoint above the durable view must be flagged");
  assert!(
    why.contains("SyncCheckpoint"),
    "the violation names the offending message kind: {why}"
  );
  // Control: a SyncCheckpoint AT the durable view (view 0) is a legitimate serve — not flagged.
  let ok_serve = Outgoing::new(
    Recipient::To(Peer::Replica(ReplicaId::new(2))),
    Message::SyncCheckpoint(viewstamp_proto::SyncCheckpoint::new(
      viewstamp_proto::View::with(0), // == durable view 0
      OpNumber::with(4),
      0,
      viewstamp_proto::Epoch::new(0),
      0,
      ReplicaId::new(0),
      0xD18F,
      bytes::Bytes::from_static(b"snapshot"),
      Bytes::new(),
    )),
  );
  c.record_durable_view_violation(0, &ok_serve);
  assert!(
    c.take_durable_view_violation().is_none(),
    "a SyncCheckpoint at the durable view is a legitimate serve and must NOT be flagged"
  );
}

#[test]
fn learner_emission_checker_exempts_a_message_minted_while_a_voter_even_if_since_demoted() {
  // Draining a queued message into the checker is not atomic with the step that minted it, so the
  // emitter's LIVE role by the time anything asks may no longer match its role when the message was
  // actually built. The checker asserts against the RECORDED mint-time role passed in here, never
  // replica 0's role right now (which this test never even touches) — so an old, legitimate vote
  // cast while the emitter was a voter is exempt no matter what it is by the time the checker runs.
  let mut c = Cluster::new(3, 1, 1, /*seed*/ 3);
  let vote = Message::StartViewChange(viewstamp_proto::StartViewChange::new(
    viewstamp_proto::View::with(1),
    ReplicaId::new(0),
    viewstamp_proto::Epoch::new(0),
    0,
  ));
  c.record_learner_emission_violation(0, &vote, /* emitter_was_voter */ true);
  assert!(
    c.take_learner_emission_violation().is_none(),
    "a counted message minted while the emitter was a voter must never be flagged"
  );
}

#[test]
fn learner_emission_checker_flags_a_message_minted_while_a_learner_even_if_since_promoted() {
  // The mirror race: a learner that emits a counted message (a genuine bug) and is THEN promoted
  // before the checker runs must still be flagged — the violation happened at mint, and a later
  // promote cannot retroactively legitimize it. The prior epoch-lag inference could never see this:
  // it only compared epochs once the emitter was ALREADY observed as non-voting, so a since-promoted
  // emitter skipped the check entirely. Asserting against the recorded mint-time role closes that
  // gap: the verdict here never reads any live role at all.
  let mut c = Cluster::new(3, 1, 1, /*seed*/ 3);
  let vote = Message::StartViewChange(viewstamp_proto::StartViewChange::new(
    viewstamp_proto::View::with(1),
    ReplicaId::new(0),
    viewstamp_proto::Epoch::new(0),
    0,
  ));
  c.record_learner_emission_violation(0, &vote, /* emitter_was_voter */ false);
  let why = c
    .take_learner_emission_violation()
    .expect("a counted message minted while the emitter was NOT a voter must be flagged");
  assert!(
    why.contains("StartViewChange"),
    "the violation names the offending message kind: {why}"
  );
  // Control: a non-counted message kind (e.g. Commit) is never this checker's concern, regardless
  // of the emitter's recorded role — only PrepareOk/StartViewChange/DoViewChange are counted votes.
  let mut c2 = Cluster::new(3, 1, 1, /*seed*/ 3);
  let commit = Message::Commit(viewstamp_proto::Commit::new(
    viewstamp_proto::View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    viewstamp_proto::Epoch::new(0),
    0,
  ));
  c2.record_learner_emission_violation(0, &commit, /* emitter_was_voter */ false);
  assert!(
    c2.take_learner_emission_violation().is_none(),
    "a non-counted message kind is never this checker's concern"
  );
}

#[test]
fn network_drops_an_oversized_inter_replica_message_but_not_small_or_client_ones() {
  // The CONVERSE that proves the frame cap is REAL: a full-`Present` 8-entry `DoViewChange` of
  // large bodies — the carrier shape header-only carriers exist to avoid — EXCEEDS `MAX_FRAME_LEN`,
  // and the sim network drops it on the
  // inter-replica path (counting it), while a header-only carrier of the SAME band, a small message,
  // and an (oversized) client-bound message all pass. This is the modelled transport send-path frame
  // guard; it is what makes the VOPR's `oversized_dropped == 0` for legitimate traffic a real oracle.
  use viewstamp_proto::{
    ClientId, DoViewChange, MAX_FRAME_LEN, OpNumber, PreparedEntry, ReplicaId, RequestNumber, View,
    max_request_body_len,
  };

  let big = max_request_body_len() / 4; // each ~4 MiB; 8 of them full-bodied dwarf the 16 MiB frame
  let body = bytes::Bytes::from(std::vec![0x5Au8; big]);
  let full_body: Vec<PreparedEntry> = (1..=8u64)
    .map(|op| {
      PreparedEntry::new(
        OpNumber::with(op),
        ClientId::new(7),
        RequestNumber::with(op),
        body.clone(),
      )
    })
    .collect();
  let header_only: Vec<PreparedEntry> = (1..=8u64)
    .map(|op| {
      PreparedEntry::repairing(
        OpNumber::with(op),
        ClientId::new(7),
        RequestNumber::with(op),
        0,
      )
    })
    .collect();
  let dvc_full = Message::DoViewChange(DoViewChange::new(
    View::with(1),
    View::with(1),
    OpNumber::with(8),
    OpNumber::with(8),
    viewstamp_proto::Epoch::new(0),
    0,
    ReplicaId::new(0),
    full_body,
  ));
  let dvc_header = Message::DoViewChange(DoViewChange::new(
    View::with(1),
    View::with(1),
    OpNumber::with(8),
    OpNumber::with(8),
    viewstamp_proto::Epoch::new(0),
    0,
    ReplicaId::new(0),
    header_only,
  ));
  // The full-body band is over the frame; the header-only band of the SAME ops is far under it.
  assert!(
    dvc_full.encoded_len() > MAX_FRAME_LEN as usize,
    "a full-body 8-entry DoViewChange of large bodies must exceed the frame cap (the old bug)"
  );
  assert!(
    dvc_header.encoded_len() < MAX_FRAME_LEN as usize,
    "a header-only DoViewChange of the same band must fit the frame cap"
  );

  let mut c = Cluster::new(3, 1, 1, /*seed*/ 7);
  let now = c.now();
  let from = Peer::Replica(ReplicaId::new(0));
  // Peer → peer, oversized: DROPPED + counted.
  c.schedule(now, from, Target::Replica(1), dvc_full.clone());
  assert_eq!(
    c.oversized_dropped(),
    1,
    "an oversized inter-replica message is dropped by the send-path frame guard and counted"
  );
  assert!(
    c.net.is_empty(),
    "the oversized peer message was dropped, not enqueued"
  );
  // Peer → peer, header-only (same band): delivered, no new drop.
  c.schedule(now, from, Target::Replica(1), dvc_header.clone());
  assert_eq!(
    c.oversized_dropped(),
    1,
    "a header-only carrier of the same band fits the frame and is NOT dropped"
  );
  assert!(!c.net.is_empty(), "the header-only carrier was enqueued");
  // A small peer message: delivered, no new drop.
  let small = Message::Commit(viewstamp_proto::Commit::new(
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    viewstamp_proto::Epoch::new(0),
    0,
  ));
  c.schedule(now, from, Target::Replica(2), small);
  assert_eq!(
    c.oversized_dropped(),
    1,
    "a small peer message is never dropped"
  );
  // An oversized CLIENT-bound message is NOT capped here (only peer traffic is — mirroring what the
  // real transport drops). Build a Reply that itself exceeds the frame and confirm it is not dropped.
  let huge_reply = Message::Reply(viewstamp_proto::Reply::new(
    View::with(1),
    ClientId::new(1),
    RequestNumber::with(1),
    bytes::Bytes::from(std::vec![0u8; MAX_FRAME_LEN as usize + 1024]),
  ));
  assert!(huge_reply.encoded_len() > MAX_FRAME_LEN as usize);
  c.schedule(now, from, Target::Client(1), huge_reply);
  assert_eq!(
    c.oversized_dropped(),
    1,
    "a client-bound message is not subject to the inter-replica frame cap (different path)"
  );
}

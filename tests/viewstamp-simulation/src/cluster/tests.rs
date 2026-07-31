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
fn the_durability_budget_bounds_permanent_faults_a_unanimous_quorum_cannot_absorb() {
  // Two voters: the quorum is unanimous, so `f` is 0 and destroying even ONE durable copy of a
  // committed op leaves it recoverable from nowhere — outside the model the protocol is proved
  // against, and a wedge there measures the injector rather than the endpoint. With a CERTAIN
  // torn-write and bit-rot roll on every append the cluster-wide budget is the only thing standing
  // between the run and that state, so it must refuse and the cluster must still commit.
  let mut c = Cluster::new(2, 2, 4, /*seed*/ 11);
  c.set_storage_faults(StorageFaults {
    torn_write_per_mille: 1000,
    bit_rot_per_mille: 1000,
    ..StorageFaults::none()
  });
  for _ in 0..5_000 {
    c.tick();
  }
  assert!(
    c.permanent_faults_refused() > 0,
    "the bound never engaged, so this lane proves nothing"
  );
  assert!(
    c.replica_commit(0).get() > 0,
    "with every permanent fault refused the cluster commits normally"
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

/// A completion minted by a PREVIOUS endpoint over the same storage is refused, not dispatched.
///
/// # The hazard this closes
///
/// A storage correlation id ([`OpId`](viewstamp_proto::OpId)) carries the incarnation of the
/// `Endpoint` that minted it alongside a sequence number, and the SEQUENCE restarts at `1` in every
/// new endpoint. Were the sequence the whole id, two endpoints over one store would mint equal ids,
/// and a completion produced for the dead one and delivered to the live one would alias onto
/// whatever the live one happened to have in flight under that number — dispatched as though its
/// own write had landed. The incarnation is what makes those ids distinguishable, and the endpoint
/// refuses any completion that does not carry its own.
///
/// [`crash`](Cluster::crash) cannot exercise this: it models power loss, so it discards the staged
/// writes and undelivered completions — exactly the evidence that would alias.
/// [`restart_in_place`](Cluster::restart_in_place) retains them, which is what a supervised endpoint
/// rebuild over a still-running storage layer does.
///
/// # Why the schedule bends the id map before the swap
///
/// Two incarnations' ids collide destructively only where their id → op maps DISAGREE. Recovery
/// spends one id per durable op in the recover window and then resumes appending, so a successor
/// recovering a log its predecessor wrote one-id-per-op re-derives the predecessor's own map: an
/// aliased completion would land on the op it was already for, and nothing observable would happen
/// either way. Deposing the view-0 primary bends the map — the view change makes the survivors mint
/// ids that are not plain head-extending appends (the durable-view root write) and re-append an
/// adopted tail out of op order — so the predecessor's ids run ahead of its op numbers while the
/// successor's, derived from the durable log alone, do not. With the constants below the predecessor
/// leaves eight appends in flight and the successor mints one of those same SEQUENCE NUMBERS for a
/// LATER op. That is the collision the incarnation has to separate, so the test is only meaningful
/// while this schedule keeps producing it — hence the inherited-work precondition below.
///
/// # What is asserted
///
/// The retaining arm must come out indistinguishable from the control on both oracles:
///
/// - no `PrepareOk` for an op whose WAL slot is still `Dirty`
///   ([`take_append_before_ack_violation`](Cluster::take_append_before_ack_violation)) — the replica
///   votes for an op only once its OWN incarnation's append is durable; and
/// - no committed op left below its durable quorum
///   ([`DurableQuorumChecker`](crate::checker::DurableQuorumChecker)), the consequence that a forged
///   vote used to produce.
///
/// Both would also hold if the foreign completions simply never arrived, so the rejection COUNTER is
/// asserted non-zero: it proves completions really were delivered and really were refused, rather
/// than the lane having gone quietly vacuous. The control arm runs the IDENTICAL schedule through
/// `crash` + `restart`, differing only in discarding the in-flight work, and refuses nothing.
#[test]
fn a_foreign_completion_is_refused_across_an_in_place_restart() {
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

  /// What one arm observed: how much in-flight work the successor inherited, how many completions it
  /// refused as foreign, and the first violation of each oracle after the swap.
  struct Observed {
    inherited: usize,
    refused: u64,
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
  /// Ticks after the swap, long enough that a forged ack and the committed-op retention breach it
  /// caused would both have landed well inside the window.
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
      refused: 0,
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
    // Read on the SUCCESSOR endpoint, which is the one doing the refusing; the counter belongs to the
    // endpoint instance, so it starts at zero when the swap installs it.
    observed.refused = c.replica_foreign_completions_rejected(2);
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
  assert_eq!(
    control.refused, 0,
    "a crash leaves nothing behind to refuse, so the discarding lane must refuse nothing"
  );

  let observed = run(Swap::RetainingInFlight);
  assert!(
    observed.inherited > 0,
    "the successor endpoint inherited no in-flight write, so no foreign completion could be \
     delivered — the lane is vacuous and proves nothing"
  );
  // The lane is live: completions from the dead endpoint really did arrive at the successor and were
  // really refused. Without this the two oracles below would also pass on a run where nothing was
  // ever delivered, which is the vacuous way to be green.
  assert!(
    observed.refused > 0,
    "the successor inherited {} in-flight write(s) but refused no completion — the predecessor's \
     completions are not reaching it, so this lane no longer exercises the choke",
    observed.inherited
  );
  assert!(
    observed.forged_ack.is_none(),
    "a refused completion still released a vote: the replica acked an op whose own append is not \
     durable: {:?}",
    observed.forged_ack
  );
  assert!(
    observed.lost_durable_quorum.is_none(),
    "a committed op fell below its durable quorum despite the refusal: {:?}",
    observed.lost_durable_quorum
  );
}

/// Crossing the retaining rebuild with the REORDERING device: an in-place restart under write
/// chaos must keep every slot's durable content owned by its newest writer.
///
/// The test above proves the incarnation choke refuses a predecessor's COMPLETIONS; this one is
/// about its WRITES. Under the ordered async WAL that test uses, a serial writer completes the
/// predecessor's staged appends strictly before any successor write to the same slot, so the
/// refusal is the whole story. Under write chaos the staged appends are un-cancellable device
/// writes that complete in a seeded out-of-submission order — so a predecessor's abandoned append
/// can land AFTER the successor endpoint has re-appended that op and released its vote on the
/// completion of its own write. Refusing the late completion un-sends nothing: the physical slot
/// then holds the dead incarnation's bytes underneath a vote the primary counted by content.
///
/// The schedule is the sibling test's, chaos-crossed: depose the view-0 primary (bending the two
/// incarnations' id → op maps), rebuild replica 2 in place with several appends in flight, and let
/// the chaos device drain. The stale-landing oracle judges every landing: no write minted by an
/// older incarnation may land over content a newer incarnation landed. The presence-based oracles
/// (append-before-ack, durable quorum) are asserted clean alongside, which is exactly the
/// blindness: they count occupied slots, so an eviction that leaves the slot occupied is invisible
/// to them.
#[test]
fn an_in_place_restart_under_write_chaos_keeps_every_voted_slots_content() {
  use crate::checker::{CheckResult, DurableQuorumChecker};

  /// The jitter base: chaos appends stay in flight `1..=2 * WAL_DELAY` polls.
  const WAL_DELAY: u32 = 32;
  /// Far above anything this run commits, so no checkpoint fires and every landed slot stays above
  /// the prune floor (nothing the oracle watches is ever legitimately discharged mid-run).
  const NO_CHECKPOINT: u64 = 32_768;
  /// Enough closed-loop clients that several appends are outstanding at once.
  const CLIENTS: u32 = 8;
  /// Ticks of ordinary operation before the primary is deposed, and again before the swap.
  const PHASE_TICKS: u32 = 60;
  /// Ticks after the swap — wide enough that every retained chaos write has landed.
  const OBSERVE_TICKS: u32 = 300;
  /// The run seed. This seed's post-deposition schedule leaves replica 2's successor re-appending
  /// an op the predecessor still has staged, with the chaos release order landing the
  /// predecessor's write LAST — and the replica's recorded vote for that op names the content the
  /// late landing evicts.
  const SEED: u64 = 64;
  /// The chaos-device seed, derived from the run seed.
  const CHAOS_SEED: u64 = SEED ^ 0x00C0_FFEE;

  let mut c = Cluster::with_checkpoint_ops(3, CLIENTS, 200, SEED, NO_CHECKPOINT);
  c.set_async_wal_delay(Some(WAL_DELAY));
  c.set_wal_write_chaos(Some(CHAOS_SEED));
  let mut quorum = DurableQuorumChecker::new();
  for _ in 0..PHASE_TICKS {
    c.tick();
  }
  // Depose the view-0 primary: the view change is what makes the successor's id → op map disagree
  // with its predecessor's (see the sibling test), so a re-minted op can target a slot whose old
  // write is still with the device.
  c.crash(0);
  for _ in 0..PHASE_TICKS {
    c.tick();
  }
  c.restart_in_place(2);
  let inherited = c.wal_staged_len_for_test(2);
  assert!(
    inherited > 0,
    "ANTI-VACUITY: the successor endpoint inherited no in-flight write — the swap retained \
     nothing, so no late landing can exist"
  );

  let mut stale: Option<SmolStr> = None;
  let mut forged_ack: Option<SmolStr> = None;
  let mut lost_quorum: Option<SmolStr> = None;
  for _ in 0..OBSERVE_TICKS {
    c.tick();
    if let Some(v) = c.take_stale_landing_violation() {
      stale.get_or_insert(v);
    }
    if let Some(v) = c.take_append_before_ack_violation() {
      forged_ack.get_or_insert(v);
    }
    if let CheckResult::Violation(v) = quorum.observe(&c) {
      lost_quorum.get_or_insert(v);
    }
  }

  // ANTI-VACUITY: the lane is live — the dead endpoint's completions really were delivered into
  // the successor and refused, and the chaos device really reordered landings on the rebuilt
  // replica.
  assert!(
    c.replica_foreign_completions_rejected(2) > 0,
    "the predecessor's completions never reached the successor — the crossing went vacuous"
  );
  assert!(
    c.wal_write_reorders_fired(2) > 0,
    "the chaos device never reordered a landing on the rebuilt replica — the crossing went vacuous"
  );

  // The presence-based oracles stay clean: an eviction that leaves the slot occupied is exactly
  // what they cannot see.
  assert!(
    forged_ack.is_none(),
    "append-before-ack tripped, so this run's failure is not the silent-eviction shape: \
     {forged_ack:?}"
  );
  assert!(
    lost_quorum.is_none(),
    "the durable-quorum oracle tripped, so this run's failure is not the silent-eviction shape: \
     {lost_quorum:?}"
  );

  // THE INVARIANT: no write minted by an older incarnation landed over durable content a newer
  // incarnation had already landed. The violation message names the evicted content and, when the
  // replica voted for that op, the vote whose durable backing vanished.
  assert!(
    stale.is_none(),
    "an abandoned predecessor write physically evicted a successor's landed slot: {stale:?}"
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

#[test]
fn a_wipe_forfeits_the_checkpoint_blocks_with_the_rest_of_the_disk() {
  // A short checkpoint interval so a checkpoint is published (and its DAG written) within the run.
  let mut c = Cluster::with_checkpoint_ops(3, 2, 40, /*seed*/ 3, /*checkpoint_ops*/ 8);
  for _ in 0..20_000 {
    c.tick();
    if c.replica_reachable_block_count(2) > 0 {
      break;
    }
  }
  assert!(
    !c.block_stores[2].is_empty() && c.replica_reachable_block_count(2) > 0,
    "the replica must hold a materialized checkpoint DAG before the wipe, or the wipe below proves \
     nothing"
  );

  c.crash(2);
  c.wipe_and_restart(2);

  // The blocks ARE the durable checkpoint's contents, so they go with the WAL and the superblock. A
  // wipe that spared them would leave the replica able to restore its state — and to serve it to a
  // peer's `RequestBlock` — from a disk it is supposed to have lost.
  assert!(
    c.block_stores[2].is_empty(),
    "a wiped disk carries no checkpoint block"
  );
  assert_eq!(
    c.replica_reachable_block_count(2),
    0,
    "no block of the pre-wipe checkpoint DAG is still reachable on the replaced medium"
  );
}

#[test]
fn a_wiped_voter_reports_no_durable_evidence() {
  // Far enough to publish a checkpoint AND leave committed ops resident in the WAL above it, so both
  // clauses of `replica_appended_op` have something to lose.
  let mut c = Cluster::with_checkpoint_ops(3, 2, 40, /*seed*/ 3, /*checkpoint_ops*/ 8);
  for _ in 0..20_000 {
    c.tick();
    if c.replica_checkpoint_op(2).get() > 0
      && c.replica_op(2).get() > c.replica_checkpoint_op(2).get()
    {
      break;
    }
  }
  let checkpointed = c.replica_checkpoint_op(2).get();
  let head = c.replica_op(2).get();
  assert!(
    checkpointed > 0 && head > checkpointed,
    "the replica must hold a durable checkpoint AND a resident tail above it before the wipe, or the \
     wipe below proves nothing (checkpoint_op={checkpointed}, op={head})"
  );
  assert!(
    c.replica_appended_op(2, OpNumber::with(checkpointed))
      && c.replica_appended_op(2, OpNumber::with(head)),
    "the replica holds both a snapshot-subsumed op and a WAL-resident one before the wipe"
  );

  c.crash(2);
  let rejoined = c.wipe_and_restart(2);

  // A VOTER fail-stops on the empty disk, so recovery installs no successor endpoint: the handle
  // reachable through the accessors is the PRE-WIPE one, still remembering a checkpoint whose blocks
  // and superblock root are gone. What the accessors report must follow the disk, not the handle —
  // otherwise a replica holding NOTHING is counted as a durable holder of everything it once had.
  assert!(
    !rejoined && c.is_crashed(2),
    "a wiped voter fail-stops and stays down"
  );
  assert!(
    c.replica_storage_wiped(2),
    "the replaced disk has had no endpoint rebuilt over it"
  );
  assert_eq!(
    c.replica_checkpoint_op(2).get(),
    0,
    "a wiped disk backs no checkpoint, whatever the stale endpoint remembers"
  );
  for op in 1..=head {
    assert!(
      !c.replica_appended_op(2, OpNumber::with(op)),
      "a wiped disk holds op {op} neither in a WAL slot nor under a subsuming checkpoint"
    );
  }
}

#[test]
fn a_wiped_learner_that_rejoins_reports_its_own_empty_disk() {
  // The complementary case: a non-voting learner recovers over the emptied store, so an endpoint IS
  // rebuilt and the forfeit state ends at that instant — the accessors go back to reporting the
  // handle, which now reads the replacement disk honestly (empty, so still nothing held).
  let mut c = Cluster::with_members(3, 1, 2, 40, /*seed*/ 3, /*checkpoint_ops*/ 8);
  const LEARNER: usize = 3;
  for _ in 0..20_000 {
    c.tick();
    if c.replica_checkpoint_op(LEARNER).get() > 0 {
      break;
    }
  }
  assert!(
    c.replica_checkpoint_op(LEARNER).get() > 0,
    "the learner must hold a durable checkpoint before the wipe"
  );

  c.crash(LEARNER);
  let rejoined = c.wipe_and_restart(LEARNER);

  assert!(rejoined, "a wiped learner rejoins on the empty disk");
  assert!(
    !c.replica_storage_wiped(LEARNER),
    "the rebuilt endpoint reads the replacement disk, so nothing is stale to correct for"
  );
  assert_eq!(
    c.replica_checkpoint_op(LEARNER).get(),
    0,
    "the rejoined learner recovered an empty store and reports it"
  );
}

//! Deterministic gates for the block-storage job seam.
//!
//! The VOPR's block axes explore these windows under the full adversarial schedule, but a sweep only
//! REPORTS how often it reached one. These tests CONSTRUCT each window and then assert what must hold
//! inside it, so the property is gated whether or not any seed happens to wander in:
//!
//! - a `Materialize` still in flight when a view change abandons the checkpoint it was for publishes
//!   NOTHING, and the durable checkpoint pointer never moves because of it;
//! - commits and heartbeats keep flowing while a storage lane is stalled;
//! - a failed durability barrier leaves no durable root naming its blocks, and the checkpoint the
//!   fault dropped is re-forced on cadence;
//! - a reconstruct whose reads fault still lets the replica converge on the same applied history as
//!   its peers;
//! - a job executed OUT of issue order fail-stops rather than silently corrupting the store, and so
//!   does a completion delivered out of issue order.

use core::time::Duration;

use viewstamp_proto::{BlockAddress, BlockJobTag};
use viewstamp_simulation::{Cluster, Faults, check_safety};

/// Ticks to spend looking for a window before giving up. Generous: each of these tests asserts it
/// REACHED its window, so an exhausted budget fails the test rather than skipping it.
const SEARCH_TICKS: u32 = 20_000;

/// A checkpoint every few ops, so a run reaches many materializes quickly.
const CHECKPOINT_OPS: u64 = 4;

/// Ticks to spend draining to quiescence once a window has been exercised.
const DRAIN_TICKS: u32 = 5_000;

/// The per-replica state `tick_checked` carries between ticks: the durable checkpoint pointer's
/// high-water (which must never regress) and the roots last walked by the flush oracle.
#[derive(Default)]
struct Watch {
  pointer: u64,
  roots: Option<(BlockAddress, BlockAddress)>,
}

/// Drives `c` for one tick and asserts the standing block-layer invariants hold afterwards: no
/// superseded completion published, no replica's durable checkpoint pointer regressed, and no durable
/// checkpoint root names an un-flushed block.
///
/// The flush oracle walks a replica's DAG only when it has PUBLISHED new roots. That is complete, not
/// just cheap: the property can only break at publication, since a held block never leaves the
/// store's flushed set (only the sweep removes it, and the sweep removes the block too).
fn tick_checked(c: &mut Cluster, watch: &mut [Watch]) {
  c.tick();
  assert_eq!(
    c.take_stale_publication_violation(),
    None,
    "a superseded block-job completion advanced a durable checkpoint pointer"
  );
  for (i, w) in watch.iter_mut().enumerate() {
    let op = c.replica_checkpoint_op(i).get();
    assert!(
      op >= w.pointer,
      "replica {i}: durable checkpoint pointer REGRESSED {} -> {op}",
      w.pointer
    );
    w.pointer = op;
    let roots = c.durable_checkpoint_roots(i);
    if roots != w.roots {
      w.roots = roots;
      assert_eq!(
        c.check_replica_durable_checkpoint_flushed(i),
        None,
        "a durable checkpoint root names a block no successful flush made durable"
      );
    }
  }
}

/// The cluster's committed frontier: the highest `commit_max` any replica reached.
fn committed_frontier(c: &Cluster) -> u64 {
  (0..c.node_count())
    .map(|i| c.replica_commit_max(i).get())
    .max()
    .unwrap_or(0)
}

/// A cluster with a tight checkpoint cadence and a mildly lossy network, so checkpoints and view
/// changes both arrive quickly.
fn cluster(seed: u64) -> Cluster {
  let mut c = Cluster::with_checkpoint_ops(3, 2, 400, seed, CHECKPOINT_OPS);
  c.set_faults(Faults {
    latency: Duration::from_millis(1),
    jitter: Duration::from_millis(2),
    drop_per_mille: 10,
    duplicate_per_mille: 10,
    hold_per_mille: 0,
  });
  c
}

/// A `Materialize` caught mid-flight by a view change publishes NOTHING.
///
/// The window is built rather than waited for: replica 1's storage lane is STALLED, so whatever job
/// reaches its head stays in flight for as long as the test wants. Once that job is a `Materialize`,
/// the primary is crashed to force a view change, and replica 1 is confirmed to still be holding the
/// materialize at the moment its view advances — that confirmation is the whole point, since a test
/// that let the job finish first would assert about a window it never entered.
///
/// The publication claim is judged PER COMPLETION by `tick_checked`, not by comparing the pointer
/// before and after: the cadence RE-FORCES the checkpoint the transition dropped, so the pointer
/// legitimately advances again moments later on a different completion, and a before/after comparison
/// would report that as a stale publication. The cluster instead samples the pointer across each
/// `on_block_done`, so a rise on a SUPERSEDED completion is attributable to it and to nothing else.
#[test]
fn a_materialize_superseded_by_a_view_change_publishes_nothing() {
  let mut c = cluster(7);
  let mut watch: Vec<Watch> = (0..c.node_count()).map(|_| Watch::default()).collect();

  // Let replica 1 publish a real durable checkpoint FIRST. Stalling its lane from tick zero would
  // leave it with no checkpoint at all, and every claim below about its pointer would then be a claim
  // about a replica that never had one to move.
  let mut published = false;
  for _ in 0..SEARCH_TICKS {
    tick_checked(&mut c, &mut watch);
    if c.replica_checkpoint_op(1).get() > 0 {
      published = true;
      break;
    }
  }
  assert!(
    published,
    "replica 1 never published a durable checkpoint — it has no pointer a stale publication could \
     move"
  );

  // Now stall its lane and wait for a materialize to land at the head.
  c.set_block_lane_paused(1, true);
  let mut found = false;
  for _ in 0..SEARCH_TICKS {
    tick_checked(&mut c, &mut watch);
    if c.held_block_job_tag(1) == Some(BlockJobTag::Materialize) {
      found = true;
      break;
    }
  }
  assert!(
    found,
    "no Materialize ever reached the stalled lane's head — the window was never entered"
  );

  // Force a view change under it. The materializing replica must SURVIVE it (a crash would discard
  // the in-flight job instead of superseding its completion), so the PRIMARY is what goes down.
  let view_before = c.replica_view(1).get();
  let primary = c.serving_primary().expect("a serving primary");
  assert_ne!(
    primary, 1,
    "the materializing replica must not be the one crashed"
  );
  c.crash(primary);
  let mut transitioned = false;
  for _ in 0..SEARCH_TICKS {
    tick_checked(&mut c, &mut watch);
    if c.replica_view(1).get() > view_before {
      transitioned = true;
      break;
    }
  }
  assert!(
    transitioned,
    "no view change formed after the primary crashed"
  );
  // THE PRECONDITION, asserted rather than assumed: the materialize is STILL in flight now that the
  // view has moved under it. Without this the test could pass on a run where the job had already
  // completed and no supersession was ever possible.
  assert_eq!(
    c.held_block_job_tag(1),
    Some(BlockJobTag::Materialize),
    "the materialize completed before the view change — the supersession window was never open"
  );
  assert_eq!(
    c.materializes_superseded_in_flight(),
    0,
    "a supersession was counted before the lane was released"
  );

  // Release the lane. What must NOT happen is that the superseded completion PUBLISHES, and that is
  // judged per completion by `tick_checked` — the cluster samples the durable checkpoint pointer
  // across each `on_block_done`, so a rise on a superseded one is attributable to it and nothing
  // else. A bare before/after comparison would not do: the cadence RE-FORCES the checkpoint the
  // transition dropped, so the pointer legitimately advances again moments later, on a different
  // completion.
  c.set_block_lane_paused(1, false);
  let mut superseded = false;
  for _ in 0..SEARCH_TICKS {
    tick_checked(&mut c, &mut watch);
    if c.materializes_superseded_in_flight() > 0 {
      superseded = true;
      break;
    }
    if c.held_block_job_tag(1).is_none() {
      break; // the lane drained without a supersession — fail below with the counter's value.
    }
  }
  assert!(
    superseded,
    "the released materialize was NOT dropped as superseded (count {}) — the view transition should \
     have abandoned the checkpoint it answered",
    c.materializes_superseded_in_flight()
  );

  // And the cluster recovers: restart the crashed primary, drain, and every replica agrees.
  c.restart(primary);
  c.set_faults(Faults::none());
  for _ in 0..SEARCH_TICKS {
    tick_checked(&mut c, &mut watch);
    if c.is_quiescent() {
      break;
    }
  }
  assert!(
    matches!(check_safety(&c), viewstamp_simulation::CheckResult::Ok),
    "replicas diverged after a superseded materialize: {:?}",
    check_safety(&c)
  );
  // Agreement alone is satisfied by a replica holding nothing, so assert the catch-up directly: the
  // replica whose materialize was superseded is back at the cluster's committed frontier.
  let frontier = committed_frontier(&c);
  assert!(
    frontier > 0,
    "the cluster committed nothing, so catching up means nothing"
  );
  assert_eq!(
    c.replica_commit_max(1).get(),
    frontier,
    "replica 1 never caught back up after its materialize was superseded — the dropped checkpoint \
     must cost a cadence, not the replica"
  );
}

/// A STALLED storage lane does not stall consensus: the cluster keeps committing and the stalled
/// replica keeps heartbeating while a block job sits outstanding on its lane.
///
/// This is the property the whole job seam was built for, and it is unobservable while block work
/// executes instantaneously. The lane stalled is the SERVING PRIMARY's — the sharpest form of the
/// claim, since the primary is what drives both commits and the heartbeat cadence, and an inline
/// executor would have parked exactly that replica's pump inside the job.
///
/// SCOPE, stated honestly: the claim is that block work does not block the PUMP, not that a dead
/// block store can be ignored forever. A cluster where NO replica can complete a checkpoint stops
/// committing within a small window by design — the durable checkpoint is what lets the log advance —
/// and that bound is a separate protocol property, not this one. Stalling one replica's lane keeps
/// the rest of the cluster checkpointing, so what is measured here is exactly the pump's independence
/// from the lane.
#[test]
fn commits_and_heartbeats_advance_while_a_block_job_is_outstanding() {
  // No faults: the claim is about the storage lane, so the primary must stay put and any progress
  // failure is attributable to the stall rather than to a view change.
  let mut c = Cluster::with_checkpoint_ops(3, 2, 1_500, 11, CHECKPOINT_OPS);
  let mut watch: Vec<Watch> = (0..c.node_count()).map(|_| Watch::default()).collect();

  for _ in 0..2_000 {
    tick_checked(&mut c, &mut watch);
  }
  let stalled = c
    .serving_primary()
    .expect("a serving primary after warm-up");
  c.set_block_lane_paused(stalled, true);

  // Run until the stalled lane is genuinely occupied — the precondition, asserted not assumed.
  let mut outstanding = false;
  for _ in 0..SEARCH_TICKS {
    tick_checked(&mut c, &mut watch);
    if c.block_job_outstanding(stalled) {
      outstanding = true;
      break;
    }
  }
  assert!(
    outstanding,
    "no block job ever reached the stalled lane — the anti-stall window was never entered"
  );

  let committed_before = committed_frontier(&c);
  let heartbeats_before = c.heartbeats_while_block_job_outstanding();
  for _ in 0..4_000 {
    tick_checked(&mut c, &mut watch);
    // The stall must PERSIST for the measurement to mean anything: a lane that drained would make
    // the progress below ordinary progress rather than progress beside a busy lane.
    assert!(
      c.block_job_outstanding(stalled),
      "the stalled lane drained — the measured progress is no longer attributable to the stall"
    );
  }
  let committed_after = committed_frontier(&c);
  assert!(
    committed_after > committed_before,
    "the cluster committed NOTHING ({committed_before} -> {committed_after}) while replica \
     {stalled}'s storage lane was stalled — block I/O is back on the consensus pump"
  );
  assert!(
    c.heartbeats_while_block_job_outstanding() > heartbeats_before,
    "replica {stalled} emitted no heartbeat while its storage lane was busy — the liveness cadence \
     stopped with the block layer"
  );

  // Release and converge, so the stall is a delay and not a wedge. A stalled lane leaves a long
  // un-checkpointed band behind it, so the drain gets its own budget rather than the search budget.
  c.set_block_lane_paused(stalled, false);
  for _ in 0..DRAIN_TICKS {
    tick_checked(&mut c, &mut watch);
    if c.is_quiescent() {
      break;
    }
  }
  assert!(
    matches!(check_safety(&c), viewstamp_simulation::CheckResult::Ok),
    "replicas diverged after a storage-lane stall: {:?}",
    check_safety(&c)
  );
}

/// A FAILED durability barrier publishes no checkpoint, and the cadence re-forces the one it dropped.
///
/// The oracle runs every tick throughout (`tick_checked`): no durable checkpoint root may name a
/// block that no successful flush made durable. The faults are asserted to have FIRED, and the
/// checkpoint pointer is asserted to have advanced ANYWAY — a run where the fault never fired would
/// prove nothing, and one where the pointer never recovered would mean the fault is terminal rather
/// than a re-forced interval.
#[test]
fn a_failed_flush_publishes_no_checkpoint_and_the_cadence_re_forces_it() {
  let mut c = cluster(23);
  c.set_block_flush_faults(Some(0xB10C_F105_4FA0_5EED));
  let mut watch: Vec<Watch> = (0..c.node_count()).map(|_| Watch::default()).collect();

  for _ in 0..6_000 {
    tick_checked(&mut c, &mut watch);
  }
  assert!(
    c.block_flush_faults_fired() > 0,
    "no durability barrier ever failed — the flush-fault plan is inert and the oracle judged a \
     fault-free run"
  );
  // Re-forcing: despite the faults, checkpoints still land. A pointer stuck at 0 would mean a
  // faulted barrier permanently wedges the checkpoint rather than costing it one cadence.
  assert!(
    watch.iter().any(|w| w.pointer > 0),
    "no replica ever published a checkpoint under flush faults ({} fired) — a failed barrier is \
     wedging the cadence instead of costing it an interval",
    c.block_flush_faults_fired()
  );

  c.set_faults(Faults::none());
  for _ in 0..SEARCH_TICKS {
    tick_checked(&mut c, &mut watch);
    if c.is_quiescent() {
      break;
    }
  }
  assert!(
    matches!(check_safety(&c), viewstamp_simulation::CheckResult::Ok),
    "replicas diverged under block-store flush faults: {:?}",
    check_safety(&c)
  );
  // One final whole-cluster verdict, unmemoized: every replica's durable checkpoint, walked in full.
  // The per-tick path above only walks a replica that published new roots, which is complete but
  // narrow; this closes the run by re-checking every held DAG at once.
  assert_eq!(
    c.check_durable_checkpoint_flushed(),
    None,
    "a durable checkpoint root names an un-flushed block at the end of a flush-fault run"
  );
  // And the faults cost intervals, not progress: every replica ends at the committed frontier.
  let frontier = committed_frontier(&c);
  assert!(
    frontier > 0,
    "the cluster committed nothing under flush faults, so agreement means nothing"
  );
  for i in 0..c.node_count() {
    assert_eq!(
      c.replica_commit_max(i).get(),
      frontier,
      "replica {i} did not reach the committed frontier under flush faults — a failed barrier is \
       costing progress rather than a checkpoint interval"
    );
  }
}

/// Builds a cluster whose replica 0 has TWO jobs queued on a stalled storage lane, ready to be
/// executed out of order. Panics if the window is never reached, so a falsifier built on it can never
/// pass by having nothing to reorder.
fn cluster_with_two_queued_block_jobs() -> Cluster {
  let mut c = cluster(7);
  c.set_block_lane_paused(0, true);
  // Drop a replica far behind and bring it back, so it state-syncs and replica 0 serves its blocks —
  // which is what puts a second job behind the checkpoint the stall is already holding.
  for t in 0..SEARCH_TICKS {
    match t {
      1_500 => c.crash(2),
      5_000 => c.restart(2),
      _ => {}
    }
    c.tick();
    if c.held_block_job_count(0) >= 2 {
      return c;
    }
  }
  panic!(
    "replica 0's stalled lane never held two jobs — the falsifier had no reordering to perform"
  );
}

/// A job EXECUTED out of issue order is caught by the lane cursor, before it touches the store.
///
/// The lane's order is a storage-safety obligation, not a convenience: a `Gc` carrying one checkpoint
/// generation's live roots, executed after the next generation's `Materialize`, frees the very blocks
/// the next durable root is about to name. The harness's own lane is FIFO by construction and so
/// cannot produce the violation by accident — which is exactly why it is produced ON PURPOSE here,
/// through the real executor, the real cursor and the real store.
///
/// Completions are NOT delivered here, so the cursor is the only guard that can object. That is the
/// half of the contract protecting the STORE; the delivery half is
/// [`an_out_of_order_block_job_completion_fail_stops`].
#[test]
#[should_panic(expected = "block job executed out of issue order")]
fn a_block_job_executed_out_of_issue_order_fail_stops() {
  let mut c = cluster_with_two_queued_block_jobs();
  c.execute_held_block_jobs_out_of_issue_order_for_test(0, /*deliver*/ false);
}

/// A COMPLETION delivered out of issue order is caught by the endpoint, before it reaches any
/// correlation state.
///
/// The same reordering as above, with the completions fed back. The endpoint objects on the very
/// first one — it knows which job it is owed next — so the violation is caught even earlier than the
/// cursor would catch it. Both guards are asserted because a driver can break either half
/// independently: it can execute in order and deliver out of order just as easily as the reverse.
#[test]
#[should_panic(expected = "block job completion out of issue order")]
fn an_out_of_order_block_job_completion_fail_stops() {
  let mut c = cluster_with_two_queued_block_jobs();
  c.execute_held_block_jobs_out_of_issue_order_for_test(0, /*deliver*/ true);
}

/// A reconstruct whose reads FAULT leaves the replica able to try again and converge.
///
/// The fault is delivered asynchronously, through the same completion a clean reconstruct rides. A
/// replica is crashed and restarted far behind so it must state-sync and rebuild its state machine
/// from a fetched checkpoint — the one path that issues `Restore` jobs — and the plan faults some of
/// those rebuilds. Both halves of the arming witness are asserted: the plan armed a job, AND that job
/// actually READ (an arm nothing consumed would prove no fault was delivered).
#[test]
fn a_faulted_reconstruct_still_converges() {
  let mut c = cluster(31);
  c.set_block_restore_faults(Some(0x2E57_04E5_5EED_B10C));
  let mut watch: Vec<Watch> = (0..c.node_count()).map(|_| Watch::default()).collect();

  // Take replica 2 down long enough that it must fetch a checkpoint rather than repair a tail.
  for _ in 0..1_500 {
    tick_checked(&mut c, &mut watch);
  }
  c.crash(2);
  for _ in 0..6_000 {
    tick_checked(&mut c, &mut watch);
  }
  c.restart(2);
  for _ in 0..SEARCH_TICKS {
    tick_checked(&mut c, &mut watch);
    if c.block_restore_faults_armed() > 0 && c.block_read_faults_fired() > 0 {
      break;
    }
  }
  assert!(
    c.block_restore_faults_armed() > 0,
    "no reconstruct was ever armed with a read fault — the restore-fault plan never fired"
  );
  assert!(
    c.block_read_faults_fired() > 0,
    "a reconstruct was armed ({}) but swallowed no read — the fault was never delivered into a job",
    c.block_restore_faults_armed()
  );

  c.set_faults(Faults::none());
  for _ in 0..SEARCH_TICKS {
    tick_checked(&mut c, &mut watch);
    if c.is_quiescent() {
      break;
    }
  }
  assert!(
    matches!(check_safety(&c), viewstamp_simulation::CheckResult::Ok),
    "replicas diverged after a faulted reconstruct: {:?}",
    check_safety(&c)
  );
  // Agreement alone would be satisfied by a replica that holds NOTHING (the empty prefix agrees with
  // every history), so the catch-up is asserted directly: the replica whose rebuilds were faulted
  // reached the cluster's committed frontier.
  let frontier = committed_frontier(&c);
  assert!(
    frontier > 0,
    "the cluster committed nothing, so catching up means nothing"
  );
  assert_eq!(
    c.replica_commit_max(2).get(),
    frontier,
    "replica 2 never caught up after its reconstructs were faulted — a faulted rebuild must cost a \
     retry, not the catch-up"
  );
}

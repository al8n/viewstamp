//! The WAL read-delay axis, driven to the state it exists to reach: a recovery read still
//! outstanding when its op's retransmission budget runs out.
//!
//! The synchronous in-memory WAL resolves every read in the call that submitted it. A recovery read
//! therefore always beats the proto's read budget, an op never resolves from its durable header with
//! a live correlation, and everything an endpoint does with a completion arriving after that point is
//! unreachable — the carried-correlation lane, its identity and durability gates, its append barrier,
//! and the promoted head's restore. [`Cluster::set_wal_read_delay`] gives reads a latency, with a
//! seeded minority of slots answering only past the whole budget.
//!
//! The subject here is a SOLO voter, because it makes the argument causal rather than circumstantial.
//! A solo voter has no peer to solicit, cannot state-sync, and (being alone) cannot escalate a
//! `RecoveringHead` wedge into a view change — so an op its recovery kept as a header-only hole, or a
//! head its recovery could not identify, has exactly ONE possible source for its body anywhere in the
//! system: the medium's own late read. If that lane did not execute, the replica would sit below the
//! hole forever. The control run with the axis off is included in the same test, so what the axis
//! changes is visible rather than asserted.

use core::time::Duration;

use viewstamp_simulation::{
  Cluster,
  storage::{READ_DELAY_SPAN, READ_STALL_FLOOR, RECOVERY_READ_BUDGET},
};

/// The read-delay base for these lanes. Per-replica derivation happens inside the cluster, so this is
/// just a fixed, arbitrary base that keeps the lane reproducible.
const READ_DELAY_BASE: u64 = 0xABCD_1234_5678_9F0F;

/// Ticks of steady solo operation before the crash: enough to commit a few hundred ops and leave
/// several checkpoints behind, so the restart's recovery window holds a real tail of durable slots.
const WARMUP_TICKS: u64 = 600;

/// Ticks of solo operation after the restart. Generous next to the stall band (at most 2.5 s of
/// virtual time, ~2500 solo ticks) so a lane that genuinely wedges is distinguishable from one that
/// merely has not been given time.
const RECOVERY_TICKS: u64 = 6_000;

/// What one solo crash/restart cycle produced.
#[derive(Debug)]
struct Cycle {
  /// The commit frontier the replica reached before the crash.
  before_commit: u64,
  /// The commit frontier it reached by the end of the run.
  after_commit: u64,
  /// Beyond-budget reads that delivered BYTES — the only completions a carried correlation can admit.
  late_bodies: u64,
  /// The distinct statuses the replica entered after the restart, in order.
  statuses: Vec<String>,
  /// Virtual time from the restart to the replica first reaching `Normal`.
  normal_at: Option<Duration>,
  /// Virtual time from the restart to the commit frontier first passing `before_commit`.
  resumed_at: Option<Duration>,
}

/// Run one solo voter through a crash and restart, with the read-delay axis `armed` or not, and
/// report what the restart did.
fn solo_cycle(seed: u64, armed: bool) -> Cycle {
  let mut c = Cluster::with_members(1, 0, 2, 400, seed, 8);
  if armed {
    c.set_wal_read_delay(Some(seed ^ READ_DELAY_BASE));
  }
  for _ in 0..WARMUP_TICKS {
    c.tick();
  }
  let before_commit = c.replica_commit(0).get();
  assert!(
    before_commit > 0,
    "seed {seed}: the solo voter committed nothing before the crash — the lane would have no \
     durable tail to recover"
  );
  c.crash(0);
  c.restart(0);
  let restart_at = c.now().as_nanos();
  let since_restart = |c: &Cluster| Duration::from_nanos(c.now().as_nanos() - restart_at);
  let mut statuses: Vec<String> = Vec::new();
  let mut normal_at = None;
  let mut resumed_at = None;
  for _ in 0..RECOVERY_TICKS {
    c.tick();
    let status = c.replica_status_str(0).to_string();
    if statuses.last() != Some(&status) {
      statuses.push(status.clone());
    }
    if normal_at.is_none() && status == "normal" {
      normal_at = Some(since_restart(&c));
    }
    if resumed_at.is_none() && c.replica_commit(0).get() > before_commit {
      resumed_at = Some(since_restart(&c));
    }
  }
  Cycle {
    before_commit,
    after_commit: c.replica_commit(0).get(),
    late_bodies: c.wal_late_bodies_delivered(0),
    statuses,
    normal_at,
    resumed_at,
  }
}

#[test]
fn a_solo_voter_recovers_a_hole_only_its_own_late_read_can_fill() {
  // Seed 9's degraded slots land on INTERIOR ops of the recovery window: the reads exhaust their
  // budget, the ops are kept as header-only holes, recovery completes, and the replica returns to
  // Normal — but with holes below its commit frontier that it can fill from nowhere but its own
  // still-outstanding reads.
  const SEED: u64 = 9;

  let control = solo_cycle(SEED, /*armed*/ false);
  assert_eq!(
    control.late_bodies, 0,
    "the control run must not delay a single read — that is what makes it the control"
  );
  assert_eq!(
    control.statuses,
    vec!["normal".to_string()],
    "with reads resolving inline the restart never lingers in a recovering status"
  );
  let control_resumed = control
    .resumed_at
    .expect("the control run resumes committing");
  assert!(
    control_resumed < RECOVERY_READ_BUDGET,
    "the control resumed after {control_resumed:?}, past the recovery read budget — the fixture is \
     not measuring what the axis changes"
  );

  let armed = solo_cycle(SEED, /*armed*/ true);
  assert!(
    armed.late_bodies > 0,
    "seed {SEED}: no read outlived the recovery read budget with bytes to deliver — the axis is \
     vacuous here and this lane proves nothing"
  );
  let normal_at = armed.normal_at.expect("the armed run reaches Normal");
  let resumed_at = armed.resumed_at.expect("the armed run resumes committing");
  // The whole argument: the replica was BACK IN SERVICE (`Normal`, its recovery finished, its read
  // budget spent) and STILL could not advance its commit frontier until well past the point any
  // in-budget read could have answered. On a cluster with no second node, the body that unblocked it
  // came from its own medium, arriving after the recovery loop stopped waiting for it.
  assert!(
    normal_at > READ_DELAY_SPAN,
    "seed {SEED}: recovery finished after {normal_at:?}, within the healthy read band \
     {READ_DELAY_SPAN:?} — every op resolved off a prompt read, so none reached its resolution with \
     a read still outstanding"
  );
  assert!(
    resumed_at > normal_at,
    "seed {SEED}: the commit frontier advanced at {resumed_at:?}, at or before recovery finished at \
     {normal_at:?} — nothing was ever held below a hole"
  );
  assert!(
    resumed_at >= READ_STALL_FLOOR,
    "seed {SEED}: the commit frontier advanced at {resumed_at:?}, before the earliest instant a \
     stalled read can come due ({READ_STALL_FLOOR:?}) — the hole was filled by a prompt read, not a \
     late one"
  );
  assert!(
    armed.after_commit > armed.before_commit,
    "seed {SEED}: the solo voter never committed past {} after the restart — the hole was never \
     filled, so the late-read lane did not run",
    armed.before_commit
  );
  println!(
    "solo interior hole: control resumed at {control_resumed:?}; armed reached Normal at \
     {normal_at:?} and resumed at {resumed_at:?} with {} late bodies, commit {} -> {}",
    armed.late_bodies, armed.before_commit, armed.after_commit
  );
}

#[test]
fn a_solo_voters_unidentifiable_head_is_restored_by_its_own_late_read() {
  // Seed 2's degraded slot is the HEAD of the recovery window. Its reads exhaust their budget too,
  // but a head whose identity recovery could not establish is not kept as a log entry — it is
  // promoted out of the log and the replica enters `RecoveringHead`, where it solicits a peer to
  // re-establish the head. A SOLO voter has no peer to answer, and the re-formation escalation
  // refuses a single-voter cluster outright (there is no quorum to re-form among), so the status is
  // terminal for every source but one: the medium's own outstanding read of that very slot.
  const SEED: u64 = 2;

  let control = solo_cycle(SEED, /*armed*/ false);
  assert_eq!(
    control.statuses,
    vec!["normal".to_string()],
    "with reads resolving inline the head is always identified inside the budget"
  );

  let armed = solo_cycle(SEED, /*armed*/ true);
  assert!(
    armed.statuses.iter().any(|s| s == "recovering_head"),
    "seed {SEED}: the restart never entered RecoveringHead (statuses {:?}) — the head slot's reads \
     did not outlive the budget, so the restore lane was not reached",
    armed.statuses
  );
  assert_eq!(
    armed.statuses.last().map(String::as_str),
    Some("normal"),
    "seed {SEED}: the solo voter never left RecoveringHead (statuses {:?}) — with no peer to \
     re-establish the head and no escalation available to a single voter, only its own late read \
     could have, and it did not",
    armed.statuses
  );
  assert!(
    armed.late_bodies > 0,
    "seed {SEED}: the replica left RecoveringHead without any beyond-budget read delivering bytes"
  );
  let normal_at = armed.normal_at.expect("the armed run reaches Normal");
  assert!(
    normal_at > RECOVERY_READ_BUDGET,
    "seed {SEED}: RecoveringHead ended after {normal_at:?}, inside the {RECOVERY_READ_BUDGET:?} \
     read budget"
  );
  assert!(
    armed.after_commit > armed.before_commit,
    "seed {SEED}: the solo voter never committed past {} after the restart",
    armed.before_commit
  );
  println!(
    "solo promoted head: statuses {:?}, back to Normal at {normal_at:?} with {} late bodies, \
     commit {} -> {}",
    armed.statuses, armed.late_bodies, armed.before_commit, armed.after_commit
  );
}

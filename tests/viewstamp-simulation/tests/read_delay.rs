//! The WAL read-delay axis, driven to the state it exists to reach: a recovery read still
//! outstanding long after every cadence tick the retry discipline could ever spend.
//!
//! The synchronous in-memory WAL resolves every read in the call that submitted it, so the WAIT the
//! proto's recovery runs on — a read that has not completed is outstanding, not failed; no cadence
//! tick spends the failure budget on it; the recovery stays open until its verdict delivers — is
//! vacuous at every seed. [`Cluster::set_wal_read_delay`] gives reads a latency, with a seeded
//! minority of slots answering only past the whole give-up horizon, so the wait becomes the
//! load-bearing path.
//!
//! The subject here is a SOLO voter, because it makes the argument causal rather than
//! circumstantial. A solo voter has no peer to solicit, cannot state-sync, and (being alone) cannot
//! escalate into a view change — so an op whose read is slow has exactly ONE possible resolution
//! anywhere in the system: the medium's own delivered verdict. If the recovery gave up on the wait,
//! the replica would either strand the op behind peer repair no donor answers or distrust a head
//! its own disk still holds; waiting is what lets it resume whole. The control run with the axis
//! off is included in the same test, so what the axis changes is visible rather than asserted.

use core::time::Duration;

use viewstamp_simulation::{
  Cluster,
  storage::{READ_GIVE_UP_HORIZON, READ_STALL_FLOOR},
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
  /// Beyond-horizon reads that delivered BYTES — completions only the wait can have consumed.
  late_bodies: u64,
  /// The distinct statuses the replica entered after the restart, in order.
  statuses: Vec<String>,
  /// Virtual time from the restart to the replica first reaching `Normal`.
  normal_at: Option<Duration>,
  /// Virtual time from the restart to the commit frontier first passing `before_commit`.
  resumed_at: Option<Duration>,
  /// The durable head the restart's recovery window opens at.
  head: u64,
  /// Whether reads of that head's slot are DEGRADED on this medium. The delivery counters carry no
  /// slot identity, so a lane that means to stall the HEAD read reads this rather than describing
  /// its intent in a comment.
  head_degraded: bool,
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
  // The durable head the restart is about to recover over, read before the recovery touches it.
  let head = c.wal_head_for_test(0);
  let head_degraded = c.wal_slot_read_degraded(0, head);
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
    head,
    head_degraded,
  }
}

#[test]
fn a_solo_voter_waits_out_slow_interior_reads_and_rejoins_whole() {
  // The degraded slots on this lane's medium land on INTERIOR ops of the recovery window. The
  // recovery WAITS on them: cadence ticks spend nothing on an outstanding read, so no op resolves
  // header-only, no hole survives into Normal, and the replica rejoins only once every delivered
  // verdict has landed — carrying the full committed tail it recovered from its own disk.
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
    control_resumed < READ_GIVE_UP_HORIZON,
    "the control resumed after {control_resumed:?}, past the give-up horizon — the fixture is \
     not measuring what the axis changes"
  );

  let armed = solo_cycle(SEED, /*armed*/ true);
  // What makes this the INTERIOR lane: the head of the window the restart recovers over is NOT one
  // of the medium's degraded slots, so every stall it waits out sits below the head. The head lane
  // below asserts the mirror image on its own seed, so neither can drift into the other's shape.
  assert!(
    !armed.head_degraded,
    "seed {SEED}: the recovery head (op {}) is a degraded slot — the stalls are no longer purely \
     interior and this lane has drifted onto the head",
    armed.head
  );
  assert!(
    armed.late_bodies > 0,
    "seed {SEED}: no read outlived the give-up horizon with bytes to deliver — the axis is \
     vacuous here and this lane proves nothing"
  );
  assert_eq!(
    armed.statuses,
    vec!["recovering".to_string(), "normal".to_string()],
    "seed {SEED}: the replica waits in Recovering until every verdict lands, then rejoins whole — \
     it neither rejoins early over open holes nor distrusts a head its own reads still owe"
  );
  let normal_at = armed.normal_at.expect("the armed run reaches Normal");
  // The whole argument: recovery could not have finished before the earliest instant a stalled
  // read comes due, because finishing REQUIRES that read's verdict — the wait is load-bearing.
  assert!(
    normal_at >= READ_STALL_FLOOR,
    "seed {SEED}: recovery finished after {normal_at:?}, before the earliest instant a stalled \
     read can come due ({READ_STALL_FLOOR:?}) — it cannot have waited for the stalled verdicts"
  );
  let resumed_at = armed.resumed_at.expect("the armed run resumes committing");
  assert!(
    resumed_at >= normal_at,
    "seed {SEED}: the commit frontier advanced at {resumed_at:?}, before recovery finished at \
     {normal_at:?} — a recovering replica must not commit"
  );
  assert!(
    armed.after_commit > armed.before_commit,
    "seed {SEED}: the solo voter never committed past {} after the restart — the wait did not \
     resume service",
    armed.before_commit
  );
  println!(
    "solo interior stalls: control resumed at {control_resumed:?}; armed reached Normal at \
     {normal_at:?} and resumed at {resumed_at:?} with {} late bodies, commit {} -> {}",
    armed.late_bodies, armed.before_commit, armed.after_commit
  );
}

#[test]
fn a_solo_voters_slow_head_read_never_routes_through_recovering_head() {
  // The degraded slot on this lane's medium is the HEAD of the recovery window. A head whose read
  // is merely slow is not an unidentifiable head — its identity is owed by an outstanding read the
  // medium must answer — so the recovery WAITS instead of promoting it faulty: `RecoveringHead` (a
  // status that solicits a peer a solo voter does not have) is never entered, and the head resolves
  // from the delivered verdict.
  const SEED: u64 = 2;

  let control = solo_cycle(SEED, /*armed*/ false);
  assert_eq!(
    control.statuses,
    vec!["normal".to_string()],
    "with reads resolving inline the head is always identified in the first drain"
  );

  let armed = solo_cycle(SEED, /*armed*/ true);
  // What makes this the HEAD lane rather than the interior one: the slot the medium stalls IS the
  // head of the window the restart recovers over. The degraded set is a pure function of (medium
  // seed, op), so a drift in the warm-up, the checkpoint geometry or the client schedule that moved
  // the stall off the head fails here instead of leaving the lane green over an interior stall.
  assert!(
    armed.head_degraded,
    "seed {SEED}: the recovery head (op {}) is not a degraded slot on this medium — the stall \
     moved off the head and this lane no longer exercises the head read",
    armed.head
  );
  assert!(
    !armed.statuses.iter().any(|s| s == "recovering_head"),
    "seed {SEED}: the restart entered RecoveringHead (statuses {:?}) — a merely-slow head read \
     was treated as an unidentifiable head instead of being waited on",
    armed.statuses
  );
  assert_eq!(
    armed.statuses,
    vec!["recovering".to_string(), "normal".to_string()],
    "seed {SEED}: the replica waits in Recovering until the head's verdict lands, then rejoins"
  );
  assert!(
    armed.late_bodies > 0,
    "seed {SEED}: no beyond-horizon read delivered bytes — the head's read never genuinely \
     outlived the give-up horizon, so this lane proves nothing"
  );
  let normal_at = armed.normal_at.expect("the armed run reaches Normal");
  assert!(
    normal_at > READ_GIVE_UP_HORIZON,
    "seed {SEED}: recovery finished after {normal_at:?}, inside the {READ_GIVE_UP_HORIZON:?} \
     give-up horizon — the head cannot have been waited out past it"
  );
  assert!(
    armed.after_commit > armed.before_commit,
    "seed {SEED}: the solo voter never committed past {} after the restart",
    armed.before_commit
  );
  println!(
    "solo slow head: statuses {:?}, back to Normal at {normal_at:?} with {} late bodies, \
     commit {} -> {}",
    armed.statuses, armed.late_bodies, armed.before_commit, armed.after_commit
  );
}

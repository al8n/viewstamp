use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use crate::{
  ClientId, Commit, Config, DoViewChange, Event, Header, Instant, Message, OpNumber, Outgoing,
  Peer, Prepare, PrepareOk, Prng, Recipient, ReplicaId, Reply, RequestNumber, SlotStatus,
  StateMachine, Status, Superblock, SuperblockDone, View, Wal, WalDone,
};

/// What the endpoint does when a submitted WAL append completes. Append-before-ack: the vote/ack a
/// completion owes is always deferred to `on_wal_done`, never cast before the op is durable. A
/// repair-fill append (see `fill_repair`) is deliberately NOT recorded here — it owes no ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
  /// A normal-path prepare append (a backup's `on_prepare`, or the primary's own `on_request`); on
  /// completion, record the ack/own-vote for this op (`send_prepare_ok` on a backup; own inflight bit
  /// + `try_commit` on the primary).
  Ack(OpNumber),
  /// A new primary's view-change ADOPTION append (codex R6-F1): an uncommitted-tail op it learned
  /// from the DVC quorum and must re-drive. On completion, set the OWN inflight vote for this op and
  /// `try_commit` — the own vote must never precede its WAL append (append-before-ack).
  AdoptVote(OpNumber),
  /// A backup's view-change ADOPTION append (codex R6-F1): an uncommitted-tail op it learned from a
  /// `StartView`/`RecoveryResponse`. On completion, send the deferred `PrepareOk` — no `PrepareOk` is
  /// sent for an adopted op before its WAL append is durable (append-before-ack).
  AdoptAck(OpNumber),
}

/// What the endpoint does once its pending durable-view (superblock) write completes.
/// Private + unit-only: a transition records the participation to run *after* the new view is
/// durable. Keyed by the minted `OpId` in `pending_sb`; a superseded (older-view) completion is
/// ignored. Mirrors `Pending`/`on_wal_done` (append-before-ack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingSbAction {
  SendDoViewChange,
  StartViewAsPrimary,
  AdoptedStartView,
}

/// Which of a checkpoint's two superblock writes is outstanding. Kept SEPARATE from
/// `PendingSbAction` (durable-view writes) and matched by its own minted `OpId`, so a durable-view
/// write completion and a checkpoint write completion never alias on the single `OpId`-match
/// dispatch (`on_sb_done`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointStep {
  /// The snapshot write is in flight; on its completion, write the new `VsrState` root.
  AwaitSnapshot { id: crate::OpId },
  /// The `VsrState` root write is in flight; on its completion, the checkpoint is durable.
  AwaitRoot { id: crate::OpId },
}

/// Staging for an in-flight checkpoint, sequencing the two superblock writes. Holds the target op
/// (the committed+applied boundary the snapshot reflects), its content id, and which step is
/// outstanding. While `Some`, no second checkpoint and no durable-view write may start (and any
/// view-change transition drops it — see the view-change exclusion in the status transitions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingCheckpoint {
  /// The op the snapshot reflects (`commit_min` at trigger time): the new `checkpoint_op` once durable.
  target_op: OpNumber,
  /// The FNV-1a-128 content id of the snapshot envelope (stored in the durable `VsrState` root).
  checkpoint_id: u128,
  /// Which superblock write is currently outstanding.
  step: CheckpointStep,
}

/// In-flight state-sync bookkeeping (M3.4a). `Some` while a lagging replica is awaiting (or
/// re-soliciting) a `SyncCheckpoint` for a `RequestSync` it broadcast — and continues to hold while
/// the synced checkpoint's two superblock writes are being made durable. `None` otherwise. Holds the
/// highest cluster `checkpoint_op` this replica has LEARNED it is behind (the target — a SyncCheckpoint
/// that does not advance us past it is ignored) plus the freshness nonce. Cleared only once the synced
/// checkpoint's durable root write completes (so a crash mid-persist re-solicits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncState {
  /// The cluster `checkpoint_op` we learned we are behind (from a Commit/Prepare/PrepareOk). We only
  /// adopt a SyncCheckpoint whose `checkpoint_op >= this`.
  target: OpNumber,
  /// Freshness nonce echoed in the SyncCheckpoint (a per-attempt bump of `self.nonce`).
  nonce: u64,
  /// `true` when this sync was raised by the M3.5 force-sync escalation ([`Endpoint::maybe_force_sync`])
  /// rather than the ordinary `> self.op` trigger. On the forced path the synced checkpoint may sit at
  /// or BELOW our head (we hold a tail above a pruned committed hole), so `apply_sync` relaxes its
  /// release-active assert from `checkpoint_op > self.op` to the true safety invariant
  /// `checkpoint_op >= commit_min` (never rewind the applied frontier). See §2 of the M3.5 plan.
  forced: bool,
}

const PREPARE_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
const COMMIT_HEARTBEAT: core::time::Duration = core::time::Duration::from_millis(50);
const PRIMARY_IDLE: core::time::Duration = core::time::Duration::from_millis(200);
const VC_MESSAGE_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
const VIEW_CHANGE_STATUS: core::time::Duration = core::time::Duration::from_millis(500);
/// Forfeit (M3.5 T3, `Status::Normal` primary): how long the checkpoint-lag forfeit condition must
/// hold CONTINUOUSLY before a stuck primary actually steps down (the anti-storm grace timer). Sits
/// above `PRIMARY_IDLE` (200ms) — so a *silent* primary is failed over first by a backup's idle VC,
/// and forfeit handles only the *alive-but-stuck* case where the primary keeps heartbeating yet
/// cannot make checkpoint progress — and below `VIEW_CHANGE_STATUS` (500ms) — so a forfeit resolves
/// before a redundant idle-driven view change escalates. A primary that catches up within the grace
/// window disarms and never forfeits (a transient lag cannot trigger it).
const FORFEIT_GRACE: core::time::Duration = core::time::Duration::from_millis(300);
/// Recovery (`Status::Recovering`): how often the recover-read timer re-submits any still
/// pending/faulty WAL-tail reads. Covers a real async driver that drops a completion, and the
/// transient-clears-on-retry case where a `Fault` only resolves on a later read.
const RECOVER_READ_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
/// Recovery: per-slot read-retry budget. A `Fault`/`Absent`/checksum-mismatch on a WAL-tail read is
/// re-submitted up to this many times (transient faults clear within the budget); once exhausted the
/// slot is classed *permanently* faulty, which drives the `Normal`-vs-`RecoveringHead` decision.
const RECOVER_READ_RETRIES: u8 = 8;
/// RecoveringHead (`Status::RecoveringHead`): how often the replica re-broadcasts its `Recovery`
/// solicitation while waiting for the canonical head. A permanently-faulty head cannot be repaired
/// from local disk, so the replica keeps soliciting a peer until a `RecoveryResponse`/`StartView`
/// re-establishes its head.
const RECOVER_HEAD_SOLICIT: core::time::Duration = core::time::Duration::from_millis(100);
/// Peer fault-repair: how often a replica holding a permanently-faulty committed-op hole re-broadcasts
/// `RequestPrepare` for each unrepaired op, until a peer answers with the missing `Prepare`. Mirrors
/// the recover-read retransmit cadence; the commit is HELD below the hole until the op arrives.
const REPAIR_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
/// State-sync (`Status::Normal`): how often a lagging replica re-broadcasts its `RequestSync`
/// solicitation while awaiting a `SyncCheckpoint` (and while the adopted checkpoint is being made
/// durable). Mirrors the other solicitation cadences; cleared once the synced checkpoint is durable.
const SYNC_SOLICIT: core::time::Duration = core::time::Duration::from_millis(100);
/// Peer fault-repair tail-gap (`Status::Normal` backup): the maximum number of `RequestPrepare`s
/// [`Endpoint::request_tail_gap`] emits per call — the size of the catch-up window it solicits above
/// its head toward `commit_max`. Bounds the work per heartbeat: `request_tail_gap` runs on every
/// `Commit`/`Prepare`, so a genuine gap is closed incrementally across heartbeats (each one advances
/// the head, sliding the window up). Without this cap a single bogus/large `commit_max` (learned from
/// one incoming `Commit`/`Prepare`) would push `commit_max - head` requests into `outgoing` in one
/// call — unbounded CPU/memory in the Sans-I/O core. A genuinely far-behind backup (the gap spans
/// many windows) catches up via state-sync, not tail-gap, so a modest window suffices; sized at a few
/// pipeline depths so steady-state catch-up never needs more than one window.
const TAIL_GAP_WINDOW: u64 = 64;
/// Recovery (`recover()`): the maximum number of WAL-tail slots `recover()` will bookkeep + submit a
/// read for in ONE pass — the size of the `(checkpoint_op .. head]` window it materializes. Bounds
/// the synchronous work of constructing a `Recovering` replica: `recover()` inserts a dense-cache
/// entry and submits one read per tail slot, so without a cap a corrupt/buggy `Wal` reporting a
/// huge `op_head` (e.g. `u64::MAX` from bit-rot in the head slot) would force unbounded CPU /
/// allocation / outgoing reads before the async fault-handling loop ever runs. A real recovery tail
/// is the small un-checkpointed pipeline above the latest checkpoint (a handful to a few hundred
/// ops), so this generous power-of-two bound never clips a legitimate recovery while capping a
/// pathological head to a fixed budget. A head BEYOND the window means this replica cannot
/// synchronously read its whole tail in one pass: the slots above `checkpoint_op + RECOVER_TAIL_WINDOW`
/// are left unread (recovered incrementally as the primary re-announces them, or — if the head slot
/// itself is unreadable — via the `RecoveringHead`/peer head-fault path), never billions of reads.
const RECOVER_TAIL_WINDOW: u64 = 8192;

/// In-flight recovery read-bookkeeping for a `Status::Recovering`/`RecoveringHead` replica.
///
/// `recover()` builds the dense log cache from headers only (bodies empty), submits the WAL-tail +
/// checkpoint reads, and stashes one of these. `handle_storage` then verifies each `ReadOk`'s
/// checksum, fills the body, retries `Fault`/`Absent`/checksum-mismatch, and — once every read is
/// satisfied — transitions to `Normal` (tail consistent) or `RecoveringHead` (head permanently
/// faulty). Private to `endpoint.rs`; never crosses the API boundary, so no accessors. All maps are
/// bounded by the WAL-tail length (bounded by the checkpoint-interval headroom).
#[derive(Debug, Default)]
struct RecoverState {
  /// Ops whose body read is still outstanding → remaining retry budget. Non-empty ⇒ reads in flight.
  pending: BTreeMap<u64, u8>,
  /// Maps an in-flight read's `OpId` → the op it reads, so a `Fault`/`Absent` completion (which
  /// carries only the `OpId`) is attributed to the right slot.
  reads: BTreeMap<u64, u64>,
  /// Ops that read back permanently faulty/absent (retry budget exhausted). Drives the
  /// `Normal`-vs-`RecoveringHead` decision in `recover_progress`.
  faulty: std::collections::BTreeSet<u64>,
  /// The in-flight checkpoint-read `OpId` (`Some` until the snapshot is restored), or `None` if no
  /// checkpoint exists / it is already restored.
  checkpoint: Option<u64>,
  /// Remaining retry budget for the checkpoint read (the per-op `pending` analog). A transient
  /// checkpoint-read `Fault` is re-submitted within this budget; once exhausted — the durable root
  /// names a snapshot that is PERMANENTLY unreadable or permanently inconsistent with the root (wrong
  /// op/hash/unparsable on EVERY read) — the replica cannot restore its SM from its OWN disk and
  /// escalates to a peer fetch (see `awaiting_peer_checkpoint`), never panics on storage-controlled
  /// bytes (F1).
  checkpoint_retries: u8,
  /// `true` once the local checkpoint read EXHAUSTED its budget (F1): the replica's own durable
  /// checkpoint snapshot is permanently unreadable/inconsistent, so it has escalated to FETCHING the
  /// checkpoint from a peer via state-sync (a forced `sync` is armed + a `RequestSync` solicited).
  /// While set, `recover_progress` will NOT complete recovery (the SM is not yet restored), and
  /// `handle_message` accepts a `SyncCheckpoint` (mirroring how `RecoveringHead` accepts `StartView`);
  /// a verified one restores the SM via `apply_sync` and completes recovery to `Normal`. Cleared on
  /// that success (alongside `recover = None`).
  awaiting_peer_checkpoint: bool,
}

/// One entry in the in-memory log (M1; persistence arrives in M3).
#[derive(Debug, Clone)]
struct LogEntry {
  client: ClientId,
  request: RequestNumber,
  body: Bytes,
}

/// Primary-side tracking of an in-flight prepare awaiting a prepare_ok quorum.
#[derive(Debug, Clone)]
struct Inflight {
  /// Bitset of replica indices that have acked (the primary sets its own bit).
  oks: u64,
  committed: bool,
}

/// Per-client session for at-most-once semantics.
#[derive(Debug, Clone, Default)]
struct Session {
  /// Highest request number accepted (assigned an op or committed).
  request: RequestNumber,
  /// Cached `(request_number, reply_body)` of the latest committed request.
  reply: Option<(RequestNumber, Bytes)>,
}

/// Absolute timer deadlines, armed per role by `arm_timers`.
#[derive(Debug, Clone, Default)]
struct Timers {
  /// Normal primary: retransmit un-acked prepares.
  prepare: Option<Instant>,
  /// Normal primary: commit heartbeat.
  commit: Option<Instant>,
  /// Normal backup: no Prepare/Commit from the primary → start a view change.
  primary_idle: Option<Instant>,
  /// ViewChange: retransmit own StartViewChange.
  svc_message: Option<Instant>,
  /// ViewChange: retransmit own DoViewChange.
  dvc_message: Option<Instant>,
  /// ViewChange: escalate to the next view if the change has not completed.
  view_change_status: Option<Instant>,
  /// ViewChange (catch-up): retransmit GetView.
  get_view_message: Option<Instant>,
  /// Recovering: re-submit any still-pending/faulty WAL-tail (and checkpoint) reads. Drives the
  /// recover loop to termination under a transient fault whose completion was dropped or whose retry
  /// only clears on a later read.
  recover_retry: Option<Instant>,
  /// RecoveringHead: re-broadcast the `Recovery` solicitation. A replica whose durable head slot is
  /// permanently faulty cannot recover from its own disk; it solicits the canonical head from a peer
  /// (the primary answers with a `RecoveryResponse`) and retries on this cadence until it adopts a
  /// head (via that response or a `StartView`) and returns to Normal.
  recover_head: Option<Instant>,
  /// Normal: re-broadcast `RequestPrepare` for each op in the pending-repair set (a committed-op hole
  /// read back permanently faulty). Armed only while `repair` is non-empty; cleared when the last
  /// hole is filled. Active in BOTH primary and backup roles — either may hold a hole after recovery.
  repair_retry: Option<Instant>,
  /// Normal (state-sync): re-broadcast `RequestSync` while a sync is outstanding (awaiting a
  /// `SyncCheckpoint` or persisting the adopted one). Armed only while `sync.is_some()`; cleared once
  /// the synced checkpoint is durable.
  sync_solicit: Option<Instant>,
}

/// The Sans-I/O Viewstamped Replication state machine for one replica.
///
/// Push inputs with `handle_*`; pull outputs with `poll_*` (drain each to `None`
/// per wake). Every state-advancing entry takes a non-decreasing `now`.
#[derive(Debug)]
pub struct Endpoint<S> {
  config: Config,
  status: Status,
  view: View,
  /// Head op (most recently prepared locally).
  op: OpNumber,
  /// Highest op durably applied to the state machine (applied frontier).
  commit_min: OpNumber,
  /// Highest op known committed cluster-wide (may exceed locally-held + applied ops).
  ///
  /// A re-learnable HINT, not a monotone invariant: re-learned via `advance_commit`'s `max` on the
  /// next Commit/Prepare, and a forced state-sync (`maybe_force_sync`) resets it to the synced
  /// `checkpoint_op`. Do NOT add a monotonicity assert on it — a forced sync may regress it.
  commit_max: OpNumber,
  /// Latest view in which this replica changed its head log.
  /// Invariants: `log_view <= view`; `log_view == view` when status==Normal.
  log_view: View,
  /// ViewChange: bitset of replicas that sent StartViewChange for `view+1` (includes our own bit once we propose).
  svc_from: u64,
  /// ViewChange: the highest view this replica is currently collecting StartViewChanges for.
  svc_target: View,
  /// ViewChange: true when this replica is merely catching up to an existing newer view
  /// (higher-view rule) rather than driving a new view change — it sends GetView, not SVC/DVC.
  catching_up: bool,
  /// ViewChange (prospective primary): collected DoViewChange messages by replica index.
  dvc_from: BTreeMap<u8, DoViewChange>,
  /// ViewChange (prospective primary): the canonical log has been formed this view.
  dvc_quorum: bool,
  /// Freshness nonce for GetView, drawn once from the prng.
  nonce: u64,
  /// In-memory log, keyed by op number.
  ///
  /// Trimmed by post-checkpoint GC ([`Self::run_gc`], M3.4b) to the un-checkpointed tail
  /// `(prune_floor .. head]`; bounded by `O(checkpoint_ops + pipeline)`.
  log: BTreeMap<u64, LogEntry>,
  /// Primary pipeline: op → ack tracking.
  ///
  /// Trimmed by post-checkpoint GC ([`Self::run_gc`], M3.4b) to the un-checkpointed tail
  /// `(prune_floor .. head]`; bounded by `O(checkpoint_ops + pipeline)`.
  inflight: BTreeMap<u64, Inflight>,
  /// Backup reorder buffer: future prepares awaiting contiguity.
  buffer: BTreeMap<u64, Prepare>,
  /// Client session table.
  ///
  /// Bounded by the active client set (one session per client), independent of op count;
  /// intentionally NOT trimmed by GC (dropping a live session risks an at-most-once dedup miss) —
  /// captured in each checkpoint envelope instead so a recover/state-sync restores it.
  clients: BTreeMap<u128, Session>,
  sm: S,
  outgoing: VecDeque<Outgoing>,
  events: VecDeque<Event>,
  timers: Timers,
  /// Monotonic source of storage correlation ids.
  next_op_id: u64,
  /// Outstanding storage submissions awaiting completion.
  pending: BTreeMap<u64, Pending>,
  /// Op numbers with an in-flight WAL append — the single source of truth for "is op N durable yet?"
  /// (codex R7-F1). An op is INSERTED here when a votable append is submitted (`on_request`,
  /// `append_prepare`, `adopt_append`) and REMOVED in `on_wal_done` once that op's append completes.
  /// `send_prepare_ok` is the choke point: a `PrepareOk` for op N may be emitted ONLY if N is NOT in
  /// this set (it is durable). This makes append-before-ack a SINGLE enforced gate, so the violation
  /// class cannot relocate again (R6-F1 was the adoption path; R7-F1 was the retransmit re-ack path).
  /// A repair-fill append (`fill_repair`) is deliberately NOT tracked here — it owes no ack. Cleared
  /// wholesale alongside `pending` on every view-change / state-sync reset (those abandon in-flight
  /// appends; a late completion finds no `pending` entry and is ignored, so its op must not linger).
  appending: std::collections::BTreeSet<u64>,
  /// The deferred view-participation action awaiting a superblock write. Only one view-change
  /// is in flight at a time; a newer transition supersedes by overwriting this field.
  /// `on_sb_done` runs the action only when the completed `OpId` matches the stored one.
  pending_sb: Option<(crate::OpId, PendingSbAction)>,
  /// An in-flight checkpoint, sequencing its two superblock writes. Kept separate from `pending_sb`
  /// (their `OpId`s never alias). `None` unless a checkpoint is mid-sequence; a view-change drops it.
  pending_checkpoint: Option<PendingCheckpoint>,
  /// The op number of this replica's latest durable checkpoint (0 until the first checkpoint
  /// goes durable). Carried on `Commit` and `PrepareOk` as the checkpoint-quorum signal.
  checkpoint_op: OpNumber,
  /// Per-replica last-reported `checkpoint_op` (keyed by replica index), filled by the primary from
  /// incoming `PrepareOk` (and recorded on backups from `Commit`, harmlessly). The primary derives
  /// [`quorum_checkpoint_op`](Self::quorum_checkpoint_op) from this to gate WAL/session GC: it never
  /// frees an op a `quorum` of replicas has not yet checkpointed. Bounded by `replica_count` (<= 64);
  /// cleared on every view-change transition (a new generation re-establishes the pipeline, so old
  /// reports are stale — clearing keeps the primary conservative until fresh `PrepareOk`s arrive).
  peer_checkpoint: BTreeMap<u8, OpNumber>,
  /// Active only while `status` is `Recovering`/`RecoveringHead`: the in-flight recovery-read
  /// bookkeeping (see [`RecoverState`]). Cleared to `None` by the `→ Normal` recovery transition
  /// (`recover_progress`); structurally `None` in every other status, since a recovering replica does
  /// not participate in consensus (the `handle_message` guard) and so cannot enter a view change
  /// while recovering. (M3.3b's `RecoveringHead → StartView` adoption will clear it on that path too.)
  recover: Option<RecoverState>,
  /// Peer fault-repair (B4): committed ops whose body read back PERMANENTLY faulty (bit-rot / torn)
  /// from this replica's own durable WAL and must be re-fetched from a peer (`RequestPrepare` →
  /// `Prepare`). An op lands here when the recover loop classes a non-head committed slot permanently
  /// faulty (it is dropped from the dense `log` cache so it cannot be applied with a wrong/empty body)
  /// or when the apply path (`commit_op`/`advance_commit`) finds a committed op's body missing. While
  /// an op is in this set the commit is HELD strictly below it (ops apply in order; a hole at op `N`
  /// stops the apply at `N-1`); the `repair_retry` timer re-solicits each op until a verified
  /// `Prepare` fills it. Bounded by the WAL-tail length (same bound as `recover`/`log`). Structurally
  /// empty once every committed op below the head is present; cleared wholesale when an adopted
  /// canonical log (StartView / new-primary selection) supplies the full committed prefix.
  repair: std::collections::BTreeSet<u64>,
  /// State-sync (M3.4a): `Some` while this replica is catching up a stale checkpoint via the
  /// `RequestSync` → `SyncCheckpoint` handshake — set when the trigger fires (it learned the cluster
  /// checkpointed past its WAL head), held through the durable re-persist of the adopted checkpoint,
  /// and cleared on the persist's root-write completion. While `Some`, ordinary tail-apply paths are
  /// not relied upon to catch up (the needed ops are below the cluster checkpoint and may be pruned);
  /// the `sync_solicit` timer re-broadcasts until a valid `SyncCheckpoint` is applied + made durable.
  sync: Option<SyncState>,
  /// State-sync peer side (M3.4a): in-flight checkpoint reads this replica issued to SERVE peers'
  /// `RequestSync`s, keyed by the read's `OpId` → `(requester, echoed nonce)`. When the read completes
  /// (`on_sb_done`), the durable snapshot is shipped as a `SyncCheckpoint` to the recorded requester.
  /// A `Fault` drops the entry silently (the requester re-solicits; another peer answers). Bounded by
  /// the number of distinct requesters (<= `replica_count`); cleared per entry on completion/fault.
  sync_serving: BTreeMap<u64, (ReplicaId, u64)>,
  /// Test/observability counter (M3.4a): how many times a state-sync has fully applied on this
  /// replica — incremented when an `apply_sync`'s durable re-persist completes (the root write lands
  /// in `on_sb_done`, the synced checkpoint becomes durable, and the replica resumes as a Normal
  /// backup). Lets the state-sync sim gate assert NON-VACUITY (the laggard genuinely state-synced
  /// rather than catching up op-by-op via retransmit). Never reset; monotone across this process's
  /// lifetime (a fresh `new`/`recover` after a crash starts it back at 0, which is correct — the
  /// gate counts syncs since the laggard's restart). Exposed only via `state_syncs_applied()`.
  state_syncs_applied: u64,
  /// Test/observability counter (M3.5 T6): the subset of `state_syncs_applied` that were raised by the
  /// FORCE-sync escalation ([`Self::maybe_force_sync`]) rather than the ordinary `> self.op` trigger —
  /// incremented in the same `on_sb_done` arm as `state_syncs_applied` when the completing sync carried
  /// `forced: true`. Lets the force-sync sim gate prove the FORCED path specifically fired (not just an
  /// ordinary state-sync), since both route through `apply_sync` and would otherwise be indistinguishable
  /// via `state_syncs_applied` alone. Same lifecycle as `state_syncs_applied` (reset to 0 on `new`/`recover`).
  forced_syncs_applied: u64,
  /// Forfeit grace timer (M3.5 T3): `Some(deadline)` while a `Normal` primary has observed the
  /// checkpoint-lag forfeit condition (`quorum_checkpoint_op - self.checkpoint_op >=
  /// config.forfeit_checkpoint_lag()`) but has not yet stepped down — the condition must persist
  /// until `deadline` (armed `now + FORFEIT_GRACE`) before the primary forfeits, so a transient lag
  /// cannot trigger a view change (anti-storm). Disarmed (`None`) the moment the primary catches up,
  /// when it actually forfeits, and on every view-change transition (a fresh generation re-evaluates
  /// from scratch). Only ever set on the primary path (`maybe_forfeit`); a backup never arms it.
  forfeit_armed: Option<Instant>,
  /// Deferred-forfeit flag (M3.5, safety): set when [`Self::maybe_force_sync`] would have force-synced
  /// but we are the PRIMARY — a primary MUST NOT force-sync, as that resets `self.op` to the checkpoint
  /// (below its head) and lets it re-issue new client requests at REUSED op numbers in the same view,
  /// which backups re-ack from their old entries WITHOUT comparing bodies → committed-state divergence.
  /// Instead the primary steps DOWN: this flag makes the next primary tick ([`Self::primary_timeouts`])
  /// forfeit (a caught-up replica then leads and the subsumed hole is recovered via that primary's
  /// ordinary checkpoint flow). Cleared on every view-change/primacy transition (alongside
  /// `forfeit_armed`) so a stale flag never carries into a fresh generation. A backup leaves this
  /// `false` and force-syncs as before. Private; never crosses the API boundary.
  pending_forfeit: bool,
}

impl<S: StateMachine> Endpoint<S> {
  /// Creates a fresh endpoint in `Status::Normal`, view 0.
  ///
  /// (M1 starts in `Normal`; the `Recovering`/`RecoveringHead` startup path is
  /// added in M3.)
  pub fn new(config: Config, seed: u64, sm: S) -> Self {
    let nonce = Prng::new(seed).next_u64();
    Self {
      config,
      status: Status::Normal,
      view: View::new(),
      op: OpNumber::new(),
      commit_min: OpNumber::new(),
      commit_max: OpNumber::new(),
      log_view: View::new(),
      svc_from: 0,
      svc_target: View::new(),
      catching_up: false,
      dvc_from: BTreeMap::new(),
      dvc_quorum: false,
      nonce,
      log: BTreeMap::new(),
      inflight: BTreeMap::new(),
      buffer: BTreeMap::new(),
      clients: BTreeMap::new(),
      sm,
      outgoing: VecDeque::new(),
      events: VecDeque::new(),
      timers: Timers::default(),
      next_op_id: 1,
      pending: BTreeMap::new(),
      appending: std::collections::BTreeSet::new(),
      pending_sb: None,
      pending_checkpoint: None,
      checkpoint_op: OpNumber::new(),
      peer_checkpoint: BTreeMap::new(),
      recover: None,
      repair: std::collections::BTreeSet::new(),
      sync: None,
      sync_serving: BTreeMap::new(),
      state_syncs_applied: 0,
      forced_syncs_applied: 0,
      forfeit_armed: None,
      pending_forfeit: false,
    }
  }

  /// Reconstructs an endpoint from durable storage after a restart — a **metadata-only constructor**
  /// that enters [`Status::Recovering`] and defers all fallible reads to an async `handle_storage`
  /// loop (faults-as-data; spec §2/§6). It does NOT return in `Normal`.
  ///
  /// **Phase 1 (here, sync + infallible).** Reads only synchronous trait metadata — the superblock
  /// root via `sb.state()` for `(view, log_view, checkpoint_op, checkpoint_id)` and `wal.op_head()` /
  /// `wal.header(op)` — and constructs the endpoint with:
  /// - `view = state.view()`, `log_view = state.log_view()`, `op = wal.op_head()`,
  ///   `checkpoint_op = state.checkpoint_op()`, and `commit_min = commit_max = checkpoint_op` (the
  ///   restored SM already reflects `[1..=checkpoint_op]`, so this prevents a double-apply; monotone
  ///   `op >= commit_max >= commit_min` holds). With no checkpoint (`checkpoint_op == 0`) this is the
  ///   M3.1b behaviour: a fresh `S`, `commit_min == commit_max == 0`.
  /// - the in-memory log cache built **from headers only over the OFFSET tail** `(checkpoint_op ..
  ///   head]` (`wal.header(op)`, bodies left empty — filled by Phase 2). NOT dense `[1..=head]`: the
  ///   committed prefix `[1..=checkpoint_op]` lives in the restored SM snapshot (and a state-synced
  ///   replica has pruned its WAL there), so the cache holds only ops ABOVE the checkpoint;
  ///   `commit_min == checkpoint_op` means `[1..=checkpoint_op]` are never re-applied. View change is
  ///   **offset-aware** (B3: `select_canonical_log` UNIONs the committed band across DVCs, so an
  ///   offset log carrying only `(checkpoint_op .. head]` is safe — no committed op a different-floor
  ///   participant needs is dropped). A slot whose `header()` is absent/faulty is still recorded as
  ///   pending (the read resolves it).
  /// - `status = Status::Recovering`, and a fresh `RecoverState`: every `op in (checkpoint_op ..
  ///   head]` is submitted via `submit_read` (minted `OpId` recorded in `recover.reads`) with a
  ///   `RECOVER_READ_RETRIES` budget in `recover.pending`; if `checkpoint_op > 0` the checkpoint
  ///   read is submitted too (its `OpId` in `recover.checkpoint`).
  ///
  /// It submits the reads (a sync, infallible trait call, mirroring `on_request`'s `submit_append`)
  /// but performs **no `poll()`** — completion handling, checksum verification, and retry all live in
  /// Phase 2. Hence the `&mut W, &mut B`.
  ///
  /// **Phase 2 (`handle_storage`, async + fallible).** `on_wal_done`/`on_sb_done` drive the reads to
  /// a consistent tail: each `ReadOk`'s body is adopted only after `Header::verify` (a torn write /
  /// bit-rot surfaces as a checksum mismatch and is treated as a fault); `Fault`/`Absent`/mismatch is
  /// retried within the budget, then classed permanently faulty; the checkpoint `CheckpointRead`
  /// restores the SM + sessions. Once every read is satisfied, `recover_progress` transitions to
  /// `Normal` (tail consistent) or `RecoveringHead` (the head slot is permanently faulty — it cannot
  /// trust its head and awaits a `StartView`, completed in M3.3b). A recovered backup re-emits
  /// nothing; it waits for the primary's `Prepare`/`Commit` to re-announce commit, exactly as before.
  ///
  /// **Durable-view.** The view is persisted before any view-change participation, so `state.view()`
  /// is trustworthy: a recovered replica resumes the view it was in when it last participated.
  pub fn recover<W: Wal, B: Superblock>(
    config: Config,
    seed: u64,
    sm: S,
    wal: &mut W,
    sb: &mut B,
  ) -> Self {
    let state = sb.state();
    let nonce = Prng::new(seed).next_u64();
    let head = wal.op_head().get();
    let checkpoint_op = state.checkpoint_op().get();
    // The high end of the tail read window (the VERIFIED read frontier): the WAL head, but capped at
    // `checkpoint_op + RECOVER_TAIL_WINDOW` so a corrupt/buggy `op_head` cannot force unbounded reads
    // (the cap rationale is on `RECOVER_TAIL_WINDOW`). The loop below materializes + reads exactly
    // `(checkpoint_op .. hi]`, so `hi` is the highest op this `recover()` actually reads and verifies.
    let hi = head.min(checkpoint_op.saturating_add(RECOVER_TAIL_WINDOW));
    // The recovered head is the VERIFIED read FRONTIER `hi`, never BELOW the durable checkpoint — NOT
    // the RAW `head` (F1, safety). A STATE-SYNCED replica (M3.4a) holds no WAL at or below the synced
    // checkpoint (it pruned the WAL there and never appended the tail), so its `wal.op_head()` can be
    // below `checkpoint_op`; the SM snapshot owns `[1..=checkpoint_op]`, so the recovered head must be
    // at least `checkpoint_op` to preserve `op >= commit_max >= commit_min == checkpoint_op`. The cache
    // below covers only the OFFSET tail `(checkpoint_op .. hi]` — for a synced replica that range is
    // empty; the prefix `[1..=checkpoint_op]` lives in the restored SM snapshot.
    //
    // Why `hi`, not `head`: if `head > hi` (a pathological / bit-rotted head far above the window), the
    // ops in `(hi, head]` were NEVER read/verified/cached here. Setting `self.op = head` would "hold"
    // them per the head, so `on_prepare`'s `pop <= self.op` branch would BLIND-RE-ACK them WITHOUT
    // consulting `self.log` — voting for ops this replica never durably appended (breaking
    // append-before-ack, risking a committed-op loss if the primary counted that false ack and then
    // died). Capping `self.op` at the read frontier means an op above it is NOT held: a later `Prepare`
    // for it takes the `pop == self.op + 1` APPEND branch (the primary re-sends; idempotent), durably
    // appending before any ack — correct. So: head below checkpoint → op = checkpoint; checkpoint <=
    // head <= frontier → op = head (unchanged, the legitimate small-tail case); head > frontier → op =
    // frontier (capped — the deep tail recovers incrementally as the primary re-announces it).
    let op = hi.max(checkpoint_op);

    let mut endpoint = Self {
      config,
      status: Status::Recovering,
      view: state.view(),
      op: OpNumber::with(op),
      // The restored SM reflects [1..=checkpoint_op] exactly; commit_min = checkpoint_op so those
      // ops are NOT re-applied. commit_max = checkpoint_op too (monotone: op >= commit_max >=
      // commit_min). The committed tail (> checkpoint_op) re-applies as the primary re-announces it.
      commit_min: OpNumber::with(checkpoint_op),
      commit_max: OpNumber::with(checkpoint_op),
      log_view: state.log_view(),
      svc_from: 0,
      svc_target: state.view(),
      catching_up: false,
      dvc_from: BTreeMap::new(),
      dvc_quorum: false,
      nonce,
      // Dense headers-only cache; bodies filled by the Recovering loop (Phase 2).
      log: BTreeMap::new(),
      inflight: BTreeMap::new(),
      buffer: BTreeMap::new(),
      // Sessions are restored from the checkpoint snapshot in `on_sb_done` (Phase 2).
      clients: BTreeMap::new(),
      sm,
      outgoing: VecDeque::new(),
      events: VecDeque::new(),
      timers: Timers::default(),
      next_op_id: 1,
      pending: BTreeMap::new(),
      appending: std::collections::BTreeSet::new(),
      pending_sb: None,
      pending_checkpoint: None,
      checkpoint_op: OpNumber::with(checkpoint_op),
      peer_checkpoint: BTreeMap::new(),
      recover: None,
      repair: std::collections::BTreeSet::new(),
      sync: None,
      sync_serving: BTreeMap::new(),
      state_syncs_applied: 0,
      forced_syncs_applied: 0,
      forfeit_armed: None,
      pending_forfeit: false,
    };

    // Phase 1: build the dense header cache (bodies empty) and submit the tail + checkpoint reads.
    // The cache + reads cover ONLY the tail ABOVE the checkpoint, `(checkpoint_op..=head]`: the SM
    // snapshot is authoritative for `[1..=checkpoint_op]` (those ops are never re-applied —
    // `commit_min == checkpoint_op` — and a STATE-SYNCED replica has pruned its WAL there, so reading
    // them would spuriously class pruned slots faulty). A recover-from-checkpoint replica and a
    // state-synced one are thus identical: both hold only the tail above the checkpoint, and the DVC
    // they later send carries that (offset) tail with `commit == checkpoint_op` (the B3-safe shape
    // asserted by the A6 tests). `head` may be below `checkpoint_op` for a synced replica → the range
    // is empty and recovery completes immediately at the synced point.
    let mut rec = RecoverState::default();
    // Bound the per-recover read-submission window (F3): a corrupt/buggy `Wal` reporting a huge
    // `op_head` must not force unbounded bookkeeping + reads here. SATURATING `checkpoint_op + 1`
    // (never overflow), with the high end `hi` (computed above) capped at `checkpoint_op +
    // RECOVER_TAIL_WINDOW` and at `head` — at most `RECOVER_TAIL_WINDOW` slots are materialized per
    // pass. A legitimate tail (the small un-checkpointed pipeline) is far below the cap; a pathological
    // head is clipped (its deep tail is recovered incrementally / via the head-fault path), never
    // billions of reads. `self.op` was set to `hi.max(checkpoint_op)` above, so the window this loop
    // reads and the held head agree EXACTLY (F1: no held op above the verified frontier).
    let lo = checkpoint_op.saturating_add(1);
    for op in lo..=hi {
      if let Some(h) = wal.header(OpNumber::with(op)) {
        endpoint.log.insert(
          op,
          LogEntry {
            client: h.client(),
            request: h.request(),
            body: Bytes::new(),
          },
        );
      }
      // Submit a read for EVERY tail op (even one whose header is absent/faulty now): the read is
      // the authoritative resolution, and a `Fault`/`Absent` completion routes through the retry
      // path. Each read gets a minted OpId (never aliases a future real op — next_op_id grows).
      let id = endpoint.mint_op_id();
      wal.submit_read(id, OpNumber::with(op));
      rec.reads.insert(id.get(), op);
      rec.pending.insert(op, RECOVER_READ_RETRIES);
    }
    if checkpoint_op > 0 {
      let id = endpoint.mint_op_id();
      sb.submit_read_checkpoint(id);
      rec.checkpoint = Some(id.get());
      rec.checkpoint_retries = RECOVER_READ_RETRIES;
    }
    endpoint.recover = Some(rec);
    // Settle the transition decider once: an EMPTY WAL with no checkpoint (head == 0) has nothing to
    // read, so it must reach Normal here (no completion would ever arrive to drive the loop).
    // Otherwise this arms the recover_retry timer so an owner driving `poll_timeout`/`handle_timeout`
    // re-submits any read whose completion is dropped or whose transient fault clears on a later read.
    endpoint.recover_progress(Instant::ZERO, sb);
    endpoint
  }

  /// The current status.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn status(&self) -> Status {
    self.status
  }

  /// The current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The head op number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The commit number (applied frontier — highest op durably applied to the SM).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit_min
  }

  /// The highest op known committed cluster-wide (may exceed locally-held + applied ops).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit_max(&self) -> OpNumber {
    self.commit_max
  }

  /// The op number of this replica's latest durable checkpoint.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// Record a peer's reported `checkpoint_op` MONOTONICALLY: a peer's durable checkpoint never
  /// regresses, so a reordered/older report (a delayed `Commit`/`PrepareOk`, or a stale message
  /// after a partition heals) must never lower the value we hold. Keeping this monotone keeps the GC
  /// prune floor (`quorum_checkpoint_op`) and the M3.5 force-sync/forfeit triggers that read it from
  /// moving backward — a regressing floor could spuriously un-fire the force-sync escalation. (T1)
  fn record_peer_checkpoint(&mut self, replica: u8, reported: OpNumber) {
    let prev = self
      .peer_checkpoint
      .get(&replica)
      .copied()
      .unwrap_or_else(OpNumber::new);
    self.peer_checkpoint.insert(replica, prev.max(reported));
  }

  /// The highest op a `quorum` of replicas (including self) has reported checkpointing.
  ///
  /// Computed from `self.checkpoint_op` plus the per-replica `peer_checkpoint` reports (defaulting an
  /// unheard peer to 0): sort all replicas' reported checkpoints descending and take the `quorum`-th
  /// highest — the largest op `v` such that at least `quorum` replicas report a checkpoint `>= v`.
  /// The primary uses this as the floor below which WAL/session GC is safe (no op a quorum still
  /// needs is freed). Conservative by construction: an unheard peer counts as 0, so a fresh primary
  /// prunes nothing until enough fresh `PrepareOk`s arrive — it never frees an op too early.
  pub fn quorum_checkpoint_op(&self) -> OpNumber {
    let count = self.config.replica_count();
    let mut cps: std::vec::Vec<u64> = std::vec::Vec::with_capacity(count as usize);
    let me = self.config.replica().get();
    cps.push(self.checkpoint_op.get()); // self always counts its own durable checkpoint
    for r in 0..count {
      if r == me {
        continue;
      }
      cps.push(self.peer_checkpoint.get(&r).map_or(0, |c| c.get()));
    }
    cps.sort_unstable_by(|a, b| b.cmp(a)); // descending
    // `cps.len() == replica_count >= quorum`, so `cps[quorum - 1]` is always in bounds.
    OpNumber::with(cps[self.config.quorum() - 1])
  }

  /// The highest `checkpoint_op` ANY single peer (or self) has reported — i.e. the newest durable
  /// checkpoint snapshot we know a `Normal` peer could ship us via `SyncCheckpoint`.
  ///
  /// Unlike [`Self::quorum_checkpoint_op`] (the quorum-th order statistic, used as the GC prune
  /// floor where a *quorum* must agree before freeing), this is the *maximum* over reporters. It is
  /// the correct floor for the force-sync escalation ([`Self::maybe_force_sync`]): a backup only ever
  /// records the PRIMARY's checkpoint (a backup hears `Commit` from the primary, never `PrepareOk`
  /// from other backups — those go to the primary), so on a backup `quorum_checkpoint_op` is
  /// structurally pinned to ~0 and the quorum-th floor can NEVER cross a hole. A single peer reporting
  /// `checkpoint_op >= N` already proves a servable snapshot `>= N` exists (it is the exact source the
  /// ordinary sync trusts, [`Self::maybe_request_sync`], which targets a *single* peer's reported
  /// checkpoint, integrity-gated by `on_sync_checkpoint`). Monotone (each `peer_checkpoint` entry is,
  /// via [`Self::record_peer_checkpoint`]), so the floor never regresses under reordering/partitions.
  fn max_peer_checkpoint_op(&self) -> OpNumber {
    let mut hi = self.checkpoint_op;
    for cp in self.peer_checkpoint.values() {
      hi = hi.max(*cp);
    }
    hi
  }

  /// Whether this `Recovering` replica's OWN checkpoint read exhausted and it is now fetching the
  /// checkpoint from a peer (F1). `false` in every other state (incl. when `recover` is `None`).
  fn awaiting_peer_checkpoint(&self) -> bool {
    self
      .recover
      .as_ref()
      .is_some_and(|r| r.awaiting_peer_checkpoint)
  }

  /// The latest view in which this replica changed its head log.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn log_view(&self) -> View {
    self.log_view
  }

  /// This replica's id.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.config.replica()
  }

  /// Whether this replica is the primary of the current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn is_primary(&self) -> bool {
    self.config.is_primary(self.view)
  }

  /// Read access to the state machine (for tests / observers).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn state_machine(&self) -> &S {
    &self.sm
  }

  /// The number of entries in this replica's in-memory `log` cache (the per-op tail cache).
  ///
  /// Exposed for the simulation boundedness checker: after M3.4b GC, this is bounded by
  /// `O(checkpoint_ops + pipeline)` — the un-checkpointed tail `(prune_floor .. head]` plus in-flight
  /// headroom. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn log_len(&self) -> usize {
    self.log.len()
  }

  /// The number of entries in this replica's primary pipeline (`inflight`) map.
  ///
  /// Exposed for the simulation boundedness checker (same bound argument as [`Self::log_len`]). Not
  /// part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn inflight_len(&self) -> usize {
    self.inflight.len()
  }

  /// The number of entries in this replica's client-session table (`clients`).
  ///
  /// Exposed for the simulation boundedness checker: `clients` is bounded by the active client set
  /// (one session per client), independent of op count. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn clients_len(&self) -> usize {
    self.clients.len()
  }

  /// Test-only: the smallest op number still held in the in-memory `log` cache, or `None` if empty.
  /// Used to assert GC trimmed the cache below the prune floor.
  #[cfg(test)]
  fn min_log_op(&self) -> Option<u64> {
    self.log.keys().next().copied()
  }

  /// Test-only: the per-peer recorded checkpoint (0 if unheard). Proves T1 monotonicity directly.
  #[cfg(test)]
  fn peer_checkpoint_for_test(&self, replica: u8) -> u64 {
    self.peer_checkpoint.get(&replica).map_or(0, |c| c.get())
  }

  /// Test-only: directly seed a peer's reported checkpoint (bypassing a real PrepareOk/Commit), so a
  /// test can construct a quorum-checkpoint floor without driving full message flows. Goes through the
  /// MONOTONE recorder, so a lower injection cannot regress a higher recorded value.
  #[cfg(test)]
  fn inject_peer_checkpoint_for_test(&mut self, replica: u8, op: u64) {
    self.record_peer_checkpoint(replica, OpNumber::with(op));
  }

  /// Test-only: set this replica's own durable `checkpoint_op` (the value the forfeit gate compares
  /// against `quorum_checkpoint_op()`), so a test can model a primary that is/ isn't keeping pace.
  #[cfg(test)]
  fn set_own_checkpoint_for_test(&mut self, op: u64) {
    self.checkpoint_op = OpNumber::with(op);
  }

  /// Test-only: is this `Recovering` replica awaiting a PEER checkpoint after its own checkpoint read
  /// exhausted (the F1 escalation)?
  #[cfg(test)]
  fn awaiting_peer_checkpoint_for_test(&self) -> bool {
    self.awaiting_peer_checkpoint()
  }

  /// Test-only: is the forfeit grace timer currently armed (M3.5 T3)?
  #[cfg(test)]
  fn forfeit_armed_for_test(&self) -> bool {
    self.forfeit_armed.is_some()
  }

  /// Test-only: is the deferred-forfeit flag set (the M3.5 safety step-down a primary raises instead of
  /// force-syncing — see `maybe_force_sync`)?
  #[cfg(test)]
  fn pending_forfeit_for_test(&self) -> bool {
    self.pending_forfeit
  }

  /// Test-only: stage a `pending_checkpoint` (bypassing the trigger), so the `on_request` defense guard
  /// (drop a client while a checkpoint-persist is in flight — the op-reset risk) can be exercised.
  #[cfg(test)]
  fn stage_pending_checkpoint_for_test(&mut self) {
    let id = self.mint_op_id();
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op: self.commit_min,
      checkpoint_id: 0,
      step: CheckpointStep::AwaitSnapshot { id },
    });
  }

  /// Test-only: force this endpoint into a `Normal` state with the given head/commit/checkpoint and a
  /// set of pending-repair holes (with the repair-retry timer armed). Mirrors how the recover loop +
  /// apply path would leave a replica holding a committed-op hole below its head. Does NOT touch the
  /// `log` cache (the holes are, by construction, ABSENT from it — the apply path treats them as
  /// missing bodies), so the commit is genuinely held below the first hole.
  #[cfg(test)]
  fn force_state_for_test(
    &mut self,
    view: u64,
    op: u64,
    commit_min: u64,
    checkpoint_op: u64,
    repair: &[u64],
  ) {
    self.status = Status::Normal;
    self.view = View::with(view);
    self.log_view = View::with(view);
    self.op = OpNumber::with(op);
    self.commit_min = OpNumber::with(commit_min);
    self.commit_max = OpNumber::with(self.commit_max.get().max(commit_min));
    self.checkpoint_op = OpNumber::with(checkpoint_op);
    self.repair = repair.iter().copied().collect();
    if !self.repair.is_empty() {
      self.timers.repair_retry = Some(Instant::ZERO);
    }
  }

  /// Test-only: is `op` a pending-repair hole?
  #[cfg(test)]
  fn has_repair_hole_for_test(&self, op: u64) -> bool {
    self.repair.contains(&op)
  }

  /// Test-only: seed an in-memory `log` entry at `op` (a placeholder body), so the held-tail
  /// preservation of `apply_sync` can be observed (`force_state_for_test` deliberately leaves the
  /// cache empty). Does not touch the WAL.
  #[cfg(test)]
  fn seed_log_entry_for_test(&mut self, op: u64) {
    self.log.insert(
      op,
      LogEntry {
        client: ClientId::new(1),
        request: RequestNumber::with(op),
        body: Bytes::new(),
      },
    );
  }

  /// Test-only: does the in-memory `log` cache hold `op`?
  #[cfg(test)]
  fn has_log_entry_for_test(&self, op: u64) -> bool {
    self.log.contains_key(&op)
  }

  /// Test-only: the outstanding sync's target op, or `None` if no sync is outstanding.
  #[cfg(test)]
  fn sync_target_for_test(&self) -> Option<u64> {
    self.sync.map(|s| s.target.get())
  }

  /// Test-only: is the outstanding sync a FORCED (M3.5) sync?
  #[cfg(test)]
  fn sync_is_forced_for_test(&self) -> bool {
    self.sync.is_some_and(|s| s.forced)
  }

  /// Test-only: the outstanding sync's nonce (panics if none) — to build a matching SyncCheckpoint.
  #[cfg(test)]
  fn sync_nonce_for_test(&self) -> u64 {
    self.sync.expect("a sync is outstanding").nonce
  }

  /// Test-only: arm a FORCED sync to `target` directly (bypassing the trigger), so the forced
  /// assert-relaxation in `apply_sync` can be exercised in isolation.
  #[cfg(test)]
  fn arm_forced_sync_for_test(&mut self, target: u64) {
    self.nonce = self.nonce.wrapping_add(1);
    self.sync = Some(SyncState {
      target: OpNumber::with(target),
      nonce: self.nonce,
      forced: true,
    });
  }

  /// Test/observability counter (M3.4a): how many state-syncs have fully applied + become durable on
  /// this replica since it was constructed. Incremented when an `apply_sync`'s durable re-persist
  /// completes (`on_sb_done` lands the synced checkpoint's root write). The state-sync sim gate uses
  /// this to assert NON-VACUITY — the laggard genuinely state-synced (>= 1) rather than catching up
  /// op-by-op via ordinary retransmit. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn state_syncs_applied(&self) -> u64 {
    self.state_syncs_applied
  }

  /// Test/observability counter (M3.5 T6): the subset of [`Self::state_syncs_applied`] raised by the
  /// FORCE-sync escalation ([`Self::maybe_force_sync`]) — a `Normal` replica that cleared a pruned
  /// committed hole below the quorum checkpoint and fetched the snapshot, instead of looping
  /// `RequestPrepare`. The focused force-sync sim gate uses this to prove the FORCED path fired
  /// specifically (`> 0`), distinguishing it from an ordinary `> self.op` state-sync. Not part of the
  /// stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn forced_syncs_applied(&self) -> u64 {
    self.forced_syncs_applied
  }

  /// Test-only: the cached `(request_number, reply_body)` a client session holds (the at-most-once
  /// reply cache a backup-turned-primary resends on a duplicate request). `None` if no session / no
  /// cached reply.
  #[cfg(test)]
  fn session_reply_for_test(&self, client: u128) -> Option<(u64, std::vec::Vec<u8>)> {
    self
      .clients
      .get(&client)
      .and_then(|s| s.reply.as_ref())
      .map(|(rn, body)| (rn.get(), body.to_vec()))
  }

  /// Mint a fresh storage correlation id.
  fn mint_op_id(&mut self) -> crate::OpId {
    let id = self.next_op_id;
    self.next_op_id += 1;
    crate::OpId::new(id)
  }

  /// Feeds an incoming protocol message.
  pub fn handle_message<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    from: Peer,
    msg: Message,
  ) {
    // A Recovering replica does NOT process ANY consensus message: it is still draining its own
    // durable storage (the async `handle_storage` loop) and does not even know its true head yet, so
    // it casts no PrepareOk/vote/DVC and adopts no peer's view until it reaches Normal. This also
    // blocks the higher-view `catch_up_to_view` pre-checks inside the per-message handlers (which
    // would otherwise yank a recovering replica into ViewChange mid-recovery).
    //
    // The ONE exception (F1): a replica whose OWN durable checkpoint read exhausted its budget cannot
    // restore its SM from disk and is FETCHING the checkpoint from a peer (`awaiting_peer_checkpoint`).
    // It must accept the answering `SyncCheckpoint` — mirroring how a `RecoveringHead` replica accepts
    // a `StartView` to learn its head. Every other message is still dropped (it casts no ack/vote).
    if self.status.is_recovering() {
      if self.awaiting_peer_checkpoint() {
        if let Message::SyncCheckpoint(m) = msg {
          self.on_recover_sync_checkpoint(now, wal, sb, m);
        }
      }
      return;
    }
    // A RecoveringHead replica (its durable head slot is permanently faulty) is the ONE exception:
    // it cannot recover its head from its own disk, so it must LEARN the canonical head from an
    // authoritative peer. We relax the guard for EXACTLY the two head-learning messages — a
    // `StartView` (the new primary's full canonical log+head+commit) and a `RecoveryResponse` from
    // the primary (the recovery-handshake equivalent). It still does NOT participate: every other
    // message (Prepare/PrepareOk/Commit/SVC/DVC/GetView/Recovery/Request) is dropped, so it casts no
    // ack/vote until adoption returns it to Normal. (Dropping a peer's `Recovery` here is correct: a
    // replica that cannot read its own head has no canonical head to hand out.)
    if self.status.is_recovering_head() {
      match msg {
        Message::StartView(m) => self.on_start_view(now, sb, m),
        Message::RecoveryResponse(m) => self.on_recovery_response(now, sb, m),
        _ => {}
      }
      return;
    }
    match msg {
      Message::Request(r) => self.on_request(now, wal, from, r),
      Message::Prepare(p) => self.on_prepare(now, wal, sb, p),
      Message::PrepareOk(ok) => self.on_prepare_ok(now, sb, ok),
      Message::Commit(c) => self.on_commit(now, sb, c),
      Message::StartViewChange(m) => self.on_start_view_change(now, sb, m),
      Message::DoViewChange(m) => self.on_do_view_change(now, wal, sb, m),
      Message::StartView(m) => self.on_start_view(now, sb, m),
      Message::GetView(m) => self.on_get_view(now, m),
      Message::RequestPrepare(m) => self.on_request_prepare(now, m),
      Message::Recovery(m) => self.on_recovery(now, m),
      Message::RecoveryResponse(m) => self.on_recovery_response(now, sb, m),
      // State-sync (M3.4a): a peer's sync solicitation is answered from our durable checkpoint
      // (`on_request_sync`); a sync response is verified + applied (`on_sync_checkpoint`).
      Message::RequestSync(m) => self.on_request_sync(now, sb, m),
      Message::SyncCheckpoint(m) => self.on_sync_checkpoint(now, wal, sb, m),
      Message::Reply(_) => {}
    }
  }

  /// Fires any timers due at `now`, dispatching by status/role.
  pub fn handle_timeout<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    match self.status {
      Status::Normal if self.is_primary() => self.primary_timeouts(now, sb),
      Status::Normal => {
        // backup: bootstrap + fire primary_idle, then re-arm THIS timer only so we
        // re-propose at the primary_idle cadence (not every tick).
        if self.timers.primary_idle.is_none() {
          self.timers.primary_idle = Some(now + PRIMARY_IDLE);
        }
        if self.timers.primary_idle.is_some_and(|d| d <= now) {
          self.on_primary_idle(now, sb);
          self.timers.primary_idle = Some(now + PRIMARY_IDLE);
        }
      }
      Status::ViewChange => self.view_change_timeouts(now, sb),
      // Recovering re-submits any still-outstanding/faulty reads on its timer (termination under a
      // dropped completion / slow-clearing transient). RecoveringHead re-broadcasts its Recovery
      // solicitation until a peer hands it the canonical head.
      Status::Recovering => self.recover_timeouts(now, wal, sb),
      Status::RecoveringHead => self.recover_head_timeouts(now),
    }
    // Peer fault-repair retransmit runs only in Normal (the only status that can solicit/serve a hole
    // and adopt the reply). It re-solicits every unrepaired committed-op hole until each is filled.
    if self.status.is_normal() {
      self.repair_timeouts(now);
      // State-sync re-solicitation likewise runs only in Normal: re-broadcast RequestSync while a
      // sync is outstanding (awaiting a SyncCheckpoint or persisting the adopted one).
      self.sync_timeouts(now);
    }
  }

  /// Drain completed storage ops and react.
  pub fn handle_storage<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    while let Some(done) = wal.poll() {
      self.on_wal_done(now, wal, sb, done);
    }
    while let Some(done) = sb.poll() {
      self.on_sb_done(now, wal, sb, done);
    }
  }

  fn on_wal_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    done: WalDone,
  ) {
    // Recovery read completions route through the recover loop (verify + retry + progress).
    if self.status.is_recovering() || self.status.is_recovering_head() {
      self.on_recover_wal_done(now, wal, sb, done);
      return;
    }
    let WalDone::Appended(id) = done else {
      return; // Normal op: only an append matters (reads/faults occur during recovery).
    };
    // Append-before-ack dispatch by the recorded kind. An OpId not in `self.pending` is a repair-fill
    // append (which owes no ack — see `fill_repair`) or a stale/superseded completion → ignore.
    let resolved = self.pending.remove(&id.get());
    // This op's WAL append is now durable: clear its in-flight mark BEFORE casting any ack/vote, so
    // the choke point (`send_prepare_ok`) sees it as durable (R7-F1). Done for every tracked kind —
    // each variant carries its op number — and never in the `None` arm (a stale/superseded completion
    // must not retract an op a FRESH adopt-append just re-marked under a new OpId).
    match &resolved {
      Some(Pending::Ack(op) | Pending::AdoptVote(op) | Pending::AdoptAck(op)) => {
        self.appending.remove(&op.get());
      }
      None => {}
    }
    match resolved {
      Some(Pending::Ack(op)) => {
        if self.is_primary() {
          // the primary's own append is durable → record its vote and try to commit
          self.record_own_vote(op.get());
          self.try_commit(now, sb);
        } else {
          self.send_prepare_ok(op);
        }
      }
      // codex R6-F1: a new primary's adopted uncommitted-tail op is now durable → only NOW set its own
      // inflight vote and try to commit. The own vote could not be cast before this append (it was
      // seeded `oks: 0` in `start_view_as_new_primary`), so the primary never counts a vote for an op
      // it has not durably appended (append-before-ack for the view-change adoption path).
      Some(Pending::AdoptVote(op)) => {
        self.record_own_vote(op.get());
        self.try_commit(now, sb);
      }
      // codex R6-F1: a backup's adopted uncommitted-tail op is now durable → send the deferred
      // PrepareOk. No PrepareOk was sent for this op before its append completed (append-before-ack).
      Some(Pending::AdoptAck(op)) => self.send_prepare_ok(op),
      None => {}
    }
  }

  /// Set this replica's own vote bit on `op`'s inflight entry (no-op if the entry is gone). Used by
  /// the primary's normal-path own append (`Pending::Ack`) and the R6-F1 view-change adoption append
  /// (`Pending::AdoptVote`) — both record the own vote ONLY once the op's WAL append is durable.
  fn record_own_vote(&mut self, op: u64) {
    let own = 1u64 << self.config.replica().get();
    if let Some(inf) = self.inflight.get_mut(&op) {
      inf.oks |= own;
    }
  }

  /// Handles a WAL completion while `Recovering`/`RecoveringHead` (Phase 2 of `recover`). Adopts a
  /// body ONLY after `Header::verify` (the faults-as-data chokepoint: a torn write / bit-rot fails
  /// verify and is treated as a `Fault`); retries `Fault`/`Absent`/mismatch within the per-slot
  /// budget, then classes the slot permanently faulty. Calls `recover_progress` after each.
  fn on_recover_wal_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    done: WalDone,
  ) {
    // The OpId of the completed read identifies which tail op it resolves (recover.reads). An
    // append completion (Appended) or an OpId we are not tracking is a stale/foreign completion —
    // ignore it (never panic): faults-as-data.
    let id = match &done {
      WalDone::ReadOk(r) => r.id(),
      WalDone::Absent(id) | WalDone::Fault(id) => *id,
      WalDone::Appended(_) => return,
    };
    let Some(rec) = self.recover.as_mut() else {
      return;
    };
    let Some(&op) = rec.reads.get(&id.get()) else {
      return; // not one of our outstanding recovery reads (stale/superseded) — ignore.
    };
    // Decide the outcome: an Ok body that verifies is adopted; everything else is a fault to retry.
    let verified_body = match &done {
      // Adopt only a body that BOTH verifies (header + body checksums) AND lands on the op we asked
      // for. A misdirected read (a different valid slot returned under our OpId) would checksum-verify
      // cleanly, so the placement check (`header.op() == op`) guards against pairing another op's body
      // with this op's metadata — the placement-integrity defense TigerBeetle makes for misdirected IO.
      WalDone::ReadOk(r)
        if r.header().op() == OpNumber::with(op) && r.header().verify(r.body()) =>
      {
        Some(r.body_bytes())
      }
      _ => None, // Absent, Fault, misdirected, OR a ReadOk that fails verify (torn/bit-rot) — a fault.
    };
    match verified_body {
      Some(body) => {
        // Adopt the verified body, retiring this read.
        rec.reads.remove(&id.get());
        rec.pending.remove(&op);
        rec.faulty.remove(&op);
        if let Some(entry) = self.log.get_mut(&op) {
          entry.body = body;
        }
      }
      None => {
        // A fault on this op: spend a retry if any remain, else class it permanently faulty.
        rec.reads.remove(&id.get());
        let budget = rec.pending.get(&op).copied().unwrap_or(0);
        if budget > 0 {
          rec.pending.insert(op, budget - 1);
          let new_id = self.mint_op_id();
          // mint_op_id reborrows self; re-borrow rec to record the new in-flight read.
          if let Some(rec) = self.recover.as_mut() {
            rec.reads.insert(new_id.get(), op);
          }
          wal.submit_read(new_id, OpNumber::with(op));
        } else {
          rec.pending.remove(&op);
          rec.faulty.insert(op);
        }
      }
    }
    self.recover_progress(now, sb);
  }

  fn on_sb_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    done: SuperblockDone,
  ) {
    // Recovery checkpoint-read completions route through the recover loop (restore SM + retry).
    if self.status.is_recovering() || self.status.is_recovering_head() {
      self.on_recover_sb_done(now, wal, sb, done);
      return;
    }
    // State-sync peer side: outside recovery a `CheckpointRead`/`Fault` means a read WE issued to
    // serve a peer's `RequestSync` completed — ship the durable snapshot (or drop the serving entry
    // on a fault; the requester re-solicits). This is status-gated apart from the recover loop above
    // (that handles reads only while recovering; this handles them while Normal).
    let id = match done {
      SuperblockDone::Wrote(id) => id,
      SuperblockDone::CheckpointRead(cr) => {
        self.serve_sync_checkpoint(cr);
        return;
      }
      SuperblockDone::Fault(id) => {
        // A faulted serve-read: drop the serving entry (if any) and stay silent. (A faulted root/
        // checkpoint WRITE outside recovery is not produced by our backends; dropping is defensive.)
        self.sync_serving.remove(&id.get());
        return;
      }
    };
    // Durable-view write? (matched first; its OpId never aliases a checkpoint write's.)
    if let Some((pending_id, action)) = self.pending_sb {
      if pending_id == id {
        self.pending_sb = None;
        match action {
          PendingSbAction::SendDoViewChange => self.send_do_view_change(now),
          PendingSbAction::StartViewAsPrimary => self.start_view_participate(now, sb),
          PendingSbAction::AdoptedStartView => self.start_view_acks(wal),
        }
        return;
      }
    }
    // Checkpoint write? Distinguish the two steps by their own minted OpIds.
    if let Some(pc) = self.pending_checkpoint {
      match pc.step {
        CheckpointStep::AwaitSnapshot { id: sid } if sid == id => {
          // The snapshot is durable → advance the durable root to name the new checkpoint.
          // `commit_min >= target_op` always (target_op was commit_min at trigger; commit_min only
          // grows), so the VsrState `commit >= checkpoint_op` invariant holds → try_new can't fail.
          let root_id = self.mint_op_id();
          let state = crate::VsrState::try_new(
            self.view,
            self.log_view,
            self.commit_min,
            pc.target_op,
            pc.checkpoint_id,
          )
          .expect("checkpoint root: commit_min >= target_op and log_view <= view");
          sb.submit_write(root_id, state);
          self.pending_checkpoint = Some(PendingCheckpoint {
            step: CheckpointStep::AwaitRoot { id: root_id },
            ..pc
          });
        }
        CheckpointStep::AwaitRoot { id: rid } if rid == id => {
          // The root is durable → the checkpoint is COMPLETE: advance the in-memory checkpoint_op,
          // then GC the WAL + per-op caches below the prune floor (M3.4b). GC runs AFTER the durable
          // root so the recovery point is the new checkpoint; a lost/failing prune is then safe (a
          // later checkpoint re-prunes). For a state-sync re-persist (below), the WAL was already
          // truncated+pruned in `apply_sync`, so this is idempotent (prunes below the same floor).
          self.checkpoint_op = pc.target_op;
          self.pending_checkpoint = None;
          self.run_gc(wal);
          // State-sync: if this root write completed a SYNC's durable re-persist (rather than an
          // ordinary checkpoint), the synced checkpoint is now durable → resume as a Normal backup.
          // Clear the sync bookkeeping + solicit timer and re-arm the Normal timers. (A sync and an
          // ordinary checkpoint can never be staged together: `apply_sync` runs only while
          // `sync.is_some()` and gates on `pending_checkpoint.is_none()`, and `maybe_checkpoint`
          // gates on `pending_checkpoint.is_none()` too — so `sync.is_some()` here means this root
          // belongs to the sync.)
          if let Some(s) = self.sync {
            self.sync = None;
            self.timers.sync_solicit = None;
            // Non-vacuity signal (M3.4a): a state-sync just fully applied + became durable.
            self.state_syncs_applied += 1;
            // Non-vacuity signal (M3.5 T6): distinguish a FORCE-sync (the escalation that recovers a
            // pruned committed hole below the quorum checkpoint) from an ordinary `> self.op` sync.
            if s.forced {
              self.forced_syncs_applied += 1;
            }
            self.arm_timers(now);
          }
        }
        _ => {} // a stale/superseded completion (e.g. from before a view change) — ignore
      }
    }
  }

  /// Handles a superblock completion while `Recovering`/`RecoveringHead` (Phase 2 of `recover`).
  /// A `CheckpointRead` restores the SM + client sessions (moved out of the old synchronous drain);
  /// a `Fault` is retried within the checkpoint budget. Calls `recover_progress` after each.
  fn on_recover_sb_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    done: SuperblockDone,
  ) {
    match done {
      SuperblockDone::CheckpointRead(cr) => {
        // Only react to the checkpoint read WE are awaiting (recover.checkpoint); a foreign/stale
        // completion is ignored, never trusted.
        let is_ours = self
          .recover
          .as_ref()
          .and_then(|r| r.checkpoint)
          .is_some_and(|want| want == cr.id().get());
        if !is_ours {
          return;
        }
        // VERIFY before restore (M3.3, safety): a `CheckpointRead` matching our read id is NOT yet
        // trustworthy — a corrupted / stale / torn superblock checkpoint could return wrong bytes. The
        // durable root (`sb.state()`) is the authority for which checkpoint this recovery targets, so
        // the read must match it on BOTH the op and the content hash, AND parse cleanly. The state-sync
        // path verifies the id the same way (`on_sync_checkpoint`); the recover path must too, or a bad
        // read would restore the wrong SM/sessions while `commit_min == checkpoint_op` — silent
        // committed-prefix loss, exactly what the checkpoint hash exists to prevent.
        let state = sb.state();
        let id_ok = crate::checkpoint_id(cr.snapshot()) == state.checkpoint_id();
        let op_ok = cr.op() == state.checkpoint_op();
        let decoded = Self::decode_checkpoint(cr.snapshot());
        // The op BOUND inside the envelope (F3) must equal the read's advertised op; a mismatch means
        // the bytes are an older checkpoint shipped under a newer op (their hash would then disagree
        // with the durable id too, but we check the bound op explicitly so the binding is load-bearing).
        let bound_ok = decoded
          .as_ref()
          .is_some_and(|(bound_op, _, _)| *bound_op == cr.op());
        let Some((_, sessions, sm_tail)) = decoded.filter(|_| id_ok && op_ok && bound_ok) else {
          // Any mismatch (wrong op / wrong hash / wrong bound op / unparsable) is a FAULT — route to the
          // SAME retry path as `SuperblockDone::Fault`: re-submit within the recover budget (or, on
          // exhaustion, escalate to a peer fetch), do NOT restore, do NOT panic. (If the bytes happened
          // to parse but failed a check, we still discard them.)
          self.retry_recover_checkpoint_read(now, wal, sb);
          return;
        };
        self.sm.restore(sm_tail);
        self.clients = sessions;
        if let Some(rec) = self.recover.as_mut() {
          rec.checkpoint = None;
        }
        self.recover_progress(now, sb);
      }
      SuperblockDone::Fault(id) => {
        let is_ours = self
          .recover
          .as_ref()
          .and_then(|r| r.checkpoint)
          .is_some_and(|want| want == id.get());
        if !is_ours {
          return;
        }
        self.retry_recover_checkpoint_read(now, wal, sb);
      }
      SuperblockDone::Wrote(_) => {
        // A stale durable-root/checkpoint *write* completion from before the crash cannot occur
        // (a fresh recover issues no writes); ignore defensively rather than panic.
      }
    }
  }

  /// Re-submit the recover checkpoint read within the retry budget — or, on EXHAUSTION, escalate to a
  /// PEER FETCH (F1). Shared by the `Fault` arm and the VERIFY-failure path (a `CheckpointRead` whose
  /// op/hash mismatched or that failed to parse) of [`Self::on_recover_sb_done`], so a corrupt/torn/
  /// stale read is retried EXACTLY like a transient fault — never restored, never panicked on.
  ///
  /// While the budget remains, a transient checkpoint-read `Fault`/mismatch is re-submitted (the
  /// common case — the durable root usually names a fully-written snapshot, the root write being
  /// step 2 after the snapshot is durable, so the budget clears). EXHAUSTION means the durable root
  /// names a snapshot that is PERMANENTLY unreadable or permanently inconsistent with the root (wrong
  /// op/hash/unparsable on EVERY read) — bit-rot/torn write in this replica's single durable copy.
  /// We must NOT panic on storage-controlled bytes (a malicious/faulty superblock could otherwise
  /// crash the replica at will). The replica instead FETCHES the checkpoint from a peer via the
  /// state-sync machinery: it arms a FORCED [`SyncState`] targeting its own `checkpoint_op` (a peer
  /// with a checkpoint `>= ours` answers) and broadcasts a `RequestSync`, then marks
  /// `awaiting_peer_checkpoint` so `recover_progress` does NOT complete (the SM is not yet restored)
  /// and `handle_message` accepts the incoming `SyncCheckpoint`. A permanent single-copy corruption
  /// that no peer can serve leaves the replica re-soliciting in this recoverable fault state (never a
  /// panic); it ultimately needs backend redundancy (spec §10) — but a healthy cluster heals it.
  fn retry_recover_checkpoint_read<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
  ) {
    let budget = self
      .recover
      .as_ref()
      .map(|r| r.checkpoint_retries)
      .unwrap_or(0);
    if budget == 0 {
      // Budget exhausted → escalate to a peer fetch instead of panicking (F1).
      self.escalate_checkpoint_to_peer_fetch(now);
      let _ = &mut *wal;
      return;
    }
    let new_id = self.mint_op_id();
    if let Some(rec) = self.recover.as_mut() {
      rec.checkpoint = Some(new_id.get());
      rec.checkpoint_retries = budget - 1;
    }
    sb.submit_read_checkpoint(new_id);
    // No progress to report yet (still awaiting the snapshot); but keep wal in the signature uniform
    // with on_recover_wal_done for the handle_storage call site.
    let _ = &mut *wal;
  }

  /// Escalate a permanently-unreadable own checkpoint to a PEER FETCH (F1). Stops local checkpoint
  /// retries, arms a FORCED state-sync targeting our own `checkpoint_op` (so a peer holding a
  /// checkpoint `>= ours` answers), broadcasts the `RequestSync`, and marks `awaiting_peer_checkpoint`
  /// so the recovery stays open (never completes to Normal with an unrestored SM) and `handle_message`
  /// accepts the answering `SyncCheckpoint`. Idempotent: if already escalated, it just (re-)solicits.
  fn escalate_checkpoint_to_peer_fetch(&mut self, now: Instant) {
    // Stop local checkpoint reads and latch the awaiting-peer state.
    if let Some(rec) = self.recover.as_mut() {
      rec.checkpoint = None;
      rec.awaiting_peer_checkpoint = true;
    }
    // Arm a FORCED sync to our own (corrupt) checkpoint_op: any peer whose durable checkpoint is at or
    // above it can serve a snapshot that subsumes ours. `forced` selects `apply_sync`'s relaxed
    // (never-rewind-the-applied-frontier) assert — correct here, where the synced op `>= checkpoint_op
    // == commit_min`. Only arm if not already syncing (anti-thrash); otherwise the existing solicit
    // stands and we just re-broadcast below.
    if self.sync.is_none() {
      self.nonce = self.nonce.wrapping_add(1);
      self.sync = Some(SyncState {
        target: self.checkpoint_op,
        nonce: self.nonce,
        forced: true,
      });
    }
    // Broadcast the solicitation now; the recover-retry timer (`recover_timeouts`) re-broadcasts on a
    // cadence while `awaiting_peer_checkpoint` holds (the Normal-only `sync_timeouts` does not run
    // during recovery).
    self.send_request_sync(now);
    self.arm_timers(now);
  }

  /// The recovery transition decider (Phase 2), called after every recovery read completion. Stays
  /// `Recovering` while any tail read or the checkpoint read is still outstanding; once all reads are
  /// satisfied it transitions to `Normal` (tail consistent / non-head holes peer-repaired) or
  /// `RecoveringHead` (the HEAD slot is permanently faulty — it cannot trust its head and must learn
  /// the canonical head from a peer).
  ///
  /// A non-head permanently-faulty committed slot is repaired peer-to-peer (B4): it is necessarily
  /// ABOVE the applied frontier (`commit_min == checkpoint_op`; the restored SM already holds
  /// `[1..=checkpoint_op]`, so a faulty `op <= checkpoint_op` is never re-applied and does not block
  /// the apply path), so the replica safely returns to `Normal` and re-fetches the op on demand via
  /// `RequestPrepare` when its commit reaches it — HOLDING the commit below the hole until then. This
  /// is what lets a recovering replica with a rotted committed slot rejoin without losing the op.
  fn recover_progress<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    let Some(rec) = self.recover.as_ref() else {
      return;
    };
    // Still draining? (tail reads pending OR the checkpoint snapshot not yet restored OR awaiting a
    // PEER checkpoint after our own read exhausted, F1). Keep the recover_retry timer armed (via
    // arm_timers for the current Recovering status) so an owner re-submits any dropped/slow read AND
    // re-solicits the peer checkpoint. Crucially, `awaiting_peer_checkpoint` blocks completion: we
    // must NEVER reach Normal with the SM unrestored (`commit_min == checkpoint_op` would then be a
    // silent committed-prefix loss) — recovery completes only once a verified `SyncCheckpoint`
    // restores the SM (via `on_recover_sync_checkpoint` → `apply_sync`).
    if !rec.pending.is_empty() || rec.checkpoint.is_some() || rec.awaiting_peer_checkpoint {
      self.arm_timers(now);
      return;
    }
    if rec.faulty.is_empty() {
      // Tail consistent: every body is present + checksum-verified → settle the terminal status. A
      // recovered backup resumes Normal (it waits for the primary's Prepare/Commit to re-announce
      // commit); a replica that was the established PRIMARY (or crashed mid-view-change) does NOT
      // resume as that primary — `complete_recovery` abdicates / re-drives the view change instead.
      self.complete_recovery(now, sb);
      return;
    }
    // Some slot read back permanently faulty (the per-slot retry budget — and the on-disk recover_retry
    // re-reads — were exhausted, so it cannot be cleared from this replica's own disk).
    let head = self.op.get();
    let faulty: std::vec::Vec<u64> = rec.faulty.iter().copied().collect();
    // Every faulty slot MUST be dropped from the dense `log` cache so it can NEVER be applied with a
    // wrong/empty body — the B4 durability invariant. The recover Phase-1 cache seeds each tail slot
    // with an EMPTY body (`Bytes::new()`) and a verified read fills it; a slot left faulty still holds
    // that empty placeholder. Dropping it here closes a real safety hole on the RecoveringHead path: a
    // later canonical-head adoption (`adopt_log`) PRESERVES any committed op the adopter already holds
    // that the canonical log omits, so a retained empty-bodied faulty op would be adopted as "held",
    // its repair hole retired, and applied EMPTY — diverging the committed op. (Observed deterministically
    // under the M3 sweep: a replica with BOTH a faulty head and a faulty non-head committed slot.)
    for &op in &faulty {
      self.log.remove(&op);
    }
    if faulty.contains(&head) {
      // The head cannot be trusted → RecoveringHead: do not participate. Solicit the canonical head
      // from a peer (the primary answers with a `RecoveryResponse`; a `StartView` also adopts), and
      // keep `recover` so the head stays flagged until adoption returns to Normal. We do NOT
      // pre-register the non-head faulty slots as repair holes (codex R6-F2): a faulty slot above the
      // checkpoint may be UNCOMMITTED (at recovery we only know `commit_min == checkpoint_op`), and a
      // pre-registered hole for an uncommitted op can NEVER be filled after the R5 repair restrictions
      // (a peer serves only `op <= commit`; `fill_repair` rejects `commit < op`), wedging the
      // `on_request` guard into a client-serving deadlock. A COMMITTED faulty slot is instead requested
      // ON DEMAND by `advance_commit` once commit reaches it (which only happens once it is committed);
      // an UNCOMMITTED one is simply truncated away if a later view change rewinds the tail.
      self.status = Status::RecoveringHead;
      self.arm_timers(now);
      self.send_recovery(now);
      return;
    }
    // Only non-head committed slots are faulty. We do NOT pre-register them as repair holes here
    // (codex R6-F2): see the RecoveringHead branch above — a faulty slot above the checkpoint may be
    // uncommitted, and pre-registering it is an unfillable post-R5 hole that deadlocks `on_request`.
    // `advance_commit` requests each missing op ON DEMAND when commit reaches it (only committed ops
    // are ever reached); the dropped empty placeholder is never resurrected (the slot was removed from
    // `self.log` above, so the apply path treats it as a hole until a verified Prepare fills it).
    // Settle the terminal status: a recovered primary abdicates / a mid-view-change recovery re-drives
    // (`complete_recovery`); only a replica that actually resumes Normal can serve the hole solicitation
    // now (a Recovering/ViewChange replica drops all messages, so it could not receive the repair
    // `Prepare` — the repair_retry timer re-solicits once it next resumes Normal).
    self.complete_recovery(now, sb);
    if self.status.is_normal() {
      // Solicit every hole now (the timer also re-solicits on a cadence until each is filled).
      let ops: std::vec::Vec<u64> = self.repair.iter().copied().collect();
      for op in ops {
        self.send_request_prepare(op);
      }
    }
  }

  /// Settle the terminal status of a recovered replica once its tail is resolved — a faithful port of
  /// TigerBeetle `replica.zig` open()'s participation decision. A replica that crashed AS the
  /// established primary has NO in-memory pipeline (`inflight` is empty) and its session table is only
  /// at `checkpoint_op`, so it MUST NOT resume as that primary: resuming Normal would freeze commit at
  /// `checkpoint_op` (every re-acked PrepareOk drops on the empty `inflight`) and could re-execute a
  /// client request retried in `(checkpoint_op, op]` (the session table no longer remembers it). So:
  ///
  /// - `log_view < view`  → crashed MID-VIEW-CHANGE (the durable view advanced but the new log was not
  ///   yet installed): re-drive `VC(view)` so the in-progress change completes.
  /// - was Normal AS the PRIMARY (`log_view == view` and we lead `view`) → ABDICATE to `view + 1`: the
  ///   clean view change rebuilds the pipeline (DVC collection → `start_view_as_new_primary`), and
  ///   `on_request` returns early while status != Normal, closing the double-execute hazard.
  /// - otherwise (a BACKUP, or a SOLO replica that is its own primary) → resume Normal.
  ///
  /// SOLO (`replica_count == 1`): a solo replica is always its own primary and CANNOT view-change (no
  /// peer quorum) — abdicating would deadlock, so it resumes Normal. But a solo primary commits via the
  /// `inflight` pipeline (quorum 1: the own append-done vote alone commits), so an empty `inflight`
  /// would stall its recovered tail `(commit_min, op]` — ops it had already committed pre-crash. We
  /// therefore REBUILD that pipeline (own-vote set, mirroring `start_view_as_new_primary`) and drive
  /// `try_commit`, so the solo primary re-commits its tail and makes progress immediately.
  fn complete_recovery<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    self.recover = None;
    if self.log_view.get() < self.view.get() {
      // Crashed mid-view-change (durable view advanced, new log not yet installed): re-drive VC(view).
      self.enter_view_change_from_recovery(now, sb, self.view);
    } else if self.config.replica_count() > 1 && self.config.is_primary(self.view) {
      // Was Normal as the PRIMARY → abdicate: a restarted primary has no in-memory pipeline and a
      // checkpoint-only session table, so it forces a clean view change to view + 1 rather than
      // resuming as the established primary.
      self.enter_view_change_from_recovery(now, sb, self.view.next());
    } else {
      // Backup, or a SOLO replica (its own primary, no quorum to view-change) → resume Normal.
      self.status = Status::Normal;
      if self.config.replica_count() == 1 {
        // Solo: rebuild the pipeline for the recovered tail so `try_commit` can re-commit ops the
        // solo primary had already committed pre-crash (an empty `inflight` would stall them — solo
        // commits via the own-vote quorum of 1). Mirror `start_view_as_new_primary`'s rebuild.
        self.inflight.clear();
        let own = 1u64 << self.config.replica().get();
        for op in (self.commit_min.get() + 1)..=self.op.get() {
          self.inflight.insert(
            op,
            Inflight {
              oks: own,
              committed: false,
            },
          );
        }
        self.arm_timers(now);
        self.try_commit(now, sb);
      } else {
        self.arm_timers(now);
      }
    }
  }

  /// Recover-retry timer: re-submit every still-unsatisfied tail read (and the checkpoint read), so
  /// the loop terminates even if a real async driver dropped a completion or a transient fault only
  /// clears on a later read. Resets each unsatisfied op to exactly ONE fresh outstanding read with a
  /// full budget (dropping its stale `reads` entries), avoiding duplicate-completion ambiguity.
  fn recover_timeouts<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    if !self.timers.recover_retry.is_some_and(|d| d <= now) {
      return;
    }
    // Collect the ops needing a (re)read: those still pending OR classed faulty. (Snapshot the set
    // first so we can mutate `recover` while iterating.)
    let (ops, want_checkpoint, awaiting_peer) = match self.recover.as_ref() {
      Some(rec) => {
        let mut ops: std::vec::Vec<u64> = rec.pending.keys().copied().collect();
        ops.extend(rec.faulty.iter().copied());
        ops.sort_unstable();
        ops.dedup();
        (ops, rec.checkpoint, rec.awaiting_peer_checkpoint)
      }
      None => (std::vec::Vec::new(), None, false),
    };
    // F1 peer-fetch: if our own checkpoint read exhausted and we are awaiting a PEER `SyncCheckpoint`,
    // re-broadcast the `RequestSync` on this cadence (the Normal-only `sync_timeouts` does not run
    // while Recovering). A peer holding a checkpoint `>= ours` answers; until then we stay here.
    if awaiting_peer && self.sync.is_some() {
      self.send_request_sync(now);
    }
    for op in ops {
      let new_id = self.mint_op_id();
      if let Some(rec) = self.recover.as_mut() {
        // Drop any prior in-flight read entries for this op (a dropped/duplicate completion now
        // resolves to nothing), then register exactly one fresh read with a full budget.
        rec.reads.retain(|_, &mut o| o != op);
        rec.reads.insert(new_id.get(), op);
        rec.faulty.remove(&op);
        rec.pending.insert(op, RECOVER_READ_RETRIES);
      }
      wal.submit_read(new_id, OpNumber::with(op));
    }
    // Re-issue the checkpoint read if it is still outstanding and its prior completion was dropped.
    if want_checkpoint.is_some() {
      let new_id = self.mint_op_id();
      if let Some(rec) = self.recover.as_mut() {
        rec.checkpoint = Some(new_id.get());
        rec.checkpoint_retries = RECOVER_READ_RETRIES;
      }
      sb.submit_read_checkpoint(new_id);
    }
    // Re-arm so we keep retrying until the loop completes.
    self.timers.recover_retry = Some(now + RECOVER_READ_RETRANSMIT);
  }

  /// RecoveringHead solicitation timer: re-broadcast the `Recovery` request (and re-arm) until a
  /// peer's `RecoveryResponse`/`StartView` re-establishes the head and adoption returns us to Normal.
  fn recover_head_timeouts(&mut self, now: Instant) {
    if self.timers.recover_head.is_some_and(|d| d <= now) {
      self.send_recovery(now); // re-broadcasts and re-arms recover_head
    }
  }

  /// Register op `op` for peer fault-repair (B4): its committed body read back permanently faulty, so
  /// we drop any stale (header-only / wrong) cache entry, record the hole, immediately solicit the op
  /// from peers, and arm the repair-retry timer. The COMMIT IS HELD below `op` by the apply loops
  /// (they break at the first missing op) — this never advances `commit_min` past the hole. Idempotent
  /// per op (a re-request while already pending just re-solicits + re-arms).
  fn request_repair(&mut self, now: Instant, op: u64) {
    // Drop the cache entry so the apply path keeps treating this slot as a hole until a VERIFIED
    // Prepare fills it (never apply a wrong/empty body). A torn slot's header-only entry is removed;
    // a bit-rotted slot was never inserted.
    self.log.remove(&op);
    self.repair.insert(op);
    self.send_request_prepare(op);
    self.timers.repair_retry = Some(now + REPAIR_RETRANSMIT);
    // Force-sync escalation (M3.5): if a quorum already checkpointed past this just-registered hole
    // (e.g. a replica recovered a rotted committed slot the cluster long since checkpointed+pruned),
    // its `RequestPrepare` is futile from the outset — escalate straight to a forced `RequestSync`.
    self.maybe_force_sync(now);
  }

  /// Broadcast a `RequestPrepare` for the single missing committed op `op` to all peers. Any peer
  /// that holds `op` answers with the `Prepare` carrying it (`on_request_prepare`). Broadcast (not
  /// primary-only) so the repair completes even mid-view-change / when the primary itself is the one
  /// missing the op.
  fn send_request_prepare(&mut self, op: u64) {
    self.outgoing.push_back(Outgoing::new(
      Recipient::Backups,
      Message::RequestPrepare(crate::RequestPrepare::new(
        self.view,
        OpNumber::with(op),
        self.config.replica(),
      )),
    ));
  }

  /// Peer-fault-repair retransmit timer: while the repair set is non-empty, re-solicit every
  /// unrepaired op and re-arm. Terminates when the last hole is filled (`fill_repair` clears the op
  /// and stops re-arming once `repair` is empty).
  fn repair_timeouts(&mut self, now: Instant) {
    if !self.timers.repair_retry.is_some_and(|d| d <= now) {
      return;
    }
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
      return;
    }
    let ops: std::vec::Vec<u64> = self.repair.iter().copied().collect();
    for op in ops {
      self.send_request_prepare(op);
    }
    self.timers.repair_retry = Some(now + REPAIR_RETRANSMIT);
  }

  /// Answer a peer's `RequestPrepare` for a committed op it read back faulty: if we are `Normal` and
  /// hold the op's body in our log cache, reply with the `Prepare` carrying it. Only a Normal replica
  /// answers (a recovering / view-changing replica may itself hold a hole at that op). The reply's
  /// `commit` field carries our commit so the requester can also learn fresh commit progress; the
  /// op's content is view-independent, so the requester accepts it regardless of our view.
  fn on_request_prepare(&mut self, _now: Instant, m: crate::RequestPrepare) {
    if !self.status.is_normal() {
      return; // only a Normal replica has a trustworthy committed log to serve from
    }
    if m.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    let op = m.op().get();
    let Some(entry) = self.log.get(&op) else {
      return; // we do not hold this op (or it is a hole for us too) — stay silent; another peer answers
    };
    // codex R5-F1: never vouch for an uncommitted op as a repair source. Serve only ops we have
    // committed (op <= commit_min) so the answering Prepare carries commit (= commit_min) >= op; an op
    // above our applied frontier is not ours to certify — stay silent and let a caught-up peer answer.
    if op > self.commit_min.get() {
      return;
    }
    let prepare = Prepare::new(
      self.view,
      OpNumber::with(op),
      self.commit_min,
      self.checkpoint_op,
      entry.client,
      entry.request,
      entry.body.clone(),
    );
    self.outgoing.push_back(Outgoing::new(
      Recipient::To(Peer::Replica(m.replica())),
      Message::Prepare(prepare),
    ));
  }

  /// Fill a peer-supplied `Prepare` for an op in our pending-repair set (B4), then resume the held
  /// commit. Two guards protect the committed slot:
  /// - **Placement** (`p.op()` equals a hole in `self.repair`): the load-bearing check — a misdirected
  ///   or mismatched reply for any other op is rejected, so a committed slot is never filled with a
  ///   different op's body. This mirrors the recovery read-path's `header.op() == op` placement check.
  /// - **Body checksum** (`Header::verify`): the body's `body_checksum` must be self-consistent. (For
  ///   an in-process `Prepare` value the header is reconstructed from its own fields, so this is a
  ///   structural belt-and-suspenders; it becomes a genuine integrity gate when a `Prepare` arrives
  ///   over a wire codec that carries the checksum independently of the body.)
  ///
  /// The integrity of the repaired *content* rests on the VSR durability guarantee that a quorum holds
  /// every committed op's correct body (the honest-peer model) plus the placement guard above. On
  /// success the body is inserted into the dense `log` cache and persisted durably via a WAL append
  /// (so future reads / DVCs / a later crash-restart serve the repaired op), the hole is cleared, and
  /// the held commit resumes. A `Prepare` whose op is not a hole (or whose body fails the checksum) is
  /// rejected (returns `false`) so the caller falls through to the normal prepare path.
  fn fill_repair<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    p: &Prepare,
  ) -> bool {
    let op = p.op().get();
    if !self.repair.contains(&op) {
      return false; // placement: not a hole we are repairing — let on_prepare handle it normally
    }
    // SAFETY (codex R5-F1): a committed repair hole may ONLY be filled with the committed value for
    // this op. A repair answer from a peer that holds op N committed carries commit >= op (it set
    // prepare.commit = its own commit_min >= N in on_request_prepare). A STALE/reordered Prepare from an
    // old view, broadcast while its body was still UNCOMMITTED, carries commit < op — reject it (keep the
    // hole open + re-solicit) so a committed slot is never overwritten with an uncommitted old-view body.
    // Soundness: under the VSR (non-Byzantine) fault model commit >= op means the sender committed op,
    // and a committed op's body is identical across all views (committed-op survival), so the body is
    // canonical.
    if p.commit().get() < p.op().get() {
      return false;
    }
    // Reconstruct the header (also needed for the durable append below) and gate on its body checksum.
    let header = Header::new(p.op(), p.view(), p.client(), p.request(), p.body());
    if !header.verify(p.body()) {
      return false; // unverifiable body — never adopt it for a committed op; keep the hole + re-solicit
    }
    // Fill the dense cache and persist the repaired op durably (append-after-verify), so a subsequent
    // crash/restart reads it cleanly and a DVC/StartView we send carries it.
    self.log.insert(
      op,
      LogEntry {
        client: p.client(),
        request: p.request(),
        body: p.body_bytes(),
      },
    );
    let id = self.mint_op_id();
    wal.submit_append(id, p.op(), header, p.body_bytes());
    // NOTE: this append's completion is a bare durability write, NOT a prepare vote — we do not add it
    // to `self.pending` (no PrepareOk/own-vote is owed for a repair fill), so on_wal_done ignores it.
    self.repair.remove(&op);
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
    }
    // The hole is filled → resume applying the held committed prefix from exactly where it stalled.
    let target = self.commit_max.get();
    self.advance_commit(now, sb, target);
    true
  }

  // ── State-sync (M3.4a): the trigger + the lagging replica's solicitation ──

  /// The state-sync TRIGGER. A replica enters state-sync iff it is `Normal` AND it learns of a cluster
  /// checkpoint strictly ABOVE its own head (`incoming_checkpoint > self.op`), via a `checkpoint_op`
  /// carried on a `Commit`/`Prepare`/`PrepareOk`. A checkpoint at op `C` means a quorum committed AND
  /// applied through `C`, so ops `[1..=C]` are committed cluster-wide and may be pruned at the source;
  /// if `C > self.op`, this replica's entire WAL is below the cluster checkpoint, so neither retransmit
  /// (`commit_min+1..=op`) nor peer fault-repair (a single in-reach op) can close a gap that starts
  /// under its own head — it must fetch the checkpoint itself. (`> self.op`, not `>= self.op`: an equal
  /// head means it holds exactly up to the checkpoint and can apply forward by the ordinary path; and
  /// not `> self.checkpoint_op`, because a replica whose tail still reaches the cluster checkpoint
  /// catches up by ordinary commit-application — state-sync is only for an out-of-reach gap.) This is
  /// the conservative, minimal trigger: it never fires when ordinary catch-up suffices, so by
  /// construction it never syncs past uncommitted state.
  ///
  /// Anti-thrash: if a sync is already outstanding (`self.sync.is_some()`) we only RAISE the target
  /// and re-solicit; we do not start a second handshake.
  fn maybe_request_sync(&mut self, now: Instant, incoming_checkpoint: OpNumber) {
    if !self.status.is_normal() {
      return; // Recovering/RecoveringHead/ViewChange have their own catch-up; never sync from there.
    }
    if incoming_checkpoint.get() <= self.op.get() {
      return; // in reach — ordinary commit-application (or peer-repair) catches us up.
    }
    // Already syncing? Only raise the target if this checkpoint is newer, then re-solicit on the
    // timer cadence — do not emit a fresh handshake per heartbeat.
    if let Some(s) = self.sync {
      if incoming_checkpoint.get() > s.target.get() {
        self.sync = Some(SyncState {
          target: incoming_checkpoint,
          nonce: s.nonce,
          // Preserve the in-flight sync's forced-ness when only raising the target (an ordinary
          // higher checkpoint does not downgrade an outstanding forced sync's assert-relaxation).
          forced: s.forced,
        });
      }
      return;
    }
    // Fresh trigger: bump the nonce deterministically (the sim seeds `self.nonce` from the prng;
    // a simple increment keeps it deterministic + distinct from the prior recovery/get-view nonce),
    // record the target, and broadcast the solicitation.
    self.nonce = self.nonce.wrapping_add(1);
    self.sync = Some(SyncState {
      target: incoming_checkpoint,
      nonce: self.nonce,
      forced: false,
    });
    self.send_request_sync(now);
  }

  /// The M3.5 force-state-sync escalation (the safety-critical core). A `Normal` replica holding a
  /// peer-fault-`repair` hole at op `N` whose `RequestPrepare` has become FUTILE — because a peer has
  /// checkpointed past `N` (`max_peer_checkpoint_op() >= N`), so that peer captured `N` in a checkpoint
  /// snapshot and pruned the servable prepare — clears the doomed hole(s) and forces a `RequestSync` to
  /// that peer checkpoint (which is `>= N`, so its snapshot subsumes `N`). This closes the GC +
  /// permanent-fault + partition strand the `run_gc` doc-comment flagged: without it, such a replica's
  /// ordinary sync trigger (`> self.op`) is FALSE (its head is above the cluster checkpoint) and no
  /// peer can serve the pruned `N`, so it is stuck at `commit_min == N-1` forever.
  ///
  /// # The floor is the MAX peer checkpoint, not the quorum-th (the backup-visibility fix)
  ///
  /// The floor is [`Self::max_peer_checkpoint_op`] — the highest checkpoint ANY peer (or self) has
  /// reported — NOT [`Self::quorum_checkpoint_op`]. A backup only ever records the PRIMARY's checkpoint
  /// (it hears `Commit` from the primary; `PrepareOk`s — the only other checkpoint-bearing message —
  /// flow to the primary, never between backups), so on a backup the quorum-th floor is structurally
  /// pinned to ~0 and could NEVER cross a hole → the escalation would never fire and the backup would
  /// hang forever (the exact strand this method exists to break). A single peer reporting
  /// `checkpoint_op >= N` already proves a servable snapshot `>= N` exists — and that is precisely the
  /// source the ordinary sync already trusts ([`Self::maybe_request_sync`] targets a single peer's
  /// reported checkpoint, integrity-gated by `on_sync_checkpoint`'s `checkpoint_id` check). So keying
  /// on a single peer's checkpoint is no weaker than the ordinary sync's own trust model.
  ///
  /// # Safety — never abandons a committed op without the snapshot replacing it
  ///
  /// We only clear holes `<= floor` and set the forced sync target to exactly `floor`. Every repair
  /// hole is a COMMITTED op (`advance_commit`/`commit_op` register a hole only at `commit_min + 1 <=
  /// commit_max`, never for an uncommitted op), so a cleared hole `M (<= floor)` is (a) subsumed by the
  /// synced snapshot (`apply_sync` restores the SM through `floor >= M`, recovering `M`'s effect) and
  /// (b) never an uncommitted decision we were free to drop anyway. A committed op `M` is never lost —
  /// merely relocated from "a servable prepare" to "inside the checkpoint", exactly the case-(1)
  /// argument in the `run_gc` proof. The forced sync target is a checkpoint a `Normal` peer demonstrably
  /// made durable+pruned past, so that peer can answer the `RequestSync`. No commit advances past `N`
  /// until the snapshot (`>= N`) is applied: the hole holds `commit_min` at `N-1` until `apply_sync`
  /// sets `commit_min = floor >= N`. The forced path NEVER fires while every hole is still IN-REACH
  /// (above the floor, i.e. no peer has pruned it yet) — it does not pre-empt the cheap single-op
  /// `RequestPrepare` repair; and even if it fires while some lagging peer could still serve the
  /// prepare, whichever recovery (the `Prepare` or the `SyncCheckpoint`) lands first wins, with no
  /// committed op lost either way.
  ///
  /// # Anti-thrash
  ///
  /// A forced sync, once outstanding (`self.sync.is_some()`), is not re-issued — we only RAISE its
  /// target if `floor` grew, exactly mirroring the ordinary trigger. Clearing the doomed holes stops
  /// the futile `RequestPrepare` retransmit (the `repair_retry` timer disarms when `repair` empties).
  fn maybe_force_sync(&mut self, now: Instant) {
    if !self.status.is_normal() || self.repair.is_empty() {
      return; // only a Normal replica with an outstanding repair hole can be in this strand.
    }
    let floor = self.max_peer_checkpoint_op();
    if floor.get() == 0 {
      return; // no peer-checkpoint floor known yet (e.g. partitioned) — stay dormant.
    }
    // Any hole AT/BELOW the peer-checkpoint floor is snapshot-only on its reporter: that peer pruned
    // the prepare, so `RequestPrepare` for it cannot be answered there. A hole strictly ABOVE the floor
    // is still in-reach (no peer has pruned it) → keep using the cheap single-op repair, do NOT escalate.
    if !self.repair.iter().any(|&op| op <= floor.get()) {
      return;
    }
    // SAFETY (M3.5): a PRIMARY must NOT force-sync. The force-sync below resets `self.op` to `floor`
    // (BELOW the primary's head) and clears the log/inflight; the primary would then accept new client
    // requests at REUSED op numbers in the SAME view, and backups still holding the old entries would
    // re-ack them from `on_prepare`'s `pop <= self.op` branch WITHOUT comparing bodies — the primary
    // commits body B while backups applied body A for the same op = committed-state divergence. So a
    // primary that reaches this strand (an unservable, checkpoint-subsumed hole) steps DOWN instead:
    // flag the deferred forfeit, which the next primary tick (`primary_timeouts`) acts on. A caught-up
    // replica then leads and the subsumed hole is recovered via that primary's ordinary checkpoint flow.
    // (Gating force-sync off the primary WITHOUT this step-down would wedge a stuck laggard-primary,
    // since its lag may be below the checkpoint-interval forfeit threshold — hence forfeit, not no-op.)
    if self.is_primary() {
      self.pending_forfeit = true;
      return;
    }
    // Clear every snapshot-only hole; the forced sync to `floor` subsumes them all (its snapshot is
    // `>= max such hole`). A hole above the floor (if any) stays and continues ordinary repair.
    self.repair.retain(|&op| op > floor.get());
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
    }
    // Solicit (or re-target) a FORCED sync to the peer-checkpoint floor.
    match self.sync {
      Some(s) if floor.get() > s.target.get() => {
        // Raise an outstanding sync's target to the floor and mark it forced (the discard-direction
        // assert in `apply_sync` must use the relaxed invariant for this synced checkpoint).
        self.sync = Some(SyncState {
          target: floor,
          nonce: s.nonce,
          forced: true,
        });
      }
      Some(_) => {} // a sync to >= floor is already outstanding — let it run (anti-thrash).
      None => {
        self.nonce = self.nonce.wrapping_add(1);
        self.sync = Some(SyncState {
          target: floor,
          nonce: self.nonce,
          forced: true,
        });
        self.send_request_sync(now);
      }
    }
  }

  /// Broadcast a `RequestSync` advertising our CURRENT (stale) checkpoint + the live sync nonce, and
  /// (re)arm the solicit timer. An ordinary state-sync request is answered only by a `Normal` peer with
  /// a STRICTLY-newer durable checkpoint; a RECOVERY peer-fetch (`awaiting_peer_checkpoint()` — our own
  /// checkpoint snapshot is permanently unreadable) sets the `recovery` flag so a peer at the SAME
  /// `checkpoint_op` also serves it (F2: without this, an idle cluster where every healthy peer holds
  /// exactly our checkpoint_op ignores the request forever → recovery livelocks).
  fn send_request_sync(&mut self, now: Instant) {
    let nonce = self.sync.map_or(self.nonce, |s| s.nonce);
    let recovery = self.awaiting_peer_checkpoint();
    self.outgoing.push_back(Outgoing::new(
      Recipient::Backups,
      Message::RequestSync(crate::RequestSync::new(
        self.view,
        self.checkpoint_op,
        self.config.replica(),
        nonce,
        recovery,
      )),
    ));
    self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
  }

  /// State-sync solicit timer: while a sync is outstanding, re-broadcast `RequestSync` and re-arm.
  /// Cleared when the synced checkpoint goes durable (`on_sb_done` clears `sync` + this timer).
  fn sync_timeouts(&mut self, now: Instant) {
    if !self.timers.sync_solicit.is_some_and(|d| d <= now) {
      return;
    }
    if self.sync.is_none() {
      self.timers.sync_solicit = None;
      return;
    }
    self.send_request_sync(now);
  }

  // ── State-sync (M3.4a): the peer side — answer a RequestSync from the durable checkpoint ──

  /// Answer a peer's `RequestSync` by shipping our latest DURABLE checkpoint, iff we are `Normal` and
  /// hold a checkpoint strictly NEWER than the requester's (else stay silent — never ship a megabyte
  /// snapshot for a no-op). Any caught-up replica (primary or backup) may answer: a committed
  /// checkpoint is immutable cluster-wide, so any holder is authoritative for its content. We do not
  /// keep the encoded envelope in memory after a checkpoint completes, so we read it back from the
  /// superblock (`submit_read_checkpoint`) and record the read in `sync_serving`; the completion
  /// (`on_sb_done`) ships the `SyncCheckpoint`.
  fn on_request_sync<B: Superblock>(&mut self, _now: Instant, sb: &mut B, m: crate::RequestSync) {
    if !self.status.is_normal() {
      return; // only a Normal replica has a trustworthy durable checkpoint to serve
    }
    if m.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    if self.checkpoint_op.get() == 0 {
      return; // nothing durable to serve — silent.
    }
    // A RECOVERY peer-fetch (F2) is served at an EQUAL checkpoint too: the requester's OWN snapshot
    // bytes are corrupt, so it needs ours even at the same `checkpoint_op`. (We are `Normal` — checked
    // above — so our durable snapshot is trustworthy.) An ordinary state-sync request keeps the strict
    // `>`: never ship a megabyte snapshot for a no-op when the requester is already at our checkpoint.
    let in_reach = if m.recovery() {
      self.checkpoint_op.get() >= m.checkpoint_op().get()
    } else {
      self.checkpoint_op.get() > m.checkpoint_op().get()
    };
    if !in_reach {
      return; // nothing the requester needs from us — silent.
    }
    let id = self.mint_op_id();
    sb.submit_read_checkpoint(id);
    self.sync_serving.insert(id.get(), (m.replica(), m.nonce()));
  }

  /// Ship a `SyncCheckpoint` for a completed serve-read (the read `on_request_sync` issued). Binds the
  /// shipped `checkpoint_id` to the shipped bytes via `checkpoint_id(cr.snapshot())` — so even a buggy
  /// superblock that returned a snapshot inconsistent with its root id cannot make us advertise
  /// mismatched bytes (the requester re-verifies, but we must not lie cheaply). Re-checks status +
  /// replica range at SHIP time (both may have changed between submit and completion): if we are no
  /// longer Normal we drop the reply.
  fn serve_sync_checkpoint(&mut self, cr: crate::CheckpointRead) {
    let Some((to, nonce)) = self.sync_serving.remove(&cr.id().get()) else {
      return; // not a serve-read we issued (a stale/foreign completion) — ignore.
    };
    if !self.status.is_normal() {
      return; // no longer a trustworthy server (entered a view change / recovery) — drop.
    }
    if to.get() >= self.config.replica_count() {
      return; // defensive range re-check.
    }
    // Only ship when the READ's op matches our CURRENT durable `checkpoint_op` (F3): we advertise
    // `cr.op()` and bind it into the snapshot, so the op we ship must be the one whose bytes these are.
    // If we checkpointed forward between submit and completion (a newer checkpoint write landed), the
    // returned bytes may be the OLD snapshot under a stale op — drop rather than ship a mismatched pair
    // (the requester re-solicits and gets our fresh checkpoint).
    if cr.op() != self.checkpoint_op {
      return;
    }
    let snapshot = cr.snapshot_bytes();
    let id = crate::checkpoint_id(&snapshot);
    self.outgoing.push_back(Outgoing::new(
      Recipient::To(Peer::Replica(to)),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        self.view,
        cr.op(),
        id,
        self.config.replica(),
        nonce,
        snapshot,
      )),
    ));
  }

  // ── State-sync (M3.4a): apply a verified SyncCheckpoint (the safety-critical core) ──

  /// Receive a `SyncCheckpoint`. Runs the §2.5 guard cascade (status; matching outstanding sync;
  /// nonce; advances past `target`, our head, and our checkpoint), then the LOAD-BEARING integrity
  /// gate — `checkpoint_id(snapshot) == checkpoint_id` — and only then `apply_sync`. A failed
  /// integrity check (a corrupt/forged snapshot) is REJECTED without touching the SM, leaving `sync`
  /// armed so the timer re-solicits (another peer answers).
  fn on_sync_checkpoint<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: crate::SyncCheckpoint,
  ) {
    // Freshness + relevance: we must be a Normal replica with an outstanding sync whose nonce matches.
    if !self.status.is_normal() {
      return;
    }
    let Some(s) = self.sync else {
      return; // no sync outstanding (already applied / never triggered) — ignore.
    };
    if m.nonce() != s.nonce {
      return; // a reply to a prior solicitation / forged — not fresh.
    }
    // Idempotency under the persist window: while the adopted checkpoint is being made durable a
    // `pending_checkpoint` is staged; a second SyncCheckpoint arriving then must be dropped (we have
    // already chosen a snapshot and are persisting it).
    if self.pending_checkpoint.is_some() {
      return;
    }
    if m.checkpoint_op().get() < s.target.get() {
      return; // does not advance us past what we know the cluster has committed — ignore.
    }
    // The `<= self.op` drop is ONLY for the ordinary trigger: there, an equal/lower checkpoint means a
    // racing tail-apply already covered it (no sync needed). A FORCED sync (M3.5) deliberately targets
    // a checkpoint AT/BELOW our head — we hold a tail above a pruned committed hole — so this guard
    // must NOT drop it; the forced sync MUST apply to subsume the hole. Forced safety is gated instead
    // on `>= self.checkpoint_op` below (advances our own checkpoint) + `apply_sync`'s `>= commit_min`
    // assert (never rewinds the applied frontier — which holds since target `>= N > commit_min`).
    if !s.forced && m.checkpoint_op().get() <= self.op.get() {
      return; // a racing tail-apply already covered the checkpoint — no sync needed (re-assert trigger).
    }
    if m.checkpoint_op().get() <= self.checkpoint_op.get() {
      return; // never regress our own checkpoint (monotone).
    }
    // The load-bearing integrity gate: never restore a snapshot whose bytes do not hash to the
    // advertised id (corrupt / forged / torn). Verified BEFORE any SM mutation. Keep `sync` armed so
    // the solicit timer re-fetches from another peer.
    if crate::checkpoint_id(m.snapshot()) != m.checkpoint_id() {
      return;
    }
    self.apply_sync(now, wal, sb, &m);
  }

  /// Apply a verified `SyncCheckpoint`: restore the SM + sessions, advance the metadata to the synced
  /// point, rebuild the WAL/log for it, and stage the durable re-persist (two superblock writes, reusing
  /// the checkpoint sequence). `sync` stays `Some` until the root write completes (`on_sb_done`), so a
  /// crash mid-persist re-solicits.
  ///
  /// **No committed op the replica already held AHEAD of the sync can be lost.** On the ORDINARY
  /// trigger the synced `checkpoint_op > self.op`, so the replica's entire held log `[..=self.op]` is
  /// at or below the synced point — every op `<= checkpoint_op` is already reflected in the restored
  /// SM. A *committed* op above `self.op` is impossible (committing an op requires having prepared it,
  /// which would put it `<= self.op`); the only thing discarded is a stale/uncommitted tail at or
  /// below the synced checkpoint, which is safe.
  ///
  /// On the M3.5 FORCED path ([`Self::maybe_force_sync`]) the synced `checkpoint_op` may instead be
  /// `<= self.op` (the replica holds a tail ABOVE a pruned committed hole). The held tail
  /// `(checkpoint_op .. self.op]` is then **PRESERVED, not discarded** (safety, VOPR seed 164). Those
  /// ops were already durably APPENDED + ACKED by this replica (it voted for them), so the cluster may
  /// have COMMITTED them off its vote. The old code reset `self.op = checkpoint_op` and truncated the
  /// WAL — destroying this replica's only durable copy of a possibly-committed op while KEEPING its
  /// `log_view`; a later view change then took its `(log_view, op)` as the canonical generation's head
  /// and dropped those committed ops cluster-wide (no donor of that generation held them), which the
  /// adopt-time `op >= commit_min` assert detected as a committed-op rewind. The "re-fetch via
  /// `Prepare`/`Commit`" argument is NOT a safe substitute: a view change can intervene before the
  /// re-fetch and finalize a head below the lost ops. The forced sync's *purpose* is only to recover
  /// the doomed hole(s) `N (<= checkpoint_op)` (subsumed by the restored snapshot) — so we keep
  /// `self.op` and the above-floor log entries, restore the SM/sessions at the snapshot, and re-apply
  /// the retained committed tail from the natural `advance_commit` flow. `commit_min` only moves
  /// FORWARD (`checkpoint_op >= N > N-1 == commit_min`), so no applied op is rewound. The release-active
  /// assert below branches: ordinary ⇒ `checkpoint_op > self.op`; forced ⇒ the true invariant
  /// `checkpoint_op >= commit_min`. Either way it makes a trigger-loosening that violates safety fail
  /// loudly rather than silently drop a committed op (matching `select_canonical_log`'s fail-stop style).
  ///
  /// **Never sync past uncommitted state.** The synced `checkpoint_op` is, by definition, a checkpoint
  /// a peer made durable — a quorum committed+applied through it — and we additionally gate on
  /// `>= sync.target`, itself derived from a committed-cluster message. So we never adopt a snapshot
  /// above the committed frontier.
  fn apply_sync<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: &crate::SyncCheckpoint,
  ) {
    let checkpoint_op = m.checkpoint_op();
    // Release-active safety assert, branched on whether this is a FORCED sync (M3.5). On the ordinary
    // path the synced checkpoint is strictly above our head, so discarding our held log `[..=op]`
    // cannot drop a committed op. On the forced path it may be at/below our head (we hold a tail above
    // a pruned committed hole); the TRUE invariant there is `checkpoint_op >= commit_min` — never
    // rewind the applied frontier — and the trigger structurally guarantees `checkpoint_op >= N > N-1
    // == commit_min`, so the held tail it discards is only uncommitted ops or committed ops the quorum
    // holds and re-announces (see the method doc's case analysis).
    if self.sync.is_some_and(|s| s.forced) {
      assert!(
        checkpoint_op.get() >= self.commit_min.get(),
        "force-sync must not rewind the applied frontier (checkpoint_op {} < commit_min {})",
        checkpoint_op.get(),
        self.commit_min.get()
      );
    } else {
      assert!(
        checkpoint_op.get() > self.op.get(),
        "state-sync must not discard a held op above the synced checkpoint (checkpoint_op {} <= op {})",
        checkpoint_op.get(),
        self.op.get()
      );
    }
    // Decode the verified envelope FIRST (before any state mutation). `on_sync_checkpoint` already
    // verified `checkpoint_id(snapshot) == m.checkpoint_id()`, so the bytes are the right checkpoint;
    // but a malformed/truncated envelope (a buggy encoder, or corruption that somehow preserved the
    // hash) must NOT panic — reject it as a fault and leave `sync` armed so the solicit timer re-fetches
    // from another peer. We have mutated nothing yet, so an early return is clean.
    let Some((bound_op, sessions, sm_tail)) = Self::decode_checkpoint(m.snapshot()) else {
      return;
    };
    // BIND-CHECK (F3, safety): the op hashed INTO the snapshot must equal the advertised `checkpoint_op`
    // we are about to advance `commit_min`/`commit_max`/`op` to. A faulty peer can ship STALE snapshot
    // bytes (whose real frontier is op A) under an OVERSTATED `checkpoint_op = B > A` whose hash still
    // matches the old bytes; without this check we would restore the OLDER SM yet advance the frontier
    // to B — silently dropping the committed ops in `(A, B]`. Reject (no mutation; `sync` stays armed so
    // another peer answers) rather than drop committed state.
    if bound_op != checkpoint_op {
      return;
    }
    // PRESERVE-TAIL (safety, VOPR seed 164): does this sync land BELOW our held head? Only the FORCED
    // path can (the ordinary assert above guarantees `checkpoint_op > self.op`). When it does, the band
    // `(checkpoint_op .. self.op]` is ops we already durably APPENDED + ACKED (we voted for them with
    // `PrepareOk`/`AdoptAck`), so the cluster may have COMMITTED them off our vote. Discarding them
    // (the old `self.op = checkpoint_op` + `wal.truncate(checkpoint_op)` + `log.clear`) destroys our
    // only durable copy of a possibly-committed op while keeping `log_view` — a later view change then
    // takes our `(log_view, op)` as the canonical generation's head and drops those committed ops
    // entirely (the loss the adopt-time `op >= commit_min` assert later trips on). The forced sync's
    // *purpose* is only to recover the pruned holes AT/BELOW the floor (subsumed by the snapshot); the
    // acked tail ABOVE the floor must survive. So keep `self.op` and the above-floor log entries,
    // restore the SM/sessions at the snapshot, and let the recovered committed tail re-apply once the
    // re-persist lands (the next Commit/Prepare drives `advance_commit` over the retained log).
    let held_tail = checkpoint_op.get() < self.op.get();
    // Restore the SM and the client-session table from the decoded envelope.
    self.sm.restore(sm_tail);
    self.clients = sessions;
    // Advance metadata monotonically to the synced point. `commit_min` becomes the synced frontier;
    // `commit_max` keeps the higher learned commit (a held tail we are about to re-apply may already be
    // known-committed). With no held tail, `op == commit_max == commit_min == checkpoint_op` (the
    // post-recover-from-checkpoint shape); with a held tail, `self.op` and `commit_max` stay, so
    // `op >= commit_max >= commit_min == checkpoint_op` still holds.
    self.commit_min = checkpoint_op;
    self.commit_max = OpNumber::with(self.commit_max.get().max(checkpoint_op.get()));
    if !held_tail {
      self.op = checkpoint_op;
      self.commit_max = checkpoint_op;
    }
    // Drop in-memory state the snapshot subsumes. Below the checkpoint everything is folded into the
    // snapshot; ABOVE it we keep the retained tail (held_tail) so a possibly-committed acked op is not
    // lost. Any pending-repair hole AT/BELOW the checkpoint is subsumed (cleared); a hole strictly
    // above it (held_tail only) stays solicited (the recovered tail may still have an interior faulty
    // slot the snapshot does not cover).
    self.log.retain(|&op, _| op > checkpoint_op.get());
    self.inflight.clear();
    self.buffer.clear();
    self.repair.retain(|&op| op > checkpoint_op.get());
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
    }
    self.pending.clear();
    // In-flight WAL appends are abandoned here too; their op numbers must not linger as "in flight"
    // (a stale completion finds no `pending` entry and is ignored) — keep `appending` in lockstep.
    self.appending.clear();
    // Rebuild the durable WAL. Drop any stale slots strictly ABOVE our head (a stale higher generation
    // that would otherwise read back as a wrong head on a later restart) — `truncate(self.op)`, which
    // is a no-op when no tail is held (`self.op == checkpoint_op`) and preserves the retained tail
    // `(checkpoint_op .. op]` otherwise. Then free slots BELOW the checkpoint (superseded by the
    // snapshot). The durable ROOT below names `commit = checkpoint_op`, so a later `recover()` restores
    // the SM at the synced point and re-reads the retained tail from the WAL.
    wal.truncate(self.op);
    wal.prune(checkpoint_op);
    // Stage the durable re-persist, reusing the checkpoint two-write sequence so a crash recovers to
    // the synced point (not the stale one). Step 1: write the snapshot under our own superblock; step
    // 2 (in `on_sb_done`) writes the new VsrState root naming it. `sync` stays armed until step 2
    // completes. (No checkpoint can already be in flight — `on_sync_checkpoint` gates on
    // `pending_checkpoint.is_none()`.)
    let id = self.mint_op_id();
    sb.submit_write_checkpoint(id, checkpoint_op, m.snapshot_bytes());
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op: checkpoint_op,
      checkpoint_id: m.checkpoint_id(),
      step: CheckpointStep::AwaitSnapshot { id },
    });
    // Keep re-soliciting until the persist's root write completes (defends a fault mid-persist).
    self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
  }

  /// Receive a `SyncCheckpoint` while RECOVERING and AWAITING A PEER CHECKPOINT (F1) — the escalation
  /// path for a replica whose OWN durable checkpoint snapshot read back permanently unreadable/
  /// inconsistent ([`Self::retry_recover_checkpoint_read`] exhaustion). It cannot restore its SM from
  /// disk, so it solicited a peer; this verifies and applies the answer, completing recovery.
  ///
  /// Verification (no SM mutation until ALL pass): an outstanding forced `sync` with a matching nonce;
  /// the peer is at least as advanced as our corrupt checkpoint (`checkpoint_op >= self.checkpoint_op`,
  /// so its snapshot subsumes ours and never rewinds the applied frontier — `commit_min ==
  /// checkpoint_op` here); the LOAD-BEARING self-consistency integrity gate `checkpoint_id(snapshot)
  /// == checkpoint_id`; and a clean decode. Any failure REJECTS the message (no panic, no restore) and
  /// leaves us awaiting — the recover-retry timer re-solicits and another peer answers.
  ///
  /// On full success it hands off to the SHARED [`Self::apply_sync`] (restore SM + sessions, advance to
  /// the synced point, durably RE-PERSIST so a re-crash recovers cleanly at the synced point, not the
  /// corrupt one): it abandons local recovery (`recover = None`) and flips to `Normal` FIRST so the
  /// re-persist's superblock completions route through the ordinary `on_sb_done` (which clears the
  /// sync + counts a forced state-sync on the root write), exactly like a Normal state-sync — recovery
  /// is thereby complete the instant the synced checkpoint is durable.
  fn on_recover_sync_checkpoint<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: crate::SyncCheckpoint,
  ) {
    debug_assert!(self.status.is_recovering() && self.awaiting_peer_checkpoint());
    let Some(s) = self.sync else {
      return; // no sync outstanding — ignore (should not happen while awaiting, but be defensive).
    };
    if m.nonce() != s.nonce {
      return; // a reply to a prior solicitation / forged — not fresh.
    }
    if m.checkpoint_op().get() < self.checkpoint_op.get() {
      return; // does not even reach our (corrupt) checkpoint — cannot subsume it; ignore.
    }
    // The load-bearing integrity gate: never restore a snapshot whose bytes do not hash to the
    // advertised id (corrupt / forged / torn). Verified BEFORE any mutation; reject + keep awaiting.
    if crate::checkpoint_id(m.snapshot()) != m.checkpoint_id() {
      return;
    }
    // Decode must succeed before we commit to applying (apply_sync also decodes, but verifying here
    // keeps the irreversible status flip below from ever stranding us Normal with an unrestored SM).
    // The op BOUND into the snapshot (F3) must equal the advertised `checkpoint_op` — a faulty peer
    // shipping stale bytes under an overstated op would otherwise advance our frontier past the
    // snapshot's real content. Verified HERE too (not only in `apply_sync`) so the Normal flip below
    // never strands us with an unrestored SM on a bind mismatch.
    match Self::decode_checkpoint(m.snapshot()) {
      Some((bound_op, _, _)) if bound_op == m.checkpoint_op() => {}
      _ => return, // unparsable, or the bound op disagrees with the advertised op — reject, keep awaiting.
    }
    // Fully verified → abandon local recovery and apply via the shared state-sync core. Flip to Normal
    // FIRST so the re-persist completions route through the ordinary `on_sb_done` (apply_sync leaves
    // `sync` armed until the durable root lands, which then clears it and resumes as a Normal backup).
    self.recover = None;
    self.status = Status::Normal;
    self.apply_sync(now, wal, sb, &m);
  }

  /// If `commit_min` has reached the next checkpoint boundary and no superblock write is pending,
  /// begin a checkpoint: snapshot the SM + client sessions, write the snapshot, and stage step 2.
  ///
  /// Called at the tails of `try_commit` and `advance_commit` — the only two sites that advance
  /// `commit_min`. The snapshot reflects the SM state at `commit_min` exactly (all ops `<= commit_min`
  /// applied, none above), so the checkpoint covers a committed+applied prefix; `target_op = commit_min`
  /// keeps the snapshot↔op correspondence exact even when a batch commit jumps past the boundary.
  fn maybe_checkpoint<B: Superblock>(&mut self, sb: &mut B) {
    // Only checkpoint once the view is settled and durable-consistent: Normal status AND
    // `log_view == view`. `advance_commit` is also called mid-view-change (in
    // `start_view_as_new_primary` / `on_start_view`, applying prior-view committed ops) — there
    // `self.view` is already the NEW view but `log_view` is still the old view and a
    // `submit_durable_view` is imminent; this gate keeps a checkpoint from racing that durable-view
    // write (a checkpoint and a view-change root must never both be in flight on the superblock). A
    // checkpoint due during a transition re-triggers cleanly once Normal resumes — `commit_min` is
    // preserved across the transition. In steady Normal `log_view == view` holds, so this never
    // blocks a legitimate checkpoint.
    if !self.status.is_normal() || self.log_view.get() != self.view.get() {
      return;
    }
    // Exclusion: never start while a durable-view write OR another checkpoint is in flight. (In
    // Normal, `pending_sb` is set only by a deferred view-participation write whose completion will
    // re-enter Normal; `maybe_checkpoint` then re-triggers. This is the no-double-trigger gate.)
    if self.pending_sb.is_some() || self.pending_checkpoint.is_some() {
      return;
    }
    let boundary = self.checkpoint_op.get() + self.config.checkpoint_ops();
    if self.commit_min.get() < boundary {
      return;
    }
    // Checkpoint at `commit_min` (a committed+applied boundary), not at the raw `boundary` op:
    // `commit_min` may have jumped past `boundary` in a batch commit, and the SM has applied through
    // `commit_min` (apply is forward-only) — so the snapshot reflects state through `commit_min`.
    let target_op = self.commit_min;
    let snapshot = self.sm.snapshot();
    // Bind the checkpoint op into the envelope so `checkpoint_id` covers it (F3): the written op and
    // the op hashed inside the snapshot are the SAME, so a later restore can prove they agree.
    let envelope = Self::encode_checkpoint(target_op, &self.clients, &snapshot);
    let checkpoint_id = crate::checkpoint_id(&envelope);
    let id = self.mint_op_id();
    sb.submit_write_checkpoint(id, target_op, envelope);
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op,
      checkpoint_id,
      step: CheckpointStep::AwaitSnapshot { id },
    });
  }

  // M3.2b: physical bounded-WAL slot reuse + stall-before-wrap (the `Wal` exposes a capacity; the
  // primary refuses to assign an op that would overwrite an un-pruned slot below `quorum_checkpoint_op`)
  // is a SEPARATE milestone — see the M3.2b plan. `run_gc` below is the *logical* safety half (the
  // prune floor a bounded-WAL backend would enforce as a physical stall): it tells the WAL what is
  // safe to free, never authorizing a free above what a quorum still needs.
  //
  /// Post-checkpoint garbage collection: free WAL slots + in-memory per-op cache entries the replica
  /// no longer needs, once a checkpoint's durable root has landed (called from `on_sb_done`'s
  /// `AwaitRoot` arm). Run AFTER the root is durable, so the recovery point is the new checkpoint root
  /// — a crash before/after a (possibly lost or failing) prune is safe: `recover()` re-derives the
  /// prunable prefix from the durable root and a later checkpoint re-prunes.
  ///
  /// # The prune floor (THE safety decision)
  ///
  /// An op `N` is freed only when `N <= floor`, and the floor is chosen so that **every freed op is
  /// already captured in this replica's own durable checkpoint snapshot** (`floor <= self.checkpoint_op`
  /// always). Concretely:
  /// - **primary:** `floor = min(self.checkpoint_op, quorum_checkpoint_op())` — never free an op a
  ///   `quorum` has not yet checkpointed, so a peer still in the live tail (below `quorum_checkpoint_op`)
  ///   can be served the op it is missing from THIS primary's WAL (`on_request_prepare` /
  ///   retransmit). Conservative: an unheard peer counts as 0, so a fresh primary frees nothing until
  ///   fresh `PrepareOk`s raise the quorum floor.
  /// - **backup:** `floor = self.checkpoint_op` — a backup collects no `PrepareOk`s, so its
  ///   `quorum_checkpoint_op()` is ~0 (peers default 0); gating a backup on the quorum floor would mean
  ///   it NEVER prunes and its WAL/log grow unbounded (defeating the boundedness deliverable). A backup
  ///   instead prunes below its OWN durable checkpoint — those ops are in its snapshot, so it loses
  ///   nothing locally, and it serves no peer WAL reads that the cluster relies on (the primary +
  ///   another up-to-date backup retain the live tail).
  ///
  /// # Proof no committed op is permanently lost (state-sync is the safety net)
  ///
  /// Take any committed op `N` that a laggard `L` might need, and any replica `R` that freed `N`
  /// (so `N <= R.floor <= R.checkpoint_op` — `N` is in `R`'s snapshot). Two exhaustive cases for `L`:
  ///
  /// 1. **`L` is below the cluster checkpoint** (some caught-up replica's `checkpoint_op > L.op`).
  ///    Then `L`'s state-sync trigger fires on the next `Commit`/`Prepare`/`PrepareOk` it hears
  ///    (`maybe_request_sync`: `incoming.checkpoint_op() > self.op`), and `L` fetches a checkpoint at
  ///    op `>= N` (the snapshot subsumes every op `<= N`). `L` recovers `N` via the snapshot — it never
  ///    needs the freed slot. This is exactly why GC is safe NOW (M3.4a state-sync) but was not before.
  /// 2. **`N` is above every operational replica's checkpoint** (it is in the recent committed tail).
  ///    Then NO replica has freed `N` (freeing requires `N <= checkpoint_op`), so `N` is still held by
  ///    the quorum that committed it, and `L` obtains it by ordinary retransmit (`commit_min+1..=op`)
  ///    or single-op peer fault-repair (`RequestPrepare` → `Prepare`).
  ///
  /// The load-bearing local invariant: **the apply loops never read a freed op.** `commit_op` /
  /// `advance_commit` read `self.log.get(op)` only for `op > commit_min`, and
  /// `commit_min >= checkpoint_op >= floor`, so every applied op is strictly above the floor and was
  /// never freed. Retransmit (`primary_timeouts`, op in `commit_min+1..=op`) is likewise all `> floor`.
  /// The only reads at/below the floor are *peer-serve* paths (`on_request_prepare`), which return
  /// silently on a freed op — and case (1)/(2) above show such a peer always has another route.
  ///
  /// (Formerly-residual strand, now CLOSED by the M3.5 force-state-sync escalation
  /// ([`Self::maybe_force_sync`]): a `Normal` replica holding a PERMANENTLY-faulty hole at `N` *below
  /// its own head but above its own checkpoint*, where every replica that ever held `N` has pruned it
  /// — a correlated multi-replica permanent fault on a single pruned op. Its head `>=` the cluster
  /// checkpoint, so the `> self.op` sync trigger does NOT fire, and no peer can serve the pruned op.
  /// This is reachable under the M3 gate's envelope (GC + permanent disk-faults + partitions). The
  /// escalation detects it via `quorum_checkpoint_op() >= N` (the op is now available ONLY as part of
  /// a checkpoint snapshot, every quorum member pruned the prepare), clears the doomed hole, and forces
  /// a `RequestSync` to the quorum checkpoint (`>= N`) — recovering `N` from the snapshot that subsumes
  /// it. Liveness-only (no committed op is ever lost or rewritten — `N` survives in every checkpoint
  /// snapshot, swapping a `RequestPrepare`-for-a-pruned-op for a satisfiable `RequestSync`). See §2 of
  /// the M3.5 plan and [`Self::maybe_force_sync`]'s safety proof.)
  fn run_gc<W: Wal>(&mut self, wal: &mut W) {
    let floor = if self.is_primary() {
      self
        .checkpoint_op
        .get()
        .min(self.quorum_checkpoint_op().get())
    } else {
      // A backup prunes below its OWN checkpoint (it serves no peer WAL reads the cluster relies on);
      // gating it on the quorum floor would never prune → unbounded WAL/log. See the method doc.
      self.checkpoint_op.get()
    };
    if floor == 0 {
      return; // nothing safe to free yet (no quorum-acknowledged checkpoint / no own checkpoint)
    }
    // `prune(below)` frees slots strictly below `below`; to free ops `<= floor` pass `below = floor+1`.
    wal.prune(OpNumber::with(floor + 1));
    // Trim the in-memory per-op caches to `(floor .. head]`. SAFE: the apply loops read only ops
    // `> commit_min >= checkpoint_op >= floor`, so nothing they touch is removed here; the freed
    // entries are committed+checkpointed (durable in the SM snapshot) and out of every reach path
    // except peer-serve, which has the state-sync/retransmit fallbacks proven above.
    self.log.retain(|&op, _| op > floor);
    self.inflight.retain(|&op, _| op > floor);
    self.buffer.retain(|&op, _| op > floor);
    // `clients` is intentionally NOT trimmed here: it grows per-CLIENT (bounded by the active client
    // set), not per-op, and dropping a LIVE session risks a dedup miss for a retry whose cached reply
    // is still needed. Every session was captured in the checkpoint envelope, so a crash + recover
    // rebuilds them; the unbounded-in-op structures (WAL, log, inflight, buffer) are the ones GC'd.
  }

  /// Persist the durable VSR root for the current `(view, log_view, commit_min)` and arm the
  /// participation deferred until the write completes.
  /// Overwrites any prior `pending_sb` (supersession): an older-view completion is then ignored.
  ///
  /// **Preserves the durable checkpoint pointer.** This write must carry the CURRENT checkpoint
  /// (`self.checkpoint_op` + the durable `checkpoint_id`), NOT zeros — a view-change root that
  /// zeroed `checkpoint_op` would regress the durable checkpoint and, once the WAL below it is GC'd
  /// (M3.2 Task 5), lose committed ops on recovery. The view transitions drop the LOGICAL
  /// `pending_checkpoint`, so `self.checkpoint_op` equals the durable checkpoint op and
  /// `sb.state().checkpoint_id()` is its matching id. (A checkpoint's step-2 root write may still be
  /// PHYSICALLY in flight when a view change issues this durable-view root write; the `Superblock`
  /// serialized root-write ordering contract guarantees this later write is the final durable root,
  /// so the stale checkpoint root cannot win.) `commit_min >= checkpoint_op` always holds, so
  /// `try_new`'s `commit >= checkpoint_op` invariant cannot fail.
  fn submit_durable_view(&mut self, action: PendingSbAction, sb: &mut impl Superblock) {
    let checkpoint_id = sb.state().checkpoint_id();
    let state = crate::VsrState::try_new(
      self.view,
      self.log_view,
      self.commit_min,
      self.checkpoint_op,
      checkpoint_id,
    )
    .expect("durable view: log_view <= view and commit_min >= checkpoint_op");
    let id = self.mint_op_id();
    sb.submit_write(id, state);
    self.pending_sb = Some((id, action));
  }

  fn primary_timeouts<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    // Deferred forfeit (M3.5, safety + liveness): a primary that hit the force-sync strand
    // ([`Self::maybe_force_sync`]) flagged a step-down rather than reset its `op` (which would let it
    // reuse op numbers in this view). Act on it FIRST, on EVERY primary tick while the flag is set —
    // and crucially do NOT clear it one-shot (F2). A one-shot forfeit broadcasts a SINGLE
    // StartViewChange and then resumes heartbeating; if that lone SVC is dropped/partitioned the
    // primary keeps heartbeating, every backup keeps resetting its `primary_idle` (so none starts its
    // own view change), and the SVC retransmit timer is not serviced while Normal — the stuck primary
    // WEDGES the cluster below the unrepairable hole. Instead we keep forfeiting until the view
    // actually changes:
    //   1. RE-PROPOSE the next view each tick — `propose_next_view` is idempotent at `view+1` (it only
    //      resets the SVC collection when raising the target, never escalates to `view+2,+3` while we
    //      stay Normal-primary), so this just RE-BROADCASTS the `StartViewChange{view+1}` under loss.
    //   2. SKIP the commit heartbeat + prepare retransmit below (the early `return`), so backups STOP
    //      hearing this primary; their `primary_idle` fires and they JOIN the SVC for `view+1` → an
    //      SVC quorum forms → the view changes (a caught-up replica leads).
    // The flag is cleared ONLY when this replica LEAVES Normal-primary — the transition handlers
    // (`transition_to_view_change_status` / `adopt_canonical_head` / `catch_up_to_view` /
    // `start_view_as_new_primary`) all clear `pending_forfeit`, so once the view changes the new
    // generation re-evaluates from scratch (no same-view re-forfeit, no cross-view leak).
    if self.pending_forfeit {
      self.forfeit(now, sb);
      return;
    }
    // Bootstrap the heartbeat the first time we're ticked as primary.
    if self.timers.commit.is_none() {
      self.timers.commit = Some(now + COMMIT_HEARTBEAT);
    }
    if self.timers.commit.is_some_and(|d| d <= now) {
      self.outgoing.push_back(Outgoing::new(
        Recipient::Backups,
        Message::Commit(Commit::new(self.view, self.commit_min, self.checkpoint_op)),
      ));
      self.timers.commit = Some(now + COMMIT_HEARTBEAT); // re-arm THIS timer only
    }
    if self.timers.prepare.is_some_and(|d| d <= now) {
      // Retransmit every un-committed prepare, in op order (`commit_min+1 ..= op`). A backup that fell
      // BELOW the primary's `commit_min` is caught up not by this (those ops are `<= commit_min`) but by
      // its OWN tail-gap solicitation ([`Self::request_tail_gap`], driven on every Commit heartbeat),
      // which fetches the missing committed band above its head via `RequestPrepare`.
      let lo = self.commit_min.get() + 1;
      let hi = self.op.get();
      for op in lo..=hi {
        if let Some(entry) = self.log.get(&op).cloned() {
          self.outgoing.push_back(Outgoing::new(
            Recipient::Backups,
            Message::Prepare(Prepare::new(
              self.view,
              OpNumber::with(op),
              self.commit_min,
              self.checkpoint_op,
              entry.client,
              entry.request,
              entry.body,
            )),
          ));
        }
      }
      // re-arm THIS timer only (clear once everything is committed)
      self.timers.prepare = if self.commit_min.get() < self.op.get() {
        Some(now + PREPARE_RETRANSMIT)
      } else {
        None
      };
    }
    // M3.5 T3: a primary that has fallen a full checkpoint interval behind the quorum's durable
    // checkpoint — continuously for the grace window — forfeits primacy (steps down via a view
    // change). Checked each primary tick, AFTER the heartbeat/retransmit above (so an alive primary
    // still heartbeats while it is being given its grace window to catch up).
    self.maybe_forfeit(now, sb);
  }

  /// M3.5 T3 — the forfeit gate. A `Normal` primary that is genuinely STUCK steps down (via a view
  /// change) so a caught-up replica leads, rather than wedge the cluster (clients whose requests sit
  /// above its stalled commit never finish). Two independent stuck-conditions, both grace-timed:
  ///
  /// 1. **Checkpoint lag.** Its own durable `checkpoint_op` lags the quorum's by at least a full
  ///    checkpoint interval (`config.forfeit_checkpoint_lag()`) — it cannot checkpoint because it is
  ///    repairing/syncing while the cluster raced ahead.
  /// 2. **Unfillable committed hole (liveness, VOPR seed 36).** It holds a `repair` hole — a COMMITTED
  ///    op below its head it cannot apply (registered only for `commit_min + 1 <= commit_max`). If that
  ///    op was CHECKPOINTED + PRUNED past on its holders (the residual case of `select_canonical_log`'s
  ///    offset-union: a committed op no canonical donor's LOG carries, so it lives only inside a peer's
  ///    checkpoint snapshot), NO peer can answer the primary's `RequestPrepare` and the only recovery is
  ///    a state-sync of that snapshot — which a PRIMARY must NOT do (force-syncing a primary resets
  ///    `self.op` below its head and reuses op numbers in this view → committed-state divergence; see
  ///    `maybe_force_sync`'s primary guard). Such a primary cannot serve clients (its commit is stuck
  ///    below the hole), cannot fill it, and — holding none of `(commit_min .. op]` — retransmits
  ///    nothing, so backups never ack and never re-trigger any reactive check: it WEDGES the cluster.
  ///    Forfeiting hands the view to a more-caught-up replica (the holder whose checkpoint covers the
  ///    band leads cleanly; it does not re-forfeit), and THIS replica then recovers the band as a
  ///    BACKUP via the ordinary force-sync escalation. The grace timer makes this self-limiting: a
  ///    FILLABLE hole (a peer holds it un-pruned, in or out of the DVC quorum — the case the
  ///    seeding-site B4 path covers) is repaired by the answering `Prepare` well within `FORFEIT_GRACE`,
  ///    emptying `repair` and DISARMING the forfeit; only a hole that persists the WHOLE window — i.e.
  ///    one no peer can serve — actually steps the primary down. No committed op is lost (it survives in
  ///    the holder's checkpoint throughout).
  ///
  /// **Anti-storm (load-bearing).** The grace timer is the key gate: the condition must hold
  /// CONTINUOUSLY for `FORFEIT_GRACE` before the primary actually steps down, so a transient lag /
  /// in-flight repair never triggers a view change. The checkpoint-lag signal is additionally
  /// quorum-gated (`quorum_checkpoint_op()`, the quorum-th order statistic over the monotone per-peer
  /// reports) and bounded at a *full* interval, so a single ahead peer cannot induce a forfeit and a
  /// healthy primary that checkpoints in lock-step never arms it. `saturating_sub` guards the
  /// (defensive) case where the primary's own checkpoint is somehow ahead of the quorum's.
  fn maybe_forfeit<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    // Only ever called from `primary_timeouts` (the Normal-primary tick); a backup behind on
    // checkpoint catches up via state-sync/force-sync and never forfeits.
    debug_assert!(self.status.is_normal() && self.is_primary());
    let lag = self
      .quorum_checkpoint_op()
      .get()
      .saturating_sub(self.checkpoint_op.get());
    // Stuck iff EITHER the checkpoint lags a full interval OR an unfilled committed `repair` hole is
    // outstanding (a committed op `<= commit_max` the apply loop is held below — see the doc). The
    // grace timer disarms a hole that fills in time, so a fillable hole never forfeits.
    let stuck = lag >= self.config.forfeit_checkpoint_lag() || !self.repair.is_empty();
    match (stuck, self.forfeit_armed) {
      // Caught up (or never behind): disarm — a transient lag / in-flight repair does not forfeit.
      (false, _) => self.forfeit_armed = None,
      // Newly stuck: arm the grace timer; do NOT step down yet.
      (true, None) => self.forfeit_armed = Some(now + FORFEIT_GRACE),
      // Stuck for the whole grace window: forfeit.
      (true, Some(deadline)) if deadline <= now => self.forfeit(now, sb),
      // Still within the grace window: wait.
      (true, Some(_)) => {}
    }
  }

  /// Forfeit primacy: step down by PROPOSING the next view (broadcast `StartViewChange`) via the
  /// existing SVC machinery — exactly as a backup's idle timeout does (`on_primary_idle` →
  /// `propose_next_view`). A caught-up replica's SVC quorum then forms and a more-up-to-date primary
  /// takes over.
  ///
  /// It deliberately does **NOT** unilaterally jump the view (`transition_to_view_change_status`):
  /// that would strand this replica alone in `ViewChange` if peers do not follow, wedging the cluster
  /// until idle timers fire. A lone `StartViewChange` cannot inflate the view (a real SVC quorum is
  /// required to transition), so proposing is the safe, established path. The grace + quorum gates in
  /// `maybe_forfeit` (and the force-sync-strand gate in `maybe_force_sync`) ensure this only fires
  /// when genuinely stuck.
  ///
  /// **Persistent until the view changes (F2).** A SINGLE proposed `StartViewChange` can be
  /// dropped/partitioned; were the primary to then resume heartbeating, every backup would keep
  /// resetting its `primary_idle` (never starting its own VC) and the cluster would wedge below the
  /// hole. So forfeiting LATCHES `pending_forfeit`: while set, `primary_timeouts` re-proposes `view+1`
  /// each tick AND stops heartbeating (backups idle-out and join the SVC → quorum → the view changes).
  /// The flag is cleared only when this replica LEAVES Normal-primary (the transition handlers clear
  /// it), so the latch self-resolves exactly when the forfeit succeeds and never leaks across views.
  /// The grace timer is disarmed here (the persistent latch, not the grace timer, now drives retries).
  fn forfeit<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    self.forfeit_armed = None;
    self.pending_forfeit = true;
    self.propose_next_view(now, sb);
  }

  fn on_primary_idle<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    self.propose_next_view(now, sb);
  }

  /// Propose moving to `self.view + 1`: adopt it as the SVC target (if higher than the current
  /// target), set our own bit, broadcast `StartViewChange{target}`, and transition on quorum.
  fn propose_next_view<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    let target = View::with(self.view.get() + 1);
    if target.get() > self.svc_target.get() {
      self.svc_target = target;
      self.svc_from = 0;
    }
    self.join_svc(now);
    self.maybe_start_view_change(now, sb);
  }

  /// Set our own bit for `svc_target` and broadcast a `StartViewChange{svc_target}`.
  fn join_svc(&mut self, now: Instant) {
    self.svc_from |= 1u64 << self.config.replica().get();
    self.push_svc(self.svc_target);
    self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
  }

  /// Broadcast a `StartViewChange` for `view` to the other replicas.
  fn push_svc(&mut self, view: View) {
    self.outgoing.push_back(Outgoing::new(
      Recipient::Backups,
      Message::StartViewChange(crate::StartViewChange::new(view, self.config.replica())),
    ));
  }

  fn view_change_timeouts<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    if self.timers.svc_message.is_some_and(|d| d <= now) {
      self.push_svc(self.svc_target); // re-broadcast the live SVC target (drives escalation under loss)
      self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
    }
    if self.timers.dvc_message.is_some_and(|d| d <= now) {
      self.send_do_view_change(now);
      self.timers.dvc_message = Some(now + VC_MESSAGE_RETRANSMIT);
    }
    if self.timers.get_view_message.is_some_and(|d| d <= now) {
      self.send_get_view(now); // re-sends and re-arms get_view_message
    }
    if self.timers.view_change_status.is_some_and(|d| d <= now) {
      // The change did not complete (the next primary is also down, or our catch-up target is
      // unreachable): become an active SVC-driver for the next view and re-arm timers for that
      // role (clears the now-stale get_view_message; arms svc/dvc/view_change_status).
      self.catching_up = false;
      self.propose_next_view(now, sb);
      self.arm_timers(now);
    }
  }

  /// A Normal backup heard from its primary this view: defer the idle timeout.
  fn note_primary_contact(&mut self, now: Instant) {
    if self.status.is_normal() && !self.is_primary() {
      self.timers.primary_idle = Some(now + PRIMARY_IDLE);
    }
  }

  fn on_start_view_change<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    m: crate::StartViewChange,
  ) {
    let target = m.view();
    if target.get() <= self.view.get() || target.get() > self.view.get() + 1 {
      // stale (≤ our view), OR a jump beyond our immediate next view — do not drive an
      // unverified inflated target from a lone SVC; we catch up to a genuinely-higher view
      // via a real Prepare/Commit from its primary (the higher-view rule), not via SVCs.
      return;
    }
    if m.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    if target.get() > self.svc_target.get() {
      // A higher target is proposed — adopt it, reset collection, and join it.
      self.svc_target = target;
      self.svc_from = 0;
      self.join_svc(now);
    }
    if target.get() == self.svc_target.get() {
      self.svc_from |= 1u64 << m.replica().get();
      self.maybe_start_view_change(now, sb);
    }
  }

  fn maybe_start_view_change<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    if (self.svc_from.count_ones() as usize) >= self.config.quorum_view_change() {
      self.transition_to_view_change_status(now, sb, self.svc_target);
    }
  }

  /// Enter `ViewChange` for `view_new`, reset pipeline + quorums, defer DoViewChange until view is durable.
  ///
  /// STEADY-STATE entry: asserts `view_new > self.view` (a self-driven view change must strictly
  /// advance the view). The recovery path enters via [`Self::enter_view_change_from_recovery`], which
  /// permits `view_new == self.view` (re-driving an in-progress view change after a crash) — it shares
  /// the identical body through `enter_view_change`.
  fn transition_to_view_change_status<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    view_new: View,
  ) {
    assert!(
      view_new.get() > self.view.get(),
      "view change must strictly advance the view"
    );
    self.enter_view_change(now, sb, view_new);
  }

  /// Recovery-only `ViewChange` entry (faithful port of TigerBeetle `replica.zig` open()): a
  /// recovered replica that was Normal as the primary ABDICATES to `view + 1`, and one that crashed
  /// mid-view-change RE-DRIVES `view` (`view_new == self.view`). The steady-state strict-advance
  /// assert ([`Self::transition_to_view_change_status`]) would trip on the re-drive, so this entry
  /// uses a relaxed `view_new >= self.view` (and `> self.view` whenever `log_view == view`, the
  /// abdication case — a Normal primary must move OFF its own view). Everything else (the pipeline /
  /// quorum / pending resets, the deferred durable-view write) is identical via `enter_view_change`.
  fn enter_view_change_from_recovery<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    view_new: View,
  ) {
    debug_assert!(
      view_new.get() >= self.view.get(),
      "recovery view change must not regress the view"
    );
    debug_assert!(
      view_new.get() > self.view.get() || self.log_view.get() < self.view.get(),
      "an abdicating recovered primary (log_view == view) must advance OFF its own view"
    );
    self.enter_view_change(now, sb, view_new);
  }

  /// The shared `ViewChange`-entry body (no view-advance assert — the callers assert their own
  /// contract). Resets the pipeline + quorums and defers the DoViewChange until the new view is durable.
  fn enter_view_change<B: Superblock>(&mut self, now: Instant, sb: &mut B, view_new: View) {
    self.view = view_new;
    self.status = Status::ViewChange;
    self.catching_up = false; // a real, self-driven change (not catch-up)
    self.svc_target = view_new; // collect future escalations above this view
    self.inflight.clear();
    self.buffer.clear();
    // Drop stale per-replica checkpoint reports: the new generation re-establishes the pipeline, so
    // old-view reports must not gate the next primary's GC. A fresh primary rebuilds the map from
    // incoming PrepareOk/Commit, staying conservative (unheard peers count as 0) until then.
    self.peer_checkpoint.clear();
    // Abandon in-flight WAL appends from the old view: their bytes are already durable, but a
    // late completion must not emit a stale-view PrepareOk or vote on a wrong-generation op.
    self.pending.clear();
    // Keep the append-before-ack in-flight set in lockstep with `pending` (R7-F1): clearing it here
    // means a later adopt-append re-marks the op fresh, and the abandoned old completion (now absent
    // from `pending`) does not retract that fresh mark in `on_wal_done`.
    self.appending.clear();
    // Supersede any in-flight checkpoint: a view change drops it (its stale superblock completion is
    // then ignored in on_sb_done). It re-triggers once Normal resumes — commit_min is preserved.
    self.pending_checkpoint = None;
    // Abandon any in-flight state-sync (M3.4a): a view change supersedes it (state-sync and view
    // change are mutually exclusive by status — §2.6). If the sync was mid-persist its
    // `pending_checkpoint` is dropped above; the synced checkpoint is NOT made durable, so the
    // view-change root below names the prior durable `checkpoint_op` (the Superblock serialized
    // root-write ordering makes that the winning root). The in-memory SM may already reflect the
    // synced point (apply_sync restored it) with `commit_min == op == synced_op`, which is internally
    // consistent; a later crash recovers either clean (empty WAL) or via RecoveringHead (pruned tail
    // → re-fetch the canonical head from a peer) — both safe, no committed op lost cluster-wide. The
    // replica re-triggers state-sync from Normal if it is still behind.
    self.sync = None;
    self.timers.sync_solicit = None;
    // A view change ends this primary generation: clear any forfeit grace timer (M3.5 T3) AND any
    // deferred-forfeit flag (the safety step-down — see `maybe_force_sync`). The new generation
    // re-evaluates from scratch once it resumes Normal as primary, so neither a stale grace deadline
    // nor a stale pending-forfeit must carry across (no same-view re-forfeit / cross-view leak).
    self.forfeit_armed = None;
    self.pending_forfeit = false;
    self.svc_from = 0;
    self.dvc_from.clear();
    self.dvc_quorum = false;
    self.arm_timers(now);
    // DVC deferred to on_sb_done: persist the new view before voting in it.
    self.submit_durable_view(PendingSbAction::SendDoViewChange, sb);
  }

  /// Send our full log + position to the prospective primary of the current view.
  fn send_do_view_change(&mut self, _now: Instant) {
    let primary = self.config.primary(self.view);
    self.outgoing.push_back(Outgoing::new(
      Recipient::To(Peer::Replica(primary)),
      Message::DoViewChange(crate::DoViewChange::new(
        self.view,
        self.log_view,
        self.op,
        self.commit_min,
        self.config.replica(),
        self.log_entries(),
      )),
    ));
  }

  /// The in-memory log as wire entries — the OFFSET tail `(checkpoint_op .. op]` for a
  /// recover-from-checkpoint / state-synced replica (the committed prefix `[1..=checkpoint_op]` lives
  /// in the SM snapshot, not the cache), or dense `[1..=op]` for a replica that never checkpointed.
  /// `select_canonical_log` is offset-aware (B3) and UNIONs these across DVCs, so a DVC carrying only
  /// the offset tail loses no committed op at view change.
  fn log_entries(&self) -> std::vec::Vec<crate::PreparedEntry> {
    self
      .log
      .iter()
      .map(|(&op, e)| {
        crate::PreparedEntry::new(OpNumber::with(op), e.client, e.request, e.body.clone())
      })
      .collect()
  }

  fn on_do_view_change<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: crate::DoViewChange,
  ) {
    // NOTE (deferred to M3 message-hardening): we do not yet validate incoming DVC well-formedness
    // (commit <= op; the log is the OFFSET tail `(checkpoint .. op]`, dense WITHIN that range — it is
    // NOT required to be dense from op 1, since a recover-from-checkpoint / state-synced sender
    // legitimately omits the prefix that lives in its SM snapshot). Safe under honest crash-stop
    // peers; matters once untrusted/real-driver inputs land. The cross-DVC commit* <= op_head
    // invariant is enforced (fail-stop) in `select_canonical_log`.
    if m.view() != self.view
      || !self.config.is_primary(self.view)
      || !self.status.is_view_change()
      || self.dvc_quorum
    {
      return;
    }
    if m.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    // Ensure our own DVC is represented (keyed by replica → a self-addressed DVC is idempotent).
    // Compute the own-DVC into a local FIRST to avoid a self borrow conflict, then insert.
    let own = self.config.replica().get();
    if !self.dvc_from.contains_key(&own) {
      let own_dvc = crate::DoViewChange::new(
        self.view,
        self.log_view,
        self.op,
        self.commit_min,
        self.config.replica(),
        self.log_entries(),
      );
      self.dvc_from.insert(own, own_dvc);
    }
    // Keep the most-advanced DVC per replica.
    let replace = self
      .dvc_from
      .get(&m.replica().get())
      .map(|cur| (m.log_view().get(), m.op().get()) > (cur.log_view().get(), cur.op().get()))
      .unwrap_or(true);
    if replace {
      self.dvc_from.insert(m.replica().get(), m);
    }
    if self.dvc_from.len() >= self.config.quorum_view_change() {
      self.start_view_as_new_primary(now, wal, sb);
    }
  }

  /// VSR canonical-log selection + nack-prepare truncation — **offset-aware** (B3).
  ///
  /// Returns `(canonical log truncated to op_head, op_head, commit*)`:
  /// - the canonical generation is the DVCs with the greatest `log_view`;
  /// - `op_head` is that generation's head, less any provably-uncommitted tail truncated by a
  ///   `quorum_nack_prepare` of nacks (contiguous ⟹ replica `r` nacks op `X` iff `r.op < X`);
  /// - `commit*` is the greatest commit across all DVCs (commit never rewinds);
  /// - the canonical log is the **UNION** of the canonical generation's entries up to `op_head` —
  ///   each op is sourced from ANY canonical-generation DVC that holds it — NOT a copy of one DVC's
  ///   `log_slice()`.
  ///
  /// **Why the union (the B3 safety fix).** Since M3.2a+ a DVC log is the *offset tail*
  /// `(checkpoint_op .. op]` — a recover-from-checkpoint or state-synced donor holds only ops above
  /// its own checkpoint (the prefix `[1..=checkpoint_op]` lives in its SM snapshot). Two
  /// canonical-generation donors can therefore have DIFFERENT floors: e.g. r0 (checkpoint 4) holds
  /// `5..=10`, r1 (checkpoint 8) holds `9,10`, both head 10 commit 8. The old code copied ONE DVC's
  /// `log_slice()` via `max_by_key(op)` (ties → highest replica id), which would pick r1's `[9,10]`
  /// and **silently drop committed ops 5,6,7 that only r0 holds** — the `commit* <= op_head`
  /// fail-stop does not catch it (the dropped ops are interior). Unioning takes ops 5,6,7 from r0,
  /// so no committed op held by any canonical donor is dropped.
  ///
  /// **The present-set is the log entries themselves (no separate bitset).** An op IS present in a
  /// DVC iff a `PreparedEntry` for it is in that DVC's `log_slice()`. The `Recovering` loop drops a
  /// faulty/absent op from the in-memory `log` cache rather than caching an empty body, so
  /// `log_entries()` (and hence every DVC's `log_slice()`) already omits faulty ops: absence from a
  /// slice means "this donor cannot supply this op" — whether because it is below the donor's
  /// checkpoint floor (fine; it is in the donor's snapshot) or because the slot read back faulty
  /// (then another donor supplies it, or peer-repair does). An explicit `u64` present-bitset would be
  /// redundant with the slice AND would cap the band at 64 ops, which the offset tail (arbitrarily
  /// many ops above a checkpoint) can exceed; the slice has no such cap.
  ///
  /// **Coverage / no-committed-op-dropped proof.** Let `floor_d = (min op in d.log) - 1` (or `d.op`
  /// if d's log is empty) be donor `d`'s present-floor, and `min_floor` the minimum over the
  /// canonical generation. The committed band the canonical log must cover for the worst (lowest-
  /// floor) adopter is `(min_floor .. commit*]`. For each such op the union includes it iff SOME
  /// canonical donor holds it. By quorum intersection a committed op was held by some current-DVC
  /// sender, and the lowest-floor canonical donor `L` (with `floor_L == min_floor`) covers
  /// `(min_floor .. op_L]`. If `op_L >= commit*`, `L` alone covers the whole band. In the residual
  /// case where a committed op in `(min_floor .. commit*]` is held by NO canonical donor (the donor
  /// that committed+checkpointed it past, plus a low-floor donor that lagged the tail), the union
  /// omits it — but this is **never a silent loss**: the adopter's `advance_commit` HOLDS the commit
  /// at the missing op and `request_repair`s it from a peer (the B4 `RequestPrepare` → `Prepare`
  /// safety net, mirroring TigerBeetle's `repair_prepares_between`). The adopt path is fixed to NOT
  /// destroy a held copy and NOT clear that repair request (see `adopt_log` / `adopt_canonical_head`).
  /// So the SAFETY property — no committed op is ever dropped — holds: a committed op is present in
  /// the union when any canonical donor holds it, and otherwise is repaired (commit blocks until
  /// then), never skipped.
  ///
  /// Run by the prospective primary once it holds `>= quorum_view_change` DoViewChange messages.
  /// NOTE: with exactly `quorum_view_change` DVCs the truncation loop provably never fires in the
  /// contiguous model (the head-holder is one of them); truncation activates only with a larger
  /// collected set. See the `no_truncation_at_minimal_quorum` test.
  fn select_canonical_log(&self) -> (std::vec::Vec<crate::PreparedEntry>, u64, u64) {
    let dvcs: std::vec::Vec<&crate::DoViewChange> = self.dvc_from.values().collect();
    debug_assert!(!dvcs.is_empty(), "selection requires at least one DVC");

    let log_view_star = dvcs.iter().map(|d| d.log_view().get()).max().unwrap_or(0);
    let canonical: std::vec::Vec<&crate::DoViewChange> = dvcs
      .iter()
      .copied()
      .filter(|d| d.log_view().get() == log_view_star)
      .collect();

    // `op_head` is the canonical generation's head, but BOUNDED to the ACTUALLY-represented log (F4):
    // a malformed DVC may CLAIM `op` far above (up to `u64::MAX`) the entries it carries, which —
    // taken at face value — would (a) spin the nack-scan below `commit* ..= op_head` for billions of
    // iterations and (b) overflow `op += 1` at `u64::MAX`. We cap the claimed head at the max op
    // actually PRESENT across the canonical donors' `log_slice()` entries, never below `commit*` (a
    // committed op must survive for the fail-stop check + the `advance_commit` repair path). For an
    // HONEST DVC the head op is always present in its slice, so `max_present_op == claimed head` and
    // this is a no-op — the legitimate (in-range) case is unchanged; only a phantom claimed head
    // (above both the entries and `commit*`) is clipped to the represented range.
    let claimed_op_head = canonical.iter().map(|d| d.op().get()).max().unwrap_or(0);
    let max_present_op = canonical
      .iter()
      .flat_map(|d| d.log_slice())
      .map(|e| e.op().get())
      .max()
      .unwrap_or(0);
    let commit_star = dvcs.iter().map(|d| d.commit().get()).max().unwrap_or(0);
    let mut op_head = claimed_op_head.min(max_present_op.max(commit_star));
    // Fail-stop (in ALL builds): if a committed op exceeds the canonical generation's head, the
    // cross-DVC VSR view-change invariant is broken — panicking is strictly safer than silently
    // dropping the committed op (which a release build's `advance_commit` cap would otherwise do).
    // (Unchanged for honest inputs: there `op_head == claimed head` and this is the original check.)
    assert!(
      commit_star <= op_head,
      "VSR safety invariant violated: commit* ({commit_star}) > op_head ({op_head}) — a committed op \
       is above the canonical log head; refusing to silently drop it"
    );

    // Truncate the uncommitted tail at the first op with a nack quorum. Nacks are monotonic in op
    // (`nacks(op) = |{d : d.op() < op}|` is non-decreasing), so the original code scanned
    // `commit*+1 ..= op_head` one op at a time for the first crossing. That per-op scan is unbounded
    // when `op_head` is large; the count only CHANGES at a donor's `d.op()+1`, so we compute the
    // crossing DIRECTLY from the sorted donor ops — bounded by the DVC count, never the op range, and
    // overflow-free (saturating). This acts on the UNCOMMITTED tail `(commit* .. op_head]` only — a
    // committed op is never truncated — and yields the IDENTICAL truncation point as the per-op scan.
    let threshold = self.config.quorum_nack_prepare();
    let mut donor_ops: std::vec::Vec<u64> = dvcs.iter().map(|d| d.op().get()).collect();
    donor_ops.sort_unstable();
    if threshold >= 1 && threshold <= donor_ops.len() {
      // `nacks(op) >= threshold` first holds at `op = donor_ops[threshold-1] + 1` (the threshold-th
      // smallest donor op, plus one); the first such op within `[commit*+1, op_head]` truncates to
      // `op - 1`. Clamp the crossing to the scan's lower bound (mirrors the loop starting at
      // `commit*+1`), then truncate iff it lands at/below the current head.
      let first_nack_op = donor_ops[threshold - 1].saturating_add(1);
      let cross = first_nack_op.max(commit_star.saturating_add(1));
      if cross <= op_head {
        op_head = cross.saturating_sub(1);
      }
    }

    // Build the canonical log by UNIONING the canonical generation's entries up to op_head: for each
    // op, take its `PreparedEntry` from any canonical donor that holds it. A committed op present in a
    // low-floor donor's offset log but absent from a higher-floor donor is therefore STILL included.
    // The BTreeMap keys by op so the result is ordered+gapless-where-present; `or_insert_with` keeps
    // the FIRST canonical donor's copy of each op. The donor choice is immaterial: every donor of the
    // canonical generation agrees on a committed op's content (same prior-view prepare), and an
    // uncommitted tail op `(commit* .. op_head]` is identical across the canonical generation too (it
    // is the same prepared op — the canonical `op_head` holder's value).
    let mut merged: BTreeMap<u64, crate::PreparedEntry> = BTreeMap::new();
    for d in &canonical {
      for entry in d.log_slice() {
        if entry.op().get() <= op_head {
          merged
            .entry(entry.op().get())
            .or_insert_with(|| entry.clone());
        }
      }
    }
    let log: std::vec::Vec<crate::PreparedEntry> = merged.into_values().collect();
    (log, op_head, commit_star)
  }

  /// Adopt the canonical log from the DVC quorum and become the active primary.
  /// Canonical-log selection + nack-prepare truncation are now performed via
  /// `select_canonical_log`. Participation (StartView broadcast + try_commit) is deferred to
  /// `start_view_participate` via `on_sb_done`, once the new view is durable.
  fn start_view_as_new_primary<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
  ) {
    // A checkpoint is never logically armed when forming a new primary's view: `maybe_checkpoint`
    // is gated on Normal status, and entering ViewChange dropped `pending_checkpoint`. (A physically
    // in-flight checkpoint root write is handled by the Superblock serialized root-write ordering
    // contract — see `submit_durable_view`.)
    debug_assert!(
      self.pending_checkpoint.is_none(),
      "no checkpoint may be logically in flight when forming a new primary's view"
    );
    // Offset-aware canonical-log selection (UNION) + nack-prepare truncation (see
    // `select_canonical_log`). The canonical log is the offset tail `(min_floor .. op_head]`, NOT
    // necessarily dense `[1..=op_head]`.
    let (canonical_log, op_head, commit_star) = self.select_canonical_log();
    self.adopt_log(&canonical_log);
    self.op = OpNumber::with(op_head);
    // Retire any pending-repair holes the adopted canonical log NOW supplies; leave the rest (a
    // committed op held by no canonical donor) for `advance_commit` below to re-`request_repair` from
    // a peer. We must NOT blanket-clear `repair` here: a committed op the union could not carry is a
    // real hole that must stay solicited, not be silently forgotten.
    let supplied: std::collections::BTreeSet<u64> =
      canonical_log.iter().map(|e| e.op().get()).collect();
    self.repair.retain(|op| !supplied.contains(op));
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
    }
    // status is still ViewChange here, so the maybe_checkpoint at advance_commit's tail is a no-op
    // (checkpoints only start in Normal) — a checkpoint must not race the StartViewAsPrimary
    // durable-view write submitted below.
    self.advance_commit(now, sb, commit_star); // apply newly-exposed committed ops (prior-view quorum decision)

    // codex R7-F2: truncate the uncommitted suffix at the FIRST interior gap above commit*. The
    // adopted canonical log is the offset-union `(min_floor .. op_head]` and may still have an interior
    // hole the union could not fill (e.g. this replica recovered a faulty/torn interior slot and dropped
    // it from the cache, and no canonical donor supplies it). The inflight-seeding loop below would
    // register an `inflight` entry for EVERY op in `(commit_min, op]` but `adopt_append` only re-appends
    // ops PRESENT in `self.log`, so a gap op would get NO vote and `try_commit` (strictly in order) would
    // wedge there FOREVER — and no peer can supply it (see the safety argument below). So drop the head
    // back below the first such gap before seeding.
    //
    // SAFETY (the gap above commit* is provably UNCOMMITTED). A committed op is held by a quorum, and the
    // current DVC set is a quorum, so by quorum intersection SOME DVC sender holds every committed op;
    // `select_canonical_log`'s offset-UNION therefore includes every committed op held by ANY canonical
    // donor. An op `G > commit*` that is ABSENT from the union is held by no canonical donor, hence was
    // never committed — and the whole suffix above `G` is uncommitted too (a committed op above an
    // uncommitted one would violate the commit prefix). Truncating it is thus safe: it mirrors
    // `select_canonical_log`'s nack-truncation of the uncommitted tail, but catches an INTERIOR gap the
    // contiguous nack-scan steps over. A gap AT or BELOW `commit*` is a COMMITTED op (a real B4 repair
    // hole the union could not carry) — it is NOT truncated here; `advance_commit` above already HELD the
    // commit at it and `request_repair`d it from a peer (the seeding loop then only spans the gap-free
    // committed-or-truncated head). The subsequent `start_view_participate` broadcasts the now-dense
    // `self.log_entries()`, so backups adopt a gap-free log too.
    if let Some(gap) = ((commit_star + 1)..=self.op.get()).find(|op| !self.log.contains_key(op)) {
      self.op = OpNumber::with(gap - 1);
      self.log.retain(|&op, _| op <= self.op.get());
      // Retire any repair holes now stranded above the truncated head (mirrors the `repair.retain`
      // cleanup above): an uncommitted op above the head is not solicited.
      self.repair.retain(|&op| op <= self.op.get());
      if self.repair.is_empty() {
        self.timers.repair_retry = None;
      }
    }

    // Backfill the client-session request high-water from the adopted in-memory log tail. This is a
    // fallback that only covers the ops still cached in `self.log` (the offset tail `(floor .. op]`).
    // The AUTHORITATIVE source of the dedup watermark is now apply-time tracking in `advance_commit`
    // (and `on_request`/`commit_op` on the primary) plus the checkpoint snapshot restored on
    // recover/state-sync — those survive M3.4b GC, whereas this loop does NOT (GC prunes `self.log`
    // below the checkpoint, so for a backup whose log is empty this loop finds nothing). Keeping it is
    // harmless (it can only RAISE the watermark for ops the new primary still holds) and guards the
    // edge where a session row was somehow not yet recorded. Without the apply-time tracking, a
    // backup-turned-primary with a GC'd log would carry `session.request == 0` and wedge every client
    // on `on_request`'s gap check — the M3.4b boundedness/offset-view-change hang this fixed.
    //
    // NOTE (deferred to the message-loss fault-sweep milestone): we still do NOT reconstruct the
    // cached *reply* body, so a client whose prior-view reply was LOST relies on the in-flight op
    // re-committing; the lost-reply resend is liveness under loss, owned by the later milestone.
    for op in 1..=self.op.get() {
      let Some((client, request)) = self.log.get(&op).map(|e| (e.client.get(), e.request)) else {
        continue;
      };
      let session = self.clients.entry(client).or_default();
      if request.get() > session.request.get() {
        session.request = request;
      }
    }

    // log_view = view BEFORE submit_durable_view (try_new requires log_view <= view).
    self.log_view = self.view;
    self.status = Status::Normal;
    self.dvc_quorum = true;
    // Becoming primary FRESH: a deferred-forfeit flag (the M3.5 safety step-down) from a prior
    // generation must not carry in (it was cleared on entering ViewChange, but clear it defensively
    // here so a fresh primary never starts already-flagged to abdicate).
    self.pending_forfeit = false;

    // Rebuild the pipeline for the uncommitted tail `(commit_min, op]`. codex R6-F1: the new primary
    // must NOT count its own vote for an op it adopted from a peer's DVC and holds ONLY in memory —
    // that would let it commit (and on crash+recover lose) an op it never durably appended. So seed
    // each inflight entry with `oks: 0` and durably (re-)append the adopted op tagged `AdoptVote`; the
    // own vote is set in `on_wal_done` ONLY once that append lands (append-before-ack — the same
    // discipline `on_request`/`on_prepare` use). `try_commit` (deferred to `start_view_participate`
    // after the durable-view write) then counts only votes whose appends are durable. Committed ops
    // `<= commit_star` are NOT re-appended: the cluster already guarantees them; only the voted-on
    // uncommitted tail must be re-driven through the WAL.
    self.inflight.clear();
    for op in (self.commit_min.get() + 1)..=self.op.get() {
      self.inflight.insert(
        op,
        Inflight {
          oks: 0, // own vote set in on_wal_done when the AdoptVote append is durable
          committed: false,
        },
      );
      self.adopt_append(wal, op, Pending::AdoptVote(OpNumber::with(op)));
    }

    // Defer participation (StartView broadcast + arm_timers + try_commit) to on_sb_done. The own votes
    // accrue independently as the AdoptVote appends complete; a StartView/own-vote never outruns its
    // WAL append (for replica_count > 1 the lone own vote is below quorum, and backups only ack after
    // this StartView, so no adopted op can commit before BOTH its append and the durable-view land).
    self.submit_durable_view(PendingSbAction::StartViewAsPrimary, sb);
  }

  /// Runs once the new-primary superblock write is durable: broadcast StartView + begin committing.
  fn start_view_participate<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    // Broadcast the canonical log to all backups.
    self.outgoing.push_back(Outgoing::new(
      Recipient::Backups,
      Message::StartView(crate::StartView::new(
        self.view,
        self.op,
        self.commit_min,
        self.config.replica(),
        self.log_entries(),
      )),
    ));

    self.arm_timers(now);
    self.try_commit(now, sb);
  }

  /// Adopt the canonical (`entries`) log for a view whose committed frontier is `commit`.
  ///
  /// The canonical log is now built by UNIONING the canonical generation (see
  /// `select_canonical_log`) and is the offset tail `(min_floor .. op_head]` — it is NOT necessarily
  /// dense `[1..=op]`, and it may even OMIT a committed op held by NO canonical donor. So adoption
  /// must be **defensive**: it preserves any *committed* op the adopter already holds (in
  /// `(.. =commit]`) that `entries` does not supply, rather than blindly clearing the log and
  /// destroying the adopter's own durable copy of a committed op. Held *uncommitted* ops (above
  /// `commit`) are governed solely by the canonical tail (a nack-truncated / lower-generation tail
  /// must not be resurrected from a stale local copy), so they are dropped; the canonical entries
  /// then overwrite/insert authoritatively. A committed op that neither side supplies is left for
  /// `advance_commit` to `request_repair` from a peer (it is never silently skipped).
  fn adopt_log(&mut self, entries: &[crate::PreparedEntry]) {
    let supplied: std::collections::BTreeSet<u64> = entries.iter().map(|e| e.op().get()).collect();
    // Preserve ONLY the adopter's APPLIED prefix (`op <= self.commit_min`) that the canonical log
    // omits — those are committed ops the adopter has itself applied, so by VSR committed-op survival
    // they are immutable and canonical-by-construction (no other view committed a different value
    // there). Everything ABOVE the applied frontier is dropped so the canonical entries below are
    // authoritative; the caller's `advance_commit(adopted_commit)` then reconstructs `(commit_min ..
    // adopted_commit]` from the freshly-inserted canonical entries, falling to repair for any omission:
    //
    //   * an UNCOMMITTED tail op — superseded by the canonical tail;
    //   * an op the canonical log itself SUPPLIES — re-inserted authoritatively below;
    //   * a committed op in the UNAPPLIED band `(commit_min .. adopted_commit]` the canonical log omits —
    //     this is the SAFETY fix (VOPR seed 24). The adopter holds a body it has NOT applied, which can
    //     be a STALE uncommitted proposal from an earlier view a later view overwrote with a different
    //     committed value (`LogEntry` carries no per-entry view, so a canonical-lineage held op is
    //     indistinguishable from a superseded one). Preserving it would diverge the committed log.
    //     Dropping it turns the slot into a hole; the caller's `advance_commit` then HOLDS the commit
    //     there and `request_repair`s the CANONICAL value from a committed-vouching peer (force-sync if
    //     the band was GC'd cluster-wide). No committed op is lost — it is fetched, never trusted local.
    //
    // This reads `self.commit_min` AT ADOPT TIME, BEFORE the caller advances the commit, so the
    // predicate uses the OLD (pre-adoption) applied frontier — both callers (`adopt_canonical_head`,
    // `start_view_as_new_primary`) run `adopt_log` strictly before their `advance_commit`.
    let applied_floor = self.commit_min.get();
    self
      .log
      .retain(|&op, _| op <= applied_floor && !supplied.contains(&op));
    for e in entries {
      self.log.insert(
        e.op().get(),
        LogEntry {
          client: e.client(),
          request: e.request(),
          body: e.body_bytes(),
        },
      );
    }
  }

  fn on_start_view<B: Superblock>(&mut self, now: Instant, sb: &mut B, m: crate::StartView) {
    // Adopt only a strictly newer view, or the current view while we have not yet returned to Normal
    // in it. Re-applying a StartView for a view we are already Normal in would rewind `op` and
    // clobber locally-appended ops. A RecoveringHead replica is NOT Normal, so a same-view StartView
    // is (correctly) adopted: it is exactly how such a replica re-establishes its faulty head.
    if m.view().get() < self.view.get()
      || (m.view().get() == self.view.get() && self.status.is_normal())
    {
      return;
    }
    if m.replica() != self.config.primary(m.view()) {
      return; // must come from the view's primary
    }
    self.adopt_canonical_head(now, sb, m.view(), m.op(), m.commit(), m.log_slice());
  }

  /// Adopt an authoritative primary's canonical head + log for `view` and return to `Normal`.
  ///
  /// Shared by [`on_start_view`](Self::on_start_view) and
  /// [`on_recovery_response`](Self::on_recovery_response): both learn the canonical head from the
  /// view's primary (a `StartView` carries it directly; a primary's `RecoveryResponse` is the
  /// recovery-handshake equivalent). Callers MUST have already verified the message is from
  /// `config.primary(view)` and is not stale (`view >= self.view`, and not a same-view re-adoption
  /// while already Normal).
  ///
  /// **No committed op is lost, and none is trusted from a possibly-stale local copy.** A
  /// `RecoveringHead` replica has already restored its durable checkpoint prefix `[1..=checkpoint_op]`
  /// into the SM during `Recovering` (so `commit_min == checkpoint_op`); the `op >= commit_min` assert
  /// below rejects any head that would rewind below that durable prefix. The adopted log is the offset
  /// tail `(min_floor .. op]` from the canonical primary (NOT necessarily dense `[1..=op]` — the
  /// primary may itself be a recover-from-checkpoint / state-synced replica whose log starts above op
  /// 1). `adopt_log` therefore preserves ONLY the adopter's APPLIED prefix (`op <= commit_min`) that
  /// the incoming offset log omits — a committed op the adopter itself applied is immutable
  /// (committed-op survival), so its local copy is canonical. A committed op in the UNAPPLIED band
  /// `(commit_min .. commit]` that the offset log omits is NOT preserved: the held body is unapplied
  /// and may be a stale superseded proposal (VOPR seed 24), so `adopt_log` drops it and `advance_commit`
  /// below HOLDS the commit at it and `request_repair`s the CANONICAL value from a committed-vouching
  /// peer (the existing force-sync path takes over if it was GC'd cluster-wide). The checkpointed
  /// prefix lives in the SM, the committed tail in the (applied-preserved + adopted + repaired) log —
  /// the committed prefix is reconstructed end to end, with peer-repair as the backstop for any omitted
  /// committed op the adopter has not applied (never silently skipped, never filled from a stale local).
  fn adopt_canonical_head<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    view: View,
    op: OpNumber,
    commit: OpNumber,
    log: &[crate::PreparedEntry],
  ) {
    assert!(
      commit.get() <= op.get(),
      "canonical head commit must not exceed its op (malformed primary)"
    );
    assert!(
      op.get() >= self.commit_min.get(),
      "must not rewind below our committed op"
    );
    self.view = view;
    self.adopt_log(log);
    self.op = op;
    // Retire any pending-repair holes the adopted canonical log NOW supplies (or that the adopter's
    // own APPLIED-prefix copy now covers, since `adopt_log` kept committed held ops `op <= commit_min`).
    // Holes the canonical log omits AND the adopter does not hold remain solicited; `advance_commit`
    // below re-requests them — INCLUDING the unapplied committed band `adopt_log` just dropped. This
    // MUST happen before `advance_commit` (which may add new holes) so we never wipe a freshly-requested
    // committed-op repair.
    let now_held: std::collections::BTreeSet<u64> = self.log.keys().copied().collect();
    self.repair.retain(|op| !now_held.contains(op));
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
    }
    // status is still ViewChange/RecoveringHead here, so the maybe_checkpoint at advance_commit's
    // tail is a no-op (checkpoints only start in Normal) — a checkpoint must not race the
    // AdoptedStartView durable-view write submitted below.
    self.advance_commit(now, sb, commit.get());
    // log_view = view BEFORE submit_durable_view (try_new requires log_view <= view).
    self.log_view = view;
    self.status = Status::Normal;
    self.catching_up = false;
    self.svc_from = 0;
    self.dvc_from.clear();
    // Adoption re-established a trustworthy head, so the recovery bookkeeping is retired: a
    // RecoveringHead replica that reaches here via this path leaves `recover` = None (the field is
    // structurally None in every non-recovering status). A non-recovering adopter already has None.
    self.recover = None;
    // (The pending-repair set was reconciled above — holes the adopted log / applied-prefix held copies
    // now cover were retired; any committed op neither side carries — including the unapplied band
    // `adopt_log` dropped — stays solicited and was re-requested by `advance_commit`. We deliberately do
    // NOT blanket-clear `repair` here: that was the B3 stranding bug — clearing right after
    // `advance_commit` requested a hole silently forgot a committed op.)
    // Abandon in-flight WAL appends from the old view (see transition_to_view_change_status).
    self.pending.clear();
    self.appending.clear(); // keep the R7-F1 in-flight set in lockstep with `pending`
    // Drop stale per-replica checkpoint reports from the old generation (see
    // transition_to_view_change_status); a backup-turned-... primary rebuilds from fresh PrepareOk.
    self.peer_checkpoint.clear();
    // Supersede any in-flight checkpoint from the old view (its stale superblock completion is then
    // ignored). The view-change root below preserves the durable checkpoint_op via submit_durable_view.
    self.pending_checkpoint = None;
    // Abandon any in-flight state-sync: adopting an authoritative canonical head supersedes it (the
    // adopted canonical log + the adopter's preserved APPLIED prefix supply the committed prefix, with
    // peer-repair as the backstop for the omitted unapplied committed band). See the note in
    // `transition_to_view_change_status` on the mid-persist case (safe; re-syncs from Normal if still behind).
    self.sync = None;
    self.timers.sync_solicit = None;
    // Adopting a canonical head starts a fresh generation in `view`: clear any forfeit grace timer
    // (M3.5 T3) AND any deferred-forfeit flag (the safety step-down — see `maybe_force_sync`) so
    // neither a stale deadline nor a stale pending-forfeit carries into this view (re-evaluated fresh).
    self.forfeit_armed = None;
    self.pending_forfeit = false;
    self.dvc_quorum = false;
    self.arm_timers(now);
    // Defer held-op re-acks to on_sb_done → `start_view_acks`: persist the new view first, and there
    // WAL-(re-)append each adopted uncommitted-tail op before its PrepareOk (codex R6-F1). The adopted
    // entries are in-memory only until then; the deferred ack gates on both the view write (here) and
    // the per-op append (in `start_view_acks`) completing, so no PrepareOk precedes either.
    self.submit_durable_view(PendingSbAction::AdoptedStartView, sb);
  }

  /// Runs once the adopted-StartView superblock write is durable: re-ack held uncommitted ops — but
  /// only AFTER each is durably (re-)appended to the WAL (codex R6-F1, append-before-ack).
  ///
  /// The adopted canonical entries lived only in the in-memory `self.log` (a `StartView` /
  /// `RecoveryResponse` installs them without a WAL write). Sending a `PrepareOk` for one before it is
  /// durable would let this backup vote for an op it could lose on crash+recover. So for each held
  /// uncommitted-tail op we `adopt_append` it (tagged `Pending::AdoptAck`) and DEFER the `PrepareOk`
  /// to `on_wal_done`, which sends it when that append lands. Running here — strictly after the
  /// durable-view write completed — also satisfies durable-view-before-participate: by the time any
  /// AdoptAck append completes the new view is already persisted, so the `PrepareOk` never precedes
  /// EITHER its WAL append or the view write (no cross-view vote, no memory-only vote). A tail op the
  /// canonical log did not actually supply is not held, so `adopt_append` skips it and no ack is owed.
  fn start_view_acks<W: Wal>(&mut self, wal: &mut W) {
    for op in (self.commit_min.get() + 1)..=self.op.get() {
      self.adopt_append(wal, op, Pending::AdoptAck(OpNumber::with(op)));
    }
  }
  /// Higher-view rule: a newer primary already exists (we saw its Prepare/Commit/PrepareOk) and we
  /// are merely stale. Fetch its log via GetView; do NOT broadcast a StartViewChange. If catch-up
  /// stalls, `view_change_status` escalates us to a real, self-driven change.
  fn catch_up_to_view(&mut self, now: Instant, view: View) {
    assert!(
      view.get() > self.view.get(),
      "catch-up target must be strictly newer than our view"
    );
    self.view = view;
    self.status = Status::ViewChange;
    self.catching_up = true;
    self.inflight.clear();
    self.buffer.clear();
    // Drop stale per-replica checkpoint reports (see transition_to_view_change_status).
    self.peer_checkpoint.clear();
    // Abandon in-flight WAL appends from the old view (see transition_to_view_change_status).
    self.pending.clear();
    self.appending.clear(); // keep the R7-F1 in-flight set in lockstep with `pending`
    // GetView is a catch-up probe, not a vote; no superblock write needed. Clear any prior-view
    // pending_sb (supersession): a stale completion from the prior view must not fire.
    self.pending_sb = None;
    // Likewise drop any in-flight checkpoint from the prior view; it re-triggers once Normal resumes.
    self.pending_checkpoint = None;
    // Abandon any in-flight state-sync (mutually exclusive with view change; see
    // `transition_to_view_change_status`). A replica catching up to a newer view re-triggers
    // state-sync from Normal if it is still behind the cluster checkpoint.
    self.sync = None;
    self.timers.sync_solicit = None;
    // A primary catching up to a newer view ends its generation: clear any forfeit grace timer
    // (M3.5 T3) AND any deferred-forfeit flag (the safety step-down — see `maybe_force_sync`) — the
    // new generation re-evaluates from scratch.
    self.forfeit_armed = None;
    self.pending_forfeit = false;
    self.svc_target = view;
    self.svc_from = 0;
    self.dvc_from.clear();
    self.dvc_quorum = false;
    self.arm_timers(now);
    self.send_get_view(now);
  }

  fn send_get_view(&mut self, now: Instant) {
    let primary = self.config.primary(self.view);
    self.outgoing.push_back(Outgoing::new(
      Recipient::To(Peer::Replica(primary)),
      Message::GetView(crate::GetView::new(
        self.view,
        self.config.replica(),
        self.nonce,
      )),
    ));
    self.timers.get_view_message = Some(now + VC_MESSAGE_RETRANSMIT);
  }

  /// Broadcast a `Recovery` solicitation (RecoveringHead) and re-arm the solicitation timer. The
  /// stable `self.nonce` tags the request so a `RecoveryResponse` to THIS replica's recovery is
  /// distinguished from unrelated traffic and matched across retries.
  fn send_recovery(&mut self, now: Instant) {
    self.outgoing.push_back(Outgoing::new(
      Recipient::Backups,
      Message::Recovery(crate::Recovery::new(self.config.replica(), self.nonce)),
    ));
    self.timers.recover_head = Some(now + RECOVER_HEAD_SOLICIT);
  }

  fn on_get_view(&mut self, _now: Instant, m: crate::GetView) {
    // Only a Normal primary at the requested view (or higher) can answer authoritatively.
    if self.status.is_normal() && self.is_primary() && self.view.get() >= m.view().get() {
      self.outgoing.push_back(Outgoing::new(
        Recipient::To(Peer::Replica(m.replica())),
        Message::StartView(crate::StartView::new(
          self.view,
          self.op,
          self.commit_min,
          self.config.replica(),
          self.log_entries(),
        )),
      ));
    }
  }

  /// Answer a peer's `Recovery` solicitation (it is in `RecoveringHead`, soliciting the canonical
  /// head). Only a `Normal` replica answers — a recovering/view-changing replica has no stable head
  /// to report. The primary answers authoritatively with its canonical log + head + commit (the
  /// recovery-handshake equivalent of a `StartView`); a Normal backup answers with only its view +
  /// echoed nonce (empty log), which still lets the soliciting replica learn the current generation
  /// and re-target the primary. The `nonce` is echoed for the requester's freshness check.
  fn on_recovery(&mut self, _now: Instant, m: crate::Recovery) {
    if !self.status.is_normal() {
      return; // only a Normal replica has a trustworthy view/head to report
    }
    if m.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    let (op, commit, log) = if self.is_primary() {
      (self.op, self.commit_min, self.log_entries())
    } else {
      // A backup cannot hand out a canonical head; it reports only its view (+ echoed nonce).
      (OpNumber::new(), OpNumber::new(), std::vec::Vec::new())
    };
    self.outgoing.push_back(Outgoing::new(
      Recipient::To(Peer::Replica(m.replica())),
      Message::RecoveryResponse(crate::RecoveryResponse::new(
        self.view,
        op,
        commit,
        self.config.replica(),
        m.nonce(),
        log,
      )),
    ));
  }

  /// Handle a `RecoveryResponse` to our own `Recovery` solicitation. Only meaningful while
  /// `RecoveringHead` (awaiting the canonical head): in any other status it is a stale completion
  /// from a prior recovery and is ignored. A response is adopted ONLY if (a) its nonce matches our
  /// outstanding solicitation (freshness — a stale response from an earlier attempt is rejected) and
  /// (b) it is from the responder's view's primary (only the primary hands out a canonical head). A
  /// backup's response (empty log) merely confirms a view; the `recover_head` timer re-solicits.
  fn on_recovery_response<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    m: crate::RecoveryResponse,
  ) {
    if !self.status.is_recovering_head() {
      return; // not awaiting a head (already Normal, or never solicited) — ignore the stale reply
    }
    if m.nonce() != self.nonce {
      return; // a response to a prior solicitation (or forged) — not fresh, ignore
    }
    if m.view().get() < self.view.get() {
      return; // a stale-view response cannot re-establish our head
    }
    if m.replica() != self.config.primary(m.view()) {
      // A non-primary response (empty log) only confirms the current generation; we cannot adopt a
      // head from it. Stay RecoveringHead; the recover_head timer keeps soliciting until the
      // primary answers (or a StartView arrives).
      return;
    }
    self.adopt_canonical_head(now, sb, m.view(), m.op(), m.commit(), m.log_slice());
  }

  fn on_request<W: Wal>(&mut self, now: Instant, wal: &mut W, _from: Peer, r: crate::Request) {
    if !self.status.is_normal() || !self.is_primary() {
      return; // backups ignore; the client retries to the primary
    }
    // Durable-view-before-participate: a pending superblock view-change write means status==Normal
    // but our view is not yet persisted. Serving a request now would create+commit an op in a view
    // we could regress out of on crash. Drop it — the client retries once the view is durable.
    //
    // DEFENSE (M3.5, safety): also drop while a state-sync OR a checkpoint-persist is in flight. Both
    // can RESET `self.op` (a sync to the checkpoint via `apply_sync`; a checkpoint completion advances
    // `checkpoint_op` and GCs) — assigning a new client request an op now risks reusing an op number a
    // backup still holds under different bytes (the op-reuse divergence `maybe_force_sync`'s primary
    // step-down guards against). A primary should never be syncing in steady state, so this only ever
    // drops a request during an abnormal in-flight reset; the client retries once it settles.
    if self.pending_sb.is_some() || self.sync.is_some() || self.pending_checkpoint.is_some() {
      return;
    }
    // codex R5-F2: do not serve clients while our committed prefix is not yet applied. If commit_max >
    // commit_min (a committed op is known but not yet applied — e.g. held by a B4 repair hole), the client
    // session table is stale for the unapplied ops; assigning a fresh op to a retry of one of them would
    // double-execute it once the gap fills (the apply loop has no dedup). Make the primary catch up first;
    // the client retries. (A healthy steady-state primary has commit_max == commit_min, so this never fires
    // then.) `!self.repair.is_empty()` is subsumed (a hole implies commit_max > commit_min) but stated for intent.
    if self.commit_max.get() > self.commit_min.get() || !self.repair.is_empty() {
      return;
    }
    let key = r.client().get();
    let session = self.clients.entry(key).or_default();

    // Dedup against the session (clients send one request at a time, numbered 1..).
    if r.request().get() < session.request.get() {
      return; // stale
    }
    if r.request().get() == session.request.get() {
      // Duplicate of the latest accepted request.
      // Clone the cached reply data out before dropping the session borrow so
      // that pushing to self.outgoing (which requires &mut self) is borrow-safe.
      let cached = session.reply.as_ref().and_then(|(rn, body)| {
        if *rn == r.request() {
          Some((*rn, body.clone()))
        } else {
          None
        }
      });
      if let Some((rn, body)) = cached {
        let reply = Reply::new(self.view, r.client(), rn, body);
        self.outgoing.push_back(Outgoing::new(
          Recipient::To(Peer::Client(r.client())),
          Message::Reply(reply),
        ));
      }
      return; // either resent the cached reply, or it's still in flight
    }
    if r.request().get() != session.request.get() + 1 {
      return; // gap: client violated one-in-flight; ignore
    }

    // Accept: assign the next op, submit to WAL, cache, broadcast Prepare.
    // The primary's own vote is counted in on_wal_done when the append is durable.
    let client = r.client();
    let request = r.request();
    let body_bytes = r.body_bytes();
    session.request = request;
    self.op = self.op.next();
    let header = Header::new(self.op, self.view, client, request, r.body());
    let id = self.mint_op_id();
    wal.submit_append(id, self.op, header, body_bytes.clone());
    self.log.insert(
      self.op.get(),
      LogEntry {
        client,
        request,
        body: body_bytes.clone(),
      },
    );
    self.inflight.insert(
      self.op.get(),
      Inflight {
        oks: 0, // own bit set on append-done in on_wal_done
        committed: false,
      },
    );
    self.pending.insert(id.get(), Pending::Ack(self.op));
    // Append-before-ack: op is in flight until its `on_wal_done` (R7-F1). The primary's own vote is
    // likewise gated — `record_own_vote` fires only on completion — but tracking it here keeps the
    // "durable?" predicate uniform across every votable append (and the choke-point debug_assert).
    self.appending.insert(self.op.get());

    self.outgoing.push_back(Outgoing::new(
      Recipient::Backups,
      Message::Prepare(Prepare::new(
        self.view,
        self.op,
        self.commit_min,
        self.checkpoint_op,
        client,
        request,
        body_bytes,
      )),
    ));

    self.arm_timers(now);
    // NOTE: try_commit() is NOT called here — the own vote is recorded in on_wal_done when the
    // append is durable, which then calls try_commit.
  }

  /// Commits the longest contiguous quorum-acked prefix beyond `commit_min`.
  fn try_commit<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    let quorum = self.config.quorum() as u32;
    let mut advanced = false;
    loop {
      let next = self.commit_min.get() + 1;
      // Extract needed data while holding a short-lived shared borrow, so the
      // borrow ends before commit_op (which needs &mut self).
      let ready = self
        .inflight
        .get(&next)
        .map(|inf| (!inf.committed, inf.oks.count_ones()))
        .map(|(not_committed, ones)| not_committed && ones >= quorum)
        .unwrap_or(false);
      if !ready {
        break;
      }
      // `commit_op` HOLDS the commit (returns false without advancing) if `next`'s body read back
      // permanently faulty and must be peer-repaired — never skip a hole. Stop the loop; the repair
      // timer re-fetches it and a later try_commit resumes from exactly here.
      if !self.commit_op(now, next) {
        break;
      }
      advanced = true;
    }
    self.commit_max = OpNumber::with(self.commit_max.get().max(self.commit_min.get()));
    if advanced {
      // Tell backups the commit advanced (also serves as a heartbeat).
      self.outgoing.push_back(Outgoing::new(
        Recipient::Backups,
        Message::Commit(Commit::new(self.view, self.commit_min, self.checkpoint_op)),
      ));
    }
    // commit_min may have advanced past a checkpoint boundary — take a checkpoint if due.
    self.maybe_checkpoint(sb);
  }

  /// Applies op `op` on the primary, caches + sends the reply, emits the event. Returns `true` if it
  /// applied; `false` if the body is missing (read back permanently faulty) — in which case it
  /// registers the op for peer fault-repair and does NOT advance `commit_min`, so the caller HOLDS
  /// the commit at the hole until a peer supplies the op (B4).
  #[must_use]
  fn commit_op(&mut self, now: Instant, op: u64) -> bool {
    // Faults-as-data (the M3.3b peer fault-repair conversion): a committed op whose body read back
    // permanently faulty (bit-rot / torn) is ABSENT from the dense `log` cache (the recover loop
    // dropped it rather than adopt a wrong/empty body). Instead of panicking, hold the commit and
    // fetch the op from a peer (`RequestPrepare` → `Prepare`); a later try_commit resumes here.
    let Some(entry) = self.log.get(&op).cloned() else {
      self.request_repair(now, op);
      return false;
    };
    let reply_body = self.sm.apply(OpNumber::with(op), &entry.body);
    self.commit_min = OpNumber::with(op);
    if let Some(inflight) = self.inflight.get_mut(&op) {
      inflight.committed = true;
    }
    let session = self.clients.entry(entry.client.get()).or_default();
    session.reply = Some((entry.request, reply_body.clone()));

    self.outgoing.push_back(Outgoing::new(
      Recipient::To(Peer::Client(entry.client)),
      Message::Reply(Reply::new(
        self.view,
        entry.client,
        entry.request,
        reply_body.clone(),
      )),
    ));
    self
      .events
      .push_back(Event::Committed(crate::Committed::new(
        OpNumber::with(op),
        entry.client,
        entry.request,
        reply_body,
      )));
    true
  }

  /// (Re)arms this replica's timers for its current role/status.
  fn arm_timers(&mut self, now: Instant) {
    // clear all, then set the ones for this role
    self.timers = Timers::default();
    match self.status {
      Status::Normal if self.is_primary() => {
        self.timers.commit = Some(now + COMMIT_HEARTBEAT);
        if self.commit_min.get() < self.op.get() {
          self.timers.prepare = Some(now + PREPARE_RETRANSMIT);
        }
      }
      Status::Normal => {
        self.timers.primary_idle = Some(now + PRIMARY_IDLE);
      }
      Status::ViewChange if self.catching_up => {
        self.timers.get_view_message = Some(now + VC_MESSAGE_RETRANSMIT);
        self.timers.view_change_status = Some(now + VIEW_CHANGE_STATUS);
      }
      Status::ViewChange => {
        self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
        self.timers.dvc_message = Some(now + VC_MESSAGE_RETRANSMIT);
        self.timers.view_change_status = Some(now + VIEW_CHANGE_STATUS);
      }
      // Recovering: re-submit any still-outstanding/faulty WAL-tail (+ checkpoint) reads on a cadence,
      // so the loop terminates even if a real async driver drops a completion or a transient fault
      // only clears on a later read.
      Status::Recovering => {
        self.timers.recover_retry = Some(now + RECOVER_READ_RETRANSMIT);
      }
      // RecoveringHead: re-broadcast the `Recovery` solicitation on a cadence. A permanently-faulty
      // head cannot be repaired from local disk, so the replica solicits the canonical head from a
      // peer until a `RecoveryResponse`/`StartView` re-establishes it (then adoption arms the Normal
      // timers).
      Status::RecoveringHead => {
        self.timers.recover_head = Some(now + RECOVER_HEAD_SOLICIT);
      }
    }
    // Peer fault-repair runs alongside the role timers: while a committed-op hole is outstanding,
    // keep the repair-retry timer armed (only Normal actually solicits/serves, but arming defensively
    // is harmless — a non-Normal status carries no hole, since adoption clears `repair`).
    if !self.repair.is_empty() {
      self.timers.repair_retry = Some(now + REPAIR_RETRANSMIT);
    }
    // State-sync solicitation runs alongside the role timers: while a sync is outstanding (awaiting a
    // SyncCheckpoint or persisting the adopted one), keep re-soliciting. Only Normal triggers/serves a
    // sync, so a non-Normal status structurally carries no `sync` (it is cleared on durability).
    if self.sync.is_some() {
      self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
    }
  }

  fn on_prepare<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    p: Prepare,
  ) {
    // Peer fault-repair (B4): a `Prepare` answering our `RequestPrepare` for a committed-op hole is
    // handled BEFORE the view/role guards below — its op's content is view-independent (a committed op
    // is immutable), so a reply from a holder in any view fills the hole; we must NOT let the
    // higher-view rule yank us into a view change, nor the `is_primary`/same-view guards drop it (a
    // recovered PRIMARY can also hold a hole). `fill_repair` verifies (checksum + placement) and
    // returns false for a non-hole / unverifiable body, so a normal Prepare falls through unchanged.
    if self.fill_repair(now, wal, sb, &p) {
      return;
    }
    if p.view().get() > self.view.get() {
      self.catch_up_to_view(now, p.view());
      return;
    }
    if !self.status.is_normal() || p.view() != self.view || self.is_primary() {
      return;
    }
    // Heard from the primary — defer the idle timeout.
    self.note_primary_contact(now);
    // State-sync trigger: a `Prepare` from a fresh primary may be the first signal a lagging backup
    // sees of the cluster's checkpoint. If the cluster checkpointed past our WAL head, solicit a
    // SyncCheckpoint instead of buffering this (unreachable) prepare forever.
    self.maybe_request_sync(now, p.checkpoint_op());
    // While a sync is outstanding we will catch up via the snapshot, not by tail-apply: drop the
    // prepare (do not buffer ops we can never reach below the cluster checkpoint). The synced
    // checkpoint's apply rebuilds the head; the primary's next Prepare/Commit then extends the tail.
    if self.sync.is_some() {
      return;
    }
    // Durable-view-before-participate: a pending superblock view-change write means status==Normal
    // but our view is not yet persisted. Acking a prepare now would cast a vote in a view we could
    // regress out of on crash → cross-view double-vote. Drop it; the primary retransmits the prepare.
    if self.pending_sb.is_some() {
      return;
    }
    // Learn the primary's commit (apply anything we already have).
    self.advance_commit(now, sb, p.commit().get());

    let pop = p.op().get();
    if pop <= self.op.get() {
      // Already have this op; (re)ack so a lost prepare_ok is recovered. Ops are immutable within a
      // view, and the higher-view rule (top of this fn) + the `view != self.view` reject mean this
      // re-ack only fires for a current-view prepare.
      //
      // Append-before-ack (codex R7-F1): re-ack INLINE only if op `pop` is DURABLE. If its WAL append
      // is still IN FLIGHT (`self.op` advanced in `append_prepare`/`adopt_append` while the append is
      // async), this branch must NOT ack — that would vote for an op the backup has not durably
      // appended, the exact violation the primary's PREPARE_RETRANSMIT during the in-flight window
      // could trigger. SUPPRESS the inline ack: the in-flight append's own `on_wal_done` already owes
      // exactly one PrepareOk(pop) AFTER durability, so the backup still acks once, at the right time.
      // (A re-ack for an op that already completed — e.g. a genuinely lost PrepareOk — still re-acks,
      // recovering it: that is the legitimate purpose of this branch.)
      //
      // The durability oracle is the WAL itself (`op_durably_appended`), NOT just the `appending` set:
      // a view change / catch-up clears `appending` (keeping it in lockstep with `pending`) while an
      // async append abandoned in the old generation is STILL staged in the WAL — and once such an op
      // is committed (commit_min advances past it), the view-change re-append range `(commit_min+1 ..=
      // op]` never re-marks it, so `appending` alone would wrongly green-light a re-ack of a
      // committed-but-still-in-flight op (codex vopr seed 17). Consulting the WAL closes that hole: a
      // `Dirty` (in-flight) / `Empty` (truncated, not re-appended) slot above the checkpoint is not yet
      // durable; a `Clean`/`Faulty` slot or one folded into the durable checkpoint is. (We keep the
      // `appending` guard too, so the in-flight-then-just-completed window still defers its single ack
      // to `on_wal_done` rather than emitting a redundant inline duplicate.)
      if !self.appending.contains(&pop) && self.op_durably_appended(wal, pop) {
        self.send_prepare_ok(p.op());
      }
      return;
    }
    if pop == self.op.get() + 1 {
      self.append_prepare(wal, p);
      // Drain any buffered, now-contiguous prepares.
      while let Some(next) = self.buffer.remove(&(self.op.get() + 1)) {
        self.append_prepare(wal, next);
      }
      // After appending, apply any ops now available up to the learned commit.
      let target = self.commit_max.get();
      self.advance_commit(now, sb, target);
    } else {
      // Future op: buffer it, and solicit the committed band between our head and it that the primary's
      // retransmit (only `commit_min+1..=op`) will never re-send (those ops are `<= commit_min`). This
      // fills the gap so the buffered op becomes reachable instead of stranding the backup at its head.
      self.buffer.insert(pop, p);
      self.request_tail_gap();
    }
  }

  fn append_prepare<W: Wal>(&mut self, wal: &mut W, p: Prepare) {
    self.op = p.op();
    let header = Header::new(p.op(), p.view(), p.client(), p.request(), p.body());
    let id = self.mint_op_id();
    wal.submit_append(id, p.op(), header, p.body_bytes());
    self.log.insert(
      p.op().get(),
      LogEntry {
        client: p.client(),
        request: p.request(),
        body: p.body_bytes(),
      },
    );
    self.pending.insert(id.get(), Pending::Ack(p.op()));
    // Append-before-ack (R7-F1): mark op in-flight so neither this op's deferred ack NOR a
    // retransmit-driven re-ack (`on_prepare`'s `pop <= self.op` branch) can emit a PrepareOk before
    // `on_wal_done` clears it. PrepareOk is deferred to on_wal_done when the append is durable.
    self.appending.insert(p.op().get());
  }

  /// Durably (re-)append an op the replica adopted into `self.log` during a view change, recording the
  /// deferred action (`Pending::AdoptVote` for the new primary's own vote, `Pending::AdoptAck` for a
  /// backup's PrepareOk) so `on_wal_done` casts it ONLY once the append lands (codex R6-F1,
  /// append-before-ack). The op's body lives only in the in-memory `self.log` until this completes —
  /// mirroring `append_prepare`, but for the already-installed adopted entry rather than an incoming
  /// `Prepare`. Header is written under the current (new) view, as `on_request` does for a fresh op.
  /// No-op if the op is not held (a committed op the canonical log omitted is peer-repaired instead).
  fn adopt_append<W: Wal>(&mut self, wal: &mut W, op: u64, kind: Pending) {
    let Some(entry) = self.log.get(&op).cloned() else {
      return; // not held — `advance_commit`/`request_repair` recovers a committed gap; nothing to ack
    };
    let header = Header::new(
      OpNumber::with(op),
      self.view,
      entry.client,
      entry.request,
      &entry.body,
    );
    let id = self.mint_op_id();
    wal.submit_append(id, OpNumber::with(op), header, entry.body);
    self.pending.insert(id.get(), kind);
    // Append-before-ack (R7-F1): the adopted op is in flight until `on_wal_done`. Both adoption kinds
    // (AdoptVote → own vote, AdoptAck → PrepareOk) defer their cast to completion; tracking the op
    // here keeps the durable predicate uniform so the choke-point gate covers the adoption path too.
    self.appending.insert(op);
  }

  /// Whether op `op` is DURABLY APPENDED on this replica's own disk — the ground-truth append-before-
  /// ack oracle, read straight from the WAL/superblock rather than from the mutable `appending` set
  /// (which is reset on view transitions, so it can lose track of an async append abandoned in an old
  /// generation while its bytes are still staged). `op` is durable iff it is folded into the durable
  /// checkpoint (`op <= checkpoint_op`, its body subsumed by the snapshot) OR its WAL slot has
  /// COMPLETED its append: `Clean` (durable + checksum-valid) or `Faulty` (durably written, then later
  /// torn / bit-rotted — the append still completed; the corrupt bytes are a separate, peer-repaired
  /// concern). A `Dirty` (still in flight) or `Empty` (never written / truncated) slot above the
  /// checkpoint is NOT yet durable.
  fn op_durably_appended<W: Wal>(&self, wal: &W, op: u64) -> bool {
    op <= self.checkpoint_op.get()
      || matches!(
        wal.status(OpNumber::with(op)),
        SlotStatus::Clean | SlotStatus::Faulty
      )
  }

  /// The single append-before-ack choke point: emits a `PrepareOk` for `op` to the primary. `op` MUST
  /// be durable — NOT in `self.appending` — at every call. The `debug_assert!` is the systematic guard
  /// (codex R7-F1): any future caller that tries to ack an op whose WAL append is still in flight trips
  /// in tests, so the violation class cannot silently relocate. Callers (`on_wal_done` after the append
  /// lands; `on_prepare`'s in-flight-gated re-ack branch) are responsible for not calling this for an
  /// in-flight op — this assert backstops that contract.
  fn send_prepare_ok(&mut self, op: OpNumber) {
    debug_assert!(
      !self.appending.contains(&op.get()),
      "append-before-ack: PrepareOk for op {} whose WAL append is still in flight",
      op.get()
    );
    let primary = self.config.primary(self.view);
    self.outgoing.push_back(Outgoing::new(
      Recipient::To(Peer::Replica(primary)),
      Message::PrepareOk(PrepareOk::new(
        self.view,
        op,
        self.config.replica(),
        self.checkpoint_op,
      )),
    ));
  }

  /// Applies committed ops we hold, up to `min(target, op)`, strictly in order. Backups discard the
  /// reply but emit `Committed` so observers can verify agreement.
  fn advance_commit<B: Superblock>(&mut self, now: Instant, sb: &mut B, target: u64) {
    // Record the learned commit regardless of whether we hold the ops yet.
    self.commit_max = OpNumber::with(self.commit_max.get().max(target));
    while self.commit_min.get() < target && self.commit_min.get() < self.op.get() {
      let op = self.commit_min.get() + 1;
      // Faults-as-data (the M3.3b peer fault-repair conversion): a committed op whose body read back
      // permanently faulty (bit-rot / torn) is ABSENT from the dense `log` cache (the recover loop
      // dropped it rather than adopt a wrong/empty body). Instead of panicking, HOLD the commit at the
      // hole — never skip op N to apply N+1 — and fetch op N from a peer (`RequestPrepare` →
      // `Prepare`); a later advance_commit (after the op arrives) resumes from exactly here.
      let Some(entry) = self.log.get(&op).cloned() else {
        self.request_repair(now, op);
        break;
      };
      let reply = self.sm.apply(OpNumber::with(op), &entry.body);
      self.commit_min = OpNumber::with(op);
      // Maintain the client-session request high-water + CACHED REPLY as we apply (mirrors the
      // primary's `commit_op`). The request watermark is the at-most-once dedup watermark a
      // backup-turned-primary needs in `on_request`. It MUST be tracked here on every apply — NOT
      // reconstructed from the `log` cache when becoming primary — because M3.4b GC prunes the `log`
      // below the checkpoint, so a backup whose log is empty (everything checkpointed+pruned) would
      // otherwise carry a stale `session.request` of 0 and wedge every client on the gap check
      // (`r.request() != session.request + 1`). The snapshot also restores these on recover/state-sync,
      // so the watermark survives both GC and a checkpoint restore.
      //
      // Caching the REPLY body here (not just the watermark) closes a real liveness gap: if a client's
      // reply is LOST in flight and then the primary fails over, the new primary (this former backup)
      // sees the client's resend as a duplicate (`request == session.request`) and must resend the
      // cached reply — but the OLD code cached the reply only on the primary's `commit_op`, so a
      // backup-turned-primary had `session.reply == None` and stayed SILENT, hanging the client forever
      // even though a healthy quorum exists. The reply is the SM's deterministic apply output, so every
      // replica that applies the op can cache it (it survives the failover; for an op recovered via a
      // checkpoint snapshot the dedup watermark still gates correctness, and the recent above-checkpoint
      // ops that a lost reply concerns are always applied through here).
      let session = self.clients.entry(entry.client.get()).or_default();
      if entry.request.get() > session.request.get() {
        session.request = entry.request;
        session.reply = Some((entry.request, reply.clone()));
      }
      self
        .events
        .push_back(Event::Committed(crate::Committed::new(
          OpNumber::with(op),
          entry.client,
          entry.request,
          reply,
        )));
    }
    // commit_min may have advanced past a checkpoint boundary — take a checkpoint if due.
    self.maybe_checkpoint(sb);
  }

  /// Solicit committed ops that sit strictly ABOVE this replica's head — the band
  /// `(max(self.op, checkpoint_op) .. commit_max]` — from peers via `RequestPrepare`, so they arrive as
  /// ordinary `Prepare`s through [`Self::on_prepare`]'s append path (advancing the head + draining the
  /// buffer). Closes a real liveness gap: the primary's prepare-retransmit only covers
  /// `(commit_min_primary .. op_primary]` ([`Self::primary_timeouts`]), so a BACKUP whose head fell
  /// BELOW the primary's `commit_min` (it missed those Prepares while briefly behind) never receives the
  /// committed band `(head .. commit_min_primary]`: those ops are `<= commit_min_primary` (never
  /// retransmitted), ABOVE the cluster checkpoint (so the `> self.op` state-sync trigger is FALSE — not
  /// snapshot-only), and ABOVE its own head (so `advance_commit`'s apply loop can never reach them).
  /// Without this it stalls at its head forever — and if it is in the only surviving quorum (another
  /// replica crashed), the WHOLE cluster stalls (no caught-up quorum can form). Observed deterministically
  /// under the M3 fault envelope (a laggard crashed while two backups were transiently behind).
  ///
  /// Self-driven + self-retrying: called on every `Commit`/`Prepare` from the primary (heartbeats every
  /// `COMMIT_HEARTBEAT`), so it re-solicits until the head catches up — no dedicated timer, and it works
  /// even when the primary's pipeline is idle (`commit_min == op`, so its prepare-retransmit is off).
  /// The requested ops are NOT registered in `self.repair` (that path is for BELOW-head holes and does
  /// not advance the head) — the answering `Prepare` flows through the normal append path instead. A
  /// peer holding the op unpruned (the primary holds the whole `(checkpoint .. op]` band) answers via
  /// `on_request_prepare`. Below the checkpoint is state-sync territory ([`Self::maybe_request_sync`]),
  /// so only the above-checkpoint portion is requested. No-op for the primary, while syncing, or when
  /// caught up (`commit_max <= self.op`).
  ///
  /// **Bounded per call** by [`TAIL_GAP_WINDOW`]: the window is `(lo .. min(commit_max, lo +
  /// TAIL_GAP_WINDOW - 1)]`, so at most `TAIL_GAP_WINDOW` `RequestPrepare`s are pushed even if
  /// `commit_max` (learned from one incoming `Commit`/`Prepare`) is enormous or malformed. A real gap
  /// is closed incrementally — `request_tail_gap` runs on every heartbeat, and each answered window
  /// raises the head, sliding the window up — so a bogus huge `commit_max` can no longer flood the
  /// Sans-I/O core, while a genuinely far-behind backup catches up via state-sync, not tail-gap.
  fn request_tail_gap(&mut self) {
    if !self.status.is_normal() || self.is_primary() || self.sync.is_some() {
      return;
    }
    let lo = self.op.get().max(self.checkpoint_op.get()) + 1;
    // Cap the request window so one large/bogus `commit_max` cannot enqueue an unbounded number of
    // `RequestPrepare`s in a single call (CPU/memory DoS in the Sans-I/O core). `lo + WINDOW - 1` cannot
    // overflow in practice (op numbers are far below u64::MAX), but `saturating_*` keeps it total.
    let hi = self
      .commit_max
      .get()
      .min(lo.saturating_add(TAIL_GAP_WINDOW).saturating_sub(1));
    for op in lo..=hi {
      self.send_request_prepare(op);
    }
  }

  fn on_prepare_ok<B: Superblock>(&mut self, now: Instant, sb: &mut B, ok: PrepareOk) {
    if ok.view().get() > self.view.get() {
      self.catch_up_to_view(now, ok.view());
      return;
    }
    if !self.status.is_normal() || !self.is_primary() || ok.view() != self.view {
      return;
    }
    if ok.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    // Record this backup's reported checkpoint for the checkpoint-quorum (the range check above
    // guards the key). Independent of inflight: even an ok for an op we no longer track still
    // carries a fresh checkpoint report. Drives `quorum_checkpoint_op` → the GC prune floor.
    // MONOTONE: a reordered older report must never lower the recorded value (the GC floor and the
    // force-sync trigger that read it must not regress under reordering/partitions).
    self.record_peer_checkpoint(ok.replica().get(), ok.checkpoint_op());
    // State-sync trigger (symmetric): a backup reporting a checkpoint above our head means we are the
    // laggard (e.g. a partition-healed old primary). The `> self.op` gate keeps this a no-op normally.
    self.maybe_request_sync(now, ok.checkpoint_op());
    // Force-sync escalation (M3.5): a fresh quorum-checkpoint report may have just crossed a `repair`
    // hole we hold, rendering its `RequestPrepare` futile (the op is pruned everywhere on the quorum).
    self.maybe_force_sync(now);
    if let Some(inflight) = self.inflight.get_mut(&ok.op().get()) {
      inflight.oks |= 1u64 << ok.replica().get();
    }
    self.try_commit(now, sb);
  }

  fn on_commit<B: Superblock>(&mut self, now: Instant, sb: &mut B, c: Commit) {
    if c.view().get() > self.view.get() {
      self.catch_up_to_view(now, c.view());
      return;
    }
    if !self.status.is_normal() || c.view() != self.view || self.is_primary() {
      return;
    }
    // Heard from the primary — defer the idle timeout.
    self.note_primary_contact(now);
    // Record the primary's reported checkpoint. Harmless on a backup (only the primary reads
    // `peer_checkpoint` for GC), but it pre-seeds the map so a backup-turned-primary starts with the
    // primary's last-known checkpoint rather than 0. Bounded by `replica_count`. MONOTONE: a
    // reordered older Commit must never lower the recorded value (so the force-sync trigger this
    // backup reads via `quorum_checkpoint_op` does not regress under reordering/partitions).
    self.record_peer_checkpoint(self.config.primary(self.view).get(), c.checkpoint_op());
    // State-sync trigger: if the cluster has checkpointed past our WAL head, solicit a SyncCheckpoint
    // (the ops we'd need are below the cluster checkpoint and may be pruned — tail-apply can't reach).
    self.maybe_request_sync(now, c.checkpoint_op());
    // Force-sync escalation (M3.5): the primary's just-recorded checkpoint may have crossed a `repair`
    // hole we hold below it (pruned everywhere on the quorum) → escalate to a forced `RequestSync`.
    self.maybe_force_sync(now);
    self.advance_commit(now, sb, c.commit().get());
    // Tail-gap repair: if the primary's commit is ABOVE our head (committed ops we are missing, above
    // the cluster checkpoint), solicit them via `RequestPrepare` — the primary's retransmit (only
    // `commit_min+1..=op`) never re-sends a committed op below its own commit_min, so a backup that fell
    // behind would otherwise be stranded at its head. Self-retrying on each heartbeat until caught up.
    self.request_tail_gap();
  }

  /// Pulls the next message to send, if any.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn poll_message(&mut self) -> Option<Outgoing> {
    self.outgoing.pop_front()
  }

  /// Pulls the next application event, if any.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn poll_event(&mut self) -> Option<Event> {
    self.events.pop_front()
  }

  /// The earliest scheduled timer deadline, if any.
  pub fn poll_timeout(&self) -> Option<Instant> {
    [
      self.timers.prepare,
      self.timers.commit,
      self.timers.primary_idle,
      self.timers.svc_message,
      self.timers.dvc_message,
      self.timers.view_change_status,
      self.timers.get_view_message,
      self.timers.recover_retry,
      self.timers.recover_head,
      self.timers.repair_retry,
      self.timers.sync_solicit,
      // M3.5 T3: the forfeit grace deadline must wake the owner so a stuck primary re-evaluates and
      // steps down promptly when the window elapses (not just on the next heartbeat tick).
      self.forfeit_armed,
    ]
    .into_iter()
    .flatten()
    .min()
  }

  /// Encodes the checkpoint op + client-session table + an SM snapshot into one checkpoint envelope.
  ///
  /// Layout: `checkpoint_op: u64 BE | sessions_len: u32 BE | repeat[ client: u128 BE | request: u64 BE
  /// | has_reply: u8 | (if has_reply) reply_request: u64 BE, reply_len: u32 BE, reply_bytes ] |
  /// sm_snapshot_bytes`.
  ///
  /// **The leading `checkpoint_op` BINDS the op into the content hash (F3, safety).** `checkpoint_id`
  /// is `hash(envelope)`, so a faulty/forged superblock cannot ship STALE snapshot bytes (whose real
  /// frontier is op A) under an OVERSTATED advertised `checkpoint_op = B > A`: the restore paths decode
  /// this leading op and reject the snapshot unless it equals the advertised op, closing the silent
  /// drop of committed ops in `(A, B]`.
  fn encode_checkpoint(op: OpNumber, sessions: &BTreeMap<u128, Session>, snapshot: &[u8]) -> Bytes {
    let mut out = std::vec::Vec::new();
    out.extend_from_slice(&op.get().to_be_bytes());
    out.extend_from_slice(&(sessions.len() as u32).to_be_bytes());
    for (client, s) in sessions {
      out.extend_from_slice(&client.to_be_bytes());
      out.extend_from_slice(&s.request.get().to_be_bytes());
      match &s.reply {
        Some((rn, body)) => {
          out.push(1);
          out.extend_from_slice(&rn.get().to_be_bytes());
          out.extend_from_slice(&(body.len() as u32).to_be_bytes());
          out.extend_from_slice(body);
        }
        None => out.push(0),
      }
    }
    out.extend_from_slice(snapshot);
    Bytes::from(out)
  }

  /// Decodes a checkpoint envelope produced by [`Self::encode_checkpoint`] into
  /// `(checkpoint_op, sessions, sm_snapshot_slice)`, or `None` if the bytes are malformed/truncated.
  ///
  /// **Fallible (M3.3, safety).** A checkpoint read may return a corrupted / stale / torn snapshot
  /// (recover or state-sync over a faulty superblock), so EVERY field access is bounds-checked
  /// (`env.get(..)?`) and returns `None` rather than panicking on an out-of-range index or a
  /// reply-length that overruns the buffer. Callers treat `None` as a FAULT (recover re-reads within
  /// its budget; state-sync rejects the snapshot and re-solicits) — never a restore. The integrity of
  /// the snapshot *content* (that it is the RIGHT checkpoint) is established separately by the
  /// `checkpoint_id` hash check at each call site; this method only guarantees safe *parsing*.
  ///
  /// The decoded `checkpoint_op` (the leading u64) is the op BOUND into the hash (F3): every restore
  /// path verifies it equals the advertised `cr.op()` / `m.checkpoint_op()` BEFORE restoring, so an
  /// overstated advertised op over stale-but-consistent bytes is rejected rather than silently dropping
  /// the committed ops above the snapshot's real frontier.
  fn decode_checkpoint(env: &[u8]) -> Option<(OpNumber, BTreeMap<u128, Session>, &[u8])> {
    // Bounds-checked fixed-width reads: each returns `None` if `[i..i+N]` is out of range.
    fn take_u32(env: &[u8], i: &mut usize) -> Option<u32> {
      let bytes = env.get(*i..*i + 4)?;
      *i += 4;
      Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }
    fn take_u64(env: &[u8], i: &mut usize) -> Option<u64> {
      let bytes = env.get(*i..*i + 8)?;
      *i += 8;
      Some(u64::from_be_bytes(bytes.try_into().ok()?))
    }
    fn take_u128(env: &[u8], i: &mut usize) -> Option<u128> {
      let bytes = env.get(*i..*i + 16)?;
      *i += 16;
      Some(u128::from_be_bytes(bytes.try_into().ok()?))
    }
    let mut i = 0usize;
    let checkpoint_op = OpNumber::with(take_u64(env, &mut i)?); // the BOUND op (F3)
    let count = take_u32(env, &mut i)? as usize;
    let mut sessions = BTreeMap::new();
    for _ in 0..count {
      let client = take_u128(env, &mut i)?;
      let request = crate::RequestNumber::with(take_u64(env, &mut i)?);
      let has_reply = *env.get(i)?;
      i += 1;
      let reply = if has_reply == 1 {
        let rn = crate::RequestNumber::with(take_u64(env, &mut i)?);
        let len = take_u32(env, &mut i)? as usize;
        let body = Bytes::copy_from_slice(env.get(i..i + len)?);
        i += len;
        Some((rn, body))
      } else {
        None
      };
      sessions.insert(client, Session { request, reply });
    }
    // The remaining bytes are the SM snapshot tail (`i <= env.len()` is guaranteed by the checked
    // reads above, so this slice never panics).
    Some((checkpoint_op, sessions, &env[i..]))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    CheckpointRead, ClientId, Config, DoViewChange, GetView, Header, OpId, OpNumber, Prepare,
    PreparedEntry, ReadOk, Recovery, RecoveryResponse, ReplicaId, Request, RequestNumber,
    SlotStatus, StartView, StartViewChange, Superblock, SuperblockDone, View, VsrState, Wal,
    WalDone,
  };
  use std::collections::VecDeque;

  struct NoopSm;
  impl StateMachine for NoopSm {
    fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> Bytes {
      Bytes::new()
    }

    fn snapshot(&self) -> Bytes {
      Bytes::new()
    }

    fn restore(&mut self, _snapshot: &[u8]) {}
  }

  /// Echoes the request body as its reply, so a test can observe exactly which bytes were applied
  /// (used to prove `recover` restores real bodies — an empty-body regression echoes empty bytes).
  struct EchoSm;
  impl StateMachine for EchoSm {
    fn apply(&mut self, _op: OpNumber, body: &[u8]) -> Bytes {
      Bytes::copy_from_slice(body)
    }

    fn snapshot(&self) -> Bytes {
      Bytes::new()
    }

    fn restore(&mut self, _snapshot: &[u8]) {}
  }

  /// Records every applied `(op, body)` and round-trips them through `snapshot`/`restore`
  /// (mirrors the sim's `LogSm`). Used to prove `recover` restores the SM from the durable
  /// checkpoint snapshot (a fresh SM has 0 applied; a restored one reflects the checkpoint).
  #[derive(Default)]
  struct CountSm {
    applied: std::vec::Vec<(u64, std::vec::Vec<u8>)>,
  }
  impl CountSm {
    fn applied(&self) -> &[(u64, std::vec::Vec<u8>)] {
      &self.applied
    }
  }
  impl StateMachine for CountSm {
    fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes {
      self.applied.push((op.get(), body.to_vec()));
      Bytes::copy_from_slice(body)
    }

    fn snapshot(&self) -> Bytes {
      let mut out = std::vec::Vec::new();
      out.extend_from_slice(&(self.applied.len() as u64).to_be_bytes());
      for (op, body) in &self.applied {
        out.extend_from_slice(&op.to_be_bytes());
        out.extend_from_slice(&(body.len() as u64).to_be_bytes());
        out.extend_from_slice(body);
      }
      Bytes::from(out)
    }

    fn restore(&mut self, snapshot: &[u8]) {
      let mut applied = std::vec::Vec::new();
      let mut i = 0usize;
      let count = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
      i += 8;
      for _ in 0..count {
        let op = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
        i += 8;
        let len = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap()) as usize;
        i += 8;
        applied.push((op, snapshot[i..i + len].to_vec()));
        i += len;
      }
      self.applied = applied;
    }
  }

  #[derive(Default)]
  struct TestWal {
    entries: BTreeMap<u64, (Header, Bytes)>,
    head: u64,
    done: VecDeque<WalDone>,
  }
  impl Wal for TestWal {
    fn op_head(&self) -> OpNumber {
      OpNumber::with(self.head)
    }
    fn header(&self, op: OpNumber) -> Option<Header> {
      self.entries.get(&op.get()).map(|(h, _)| *h)
    }
    fn status(&self, op: OpNumber) -> SlotStatus {
      if self.entries.contains_key(&op.get()) {
        SlotStatus::Clean
      } else {
        SlotStatus::Empty
      }
    }
    fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes) {
      self.entries.insert(op.get(), (header, body));
      self.head = self.head.max(op.get());
      self.done.push_back(WalDone::Appended(id));
    }
    fn submit_read(&mut self, id: OpId, op: OpNumber) {
      self.done.push_back(match self.entries.get(&op.get()) {
        Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
        None => WalDone::Absent(id),
      });
    }
    fn truncate(&mut self, above: OpNumber) {
      self.entries.retain(|&op, _| op <= above.get());
      self.head = self.head.min(above.get());
    }
    fn prune(&mut self, below: OpNumber) {
      self.entries.retain(|&op, _| op >= below.get());
    }
    fn poll(&mut self) -> Option<WalDone> {
      self.done.pop_front()
    }
  }

  struct TestSb {
    state: VsrState,
    done: VecDeque<SuperblockDone>,
    /// The last checkpoint snapshot written (op, bytes) — stored so a recover/read test can read it
    /// back, mirroring `InMemorySuperblock`.
    checkpoint: Option<(OpNumber, Bytes)>,
  }
  impl Default for TestSb {
    fn default() -> Self {
      Self {
        state: VsrState::initial(),
        done: VecDeque::new(),
        checkpoint: None,
      }
    }
  }
  impl Superblock for TestSb {
    fn state(&self) -> VsrState {
      self.state
    }
    fn submit_write(&mut self, id: OpId, state: VsrState) {
      self.state = state;
      self.done.push_back(SuperblockDone::Wrote(id));
    }
    fn submit_write_checkpoint(&mut self, id: OpId, op: OpNumber, snapshot: Bytes) {
      self.checkpoint = Some((op, snapshot));
      self.done.push_back(SuperblockDone::Wrote(id));
    }
    fn submit_read_checkpoint(&mut self, id: OpId) {
      let done = match &self.checkpoint {
        Some((op, snap)) => {
          SuperblockDone::CheckpointRead(CheckpointRead::new(id, *op, snap.clone()))
        }
        None => SuperblockDone::Fault(id),
      };
      self.done.push_back(done);
    }
    fn poll(&mut self) -> Option<SuperblockDone> {
      self.done.pop_front()
    }
  }

  /// A superblock that completes writes *lazily*, one durability round at a time — modelling a real
  /// async superblock where a write submitted during a `handle_storage` drain does NOT complete in
  /// that same drain (it lands on disk between ticks). Submissions queue in `inflight`; `flush()`
  /// (called by the test between `handle_storage` rounds) makes the currently-inflight writes
  /// durable (`ready`). This lets a test step the 3-step checkpoint sequence one superblock write at
  /// a time and observe the intermediate (not-yet-durable) states the synchronous `TestSb` hides.
  struct StepSb {
    state: VsrState,
    inflight: VecDeque<SuperblockDone>,
    ready: VecDeque<SuperblockDone>,
    /// The state each inflight write will publish once flushed (paired by position with `inflight`).
    inflight_states: VecDeque<VsrState>,
    checkpoint: Option<(OpNumber, Bytes)>,
  }
  impl Default for StepSb {
    fn default() -> Self {
      Self {
        state: VsrState::initial(),
        inflight: VecDeque::new(),
        ready: VecDeque::new(),
        inflight_states: VecDeque::new(),
        checkpoint: None,
      }
    }
  }
  impl StepSb {
    /// Make all currently-inflight writes durable: publish their states and move completions to
    /// `ready`. Writes submitted *after* this call wait for the next `flush`.
    fn flush(&mut self) {
      while let Some(done) = self.inflight.pop_front() {
        if let Some(state) = self.inflight_states.pop_front() {
          self.state = state;
        }
        self.ready.push_back(done);
      }
    }
    /// Whether a checkpoint write or root write is still inflight (not yet flushed).
    fn has_inflight(&self) -> bool {
      !self.inflight.is_empty()
    }
  }
  impl Superblock for StepSb {
    fn state(&self) -> VsrState {
      self.state
    }
    fn submit_write(&mut self, id: OpId, state: VsrState) {
      self.inflight.push_back(SuperblockDone::Wrote(id));
      self.inflight_states.push_back(state);
    }
    fn submit_write_checkpoint(&mut self, id: OpId, op: OpNumber, snapshot: Bytes) {
      // The checkpoint snapshot becomes readable only once this write is flushed; record it eagerly
      // for simplicity (the durability gate that matters is the VsrState root ordering).
      self.checkpoint = Some((op, snapshot));
      self.inflight.push_back(SuperblockDone::Wrote(id));
      self.inflight_states.push_back(self.state); // a checkpoint write does not change the root
    }
    fn submit_read_checkpoint(&mut self, id: OpId) {
      let done = match &self.checkpoint {
        Some((op, snap)) => {
          SuperblockDone::CheckpointRead(CheckpointRead::new(id, *op, snap.clone()))
        }
        None => SuperblockDone::Fault(id),
      };
      self.ready.push_back(done);
    }
    fn poll(&mut self) -> Option<SuperblockDone> {
      self.ready.pop_front()
    }
  }

  /// A WAL whose reads can be *scripted* to fault, so a test can drive the async `Recovering`
  /// loop's retry/RecoveringHead branches deterministically. Each slot carries a real
  /// `(header, body)` (so a clean read verifies) plus an optional fault script:
  /// - `read_faults[op] = n` → the next `n` reads of `op` return `WalDone::Fault` (a TRANSIENT
  ///   fault: the `n+1`-th read succeeds). `u8::MAX` models a fault that outlives any finite
  ///   retry budget (→ a *permanently* faulty slot from the proto's view).
  /// - `corrupt[op]` → every read of `op` returns a `ReadOk` whose body does NOT match its header
  ///   (a torn write / bit-rot the backend cannot hide): the proto's `Header::verify` chokepoint
  ///   must reject it rather than adopt the corrupt body.
  ///
  /// Reads complete synchronously into the queue (like `TestWal`); the fault is in the *verdict*,
  /// not the timing, which is exactly what the recover loop must tolerate.
  struct ScriptedWal {
    entries: BTreeMap<u64, (Header, Bytes)>,
    head: u64,
    read_faults: BTreeMap<u64, u8>,
    corrupt: std::collections::BTreeSet<u64>,
    done: VecDeque<WalDone>,
  }
  impl ScriptedWal {
    /// A WAL holding dense ops `1..=n`, each with header+body `[op]` (a clean read verifies).
    fn with_entries(n: u64) -> Self {
      let mut entries = BTreeMap::new();
      for op in 1..=n {
        let body = Bytes::copy_from_slice(&[op as u8]);
        let h = Header::new(
          OpNumber::with(op),
          View::new(),
          ClientId::new(7),
          RequestNumber::with(op),
          &body,
        );
        entries.insert(op, (h, body));
      }
      Self {
        entries,
        head: n,
        read_faults: BTreeMap::new(),
        corrupt: std::collections::BTreeSet::new(),
        done: VecDeque::new(),
      }
    }
    /// Script the next `times` reads of `op` to fault (transient). `u8::MAX` ⇒ never clears.
    fn script_read_fault(&mut self, op: OpNumber, times: u8) {
      self.read_faults.insert(op.get(), times);
    }
    /// Script every read of `op` to return a ReadOk whose body fails `Header::verify` (permanent).
    fn script_corrupt_body(&mut self, op: OpNumber) {
      self.corrupt.insert(op.get());
    }
  }
  impl Wal for ScriptedWal {
    fn op_head(&self) -> OpNumber {
      OpNumber::with(self.head)
    }
    fn header(&self, op: OpNumber) -> Option<Header> {
      self.entries.get(&op.get()).map(|(h, _)| *h)
    }
    fn status(&self, op: OpNumber) -> SlotStatus {
      if self.entries.contains_key(&op.get()) {
        SlotStatus::Clean
      } else {
        SlotStatus::Empty
      }
    }
    fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes) {
      self.entries.insert(op.get(), (header, body));
      self.head = self.head.max(op.get());
      self.done.push_back(WalDone::Appended(id));
    }
    fn submit_read(&mut self, id: OpId, op: OpNumber) {
      // A scripted transient fault takes precedence and decrements its remaining count.
      if let Some(remaining) = self.read_faults.get_mut(&op.get()) {
        if *remaining > 0 {
          if *remaining != u8::MAX {
            *remaining -= 1;
          }
          self.done.push_back(WalDone::Fault(id));
          return;
        }
      }
      let done = match self.entries.get(&op.get()) {
        Some((h, b)) if self.corrupt.contains(&op.get()) => {
          // A corrupt slot returns the ORIGINAL header with a flipped body so verify fails.
          let mut torn = b.to_vec();
          torn.push(0xFF);
          WalDone::ReadOk(ReadOk::new(id, *h, Bytes::from(torn)))
        }
        Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
        None => WalDone::Absent(id),
      };
      self.done.push_back(done);
    }
    fn truncate(&mut self, above: OpNumber) {
      self.entries.retain(|&op, _| op <= above.get());
      self.head = self.head.min(above.get());
    }
    fn prune(&mut self, below: OpNumber) {
      self.entries.retain(|&op, _| op >= below.get());
    }
    fn poll(&mut self) -> Option<WalDone> {
      self.done.pop_front()
    }
  }

  #[test]
  fn fresh_endpoint_state() {
    let cfg = Config::try_new(1, ReplicaId::new(0), 3).expect("valid cluster config");
    let e = Endpoint::new(cfg, 99, NoopSm);
    assert_eq!(e.status(), Status::Normal);
    assert_eq!(e.view(), View::new());
    assert_eq!(e.op(), OpNumber::new());
    assert_eq!(e.commit(), OpNumber::new());
    assert!(e.is_primary()); // replica 0 is primary of view 0
  }

  // Helper: build a backup endpoint (replica 1 of 3).
  fn backup() -> Endpoint<NoopSm> {
    Endpoint::new(
      Config::try_new(1, ReplicaId::new(1), 3).expect("valid cluster config"),
      0,
      NoopSm,
    )
  }

  fn primary_peer() -> Peer {
    Peer::Replica(ReplicaId::new(0))
  }

  fn prepare(op: u64, commit: u64) -> Message {
    prepare_ck(op, commit, 0)
  }

  /// A `Prepare` carrying an explicit `checkpoint_op` (the state-sync trigger signal).
  fn prepare_ck(op: u64, commit: u64, checkpoint_op: u64) -> Message {
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(op),
      OpNumber::with(commit),
      OpNumber::with(checkpoint_op),
      ClientId::new(7),
      RequestNumber::with(op),
      Bytes::copy_from_slice(&[op as u8]),
    ))
  }

  #[test]
  fn backup_appends_and_acks_then_commits_via_piggyback() {
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(!e.is_primary());
    let now = Instant::ZERO;

    // Prepare op=1, commit=0: submit append, pump storage so it completes, ack, commit stays 0.
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    assert_eq!(e.op(), OpNumber::with(1));
    assert_eq!(e.commit(), OpNumber::with(0));
    e.handle_storage(now, &mut wal, &mut sb); // pump WAL → on_wal_done → PrepareOk
    match e.poll_message().expect("prepare_ok emitted").into_msg() {
      Message::PrepareOk(ok) => {
        assert_eq!(ok.op(), OpNumber::with(1));
        assert_eq!(ok.replica(), ReplicaId::new(1));
      }
      _ => panic!("expected PrepareOk"),
    }

    // Prepare op=2, commit=1: piggybacked commit applies op 1 (synchronously), then append op 2.
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
    assert_eq!(e.op(), OpNumber::with(2));
    assert_eq!(e.commit(), OpNumber::with(1));
  }

  #[test]
  fn backup_buffers_out_of_order_prepares() {
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;

    // op=2 arrives before op=1: buffered, head op stays 0.
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 0));
    assert_eq!(e.op(), OpNumber::with(0));

    // op=1 arrives: append 1, then drain buffered op 2.
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    assert_eq!(e.op(), OpNumber::with(2));
  }

  #[test]
  fn backup_caches_the_reply_so_a_backup_turned_primary_can_resend_it() {
    // REGRESSION (the lost-reply-across-failover hang the M3 sweep exposed): the primary caches each
    // committed reply (`commit_op`), but a BACKUP used to discard it. So if a client's reply was LOST
    // in flight and the primary then failed over, the new primary (a former backup) saw the client's
    // resend as a duplicate (`request == session.request`) yet had NO cached reply to resend — staying
    // SILENT and hanging the client forever, even with a healthy quorum. The fix caches the reply on
    // the backup's apply path too (it is the SM's deterministic output). Here: a backup applies op 1
    // (client 7, request 1) and must hold its cached reply.
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // Prepare op 1 (client 7, request 1), make it durable, then Commit to apply it.
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    e.handle_storage(now, &mut wal, &mut sb);
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(View::new(), OpNumber::with(1), OpNumber::new())),
    );
    assert_eq!(e.commit(), OpNumber::with(1), "the backup applied op 1");
    // The backup cached the reply for client 7's request 1 — so once it becomes primary it can resend
    // it on a duplicate request (NoopSm's reply body is empty, but the cache ENTRY must be present and
    // keyed to request 1, which is what the duplicate-resend path checks).
    let cached = e.session_reply_for_test(7);
    assert!(
      cached.is_some(),
      "a backup must cache the committed reply (so a backup-turned-primary can resend a lost reply)"
    );
    assert_eq!(
      cached.unwrap().0,
      1,
      "the cached reply is keyed to the applied request number"
    );
  }

  #[test]
  fn backup_below_primary_commit_solicits_the_committed_tail_gap() {
    // REGRESSION (the backup tail-gap liveness bug): a backup whose head fell BELOW the primary's
    // commit_min is missing committed ops that are ABOVE the cluster checkpoint (so the `> self.op`
    // state-sync trigger is FALSE) yet ABOVE its head (so advance_commit can't reach them). The
    // primary's prepare-retransmit only covers `commit_min+1..=op`, so it never re-sends them. Without
    // a backup-side solicitation the backup stalls at its head forever (and can wedge the whole cluster
    // if it is in the only surviving quorum). The fix: on hearing a Commit whose commit is above our
    // head, solicit the band `(head .. commit]` via RequestPrepare so it arrives as ordinary Prepares.
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;

    // Bring the backup to head op 2 (append 1, 2 via in-order Prepares; commit stays 0).
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    e.handle_storage(now, &mut wal, &mut sb);
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 0));
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(e.op(), OpNumber::with(2));
    while e.poll_message().is_some() {} // drain the acks

    // A Commit learns the primary committed up to op 5 (checkpoint still 2, so 3,4,5 are above the
    // checkpoint — NOT snapshot-only). The backup holds only up to op 2 → it must solicit 3,4,5.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(5),
        OpNumber::with(2),
      )),
    );
    // It does NOT advance commit past its head (it lacks 3,4,5) and does NOT state-sync (head >= ckpt).
    assert_eq!(
      e.commit(),
      OpNumber::with(2),
      "commit is held at the head until the gap fills"
    );
    // It solicits exactly the committed tail-gap (3,4,5) via RequestPrepare — NOT a state-sync.
    let mut requested = std::collections::BTreeSet::new();
    let mut saw_request_sync = false;
    while let Some(out) = e.poll_message() {
      match out.into_msg() {
        Message::RequestPrepare(rp) => {
          requested.insert(rp.op().get());
        }
        Message::RequestSync(_) => saw_request_sync = true,
        _ => {}
      }
    }
    assert_eq!(
      requested,
      [3, 4, 5].into_iter().collect(),
      "the backup solicits exactly the committed tail-gap (3,4,5) above its head"
    );
    assert!(
      !saw_request_sync,
      "the gap is above the cluster checkpoint → ordinary tail-gap repair, not a state-sync"
    );
  }

  #[test]
  fn tail_gap_repair_is_bounded_per_call() {
    // REGRESSION (the unbounded tail-gap DoS): a backup that learns a `commit_max` FAR above its head
    // (a large legitimate gap, or a malformed/bogus Commit) must NOT push the whole `(head .. commit_max]`
    // band into `outgoing` in a single `request_tail_gap` call — that is unbounded CPU/memory in the
    // Sans-I/O core. It must emit at most `TAIL_GAP_WINDOW` RequestPrepares per call (the rest follow on
    // later heartbeats as the head advances). Before the fix this enqueued ~1,000,000 RequestPrepares.
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // The backup is at head 0, checkpoint 0. A single Commit advertises a colossal commit_max — above
    // the checkpoint (so this is tail-gap territory, not state-sync) and far above the head.
    let bogus = 1_000_000u64;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(bogus),
        OpNumber::with(0),
      )),
    );
    // It records the learned commit_max but solicits only a bounded window above its head.
    assert_eq!(
      e.commit_max(),
      OpNumber::with(bogus),
      "the learned commit_max is recorded (it just is not all solicited at once)"
    );
    let mut requested: std::vec::Vec<u64> = std::vec::Vec::new();
    while let Some(out) = e.poll_message() {
      if let Message::RequestPrepare(rp) = out.msg_ref() {
        requested.push(rp.op().get());
      }
    }
    assert_eq!(
      requested.len() as u64,
      TAIL_GAP_WINDOW,
      "at most TAIL_GAP_WINDOW RequestPrepares are emitted per call, not the whole range"
    );
    // The window starts at the first op above the head (1) and is contiguous up to the cap — so the gap
    // is closed incrementally from the bottom across heartbeats, never all at once.
    assert_eq!(
      requested,
      (1..=TAIL_GAP_WINDOW).collect::<std::vec::Vec<u64>>(),
      "the bounded window is the contiguous band (head+1 ..= head+TAIL_GAP_WINDOW)"
    );
  }

  #[test]
  fn tail_gap_repair_within_the_window_requests_the_whole_gap() {
    // The cap must not under-serve a SMALL gap: a backup whose gap fits inside one window still solicits
    // exactly the gap (no truncation, no over-request past commit_max).
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // Head 0, checkpoint 0, commit_max 3 (< TAIL_GAP_WINDOW) → solicit exactly {1,2,3}.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(3),
        OpNumber::with(0),
      )),
    );
    let mut requested: std::vec::Vec<u64> = std::vec::Vec::new();
    while let Some(out) = e.poll_message() {
      if let Message::RequestPrepare(rp) = out.msg_ref() {
        requested.push(rp.op().get());
      }
    }
    assert_eq!(
      requested,
      std::vec![1, 2, 3],
      "a gap smaller than the window is requested in full (no truncation, no over-request)"
    );
  }

  #[test]
  fn fresh_endpoint_log_view_is_zero() {
    let e = Endpoint::new(
      Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
      99,
      NoopSm,
    );
    assert_eq!(e.log_view(), View::new());
    assert_eq!(e.status(), Status::Normal);
  }

  #[test]
  fn backup_transitions_on_svc_quorum_and_sends_dvc() {
    // replica 1 of 3. After primary_idle and one peer SVC, the SVC quorum (2) is met:
    // it transitions to ViewChange(view 1) and sends a DoViewChange to primary(1)=replica 1.
    use crate::StartViewChange;
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_timeout(now, &mut wal, &mut sb); // status=Normal backup → bootstraps primary_idle; not yet due
    let later = now + core::time::Duration::from_millis(300);
    e.handle_timeout(later, &mut wal, &mut sb); // primary_idle due → on_primary_idle → broadcast SVC(view 1), own bit set
    assert_eq!(e.status(), Status::Normal); // 1 of 2 — not yet quorum
    e.handle_message(
      later,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
    );
    assert_eq!(e.status(), Status::ViewChange);
    assert_eq!(e.view(), View::with(1));
    // DoViewChange is deferred until the view is durable — pump storage first.
    e.handle_storage(later, &mut wal, &mut sb);
    // it should have emitted a DoViewChange to primary(view 1) = replica 1 (itself).
    let mut saw_dvc = false;
    while let Some(out) = e.poll_message() {
      if let Message::DoViewChange(d) = out.into_msg() {
        assert_eq!(d.view(), View::with(1));
        assert_eq!(d.replica(), ReplicaId::new(1));
        saw_dvc = true;
      }
    }
    assert!(saw_dvc, "must send a DoViewChange to the new primary");
  }

  #[test]
  fn new_primary_adopts_canonical_log_and_starts_view() {
    // replica 1 is primary of view 1. Feed a DVC quorum (2 of 3) of DoViewChange for view 1.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // drive it into ViewChange(view 1) first (reuse the SVC path):
    e.handle_timeout(
      now + core::time::Duration::from_millis(300),
      &mut wal,
      &mut sb,
    ); // primary_idle → SVC(view1), own bit
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    );
    assert_eq!(e.status(), Status::ViewChange); // now collecting DVCs as primary(view 1)
    while e.poll_message().is_some() {} // discard outgoing so far
    // Feed a DoViewChange from replica 2 with a richer log (log_view 0, op 2, commit 1):
    let dvc = DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(2),
      OpNumber::with(1),
      ReplicaId::new(2),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b"),
        ),
      ],
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::DoViewChange(dvc),
    );
    // replica 1's own DVC (op 0) + replica 2's DVC (op 2) = quorum 2 → adopt op 2, become Normal primary.
    assert_eq!(e.status(), Status::Normal);
    assert!(e.is_primary());
    assert_eq!(e.view(), View::with(1));
    assert_eq!(e.op(), OpNumber::with(2));
    // StartView is deferred until the view is durable — pump storage first.
    e.handle_storage(now, &mut wal, &mut sb);
    // It must broadcast a StartView carrying the canonical log.
    let mut saw_sv = false;
    while let Some(out) = e.poll_message() {
      if let Message::StartView(sv) = out.into_msg() {
        assert_eq!(sv.op(), OpNumber::with(2));
        assert_eq!(sv.log_slice().len(), 2);
        saw_sv = true;
      }
    }
    assert!(saw_sv, "new primary must broadcast StartView");
  }

  #[test]
  fn new_primary_does_not_vote_for_an_adopted_op_before_its_wal_append() {
    // codex R6-F1 (REGRESSION, the cardinal append-before-ack invariant): a new primary that adopts an
    // uncommitted-tail op it learned from a PEER's DVC (it did NOT hold the op before) must NOT count
    // its OWN vote for that op — and must NOT commit it — until the op's WAL append is durable. The
    // own vote could only be cast from memory before, so a crash+recover would lose the op it voted
    // for. Here replica 1 becomes primary of view 1 and adopts op 2 (uncommitted: commit* = 1) supplied
    // ONLY by replica 2's DVC; replica 1's own DVC holds op 0, so op 2 is peer-learned + memory-only.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_timeout(
      now + core::time::Duration::from_millis(300),
      &mut wal,
      &mut sb,
    ); // primary_idle → SVC(view1), own bit
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    );
    assert_eq!(e.status(), Status::ViewChange);
    while e.poll_message().is_some() {}
    let dvc = DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(2),
      OpNumber::with(1),
      ReplicaId::new(2),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b"),
        ),
      ],
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::DoViewChange(dvc),
    );
    // Now the new primary (replica 1) is Normal with op 2 adopted, commit* = 1 — BEFORE any storage.
    assert_eq!(e.status(), Status::Normal);
    assert!(e.is_primary());
    assert_eq!(e.op(), OpNumber::with(2));
    assert_eq!(
      e.commit(),
      OpNumber::with(1),
      "op 1 applied; op 2 still uncommitted"
    );
    let own_bit = 1u64 << 1; // replica 1
    // THE INVARIANT: op 2's inflight entry carries NO own vote yet — the WAL append has not completed.
    // Fail-before (the bug): the own vote was seeded immediately (`oks: own`), so this was `own_bit`.
    assert_eq!(
      e.inflight.get(&2).map(|i| i.oks),
      Some(0),
      "the new primary must NOT vote for the adopted op 2 before its WAL append is durable (R6-F1)"
    );

    // Pump storage: the AdoptVote append for op 2 completes → on_wal_done sets the own vote; the
    // durable-view write completes → start_view_participate broadcasts StartView + try_commit. With a
    // 3-cluster quorum of 2, the lone own vote still cannot commit op 2.
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.inflight.get(&2).map(|i| i.oks),
      Some(own_bit),
      "after the WAL append completes the own vote is recorded (append-before-ack honoured)"
    );
    assert_eq!(
      e.commit(),
      OpNumber::with(1),
      "the own vote alone is below quorum (2) — op 2 is not yet committed"
    );
    use crate::Wal as _;
    assert!(
      wal.header(OpNumber::with(2)).is_some(),
      "op 2 was durably appended to the WAL before its own vote was counted (R6-F1)"
    );

    // A backup PrepareOk for op 2 now reaches quorum (own + backup) → op 2 commits.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::PrepareOk(PrepareOk::new(
        View::with(1),
        OpNumber::with(2),
        ReplicaId::new(2),
        OpNumber::new(),
      )),
    );
    assert_eq!(
      e.commit(),
      OpNumber::with(2),
      "op 2 commits once the durable own vote + a backup ack reach quorum"
    );
  }

  #[test]
  fn new_primary_adopted_vote_survives_crash_before_checkpoint() {
    // codex R6-F1 (REGRESSION): after the new primary records its OWN vote for an adopted peer-learned
    // op, that op MUST be in its durable WAL — so a crash+recover BEFORE any checkpoint still produces
    // it. We drive the adoption, pump until the AdoptVote append lands (own vote recorded), then CRASH
    // (drop all in-memory state) and RECOVER from the durable WAL+Superblock; op 2 must be present.
    // Fail-before: the vote was memory-only, so the op was absent from the WAL and lost on recover.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_timeout(
      now + core::time::Duration::from_millis(300),
      &mut wal,
      &mut sb,
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    );
    let dvc = DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(2),
      OpNumber::with(1),
      ReplicaId::new(2),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b"),
        ),
      ],
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::DoViewChange(dvc),
    );
    // Pump until the AdoptVote append is durable (the own vote is recorded only then).
    let own_bit = 1u64 << 1;
    for _ in 0..4 {
      e.handle_storage(now, &mut wal, &mut sb);
      if e.inflight.get(&2).map(|i| i.oks) == Some(own_bit) {
        break;
      }
    }
    assert_eq!(
      e.inflight.get(&2).map(|i| i.oks),
      Some(own_bit),
      "precondition: the new primary recorded its own vote for op 2"
    );

    // CRASH: discard `e` (all in-memory state) and RECOVER from the durable WAL + Superblock — exactly
    // what the simulation's crash/restart does. The op the primary voted for must survive.
    drop(e);
    let mut recovered = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    for _ in 0..16 {
      recovered.handle_storage(now, &mut wal, &mut sb);
      if !recovered.status().is_recovering() {
        break;
      }
    }
    use crate::Wal as _;
    assert!(
      wal.header(OpNumber::with(2)).is_some(),
      "op 2 the new primary voted for is in the durable WAL after crash+recover (R6-F1)"
    );
    assert!(
      recovered.op().get() >= 2,
      "the recovered replica re-establishes its head through the voted-for op (it was durable)"
    );
  }

  #[test]
  fn backup_adopted_ack_survives_crash_before_checkpoint() {
    // codex R6-F1 (REGRESSION, backup side): after a backup sends its PrepareOk for an adopted
    // StartView tail op, that op MUST be in its durable WAL — a crash+recover before any checkpoint
    // still produces it. Drive the adoption, pump until the PrepareOk is emitted (its AdoptAck append
    // landed), then CRASH + RECOVER; op 2 must be present. Fail-before: the ack was memory-only.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    let sv = StartView::new(
      View::with(1),
      OpNumber::with(2),
      OpNumber::with(1),
      ReplicaId::new(1),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b"),
        ),
      ],
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartView(sv),
    );
    // Pump until the PrepareOk for op 2 is emitted (which is gated on its AdoptAck append landing).
    let mut acked = false;
    for _ in 0..4 {
      e.handle_storage(now, &mut wal, &mut sb);
      while let Some(out) = e.poll_message() {
        if let Message::PrepareOk(ok) = out.into_msg() {
          if ok.op() == OpNumber::with(2) {
            acked = true;
          }
        }
      }
      if acked {
        break;
      }
    }
    assert!(acked, "precondition: the backup acked the adopted op 2");

    // CRASH + RECOVER from durable storage.
    drop(e);
    let mut recovered = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(2), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    for _ in 0..16 {
      recovered.handle_storage(now, &mut wal, &mut sb);
      if !recovered.status().is_recovering() {
        break;
      }
    }
    use crate::Wal as _;
    assert!(
      wal.header(OpNumber::with(2)).is_some(),
      "op 2 the backup acked is in the durable WAL after crash+recover (R6-F1 append-before-ack)"
    );
    assert!(
      recovered.op().get() >= 2,
      "the recovered backup re-establishes its head through the acked op (it was durable)"
    );
  }

  #[test]
  fn new_primary_truncates_an_uncommitted_interior_canonical_log_gap() {
    // codex R7-F2 (CONSENSUS-CRITICAL): a replica that recovered with a faulty INTERIOR slot (here
    // checkpoint 0, head 3, op 2 read back permanently faulty + still uncommitted) drops op 2 from its
    // cache, so its log is `{1, 3}` with an interior GAP at op 2. It then becomes the new primary via a
    // DVC quorum where no donor supplies op 2 (op 2 is uncommitted and unique — no quorum holds it). The
    // adopted canonical log is `{1, 3}`, op_head 3, commit* 0; op 2 is ABOVE the committed frontier
    // (commit* == 0) yet held by NO canonical donor, so it is provably UNCOMMITTED (a committed op would
    // be held by a quorum and thus by some canonical donor → present in the offset-union).
    //
    // Fail-before: the seeding loop registered an `inflight` entry for EVERY op in `(commit_min, op_head]`
    // and `adopt_append`ed each — but `adopt_append` only appends ops PRESENT in `self.log`, so the gap op
    // 2 was silently skipped, its own vote was never recorded (`inflight[2].oks == 0` forever), and
    // `try_commit` (strictly in order) wedged at op 2 — no fresh client op above it could ever commit, and
    // no peer can supply the unique uncommitted op. The fix truncates the head at the first gap above
    // commit* BEFORE seeding, dropping the uncommitted suffix `{2, 3}`.
    let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
    assert_eq!(r.op(), OpNumber::with(3), "recovered head is op 3");
    assert!(
      !r.log.contains_key(&2),
      "precondition: the faulty op 2 is absent from the cache (interior gap)"
    );
    assert!(
      !r.has_repair_hole_for_test(2),
      "precondition: op 2 is uncommitted, so it is NOT a repair hole (R6-F2)"
    );
    while r.poll_message().is_some() {} // discard the recovery-time chatter
    let now = Instant::ZERO;

    // Drive replica 1 to primary of view 1: an SVC quorum (own + replica 0) enters ViewChange(1); pump
    // the durable-view write so it sends its own DVC; then a peer DVC reaches the DVC quorum.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    );
    assert_eq!(r.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
    r.handle_storage(now, &mut wal, &mut sb); // complete the SendDoViewChange durable-view write
    while r.poll_message().is_some() {}
    // Replica 2's DVC ALSO lacks op 2 (uncommitted+unique: no quorum holds it), same generation
    // (log_view 0), head 3, commit 0 → the offset-union still has the interior gap at op 2.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::DoViewChange(DoViewChange::new(
        View::with(1),
        View::with(0),
        OpNumber::with(3),
        OpNumber::with(0),
        ReplicaId::new(2),
        std::vec![
          PreparedEntry::new(
            OpNumber::with(1),
            ClientId::new(7),
            RequestNumber::with(1),
            bytes::Bytes::copy_from_slice(&[1u8]),
          ),
          PreparedEntry::new(
            OpNumber::with(3),
            ClientId::new(7),
            RequestNumber::with(3),
            bytes::Bytes::copy_from_slice(&[3u8]),
          ),
        ],
      )),
    );
    assert!(r.is_primary(), "replica 1 became the primary of view 1");

    // The head is truncated to op 1 (just below the uncommitted gap at op 2); the uncommitted suffix
    // `{2, 3}` is dropped from the cache.
    assert_eq!(
      r.op(),
      OpNumber::with(1),
      "the head is truncated below the first uncommitted interior gap (op 2)"
    );
    assert!(
      !r.log.contains_key(&2) && !r.log.contains_key(&3),
      "the uncommitted suffix above the gap is dropped from the cache"
    );
    assert!(
      !r.has_repair_hole_for_test(2) && !r.has_repair_hole_for_test(3),
      "an uncommitted gap above commit* is truncated, NOT left as a (futile) repair hole"
    );
    assert!(
      !r.inflight.contains_key(&2),
      "no stuck inflight entry for the gap op (fail-before: inflight[2].oks == 0 forever)"
    );

    // Pump the StartViewAsPrimary durable-view write so the new primary begins participating.
    r.handle_storage(now, &mut wal, &mut sb);
    while r.poll_message().is_some() {}
    // Land the AdoptVote append for the surviving tail op 1 (its own vote is recorded then).
    for _ in 0..4 {
      r.handle_storage(now, &mut wal, &mut sb);
    }

    // Liveness: a fresh client request is accepted (commit_max == commit_min == 0, repair empty) and —
    // crucially — COMMITS. It is assigned op 2 (the truncated head + 1), and with a backup ack it reaches
    // the commit quorum, proving `try_commit` is NOT wedged at the former gap.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(9)),
      Message::Request(Request::new(
        ClientId::new(9),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"fresh"),
      )),
    );
    assert_eq!(
      r.op(),
      OpNumber::with(2),
      "the fresh client op fills the truncated head's next slot (op 2), not op 4"
    );
    for _ in 0..4 {
      r.handle_storage(now, &mut wal, &mut sb); // land the fresh op's own-vote append
    }
    // Both backups ack the surviving tail op 1 AND the fresh op 2 → each reaches the quorum of 2.
    for ack_op in [1u64, 2] {
      for backup in [0u8, 2] {
        r.handle_message(
          now,
          &mut wal,
          &mut sb,
          Peer::Replica(ReplicaId::new(backup)),
          Message::PrepareOk(PrepareOk::new(
            View::with(1),
            OpNumber::with(ack_op),
            ReplicaId::new(backup),
            OpNumber::new(),
          )),
        );
      }
    }
    assert_eq!(
      r.commit(),
      OpNumber::with(2),
      "commit progresses through the fresh op — try_commit is not wedged at the former interior gap"
    );
  }

  #[test]
  fn new_primary_does_not_truncate_a_committed_interior_gap_it_repairs_it() {
    // codex R7-F2 (the COMPLEMENT — a COMMITTED gap must NOT be truncated). Same faulty-interior-slot
    // replica (checkpoint 0, head 3, op 2 absent), but this time the DVC quorum reports commit* == 3, so
    // op 2 is BELOW the committed frontier — a real B4 repair hole the offset-union could not carry, NOT
    // an uncommitted gap. The seeding-site truncation only scans `(commit* .. op]`, so op 2 (≤ commit*)
    // is OUTSIDE it: the head is NOT truncated, op 2 stays a `repair` hole, the commit is HELD at op 1,
    // and a peer-supplied (committed-vouching) Prepare fills it and resumes the held commit. This guards
    // the truncation from over-reaching into a committed op (which would silently drop it).
    let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
    while r.poll_message().is_some() {}
    let now = Instant::ZERO;
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    );
    r.handle_storage(now, &mut wal, &mut sb); // complete the SendDoViewChange durable-view write
    while r.poll_message().is_some() {}
    // Replica 2's DVC: same generation (log_view 0), head 3, but commit 3 (it committed past op 2). Its
    // own offset log still lacks op 2, so the union has the gap at op 2 — but commit* now == 3.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::DoViewChange(DoViewChange::new(
        View::with(1),
        View::with(0),
        OpNumber::with(3),
        OpNumber::with(3),
        ReplicaId::new(2),
        std::vec![
          PreparedEntry::new(
            OpNumber::with(1),
            ClientId::new(7),
            RequestNumber::with(1),
            bytes::Bytes::copy_from_slice(&[1u8]),
          ),
          PreparedEntry::new(
            OpNumber::with(3),
            ClientId::new(7),
            RequestNumber::with(3),
            bytes::Bytes::copy_from_slice(&[3u8]),
          ),
        ],
      )),
    );
    assert!(r.is_primary(), "replica 1 became the primary of view 1");

    // The head is NOT truncated (op 2 is committed, ≤ commit* == 3) — it stays at op 3 — and op 2 is a
    // repair hole with the commit HELD at op 1 (the apply loop never skips the committed hole).
    assert_eq!(
      r.op(),
      OpNumber::with(3),
      "a committed interior gap does NOT truncate the head (op 2 ≤ commit*)"
    );
    assert!(
      r.has_repair_hole_for_test(2),
      "the committed gap is a repair hole (on-demand B4 repair), not silently dropped"
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(1),
      "the commit is HELD below the committed hole until a peer supplies op 2"
    );

    // Pump the StartViewAsPrimary durable-view write, then a peer answers our RequestPrepare with op 2's
    // committed-vouching Prepare (commit 3 >= op 2) → fill the hole and resume the held commit to op 3.
    r.handle_storage(now, &mut wal, &mut sb);
    while r.poll_message().is_some() {}
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      repair_prepare(0, 2, 3),
    );
    assert!(
      !r.has_repair_hole_for_test(2),
      "the committed-vouching Prepare fills the hole"
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(3),
      "the held commit resumes once the committed gap is repaired (op 2 then 3 apply in order)"
    );
  }

  #[test]
  fn new_primary_reconstructs_sessions_so_retries_dedup() {
    // replica 1 becomes primary of view 1, adopting client 7's requests 1 (committed) and 2.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_timeout(
      now + core::time::Duration::from_millis(300),
      &mut wal,
      &mut sb,
    ); // primary_idle → SVC
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    );
    while e.poll_message().is_some() {}
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::DoViewChange(DoViewChange::new(
        View::with(1),
        View::with(0),
        OpNumber::with(2),
        OpNumber::with(1),
        ReplicaId::new(2),
        std::vec![
          PreparedEntry::new(
            OpNumber::with(1),
            ClientId::new(7),
            RequestNumber::with(1),
            bytes::Bytes::from_static(b"a"),
          ),
          PreparedEntry::new(
            OpNumber::with(2),
            ClientId::new(7),
            RequestNumber::with(2),
            bytes::Bytes::from_static(b"b"),
          ),
        ],
      )),
    );
    assert!(e.is_primary());
    assert_eq!(e.op(), OpNumber::with(2));
    while e.poll_message().is_some() {}
    // The new primary deferred participation until its view is durable; pump storage so the
    // durable-view write completes and it may serve requests (durable-view-before-participate).
    e.handle_storage(now, &mut wal, &mut sb);
    while e.poll_message().is_some() {}

    // A retry of request 1 (already adopted+committed) must NOT create a new op (dedup, no re-exec).
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      )),
    );
    assert_eq!(
      e.op(),
      OpNumber::with(2),
      "retry of an adopted request must be deduplicated, not re-executed"
    );

    // A genuinely new request (3) IS accepted → op advances to 3.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(3),
        bytes::Bytes::from_static(b"c"),
      )),
    );
    assert_eq!(
      e.op(),
      OpNumber::with(3),
      "a new request after the adopted ones is accepted"
    );
  }

  /// Build a DoViewChange whose log is the contiguous prefix `[1..=op]`.
  fn dvc(replica: u8, log_view: u64, op: u64, commit: u64) -> DoViewChange {
    let log = (1..=op)
      .map(|i| {
        PreparedEntry::new(
          OpNumber::with(i),
          ClientId::new(1),
          RequestNumber::with(i),
          bytes::Bytes::copy_from_slice(&i.to_be_bytes()),
        )
      })
      .collect();
    DoViewChange::new(
      View::with(log_view + 10),
      View::with(log_view),
      OpNumber::with(op),
      OpNumber::with(commit),
      ReplicaId::new(replica),
      log,
    )
  }

  #[test]
  fn canonical_selection_prefers_highest_log_view_over_longer_log() {
    // r0 has the newest generation (log_view 2) but a SHORTER log; r1/r2 are longer but stale.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
    e.dvc_from.insert(0, dvc(0, 2, 3, 1));
    e.dvc_from.insert(1, dvc(1, 1, 5, 1));
    e.dvc_from.insert(2, dvc(2, 1, 5, 1));
    let (log, op_head, commit_star) = e.select_canonical_log();
    assert_eq!(op_head, 3, "newest log_view wins, not the longer stale log");
    assert_eq!(log.len(), 3);
    assert_eq!(commit_star, 1);
  }

  #[test]
  fn nack_prepare_truncates_provably_uncommitted_tail() {
    // N=5 → quorum_nack_prepare = 3. Head op 5 held only by r0; r1,r2,r3 stop at op 2.
    // ops 3..=5 each get 3 nacks (r1,r2,r3) ≥ 3 → truncated to op 2.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
    e.dvc_from.insert(0, dvc(0, 1, 5, 2));
    e.dvc_from.insert(1, dvc(1, 1, 2, 2));
    e.dvc_from.insert(2, dvc(2, 1, 2, 2));
    e.dvc_from.insert(3, dvc(3, 1, 2, 2));
    let (log, op_head, _) = e.select_canonical_log();
    assert_eq!(op_head, 2, "ops 3..=5 had a nack quorum → truncated");
    assert_eq!(log.len(), 2);
  }

  #[test]
  fn committed_ops_are_never_truncated() {
    // commit* = 4: op 5 is the only uncommitted op, nacked by 3 → truncated; 1..=4 survive.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
    e.dvc_from.insert(0, dvc(0, 1, 5, 4));
    e.dvc_from.insert(1, dvc(1, 1, 4, 4));
    e.dvc_from.insert(2, dvc(2, 1, 4, 4));
    e.dvc_from.insert(3, dvc(3, 1, 4, 4));
    let (log, op_head, commit_star) = e.select_canonical_log();
    assert_eq!(commit_star, 4);
    assert_eq!(
      op_head, 4,
      "uncommitted op 5 truncated, committed 1..=4 kept"
    );
    assert_eq!(log.len(), 4);
  }

  #[test]
  fn no_truncation_at_minimal_quorum() {
    // Documents the contiguous-model property: with exactly quorum_view_change=3 DVCs,
    // the head-holder (r0) prevents a nack quorum (≤ 2 nacks < 3) → adopt whole.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
    e.dvc_from.insert(0, dvc(0, 1, 5, 2));
    e.dvc_from.insert(1, dvc(1, 1, 2, 2));
    e.dvc_from.insert(2, dvc(2, 1, 2, 2));
    let (_, op_head, _) = e.select_canonical_log();
    assert_eq!(
      op_head, 5,
      "no nack quorum possible at minimal quorum → no truncation"
    );
  }

  #[test]
  fn stalled_view_change_escalates_to_the_next_view() {
    // replica 3 of 5 (a backup at views 0,1,2). Drive it into ViewChange(1); the new primary(1)
    // never sends a StartView, so view_change_status escalates it toward view 2.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(3), 5).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let t = Instant::ZERO + core::time::Duration::from_millis(300);
    e.handle_timeout(t, &mut wal, &mut sb); // primary_idle → propose view 1 (own bit, 1/3)
    e.handle_message(
      t,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    ); // 2/3
    e.handle_message(
      t,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(1))),
    ); // 3/3 → ViewChange(1)
    assert_eq!(e.view(), View::with(1));
    assert_eq!(e.status(), Status::ViewChange);

    // Stuck: fire view_change_status (~500ms after transition) → escalate, proposing view 2.
    let t2 = t + core::time::Duration::from_millis(600);
    e.handle_timeout(t2, &mut wal, &mut sb);
    // Two peers also propose view 2 → quorum → transition to view 2.
    e.handle_message(
      t2,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(2), ReplicaId::new(0))),
    );
    e.handle_message(
      t2,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartViewChange(StartViewChange::new(View::with(2), ReplicaId::new(1))),
    );
    assert_eq!(e.view(), View::with(2), "escalated to the next view");
    assert_eq!(e.status(), Status::ViewChange);
  }

  #[test]
  fn backup_adopts_start_view() {
    // replica 2 of 3 receives a StartView for view 1 from primary(1)=replica 1.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    let sv = StartView::new(
      View::with(1),
      OpNumber::with(2),
      OpNumber::with(1),
      ReplicaId::new(1),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b"),
        ),
      ],
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartView(sv),
    );
    assert_eq!(e.status(), Status::Normal);
    assert_eq!(e.view(), View::with(1));
    assert_eq!(e.log_view(), View::with(1));
    assert_eq!(e.op(), OpNumber::with(2));
    assert_eq!(e.commit(), OpNumber::with(1)); // op 1 applied
    // codex R6-F1: the PrepareOk for the held uncommitted op (op 2) is deferred until BOTH the new
    // view is durable AND op 2 is durably (re-)appended to the WAL (append-before-ack). Two sequential
    // storage steps: (1) the durable-view write completes → `start_view_acks` submits the WAL append;
    // (2) the append completes → `on_wal_done` sends the PrepareOk. Pump until it appears (bounded).
    let mut acked_op2 = false;
    for _ in 0..4 {
      e.handle_storage(now, &mut wal, &mut sb);
      while let Some(out) = e.poll_message() {
        if let Message::PrepareOk(ok) = out.into_msg() {
          if ok.op() == OpNumber::with(2) {
            acked_op2 = true;
          }
        }
      }
      if acked_op2 {
        break;
      }
    }
    assert!(
      acked_op2,
      "backup must ack its held uncommitted ops in the new view"
    );
    // Append-before-ack: op 2 is in the durable WAL by the time it is acked (so a crash+recover after
    // the ack still produces it). The committed op 1 below the ack range is also durably present.
    use crate::Wal as _;
    assert!(
      wal.header(OpNumber::with(2)).is_some(),
      "the acked op 2 was durably (re-)appended to the WAL before the PrepareOk (R6-F1)"
    );
  }

  #[test]
  fn higher_view_prepare_triggers_get_view_catch_up() {
    // replica 0 at view 0 receives a Prepare for view 1 → catch up, sending GetView to primary(1)=1.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::Prepare(Prepare::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(0),
        OpNumber::with(0),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"x"),
      )),
    );
    assert_eq!(e.view(), View::with(1));
    assert_eq!(e.status(), Status::ViewChange);
    let mut saw_get_view = false;
    while let Some(out) = e.poll_message() {
      if let Message::GetView(g) = out.into_msg() {
        assert_eq!(g.view(), View::with(1));
        saw_get_view = true;
      }
    }
    assert!(
      saw_get_view,
      "catch-up sends GetView (not a StartViewChange)"
    );

    // The StartView reply ends the catch-up: replica 0 becomes Normal in view 1.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartView(StartView::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(1),
        ReplicaId::new(1),
        std::vec![PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"x"),
        )],
      )),
    );
    assert_eq!(e.status(), Status::Normal);
    assert_eq!(e.view(), View::with(1));
  }

  #[test]
  fn normal_primary_answers_get_view_with_start_view() {
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    e.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::GetView(GetView::new(View::with(0), ReplicaId::new(1), 5)),
    );
    let mut saw_sv = false;
    while let Some(out) = e.poll_message() {
      if let Message::StartView(sv) = out.into_msg() {
        assert_eq!(sv.view(), View::with(0));
        assert_eq!(sv.replica(), ReplicaId::new(0));
        saw_sv = true;
      }
    }
    assert!(saw_sv, "a Normal primary answers GetView with a StartView");
  }

  #[test]
  fn lone_high_svc_is_ignored_not_driven() {
    // A single StartViewChange for a far-future view must NOT inflate our view (C1 guard):
    // an SVC is not evidence a primary exists at that view.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 5).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    e.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(100), ReplicaId::new(0))),
    );
    assert_eq!(
      e.view(),
      View::new(),
      "a lone high SVC must not inflate our view"
    );
    assert_eq!(e.status(), Status::Normal);
  }

  #[test]
  fn commit_max_tracks_learned_commit_above_applied() {
    // A backup that hears commit=5 but only holds op 2 records commit_max=5, commit_min=2.
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 5)); // primary says commit=5, we have op 2
    assert_eq!(
      e.commit(),
      OpNumber::with(2),
      "commit_min only advances over ops we hold"
    );
    assert_eq!(
      e.commit_max(),
      OpNumber::with(5),
      "commit_max records the learned commit"
    );
  }

  #[test]
  fn backup_acks_only_after_append_is_durable() {
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    assert!(
      e.poll_message().is_none(),
      "no PrepareOk before the append is durable"
    );
    assert_eq!(
      wal.op_head(),
      OpNumber::with(1),
      "the prepare was submitted to the WAL"
    );
    e.handle_storage(now, &mut wal, &mut sb);
    match e
      .poll_message()
      .expect("PrepareOk after durable")
      .into_msg()
    {
      Message::PrepareOk(ok) => assert_eq!(ok.op(), OpNumber::with(1)),
      _ => panic!("expected PrepareOk"),
    }
  }

  #[test]
  #[should_panic(expected = "must not rewind below our committed op")]
  fn on_start_view_rewind_below_commit_panics() {
    // Adopt a StartView for view 1 with op 2 (commit 2), then a StartView for view 2 with op 1
    // (< our committed op 2). The second must fail-stop, not silently rewind.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    e.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)), // primary of view 1
      Message::StartView(StartView::new(
        View::with(1),
        OpNumber::with(2),
        OpNumber::with(2),
        ReplicaId::new(1),
        std::vec![
          PreparedEntry::new(
            OpNumber::with(1),
            ClientId::new(7),
            RequestNumber::with(1),
            bytes::Bytes::from_static(b"a")
          ),
          PreparedEntry::new(
            OpNumber::with(2),
            ClientId::new(7),
            RequestNumber::with(2),
            bytes::Bytes::from_static(b"b")
          ),
        ],
      )),
    );
    assert_eq!(e.commit(), OpNumber::with(2));
    e.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)), // primary of view 2
      Message::StartView(StartView::new(
        View::with(2),
        OpNumber::with(1),
        OpNumber::with(1),
        ReplicaId::new(2),
        std::vec![PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a")
        )],
      )),
    );
  }

  #[test]
  fn recover_enters_recovering_then_reaches_normal_after_reads_drain() {
    // recover() is now a metadata-only constructor: it returns in Recovering and only reaches
    // Normal after handle_storage drains the tail reads. (Was: synchronous → Normal immediately.)
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
    e.handle_storage(now, &mut wal, &mut sb);
    drop(e);

    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    assert_eq!(
      r.status(),
      Status::Recovering,
      "recover is now a metadata-only constructor (Recovering)"
    );
    r.handle_storage(now, &mut wal, &mut sb); // drain the tail reads
    assert_eq!(r.status(), Status::Normal, "tail consistent => Normal");
    assert_eq!(r.op(), OpNumber::with(2));
  }

  #[test]
  fn recover_retries_a_transient_read_fault_then_reaches_normal() {
    // A ScriptedWal faults op 2's read ONCE, then reads clean. The Recovering loop retries and
    // reaches Normal with the real body — a transient storage fault during recovery is tolerated.
    let mut wal = ScriptedWal::with_entries(2);
    wal.script_read_fault(OpNumber::with(2), 1);
    let mut sb = TestSb::default();
    let now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      EchoSm,
      &mut wal,
      &mut sb,
    );
    assert_eq!(r.status(), Status::Recovering);
    // Pump until the retry clears (bounded): each handle_storage drains one round + re-submits.
    for _ in 0..8 {
      r.handle_storage(now, &mut wal, &mut sb);
      if r.status() == Status::Normal {
        break;
      }
    }
    assert_eq!(
      r.status(),
      Status::Normal,
      "transient read-fault retried => Normal"
    );
    assert_eq!(r.op(), OpNumber::with(2));
  }

  #[test]
  fn recover_head_permanently_faulty_enters_recovering_head() {
    // A ScriptedWal faults op 2's (the head's) read PERMANENTLY (beyond the retry budget). The
    // replica cannot trust its head => RecoveringHead, never Normal. It then SOLICITS the canonical
    // head (a Recovery broadcast) but still casts no ack/vote in response to a re-delivered prepare.
    let mut wal = ScriptedWal::with_entries(2);
    wal.script_read_fault(OpNumber::with(2), u8::MAX); // exceeds the retry budget
    let mut sb = TestSb::default();
    let now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    for _ in 0..16 {
      r.handle_storage(now, &mut wal, &mut sb);
      if r.status() != Status::Recovering {
        break;
      }
    }
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "permanently-faulty head => RecoveringHead"
    );
    // On entry it solicits the canonical head (Recovery); drain that — it is NOT participation.
    while let Some(out) = r.poll_message() {
      assert!(
        out.msg_ref().is_recovery(),
        "the only message a RecoveringHead replica emits on entry is a Recovery solicitation"
      );
    }
    // A RecoveringHead replica must not participate: it casts no PrepareOk on a re-delivered prepare.
    r.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
    assert!(
      r.poll_message().is_none(),
      "RecoveringHead replica emits no ack/vote in response to a prepare"
    );
  }

  // ── B4: peer fault-repair (RequestPrepare → Prepare) ──

  /// A real `Prepare` for op `op` from `view`, carrying client 7 / request `op` / body `[op]` (the
  /// exact bytes `ScriptedWal::with_entries` stores), so a repair fill verifies against it.
  fn repair_prepare(view: u64, op: u64, commit: u64) -> Message {
    Message::Prepare(Prepare::new(
      View::with(view),
      OpNumber::with(op),
      OpNumber::with(commit),
      OpNumber::with(0),
      ClientId::new(7),
      RequestNumber::with(op),
      Bytes::copy_from_slice(&[op as u8]),
    ))
  }

  #[test]
  fn on_request_prepare_holder_replies_with_the_prepare() {
    // A Normal replica that holds a committed op answers a peer's RequestPrepare with the Prepare
    // carrying that op's body — the peer-fault-repair *server* side.
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // Hold ops 1 + 2 (apply 1 via the piggybacked commit).
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    e.handle_storage(now, &mut wal, &mut sb);
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
    e.handle_storage(now, &mut wal, &mut sb);
    while e.poll_message().is_some() {} // discard acks

    // Replica 2 asks us for op 1.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestPrepare(crate::RequestPrepare::new(
        View::new(),
        OpNumber::with(1),
        ReplicaId::new(2),
      )),
    );
    let out = e.poll_message().expect("holder answers RequestPrepare");
    assert_eq!(
      out.to(),
      Recipient::To(Peer::Replica(ReplicaId::new(2))),
      "the Prepare is addressed back to the requester"
    );
    match out.into_msg() {
      Message::Prepare(p) => {
        assert_eq!(p.op(), OpNumber::with(1));
        assert_eq!(p.body(), &[1u8], "carries op 1's real body");
      }
      other => panic!("expected a Prepare reply, got {other:?}"),
    }
  }

  #[test]
  fn on_request_prepare_for_an_op_we_lack_is_silent() {
    // A replica that does NOT hold the requested op stays silent (another peer answers) — never
    // fabricates a Prepare.
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestPrepare(crate::RequestPrepare::new(
        View::new(),
        OpNumber::with(9),
        ReplicaId::new(2),
      )),
    );
    assert!(
      e.poll_message().is_none(),
      "a replica that lacks the op answers no RequestPrepare"
    );
  }

  #[test]
  fn on_request_prepare_serves_only_committed_ops_not_uncommitted_held_ops() {
    // R5-F1 (mirror, server side): a replica must NEVER vouch for an UNCOMMITTED op as a repair source.
    // It serves a RequestPrepare only for ops it has COMMITTED (`op <= commit_min`); for an op it merely
    // HOLDS but has not yet applied/committed (`op > commit_min`) it stays SILENT — that op is not its
    // to certify, and the answering Prepare's `commit` (= commit_min) would otherwise be < op, i.e. a
    // stale uncommitted vouch the requester's `fill_repair` now rejects anyway. A caught-up peer answers.
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // Hold ops 1 + 2 but COMMIT only op 1 (prepare(2,1) piggybacks commit=1 → commit_min == 1, op == 2).
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    e.handle_storage(now, &mut wal, &mut sb);
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
    e.handle_storage(now, &mut wal, &mut sb);
    while e.poll_message().is_some() {} // discard acks
    assert_eq!(e.commit(), OpNumber::with(1), "committed through op 1 only");
    assert_eq!(
      e.op(),
      OpNumber::with(2),
      "but holds op 2 (uncommitted) in its log"
    );

    // Asking for op 2 (> commit_min == 1, held-but-uncommitted) → SILENT (not ours to certify).
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestPrepare(crate::RequestPrepare::new(
        View::new(),
        OpNumber::with(2),
        ReplicaId::new(2),
      )),
    );
    assert!(
      e.poll_message().is_none(),
      "no Prepare for an uncommitted held op (op 2 > commit_min) — we never vouch for it"
    );

    // Asking for op 1 (<= commit_min, committed) → answered (the answering Prepare carries commit >= op).
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestPrepare(crate::RequestPrepare::new(
        View::new(),
        OpNumber::with(1),
        ReplicaId::new(2),
      )),
    );
    match e
      .poll_message()
      .expect("a committed op IS served")
      .into_msg()
    {
      Message::Prepare(p) => {
        assert_eq!(p.op(), OpNumber::with(1), "serves the committed op 1");
        assert!(
          p.commit().get() >= p.op().get(),
          "the answer vouches op 1 is committed (commit = commit_min >= op)"
        );
      }
      other => panic!("expected a Prepare for the committed op, got {other:?}"),
    }
  }

  /// Recover replica 1 of 3 from a WAL holding dense ops `1..=head` where the single NON-head
  /// committed slot `faulty_op` read back permanently faulty (bit-rot). Returns the recovered
  /// endpoint (now Normal, holding a peer-repair hole at `faulty_op`) + its wal/sb.
  fn recovering_with_hole(head: u64, faulty_op: u64) -> (Endpoint<CountSm>, ScriptedWal, TestSb) {
    assert!(faulty_op < head, "the hole must be below the head");
    let mut wal = ScriptedWal::with_entries(head);
    wal.script_read_fault(OpNumber::with(faulty_op), u8::MAX); // permanent: never clears on disk
    let mut sb = TestSb::default();
    let now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      CountSm::default(),
      &mut wal,
      &mut sb,
    );
    for _ in 0..32 {
      r.handle_storage(now, &mut wal, &mut sb);
      if !r.status().is_recovering() {
        break;
      }
    }
    (r, wal, sb)
  }

  #[test]
  fn recover_non_head_faulty_committed_slot_becomes_normal_and_requests_repair() {
    // A permanently-faulty NON-head committed slot must NOT strand the replica (the old behaviour) and
    // must NOT panic: the replica returns to Normal, drops the unreadable slot from its cache, and
    // — once its commit reaches the slot — broadcasts a RequestPrepare for it (peer fault-repair),
    // HOLDING its commit below the hole. (codex R6-F2) The slot is NOT pre-registered as a repair hole
    // at recovery time: a faulty slot above the checkpoint may be UNCOMMITTED, and registering it then
    // would be an unfillable hole after the R5 repair restrictions; `advance_commit` requests it ON
    // DEMAND only when commit reaches it (which only happens once it is committed).
    let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
    assert_eq!(
      r.status(),
      Status::Normal,
      "a non-head faulty committed slot peer-repairs from Normal (never strands in Recovering)"
    );
    // It did NOT pre-register op 2 as a repair hole at recovery time (commit_max is still 0, so op 2
    // is uncommitted as far as this replica knows). No RequestPrepare is solicited yet.
    assert!(
      !r.has_repair_hole_for_test(2),
      "the faulty slot is NOT pre-registered as a repair hole at recovery (it may be uncommitted)"
    );
    assert!(
      r.poll_message().is_none(),
      "no RequestPrepare is solicited at recovery time — repair is on-demand"
    );

    // Learn commit up to 3 (e.g. a Commit from the primary): op 1 applies, op 2 is a HOLE → commit
    // HELD at 1 (never skips to apply op 3 with op 2 missing). Reaching op 2 with commit now covering
    // it is exactly when `advance_commit` requests the repair ON DEMAND.
    let now = Instant::ZERO;
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(View::new(), OpNumber::with(3), OpNumber::new())),
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(1),
      "commit is HELD below the hole — op 2's body is missing, so op 3 must not apply"
    );
    assert_eq!(
      r.state_machine().applied(),
      &[(1, std::vec![1u8])],
      "only op 1 applied; the hole stops the apply strictly in order"
    );
    // NOW op 2 is registered (on demand) and solicited: advance_commit reached it once commit covered it.
    assert!(
      r.has_repair_hole_for_test(2),
      "advance_commit registers the now-committed faulty op as a repair hole on demand"
    );
    let mut asked_for_2 = false;
    while let Some(out) = r.poll_message() {
      if let Message::RequestPrepare(rp) = out.into_msg() {
        assert_eq!(rp.op(), OpNumber::with(2));
        asked_for_2 = true;
      }
    }
    assert!(
      asked_for_2,
      "the replica solicits the faulty committed op once its commit reaches it"
    );
  }

  #[test]
  fn recover_does_not_pre_register_an_uncommitted_faulty_tail_slot_as_a_repair_hole() {
    // codex R6-F2 (REGRESSION): a faulty slot ABOVE the checkpoint may be UNCOMMITTED. At recovery the
    // replica only knows `commit_min == commit_max == checkpoint_op`, so it must NOT pre-register the
    // slot in `self.repair`: post-R5 a peer serves only `op <= commit_min` and `fill_repair` rejects
    // `commit < op`, so an uncommitted repair hole can NEVER be filled — and the R5-F2 `on_request`
    // guard (`!self.repair.is_empty()`) would then drop every client forever (a liveness deadlock).
    //
    // Recover with an uncommitted interior faulty slot (checkpoint 0, head 3, faulty op 2, and NO
    // Commit ever raising commit_max past 0). After recovery `self.repair` must be EMPTY (fail-before:
    // it was `{2}`), so the apply path never wedges on an unfillable hole.
    let (r, _wal, _sb) = recovering_with_hole(3, 2);
    assert_eq!(
      r.status(),
      Status::Normal,
      "the recovered backup resumes Normal (the faulty slot is dropped from the cache, not stranding)"
    );
    assert!(
      !r.has_repair_hole_for_test(2),
      "an UNCOMMITTED faulty tail slot is NOT registered as a repair hole at recovery (R6-F2)"
    );
    assert!(
      r.repair.is_empty(),
      "the repair set is empty after recovery — no unfillable hole, no on_request deadlock (R6-F2)"
    );

    // Liveness consequence: with an empty repair set the R5-F2 `on_request` guard does NOT drop
    // clients. Demonstrate on a Normal PRIMARY (the role that serves requests): with the buggy
    // pre-registration (`repair = {uncommitted op}`) `on_request` returns early and the client hangs;
    // with the empty repair the recovery now produces, the primary accepts the request and prepares it.
    let now = Instant::ZERO;
    let mk_request = || {
      Message::Request(crate::Request::new(
        ClientId::new(7),
        RequestNumber::with(1),
        Bytes::copy_from_slice(b"x"),
      ))
    };
    // (a) buggy state: an uncommitted op stranded in `repair` → every client is dropped (the deadlock).
    {
      let mut p = Endpoint::new(
        Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
        0,
        CountSm::default(),
      );
      let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
      p.repair.insert(5); // simulate the old pre-registration of an uncommitted faulty slot
      p.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        mk_request(),
      );
      assert!(
        p.poll_message().is_none(),
        "with a stranded uncommitted hole in `repair`, on_request drops the client (the deadlock R6-F2 removes)"
      );
    }
    // (b) fixed state: empty repair (what recovery now leaves) → the primary serves the request.
    {
      let mut p = Endpoint::new(
        Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
        0,
        CountSm::default(),
      );
      let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
      assert!(p.repair.is_empty(), "fresh primary has no repair holes");
      p.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        mk_request(),
      );
      let prepared = std::iter::from_fn(|| p.poll_message())
        .any(|out| matches!(out.into_msg(), Message::Prepare(_)));
      assert!(
        prepared,
        "with an empty repair set the primary serves the client (broadcasts a Prepare) — no deadlock"
      );
    }
  }

  #[test]
  fn repaired_prepare_fills_the_hole_and_resumes_the_held_commit() {
    // End to end: a held-commit replica receives the peer-supplied Prepare for its hole, verifies it
    // (checksum + placement), fills the cache, and resumes applying the committed prefix in order —
    // the committed op is restored, NOT lost.
    let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
    while r.poll_message().is_some() {} // discard the solicitation
    let now = Instant::ZERO;
    // Learn commit up to 3 → applies op 1, holds at the op-2 hole.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(View::new(), OpNumber::with(3), OpNumber::new())),
    );
    assert_eq!(r.commit(), OpNumber::with(1), "held at the hole");

    // A peer answers our RequestPrepare with op 2's Prepare → fill + resume.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      repair_prepare(0, 2, 3),
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(3),
      "the hole filled → the held commit resumes and applies ops 2 then 3 in order"
    );
    assert_eq!(
      r.state_machine().applied(),
      &[
        (1, std::vec![1u8]),
        (2, std::vec![2u8]),
        (3, std::vec![3u8])
      ],
      "every committed op applied in order — the rotted op 2 was repaired from a peer, not lost"
    );
    // The repaired op was persisted durably (a later read serves it), so the hole cannot reopen.
    use crate::Wal as _;
    assert!(
      wal.header(OpNumber::with(2)).is_some(),
      "the repaired op 2 is re-appended to the WAL (durable for future reads / DVCs)"
    );
  }

  #[test]
  fn a_misplaced_repaired_prepare_is_rejected_not_adopted() {
    // Placement guard (the misdirected-IO defense the recovery read path makes, applied to a peer
    // reply): a Prepare for an op that is NOT our hole must NOT fill it. The hole stays open, the
    // commit stays HELD, and no wrong op's body is applied to the held slot.
    let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
    while r.poll_message().is_some() {}
    let now = Instant::ZERO;
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(View::new(), OpNumber::with(3), OpNumber::new())),
    );
    assert_eq!(r.commit(), OpNumber::with(1));
    // A Prepare for op 5 (not our hole, op 2) is rejected by the placement check (`repair.contains`).
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      repair_prepare(0, 5, 3),
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(1),
      "a Prepare whose op is not the hole does not fill it (placement mismatch)"
    );
    assert_eq!(
      r.state_machine().applied(),
      &[(1, std::vec![1u8])],
      "no wrong body applied; the commit stays held until the CORRECT op 2 arrives"
    );
    // The correct op 2 still repairs it (liveness: a wrong reply did not poison the hole).
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      repair_prepare(0, 2, 3),
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(3),
      "the correct op 2 fills the hole"
    );
  }

  #[test]
  fn fill_repair_rejects_a_stale_uncommitted_prepare_for_a_committed_hole() {
    // R5-F1 (committed-op survival): a committed repair hole may ONLY be filled with the committed
    // value for the op. A STALE/reordered Prepare from an old view, broadcast while its body was still
    // UNCOMMITTED (`commit < op`), must be REJECTED — it does not vouch the op is committed, and the
    // committed value at that op could be a DIFFERENT body. Accepting it would diverge the replica from
    // the quorum that committed the real body. The hole stays open + the commit stays HELD until a
    // Prepare that vouches commit >= op arrives.
    let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
    while r.poll_message().is_some() {} // discard the solicitation
    let now = Instant::ZERO;
    // Learn commit up to 3 → applies op 1, holds at the op-2 hole.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(View::new(), OpNumber::with(3), OpNumber::new())),
    );
    assert_eq!(r.commit(), OpNumber::with(1), "held at the hole");

    // A STALE Prepare for op 2 carrying `commit = 1` (< op 2): an old-view primary broadcast it while
    // op 2 was still uncommitted. Placement (op 2 IS our hole) + body checksum both PASS — only the new
    // commit-vouch guard rejects it.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      repair_prepare(0, 2, 1),
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(1),
      "a stale Prepare (commit < op) does NOT fill a committed hole — commit stays HELD"
    );
    assert!(
      r.has_repair_hole_for_test(2),
      "the hole stays OPEN (re-solicited) — the uncommitted old-view body is never adopted"
    );
    assert_eq!(
      r.state_machine().applied(),
      &[(1, std::vec![1u8])],
      "no uncommitted body applied to the held slot"
    );

    // A Prepare that VOUCHES op 2 is committed (`commit = 2` >= op 2, from a peer that holds it
    // committed) fills the hole and resumes the held commit — liveness preserved.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      repair_prepare(0, 2, 2),
    );
    assert!(
      !r.has_repair_hole_for_test(2),
      "a committed-vouching Prepare (commit >= op) clears the hole"
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(3),
      "the committed value fills the hole → the held commit resumes (ops 2 then 3 apply in order)"
    );
    assert_eq!(
      r.state_machine().applied(),
      &[
        (1, std::vec![1u8]),
        (2, std::vec![2u8]),
        (3, std::vec![3u8])
      ],
      "every committed op applied in order — only the committed value filled the hole"
    );
    use crate::Wal as _;
    assert!(
      wal.header(OpNumber::with(2)).is_some(),
      "the committed op 2 is durably (re)appended once the vouching Prepare fills it"
    );
  }

  #[test]
  fn repair_holds_the_commit_across_a_long_unrepaired_window() {
    // Liveness/safety under delay: while the hole is unrepaired the commit stays HELD no matter how
    // much further commit the primary announces — a committed op above the hole is NEVER applied
    // before the hole is filled (strict in-order apply). Then a single repair fills it and the whole
    // suffix applies at once.
    let (mut r, mut wal, mut sb) = recovering_with_hole(4, 2);
    while r.poll_message().is_some() {}
    let now = Instant::ZERO;
    // Repeatedly learn commit up to the head; the hole at op 2 pins the applied frontier at op 1.
    for _ in 0..5 {
      r.handle_message(
        now,
        &mut wal,
        &mut sb,
        primary_peer(),
        Message::Commit(Commit::new(View::new(), OpNumber::with(4), OpNumber::new())),
      );
      assert_eq!(
        r.commit(),
        OpNumber::with(1),
        "commit pinned at the hole regardless of how far the primary's commit advances"
      );
    }
    // One repair → the entire held suffix (2,3,4) applies in order.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      repair_prepare(0, 2, 4),
    );
    assert_eq!(r.commit(), OpNumber::with(4));
    assert_eq!(
      r.state_machine().applied(),
      &[
        (1, std::vec![1u8]),
        (2, std::vec![2u8]),
        (3, std::vec![3u8]),
        (4, std::vec![4u8])
      ],
      "every committed op applied in order once the single hole was repaired"
    );
  }

  /// Drive a replica (replica 1 of 3) into `RecoveringHead` by permanently faulting its head op's
  /// read, returning the recovered endpoint + its (still-faulty) wal/sb. The head op is `head`.
  fn recovering_head(head: u64) -> (Endpoint<NoopSm>, ScriptedWal, TestSb) {
    let mut wal = ScriptedWal::with_entries(head);
    wal.script_read_fault(OpNumber::with(head), u8::MAX); // head read never clears → permanently faulty
    let mut sb = TestSb::default();
    let now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    for _ in 0..16 {
      r.handle_storage(now, &mut wal, &mut sb);
      if r.status() != Status::Recovering {
        break;
      }
    }
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "setup: head faulty → RecoveringHead"
    );
    (r, wal, sb)
  }

  #[test]
  fn recovering_head_solicits_recovery_on_entry() {
    // On entering RecoveringHead the replica broadcasts a Recovery solicitation (it cannot recover
    // its head from its own disk) carrying its replica id + nonce.
    let (mut r, _wal, _sb) = recovering_head(2);
    let mut saw_recovery = false;
    while let Some(out) = r.poll_message() {
      if let Message::Recovery(rec) = out.into_msg() {
        assert_eq!(rec.replica(), ReplicaId::new(1));
        saw_recovery = true;
      }
    }
    assert!(
      saw_recovery,
      "RecoveringHead solicits the canonical head via Recovery"
    );
    // It also armed the solicitation timer so an owner driving poll_timeout keeps re-soliciting.
    assert!(
      r.poll_timeout().is_some(),
      "RecoveringHead arms the recover_head timer"
    );
  }

  #[test]
  fn recovering_head_adopts_start_view_and_becomes_normal() {
    // A replica stuck in RecoveringHead (head slot permanently lost) receives a StartView from the
    // view's primary; it adopts the canonical head + log, persists the view, and becomes Normal —
    // the committed op it could not read locally is restored from the canonical log.
    let (mut r, mut wal, mut sb) = recovering_head(2);
    while r.poll_message().is_some() {} // discard the solicitation
    let now = Instant::ZERO;
    // primary(view 1) of a 3-cluster is replica 1 — but THIS replica is replica 1, so use view 0's
    // primary (replica 0) at a view >= ours (view 0). A same-view StartView from the primary adopts
    // because a RecoveringHead replica is not Normal.
    let sv = StartView::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      ReplicaId::new(0), // primary of view 0
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b"),
        ),
      ],
    );
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartView(sv),
    );
    assert_eq!(
      r.status(),
      Status::Normal,
      "RecoveringHead adopts the StartView → Normal"
    );
    assert_eq!(
      r.op(),
      OpNumber::with(2),
      "head re-established from the canonical log"
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(2),
      "the committed prefix is restored"
    );
    // The recovery bookkeeping is cleared (structurally None in Normal).
    assert!(r.recover.is_none(), "recover state cleared on adoption");
    // The new view is persisted before participation; pump the durable-view write, then it re-acks.
    r.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(sb.state().view(), View::new());
  }

  #[test]
  fn recovering_head_with_a_faulty_non_head_slot_never_applies_an_empty_body() {
    // REGRESSION (the empty-body divergence the M3 sweep exposed): a replica that recovers with BOTH a
    // faulty HEAD slot (→ RecoveringHead) AND a faulty NON-head committed slot must STILL drop the
    // non-head slot from its `log` cache (it holds only an EMPTY placeholder body from recover Phase 1).
    // Otherwise, when it later adopts a canonical head whose (offset) log OMITS that slot, `adopt_log`
    // PRESERVES the empty-bodied held copy, `adopt_canonical_head` retires its repair hole (it is now
    // "held"), and `advance_commit` applies it with the EMPTY body — diverging a committed op. The fix
    // drops every faulty slot from the cache on the RecoveringHead path and registers the non-head ones
    // as repair holes, so adoption keeps the hole and the commit is HELD until a peer serves the op.
    let mut wal = ScriptedWal::with_entries(4);
    wal.script_read_fault(OpNumber::with(4), u8::MAX); // faulty HEAD → RecoveringHead
    wal.script_read_fault(OpNumber::with(2), u8::MAX); // faulty NON-head committed slot (empty in cache)
    let mut sb = TestSb::default();
    let now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      CountSm::default(),
      &mut wal,
      &mut sb,
    );
    for _ in 0..32 {
      r.handle_storage(now, &mut wal, &mut sb);
      if r.status() != Status::Recovering {
        break;
      }
    }
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "faulty head → RecoveringHead"
    );
    while r.poll_message().is_some() {} // discard the Recovery solicitation

    // Adopt a StartView from the view-0 primary (replica 0): canonical head op 4, commit 4, but an
    // OFFSET log carrying only ops 3,4 — it OMITS op 2 (modelling a primary whose log starts above 2).
    let sv = StartView::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
      ReplicaId::new(0),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(3),
          ClientId::new(7),
          RequestNumber::with(3),
          bytes::Bytes::copy_from_slice(&[3u8]),
        ),
        PreparedEntry::new(
          OpNumber::with(4),
          ClientId::new(7),
          RequestNumber::with(4),
          bytes::Bytes::copy_from_slice(&[4u8]),
        ),
      ],
    );
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartView(sv),
    );

    // Op 2 was NOT resurrected from the empty placeholder: it stays a solicited repair hole, NEVER
    // applied empty. This replica recovered from its WAL alone (no checkpoint, commit_min == 0), so it
    // had APPLIED nothing — ops 1 AND 2 are both committed-but-unapplied at adopt time. The offset
    // canonical log omits op 2 (and op 1), so BOTH become repair holes: the commit is HELD at 0 at the
    // first hole (op 1), op 2 is registered once op 1 fills. (The seed-24 safety fix means an UNAPPLIED
    // omitted committed op is never resurrected from the local cache — including op 1, whose clean-read
    // WAL body could itself be a superseded proposal — so it is fetched from a peer, not trusted local.
    // This only STRENGTHENS the original guard: still no empty/stale body is ever applied to op 2.)
    assert!(
      r.has_repair_hole_for_test(2) || r.has_repair_hole_for_test(1),
      "an omitted unapplied committed op (op 1 first, then op 2) is a repair hole — never resurrected"
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(0),
      "the commit is HELD below the first unfilled hole (op 1), never advanced over an empty/stale body"
    );
    // CRUCIAL: no op was ever applied with an empty body (the divergence signature).
    for (op, body) in r.state_machine().applied() {
      assert!(
        !body.is_empty(),
        "op {op} was applied with an EMPTY body — the committed-op divergence this guards against"
      );
    }
    // And op 2 specifically is not applied at all yet (held — its faulty empty placeholder was dropped).
    assert!(
      !r.state_machine().applied().iter().any(|(op, _)| *op == 2),
      "op 2 is not applied until a verified body arrives"
    );
    assert!(
      !r.log.contains_key(&2),
      "op 2's faulty empty placeholder is never re-introduced into the log cache"
    );
  }

  #[test]
  fn recovering_head_adopts_recovery_response_from_primary() {
    // The full handshake: a RecoveringHead replica's Recovery is answered by the primary with a
    // RecoveryResponse carrying the canonical head; the replica adopts it and returns to Normal.
    let (mut r, mut wal, mut sb) = recovering_head(2);
    // Capture the nonce the replica solicited with (so we echo it in the primary's response).
    let mut nonce = 0;
    while let Some(out) = r.poll_message() {
      if let Message::Recovery(rec) = out.into_msg() {
        nonce = rec.nonce();
      }
    }
    let now = Instant::ZERO;
    // The primary of view 0 (replica 0) answers with its canonical log + head + commit, echoing nonce.
    let resp = RecoveryResponse::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      ReplicaId::new(0),
      nonce,
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b"),
        ),
      ],
    );
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::RecoveryResponse(resp),
    );
    assert_eq!(
      r.status(),
      Status::Normal,
      "adopt the primary's RecoveryResponse → Normal"
    );
    assert_eq!(r.op(), OpNumber::with(2));
    assert_eq!(r.commit(), OpNumber::with(2));
    assert!(r.recover.is_none());
  }

  #[test]
  fn recovering_head_ignores_stale_or_non_primary_recovery_response() {
    // A RecoveryResponse with the WRONG nonce (a stale prior solicitation) is ignored, and a
    // response from a NON-primary (empty log) cannot re-establish a head — the replica stays
    // RecoveringHead in both cases, never adopting an unauthoritative head.
    let (mut r, mut wal, mut sb) = recovering_head(2);
    let mut nonce = 0;
    while let Some(out) = r.poll_message() {
      if let Message::Recovery(rec) = out.into_msg() {
        nonce = rec.nonce();
      }
    }
    let now = Instant::ZERO;
    // Wrong nonce → ignored.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::RecoveryResponse(RecoveryResponse::new(
        View::new(),
        OpNumber::with(2),
        OpNumber::with(2),
        ReplicaId::new(0),
        nonce.wrapping_add(1), // stale/forged
        std::vec![PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        )],
      )),
    );
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "a wrong-nonce response is ignored"
    );
    // A response from a non-primary (replica 2, with empty log) → ignored (no canonical head).
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::RecoveryResponse(RecoveryResponse::new(
        View::new(),
        OpNumber::new(),
        OpNumber::new(),
        ReplicaId::new(2), // NOT primary(view 0)
        nonce,
        std::vec![],
      )),
    );
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "a non-primary response cannot re-establish the head"
    );
  }

  #[test]
  fn recovering_head_does_not_participate_on_non_head_learning_messages() {
    // The guard relaxation is SURGICAL: a RecoveringHead replica processes only StartView /
    // RecoveryResponse. A Prepare/Commit/PrepareOk must NOT be acted on (no vote/ack), and must NOT
    // pull it into a view change via the higher-view rule.
    let (mut r, mut wal, mut sb) = recovering_head(2);
    while r.poll_message().is_some() {} // discard the solicitation
    let now = Instant::ZERO;
    // A higher-view Prepare would normally trigger catch_up_to_view → ViewChange. It must be dropped.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Prepare(Prepare::new(
        View::with(5),
        OpNumber::with(3),
        OpNumber::with(2),
        OpNumber::with(0),
        ClientId::new(7),
        RequestNumber::with(3),
        Bytes::from_static(b"z"),
      )),
    );
    // A current-view Prepare for an op we hold would normally re-ack. It must be dropped too.
    r.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    // A Commit would normally advance commit. Dropped.
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(View::new(), OpNumber::with(1), OpNumber::new())),
    );
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "no message pulled it out of RecoveringHead"
    );
    assert_eq!(r.view(), View::new(), "view unchanged (no catch-up)");
    assert!(
      r.poll_message().is_none(),
      "RecoveringHead casts no ack/vote on non-head-learning messages"
    );
  }

  // ── R4-F1: a recovered replica must NOT resume as the established primary ──

  /// A `Request` from client 7 (request `rn`, body `[rn]`) — a FRESH client request, used to prove a
  /// non-Normal recovered replica does not serve it (no Prepare/Reply emitted).
  fn client_request(rn: u64) -> Message {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  }

  /// Build a `TestSb` whose durable root names `(view, log_view)` (checkpoint 0, commit 0) — so a
  /// recover() reads back a replica that was Normal (log_view == view) or mid-view-change
  /// (log_view < view) before the crash.
  fn sb_with_view(view: u64, log_view: u64) -> TestSb {
    let state = VsrState::try_new(
      View::with(view),
      View::with(log_view),
      OpNumber::new(),
      OpNumber::new(),
      0,
    )
    .expect("log_view <= view, commit >= checkpoint");
    TestSb {
      state,
      done: VecDeque::new(),
      checkpoint: None,
    }
  }

  /// A WAL holding dense ops `1..=head`, each header stamped with `view` (so a recovered replica's
  /// tail reads verify against the view the root names). Bodies are `[op]`.
  fn wal_in_view(head: u64, view: u64) -> TestWal {
    let mut wal = TestWal::default();
    for op in 1..=head {
      let body = Bytes::copy_from_slice(&[op as u8]);
      let h = Header::new(
        OpNumber::with(op),
        View::with(view),
        ClientId::new(7),
        RequestNumber::with(op),
        &body,
      );
      wal.entries.insert(op, (h, body));
    }
    wal.head = head;
    wal
  }

  #[test]
  fn recovered_primary_abdicates_to_a_view_change_instead_of_resuming_normal() {
    // A replica that was the PRIMARY of its restored view (log_view == view, replica_count > 1) must
    // NOT resume Normal with an empty pipeline (which would freeze commit at checkpoint_op and risk
    // re-executing a retried request). Per TigerBeetle replica.zig open(), it abdicates: forces a
    // view change to view+1. Replica 0 is primary of view 0; the root names view 0 / log_view 0.
    let mut wal = wal_in_view(2, 0);
    let mut sb = sb_with_view(0, 0);
    let now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    for _ in 0..16 {
      r.handle_storage(now, &mut wal, &mut sb);
      if !r.status().is_recovering() {
        break;
      }
    }
    assert_eq!(
      r.status(),
      Status::ViewChange,
      "a recovered primary abdicates (ViewChange), never resumes Normal with an empty pipeline"
    );
    assert_eq!(
      r.view(),
      View::with(1),
      "abdication forces the NEXT view (view + 1)"
    );
    // Drain the abdication's own view-change traffic (StartViewChange etc.) — it is NOT request service.
    while r.poll_message().is_some() {}
    // The double-execute hazard is closed: a fresh client request is NOT served while not Normal —
    // no Prepare to backups, no Reply to the client (on_request returns early on status != Normal).
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      client_request(1),
    );
    while let Some(out) = r.poll_message() {
      let m = out.into_msg();
      assert!(
        !matches!(m, Message::Prepare(_) | Message::Reply(_)),
        "an abdicating recovered primary serves no request: neither Prepare nor Reply, got {m:?}"
      );
    }
  }

  #[test]
  fn recovered_backup_resumes_normal_unchanged() {
    // A replica that is NOT the primary of its restored view resumes Normal (unchanged behaviour).
    // Replica 1 of 3 in view 0 is a backup (primary of view 0 is replica 0).
    let mut wal = wal_in_view(2, 0);
    let mut sb = sb_with_view(0, 0);
    let now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    for _ in 0..16 {
      r.handle_storage(now, &mut wal, &mut sb);
      if !r.status().is_recovering() {
        break;
      }
    }
    assert_eq!(
      r.status(),
      Status::Normal,
      "a recovered backup resumes Normal (it waits for the primary's Prepare/Commit)"
    );
    assert_eq!(
      r.view(),
      View::new(),
      "a recovered backup does not advance the view"
    );
    assert_eq!(r.op(), OpNumber::with(2));
  }

  #[test]
  fn recovered_mid_view_change_redrives_the_in_progress_view_change() {
    // log_view < view: the durable view advanced (a view change was in progress) but the new log was
    // not yet installed. On recovery the replica re-drives VC(view) — it enters ViewChange AT `view`
    // (not view+1, not Normal). Root names view 1 / log_view 0; replica 2 of 3 (a backup of view 1).
    let mut wal = wal_in_view(2, 0);
    let mut sb = sb_with_view(1, 0);
    let now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(2), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    for _ in 0..16 {
      r.handle_storage(now, &mut wal, &mut sb);
      if !r.status().is_recovering() {
        break;
      }
    }
    assert_eq!(
      r.status(),
      Status::ViewChange,
      "a replica that crashed mid-view-change re-drives the view change (ViewChange)"
    );
    assert_eq!(
      r.view(),
      View::with(1),
      "it re-drives the SAME in-progress view (log_view < view → VC at view, not view+1)"
    );
  }

  #[test]
  fn recovered_solo_primary_resumes_normal_and_commits_its_tail() {
    // A solo cluster (replica_count == 1) is always its own primary and CANNOT view-change (no peer
    // quorum) — it must resume Normal, NOT abdicate (which would deadlock). It must also still make
    // progress: the recovered tail (ops the solo primary committed pre-crash, above the last
    // checkpoint) re-commits from the rebuilt pipeline rather than stalling on an empty inflight.
    let mut wal = wal_in_view(2, 0);
    let mut sb = sb_with_view(0, 0);
    let now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(0), 1).unwrap(),
      0,
      CountSm::default(),
      &mut wal,
      &mut sb,
    );
    for _ in 0..16 {
      r.handle_storage(now, &mut wal, &mut sb);
      if !r.status().is_recovering() {
        break;
      }
    }
    assert_eq!(
      r.status(),
      Status::Normal,
      "a solo replica resumes Normal (it cannot view-change)"
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(2),
      "the solo primary re-commits its recovered tail (no stall on an empty inflight)"
    );
    // And it still serves a fresh request end-to-end (op 3 commits).
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      client_request(1),
    );
    for _ in 0..4 {
      r.handle_storage(now, &mut wal, &mut sb);
    }
    assert_eq!(
      r.commit(),
      OpNumber::with(3),
      "a solo primary still commits a NEW request after recovery"
    );
  }

  #[test]
  fn normal_primary_answers_recovery_with_canonical_response() {
    // A Normal primary answers a peer's Recovery with a RecoveryResponse carrying its canonical
    // log + head + commit, echoing the nonce. (Replica 0 is primary of view 0.)
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, EchoSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // Give the primary one committed op so its response is non-trivial.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(1),
        Bytes::from_static(b"a"),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb); // own append durable → commit op 1 (quorum 2 in N=3? no)
    while e.poll_message().is_some() {}
    // A peer (replica 2) solicits recovery.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::Recovery(Recovery::new(ReplicaId::new(2), 0x1234)),
    );
    let mut resp = None;
    while let Some(out) = e.poll_message() {
      if let Message::RecoveryResponse(rr) = out.into_msg() {
        resp = Some(rr);
      }
    }
    let rr = resp.expect("Normal primary answers Recovery with a RecoveryResponse");
    assert_eq!(rr.replica(), ReplicaId::new(0), "answered by the primary");
    assert_eq!(rr.nonce(), 0x1234, "the nonce is echoed");
    assert_eq!(rr.op(), OpNumber::with(1), "carries the primary's head");
    assert_eq!(rr.log_slice().len(), 1, "carries the canonical log");
  }

  #[test]
  fn normal_backup_answers_recovery_with_view_only() {
    // A Normal BACKUP answers a Recovery with only its view + echoed nonce (no canonical head):
    // op/commit are 0 and the log is empty. (Replica 2 is a backup of view 0.)
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::Recovery(Recovery::new(ReplicaId::new(1), 0x5678)),
    );
    let mut rr = None;
    while let Some(out) = e.poll_message() {
      if let Message::RecoveryResponse(r) = out.into_msg() {
        rr = Some(r);
      }
    }
    let rr = rr.expect("a Normal backup also answers a Recovery (view only)");
    assert_eq!(rr.nonce(), 0x5678);
    assert!(
      rr.log_slice().is_empty(),
      "a backup carries no canonical log"
    );
    assert_eq!(rr.op(), OpNumber::new(), "a backup reports no head");
  }

  #[test]
  fn recover_read_ok_with_bad_checksum_does_not_adopt_the_corrupt_body() {
    // The verify chokepoint (spec §3): a ReadOk whose body fails Header::verify is treated as a
    // fault, not adopted. With it as the head and permanently corrupt => RecoveringHead.
    let mut wal = ScriptedWal::with_entries(1);
    wal.script_corrupt_body(OpNumber::with(1)); // ReadOk with a body that fails verify, forever
    let mut sb = TestSb::default();
    let now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    for _ in 0..16 {
      r.handle_storage(now, &mut wal, &mut sb);
      if r.status() != Status::Recovering {
        break;
      }
    }
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "a checksum-failing head body is never adopted"
    );
  }

  #[test]
  fn recovering_replica_ignores_messages_and_does_not_join_a_view_change() {
    // Non-participation: a Recovering replica must NOT process consensus messages — in particular a
    // higher-view Prepare must NOT pull it into ViewChange (the catch_up_to_view leak). It stays
    // Recovering and emits nothing until its own storage loop completes.
    let mut wal = ScriptedWal::with_entries(2);
    wal.script_read_fault(OpNumber::with(2), 2); // keep it Recovering (not yet drained)
    let mut sb = TestSb::default();
    let now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    assert_eq!(r.status(), Status::Recovering);
    // A higher-view Prepare (view 5) — would normally trigger catch_up_to_view → ViewChange.
    let higher = Message::Prepare(Prepare::new(
      View::with(5),
      OpNumber::with(3),
      OpNumber::with(2),
      OpNumber::with(0),
      ClientId::new(7),
      RequestNumber::with(3),
      Bytes::from_static(b"z"),
    ));
    r.handle_message(now, &mut wal, &mut sb, primary_peer(), higher);
    assert_eq!(
      r.status(),
      Status::Recovering,
      "a Recovering replica ignores a higher-view message (no catch_up_to_view)"
    );
    assert_eq!(r.view(), View::new(), "view is unchanged (no adoption)");
    assert!(
      r.poll_message().is_none(),
      "Recovering replica emits nothing"
    );
  }

  #[test]
  fn recover_timer_resubmits_a_dropped_transient_fault() {
    // Robustness for a real async driver: if a transient fault's completion never produces a clean
    // read in the SAME drain, the recover_retry timer must re-submit pending/faulty reads so the
    // loop still terminates. Here op 2 faults twice (so one pump leaves it faulty-with-budget); a
    // timeout fires the retry, the next read is clean, and we reach Normal.
    let mut wal = ScriptedWal::with_entries(2);
    wal.script_read_fault(OpNumber::with(2), 2);
    let mut sb = TestSb::default();
    let mut now = Instant::ZERO;
    let mut r = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      EchoSm,
      &mut wal,
      &mut sb,
    );
    // A Recovering replica must arm a timer (so an owner driving poll_timeout makes progress).
    assert!(
      r.poll_timeout().is_some(),
      "Recovering arms the recover_retry timer"
    );
    for _ in 0..8 {
      r.handle_storage(now, &mut wal, &mut sb);
      if r.status() == Status::Normal {
        break;
      }
      // Advance to the next timer deadline and fire it (re-submits pending/faulty reads).
      if let Some(t) = r.poll_timeout() {
        now = t;
        r.handle_timeout(now, &mut wal, &mut sb);
      }
    }
    assert_eq!(
      r.status(),
      Status::Normal,
      "the recover_retry timer drives the loop to termination"
    );
  }

  #[test]
  fn recover_rebuilds_log_and_op_from_wal() {
    // A backup appends ops 1,2 durably, then "crashes". recover() from the SAME wal/sb rebuilds
    // op=2 with REAL bodies, view from the superblock. recover() is now metadata-only (returns
    // Recovering); a no-fault TestWal completes the tail reads in one handle_storage → Normal.
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
    e.handle_storage(now, &mut wal, &mut sb);
    // Drop `e` (crash). Recover a fresh endpoint from the SAME durable wal/sb.
    drop(e);
    let mut recovered = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    assert_eq!(
      recovered.status(),
      Status::Recovering,
      "recover is a metadata-only constructor (Recovering)"
    );
    recovered.handle_storage(now, &mut wal, &mut sb); // drain the tail reads → Normal
    assert_eq!(
      recovered.op(),
      OpNumber::with(2),
      "op restored from the WAL head"
    );
    assert_eq!(
      recovered.view(),
      View::new(),
      "view restored from the superblock"
    );
    assert_eq!(recovered.status(), Status::Normal);
    // Recovery is read-only: the durable WAL head is unchanged.
    assert_eq!(
      wal.op_head(),
      OpNumber::with(2),
      "WAL head is intact after recovery"
    );
    // Body restoration itself is asserted end-to-end in `recover_restores_real_bodies`.
  }

  #[test]
  fn recover_restores_real_bodies() {
    // recover() must rebuild REAL bodies from the WAL, not empty placeholders: the SM-apply paths
    // read `entry.body`, so an empty body would silently diverge the recovered replica. Durably
    // append ops 1,2 (bodies [1],[2]) to a backup, crash, recover with an echoing SM, then have
    // the primary announce commit=2 — the recovered backup re-applies both ops from its restored
    // WAL bodies, and the Committed events must carry the ORIGINAL bytes.
    let cfg = || Config::try_new(1, ReplicaId::new(1), 3).expect("valid cluster config");
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;

    let mut e = Endpoint::new(cfg(), 0, EchoSm);
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
    e.handle_storage(now, &mut wal, &mut sb);
    drop(e); // crash

    let mut recovered = Endpoint::recover(cfg(), 0, EchoSm, &mut wal, &mut sb);
    assert_eq!(recovered.status(), Status::Recovering);
    recovered.handle_storage(now, &mut wal, &mut sb); // restore the tail bodies → Normal
    assert_eq!(recovered.status(), Status::Normal);
    recovered.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
    );

    let mut applied = std::vec::Vec::new();
    while let Some(ev) = recovered.poll_event() {
      if let Ok(c) = ev.try_unwrap_committed() {
        applied.push((c.op().get(), c.reply().to_vec()));
      }
    }
    assert_eq!(
      applied,
      std::vec![(1u64, std::vec![1u8]), (2u64, std::vec![2u8])],
      "recovered replica re-applies ops 1,2 with their ORIGINAL restored bodies"
    );
  }

  #[test]
  fn dvc_is_deferred_until_view_is_durable() {
    use crate::StartViewChange;
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let later = Instant::ZERO + core::time::Duration::from_millis(300);
    e.handle_timeout(later, &mut wal, &mut sb);
    e.handle_message(
      later,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
    );
    assert_eq!(e.status(), Status::ViewChange);
    assert_eq!(e.view(), View::with(1));
    let mut saw_dvc_before = false;
    while let Some(out) = e.poll_message() {
      if matches!(out.into_msg(), Message::DoViewChange(_)) {
        saw_dvc_before = true;
      }
    }
    assert!(
      !saw_dvc_before,
      "DoViewChange must NOT be sent before the view is durable"
    );
    assert_eq!(
      sb.state().view(),
      View::with(1),
      "new view submitted to the superblock"
    );
    e.handle_storage(later, &mut wal, &mut sb);
    let mut saw_dvc_after = false;
    while let Some(out) = e.poll_message() {
      if let Message::DoViewChange(d) = out.into_msg() {
        assert_eq!(d.view(), View::with(1));
        saw_dvc_after = true;
      }
    }
    assert!(
      saw_dvc_after,
      "DoViewChange is sent once the view is durable"
    );
  }

  #[test]
  fn superseded_view_write_is_ignored() {
    use crate::StartViewChange;
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(3), 5).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let t = Instant::ZERO + core::time::Duration::from_millis(300);
    e.handle_timeout(t, &mut wal, &mut sb);
    e.handle_message(
      t,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    );
    e.handle_message(
      t,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(1))),
    );
    assert_eq!(e.view(), View::with(1));
    while e.poll_message().is_some() {}
    let t2 = t + core::time::Duration::from_millis(600);
    e.handle_timeout(t2, &mut wal, &mut sb);
    e.handle_message(
      t2,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(2), ReplicaId::new(0))),
    );
    e.handle_message(
      t2,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartViewChange(StartViewChange::new(View::with(2), ReplicaId::new(1))),
    );
    assert_eq!(e.view(), View::with(2));
    while e.poll_message().is_some() {}
    e.handle_storage(t2, &mut wal, &mut sb);
    let mut dvc_views = std::vec::Vec::new();
    while let Some(out) = e.poll_message() {
      if let Message::DoViewChange(d) = out.into_msg() {
        dvc_views.push(d.view().get());
      }
    }
    assert!(
      !dvc_views.contains(&1),
      "superseded view-1 DoViewChange must never be sent"
    );
    assert!(
      dvc_views.contains(&2),
      "live view-2 DoViewChange is sent once view 2 is durable"
    );
  }

  #[test]
  fn backup_does_not_prepare_ok_before_start_view_is_durable() {
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    let sv = StartView::new(
      View::with(1),
      OpNumber::with(2),
      OpNumber::with(1),
      ReplicaId::new(1),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a")
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b")
        ),
      ],
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartView(sv),
    );
    assert_eq!(e.status(), Status::Normal);
    assert_eq!(e.view(), View::with(1));
    assert!(
      e.poll_message().is_none(),
      "backup must NOT PrepareOk before the view is durable"
    );
    assert_eq!(sb.state().view(), View::with(1));
    // codex R6-F1: the re-ack now ALSO waits for op 2's WAL (re-)append (append-before-ack), so it
    // arrives after two sequential storage steps (durable-view → submit append; append → PrepareOk).
    let mut acked_op2 = false;
    for _ in 0..4 {
      e.handle_storage(now, &mut wal, &mut sb);
      while let Some(out) = e.poll_message() {
        if let Message::PrepareOk(ok) = out.into_msg() {
          if ok.op() == OpNumber::with(2) {
            acked_op2 = true;
          }
        }
      }
      if acked_op2 {
        break;
      }
    }
    assert!(
      acked_op2,
      "held uncommitted ops re-acked once the new view AND their WAL append are durable"
    );
    use crate::Wal as _;
    assert!(
      wal.header(OpNumber::with(2)).is_some(),
      "op 2 is durable in the WAL before its PrepareOk (R6-F1 append-before-ack)"
    );
  }

  #[test]
  fn reack_suppressed_for_committed_op_not_durably_appended_locally() {
    // codex vopr seed 17 (append-before-ack): the `pop <= self.op` re-ack branch must consult the WAL
    // for durability, NOT just the `appending` set. A view change / catch-up clears `appending` (to
    // keep it in lockstep with `pending`); with an ASYNC WAL an append abandoned in the old generation
    // is still in flight, and once that op is COMMITTED (commit_min advances past it) the view-change
    // re-append range `(commit_min+1 ..= op]` never re-marks it. So `appending` is empty for an op the
    // replica has NOT durably appended — and a retransmitted current-view Prepare(pop) would re-ack it,
    // claiming a durability this replica does not have (it could lose the op on crash). We reproduce
    // that exact divergent state directly: op 5 committed + at the head, but ABSENT from the WAL (a
    // not-yet-durable slot, exactly like an in-flight async append) and not in `appending`.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // view 0 (primary is replica 0, so replica 2 is a backup), op 5 = commit_min (committed + at head),
    // checkpoint_op 0, no repair holes. `appending` is empty (fresh) and the WAL holds nothing — the
    // post-async-view-change divergence where op 5's local append never became durable.
    e.force_state_for_test(
      /*view*/ 0,
      /*op*/ 5,
      /*commit_min*/ 5,
      /*checkpoint_op*/ 0,
      &[],
    );
    assert_eq!(
      wal.status(OpNumber::with(5)),
      SlotStatus::Empty,
      "precondition: op 5 not durable"
    );

    // The primary RETRANSMITS the current-view Prepare(5) (its PREPARE_RETRANSMIT). pop=5 <= self.op=5
    // → the re-ack branch. It must NOT ack: op 5 is not durably appended on THIS replica.
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(5, 5));
    let mut premature = 0;
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg() {
        if ok.op() == OpNumber::with(5) {
          premature += 1;
        }
      }
    }
    assert_eq!(
      premature, 0,
      "append-before-ack: must not re-ack op 5 while it is not durably appended locally (pre-fix the \
       `appending`-only guard let this through → premature PrepareOk(5))"
    );

    // Legitimacy check: once op 5 IS durably appended locally, the same retransmitted Prepare(5) DOES
    // re-ack it — the fix suppresses only the non-durable case, preserving lost-PrepareOk recovery.
    let h = Header::new(
      OpNumber::with(5),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(5),
      &[5u8],
    );
    wal.submit_append(
      OpId::new(5),
      OpNumber::with(5),
      h,
      Bytes::copy_from_slice(&[5u8]),
    );
    let _ = wal.poll(); // TestWal is synchronous: op 5 is now durable (Clean).
    assert_eq!(wal.status(OpNumber::with(5)), SlotStatus::Clean);
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(5, 5));
    let mut reacked = false;
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg() {
        if ok.op() == OpNumber::with(5) {
          reacked = true;
        }
      }
    }
    assert!(
      reacked,
      "a durable committed op is still re-acked on retransmit (legitimate lost-PrepareOk recovery)"
    );
  }

  #[test]
  fn new_prepare_not_acked_while_view_write_pending() {
    // Durable-view completeness: after adopting a StartView the backup is Normal in the new view but
    // the view is not yet durable (pending_sb armed). A new prepare arriving in this window must NOT
    // be acked until the view is durable; the primary retransmits it afterward.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // Adopt a StartView for view 1 with op 1 fully committed (no held re-acks to muddy the assertion).
    let sv = StartView::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(1),
      ReplicaId::new(1),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      )],
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartView(sv),
    );
    assert_eq!(e.status(), Status::Normal);
    let prep2 = || {
      Message::Prepare(Prepare::new(
        View::with(1),
        OpNumber::with(2),
        OpNumber::with(1),
        OpNumber::with(0),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b"),
      ))
    };
    // A new prepare (op 2) arrives BEFORE the durable-view write is pumped (pending_sb still armed).
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      prep2(),
    );
    e.handle_storage(now, &mut wal, &mut sb); // drains the StartView write; would pump op 2 if accepted
    let mut acked_op2 = false;
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg() {
        if ok.op() == OpNumber::with(2) {
          acked_op2 = true;
        }
      }
    }
    assert!(
      !acked_op2,
      "a new prepare must NOT be acked while the view-change write is pending"
    );
    // Re-deliver (as the primary retransmits) now that the view is durable → it is acked.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      prep2(),
    );
    e.handle_storage(now, &mut wal, &mut sb); // append-before-ack: pump the WAL append
    let mut acked_after = false;
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg() {
        if ok.op() == OpNumber::with(2) {
          acked_after = true;
        }
      }
    }
    assert!(
      acked_after,
      "once the view is durable, the retransmitted prepare is acked"
    );
  }

  #[test]
  fn checkpoint_envelope_round_trips_sessions_and_snapshot() {
    let mut sessions = BTreeMap::new();
    sessions.insert(
      7u128,
      Session {
        request: RequestNumber::with(3),
        reply: Some((RequestNumber::with(3), Bytes::from_static(b"r3"))),
      },
    );
    sessions.insert(
      9u128,
      Session {
        request: RequestNumber::with(1),
        reply: None,
      },
    );
    let snap = Bytes::from_static(b"SM-SNAPSHOT");
    let env = Endpoint::<NoopSm>::encode_checkpoint(OpNumber::with(42), &sessions, &snap);
    let (decoded_op, decoded_sessions, decoded_snap) =
      Endpoint::<NoopSm>::decode_checkpoint(&env).expect("a well-formed envelope decodes");
    assert_eq!(
      decoded_op,
      OpNumber::with(42),
      "the bound checkpoint op round-trips (F3)"
    );
    assert_eq!(decoded_snap, &b"SM-SNAPSHOT"[..]);
    assert_eq!(decoded_sessions.len(), 2);
    assert_eq!(decoded_sessions[&7].request, RequestNumber::with(3));
    assert_eq!(
      decoded_sessions[&7].reply.as_ref().unwrap().1,
      Bytes::from_static(b"r3")
    );
    assert_eq!(decoded_sessions[&9].reply, None);
    // The bound op is part of the content hash: encoding the SAME sessions+snapshot under a DIFFERENT
    // op yields a DIFFERENT checkpoint_id (so an overstated advertised op cannot reuse stale bytes' id).
    let env_other_op = Endpoint::<NoopSm>::encode_checkpoint(OpNumber::with(43), &sessions, &snap);
    assert_ne!(
      crate::checkpoint_id(&env),
      crate::checkpoint_id(&env_other_op),
      "the checkpoint op is bound into the content hash"
    );
    // empty sessions + empty snapshot is a valid envelope (op 0)
    let empty =
      Endpoint::<NoopSm>::encode_checkpoint(OpNumber::new(), &BTreeMap::new(), &Bytes::new());
    let (eop, es, esnap) =
      Endpoint::<NoopSm>::decode_checkpoint(&empty).expect("the empty envelope decodes");
    assert_eq!(eop, OpNumber::new());
    assert!(es.is_empty());
    assert!(esnap.is_empty());

    // A truncated / malformed envelope decodes to None (fault-not-panic), never an out-of-range panic.
    assert!(
      Endpoint::<NoopSm>::decode_checkpoint(&[]).is_none(),
      "an empty buffer (missing the leading op) is malformed → None"
    );
    assert!(
      Endpoint::<NoopSm>::decode_checkpoint(&[0, 0, 0, 0, 0, 0, 0]).is_none(),
      "a buffer too short for the 8-byte leading op is malformed → None"
    );
    assert!(
      Endpoint::<NoopSm>::decode_checkpoint(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none(),
      "the op is present but the buffer is too short for the 4-byte session count → None"
    );
    // The op + a count of 1 session but with no session bytes following → None (not a panic).
    let mut count1 = std::vec::Vec::new();
    count1.extend_from_slice(&7u64.to_be_bytes()); // bound op
    count1.extend_from_slice(&1u32.to_be_bytes()); // 1 session, no payload follows
    assert!(
      Endpoint::<NoopSm>::decode_checkpoint(&count1).is_none(),
      "a count of 1 with no session payload is truncated → None"
    );
    // A reply-length field that overruns the remaining bytes → None (the bounds check on the body).
    let mut overrun = std::vec::Vec::new();
    overrun.extend_from_slice(&7u64.to_be_bytes()); // bound op
    overrun.extend_from_slice(&1u32.to_be_bytes()); // 1 session
    overrun.extend_from_slice(&7u128.to_be_bytes()); // client
    overrun.extend_from_slice(&3u64.to_be_bytes()); // request
    overrun.push(1); // has_reply
    overrun.extend_from_slice(&3u64.to_be_bytes()); // reply request number
    overrun.extend_from_slice(&999u32.to_be_bytes()); // reply len 999 (but no body follows)
    assert!(
      Endpoint::<NoopSm>::decode_checkpoint(&overrun).is_none(),
      "a reply length that overruns the buffer is malformed → None (no panic)"
    );
  }

  #[test]
  fn recover_restores_a_nonzero_durable_view() {
    // A replica that advanced its view persists it; recover() restores it (no regression to view 0,
    // which would risk a cross-view double-vote). Drive a backup into ViewChange(view 1) so it writes
    // the durable view, pump the write, then crash + recover from the SAME wal/sb.
    use crate::StartViewChange;
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let later = Instant::ZERO + core::time::Duration::from_millis(300);
    e.handle_timeout(later, &mut wal, &mut sb); // primary_idle → propose view 1 (own SVC bit)
    e.handle_message(
      later,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
    ); // SVC quorum → ViewChange(view 1) → durable-view write submitted
    e.handle_storage(later, &mut wal, &mut sb); // make the durable-view write complete
    assert_eq!(
      sb.state().view(),
      View::with(1),
      "view 1 is durable before the crash"
    );
    assert_eq!(
      sb.state().log_view(),
      View::new(),
      "the view change did not complete: the durable log_view is still 0 (mid-view-change)"
    );
    drop(e); // crash

    let recovered = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
    assert_eq!(
      recovered.view(),
      View::with(1),
      "recover() restores the advanced durable view (no regression to view 0)"
    );
    // The durable root is `view 1 / log_view 0` — the replica crashed MID-VIEW-CHANGE (it had
    // escalated to ViewChange(1) and persisted the view, but never installed a view-1 log). Per the
    // R4-F1 fix (TigerBeetle replica.zig open()), recovery RE-DRIVES the in-progress view change
    // rather than resuming Normal: `log_view < view` → ViewChange at `view` (NOT Normal, which would
    // wrongly resume a never-completed view change). No op was appended (op_head == 0) and there is no
    // checkpoint, so the empty-WAL fast path settles the terminal status directly in recover().
    assert_eq!(
      recovered.status(),
      Status::ViewChange,
      "a mid-view-change recovery re-drives the view change, it does not resume Normal"
    );
  }

  #[test]
  fn primary_checkpoints_after_interval_ops_via_two_superblock_writes() {
    // Single-replica cluster (quorum 1): the primary commits each op as soon as its append is
    // durable. With checkpoint_ops=2, committing op 2 makes commit_min=2 >= checkpoint_op(0)+2 →
    // the checkpoint sequence runs (TWO superblock writes), and checkpoint_op advances to 2 ONLY
    // after BOTH writes are durable. `StepSb` completes writes lazily (`flush` between rounds) so
    // each of the three steps is observed in isolation.
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
    let mut e = Endpoint::new(cfg, 0, EchoSm);
    let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
    let now = Instant::ZERO;
    let req = |rn: u64| {
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      ))
    };

    // Commit op 1: not yet at the interval; no checkpoint, nothing inflight on the superblock.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(1),
    );
    e.handle_storage(now, &mut wal, &mut sb); // append durable → commit op 1
    assert_eq!(e.commit(), OpNumber::with(1));
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(0),
      "no checkpoint before the interval"
    );
    assert!(
      !sb.has_inflight(),
      "no superblock write before the interval"
    );

    // Commit op 2: commit_min reaches checkpoint_op(0)+checkpoint_ops(2)=2 → step 1: the snapshot
    // write is submitted (inflight) but NOT yet durable.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(2),
    );
    e.handle_storage(now, &mut wal, &mut sb); // append durable → commit op 2 → submit_write_checkpoint
    assert_eq!(e.commit(), OpNumber::with(2));
    assert!(sb.has_inflight(), "step 1: the snapshot write is inflight");
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(0),
      "checkpoint not durable until BOTH sb writes complete"
    );
    assert_eq!(
      sb.state().checkpoint_op(),
      OpNumber::with(0),
      "the durable root still names the OLD checkpoint after only step 1's submit"
    );

    // Flush step 1 (snapshot durable) → step 2: the VsrState root write is submitted (inflight).
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
    assert!(sb.has_inflight(), "step 2: the root write is inflight");
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(0),
      "still not durable after only the snapshot write completed"
    );

    // Flush step 2 (root durable) → step 3: the checkpoint officially advances in-memory.
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
    assert!(!sb.has_inflight(), "the sequence is complete");
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(2),
      "checkpoint durable after both writes"
    );
    // The durable root now names the new checkpoint, with a non-zero content id (hash of envelope).
    assert_eq!(sb.state().checkpoint_op(), OpNumber::with(2));
    assert_ne!(sb.state().checkpoint_id(), 0);
  }

  #[test]
  fn checkpoint_does_not_double_trigger_while_in_flight() {
    // While a checkpoint's superblock writes are pending, commit_min may keep advancing; a second
    // overlapping checkpoint must NOT start. checkpoint_ops=2: after op 2 triggers a checkpoint,
    // committing ops 3,4 (which also cross a 2-op boundary) must not arm a second checkpoint while
    // the first is in flight — only ONE checkpoint completes, landing at the op it staged (2).
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
    let mut e = Endpoint::new(cfg, 0, EchoSm);
    let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
    let now = Instant::ZERO;
    let req = |rn: u64| {
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      ))
    };

    // Commit ops 1,2 → checkpoint triggers (step 1: snapshot write inflight, NOT durable).
    for rn in 1..=2 {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        req(rn),
      );
      e.handle_storage(now, &mut wal, &mut sb);
    }
    assert_eq!(e.commit(), OpNumber::with(2));
    assert_eq!(e.checkpoint_op(), OpNumber::with(0));
    assert!(
      sb.has_inflight(),
      "the first checkpoint's snapshot write is inflight"
    );

    // Send requests 3,4 WHILE the first checkpoint's snapshot write is still in flight. The M3.5
    // op-reset DEFENSE (`on_request` short-circuits while `pending_checkpoint.is_some()`) DROPS them —
    // a primary must not assign new ops while a checkpoint-persist is in flight (an op-reuse hazard).
    // So commit stays at 2, and (a fortiori) no second checkpoint is armed.
    for rn in 3..=4 {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        req(rn),
      );
      e.handle_storage(now, &mut wal, &mut sb);
    }
    assert_eq!(
      e.commit(),
      OpNumber::with(2),
      "requests are dropped while a checkpoint-persist is in flight (the op-reset defense) — commit held at 2"
    );
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(0),
      "the first checkpoint is still in flight"
    );

    // Drive the first (and only) in-flight checkpoint — staged at target_op=2 — to completion by
    // flushing its two writes. It advances checkpoint_op to 2 exactly (no second checkpoint started).
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb); // step 1 done → step 2 (root write) inflight
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb); // step 2 done → checkpoint advances to 2
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(2),
      "exactly one checkpoint completed at its staged op (2), no double-trigger"
    );
    assert_eq!(sb.state().checkpoint_op(), OpNumber::with(2));

    // Now the checkpoint is durable (no persist in flight), so the primary serves again. Resending
    // 3,4 commits them; commit_min reaches 4 → the boundary re-evaluates (4 >= checkpoint_op(2)+2) and
    // a SECOND checkpoint triggers at op 4 and completes. This proves the gate only suppressed the
    // OVERLAP, and that the serve-defense releases the moment the persist finishes.
    for rn in 3..=4 {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        req(rn),
      );
      e.handle_storage(now, &mut wal, &mut sb);
    }
    assert_eq!(
      e.commit(),
      OpNumber::with(4),
      "the primary serves again once the persist is durable (3,4 now commit)"
    );
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb); // snapshot done → root write
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb); // root done → checkpoint advances
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(4),
      "a fresh checkpoint runs once the prior one is durable (boundary re-evaluated at commit_min=4)"
    );
  }

  #[test]
  fn checkpoint_completes_in_one_drain_with_synchronous_superblock() {
    // The sim's real `InMemorySuperblock` completes ALL queued writes (including ones submitted
    // mid-drain) in a single `handle_storage`. `TestSb` models that. Confirm the whole 3-step
    // sequence completes in the single drain that commits the boundary op — this is the path the
    // sim `Cluster` exercises each tick, so a long-enough sim run checkpoints.
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
    let mut e = Endpoint::new(cfg, 0, EchoSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    let req = |rn: u64| {
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      ))
    };
    for rn in 1..=2 {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        req(rn),
      );
      e.handle_storage(now, &mut wal, &mut sb);
    }
    assert_eq!(e.commit(), OpNumber::with(2));
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(2),
      "synchronous superblock completes both checkpoint writes in the boundary-commit drain"
    );
    assert_eq!(sb.state().checkpoint_op(), OpNumber::with(2));
    assert_ne!(sb.state().checkpoint_id(), 0);
  }

  #[test]
  fn checkpoint_gcs_wal_and_maps_below_the_quorum_checkpoint() {
    // M3.4b GC: once a checkpoint is durable, the WAL slots + in-memory caches below the prune floor
    // are freed. Single replica (quorum 1) → quorum_checkpoint_op == self.checkpoint_op, so the floor
    // is the checkpoint op (2): ops <= 2 are pruned from the WAL and the log/inflight caches, while a
    // NEW request still commits (apply reads from commit_min, not from a pruned op).
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
    let mut e = Endpoint::new(cfg, 0, EchoSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    let req = |rn: u64| {
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      ))
    };
    for rn in 1..=2 {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        req(rn),
      );
      e.handle_storage(now, &mut wal, &mut sb); // append durable → commit; on op 2, checkpoint completes
    }
    assert_eq!(e.checkpoint_op(), OpNumber::with(2));
    // Quorum=1 → prune floor = checkpoint_op = 2 → ops <= 2 are freed from the WAL.
    assert!(
      wal.header(OpNumber::with(1)).is_none(),
      "op 1 pruned from the WAL"
    );
    assert!(
      wal.header(OpNumber::with(2)).is_none(),
      "op 2 pruned from the WAL"
    );
    // The in-memory log + inflight caches are trimmed to (floor .. head] = empty here (head == 2).
    assert_eq!(
      e.min_log_op(),
      None,
      "log cache trimmed entirely below the checkpoint (nothing above op 2 yet)"
    );
    assert_eq!(e.log_len(), 0, "log cache empty after the prune");
    assert_eq!(
      e.inflight_len(),
      0,
      "inflight cache trimmed below the checkpoint"
    );
    // A NEW request still commits (op 3) — the SM applies from commit_min, not from a pruned op.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(3),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.commit(),
      OpNumber::with(3),
      "commit continues past the pruned checkpoint"
    );
    assert_eq!(
      e.min_log_op(),
      Some(3),
      "op 3 is cached above the floor; the pruned prefix stays gone"
    );
  }

  #[test]
  fn backup_gcs_below_its_own_checkpoint_even_without_quorum_reports() {
    // A backup never collects PrepareOks, so its `quorum_checkpoint_op` would be 0 (peers default 0)
    // — if GC used the quorum floor on a backup, the backup would never prune and its WAL/log would
    // grow unbounded. M3.4b's asymmetric floor lets a BACKUP prune below its OWN durable checkpoint
    // (those ops are in its snapshot; a laggard below it state-syncs). This test drives a backup
    // (replica 1 of 3) to a durable checkpoint via Prepares + Commits and asserts it pruned.
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
    let mut e = Endpoint::new(cfg, 0, EchoSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // The backup has heard from no peers → its quorum_checkpoint_op is 0 (conservative).
    assert_eq!(e.quorum_checkpoint_op(), OpNumber::with(0));
    // Append ops 1,2 via Prepares from the primary (replica 0, view 0), pumping the durable append.
    for op in 1..=2u64 {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Replica(ReplicaId::new(0)),
        Message::Prepare(Prepare::new(
          View::new(),
          OpNumber::with(op),
          OpNumber::with(op - 1), // commit lags by one so each Prepare also commits the prior op
          OpNumber::new(),        // primary's checkpoint_op (0; irrelevant here)
          ClientId::new(7),
          RequestNumber::with(op),
          Bytes::from(std::vec![op as u8]),
        )),
      );
      e.handle_storage(now, &mut wal, &mut sb);
    }
    // Commit op 2 so the backup's commit_min reaches the boundary and it checkpoints.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(e.commit(), OpNumber::with(2), "backup committed op 2");
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(2),
      "backup took a durable checkpoint at op 2"
    );
    // The backup's quorum floor is STILL 0: N=3 needs 2 replicas to report a checkpoint, but only
    // self reports 2 (peers default 0) → the quorum-th-highest is 0. This is exactly why a backup
    // cannot use the quorum floor (it would never prune). It pruned below its OWN checkpoint instead.
    assert_eq!(
      e.quorum_checkpoint_op(),
      OpNumber::with(0),
      "the backup's quorum floor is 0 (only self reports a checkpoint) — yet it still pruned"
    );
    assert!(
      wal.header(OpNumber::with(1)).is_none() && wal.header(OpNumber::with(2)).is_none(),
      "a backup prunes its WAL below its own checkpoint (boundedness), no quorum reports needed"
    );
    assert_eq!(
      e.log_len(),
      0,
      "backup log cache trimmed below its own checkpoint"
    );
  }

  #[test]
  fn recover_restores_from_the_durable_checkpoint_not_op_zero() {
    // A single-replica primary commits past a checkpoint (checkpoint_ops=2), so the checkpoint is
    // durable; then it "crashes". recover() MUST restore the SM from the checkpoint snapshot and set
    // commit_min == checkpoint_op (NOT 0) — re-applying [1..=checkpoint_op] would double-apply.
    // (M3.2a never prunes the WAL — Task 5/GC is deferred — so the WAL still holds ops [1..=head];
    //  the log cache is rebuilt for the tail (checkpoint_op..=head] only, the snapshot owns the rest.)
    let cfg = || Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    let req = |rn: u64| {
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      ))
    };
    let mut e = Endpoint::new(cfg(), 0, CountSm::default());
    for rn in 1..=2 {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        req(rn),
      );
      e.handle_storage(now, &mut wal, &mut sb); // append durable → commit → (at op 2) checkpoint
    }
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(2),
      "checkpoint is durable"
    );
    assert_eq!(
      e.state_machine().applied().len(),
      2,
      "the live SM applied ops 1,2 before the crash"
    );
    drop(e); // crash

    // recover() restores from the checkpoint snapshot, NOT by replaying from op 0. The consensus
    // metadata (commit/checkpoint/op) is set synchronously in Phase 1; the SM snapshot restore
    // happens in the Recovering handle_storage loop (Phase 2), so pump it before the SM asserts.
    let mut recovered = Endpoint::recover(cfg(), 0, CountSm::default(), &mut wal, &mut sb);
    assert_eq!(recovered.status(), Status::Recovering);
    assert_eq!(
      recovered.commit(),
      OpNumber::with(2),
      "commit_min restored to the checkpoint op, not 0"
    );
    assert_eq!(
      recovered.checkpoint_op(),
      OpNumber::with(2),
      "checkpoint_op restored from the durable root"
    );
    assert_eq!(
      recovered.op(),
      OpNumber::with(2),
      "op restored from the WAL head (head >= commit_min == checkpoint_op)"
    );
    // commit_max is restored to checkpoint_op too (monotone bounds: op >= commit_max >= commit_min).
    assert_eq!(recovered.commit_max(), OpNumber::with(2));
    recovered.handle_storage(now, &mut wal, &mut sb); // restore the SM snapshot + tail bodies → Normal
    assert_eq!(recovered.status(), Status::Normal);
    // The SM was restored from the snapshot: it already reflects ops 1,2 (NOT re-applied → exactly 2).
    assert_eq!(
      recovered.state_machine().applied().len(),
      2,
      "SM restored from the checkpoint snapshot (no double-apply)"
    );
    assert_eq!(
      recovered.state_machine().applied(),
      &[(1u64, std::vec![1u8]), (2u64, std::vec![2u8])],
      "the restored SM reflects exactly the checkpointed applied prefix"
    );
  }

  /// A superblock whose `state()` names a durable checkpoint at op 2 with a FIXED content id, and whose
  /// checkpoint reads return a SCRIPTED sequence of snapshots (front of the queue first). Used to model
  /// a torn/stale/corrupt checkpoint read during recover: the first read can return wrong bytes/op, a
  /// later one the correct snapshot — so the recover path can be observed to REJECT the bad read (no
  /// restore), retry, then restore from the good read. Writes are not exercised here.
  ///
  /// Reads complete LAZILY (like `StepSb`): a read submitted during a `handle_storage` drain does NOT
  /// complete in that same drain — its response queues in `inflight` and surfaces on the NEXT `poll`
  /// round. This lets a retry submitted mid-drain be observed on the following drain (rather than the
  /// whole script collapsing into one synchronous drain), so each reject→retry step is distinct.
  struct ScriptedCheckpointSb {
    state: VsrState,
    reads: VecDeque<(OpNumber, Bytes)>,
    ready: VecDeque<SuperblockDone>,
    inflight: VecDeque<SuperblockDone>,
  }
  impl Superblock for ScriptedCheckpointSb {
    fn state(&self) -> VsrState {
      self.state
    }
    fn submit_write(&mut self, id: OpId, state: VsrState) {
      self.state = state;
      self.inflight.push_back(SuperblockDone::Wrote(id));
    }
    fn submit_write_checkpoint(&mut self, id: OpId, _op: OpNumber, _snapshot: Bytes) {
      self.inflight.push_back(SuperblockDone::Wrote(id));
    }
    fn submit_read_checkpoint(&mut self, id: OpId) {
      // Pop the next scripted response; if the script is exhausted, fault (forces the budget path).
      let done = match self.reads.pop_front() {
        Some((op, snap)) => SuperblockDone::CheckpointRead(CheckpointRead::new(id, op, snap)),
        None => SuperblockDone::Fault(id),
      };
      self.inflight.push_back(done); // completes on the NEXT poll round, not this drain
    }
    fn poll(&mut self) -> Option<SuperblockDone> {
      self.ready.pop_front()
    }
  }
  impl ScriptedCheckpointSb {
    fn new(state: VsrState, reads: VecDeque<(OpNumber, Bytes)>) -> Self {
      Self {
        state,
        reads,
        ready: VecDeque::new(),
        inflight: VecDeque::new(),
      }
    }
    /// Make currently-inflight reads available to the next `poll` (mirrors `StepSb::flush`).
    fn flush(&mut self) {
      while let Some(done) = self.inflight.pop_front() {
        self.ready.push_back(done);
      }
    }
  }

  #[test]
  fn recover_rejects_a_mismatched_checkpoint_read_and_retries_then_restores() {
    // SAFETY REGRESSION (recover trusted an unverified checkpoint read): a `CheckpointRead` matching the
    // read id but whose CONTENT does not match the durable root (`sb.state()`) — wrong content hash or
    // wrong op — must be REJECTED (not restored) and retried within the recover budget, exactly like a
    // transient fault. Restoring a stale/corrupt snapshot while `commit_min == checkpoint_op` would be
    // silent committed-prefix loss. Here the FIRST read returns corrupt bytes (hash mismatch), the
    // SECOND returns bytes with the wrong op, and only the THIRD is the genuine snapshot.
    // The SM tail must be a VALID CountSm snapshot (an empty one = 8 zero bytes for the count), so the
    // restore on the genuine read succeeds; the verify logic under test is independent of the payload.
    let good_snap = CountSm::default().snapshot();
    let good_env =
      Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
    let good_id = crate::checkpoint_id(&good_env);
    // Durable root: checkpoint at op 2, naming the GOOD envelope's content id.
    let state = VsrState::try_new(
      View::new(),
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      good_id,
    )
    .unwrap();
    let mut sb = ScriptedCheckpointSb::new(
      state,
      VecDeque::from(std::vec![
        // (1) right op, WRONG bytes (hash mismatch) → rejected.
        (OpNumber::with(2), Bytes::from_static(b"CORRUPT")),
        // (2) right bytes, WRONG op (2 expected) → rejected.
        (OpNumber::with(99), good_env.clone()),
        // (3) the genuine snapshot → accepted.
        (OpNumber::with(2), good_env.clone()),
      ]),
    );
    // An empty WAL with head == checkpoint_op (2): the recover tail range (3..=2) is empty, so the ONLY
    // outstanding read is the checkpoint read — isolating the verify-and-retry behaviour.
    let mut wal = TestWal {
      entries: BTreeMap::new(),
      head: 2,
      done: VecDeque::new(),
    };
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
    let now = Instant::ZERO;
    let mut e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
    assert_eq!(e.status(), Status::Recovering);
    assert_eq!(
      e.commit(),
      OpNumber::with(2),
      "commit_min set to the checkpoint op"
    );

    // Drain #1: the corrupt-bytes read is REJECTED — SM not restored, still Recovering, a new read armed.
    sb.flush(); // release the Phase-1 checkpoint read (the corrupt one)
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.state_machine().applied().len(),
      0,
      "a hash-mismatched read must NOT restore the SM"
    );
    assert_eq!(
      e.status(),
      Status::Recovering,
      "still recovering after rejecting the corrupt read (retry armed)"
    );

    // Drain #2: the wrong-op read is REJECTED too — still no restore, still Recovering.
    sb.flush(); // release the retry read submitted in drain #1 (the wrong-op one)
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.state_machine().applied().len(),
      0,
      "a wrong-op read must NOT restore the SM"
    );
    assert_eq!(
      e.status(),
      Status::Recovering,
      "still recovering after the wrong-op read"
    );

    // Drain #3: the genuine read is accepted → SM restored, recovery completes to Normal.
    sb.flush(); // release the retry read submitted in drain #2 (the genuine one)
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.status(),
      Status::Normal,
      "recovery completes once a VERIFIED checkpoint read lands"
    );
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(2),
      "recovered at the durable checkpoint"
    );
  }

  #[test]
  fn recover_does_not_panic_on_a_truncated_checkpoint_read() {
    // SAFETY: a truncated/malformed snapshot whose bytes pass NEITHER the hash nor parse must be
    // treated as a fault (decode → None), NOT panic recovery. We script a single garbage read followed
    // by the genuine one: the garbage is rejected (no panic, no restore), then recovery completes.
    // The SM tail must be a VALID CountSm snapshot (an empty one = 8 zero bytes for the count), so the
    // restore on the genuine read succeeds; the verify logic under test is independent of the payload.
    let good_snap = CountSm::default().snapshot();
    let good_env =
      Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
    let good_id = crate::checkpoint_id(&good_env);
    let state = VsrState::try_new(
      View::new(),
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      good_id,
    )
    .unwrap();
    let mut sb = ScriptedCheckpointSb::new(
      state,
      VecDeque::from(std::vec![
        // A 2-byte garbage snapshot: too short even for the 8-byte leading op → decode returns None.
        (OpNumber::with(2), Bytes::from_static(&[0xAB, 0xCD])),
        (OpNumber::with(2), good_env.clone()),
      ]),
    );
    let mut wal = TestWal {
      entries: BTreeMap::new(),
      head: 2,
      done: VecDeque::new(),
    };
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
    let now = Instant::ZERO;
    let mut e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
    // Drain #1: the truncated read does NOT panic — it is rejected; still Recovering.
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.status(),
      Status::Recovering,
      "a truncated snapshot is a fault (decode None), not a panic"
    );
    assert_eq!(
      e.state_machine().applied().len(),
      0,
      "nothing restored from garbage bytes"
    );
    // Drain #2: the genuine read completes recovery.
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.status(),
      Status::Normal,
      "recovery completes on the valid read"
    );
  }

  #[test]
  fn recover_escalates_to_a_peer_fetch_when_its_own_checkpoint_is_permanently_unreadable() {
    // F1 REGRESSION (a permanently-corrupt own checkpoint must NOT panic recovery): when this replica's
    // OWN durable checkpoint snapshot read back unreadable/mismatched on EVERY attempt, the OLD code hit
    // an `assert!` once the per-op retry budget exhausted — crashing the replica on storage-controlled
    // bytes (a faulty/malicious superblock could do this at will). The fix ESCALATES to fetching the
    // checkpoint from a peer via state-sync (a forced sync + a `RequestSync`), staying in a recoverable
    // fault state, and completes recovery once a verified peer `SyncCheckpoint` restores the SM.
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
    let now = Instant::ZERO;
    // Durable root: a checkpoint at op 2 naming SOME id. The scripted superblock has an EMPTY read
    // script, so EVERY `submit_read_checkpoint` FAULTS — a permanently-unreadable snapshot.
    let state = VsrState::try_new(
      View::new(),
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      0xDEAD_BEEF,
    )
    .unwrap();
    let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new()); // empty → always faults
    // Empty WAL with head == checkpoint_op (2): the tail range is empty, isolating the checkpoint path.
    let mut wal = TestWal {
      entries: BTreeMap::new(),
      head: 2,
      done: VecDeque::new(),
    };
    let mut e = Endpoint::recover(cfg, 5, CountSm::default(), &mut wal, &mut sb);
    assert_eq!(e.status(), Status::Recovering);

    // Drive well past the per-op retry budget (RECOVER_READ_RETRIES). Each round: flush the inflight
    // fault, then drain. The CORE property: this NEVER panics (the old `assert!` is gone).
    for _ in 0..(RECOVER_READ_RETRIES as usize + 4) {
      sb.flush();
      e.handle_storage(now, &mut wal, &mut sb);
    }
    // After exhaustion the replica escalated to a peer fetch: still Recovering (SM not yet restored —
    // never silently Normal with a fresh SM at commit_min == 2), awaiting a peer checkpoint, with a
    // FORCED sync armed at our own checkpoint op and a RequestSync emitted.
    assert_eq!(
      e.status(),
      Status::Recovering,
      "a permanently-unreadable own checkpoint does NOT complete recovery (and does NOT panic)"
    );
    assert!(
      e.awaiting_peer_checkpoint_for_test(),
      "the replica escalated to fetching the checkpoint from a peer"
    );
    assert!(
      e.sync_is_forced_for_test(),
      "a FORCED sync was armed for the peer fetch"
    );
    assert_eq!(
      e.sync_target_for_test(),
      Some(2),
      "the forced sync targets our own checkpoint op (a peer >= it answers)"
    );
    assert_eq!(
      e.state_machine().applied().len(),
      0,
      "nothing restored from the unreadable snapshot"
    );
    let mut saw_request_sync = false;
    while let Some(out) = e.poll_message() {
      if let Message::RequestSync(_) = out.msg_ref() {
        saw_request_sync = true;
      }
    }
    assert!(
      saw_request_sync,
      "the replica solicited a peer checkpoint (RequestSync)"
    );

    // A peer answers with a VALID SyncCheckpoint (op 2, the genuine snapshot, matching nonce). The
    // recovering replica accepts it (the relaxed guard), restores the SM, durably re-persists, and
    // completes recovery to Normal.
    let good_snap = CountSm::default().snapshot();
    let good_env =
      Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
    let good_id = crate::checkpoint_id(&good_env);
    let nonce = e.sync_nonce_for_test();
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(2),
        good_id,
        ReplicaId::new(0),
        nonce,
        good_env.clone(),
      )),
    );
    // apply_sync staged the durable re-persist (two superblock writes); drive them to completion.
    for _ in 0..3 {
      sb.flush();
      e.handle_storage(now, &mut wal, &mut sb);
    }
    assert_eq!(
      e.status(),
      Status::Normal,
      "a verified peer SyncCheckpoint completes recovery to Normal"
    );
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(2),
      "recovered at the peer's checkpoint op"
    );
    assert!(
      !e.awaiting_peer_checkpoint_for_test(),
      "the peer-fetch latch is cleared on success"
    );
    assert_eq!(
      e.sync_target_for_test(),
      None,
      "the sync is cleared once the synced checkpoint is durable"
    );
    assert_eq!(
      e.forced_syncs_applied(),
      1,
      "the recovery peer-fetch routed through apply_sync as a FORCED state-sync"
    );
  }

  #[test]
  fn recover_does_not_panic_when_a_mismatched_checkpoint_read_always_faults_then_a_peer_serves() {
    // F1 REGRESSION (variant): the checkpoint read MATCHES our read id but its CONTENT is permanently
    // wrong (hash mismatch on every attempt) — the verify-failure path, not a raw Fault. It must route
    // to the SAME budget→peer-fetch escalation (no panic), then a peer's good SyncCheckpoint completes.
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
    let now = Instant::ZERO;
    let good_snap = CountSm::default().snapshot();
    let good_env =
      Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
    let good_id = crate::checkpoint_id(&good_env);
    // Durable root names the GOOD id at op 2, but every scripted read returns CORRUPT bytes (wrong
    // hash) — a permanently-inconsistent snapshot. Provide many corrupt reads (more than the budget).
    let state = VsrState::try_new(
      View::new(),
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      good_id,
    )
    .unwrap();
    let corrupt_reads: VecDeque<(OpNumber, Bytes)> = (0..(RECOVER_READ_RETRIES as usize + 6))
      .map(|_| (OpNumber::with(2), Bytes::from_static(b"CORRUPT")))
      .collect();
    let mut sb = ScriptedCheckpointSb::new(state, corrupt_reads);
    let mut wal = TestWal {
      entries: BTreeMap::new(),
      head: 2,
      done: VecDeque::new(),
    };
    let mut e = Endpoint::recover(cfg, 5, CountSm::default(), &mut wal, &mut sb);
    for _ in 0..(RECOVER_READ_RETRIES as usize + 8) {
      sb.flush();
      e.handle_storage(now, &mut wal, &mut sb); // must NOT panic on the verify-failure exhaustion
    }
    assert_eq!(
      e.status(),
      Status::Recovering,
      "no panic; escalated to peer fetch"
    );
    assert!(e.awaiting_peer_checkpoint_for_test());
    let nonce = e.sync_nonce_for_test();
    while e.poll_message().is_some() {}
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(2),
        good_id,
        ReplicaId::new(0),
        nonce,
        good_env.clone(),
      )),
    );
    for _ in 0..3 {
      sb.flush();
      e.handle_storage(now, &mut wal, &mut sb);
    }
    assert_eq!(
      e.status(),
      Status::Normal,
      "recovery completes once a peer serves the genuine checkpoint"
    );
  }

  #[test]
  fn recover_with_no_checkpoint_is_unchanged() {
    // Backward-compat guard: with checkpoint_op == 0 (no checkpoint yet), recover() behaves EXACTLY
    // as the M3.1b path — commit_min == commit_max == 0, a fresh SM (0 applied), log cache [1..=head].
    let cfg = || Config::try_new(1, ReplicaId::new(1), 3).unwrap();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    let mut e = Endpoint::new(cfg(), 0, CountSm::default());
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(e.checkpoint_op(), OpNumber::with(0), "no checkpoint taken");
    drop(e);

    let mut recovered = Endpoint::recover(cfg(), 0, CountSm::default(), &mut wal, &mut sb);
    assert_eq!(recovered.status(), Status::Recovering);
    recovered.handle_storage(now, &mut wal, &mut sb); // drain the tail reads → Normal
    assert_eq!(recovered.status(), Status::Normal);
    assert_eq!(recovered.op(), OpNumber::with(2), "op from the WAL head");
    assert_eq!(
      recovered.commit(),
      OpNumber::with(0),
      "no checkpoint → commit_min stays 0 (M3.1b behavior)"
    );
    assert_eq!(recovered.commit_max(), OpNumber::with(0));
    assert_eq!(recovered.checkpoint_op(), OpNumber::with(0));
    assert_eq!(
      recovered.state_machine().applied().len(),
      0,
      "no checkpoint → fresh SM, nothing restored/applied"
    );
  }

  #[test]
  fn recover_bounds_the_read_window_for_a_huge_op_head() {
    // F3 REGRESSION (unbounded read submission): a corrupt/buggy `Wal` reporting an enormous
    // `op_head` must NOT make `recover()` bookkeep + submit a read per slot from `checkpoint_op+1`
    // up to that head (billions of inserts/reads/allocations before any async fault-handling runs).
    // With the fix, the per-recover window is capped at `RECOVER_TAIL_WINDOW`, so at most that many
    // reads are submitted regardless of the claimed head. (Before the fix this loops ~u64::MAX times
    // and never returns.)
    let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
    let mut wal = TestWal {
      entries: BTreeMap::new(),
      head: u64::MAX, // a pathological / bit-rotted head
      done: VecDeque::new(),
    };
    let mut sb = TestSb::default(); // no checkpoint (checkpoint_op == 0) → no checkpoint read
    let e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
    assert_eq!(e.status(), Status::Recovering);
    // `recover()` submits exactly one read per materialized tail slot, each queued in the WAL's
    // `done` buffer. The count must be bounded by the window, never the claimed head.
    assert!(
      wal.done.len() as u64 <= RECOVER_TAIL_WINDOW,
      "recover submitted {} reads — must be capped at RECOVER_TAIL_WINDOW ({RECOVER_TAIL_WINDOW})",
      wal.done.len()
    );
    assert_eq!(
      wal.done.len() as u64,
      RECOVER_TAIL_WINDOW,
      "with a head far above the window, exactly RECOVER_TAIL_WINDOW slots are materialized"
    );
  }

  #[test]
  fn recover_does_not_overflow_with_a_checkpoint_op_near_u64_max() {
    // F3 REGRESSION (overflow): `checkpoint_op + 1` and `checkpoint_op + RECOVER_TAIL_WINDOW` must use
    // SATURATING arithmetic so a `checkpoint_op` near `u64::MAX` (a corrupt durable root) cannot
    // overflow-panic while computing the tail window. Here the durable root claims a checkpoint at
    // `u64::MAX - 1` and the WAL head equals it, so the tail range is empty — recovery must construct
    // cleanly (no panic) with no tail reads. (The checkpoint READ itself faults — no snapshot — which
    // the budget/peer-fetch path handles; we only assert the constructor does not overflow.)
    let near_max = u64::MAX - 1;
    let state = VsrState::try_new(
      View::new(),
      View::new(),
      OpNumber::with(near_max),
      OpNumber::with(near_max),
      0,
    )
    .unwrap();
    let mut sb = TestSb {
      state,
      done: VecDeque::new(),
      checkpoint: None, // the checkpoint read will fault (no snapshot) — not under test here
    };
    let mut wal = TestWal {
      entries: BTreeMap::new(),
      head: near_max, // head == checkpoint_op → empty tail range
      done: VecDeque::new(),
    };
    let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
    // The CORE assertion is simply that this does not overflow-panic.
    let e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
    assert_eq!(e.status(), Status::Recovering);
    assert_eq!(
      wal.done.len(),
      0,
      "head == checkpoint_op → the tail range is empty, no tail reads submitted"
    );
  }

  #[test]
  fn recover_op_stays_at_the_verified_frontier_not_the_raw_head() {
    // F1 REGRESSION (a SAFETY regression introduced by the R2 read-window cap): the R2 fix capped the
    // recover READ window at `checkpoint_op + RECOVER_TAIL_WINDOW` but still set `self.op =
    // head.max(checkpoint_op)` (the RAW head). When `head` is far above the window, ops in `(frontier,
    // head]` are "held" per `self.op` yet were NEVER read/verified/cached — so `on_prepare`'s `pop <=
    // self.op` branch would BLIND-RE-ACK them without consulting `self.log`, voting for ops never
    // durably appended (append-before-ack broken → a committed op can be lost if the primary counted
    // that false ack and then died). With the fix `self.op` is the VERIFIED read frontier `hi`, so an
    // op above it is NOT held and a later `Prepare` for it APPENDS (idempotent re-send) before any ack.
    let checkpoint_op = 2u64;
    let frontier = checkpoint_op + RECOVER_TAIL_WINDOW;
    let head = frontier + 1000; // a pathological / bit-rotted head FAR above the read window
    // A CountSm checkpoint at op 2 (applied ops 1,2) + its envelope, with the durable root naming it.
    let mut donor_sm = CountSm::default();
    donor_sm.apply(OpNumber::with(1), &[1]);
    donor_sm.apply(OpNumber::with(2), &[2]);
    let env = Endpoint::<CountSm>::encode_checkpoint(
      OpNumber::with(checkpoint_op),
      &BTreeMap::new(),
      &donor_sm.snapshot(),
    );
    let id = crate::checkpoint_id(&env);
    let state = VsrState::try_new(
      View::new(),
      View::new(),
      OpNumber::with(checkpoint_op),
      OpNumber::with(checkpoint_op),
      id,
    )
    .unwrap();
    // A WAL whose head is the pathological value, but which actually HOLDS only the in-window tail
    // `(checkpoint_op ..= frontier]` (reads above the frontier are never submitted). Each tail header is
    // a current-view (view 0) entry so a later Prepare at `frontier+1` is contiguous with the frontier.
    let mut entries = BTreeMap::new();
    for op in (checkpoint_op + 1)..=frontier {
      let h = Header::new(
        OpNumber::with(op),
        View::new(),
        ClientId::new(7),
        RequestNumber::with(op),
        &[op as u8],
      );
      entries.insert(op, (h, Bytes::from(std::vec![op as u8])));
    }
    let mut wal = TestWal {
      entries,
      head,
      done: VecDeque::new(),
    };
    let mut sb = TestSb {
      state,
      done: VecDeque::new(),
      checkpoint: Some((OpNumber::with(checkpoint_op), env)),
    };
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, RECOVER_TAIL_WINDOW).unwrap();
    let now = Instant::ZERO;
    let mut e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
    // THE core assertion: the recovered head is the VERIFIED read frontier, NOT the raw head.
    assert_eq!(
      e.op(),
      OpNumber::with(frontier),
      "recover holds the verified read frontier, never the raw (pathological) head"
    );
    assert_ne!(e.op(), OpNumber::with(head), "must NOT hold the raw head");
    // Drive the in-window tail reads + the checkpoint read to completion → Normal.
    while e.status() != Status::Normal {
      e.handle_storage(now, &mut wal, &mut sb);
    }
    assert_eq!(
      e.op(),
      OpNumber::with(frontier),
      "frontier preserved into Normal"
    );
    while e.poll_message().is_some() {} // drain everything emitted during recovery

    // A `Prepare` for an op in `(frontier, head]` (here `frontier+1`) must be APPENDED, not blind
    // re-acked: it is `== self.op + 1`, so it takes the append branch. Observable: `self.op` ADVANCES
    // to it (a re-ack would leave op unchanged) and the durable WAL gains the entry; the PrepareOk is
    // DEFERRED to the append completion (no immediate PrepareOk is emitted before the WAL append lands).
    let danger = frontier + 1;
    let p = Prepare::new(
      View::new(),
      OpNumber::with(danger),
      OpNumber::with(frontier), // commit (does not advance past held)
      OpNumber::with(checkpoint_op),
      ClientId::new(7),
      RequestNumber::with(danger),
      Bytes::from(std::vec![0xAB]),
    );
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), Message::Prepare(p));
    assert_eq!(
      e.op(),
      OpNumber::with(danger),
      "a Prepare above the frontier is APPENDED (op advances), not blind-re-acked",
    );
    assert!(
      wal.entries.contains_key(&danger),
      "the durable WAL gained the appended op (append-before-ack honored)",
    );
    // No PrepareOk for `danger` is emitted yet — it is deferred until the WAL append completes (a blind
    // re-ack would have emitted one INLINE, before the op was durable).
    let premature_ack = {
      let mut found = false;
      while let Some(out) = e.poll_message() {
        if let Message::PrepareOk(ok) = out.msg_ref() {
          if ok.op() == OpNumber::with(danger) {
            found = true;
          }
        }
      }
      found
    };
    assert!(
      !premature_ack,
      "no PrepareOk before the append is durable — the false-re-ack path is closed",
    );
  }

  #[test]
  fn view_change_preserves_the_durable_checkpoint_pointer() {
    // SAFETY REGRESSION GUARD: a view-change durable-view write must NOT regress the durable
    // checkpoint_op to 0 (that would, once the WAL below it is GC'd in Task 5, lose committed ops on
    // recovery). Drive a single-replica primary to a durable checkpoint at op 2, then force a view
    // change (escalate to view 1) and let its durable-view write land; the durable root must still
    // name checkpoint_op=2 with its original id.
    use crate::StartViewChange;
    // N=3 so a view change is reachable, but checkpoint_ops=2 and we commit 2 ops as primary first.
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, 2).unwrap();
    let mut e = Endpoint::new(cfg, 0, EchoSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    let req = |rn: u64| {
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      ))
    };
    // Commit 2 ops with a 2-of-3 quorum (replica 1 acks), so commit_min reaches 2 and a checkpoint
    // is taken. The primary's own append + replica 1's PrepareOk = quorum 2.
    for rn in 1..=2 {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        req(rn),
      );
      e.handle_storage(now, &mut wal, &mut sb); // primary's own append durable (own vote)
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Replica(ReplicaId::new(1)),
        Message::PrepareOk(PrepareOk::new(
          View::new(),
          OpNumber::with(rn),
          ReplicaId::new(1),
          OpNumber::new(),
        )),
      );
      e.handle_storage(now, &mut wal, &mut sb); // drain any checkpoint writes
    }
    assert_eq!(e.commit(), OpNumber::with(2));
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(2),
      "checkpoint is durable at op 2"
    );
    let id_before = sb.state().checkpoint_id();
    assert_ne!(id_before, 0);

    // Force a view change: two peers send StartViewChange(view 1) → SVC quorum → ViewChange(1),
    // which submits a durable-view write. Pump it.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(1))),
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
    );
    assert_eq!(e.status(), Status::ViewChange);
    e.handle_storage(now, &mut wal, &mut sb); // the durable-view write completes
    assert_eq!(
      sb.state().checkpoint_op(),
      OpNumber::with(2),
      "the view-change durable-view write must PRESERVE the checkpoint_op (not regress to 0)"
    );
    assert_eq!(
      sb.state().checkpoint_id(),
      id_before,
      "and preserve the matching checkpoint id"
    );
    // The in-memory checkpoint_op is likewise unchanged by the view change.
    assert_eq!(e.checkpoint_op(), OpNumber::with(2));
  }

  #[test]
  fn primary_tracks_quorum_checkpoint_op() {
    // N=3, quorum=2. Primary self.checkpoint_op=0. Backups report checkpoints 5 and 3 via PrepareOk.
    // self(0)=0, r1=5, r2=3 → sorted desc [5,3,0]; the quorum(2)-th highest (index 1) is 3 — the
    // highest op a quorum (2 of 3) has reported checkpointing.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // A fresh primary in Normal view 0 with no peers heard from has quorum_checkpoint_op == 0.
    assert_eq!(e.quorum_checkpoint_op(), OpNumber::new());
    // Quorum-checkpoint tracking is independent of inflight: the ok is recorded for its replica even
    // without a matching inflight op (the replica-id range check is the only guard).
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(1),
        ReplicaId::new(1),
        OpNumber::with(5),
      )),
    );
    // Only one backup heard from: self(0)=0, r1=5, r2=unheard(0) → desc [5,0,0] → index 1 = 0.
    assert_eq!(
      e.quorum_checkpoint_op(),
      OpNumber::new(),
      "one backup is not yet a quorum-checkpoint above 0"
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(1),
        ReplicaId::new(2),
        OpNumber::with(3),
      )),
    );
    assert_eq!(e.quorum_checkpoint_op(), OpNumber::with(3));
  }

  #[test]
  fn quorum_checkpoint_op_single_replica_is_self() {
    // N=1, quorum=1 → the quorum checkpoint is exactly self's checkpoint (no peers to wait for).
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
    let mut e = Endpoint::new(cfg, 0, EchoSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    assert_eq!(e.quorum_checkpoint_op(), OpNumber::new());
    let req = |rn: u64| {
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      ))
    };
    for rn in 1..=2 {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        req(rn),
      );
      e.handle_storage(now, &mut wal, &mut sb);
    }
    assert_eq!(e.checkpoint_op(), OpNumber::with(2));
    assert_eq!(
      e.quorum_checkpoint_op(),
      OpNumber::with(2),
      "single-replica quorum checkpoint follows self's checkpoint"
    );
  }

  // ── M3.5 T1: monotone peer_checkpoint ──

  #[test]
  fn peer_checkpoint_is_monotone_under_reordering() {
    // A primary records a peer's checkpoint_op, then a REORDERED older report arrives. The recorded
    // value must NOT regress — the GC floor + the force-sync trigger that read `quorum_checkpoint_op`
    // all rely on monotone per-peer checkpoints (a regressing floor could un-fire the escalation).
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 1, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(ep.is_primary(), "replica 0 is the view-0 primary");
    // A PrepareOk from replica 1 reporting checkpoint_op = 8.
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(1),
        ReplicaId::new(1),
        OpNumber::with(8),
      )),
    );
    assert_eq!(ep.peer_checkpoint_for_test(1), 8);
    // A REORDERED older PrepareOk from replica 1 reporting checkpoint_op = 4 — must NOT regress.
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(1),
        ReplicaId::new(1),
        OpNumber::with(4),
      )),
    );
    assert_eq!(
      ep.peer_checkpoint_for_test(1),
      8,
      "a reordered older report must not regress the recorded peer checkpoint"
    );
  }

  #[test]
  fn on_commit_records_the_primary_checkpoint_monotonically() {
    // The backup-side record path (`on_commit`) is likewise monotone: a reordered older Commit from
    // the primary must not lower the recorded primary checkpoint.
    let mut e = sync_backup(); // replica 1 of 3, primary is replica 0
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(0),
        OpNumber::with(6),
      )),
    );
    assert_eq!(e.peer_checkpoint_for_test(0), 6);
    // A reordered older Commit (checkpoint 2) must not regress the recorded value.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(0),
        OpNumber::with(2),
      )),
    );
    assert_eq!(
      e.peer_checkpoint_for_test(0),
      6,
      "a reordered older Commit must not regress the recorded primary checkpoint"
    );
  }

  // ── State-sync (M3.4a) ──

  /// Drive a real 3-replica primary (replica 0) to a DURABLE checkpoint at `ckpt`, returning the
  /// endpoint + its storage so a test can read the checkpoint envelope back (the donor for sync apply
  /// tests). `checkpoint_ops == ckpt`, so committing `ckpt` ops takes exactly one checkpoint.
  fn donor_primary_at_checkpoint(ckpt: u64) -> (Endpoint<CountSm>, TestWal, TestSb) {
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, ckpt).unwrap();
    let mut e = Endpoint::new(cfg, 0, CountSm::default());
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    let req = |rn: u64| {
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      ))
    };
    for rn in 1..=ckpt {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        req(rn),
      );
      e.handle_storage(now, &mut wal, &mut sb); // primary's own append durable (own vote)
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Replica(ReplicaId::new(1)),
        Message::PrepareOk(PrepareOk::new(
          View::new(),
          OpNumber::with(rn),
          ReplicaId::new(1),
          OpNumber::new(),
        )),
      );
      e.handle_storage(now, &mut wal, &mut sb); // drain checkpoint writes
    }
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(ckpt),
      "donor checkpoint is durable"
    );
    (e, wal, sb)
  }

  /// Read the durable checkpoint envelope (+ its id) back from a donor's superblock.
  fn donor_envelope(sb: &TestSb) -> (Bytes, u128) {
    let (_op, env) = sb
      .checkpoint
      .clone()
      .expect("donor has a durable checkpoint snapshot");
    let id = sb.state().checkpoint_id();
    assert_eq!(
      crate::checkpoint_id(&env),
      id,
      "donor envelope hashes to its durable id"
    );
    (env, id)
  }

  /// Capture the nonce of the `RequestSync` a replica just emitted (and drain the rest).
  fn captured_sync_nonce(e: &mut Endpoint<CountSm>) -> u64 {
    let mut nonce = None;
    while let Some(out) = e.poll_message() {
      if let Message::RequestSync(r) = out.msg_ref() {
        nonce = Some(r.nonce());
      }
    }
    nonce.expect("a RequestSync was emitted")
  }

  // A backup over CountSm (replica 1 of 3) — the laggard in sync tests.
  fn sync_backup() -> Endpoint<CountSm> {
    Endpoint::new(
      Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap(),
      0,
      CountSm::default(),
    )
  }

  #[test]
  fn stale_checkpoint_commit_triggers_request_sync() {
    // replica 1 of 3, Normal, head op 0, checkpoint 0. A Commit advertising checkpoint_op=8 (> our
    // head) means the cluster checkpointed past our entire WAL → we must state-sync.
    let mut e = sync_backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(10),
        OpNumber::with(8),
      )),
    );
    let mut saw = None;
    while let Some(out) = e.poll_message() {
      if let Message::RequestSync(r) = out.msg_ref() {
        saw = Some(*r);
      }
    }
    let r = saw.expect("a stale-checkpoint replica broadcasts RequestSync");
    assert_eq!(
      r.checkpoint_op(),
      OpNumber::with(0),
      "advertises our stale checkpoint"
    );
    assert_eq!(r.replica(), ReplicaId::new(1));
    assert_eq!(
      e.status(),
      Status::Normal,
      "still Normal (sync is in-band, not a status)"
    );
  }

  #[test]
  fn stale_checkpoint_prepare_triggers_request_sync() {
    // A `Prepare` (not just a Commit) carrying checkpoint_op > our head also triggers the sync — the
    // A2 signal closes the last trigger gap for a backup that only ever hears Prepares.
    let mut e = sync_backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare_ck(9, 8, 8));
    let mut saw_sync = false;
    while let Some(out) = e.poll_message() {
      saw_sync |= out.msg_ref().is_request_sync();
    }
    assert!(
      saw_sync,
      "a Prepare advertising a far-ahead checkpoint triggers state-sync"
    );
  }

  #[test]
  fn in_reach_checkpoint_does_not_trigger_sync() {
    // checkpoint_op == our head (8) and we hold the tail → ordinary catch-up suffices, NO sync.
    let mut e = sync_backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    for op in 1..=8 {
      e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(op, 0));
      e.handle_storage(now, &mut wal, &mut sb);
    }
    while e.poll_message().is_some() {}
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(8),
        OpNumber::with(8),
      )),
    );
    let mut saw_sync = false;
    while let Some(out) = e.poll_message() {
      saw_sync |= out.msg_ref().is_request_sync();
    }
    assert!(!saw_sync, "checkpoint within our held log → no state-sync");
  }

  #[test]
  fn already_syncing_does_not_emit_a_second_handshake_per_heartbeat() {
    // Once a sync is outstanding, a second Commit only RAISES the target — it does not emit a fresh
    // RequestSync per heartbeat (only the timer re-solicits).
    let mut e = sync_backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(10),
        OpNumber::with(8),
      )),
    );
    let first: usize = {
      let mut n = 0;
      while let Some(out) = e.poll_message() {
        n += usize::from(out.msg_ref().is_request_sync());
      }
      n
    };
    assert_eq!(first, 1, "the trigger emits exactly one RequestSync");
    // A second heartbeat (even a higher checkpoint) must NOT emit another handshake immediately.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(12),
        OpNumber::with(10),
      )),
    );
    let second: usize = {
      let mut n = 0;
      while let Some(out) = e.poll_message() {
        n += usize::from(out.msg_ref().is_request_sync());
      }
      n
    };
    assert_eq!(
      second, 0,
      "a second heartbeat raises the target but emits no fresh handshake"
    );
  }

  #[test]
  fn primary_answers_request_sync_with_sync_checkpoint() {
    // A donor primary with a durable checkpoint at op 2 answers a lagging replica's RequestSync by
    // shipping a SyncCheckpoint with the right op/id/snapshot/nonce, addressed back to the requester.
    let (mut e, mut wal, mut sb) = donor_primary_at_checkpoint(2);
    let now = Instant::ZERO;
    while e.poll_message().is_some() {} // drain prepares/replies from the warm-up
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestSync(crate::RequestSync::new(
        e.view(),
        OpNumber::with(0),
        ReplicaId::new(2),
        0xCAFE,
        false, // ordinary state-sync (not a recovery peer-fetch)
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb); // the checkpoint read completes → ship SyncCheckpoint
    let mut shipped = None;
    while let Some(out) = e.poll_message() {
      if let Message::SyncCheckpoint(s) = out.msg_ref() {
        shipped = Some((out.to(), s.clone()));
      }
    }
    let (to, s) = shipped.expect("primary ships a SyncCheckpoint");
    assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(2))));
    assert_eq!(s.checkpoint_op(), OpNumber::with(2));
    assert_eq!(s.checkpoint_id(), sb.state().checkpoint_id());
    assert_eq!(s.nonce(), 0xCAFE);
    assert_eq!(
      crate::checkpoint_id(s.snapshot()),
      s.checkpoint_id(),
      "shipped snapshot provably matches its advertised id"
    );
  }

  #[test]
  fn peer_without_newer_checkpoint_does_not_answer_request_sync() {
    // A replica whose checkpoint == requester's (or 0) ships nothing (no megabyte for a no-op).
    let mut e = sync_backup(); // checkpoint 0
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::RequestSync(crate::RequestSync::new(
        e.view(),
        OpNumber::with(0),
        ReplicaId::new(0),
        1,
        false, // ordinary state-sync (not a recovery peer-fetch)
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert!(e.poll_message().is_none(), "nothing newer → silent");
  }

  #[test]
  fn recovery_request_sync_is_served_by_a_peer_at_the_same_checkpoint() {
    // F2 REGRESSION (recovery peer-fetch livelock): a recovering replica whose OWN checkpoint snapshot
    // is permanently corrupt solicits a RECOVERY RequestSync advertising its (known) checkpoint_op. The
    // R2 escalation only got served by a STRICTLY-newer peer (`>`), so on an idle cluster where every
    // healthy peer holds EXACTLY the same checkpoint_op, the request was ignored forever → the recovery
    // livelocked (the cluster could stay unavailable if that replica is needed for quorum). With the
    // fix, a `recovery` request is served by a peer at an EQUAL checkpoint_op; an ordinary one is not.
    let now = Instant::ZERO;
    // A donor that is Normal at checkpoint op 2.
    let (mut donor, mut wal, mut sb) = donor_primary_at_checkpoint(2);
    while donor.poll_message().is_some() {} // drain warm-up

    // (a) A RECOVERY request at the SAME checkpoint (op 2) IS served.
    donor.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestSync(crate::RequestSync::new(
        donor.view(),
        OpNumber::with(2), // EQUAL to the donor's checkpoint
        ReplicaId::new(2),
        0xF00D,
        true, // recovery peer-fetch
      )),
    );
    donor.handle_storage(now, &mut wal, &mut sb); // checkpoint read completes → ship SyncCheckpoint
    let mut served = None;
    while let Some(out) = donor.poll_message() {
      if let Message::SyncCheckpoint(s) = out.msg_ref() {
        served = Some((out.to(), s.clone()));
      }
    }
    let (to, s) = served.expect("a recovery request at an EQUAL checkpoint IS served");
    assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(2))));
    assert_eq!(s.checkpoint_op(), OpNumber::with(2));
    assert_eq!(s.nonce(), 0xF00D);

    // (b) An ORDINARY (non-recovery) request at the SAME checkpoint is NOT served (strict `>`).
    donor.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestSync(crate::RequestSync::new(
        donor.view(),
        OpNumber::with(2), // EQUAL to the donor's checkpoint
        ReplicaId::new(2),
        0xBEEF,
        false, // ordinary state-sync
      )),
    );
    donor.handle_storage(now, &mut wal, &mut sb);
    let mut ordinary_served = false;
    while let Some(out) = donor.poll_message() {
      if matches!(out.msg_ref(), Message::SyncCheckpoint(_)) {
        ordinary_served = true;
      }
    }
    assert!(
      !ordinary_served,
      "an ordinary RequestSync at an equal checkpoint is NOT served (no megabyte for a no-op)",
    );
  }

  #[test]
  fn recovery_peer_fetch_converges_against_an_equal_checkpoint_peer() {
    // F2 REGRESSION (end-to-end convergence): a replica whose OWN durable checkpoint snapshot is
    // permanently unreadable escalates to a recovery peer-fetch; a Normal peer at the SAME checkpoint
    // op serves it; delivering that SyncCheckpoint converges the recovering replica to Normal. (Before
    // the fix the equal-checkpoint peer ignored the request and the replica never left Recovering.)
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
    let now = Instant::ZERO;
    // Durable root names a checkpoint at op 2; the scripted SB has an EMPTY read script → every
    // checkpoint read FAULTS (permanently-unreadable own snapshot).
    let state = VsrState::try_new(
      View::new(),
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      0xDEAD_BEEF,
    )
    .unwrap();
    let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new());
    let mut wal = TestWal {
      entries: BTreeMap::new(),
      head: 2, // head == checkpoint_op → empty tail; isolates the checkpoint path
      done: VecDeque::new(),
    };
    let mut e = Endpoint::recover(cfg, 5, CountSm::default(), &mut wal, &mut sb);
    // Drive past the per-op retry budget so it escalates to a peer fetch.
    for _ in 0..(RECOVER_READ_RETRIES as usize + 4) {
      sb.flush();
      e.handle_storage(now, &mut wal, &mut sb);
    }
    assert_eq!(e.status(), Status::Recovering);
    assert!(e.awaiting_peer_checkpoint_for_test());
    // The escalation emits a RequestSync flagged `recovery` and advertising our own checkpoint op (2).
    let mut req = None;
    while let Some(out) = e.poll_message() {
      if let Message::RequestSync(r) = out.msg_ref() {
        req = Some(*r);
      }
    }
    let req = req.expect("a RequestSync was solicited");
    assert!(req.recovery(), "the recovery escalation flags the request");
    assert_eq!(
      req.checkpoint_op(),
      OpNumber::with(2),
      "advertises its own checkpoint op"
    );

    // A peer that is Normal at the SAME checkpoint op (2) serves this exact request.
    let (mut peer, mut pwal, mut psb) = donor_primary_at_checkpoint(2);
    while peer.poll_message().is_some() {}
    peer.handle_message(
      now,
      &mut pwal,
      &mut psb,
      Peer::Replica(ReplicaId::new(1)),
      Message::RequestSync(req),
    );
    peer.handle_storage(now, &mut pwal, &mut psb);
    let mut answer = None;
    while let Some(out) = peer.poll_message() {
      if let Message::SyncCheckpoint(s) = out.msg_ref() {
        answer = Some(s.clone());
      }
    }
    let answer = answer.expect("the equal-checkpoint peer SERVES the recovery request (F2)");

    // Deliver the peer's SyncCheckpoint back to the recovering replica → it applies + re-persists +
    // converges to Normal at the synced point.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::SyncCheckpoint(answer),
    );
    e.handle_storage(now, &mut wal, &mut sb); // drive the durable re-persist
    assert_eq!(
      e.status(),
      Status::Normal,
      "the recovering replica converged via the equal-checkpoint peer fetch",
    );
    assert_eq!(e.checkpoint_op(), OpNumber::with(2));
    assert!(
      !e.awaiting_peer_checkpoint_for_test(),
      "no longer awaiting a peer checkpoint"
    );
  }

  /// Trigger a sync on a laggard backup and deliver `m`, returning the post-delivery endpoint state.
  /// `donor_sb` provides the durable checkpoint snapshot the laggard re-persists to.
  fn sync_apply_harness(checkpoint_op: u64) -> (Endpoint<CountSm>, TestWal, TestSb, Bytes, u128) {
    let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(checkpoint_op);
    let (env, id) = donor_envelope(&dsb);
    let e = sync_backup();
    let wal = TestWal::default();
    let sb = TestSb::default();
    (e, wal, sb, env, id)
  }

  #[test]
  fn sync_checkpoint_restores_and_resumes_at_the_synced_point() {
    let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
    let now = Instant::ZERO;
    // Trigger sync (Commit advertising checkpoint_op=4), capture the nonce it used.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(4),
        OpNumber::with(4),
      )),
    );
    let nonce = captured_sync_nonce(&mut e);
    // Deliver the SyncCheckpoint.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4),
        id,
        ReplicaId::new(0),
        nonce,
        env.clone(),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb); // drive the durable re-persist (TestSb synchronous)
    assert_eq!(e.checkpoint_op(), OpNumber::with(4));
    assert_eq!(e.commit(), OpNumber::with(4));
    assert_eq!(e.commit_max(), OpNumber::with(4));
    assert_eq!(e.op(), OpNumber::with(4));
    assert_eq!(e.status(), Status::Normal);
    assert_eq!(
      e.state_machine().applied().len(),
      4,
      "SM restored from the snapshot, not replayed"
    );
    assert_eq!(
      sb.state().checkpoint_op(),
      OpNumber::with(4),
      "synced checkpoint is now durable"
    );
    assert_eq!(sb.state().checkpoint_id(), id);
  }

  #[test]
  fn sync_checkpoint_with_mismatched_id_is_rejected_not_restored() {
    // A corrupt/forged snapshot whose bytes don't hash to the advertised id MUST NOT be restored.
    let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(4),
        OpNumber::with(4),
      )),
    );
    let nonce = captured_sync_nonce(&mut e);
    let bad_env = Bytes::from_static(b"not the real envelope");
    let advertised = 0xDEAD_BEEF_u128; // != checkpoint_id(bad_env)
    assert_ne!(advertised, crate::checkpoint_id(&bad_env));
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4),
        advertised,
        ReplicaId::new(0),
        nonce,
        bad_env,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(0),
      "rejected: checkpoint not advanced"
    );
    assert_eq!(
      e.state_machine().applied().len(),
      0,
      "rejected: SM untouched"
    );
    // sync stays armed → it re-solicits on the timer.
    assert!(
      e.poll_timeout().is_some(),
      "sync remains armed to re-solicit"
    );
  }

  #[test]
  fn sync_checkpoint_with_op_not_bound_to_the_snapshot_is_rejected_not_restored() {
    // F3 REGRESSION (overstated checkpoint op over stale-but-consistent bytes): a faulty peer ships a
    // snapshot whose REAL frontier is op A=2 but advertises `checkpoint_op = B=4`. The snapshot's bytes
    // hash to the advertised `checkpoint_id` (so the existing integrity gate PASSES — the id is
    // consistent with the OLD bytes), yet B > A. Before binding the op into the hash, the receiver
    // restored the op-2 SM but advanced `commit_min`/`commit_max`/`op` to 4 — SILENTLY DROPPING the
    // committed ops in (A, B] = (2, 4]. With the fix, the op bound INSIDE the envelope (2) is compared
    // to the advertised op (4) and the mismatch REJECTS the snapshot: no restore, no commit advance.
    let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
    let now = Instant::ZERO;
    // Trigger a sync targeting op 4 (the overstated op).
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(4),
        OpNumber::with(4),
      )),
    );
    let nonce = captured_sync_nonce(&mut e);
    // Build a STALE-BUT-CONSISTENT envelope: a genuine snapshot bound to op A=2, with the matching id.
    let mut stale_sm = CountSm::default();
    stale_sm.apply(OpNumber::with(1), &[1]);
    stale_sm.apply(OpNumber::with(2), &[2]);
    let stale_env = Endpoint::<CountSm>::encode_checkpoint(
      OpNumber::with(2),
      &BTreeMap::new(),
      &stale_sm.snapshot(),
    );
    let real_id = crate::checkpoint_id(&stale_env); // the id IS consistent with these (op-2) bytes
    // Deliver it advertising the OVERSTATED op B=4 but the bytes' REAL id → the hash gate passes, the
    // op-binding gate must reject (bound op 2 != advertised op 4).
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4), // OVERSTATED — does not match the op bound (2) inside the snapshot
        real_id,           // matches checkpoint_id(stale_env), so the integrity gate PASSES
        ReplicaId::new(0),
        nonce,
        stale_env,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb); // (no re-persist should have been staged)
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(0),
      "rejected: checkpoint op not advanced to the overstated value",
    );
    // The APPLIED frontier (`commit_min`) is the safety-critical one: it must NOT advance past the
    // snapshot's real frontier — that is precisely the committed-op drop the binding prevents. (The
    // cluster-wide `commit_max` legitimately becomes 4 from the learned Commit; that is just a watermark
    // we have NOT caught up to, not an applied/durable advance — the replica still lacks ops (2, 4].)
    assert_eq!(
      e.commit(),
      OpNumber::with(0),
      "rejected: applied frontier (commit_min) NOT advanced past the snapshot's real content",
    );
    assert_eq!(
      e.op(),
      OpNumber::with(0),
      "rejected: head not advanced to the overstated op"
    );
    assert_eq!(
      e.state_machine().applied().len(),
      0,
      "rejected: SM untouched (the op-2 snapshot was NOT restored under op 4)",
    );
    assert_eq!(e.state_syncs_applied(), 0, "no state-sync was applied",);
    // sync stays armed → it re-solicits on the timer (another peer answers).
    assert!(
      e.poll_timeout().is_some(),
      "sync remains armed to re-solicit"
    );
  }

  #[test]
  fn stale_nonce_sync_checkpoint_is_ignored() {
    let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(4),
        OpNumber::with(4),
      )),
    );
    let nonce = captured_sync_nonce(&mut e);
    // Deliver a SyncCheckpoint with the WRONG nonce — must be ignored.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4),
        id,
        ReplicaId::new(0),
        nonce.wrapping_add(1),
        env,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(0),
      "wrong nonce → ignored"
    );
    assert_eq!(e.state_machine().applied().len(), 0);
  }

  #[test]
  fn sync_checkpoint_below_target_is_ignored() {
    // A SyncCheckpoint whose checkpoint_op does not even reach the target we learned the cluster has
    // committed (an out-of-date peer answering with an OLDER checkpoint) → ignored: it would not
    // advance us past the committed frontier. (Target 6; a reply at op 4 is dropped.)
    let mut e = sync_backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let (_d, _dw, dsb) = donor_primary_at_checkpoint(4);
    let (env4, id4) = donor_envelope(&dsb);
    let now = Instant::ZERO;
    // Trigger a sync targeting 6 (the cluster's known checkpoint).
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(6),
        OpNumber::with(6),
      )),
    );
    let nonce = captured_sync_nonce(&mut e);
    // A stale peer answers with checkpoint 4 (< target 6): must be ignored.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4),
        id4,
        ReplicaId::new(0),
        nonce,
        env4,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(0),
      "a SyncCheckpoint below the learned target is ignored (would not reach the committed frontier)"
    );
    assert!(
      e.poll_timeout().is_some(),
      "sync stays armed to await a checkpoint >= target"
    );
  }

  #[test]
  fn sync_checkpoint_without_an_outstanding_sync_is_ignored() {
    // A SyncCheckpoint arriving with NO sync outstanding (never triggered, or already applied) is
    // dropped — never an unsolicited restore. This also covers the "duplicate after apply" case (the
    // first apply clears `sync`, so a re-delivery finds no outstanding sync).
    let mut e = sync_backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let (_d, _dw, dsb) = donor_primary_at_checkpoint(4);
    let (env, id) = donor_envelope(&dsb);
    let now = Instant::ZERO;
    // No trigger fired → sync is None. Deliver a (valid) SyncCheckpoint anyway.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4),
        id,
        ReplicaId::new(0),
        0xABCD,
        env,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(0),
      "an unsolicited SyncCheckpoint (no outstanding sync) is ignored"
    );
    assert_eq!(e.state_machine().applied().len(), 0);
  }

  #[test]
  fn lower_sync_checkpoint_is_ignored_after_a_higher_one() {
    // Monotonicity: after syncing to checkpoint 4, a later SyncCheckpoint advertising a LOWER
    // checkpoint must never regress us. (We forge a stale reply at the same nonce/below our point.)
    let (mut e, mut wal, mut sb, env4, id4) = sync_apply_harness(4);
    let (_d2, _dw2, dsb2) = donor_primary_at_checkpoint(2);
    let (env2, id2) = donor_envelope(&dsb2);
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(4),
        OpNumber::with(4),
      )),
    );
    let nonce = captured_sync_nonce(&mut e);
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4),
        id4,
        ReplicaId::new(0),
        nonce,
        env4,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(e.checkpoint_op(), OpNumber::with(4));
    // A stale lower SyncCheckpoint (op 2) arriving now: sync is already cleared, and even if it
    // weren't, `> self.checkpoint_op` fails. It must be ignored — no regression.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(2),
        id2,
        ReplicaId::new(0),
        nonce,
        env2,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(4),
      "a lower SyncCheckpoint never regresses us"
    );
    assert_eq!(e.commit(), OpNumber::with(4));
  }

  #[test]
  fn sync_checkpoint_clears_a_pending_repair_hole_below_the_synced_point() {
    // A replica with a `repair` hole at op 2 that then syncs a checkpoint at op 5 drops the hole
    // (subsumed by the snapshot) and stops the repair timer.
    let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(6);
    // Use a checkpoint at 6 so it is strictly above the hole at 2 and the head.
    let (env, id) = donor_envelope(&dsb);
    let mut e = sync_backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // Manufacture a pending-repair hole at op 2 (as the recover loop would).
    e.request_repair(now, 2);
    assert!(e.repair.contains(&2), "hole registered");
    assert!(e.timers.repair_retry.is_some(), "repair timer armed");
    // Trigger + apply a sync to checkpoint 6 (above the hole).
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(6),
        OpNumber::with(6),
      )),
    );
    let nonce = captured_sync_nonce(&mut e);
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(6),
        id,
        ReplicaId::new(0),
        nonce,
        env,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(e.checkpoint_op(), OpNumber::with(6));
    assert!(
      e.repair.is_empty(),
      "the hole below the synced point is subsumed + cleared"
    );
    assert!(e.timers.repair_retry.is_none(), "repair timer stopped");
  }

  // ── M3.5 T2: force-state-sync escalation ───────────────────────────────────────────────────────

  #[test]
  fn a_pruned_committed_hole_forces_a_state_sync() {
    // A Normal BACKUP (replica 1 of 3) holds a repair hole at op N=2 with a head ABOVE it (op=4),
    // where a QUORUM has checkpointed past N (so RequestPrepare is futile — the op is pruned on the
    // quorum). It must (a) clear the doomed hole, (b) emit a RequestSync (not just RequestPrepare),
    // (c) record a FORCED sync targeting the quorum checkpoint.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 7, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    // Normal-backup state: head op 4, commit held at 1, own checkpoint 0, a committed hole at op 2.
    ep.force_state_for_test(0, 4, 1, 0, &[2]);
    assert!(!ep.is_primary());
    assert!(ep.has_repair_hole_for_test(2), "the hole is registered");
    // Teach it a QUORUM (2 of 3) has checkpointed past N=2: peers 0 and 2 report checkpoint_op = 4.
    // (self reports 0; the 2nd-highest of {0,4,4} = 4 >= N=2 → the hole is snapshot-only.)
    ep.inject_peer_checkpoint_for_test(0, 4);
    ep.inject_peer_checkpoint_for_test(2, 4);
    assert_eq!(
      ep.quorum_checkpoint_op(),
      OpNumber::with(4),
      "the quorum-checkpoint floor is 4 (>= the hole at 2)"
    );
    // Drive a real checkpoint report (a Commit from the primary, replica 0) so the production
    // `on_commit` → `maybe_force_sync` path runs the escalation.
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(1),
        OpNumber::with(4),
      )),
    );
    // (a) the doomed hole is cleared, and its retry timer stopped.
    assert!(
      !ep.has_repair_hole_for_test(2),
      "the snapshot-only hole at N=2 is cleared"
    );
    assert!(
      ep.timers.repair_retry.is_none(),
      "the futile repair retransmit is stopped"
    );
    // (c) a FORCED sync to the quorum checkpoint (4) is recorded.
    assert_eq!(
      ep.sync_target_for_test(),
      Some(4),
      "the forced sync targets the quorum checkpoint"
    );
    assert!(
      ep.sync_is_forced_for_test(),
      "the sync is marked forced (the assert-relaxation path)"
    );
    // (b) a RequestSync was emitted (not merely a RequestPrepare).
    let mut saw_request_sync = false;
    let mut saw_request_prepare = false;
    while let Some(out) = ep.poll_message() {
      match out.msg_ref() {
        Message::RequestSync(_) => saw_request_sync = true,
        Message::RequestPrepare(_) => saw_request_prepare = true,
        _ => {}
      }
    }
    assert!(
      saw_request_sync,
      "a RequestSync is solicited instead of looping RequestPrepare"
    );
    let _ = saw_request_prepare; // an earlier futile RequestPrepare may have been emitted before the escalation
    // SAFETY: the commit frontier did NOT advance past the hole — it stays at N-1 until the snapshot
    // (>= N) is applied. No committed op is abandoned; it is recovered from the synced snapshot.
    assert_eq!(
      ep.commit(),
      OpNumber::with(1),
      "no commit advances past the hole until the forced snapshot lands"
    );
  }

  #[test]
  fn force_sync_does_not_fire_when_the_op_is_still_peer_repairable() {
    // The escalation must NOT pre-empt the cheap single-op repair when the hole is still IN-REACH —
    // i.e. NO peer has checkpointed past it, so every reporter may still hold it as a servable prepare.
    // Here the only peer report (replica 0) is a checkpoint BELOW the hole (N=4, primary checkpoint=3),
    // so the max-peer floor stays below N → no force-sync.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 7, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    // Head op 6, commit held at 3, own checkpoint 0, a committed hole at op 4.
    ep.force_state_for_test(0, 6, 3, 0, &[4]);
    // The primary (replica 0) reports a checkpoint of 3 — BELOW the hole at 4. The max-peer floor is
    // max{self=0, r0=3} = 3 < N=4 → the hole is still in-reach (the primary has NOT pruned op 4, so a
    // RequestPrepare can still be answered) → no force-sync.
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(3),
        OpNumber::with(3),
      )),
    );
    assert_eq!(
      ep.max_peer_checkpoint_op(),
      OpNumber::with(3),
      "the max-peer floor (3) stays below the hole (4)"
    );
    // The hole is RETAINED (still peer-repairable) and NO sync is armed.
    assert!(
      ep.has_repair_hole_for_test(4),
      "an in-reach hole keeps using ordinary RequestPrepare repair"
    );
    assert_eq!(
      ep.sync_target_for_test(),
      None,
      "no forced sync is armed while no peer has pruned the op (it may still be served)"
    );
    assert!(
      ep.timers.repair_retry.is_some(),
      "the repair retransmit timer stays armed"
    );
  }

  #[test]
  fn force_sync_fires_on_a_backup_that_only_hears_the_primary() {
    // REGRESSION (the backup-visibility bug): a Normal BACKUP only ever records the PRIMARY's
    // checkpoint (PrepareOks flow to the primary, never between backups), so `quorum_checkpoint_op`
    // is structurally pinned at ~0 on a backup. The escalation MUST key on the max single-peer
    // checkpoint instead — otherwise a backup stuck on a pruned committed hole below the cluster
    // checkpoint (head above it) hangs at `commit_min == N-1` forever. Here a SINGLE peer report (the
    // primary's Commit, checkpoint=8) past the hole (N=2) is enough to force the sync.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 7, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    // Head op 10 (ABOVE the cluster checkpoint, so the ORDINARY `> self.op` sync stays FALSE — this is
    // the precise force-sync regime), commit held at 1, own checkpoint 0, a committed hole at op 2.
    ep.force_state_for_test(0, 10, 1, 0, &[2]);
    assert!(!ep.is_primary());
    // Only the primary (replica 0) reports — exactly a backup's real visibility. quorum_checkpoint_op
    // is still 0 here (only self + one peer report), proving the OLD quorum-gated trigger could never
    // have fired; the max-peer floor (8) is what rescues it. The primary's checkpoint (8) is BELOW the
    // head (10), so `maybe_request_sync` (`8 > 10`?) does NOT fire — ONLY the forced path can.
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(1),
        OpNumber::with(8),
      )),
    );
    assert_eq!(
      ep.quorum_checkpoint_op(),
      OpNumber::with(0),
      "the quorum-th floor is 0 on a backup (only the primary reports) — the OLD trigger was dead here"
    );
    assert!(
      !ep.has_repair_hole_for_test(2),
      "the snapshot-only hole is cleared via the max-peer floor (the backup no longer hangs)"
    );
    assert_eq!(
      ep.sync_target_for_test(),
      Some(8),
      "the forced sync targets the primary's reported checkpoint"
    );
    assert!(ep.sync_is_forced_for_test(), "the sync is marked forced");
  }

  #[test]
  fn force_sync_stays_dormant_until_a_quorum_floor_is_known() {
    // Empty repair set, or no quorum-checkpoint floor → the escalation is a no-op (it must never fire
    // spuriously). With a hole but a zero floor (partitioned: no peers heard), it stays dormant.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 7, NoopSm);
    // No holes at all → maybe_force_sync is a no-op.
    ep.maybe_force_sync(Instant::ZERO);
    assert_eq!(ep.sync_target_for_test(), None);
    // A hole but no quorum floor (no peer reports) → still dormant.
    ep.force_state_for_test(0, 4, 1, 0, &[2]);
    ep.maybe_force_sync(Instant::ZERO);
    assert!(
      ep.has_repair_hole_for_test(2),
      "the hole survives — no floor means no escalation"
    );
    assert_eq!(
      ep.sync_target_for_test(),
      None,
      "no sync armed without a quorum floor"
    );
  }

  #[test]
  fn forced_sync_preserves_a_held_tail_above_the_checkpoint_without_panic() {
    // SAFETY (VOPR seed 164): a forced sync where checkpoint_op (3) <= self.op (5). The held tail
    // (3..5] is ops this replica already durably appended + ACKED, so the cluster may have COMMITTED
    // them off its vote. The OLD code discarded the tail (rewound the head to 3 + truncated the WAL),
    // destroying its only durable copy while keeping `log_view` — a later view change then took its
    // (log_view, op) as the canonical head and dropped those committed ops, the loss `adopt_canonical_
    // head`'s `op >= commit_min` assert trips on. The forced path must instead apply WITHOUT panic,
    // PRESERVE the above-floor tail (keep op 5 + its log entries), restore the SM at the snapshot, and
    // subsume the doomed hole at 2.
    let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(3);
    let (env, id) = donor_envelope(&dsb);
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 1, CountSm::default());
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    // A backup holding a tail at op 5, commit at 1, a committed hole at 2, own checkpoint 0. Seed the
    // in-memory tail entries (4, 5) it holds above the synced checkpoint (force_state_for_test leaves
    // the cache empty); these must survive the forced sync.
    ep.force_state_for_test(0, 5, 1, 0, &[2]);
    ep.seed_log_entry_for_test(4);
    ep.seed_log_entry_for_test(5);
    ep.arm_forced_sync_for_test(3); // self.sync = Some { target: 3, forced: true }
    let nonce = ep.sync_nonce_for_test();
    // A valid SyncCheckpoint at op 3 (id matches its bytes) — must apply, not panic.
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(3),
        id,
        ReplicaId::new(0),
        nonce,
        env,
      )),
    );
    ep.handle_storage(Instant::ZERO, &mut wal, &mut sb); // drive the durable re-persist
    assert_eq!(
      ep.op(),
      OpNumber::with(5),
      "the held tail above the synced checkpoint is PRESERVED — the head is NOT rewound to 3"
    );
    assert!(
      ep.has_log_entry_for_test(4) && ep.has_log_entry_for_test(5),
      "the above-floor tail entries (4, 5) survive the forced sync"
    );
    assert_eq!(
      ep.commit(),
      OpNumber::with(3),
      "the applied frontier advanced to the synced point (past the old hole at 2)"
    );
    assert_eq!(
      ep.checkpoint_op(),
      OpNumber::with(3),
      "synced checkpoint adopted"
    );
    assert!(
      !ep.has_repair_hole_for_test(2),
      "the pruned committed hole at/below the floor is subsumed by the snapshot"
    );
    assert_eq!(
      ep.state_syncs_applied(),
      1,
      "the forced sync routed through apply_sync → the durable re-persist completed"
    );
  }

  #[test]
  fn a_primary_in_the_force_sync_strand_forfeits_instead_of_resetting_op() {
    // SAFETY REGRESSION (op-number reuse → divergence): a PRIMARY that reaches the force-sync strand (a
    // committed-op repair hole at/below `max_peer_checkpoint_op`) must NOT force-sync. Force-sync resets
    // `self.op` to the checkpoint (BELOW the primary's head) and clears the log/inflight; the primary
    // would then assign NEW client requests at REUSED op numbers in the same view, which backups re-ack
    // from their old entries WITHOUT comparing bodies → the primary commits body B while backups applied
    // body A for the same op (committed-state divergence). The fix: the primary flags a deferred forfeit
    // and steps down on its next tick — `self.op` is NEVER rewound, and no forced sync is armed.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 7, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(ep.is_primary(), "replica 0 at view 0 is the primary");
    // The primary holds a head at op 10 with a committed-op hole at op 2 (commit held at 1 below it).
    // (A recovered primary with a rotted committed slot the cluster long since checkpointed+pruned.)
    ep.force_state_for_test(0, 10, 1, 0, &[2]);
    assert_eq!(ep.op(), OpNumber::with(10));
    // A backup's PrepareOk reports checkpoint_op = 8 — ABOVE the hole at 2, so the hole is snapshot-only
    // on that peer (pruned: RequestPrepare is futile). This drives the production `on_prepare_ok` →
    // `maybe_force_sync` path on the PRIMARY (the exact strand the finding flagged as reachable).
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(2),
        ReplicaId::new(1),
        OpNumber::with(8),
      )),
    );
    assert_eq!(
      ep.max_peer_checkpoint_op(),
      OpNumber::with(8),
      "the peer-checkpoint floor (8) is above the hole (2) → the force-sync strand is entered"
    );
    // The CORE assertion: the primary flagged a deferred forfeit and did NOT touch its op or arm a sync.
    assert!(
      ep.pending_forfeit_for_test(),
      "the primary flags a deferred forfeit instead of force-syncing"
    );
    assert_eq!(
      ep.op(),
      OpNumber::with(10),
      "the primary's op is NOT rewound to the checkpoint (no op-number reuse)"
    );
    assert_eq!(
      ep.sync_target_for_test(),
      None,
      "no forced sync is armed on the primary (it steps down, it does not reset its state)"
    );
    assert!(
      ep.has_repair_hole_for_test(2),
      "the hole is NOT cleared by a force-sync — the primary abdicates rather than subsume it locally"
    );
    // No RequestSync was emitted (a primary never force-syncs).
    let mut saw_request_sync = false;
    while let Some(out) = ep.poll_message() {
      if let Message::RequestSync(_) = out.msg_ref() {
        saw_request_sync = true;
      }
    }
    assert!(
      !saw_request_sync,
      "a primary in the force-sync strand emits NO RequestSync (no self-reset)"
    );
    // The next primary tick ACTS on the flag: it forfeits by proposing the next view (StartViewChange).
    // The flag PERSISTS (F2) — the lone SVC has not yet formed a quorum, so the view has not changed;
    // the latch keeps the primary re-proposing + not heartbeating until it does. The op is unchanged.
    ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
    assert!(
      ep.pending_forfeit_for_test(),
      "the forfeit PERSISTS until the view actually changes (not one-shot — a dropped SVC must not let \
       the primary resume heartbeating and wedge the cluster)"
    );
    assert_eq!(
      ep.op(),
      OpNumber::with(10),
      "op remains unchanged across the forfeit (never reset)"
    );
    let mut saw_svc_view1 = false;
    while let Some(out) = ep.poll_message() {
      if let Message::StartViewChange(svc) = out.into_msg() {
        if svc.view().get() == 1 {
          saw_svc_view1 = true;
        }
      }
    }
    assert!(
      saw_svc_view1,
      "the flagged primary forfeits on its next tick (proposes view 1 via StartViewChange)"
    );
  }

  #[test]
  fn a_primary_in_the_force_sync_strand_never_reuses_an_op_number() {
    // SAFETY (the heart of the finding): the op-reuse divergence happens ONLY if the primary's `op` is
    // REWOUND below its head (force-sync resets it to the checkpoint, then new requests land at the
    // vacated op numbers that backups still hold under old bodies). The forfeit fix guarantees `op` is
    // NEVER rewound. We drive the full strand→forfeit→serve sequence and assert `op` is monotone
    // non-decreasing throughout: a request the (still-Normal, lone-SVC) primary serves lands at a FRESH
    // op ABOVE the old head (11), never at a reused number. Under the OLD force-sync behaviour `op`
    // would have collapsed to the checkpoint floor, and the next request would have reused op 9/10.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 7, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    ep.force_state_for_test(0, 10, 1, 0, &[2]);
    let head_at_strand = ep.op().get();
    assert_eq!(head_at_strand, 10);
    // Enter the force-sync strand (flag the deferred forfeit) via a peer PrepareOk above the hole.
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(2),
        ReplicaId::new(1),
        OpNumber::with(8),
      )),
    );
    assert!(ep.pending_forfeit_for_test());
    assert!(
      ep.op().get() >= head_at_strand,
      "entering the strand did NOT rewind op (no force-sync reset)"
    );
    while ep.poll_message().is_some() {}
    // The forfeit fires on the next tick → the primary proposes view 1 (a lone SVC; view stays 0 until a
    // real SVC quorum forms, so it may still be primary-of-view-0 and serve).
    ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
    assert!(
      ep.op().get() >= head_at_strand,
      "the forfeit did NOT rewind op (it steps down, it does not reset state)"
    );
    while ep.poll_message().is_some() {}
    // A fresh client request: whatever the primary does with it, it must NOT assign it an op number
    // at/below the head it held at the strand (that would be a reuse). If it serves at all, it serves
    // STRICTLY ABOVE the old head.
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(9)),
      Message::Request(Request::new(
        ClientId::new(9),
        RequestNumber::with(1),
        Bytes::from(std::vec![42u8]),
      )),
    );
    assert!(
      ep.op().get() >= head_at_strand,
      "op is never rewound across the whole sequence → no op number is ever reused"
    );
    // Any Prepare the primary broadcast for the new request carries an op STRICTLY above the old head —
    // never a reused op number that a backup still holds under a different body.
    while let Some(out) = ep.poll_message() {
      if let Message::Prepare(p) = out.msg_ref() {
        assert!(
          p.op().get() > head_at_strand,
          "a served request lands at a FRESH op (> old head {head_at_strand}), never a reused number"
        );
      }
    }
  }

  #[test]
  fn on_request_is_dropped_while_a_sync_or_checkpoint_persist_is_in_flight() {
    // DEFENSE (Codex): a primary must NOT serve a client while a state-sync OR a checkpoint-persist is
    // in flight — either can reset `self.op` (a sync via `apply_sync`; a checkpoint completion advances
    // checkpoint_op + GCs), so assigning a new request an op now risks op-number reuse. Both an
    // outstanding `sync` and an outstanding `pending_checkpoint` must short-circuit `on_request`.
    let serve = |arm: fn(&mut Endpoint<NoopSm>)| -> bool {
      let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
      let mut ep = Endpoint::new(cfg, 7, NoopSm);
      let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
      assert!(ep.is_primary());
      let head_before = ep.op();
      arm(&mut ep);
      ep.handle_message(
        Instant::ZERO,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(9)),
        Message::Request(Request::new(
          ClientId::new(9),
          RequestNumber::with(1),
          Bytes::from(std::vec![1u8]),
        )),
      );
      ep.op() != head_before // true ⇒ the request was served (op advanced)
    };
    // With a sync outstanding → dropped (op does not advance).
    assert!(
      !serve(|ep| ep.arm_forced_sync_for_test(0)),
      "a request is dropped while a state-sync is outstanding (op-reset risk)"
    );
    // With a checkpoint-persist staged → dropped.
    assert!(
      !serve(|ep| ep.stage_pending_checkpoint_for_test()),
      "a request is dropped while a checkpoint-persist is in flight (op-reset risk)"
    );
    // Control: a clean primary (nothing in flight) DOES serve the request (op advances) — proving the
    // guard is specific to the in-flight-reset states, not a blanket block.
    assert!(
      serve(|_| {}),
      "a clean primary serves the request (the guard does not over-block)"
    );
  }

  #[test]
  fn on_request_waits_for_the_committed_prefix_to_apply_before_serving_clients() {
    // R5-F2 (at-most-once / sessions-caught-up): a primary must NOT assign a fresh op to a client while
    // its committed prefix is unapplied (`commit_max > commit_min` — a committed op is KNOWN but held by
    // a B4 repair hole). The session/dedup table (`self.clients`) is only updated as ops APPLY, so during
    // the gap a just-committed client request is ABSENT from the table → a retry would be mis-seen as NEW
    // and assigned an op ABOVE the gap → when the hole fills, the apply loop (which has no dedup) would
    // execute BOTH the original AND the duplicate → divergence. The primary must catch up first; the
    // client retries.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 8).unwrap();
    let mut ep = Endpoint::new(cfg, 7, CountSm::default());
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    // Primary holding a committed-op GAP: head op 4, commit HELD at 1 by a hole at op 2, but commit_max
    // = 4 (ops 2..=4 are known committed cluster-wide, merely unapplied here). Ops 3 + 4 are present in
    // the log; only op 2 is the unreadable hole. (`force_state_for_test` keeps commit_max == commit_min,
    // so raise it directly to model the known-but-unapplied committed suffix.)
    ep.force_state_for_test(0, 4, 1, 0, &[2]);
    ep.commit_max = OpNumber::with(4);
    for op in [3u64, 4u64] {
      ep.log.insert(
        op,
        LogEntry {
          client: ClientId::new(7),
          request: RequestNumber::with(op),
          body: Bytes::copy_from_slice(&[op as u8]),
        },
      );
    }
    assert!(ep.is_primary());
    assert!(
      ep.commit_max().get() > ep.commit().get(),
      "precondition: a committed op is known but not yet applied (commit_max > commit_min)"
    );
    let head_before = ep.op();

    // A FRESH client request (client 9, request 1) arrives DURING the gap → must be DROPPED: no Prepare,
    // no Reply, and the head op does NOT advance (no fresh op assigned that could later double-execute).
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(9)),
      Message::Request(Request::new(
        ClientId::new(9),
        RequestNumber::with(1),
        Bytes::from(std::vec![1u8]),
      )),
    );
    assert_eq!(
      ep.op(),
      head_before,
      "no fresh op is assigned while the committed prefix is unapplied (sessions stale)"
    );
    assert!(
      ep.poll_message().is_none(),
      "no Prepare and no Reply is emitted during the committed gap"
    );

    // Close the gap: the hole at op 2 is filled (a vouching repair Prepare, commit >= op), so
    // `advance_commit` applies ops 2,3,4 in order → commit_min catches up to commit_max == 4, and the
    // repair set empties.
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      primary_peer(),
      repair_prepare(0, 2, 4),
    );
    assert_eq!(
      ep.commit(),
      OpNumber::with(4),
      "the gap closed: the committed prefix is fully applied (commit_min == commit_max)"
    );
    assert!(
      !ep.has_repair_hole_for_test(2),
      "the repair hole is cleared once the committed value fills it"
    );
    while ep.poll_message().is_some() {} // discard catch-up output (Committed/etc.)

    // Now the SAME fresh request IS served — the primary assigns it a fresh op and broadcasts a Prepare.
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(9)),
      Message::Request(Request::new(
        ClientId::new(9),
        RequestNumber::with(1),
        Bytes::from(std::vec![1u8]),
      )),
    );
    assert!(
      ep.op().get() > head_before.get(),
      "once the committed prefix is applied, the primary serves the request (op advances)"
    );
    let mut saw_prepare = false;
    while let Some(out) = ep.poll_message() {
      if let Message::Prepare(p) = out.msg_ref() {
        assert!(
          p.op().get() > 4,
          "the served request lands at a fresh op above the (now-applied) committed prefix"
        );
        saw_prepare = true;
      }
    }
    assert!(
      saw_prepare,
      "the primary broadcasts a Prepare for the request once it has caught up"
    );
  }

  // ── M3.5 T3: forfeit — a lagging primary steps down via a view change ───────────────────────────

  #[test]
  fn a_lagging_primary_forfeits_after_the_grace_period() {
    // Primary (replica 0 of 3), checkpoint_ops=4 ⇒ forfeit lag bound = 4. A quorum reports
    // checkpoint_op = 8 while the primary's own checkpoint_op stays 0 (it is stuck — repairing/
    // syncing while the cluster raced ahead). After the grace period the primary must FORFEIT by
    // PROPOSING a view change (broadcast StartViewChange for view 1) via the SVC machinery — NOT a
    // unilateral view jump (it stays in its own view until a real SVC quorum forms).
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 1, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(ep.is_primary());
    // Two peers report checkpoint_op = 8 (a quorum of 2-of-3 incl. neither self) → the primary's
    // own checkpoint (0) lags the quorum checkpoint (8) by 8 >= the bound 4.
    ep.inject_peer_checkpoint_for_test(1, 8);
    ep.inject_peer_checkpoint_for_test(2, 8);
    assert_eq!(
      ep.quorum_checkpoint_op(),
      OpNumber::with(8),
      "the quorum-checkpoint floor is 8, a full interval beyond the primary's 0"
    );
    // First primary timeout ARMS the grace timer but does NOT forfeit yet (anti-storm: a transient
    // lag must persist for the grace window before the primary steps down).
    ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
    assert!(
      ep.forfeit_armed_for_test(),
      "the lagging primary armed the forfeit grace timer"
    );
    assert_eq!(
      ep.view().get(),
      0,
      "no forfeit before the grace period elapses (no SVC yet)"
    );
    let mut saw_svc_before_grace = false;
    while let Some(out) = ep.poll_message() {
      if let Message::StartViewChange(svc) = out.into_msg() {
        if svc.view().get() == 1 {
          saw_svc_before_grace = true;
        }
      }
    }
    assert!(
      !saw_svc_before_grace,
      "the primary must NOT propose a view change before the grace period elapses"
    );
    // Advance past the grace period (300ms) and tick again → forfeit: it proposes view 1 (SVC).
    let later = Instant::ZERO + core::time::Duration::from_millis(400);
    ep.handle_timeout(later, &mut wal, &mut sb);
    let mut saw_svc_view1 = false;
    while let Some(out) = ep.poll_message() {
      if let Message::StartViewChange(svc) = out.into_msg() {
        if svc.view().get() == 1 {
          saw_svc_view1 = true;
        }
      }
    }
    assert!(
      saw_svc_view1,
      "a stuck primary forfeits by PROPOSING the next view (StartViewChange for view 1), not a unilateral jump"
    );
    assert!(
      !ep.forfeit_armed_for_test(),
      "the grace timer is disarmed once the forfeit fires (no same-view re-forfeit)"
    );
  }

  #[test]
  fn a_healthy_primary_never_forfeits() {
    // The primary keeps pace: its own checkpoint advances in step with the quorum's. The forfeit
    // condition (lag >= a full checkpoint interval) is never satisfied, so the grace timer never
    // arms and no view change is ever proposed — the anti-storm guarantee in steady state.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 1, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(ep.is_primary());
    ep.set_own_checkpoint_for_test(8); // the primary's own checkpoint is current
    ep.inject_peer_checkpoint_for_test(1, 8);
    ep.inject_peer_checkpoint_for_test(2, 8); // quorum checkpoint 8 == own 8 → lag 0 < bound 4
    for ms in [0u64, 400, 800] {
      ep.handle_timeout(
        Instant::ZERO + core::time::Duration::from_millis(ms),
        &mut wal,
        &mut sb,
      );
      assert!(
        !ep.forfeit_armed_for_test(),
        "forfeit grace is never armed for a healthy primary (ms={ms})"
      );
    }
    assert_eq!(ep.view().get(), 0, "a healthy primary never forfeits");
    let mut saw_svc = false;
    while let Some(out) = ep.poll_message() {
      if let Message::StartViewChange(_) = out.into_msg() {
        saw_svc = true;
      }
    }
    assert!(
      !saw_svc,
      "a healthy primary never proposes a forfeit-driven view change"
    );
  }

  #[test]
  fn a_backup_never_forfeits_even_when_behind() {
    // A BACKUP (replica 1) far behind the quorum checkpoint must NOT forfeit — forfeit is a PRIMARY
    // stepping aside; a behind backup catches up via state-sync/force-sync. The forfeit check lives
    // only on the primary path (primary_timeouts), so the backup never arms it.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 1, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(!ep.is_primary());
    ep.inject_peer_checkpoint_for_test(0, 8);
    ep.inject_peer_checkpoint_for_test(2, 8);
    for ms in [0u64, 400, 800] {
      ep.handle_timeout(
        Instant::ZERO + core::time::Duration::from_millis(ms),
        &mut wal,
        &mut sb,
      );
    }
    assert!(
      !ep.forfeit_armed_for_test(),
      "a backup never arms forfeit (forfeit is exclusively a primary stepping aside)"
    );
  }

  #[test]
  fn a_transiently_lagging_primary_recovers_and_disarms_without_forfeiting() {
    // Anti-storm: a primary that briefly lags (arming the grace timer) but CATCHES UP before the
    // grace elapses must DISARM and never forfeit. Models a primary that was momentarily behind on
    // checkpoint, then checkpointed in step with the cluster within the grace window.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 1, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(ep.is_primary());
    ep.inject_peer_checkpoint_for_test(1, 8);
    ep.inject_peer_checkpoint_for_test(2, 8); // quorum 8, own 0 → lag 8 >= 4 → arms
    ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
    assert!(ep.forfeit_armed_for_test(), "the lag armed the grace timer");
    // The primary catches its own checkpoint up to the quorum BEFORE the grace elapses.
    ep.set_own_checkpoint_for_test(8); // lag now 0 < bound 4
    let mid = Instant::ZERO + core::time::Duration::from_millis(100); // still within the 300ms grace
    ep.handle_timeout(mid, &mut wal, &mut sb);
    assert!(
      !ep.forfeit_armed_for_test(),
      "catching up disarms the grace timer (the transient lag does not forfeit)"
    );
    // Even well past the original grace deadline, no forfeit fires.
    let later = Instant::ZERO + core::time::Duration::from_millis(400);
    ep.handle_timeout(later, &mut wal, &mut sb);
    assert_eq!(
      ep.view().get(),
      0,
      "a primary that caught up never forfeits"
    );
    let mut saw_svc = false;
    while let Some(out) = ep.poll_message() {
      if let Message::StartViewChange(_) = out.into_msg() {
        saw_svc = true;
      }
    }
    assert!(!saw_svc, "no forfeit-driven view change after catch-up");
  }

  #[test]
  fn a_primary_stuck_on_an_unfillable_committed_hole_forfeits_after_the_grace_period() {
    // LIVENESS REGRESSION (VOPR seed 36): a new primary can adopt a canonical head with a COMMITTED
    // interior hole the offset-union could not carry (a committed op a holder checkpointed + pruned
    // past, so it lives only inside a peer's checkpoint snapshot — unservable via `RequestPrepare`).
    // Such a primary is stuck: its commit is HELD below the hole, it cannot serve clients, it cannot
    // fill the hole (no peer can answer), and — holding none of the band above its commit — it
    // retransmits nothing, so backups never ack and no reactive check re-fires. It must FORFEIT so a
    // caught-up replica (the checkpoint holder) leads. Here: primary (replica 0 of 3), commit held at
    // 1 with a committed `repair` hole at op 2 that NO peer answers; after the grace window it must
    // forfeit by PROPOSING view 1 (StartViewChange) — even though its checkpoint does NOT lag (the
    // OTHER forfeit condition is off), so this isolates the unfillable-hole trigger.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 1, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(ep.is_primary());
    // Head 10, commit 1, a committed hole at op 2, own checkpoint 8 == quorum (no checkpoint-lag).
    ep.force_state_for_test(0, 10, 1, 8, &[2]);
    ep.set_own_checkpoint_for_test(8);
    ep.inject_peer_checkpoint_for_test(1, 8);
    ep.inject_peer_checkpoint_for_test(2, 8); // quorum 8 == own 8 → lag 0 (the lag trigger is OFF)
    // First primary tick ARMS the grace timer (the hole is outstanding) but does NOT forfeit yet.
    ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
    assert!(
      ep.forfeit_armed_for_test(),
      "an outstanding committed repair hole arms the forfeit grace timer"
    );
    assert_eq!(ep.view().get(), 0, "no forfeit before the grace elapses");
    while ep.poll_message().is_some() {}
    // Past the grace window, with the hole STILL unfilled (no peer answered) → forfeit (propose view 1).
    let later = Instant::ZERO + core::time::Duration::from_millis(400);
    ep.handle_timeout(later, &mut wal, &mut sb);
    let mut saw_svc_view1 = false;
    while let Some(out) = ep.poll_message() {
      if let Message::StartViewChange(svc) = out.into_msg() {
        if svc.view().get() == 1 {
          saw_svc_view1 = true;
        }
      }
    }
    assert!(
      saw_svc_view1,
      "a primary stuck on an unfillable committed hole forfeits (proposes view 1) after the grace window"
    );
  }

  #[test]
  fn a_primary_whose_committed_hole_fills_within_grace_does_not_forfeit() {
    // ANTI-STORM complement of the above: a committed repair hole that a peer CAN serve is filled by
    // the answering `Prepare` well within the grace window, emptying `repair` and DISARMING the
    // forfeit — so a FILLABLE hole (the ordinary B4 repair case) never triggers a view change. Primary
    // (replica 0 of 3), commit held at 1 with a hole at op 2; a peer answers with op 2's
    // committed-vouching Prepare (commit 2 >= op 2) before the grace elapses.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 1, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(ep.is_primary());
    // Head 2, commit 1, a committed hole at op 2, own checkpoint 0 (no checkpoint-lag peers injected).
    ep.force_state_for_test(0, 2, 1, 0, &[2]);
    // First tick arms the grace timer (the hole is outstanding).
    ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
    assert!(
      ep.forfeit_armed_for_test(),
      "the outstanding committed hole arms the grace timer"
    );
    while ep.poll_message().is_some() {}
    // A peer answers our RequestPrepare with op 2's committed-vouching Prepare → fills the hole.
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      primary_peer(),
      repair_prepare(0, 2, 2),
    );
    assert!(
      !ep.has_repair_hole_for_test(2),
      "the committed-vouching Prepare fills the hole"
    );
    // Next tick within the grace window: the hole is gone → the grace timer DISARMS, no forfeit.
    let mid = Instant::ZERO + core::time::Duration::from_millis(100);
    ep.handle_timeout(mid, &mut wal, &mut sb);
    assert!(
      !ep.forfeit_armed_for_test(),
      "filling the hole disarms the grace timer (a fillable hole does not forfeit)"
    );
    let later = Instant::ZERO + core::time::Duration::from_millis(400);
    ep.handle_timeout(later, &mut wal, &mut sb);
    let mut saw_svc = false;
    while let Some(out) = ep.poll_message() {
      if let Message::StartViewChange(_) = out.into_msg() {
        saw_svc = true;
      }
    }
    assert!(
      !saw_svc && ep.view().get() == 0,
      "a primary whose committed hole filled in time never forfeits"
    );
  }

  #[test]
  fn a_forfeiting_primary_keeps_proposing_and_stops_heartbeating_until_the_view_changes() {
    // F2 REGRESSION (a one-shot forfeit can be LOST → the cluster wedges): when the FIRST forfeit
    // StartViewChange is dropped/partitioned, the OLD code cleared `pending_forfeit` one-shot and the
    // primary RESUMED heartbeating — so every backup kept resetting its `primary_idle` (none started
    // its own VC) and the SVC retransmit timer was never serviced while Normal, wedging the cluster
    // below the unrepairable hole. The fix keeps forfeiting until the view actually changes: each
    // primary tick RE-PROPOSES view+1 AND skips the commit heartbeat + prepare retransmit, so backups
    // stop hearing the primary and join the SVC. Here we DROP every emitted SVC and tick repeatedly:
    // the primary must (a) re-broadcast the SVC each tick, (b) NEVER emit a Commit heartbeat, and
    // (c) keep `pending_forfeit` latched — none of which the one-shot code did.
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 7, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(ep.is_primary(), "replica 0 at view 0 is the primary");
    // Enter the force-sync strand → the primary flags a deferred forfeit (a committed hole at op 2 a
    // peer has already checkpointed+pruned past).
    ep.force_state_for_test(0, 10, 1, 0, &[2]);
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(2),
        ReplicaId::new(1),
        OpNumber::with(8),
      )),
    );
    assert!(
      ep.pending_forfeit_for_test(),
      "the strand flagged a deferred forfeit"
    );
    while ep.poll_message().is_some() {} // discard anything emitted on entry

    // Tick the primary repeatedly at advancing times, DROPPING every emitted message (the SVC is
    // partitioned away). Across EVERY tick: an SVC for view 1 is re-proposed, and NO Commit heartbeat
    // is ever emitted. The view never changes (the lone SVC forms no quorum), and the flag persists.
    for i in 0..5u64 {
      let now = Instant::ZERO + core::time::Duration::from_millis(100 * (i + 1));
      ep.handle_timeout(now, &mut wal, &mut sb);
      let mut saw_svc_view1 = false;
      let mut saw_commit_heartbeat = false;
      while let Some(out) = ep.poll_message() {
        match out.into_msg() {
          Message::StartViewChange(svc) if svc.view().get() == 1 => saw_svc_view1 = true,
          Message::Commit(_) => saw_commit_heartbeat = true,
          _ => {}
        }
      }
      assert!(
        saw_svc_view1,
        "tick {i}: the forfeiting primary RE-PROPOSES view 1 each tick (idempotent re-broadcast under loss)"
      );
      assert!(
        !saw_commit_heartbeat,
        "tick {i}: the forfeiting primary must NOT heartbeat (so backups idle-out and join the SVC) — \
         the one-shot code resumed heartbeating here and wedged the cluster"
      );
      assert_eq!(
        ep.view().get(),
        0,
        "tick {i}: view unchanged while the lone SVC forms no quorum"
      );
      assert!(
        ep.pending_forfeit_for_test(),
        "tick {i}: the forfeit latch PERSISTS until the view actually changes"
      );
    }

    // Now a backup's StartViewChange for view 1 ARRIVES → with the primary's own bit, an SVC quorum
    // (2-of-3) forms → the view changes. Leaving Normal-primary CLEARS the latch (the new generation
    // re-evaluates from scratch), so the cluster is unwedged.
    let now = Instant::ZERO + core::time::Duration::from_millis(700);
    ep.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartViewChange(crate::StartViewChange::new(
        View::with(1),
        ReplicaId::new(1),
      )),
    );
    assert_eq!(
      ep.view().get(),
      1,
      "an SVC quorum (primary + one backup) forms → the view changes (the cluster is NOT wedged)"
    );
    assert!(
      ep.status().is_view_change(),
      "the primary transitioned into the view change for view 1"
    );
    assert!(
      !ep.pending_forfeit_for_test(),
      "leaving Normal-primary clears the forfeit latch (no cross-view leak)"
    );
  }

  #[test]
  fn recover_after_state_sync_restores_the_synced_checkpoint() {
    // Durability-before-resume: after a sync goes durable, a crash + recover() must come back at the
    // synced checkpoint (the durable root names it), not the stale one.
    let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(4),
        OpNumber::with(4),
      )),
    );
    let nonce = captured_sync_nonce(&mut e);
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4),
        id,
        ReplicaId::new(0),
        nonce,
        env,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
    drop(e); // crash
    // Recover from the same wal/sb: the synced checkpoint is the durable root.
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
    let mut recovered = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
    assert_eq!(
      recovered.checkpoint_op(),
      OpNumber::with(4),
      "recovered at the synced checkpoint"
    );
    assert_eq!(recovered.commit(), OpNumber::with(4));
    assert_eq!(
      recovered.op(),
      OpNumber::with(4),
      "op >= commit_min must hold after recover (the synced head, not a sub-checkpoint WAL head)"
    );
    recovered.handle_storage(now, &mut wal, &mut sb); // restore SM from the synced snapshot → Normal
    assert_eq!(recovered.status(), Status::Normal);
    assert_eq!(
      recovered.state_machine().applied().len(),
      4,
      "recovered SM reflects the synced checkpoint prefix"
    );
  }

  // ── State-sync (M3.4a) — A6: view-change / B3-interaction safety (regression guards) ──

  #[test]
  fn synced_replica_reports_its_checkpoint_in_view_change() {
    // After syncing to checkpoint 4, force the replica into a view change and inspect its DVC: it must
    // report commit == 4 (the synced point) with log_view <= view and a tail that does NOT start at
    // op 1 — exactly the recover-from-checkpoint shape (this is the B3 interaction; no B3 code here).
    // Use replica 2 of 3 as the laggard: in view 1 the primary is replica 1 (not itself), so it sends
    // a DoViewChange we can capture (a replica that is itself the next primary would form the
    // canonical log directly instead of sending a DVC).
    let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(4);
    let (env, id) = donor_envelope(&dsb);
    let mut e = Endpoint::new(
      Config::with_checkpoint_ops(1, ReplicaId::new(2), 3, 2).unwrap(),
      0,
      CountSm::default(),
    );
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(4),
        OpNumber::with(4),
      )),
    );
    let nonce = {
      let mut nonce = None;
      while let Some(out) = e.poll_message() {
        if let Message::RequestSync(r) = out.msg_ref() {
          nonce = Some(r.nonce());
        }
      }
      nonce.expect("a RequestSync was emitted")
    };
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4),
        id,
        ReplicaId::new(0),
        nonce,
        env,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert_eq!(e.checkpoint_op(), OpNumber::with(4));
    assert_eq!(e.status(), Status::Normal);
    while e.poll_message().is_some() {}

    // Force a view change to view 1 (primary = replica 1): replica 2 proposes view 1 on idle, a peer
    // SVC completes the quorum → ViewChange(1) → it sends a DoViewChange to replica 1.
    let later = now + core::time::Duration::from_millis(300);
    e.handle_timeout(later, &mut wal, &mut sb); // primary_idle → propose view 1 (own bit)
    e.handle_message(
      later,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    );
    assert_eq!(e.status(), Status::ViewChange);
    assert_eq!(e.view(), View::with(1));
    e.handle_storage(later, &mut wal, &mut sb); // durable-view write completes → DVC is sent
    let mut dvc = None;
    while let Some(out) = e.poll_message() {
      if let Message::DoViewChange(d) = out.msg_ref() {
        dvc = Some(d.clone());
      }
    }
    let dvc = dvc.expect("a synced backup sends a DoViewChange");
    assert_eq!(
      dvc.commit(),
      OpNumber::with(4),
      "reports the synced checkpoint as commit, not a sparse log"
    );
    assert_eq!(
      dvc.op(),
      OpNumber::with(4),
      "head is the synced point (tail-empty)"
    );
    assert!(dvc.log_view().get() <= dvc.view().get(), "log_view <= view");
    // The carried log is the (empty) tail above the checkpoint — it does NOT fabricate ops [1..=4].
    assert!(
      dvc.log_slice().iter().all(|e| e.op().get() > 4),
      "the DVC log is the tail above the synced checkpoint (no fabricated sub-checkpoint ops)"
    );
  }

  /// A DVC whose dense log starts at `floor+1` (a state-synced donor, checkpoint at `floor`), head
  /// `op`, commit `commit`. Models the offset log a synced replica carries.
  fn dvc_offset(replica: u8, log_view: u64, floor: u64, op: u64, commit: u64) -> DoViewChange {
    let log = ((floor + 1)..=op)
      .map(|i| {
        PreparedEntry::new(
          OpNumber::with(i),
          ClientId::new(1),
          RequestNumber::with(i),
          bytes::Bytes::copy_from_slice(&i.to_be_bytes()),
        )
      })
      .collect();
    DoViewChange::new(
      View::with(log_view + 10),
      View::with(log_view),
      OpNumber::with(op),
      OpNumber::with(commit),
      ReplicaId::new(replica),
      log,
    )
  }

  #[test]
  fn canonical_selection_with_a_checkpoint_offset_log_is_safe() {
    // A canonical generation where one DVC's log starts above op 1 (its donor was state-synced to
    // checkpoint 4, commit 4) must not be mis-truncated, and the commit* <= op_head fail-stop must not
    // trip for a synced participant (its commit == op_head == checkpoint when tail-empty).
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
    // r0: a full-from-1 log (head 5, commit 4). r1: the SAME generation but state-synced — its log
    // starts at op 5 (checkpoint 4), head 5, commit 4. Same log_view → both canonical.
    e.dvc_from.insert(0, dvc(0, 1, 5, 4));
    e.dvc_from.insert(1, dvc_offset(1, 1, 4, 5, 4));
    let (log, op_head, commit_star) = e.select_canonical_log();
    assert_eq!(
      op_head, 5,
      "the offset log does not shorten the canonical head"
    );
    assert_eq!(commit_star, 4, "commit* preserved");
    assert!(
      commit_star <= op_head,
      "the fail-stop invariant holds for an offset-log participant"
    );
    // The UNION covers [1..=5]: r0 supplies the prefix the offset r1 omits, so no op is dropped.
    let present: std::collections::BTreeSet<u64> = log.iter().map(|e| e.op().get()).collect();
    assert_eq!(
      present,
      (1..=5u64).collect::<std::collections::BTreeSet<u64>>(),
      "the union of r0's full log and r1's offset log covers ops 1..=5"
    );
  }

  #[test]
  fn view_change_abandons_an_outstanding_sync() {
    // State-sync and view change are mutually exclusive by status: a higher-view message arriving
    // while a sync is outstanding takes the replica into ViewChange and clears the stale sync (so the
    // sync_solicit timer does not linger). The replica re-triggers state-sync from Normal if still
    // behind.
    let mut e = sync_backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // Trigger a sync (in view 0).
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(8),
        OpNumber::with(8),
      )),
    );
    while e.poll_message().is_some() {}
    assert!(e.poll_timeout().is_some(), "sync armed");
    // A higher-view Commit arrives → catch_up_to_view → ViewChange, which must clear the sync.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::Commit(Commit::new(
        View::with(1),
        OpNumber::with(8),
        OpNumber::with(8),
      )),
    );
    assert_eq!(e.status(), Status::ViewChange);
    assert!(
      e.sync.is_none(),
      "the outstanding sync is abandoned on entering a view change"
    );
    assert!(
      e.timers.sync_solicit.is_none(),
      "the sync solicit timer is cleared"
    );
  }

  #[test]
  fn canonical_selection_with_a_fully_checkpoint_synced_participant_is_safe() {
    // The extreme: a state-synced participant whose tail is EMPTY (head == commit == checkpoint 4, no
    // log entries at all). select_canonical_log must handle commit == op_head with an empty offset log
    // without panicking or fabricating ops.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
    e.dvc_from.insert(0, dvc(0, 1, 5, 4));
    e.dvc_from.insert(1, dvc_offset(1, 1, 4, 4, 4)); // tail-empty synced participant
    let (_log, op_head, commit_star) = e.select_canonical_log();
    assert_eq!(op_head, 5);
    assert_eq!(commit_star, 4);
    assert!(commit_star <= op_head);
  }

  // ── B3: offset-aware canonical-log selection (UNION committed entries across DVCs) ──

  #[test]
  fn select_canonical_log_unions_committed_ops_across_different_floor_dvcs() {
    // The reviewer's reproduction (the heart of B3): TWO different-floor offset DVCs in the SAME
    // canonical generation, both head op 10 commit 8. r0 (floor 4) holds ops 5..=10; r1 (floor 8) holds
    // only 9,10. Both tie at op 10, so the OLD `max_by_key(op)` (ties → highest replica id) picks r1's
    // log [9,10] and SILENTLY DROPS committed ops 5,6,7 — which only r0 holds. The `commit* <= op_head`
    // fail-stop does NOT trip (the dropped ops are interior). select_canonical_log MUST instead UNION:
    // the returned canonical log must cover EVERY committed op (5..=8) that ANY canonical DVC holds.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
    e.dvc_from.insert(0, dvc_offset(0, 1, 4, 10, 8)); // floor 4: holds 5,6,7,8,9,10
    e.dvc_from.insert(1, dvc_offset(1, 1, 8, 10, 8)); // floor 8: holds 9,10 only
    let (log, op_head, commit_star) = e.select_canonical_log();
    assert_eq!(op_head, 10, "canonical head is the generation's head");
    assert_eq!(commit_star, 8, "commit* is the greatest commit");
    // The committed band the union MUST cover: ops 5..=8 (above the lowest floor 4, up to commit*).
    // Without the union fix the log would be just [9,10] and these would be absent.
    let present: std::collections::BTreeSet<u64> = log.iter().map(|e| e.op().get()).collect();
    for op in 5..=8u64 {
      assert!(
        present.contains(&op),
        "committed op {op} (held only by r0's offset log) must be in the canonical log, not dropped"
      );
    }
    // And the uncommitted tail r0 holds (9,10) is included too (no nack quorum truncates it here).
    assert!(
      present.contains(&9) && present.contains(&10),
      "the head ops are present"
    );
    // The entries are the real ones (op-tagged bodies), not fabricated.
    for entry in &log {
      assert_eq!(
        entry.body(),
        &entry.op().get().to_be_bytes()[..],
        "each unioned entry carries the donor's real body"
      );
    }
  }

  #[test]
  fn select_canonical_log_stitches_the_band_across_three_offset_donors() {
    // Three canonical-generation donors with staggered floors must be STITCHED so the committed band
    // is fully covered even though NO single donor holds it all. N=5, quorum_view_change=3.
    //   r0: floor 0, holds 1,2,3 (head 3)         — the prefix
    //   r1: floor 3, holds 4,5,6 (head 6)         — the middle
    //   r2: floor 6, holds 7,8 (head 8, commit 8) — the suffix + the committed frontier
    // commit* = 8, op_head = 8. The union must produce a dense [1..=8] — dropping any of 1..=8 would
    // lose a committed op some lower-floor adopter needs.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 5).unwrap(), 0, NoopSm);
    e.dvc_from.insert(0, dvc_offset(0, 1, 0, 3, 3));
    e.dvc_from.insert(1, dvc_offset(1, 1, 3, 6, 6));
    e.dvc_from.insert(2, dvc_offset(2, 1, 6, 8, 8));
    let (log, op_head, commit_star) = e.select_canonical_log();
    assert_eq!(op_head, 8);
    assert_eq!(commit_star, 8);
    let present: std::collections::BTreeSet<u64> = log.iter().map(|e| e.op().get()).collect();
    assert_eq!(
      present,
      (1..=8u64).collect::<std::collections::BTreeSet<u64>>(),
      "the union stitches all three offset donors into a gapless committed band 1..=8"
    );
  }

  /// Build a MALFORMED DVC that CLAIMS head `claimed_op` but carries only `present` real entries
  /// (`1..=present`). Models a peer (or fuzzed wire input) advertising an enormous op far above its
  /// actual log — the F4 attack shape.
  fn dvc_claiming(
    replica: u8,
    log_view: u64,
    claimed_op: u64,
    commit: u64,
    present: u64,
  ) -> DoViewChange {
    let log = (1..=present)
      .map(|i| {
        PreparedEntry::new(
          OpNumber::with(i),
          ClientId::new(1),
          RequestNumber::with(i),
          Bytes::copy_from_slice(&i.to_be_bytes()),
        )
      })
      .collect();
    DoViewChange::new(
      View::with(log_view + 10),
      View::with(log_view),
      OpNumber::with(claimed_op),
      OpNumber::with(commit),
      ReplicaId::new(replica),
      log,
    )
  }

  #[test]
  fn select_canonical_log_bounds_a_dvc_claiming_a_huge_op() {
    // F4 REGRESSION (unbounded nack-scan + overflow): DoViewChanges whose CLAIMED `op` is enormous
    // (here `u64::MAX`) but whose `log_slice()` carries only a few real entries must NOT make the
    // nack-truncation loop scan `commit*+1 ..= u64::MAX` op-by-op. The UNBOUNDED case is when a NACK
    // quorum's worth of donors claim a huge op: then the loop's nack count never reaches the threshold
    // for any finite op, so the OLD `while op <= op_head { ...; op += 1 }` would iterate ~u64::MAX
    // times and finally OVERFLOW `op += 1` at `u64::MAX`. With the fix the scan is derived from the
    // sorted donor ops (bounded by the DVC count) and `op_head` is bounded to the represented log.
    // N=3 → quorum_nack_prepare = 2, so we make TWO donors claim the phantom head.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
    // r0: honest — holds ops 1,2,3 (head 3, commit 2).
    e.dvc_from.insert(0, dvc(0, 1, 3, 2));
    // r1, r2 (SAME generation): MALFORMED — each claims op == u64::MAX but carries only ops 1..=3.
    e.dvc_from.insert(1, dvc_claiming(1, 1, u64::MAX, 2, 3));
    e.dvc_from.insert(2, dvc_claiming(2, 1, u64::MAX, 2, 3));
    // Must return PROMPTLY (no unbounded scan, no overflow panic) and bound op_head to the represented
    // log: the max op actually present across the canonical donors is 3, so op_head <= 3.
    let (log, op_head, commit_star) = e.select_canonical_log();
    assert!(
      op_head <= 3,
      "op_head must be bounded to the represented log (<= 3), not the claimed u64::MAX, got {op_head}"
    );
    assert_eq!(commit_star, 2, "commit* is the greatest claimed commit");
    assert!(
      commit_star <= op_head,
      "the fail-stop invariant still holds"
    );
    // The merged log contains only real, present entries — never a phantom op near u64::MAX.
    for entry in &log {
      assert!(
        entry.op().get() <= 3,
        "no fabricated entry above the represented log"
      );
    }
  }

  #[test]
  fn adopt_canonical_head_keeps_committed_ops_an_offset_canonical_log_omits() {
    // B3 gate, CORRECTED to the safe semantics (this is a correctness CORRECTION, not a weakening — see
    // below). A backup holds committed ops 5..=8 in its OFFSET log; the lower band 5,6 it has APPLIED
    // (commit_min == 6), the upper band 7,8 it has NOT (committed by a prior-view quorum but unapplied;
    // op == 8). It adopts a StartView whose canonical log is itself OFFSET, starts at op 9 (does NOT
    // carry 5..=8), commit 8. The two bands are now handled DIFFERENTLY, and that distinction is the fix:
    //
    //   * APPLIED & omitted (5,6, `op <= commit_min`): a committed op the adopter ITSELF applied is
    //     immutable (VSR committed-op survival ⇒ no other view committed a different value), so its local
    //     copy is canonical. It is PRESERVED directly from `self.log` (kept, never re-fetched).
    //   * UNAPPLIED & omitted (7,8, `op in (commit_min, commit]`): the held body is unapplied and may be a
    //     STALE superseded proposal (VOPR seed 24) — `LogEntry` has no per-entry view to tell. It is
    //     therefore DROPPED and REPAIRED: `advance_commit` HOLDS the commit at the first such op and
    //     `request_repair`s the CANONICAL value from a committed-vouching peer.
    //
    // Why this is a CORRECTION, not a weakening of the original B3 safety property: B3's invariant is "no
    // committed op an offset canonical log omits is ever LOST." That still holds end-to-end here — the
    // omitted committed band ends up correct (applied to the SM after repair), never silently skipped. The
    // ONLY change is the SOURCE for the UNAPPLIED band: a possibly-stale local copy (which diverged the
    // committed log under seed 24) is replaced by the quorum's canonical value fetched via peer-repair.
    // The original B3 bug (clearing the whole log + then `repair.clear()` stranding the op) stays fixed:
    // the omitted committed op is never forgotten — it is a held hole until its canonical value arrives.
    let mut e = Endpoint::new(
      Config::try_new(1, ReplicaId::new(2), 3).unwrap(),
      0,
      CountSm::default(),
    );
    // Hand-build the offset-backup state: checkpoint 4, applied through 6 (commit_min == commit_max == 6;
    // the [1..=6] prefix lives in the checkpoint, not the empty CountSm), head 8, offset tail 5..=8 held.
    e.checkpoint_op = OpNumber::with(4);
    e.commit_min = OpNumber::with(6);
    e.commit_max = OpNumber::with(6);
    e.op = OpNumber::with(8);
    for op in 5..=8u64 {
      e.log.insert(
        op,
        LogEntry {
          client: ClientId::new(7),
          request: RequestNumber::with(op),
          body: Bytes::copy_from_slice(&op.to_be_bytes()),
        },
      );
    }
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // The canonical StartView for view 1 from primary 1: an OFFSET log starting at op 9 (head 10),
    // commit 8. It does NOT carry ops 5..=8.
    let sv = StartView::new(
      View::with(1),
      OpNumber::with(10),
      OpNumber::with(8),
      ReplicaId::new(1),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(9),
          ClientId::new(7),
          RequestNumber::with(9),
          Bytes::copy_from_slice(&9u64.to_be_bytes()),
        ),
        PreparedEntry::new(
          OpNumber::with(10),
          ClientId::new(7),
          RequestNumber::with(10),
          Bytes::copy_from_slice(&10u64.to_be_bytes()),
        ),
      ],
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartView(sv),
    );
    assert_eq!(e.status(), Status::Normal, "adoption completes");
    // APPLIED & omitted (5,6): PRESERVED directly — still in the log cache, never turned into a hole.
    assert!(
      e.log.contains_key(&5) && e.log.contains_key(&6),
      "an omitted committed op the adopter HAS applied is preserved directly from its own log"
    );
    assert!(
      !e.has_repair_hole_for_test(5) && !e.has_repair_hole_for_test(6),
      "the applied-and-preserved ops are not repaired"
    );
    // UNAPPLIED & omitted (7,8): REPAIRED. The commit is HELD at the first (6) until the canonical value
    // arrives; op 7 is a registered hole (op 8 becomes one after 7 fills). The held copy was DROPPED.
    assert_eq!(
      e.commit(),
      OpNumber::with(6),
      "commit is HELD at the unapplied omitted band until the canonical value is repaired"
    );
    assert!(
      e.has_repair_hole_for_test(7) && !e.log.contains_key(&7),
      "the first unapplied omitted committed op (7) is a repair hole, its held body dropped"
    );
    // A committed-vouching peer (commit 8 >= op) supplies the canonical value for the repaired band.
    for op in [7u64, 8] {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Replica(ReplicaId::new(1)),
        repair_prepare(1, op, 8),
      );
    }
    assert_eq!(
      e.commit(),
      OpNumber::with(8),
      "commit reaches 8: the omitted committed band is repaired, not lost (the B3 safety property holds)"
    );
    // The SM applied exactly the unapplied band 7,8 (5,6 lived below commit_min, never re-applied; 1..=4
    // in the checkpoint). SAFETY: no committed op the offset StartView omitted was lost.
    let applied: std::vec::Vec<u64> = e.sm.applied().iter().map(|(op, _)| *op).collect();
    assert_eq!(
      applied,
      std::vec![7, 8],
      "the unapplied omitted committed band 7..=8 is repaired to the SM (canonical value, not stale local)"
    );
    assert!(
      e.repair.is_empty(),
      "no committed op is left stranded in the repair set"
    );
  }

  #[test]
  fn adopt_log_does_not_preserve_a_stale_unapplied_held_copy_for_a_committed_op() {
    // SAFETY REGRESSION (VOPR seed 24): the B3 "preserve the omitted committed op from the adopter's
    // own log" rule is only sound for ops the adopter has APPLIED (`op <= commit_min`) — those are
    // committed+immutable. For a committed op in `(commit_min .. adopted_commit]` the adopter holds a
    // body it has NOT applied: it can be a STALE UNCOMMITTED proposal from an earlier view that a later
    // view overwrote with a DIFFERENT committed value (`LogEntry` carries no per-entry view, so the
    // proto cannot tell a canonical-lineage held op from a superseded one). Preserving it diverges the
    // adopter's committed log from the quorum's. The fix: preserve ONLY `op <= commit_min`; the omitted
    // committed band `(commit_min .. adopted_commit]` becomes repair holes whose CANONICAL value is
    // fetched from a committed-vouching peer (commit HELD until then) — never trusted from local.
    //
    // Setup mirrors seed 24: the adopter holds the two committed ops 5,6 TRANSPOSED (op 5 -> body[6],
    // op 6 -> body[5] — stale superseded proposals), while the cluster committed op 5 -> body[5], op 6
    // -> body[6]. checkpoint == commit_min == 4 (those held bodies are UNAPPLIED), op == 8. The adopted
    // offset StartView (head 10, commit 8) OMITS 5,6 (its log starts at op 7).
    let mut e = Endpoint::new(
      Config::try_new(1, ReplicaId::new(2), 3).unwrap(),
      0,
      CountSm::default(),
    );
    e.checkpoint_op = OpNumber::with(4);
    e.commit_min = OpNumber::with(4);
    e.commit_max = OpNumber::with(4);
    e.op = OpNumber::with(8);
    // The STALE, TRANSPOSED held copies for the (commit_min .. commit] band: op 5 holds op 6's body and
    // vice-versa. (Bodies are single-byte `[op]`, matching `repair_prepare`'s canonical encoding, so the
    // post-repair canonical value `[5]`/`[6]` is provably DIFFERENT from the preserved-stale `[6]`/`[5]`.)
    e.log.insert(
      5,
      LogEntry {
        client: ClientId::new(7),
        request: RequestNumber::with(5),
        body: Bytes::copy_from_slice(&[6u8]),
      },
    );
    e.log.insert(
      6,
      LogEntry {
        client: ClientId::new(7),
        request: RequestNumber::with(6),
        body: Bytes::copy_from_slice(&[5u8]),
      },
    );
    // op 7,8 are also in the (commit_min .. commit] band and OMITTED below; they ride the same repair
    // path. Give the adopter NO held copy for them, so they are pure holes filled only from the peer.
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    // The canonical offset StartView for view 1 (head 10, commit 8) starts at op 9 — it OMITS 5,6,7,8.
    let sv = StartView::new(
      View::with(1),
      OpNumber::with(10),
      OpNumber::with(8),
      ReplicaId::new(1),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(9),
          ClientId::new(7),
          RequestNumber::with(9),
          Bytes::copy_from_slice(&[9u8]),
        ),
        PreparedEntry::new(
          OpNumber::with(10),
          ClientId::new(7),
          RequestNumber::with(10),
          Bytes::copy_from_slice(&[10u8]),
        ),
      ],
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartView(sv),
    );
    assert_eq!(e.status(), Status::Normal, "adoption completes");
    // The stale held copies are DROPPED, not preserved: op 5 is a repair hole and the commit is HELD at
    // the first omitted op (4) — never advanced past op 5 with the stale `[6]` body. (Fail-before: the
    // old rule kept 5->[6] and 6->[5], APPLIED both, and commit jumped to 6 — the transposition — before
    // holding at op 7, with NO hole at 5 or 6.)
    assert_eq!(
      e.commit(),
      OpNumber::with(4),
      "commit is HELD at the first omitted committed op (the stale body is not applied)"
    );
    // `advance_commit` registers a hole at the FIRST unfetched committed op (op 5) and HOLDS there —
    // ops 6,7,8 become holes lazily as each fill resumes the apply loop. The decisive safety fact is
    // that op 5's STALE held body `[6]` was DROPPED, so the commit could not advance past it. (Fail-
    // before: the old rule kept 5->[6], 6->[5], applied them, and commit jumped to 6 with NO hole at 5.)
    assert!(
      e.has_repair_hole_for_test(5),
      "the first omitted, unapplied committed op (5) becomes a repair hole (canonical value to be fetched)"
    );
    assert!(
      !e.log.contains_key(&5) && !e.log.contains_key(&6),
      "neither stale transposed body survives in the log cache"
    );
    assert!(
      e.sm.applied().is_empty(),
      "NOTHING is applied yet — no stale transposed body reached the SM"
    );
    // A committed-vouching peer Prepare (commit 8 >= op) supplies the CANONICAL value for each hole in
    // order: op 5 -> body[5], op 6 -> body[6] (the un-transposed quorum values), then op 7,8. Each fill
    // resumes the apply loop, which then registers + we fill the next hole.
    for op in [5u64, 6, 7, 8] {
      assert!(
        e.has_repair_hole_for_test(op),
        "op {op} is a registered repair hole before its canonical Prepare arrives"
      );
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        Peer::Replica(ReplicaId::new(1)),
        repair_prepare(1, op, 8),
      );
    }
    assert!(
      e.repair.is_empty(),
      "every committed hole is filled from the peer's canonical value"
    );
    assert_eq!(
      e.commit(),
      OpNumber::with(8),
      "commit resumes to 8 once the canonical band is repaired"
    );
    // The applied log matches the QUORUM (op 5 -> [5], op 6 -> [6]) — NOT the adopter's stale transpose.
    // This is the exact equality `check_safety` enforces; fail-before it would be [(5,[6]),(6,[5]),...].
    assert_eq!(
      e.sm.applied(),
      &[
        (5, std::vec![5u8]),
        (6, std::vec![6u8]),
        (7, std::vec![7u8]),
        (8, std::vec![8u8]),
      ],
      "the repaired committed band carries the canonical (un-transposed) quorum values"
    );
  }
}

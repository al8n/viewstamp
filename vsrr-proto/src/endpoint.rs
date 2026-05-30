use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use crate::{
  ClientId, Commit, Config, DoViewChange, Event, Header, Instant, Message, OpNumber, Outgoing,
  Peer, Prepare, PrepareOk, Prng, Recipient, ReplicaId, Reply, RequestNumber, StateMachine, Status,
  Superblock, SuperblockDone, View, Wal, WalDone,
};

/// What the endpoint does when a submitted storage op completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
  /// A prepare append; on completion, record the ack for this op.
  Ack(OpNumber),
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
}

const PREPARE_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
const COMMIT_HEARTBEAT: core::time::Duration = core::time::Duration::from_millis(50);
const PRIMARY_IDLE: core::time::Duration = core::time::Duration::from_millis(200);
const VC_MESSAGE_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
const VIEW_CHANGE_STATUS: core::time::Duration = core::time::Duration::from_millis(500);
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
  /// checkpoint-read `Fault` is re-submitted within this budget; a *permanent* one is unreachable in
  /// M3.3a — the durable root only ever names a fully-written snapshot (the root write is step 2,
  /// after the snapshot is durable) — so the budget always clears. Exhausting it is a state-sync
  /// (M3.4) concern, asserted unreachable here.
  checkpoint_retries: u8,
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
  /// These maps are never pruned (committed entries accumulate). Bounded for the
  /// simulator's finite runs; a checkpoint/GC trim is deferred to M3.
  log: BTreeMap<u64, LogEntry>,
  /// Primary pipeline: op → ack tracking.
  ///
  /// These maps are never pruned (committed entries accumulate). Bounded for the
  /// simulator's finite runs; a checkpoint/GC trim is deferred to M3.
  inflight: BTreeMap<u64, Inflight>,
  /// Backup reorder buffer: future prepares awaiting contiguity.
  buffer: BTreeMap<u64, Prepare>,
  /// Client session table.
  ///
  /// These maps are never pruned (committed entries accumulate). Bounded for the
  /// simulator's finite runs; a checkpoint/GC trim is deferred to M3.
  clients: BTreeMap<u128, Session>,
  sm: S,
  outgoing: VecDeque<Outgoing>,
  events: VecDeque<Event>,
  timers: Timers,
  /// Monotonic source of storage correlation ids.
  next_op_id: u64,
  /// Outstanding storage submissions awaiting completion.
  pending: BTreeMap<u64, Pending>,
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
      pending_sb: None,
      pending_checkpoint: None,
      checkpoint_op: OpNumber::new(),
      peer_checkpoint: BTreeMap::new(),
      recover: None,
      repair: std::collections::BTreeSet::new(),
      sync: None,
      sync_serving: BTreeMap::new(),
      state_syncs_applied: 0,
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
  /// - `status = Status::Recovering`, and a fresh [`RecoverState`]: every `op in (checkpoint_op ..
  ///   head]` is submitted via `submit_read` (minted `OpId` recorded in `recover.reads`) with a
  ///   [`RECOVER_READ_RETRIES`] budget in `recover.pending`; if `checkpoint_op > 0` the checkpoint
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
    // The recovered head is the WAL head, but never BELOW the durable checkpoint: a STATE-SYNCED
    // replica (M3.4a) holds no WAL at or below the synced checkpoint (it pruned the WAL there and
    // never appended the tail), so its `wal.op_head()` can be below `checkpoint_op`. The SM snapshot
    // owns `[1..=checkpoint_op]`, so the recovered head must be at least `checkpoint_op` to preserve
    // `op >= commit_max >= commit_min == checkpoint_op`; the tail above re-applies as the primary
    // re-announces it. (Before state-sync this was a no-op: GC is deferred, so a checkpoint-bearing
    // WAL always held `[1..=head]` with `head >= checkpoint_op`.) The cache below covers only the
    // OFFSET tail `(checkpoint_op .. head]` — for a synced replica that range is empty, exactly the
    // post-sync shape; the prefix `[1..=checkpoint_op]` lives in the restored SM snapshot.
    let op = head.max(checkpoint_op);

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
      pending_sb: None,
      pending_checkpoint: None,
      checkpoint_op: OpNumber::with(checkpoint_op),
      peer_checkpoint: BTreeMap::new(),
      recover: None,
      repair: std::collections::BTreeSet::new(),
      sync: None,
      sync_serving: BTreeMap::new(),
      state_syncs_applied: 0,
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
    for op in (checkpoint_op + 1)..=head {
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
    if self.status.is_recovering() {
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
      Message::DoViewChange(m) => self.on_do_view_change(now, sb, m),
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
      Status::Normal if self.is_primary() => self.primary_timeouts(now),
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
    let Some(Pending::Ack(op)) = self.pending.remove(&id.get()) else {
      return;
    };
    if self.is_primary() {
      // the primary's own append is durable → record its vote and try to commit
      let own = 1u64 << self.config.replica().get();
      if let Some(inf) = self.inflight.get_mut(&op.get()) {
        inf.oks |= own;
      }
      self.try_commit(now, sb);
    } else {
      self.send_prepare_ok(op);
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
          PendingSbAction::AdoptedStartView => self.start_view_acks(now),
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
          if self.sync.is_some() {
            self.sync = None;
            self.timers.sync_solicit = None;
            // Non-vacuity signal (M3.4a): a state-sync just fully applied + became durable.
            self.state_syncs_applied += 1;
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
        let (sessions, sm_tail) = Self::decode_checkpoint(cr.snapshot());
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
        // Retry the checkpoint read within budget. A *permanent* checkpoint-read fault is
        // unreachable in M3.3a: the durable root only ever names a fully-written snapshot, so the
        // sim injects only TRANSIENT checkpoint faults — the budget always clears. Exhaustion would
        // mean the durable root names an unreadable checkpoint, which is a state-sync (M3.4) repair
        // concern, not something we can resolve locally; we assert it unreachable rather than hang.
        let budget = self
          .recover
          .as_ref()
          .map(|r| r.checkpoint_retries)
          .unwrap_or(0);
        assert!(
          budget > 0,
          "recover: checkpoint read faulted past its retry budget — the durable root names an \
           unreadable snapshot (a permanent checkpoint fault is an M3.4 state-sync concern, \
           unreachable in M3.3a where the root always names a fully-written snapshot)"
        );
        let new_id = self.mint_op_id();
        if let Some(rec) = self.recover.as_mut() {
          rec.checkpoint = Some(new_id.get());
          rec.checkpoint_retries = budget - 1;
        }
        sb.submit_read_checkpoint(new_id);
        // No progress to report yet (still awaiting the snapshot); but keep wal in the signature
        // uniform with on_recover_wal_done for the handle_storage call site.
        let _ = &mut *wal;
      }
      SuperblockDone::Wrote(_) => {
        // A stale durable-root/checkpoint *write* completion from before the crash cannot occur
        // (a fresh recover issues no writes); ignore defensively rather than panic.
      }
    }
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
  fn recover_progress<B: Superblock>(&mut self, now: Instant, _sb: &mut B) {
    let Some(rec) = self.recover.as_ref() else {
      return;
    };
    // Still draining? (tail reads pending OR the checkpoint snapshot not yet restored). Keep the
    // recover_retry timer armed (via arm_timers for the current Recovering status) so an owner
    // re-submits any dropped/slow read.
    if !rec.pending.is_empty() || rec.checkpoint.is_some() {
      self.arm_timers(now);
      return;
    }
    if rec.faulty.is_empty() {
      // Tail consistent: every body is present + checksum-verified → return to Normal. A recovered
      // backup re-emits nothing; it waits for the primary's Prepare/Commit to re-announce commit.
      self.recover = None;
      self.status = Status::Normal;
      self.arm_timers(now);
      return;
    }
    // Some slot read back permanently faulty (the per-slot retry budget — and the on-disk recover_retry
    // re-reads — were exhausted, so it cannot be cleared from this replica's own disk).
    let head = self.op.get();
    if rec.faulty.contains(&head) {
      // The head cannot be trusted → RecoveringHead: do not participate. Solicit the canonical head
      // from a peer (the primary answers with a `RecoveryResponse`; a `StartView` also adopts), and
      // keep `recover` so the head stays flagged until adoption returns to Normal.
      self.status = Status::RecoveringHead;
      self.arm_timers(now);
      self.send_recovery(now);
      return;
    }
    // Only non-head committed slots are faulty: hand each to peer fault-repair (B4) and return to
    // Normal. Each faulty op is dropped from the dense `log` cache (so it is never applied with a
    // wrong/empty body) and recorded in `repair`; the apply loops HOLD the commit at the first hole
    // and the repair timer re-fetches it from a peer. We must reach Normal first — a Recovering
    // replica drops all messages, so it could not receive the repair `Prepare` while Recovering.
    let faulty: std::vec::Vec<u64> = rec.faulty.iter().copied().collect();
    self.recover = None;
    self.status = Status::Normal;
    for op in faulty {
      self.log.remove(&op);
      self.repair.insert(op);
    }
    self.arm_timers(now);
    // Solicit every hole now (the timer also re-solicits on a cadence until each is filled).
    let ops: std::vec::Vec<u64> = self.repair.iter().copied().collect();
    for op in ops {
      self.send_request_prepare(op);
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
    let (ops, want_checkpoint) = match self.recover.as_ref() {
      Some(rec) => {
        let mut ops: std::vec::Vec<u64> = rec.pending.keys().copied().collect();
        ops.extend(rec.faulty.iter().copied());
        ops.sort_unstable();
        ops.dedup();
        (ops, rec.checkpoint)
      }
      None => (std::vec::Vec::new(), None),
    };
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
    });
    self.send_request_sync(now);
  }

  /// Broadcast a `RequestSync` advertising our CURRENT (stale) checkpoint + the live sync nonce, and
  /// (re)arm the solicit timer. Any `Normal` peer with a strictly-newer durable checkpoint answers.
  fn send_request_sync(&mut self, now: Instant) {
    let nonce = self.sync.map_or(self.nonce, |s| s.nonce);
    self.outgoing.push_back(Outgoing::new(
      Recipient::Backups,
      Message::RequestSync(crate::RequestSync::new(
        self.view,
        self.checkpoint_op,
        self.config.replica(),
        nonce,
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
    if self.checkpoint_op.get() == 0 || self.checkpoint_op.get() <= m.checkpoint_op().get() {
      return; // nothing durable, or nothing strictly newer than the requester — silent.
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
    if m.checkpoint_op().get() <= self.op.get() {
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
  /// **No committed op the replica already held AHEAD of the sync can be lost.** The trigger requires
  /// the synced `checkpoint_op > self.op` (re-asserted by the release-active assert below), so the
  /// replica's entire held log `[..=self.op]` is at or below the synced point — every op `<=
  /// checkpoint_op` is already reflected in the restored SM. A *committed* op above `self.op` is
  /// impossible (committing an op requires having prepared it, which would put it `<= self.op`); the
  /// only thing discarded is a stale/uncommitted tail at or below the synced checkpoint, which is safe.
  /// The assert makes any future trigger-loosening that violates this fail loudly rather than silently
  /// drop a committed op (matching `select_canonical_log`'s fail-stop style).
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
    // Release-active safety assert: the synced checkpoint is strictly above our head, so discarding
    // our held log `[..=op]` cannot drop a committed op (see the method doc's reasoning).
    assert!(
      checkpoint_op.get() > self.op.get(),
      "state-sync must not discard a held op above the synced checkpoint (checkpoint_op {} <= op {})",
      checkpoint_op.get(),
      self.op.get()
    );
    // Decode + restore the SM and the client-session table from the verified envelope.
    let (sessions, sm_tail) = Self::decode_checkpoint(m.snapshot());
    self.sm.restore(sm_tail);
    self.clients = sessions;
    // Advance metadata monotonically to the synced point: it becomes the new head (we hold no log
    // above it) and the applied+committed frontier. `op == commit_max == commit_min == checkpoint_op`
    // respects `op >= commit_max >= commit_min >= checkpoint_op` with equality at the synced point.
    self.op = checkpoint_op;
    self.commit_min = checkpoint_op;
    self.commit_max = checkpoint_op;
    // Drop all in-memory tail/pipeline state: we hold no ops below the checkpoint (subsumed by the
    // snapshot) and none above yet — exactly the post-recover-from-checkpoint shape. Any pending-repair
    // hole was necessarily `<= checkpoint_op` (it was a committed op below our old head), so it is
    // subsumed too; clear it and stop the repair timer (mirrors `adopt_canonical_head`).
    self.log.clear();
    self.inflight.clear();
    self.buffer.clear();
    self.repair.clear();
    self.timers.repair_retry = None;
    self.pending.clear();
    // Rebuild the durable WAL for "head == checkpoint_op, nothing below needed": drop any stale tail
    // slots ABOVE the synced point (a stale generation that would otherwise read back as a higher,
    // wrong head on a later restart), then free slots BELOW it (superseded by the snapshot). After
    // this, `wal.op_head() <= checkpoint_op` with no slot above; we do NOT require the WAL head to
    // EQUAL `self.op` — state-sync replicas, like recover-from-checkpoint replicas, rebuild the tail
    // from the primary's next Prepare. The durable ROOT below names `commit = checkpoint_op`, so a
    // later `recover()` restores cleanly at the synced point.
    wal.truncate(checkpoint_op);
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
    let envelope = Self::encode_checkpoint(&self.clients, &snapshot);
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
  /// (Residual, flagged for a later milestone: a `Normal` replica holding a PERMANENTLY-faulty hole at
  /// `N` *below its own head but above its own checkpoint*, where every replica that ever held `N` has
  /// pruned it — a correlated multi-replica permanent fault on a single pruned op. Its head `>=`
  /// the cluster checkpoint, so the `> self.op` sync trigger may not fire, and no peer can serve the
  /// pruned op: it is stuck (a liveness gap, not an agreement/durability violation — no committed op is
  /// rewritten). Unreachable under the honest crash-stop + no-fault model of this milestone's gate
  /// (`StorageFaults::none()` ⇒ append-before-ack ⇒ no hole below a live head). A future
  /// "stuck-below-the-cluster-checkpoint ⇒ force state-sync" escalation closes it.)
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

  fn primary_timeouts(&mut self, now: Instant) {
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
      // Retransmit every un-committed prepare, in op order.
      // NOTE (M3): this only re-sends ops in `commit_min+1..=op`; a backup that has
      // fallen BELOW `commit_min` (a gap at/under the commit point) cannot be repaired
      // by retransmission and needs state transfer (GetState/NewState), which is
      // out of scope for M1. Quorum still progresses via the primary + one healthy
      // backup, so this is not an M1 liveness blocker.
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

  fn on_do_view_change<B: Superblock>(&mut self, now: Instant, sb: &mut B, m: crate::DoViewChange) {
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
      self.start_view_as_new_primary(now, sb);
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

    let mut op_head = canonical.iter().map(|d| d.op().get()).max().unwrap_or(0);
    let commit_star = dvcs.iter().map(|d| d.commit().get()).max().unwrap_or(0);
    // Fail-stop (in ALL builds): if a committed op exceeds the canonical generation's head, the
    // cross-DVC VSR view-change invariant is broken — panicking is strictly safer than silently
    // dropping the committed op (which a release build's `advance_commit` cap would otherwise do).
    assert!(
      commit_star <= op_head,
      "VSR safety invariant violated: commit* ({commit_star}) > op_head ({op_head}) — a committed op \
       is above the canonical log head; refusing to silently drop it"
    );

    // Truncate the uncommitted tail at the first op with a nack quorum (ascending; nacks are
    // monotonic in op, so the first crossing truncates everything above it). Unchanged: this acts on
    // the UNCOMMITTED tail `(commit* .. op_head]` only — a committed op is never truncated.
    let threshold = self.config.quorum_nack_prepare();
    let mut op = commit_star + 1;
    while op <= op_head {
      let nacks = dvcs.iter().filter(|d| d.op().get() < op).count();
      if nacks >= threshold {
        op_head = op - 1;
        break;
      }
      op += 1;
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
  fn start_view_as_new_primary<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
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
    self.adopt_log(&canonical_log, commit_star);
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

    // Rebuild the pipeline for uncommitted ops; the new primary votes for each.
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

    // Defer participation (StartView broadcast + arm_timers + try_commit) to on_sb_done.
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
  fn adopt_log(&mut self, entries: &[crate::PreparedEntry], commit: u64) {
    let supplied: std::collections::BTreeSet<u64> = entries.iter().map(|e| e.op().get()).collect();
    // Retain only the committed ops the canonical log omits (`op <= commit` and not in `supplied`):
    // those are the adopter's own authoritative copies of committed ops a different-floor canonical
    // generation could not carry. Everything else (uncommitted tail, ops the canonical log supplies)
    // is dropped so the canonical entries below are authoritative.
    self
      .log
      .retain(|&op, _| op <= commit && !supplied.contains(&op));
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
  /// **No committed op is lost.** A `RecoveringHead` replica has already restored its durable
  /// checkpoint prefix `[1..=checkpoint_op]` into the SM during `Recovering` (so
  /// `commit_min == checkpoint_op`); the `op >= commit_min` assert below rejects any head that would
  /// rewind below that durable prefix. The adopted log is the offset tail `(min_floor .. op]` from the
  /// canonical primary (NOT necessarily dense `[1..=op]` — the primary may itself be a
  /// recover-from-checkpoint / state-synced replica whose log starts above op 1). `adopt_log` is
  /// therefore defensive: it **preserves any committed op the adopter already holds** that the
  /// incoming offset log omits, instead of clearing the log and destroying the adopter's own durable
  /// copy. `advance_commit` then applies `(commit_min .. commit]` from the union of the preserved
  /// held copies and the adopted entries; should a committed op be supplied by NEITHER, it
  /// `request_repair`s it from a peer and HOLDS the commit there (never skips it). The checkpointed
  /// prefix lives in the SM, the committed tail in the (preserved+adopted) log — the committed prefix
  /// is reconstructed end to end, with peer-repair as the backstop for any op neither side carries.
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
    self.adopt_log(log, commit.get());
    self.op = op;
    // Retire any pending-repair holes the adopted canonical log NOW supplies (or that the adopter's
    // own preserved copy now covers, since `adopt_log` kept committed held ops). Holes the canonical
    // log omits AND the adopter does not hold remain solicited; `advance_commit` below re-requests
    // them. This MUST happen before `advance_commit` (which may add new holes) so we never wipe a
    // freshly-requested committed-op repair.
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
    // (The pending-repair set was reconciled above — holes the adopted log / preserved held copies now
    // cover were retired; any committed op neither side carries stays solicited and was re-requested by
    // `advance_commit`. We deliberately do NOT blanket-clear `repair` here: that was the B3 stranding
    // bug — clearing right after `advance_commit` requested a hole silently forgot a committed op.)
    // Abandon in-flight WAL appends from the old view (see transition_to_view_change_status).
    self.pending.clear();
    // Drop stale per-replica checkpoint reports from the old generation (see
    // transition_to_view_change_status); a backup-turned-... primary rebuilds from fresh PrepareOk.
    self.peer_checkpoint.clear();
    // Supersede any in-flight checkpoint from the old view (its stale superblock completion is then
    // ignored). The view-change root below preserves the durable checkpoint_op via submit_durable_view.
    self.pending_checkpoint = None;
    // Abandon any in-flight state-sync: adopting an authoritative canonical head supersedes it (the
    // adopted canonical log + the adopter's preserved committed ops supply the committed prefix, with
    // peer-repair as the backstop). See the note in `transition_to_view_change_status` on the
    // mid-persist case (safe; re-syncs from Normal if still behind).
    self.sync = None;
    self.timers.sync_solicit = None;
    self.dvc_quorum = false;
    self.arm_timers(now);
    // Defer held-op re-acks to on_sb_done: persist the new view before acking in it.
    self.submit_durable_view(PendingSbAction::AdoptedStartView, sb);
  }

  /// Runs once the adopted-StartView superblock write is durable: re-ack held uncommitted ops.
  fn start_view_acks(&mut self, _now: Instant) {
    // Ack every held uncommitted op so the new primary can re-reach quorum in this view.
    for op in (self.commit_min.get() + 1)..=self.op.get() {
      self.send_prepare_ok(OpNumber::with(op));
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
    if self.pending_sb.is_some() {
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
      // Already have this op; (re)ack so a lost prepare_ok is recovered.
      // Ops are immutable within a view. The higher-view rule (top of this fn)
      // and the `view != self.view` reject mean this re-ack only fires for a
      // current-view prepare, so blind re-ack is safe.
      // This op is already durable → re-ack immediately (inline, no WAL submit).
      self.send_prepare_ok(p.op());
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
      // Future op: buffer until the gap fills (primary also retransmits).
      self.buffer.insert(pop, p);
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
    // PrepareOk is deferred to on_wal_done when the append is durable.
  }

  fn send_prepare_ok(&mut self, op: OpNumber) {
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
      // Maintain the client-session request high-water as we apply (mirrors the primary's `commit_op`,
      // minus the reply body a backup discards). This is the at-most-once dedup watermark a
      // backup-turned-primary needs in `on_request`. It MUST be tracked here on every apply — NOT
      // reconstructed from the `log` cache when becoming primary — because M3.4b GC prunes the `log`
      // below the checkpoint, so a backup whose log is empty (everything checkpointed+pruned) would
      // otherwise carry a stale `session.request` of 0 and wedge every client on the gap check
      // (`r.request() != session.request + 1`). The snapshot also restores these on recover/state-sync,
      // so the watermark survives both GC and a checkpoint restore.
      let session = self.clients.entry(entry.client.get()).or_default();
      if entry.request.get() > session.request.get() {
        session.request = entry.request;
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
    self
      .peer_checkpoint
      .insert(ok.replica().get(), ok.checkpoint_op());
    // State-sync trigger (symmetric): a backup reporting a checkpoint above our head means we are the
    // laggard (e.g. a partition-healed old primary). The `> self.op` gate keeps this a no-op normally.
    self.maybe_request_sync(now, ok.checkpoint_op());
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
    // primary's last-known checkpoint rather than 0. Bounded by `replica_count`.
    self
      .peer_checkpoint
      .insert(self.config.primary(self.view).get(), c.checkpoint_op());
    // State-sync trigger: if the cluster has checkpointed past our WAL head, solicit a SyncCheckpoint
    // (the ops we'd need are below the cluster checkpoint and may be pruned — tail-apply can't reach).
    self.maybe_request_sync(now, c.checkpoint_op());
    self.advance_commit(now, sb, c.commit().get());
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
    ]
    .into_iter()
    .flatten()
    .min()
  }

  /// Encodes the client-session table + an SM snapshot into one checkpoint envelope.
  ///
  /// Layout: `sessions_len: u32 BE | repeat[ client: u128 BE | request: u64 BE | has_reply: u8 |
  /// (if has_reply) reply_request: u64 BE, reply_len: u32 BE, reply_bytes ] | sm_snapshot_bytes`.
  fn encode_checkpoint(sessions: &BTreeMap<u128, Session>, snapshot: &[u8]) -> Bytes {
    let mut out = std::vec::Vec::new();
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
  /// `(sessions, sm_snapshot_slice)`.
  ///
  /// **Panics on malformed input** — for M3.2a the envelope is always proto-produced; fallibility
  /// is deferred to M3.3 when checkpoint reads can return `Faulty`.
  fn decode_checkpoint(env: &[u8]) -> (BTreeMap<u128, Session>, &[u8]) {
    let mut i = 0usize;
    let count = u32::from_be_bytes(env[i..i + 4].try_into().unwrap()) as usize;
    i += 4;
    let mut sessions = BTreeMap::new();
    for _ in 0..count {
      let client = u128::from_be_bytes(env[i..i + 16].try_into().unwrap());
      i += 16;
      let request =
        crate::RequestNumber::with(u64::from_be_bytes(env[i..i + 8].try_into().unwrap()));
      i += 8;
      let has_reply = env[i];
      i += 1;
      let reply = if has_reply == 1 {
        let rn = crate::RequestNumber::with(u64::from_be_bytes(env[i..i + 8].try_into().unwrap()));
        i += 8;
        let len = u32::from_be_bytes(env[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        let body = Bytes::copy_from_slice(&env[i..i + len]);
        i += len;
        Some((rn, body))
      } else {
        None
      };
      sessions.insert(client, Session { request, reply });
    }
    (sessions, &env[i..])
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
    // PrepareOk is deferred until the view is durable — pump storage first.
    e.handle_storage(now, &mut wal, &mut sb);
    // it should send PrepareOk for the held uncommitted op (op 2) to primary 1.
    let mut acked_op2 = false;
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg() {
        if ok.op() == OpNumber::with(2) {
          acked_op2 = true;
        }
      }
    }
    assert!(
      acked_op2,
      "backup must ack its held uncommitted ops in the new view"
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
    // broadcasts a RequestPrepare for it (peer fault-repair). It HOLDS its commit below the hole.
    let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
    assert_eq!(
      r.status(),
      Status::Normal,
      "a non-head faulty committed slot peer-repairs from Normal (never strands in Recovering)"
    );
    // It solicited op 2 from peers.
    let mut asked_for_2 = false;
    while let Some(out) = r.poll_message() {
      if let Message::RequestPrepare(rp) = out.into_msg() {
        assert_eq!(rp.op(), OpNumber::with(2));
        asked_for_2 = true;
      }
    }
    assert!(asked_for_2, "the replica solicits the faulty committed op");

    // Learn commit up to 3 (e.g. a Commit from the primary): op 1 applies, op 2 is a HOLE → commit
    // HELD at 1 (never skips to apply op 3 with op 2 missing).
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
    e.handle_storage(now, &mut wal, &mut sb);
    let mut acked_op2 = false;
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg() {
        if ok.op() == OpNumber::with(2) {
          acked_op2 = true;
        }
      }
    }
    assert!(
      acked_op2,
      "held uncommitted ops re-acked once the new view is durable"
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
    let env = Endpoint::<NoopSm>::encode_checkpoint(&sessions, &snap);
    let (decoded_sessions, decoded_snap) = Endpoint::<NoopSm>::decode_checkpoint(&env);
    assert_eq!(decoded_snap, &b"SM-SNAPSHOT"[..]);
    assert_eq!(decoded_sessions.len(), 2);
    assert_eq!(decoded_sessions[&7].request, RequestNumber::with(3));
    assert_eq!(
      decoded_sessions[&7].reply.as_ref().unwrap().1,
      Bytes::from_static(b"r3")
    );
    assert_eq!(decoded_sessions[&9].reply, None);
    // empty sessions + empty snapshot is a valid envelope
    let empty = Endpoint::<NoopSm>::encode_checkpoint(&BTreeMap::new(), &Bytes::new());
    let (es, esnap) = Endpoint::<NoopSm>::decode_checkpoint(&empty);
    assert!(es.is_empty());
    assert!(esnap.is_empty());
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
    // No op was ever appended (op_head == 0) and there is no checkpoint, so recovery has nothing to
    // read: the empty-WAL fast path reaches Normal directly in recover() (no handle_storage needed).
    assert_eq!(recovered.status(), Status::Normal);
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

    // Commit ops 3,4 WITHOUT flushing the in-flight checkpoint. The append completions advance
    // commit_min to 4, but maybe_checkpoint must bail (a checkpoint is in flight) — no second
    // snapshot write is armed. (We do NOT flush, so the only inflight write remains the first
    // checkpoint's step-1 snapshot write.)
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
    assert_eq!(e.commit(), OpNumber::with(4));
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(0),
      "the first checkpoint is still in flight"
    );

    // Drive the first (and only) in-flight checkpoint — staged at target_op=2 — to completion by
    // flushing its two writes. It advances checkpoint_op to 2 exactly (NOT 4 — it was staged at 2,
    // and no second checkpoint started for ops 3,4 while it was in flight).
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

    // Now that the first checkpoint is durable, the NEXT commit re-evaluates the boundary:
    // commit_min=4 >= checkpoint_op(2)+2=4 → a SECOND checkpoint triggers (at op 4) and completes.
    // This proves the gate only suppressed the OVERLAP, not all future checkpoints.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(5),
    );
    e.handle_storage(now, &mut wal, &mut sb); // commit op 5 → maybe_checkpoint at commit_min=5 → snapshot write
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb); // snapshot done → root write
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb); // root done → checkpoint advances
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(5),
      "a fresh checkpoint runs once the prior one is durable (boundary re-evaluated at commit_min)"
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
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    assert!(e.poll_message().is_none(), "nothing newer → silent");
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

  #[test]
  fn adopt_canonical_head_keeps_committed_ops_an_offset_canonical_log_omits() {
    // End-to-end defence: a backup holds committed ops 5..=8 in its OFFSET log (checkpoint 4, those ops
    // committed by a prior-view quorum but not yet locally applied: commit_min == 4, op == 8). It then
    // adopts a StartView whose canonical log is itself OFFSET and starts at op 9 (it does NOT carry
    // 5..=8) but whose commit is 8. The OLD adopt_log `self.log.clear()` would DESTROY the backup's own
    // copies of 5..=8, advance_commit would `request_repair(5)`, and adopt_canonical_head's
    // `repair.clear()` would then WIPE that request — stranding the replica below commit with a divergent
    // SM. After the fix the backup keeps 5..=8, applies them, commit reaches 8, and the SM holds 5..=8.
    let mut e = Endpoint::new(
      Config::try_new(1, ReplicaId::new(2), 3).unwrap(),
      0,
      CountSm::default(),
    );
    // Hand-build the offset-backup state: checkpoint 4, committed prefix [1..=4] in the SM (commit_min
    // == commit_max == checkpoint_op == 4), and the offset tail 5..=8 held in the in-memory log.
    e.checkpoint_op = OpNumber::with(4);
    e.commit_min = OpNumber::with(4);
    e.commit_max = OpNumber::with(4);
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
    // commit 8. It does NOT carry ops 5..=8 — those must survive from the adopter's own log.
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
    assert_eq!(
      e.commit(),
      OpNumber::with(8),
      "commit reaches 8: the committed ops 5..=8 were applied, not lost"
    );
    // The SM applied exactly ops 5..=8 (the prior prefix [1..=4] lived in the checkpoint, not re-applied).
    let applied: std::vec::Vec<u64> = e.sm.applied().iter().map(|(op, _)| *op).collect();
    assert_eq!(
      applied,
      std::vec![5, 6, 7, 8],
      "the SM has the committed ops 5..=8 the offset StartView omitted"
    );
    assert!(
      e.repair.is_empty(),
      "no committed op is left stranded in the repair set"
    );
  }
}

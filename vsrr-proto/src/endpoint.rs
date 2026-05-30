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

const PREPARE_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
const COMMIT_HEARTBEAT: core::time::Duration = core::time::Duration::from_millis(50);
const PRIMARY_IDLE: core::time::Duration = core::time::Duration::from_millis(200);
const VC_MESSAGE_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
const VIEW_CHANGE_STATUS: core::time::Duration = core::time::Duration::from_millis(500);

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
    }
  }

  /// Reconstructs an endpoint from durable storage after a restart, restoring from the durable
  /// checkpoint (not op 0).
  ///
  /// Reads the superblock root for `(view, log_view, checkpoint_op, checkpoint_id)` and returns to
  /// `Status::Normal`. Two cases, on `state.checkpoint_op()`:
  ///
  /// - **A checkpoint exists (`checkpoint_op > 0`).** Reads the durable checkpoint snapshot
  ///   (`submit_read_checkpoint` → synchronous `CheckpointRead` drain — see the drain note below),
  ///   splits the envelope into `(sessions, sm_snapshot)`, restores the state machine
  ///   (`sm.restore(sm_snapshot)`) and the client-session table, and sets
  ///   `commit_min = commit_max = checkpoint_op`. The restored SM already reflects the applied
  ///   prefix `[1..=checkpoint_op]`, so `commit_min = checkpoint_op` (NOT 0) prevents double-applying
  ///   those ops; only the committed tail above the checkpoint (`> checkpoint_op`) is re-applied, as
  ///   the primary re-announces commit via `advance_commit`.
  /// - **No checkpoint yet (`checkpoint_op == 0`).** Identical to the M3.1b behavior: a fresh `S`,
  ///   `commit_min = commit_max = 0`, and the committed prefix is re-applied lazily by
  ///   `advance_commit` as the primary re-announces its commit (no checkpoint has persisted a commit
  ///   point yet).
  ///
  /// In both cases the in-memory log cache is rebuilt **dense** from the WAL `[1..=op_head]` (headers
  /// AND real bodies). M3.2a never prunes the WAL (GC is deferred to after M3.4) AND view change is
  /// not yet checkpoint-aware, so the recovered replica must keep the full log to participate safely
  /// in a view change — a sparse log below the checkpoint would make its DoViewChange/StartView omit
  /// committed ops (the same hazard that defers GC). `commit_min = checkpoint_op` means
  /// `advance_commit` never RE-APPLIES `<= checkpoint_op` (those are in the restored SM); the
  /// `[1..=checkpoint_op]` cache entries serve only view-change/retransmit. Post-M3.4 (GC +
  /// checkpoint-aware view change), this rebuild becomes tail-only.
  ///
  /// **Durable-view.** The view is persisted to the superblock before any view-change participation,
  /// so `state.view()` is trustworthy: a recovered replica resumes the view it was in when it last
  /// participated.
  ///
  /// **Synchronous checkpoint/body-read drain.** Bodies and the checkpoint snapshot live behind the
  /// async `submit_read`/`submit_read_checkpoint` + `poll` interface; recovery drains them
  /// synchronously against the in-memory `Wal`/`Superblock` (whose reads complete immediately),
  /// which is why this takes `&mut W` and `&mut B`. When M3.3 makes reads truly async (and able to
  /// return `Fault`/torn), recovery moves into a `Status::Recovering` `handle_storage` read loop that
  /// retries on `Fault`, and these synchronous drains are removed.
  pub fn recover<W: Wal, B: Superblock>(
    config: Config,
    seed: u64,
    mut sm: S,
    wal: &mut W,
    sb: &mut B,
  ) -> Self {
    let state = sb.state();
    let nonce = Prng::new(seed).next_u64();
    let head = wal.op_head().get();
    let checkpoint_op = state.checkpoint_op().get();

    // Restore the checkpoint, if one is durable: read the snapshot envelope (synchronous drain — the
    // in-memory superblock completes the read immediately; the async `Status::Recovering` loop is
    // M3.3), then restore the SM + the client-session table from it. `OpId::new(0)` is a reserved
    // correlation id for the recovery read: `next_op_id` starts at 1, so 0 never aliases a real op.
    // When `checkpoint_op == 0` no checkpoint exists; the SM stays fresh and `clients` stays empty
    // (exactly the M3.1b behavior — the regression guard).
    let mut clients: BTreeMap<u128, Session> = BTreeMap::new();
    if checkpoint_op > 0 {
      sb.submit_read_checkpoint(crate::OpId::new(0));
      while let Some(done) = sb.poll() {
        if let SuperblockDone::CheckpointRead(cr) = done {
          let (restored_sessions, sm_tail) = Self::decode_checkpoint(cr.snapshot());
          sm.restore(sm_tail);
          clients = restored_sessions;
        }
        // M3.2a: a `Fault` here cannot happen — the durable root only ever names a fully-written
        // snapshot (the root write is step 2, after the snapshot write is durable). M3.3 handles
        // `Fault`/torn reads via the async recovery loop.
      }
    }

    // Rebuild the log cache DENSE [1..=head] from the WAL. M3.2a never prunes the WAL and view change
    // is not yet checkpoint-aware, so a recovered replica must hold the FULL log to participate in a
    // view change safely — a sparse log below the checkpoint would omit committed ops from its
    // DoViewChange/StartView (the very hazard that defers GC). `commit_min = checkpoint_op` already
    // prevents re-applying [1..=checkpoint_op] (they are in the restored SM); these cache entries
    // serve only view-change/retransmit. Post-M3.4 (GC + checkpoint-aware view change) this becomes
    // tail-only. Headers from the sync metadata view; bodies via a sync read drain.
    let mut log = BTreeMap::new();
    for op in 1..=head {
      if let Some(h) = wal.header(OpNumber::with(op)) {
        log.insert(
          op,
          LogEntry {
            client: h.client(),
            request: h.request(),
            body: Bytes::new(),
          },
        );
      }
    }
    for op in 1..=head {
      wal.submit_read(crate::OpId::new(op), OpNumber::with(op));
    }
    // Drain every completion, matching each ReadOk to its op, rather than counting reads: a
    // counter could be tripped early by a stray pre-existing completion in the queue, leaving a
    // real op's body empty and silently diverging the SM on re-apply. Draining to `None` fills
    // every requested op exactly (a stray ReadOk for the same op carries the same durable body).
    while let Some(done) = wal.poll() {
      if let WalDone::ReadOk(r) = done {
        if let Some(entry) = log.get_mut(&r.op().get()) {
          entry.body = r.body_bytes();
        }
      }
    }

    Self {
      config,
      status: Status::Normal,
      view: state.view(),
      op: OpNumber::with(head),
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
      log,
      inflight: BTreeMap::new(),
      buffer: BTreeMap::new(),
      clients,
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
    }
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
    match msg {
      Message::Request(r) => self.on_request(now, wal, from, r),
      Message::Prepare(p) => self.on_prepare(now, wal, sb, p),
      Message::PrepareOk(ok) => self.on_prepare_ok(now, sb, ok),
      Message::Commit(c) => self.on_commit(now, sb, c),
      Message::StartViewChange(m) => self.on_start_view_change(now, sb, m),
      Message::DoViewChange(m) => self.on_do_view_change(now, sb, m),
      Message::StartView(m) => self.on_start_view(now, sb, m),
      Message::GetView(m) => self.on_get_view(now, m),
      Message::Reply(_) => {}
    }
  }

  /// Fires any timers due at `now`, dispatching by status/role.
  pub fn handle_timeout<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    let _ = &mut *wal; // WAL unused in timeouts
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
      Status::Recovering | Status::RecoveringHead => {}
    }
  }

  /// Drain completed storage ops and react.
  pub fn handle_storage<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    while let Some(done) = wal.poll() {
      self.on_wal_done(now, sb, done);
    }
    while let Some(done) = sb.poll() {
      self.on_sb_done(now, sb, done);
    }
  }

  fn on_wal_done<B: Superblock>(&mut self, now: Instant, sb: &mut B, done: WalDone) {
    let WalDone::Appended(id) = done else {
      return;
    }; // M3.1a: only appends (reads/faults are later)
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

  fn on_sb_done<B: Superblock>(&mut self, now: Instant, sb: &mut B, done: SuperblockDone) {
    let SuperblockDone::Wrote(id) = done else {
      return; // CheckpointRead is drained synchronously in recover(); Fault is M3.3
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
          // The root is durable → the checkpoint is COMPLETE: advance the in-memory checkpoint_op.
          // (GC / prune of the WAL + maps below the checkpoint lands in Task 5.)
          self.checkpoint_op = pc.target_op;
          self.pending_checkpoint = None;
        }
        _ => {} // a stale/superseded completion (e.g. from before a view change) — ignore
      }
    }
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

  /// The full in-memory log `[1..=op]` as wire entries.
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
    // (commit <= op, dense log [1..=op]). Safe under honest crash-stop peers; matters once
    // untrusted/real-driver inputs land. The cross-DVC commit* <= op_head invariant is enforced
    // (fail-stop) in `select_canonical_log`.
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

  /// VSR canonical-log selection + nack-prepare truncation.
  ///
  /// Returns `(canonical log truncated to op_head, op_head, commit*)`:
  /// - the canonical generation is the DVCs with the greatest `log_view`;
  /// - `op_head` is that generation's head, less any provably-uncommitted tail truncated by a
  ///   `quorum_nack_prepare` of nacks (contiguous ⟹ replica `r` nacks op `X` iff `r.op < X`);
  /// - `commit*` is the greatest commit across all DVCs (commit never rewinds).
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
    // monotonic in op, so the first crossing truncates everything above it).
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

    // Adopt the canonical DVC with the greatest op, truncated to op_head.
    let chosen = canonical
      .iter()
      .copied()
      .max_by_key(|d| d.op().get())
      .expect("canonical set is non-empty");
    let log: std::vec::Vec<crate::PreparedEntry> = chosen
      .log_slice()
      .iter()
      .filter(|entry| entry.op().get() <= op_head)
      .cloned()
      .collect();
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
    // Canonical-log selection + nack-prepare truncation (see `select_canonical_log`).
    let (canonical_log, op_head, commit_star) = self.select_canonical_log();
    self.adopt_log(&canonical_log);
    self.op = OpNumber::with(op_head);
    // status is still ViewChange here, so the maybe_checkpoint at advance_commit's tail is a no-op
    // (checkpoints only start in Normal) — a checkpoint must not race the StartViewAsPrimary
    // durable-view write submitted below.
    self.advance_commit(now, sb, commit_star); // apply newly-exposed committed ops (prior-view quorum decision)

    // Reconstruct client sessions from the adopted log. A backup-turned-primary has no
    // session state; without this, a client's retry of an already-adopted request would be
    // mis-deduplicated by `on_request` — re-executed (request 1) or stalled (request > 1).
    // Record each client's highest accepted request so retries deduplicate.
    //
    // NOTE (deferred to the message-loss fault-sweep milestone): we do NOT yet reconstruct the
    // cached *reply* body, so a client whose prior-view reply was LOST cannot be re-served the
    // cached reply here (it relies on the in-flight op re-committing, or — for already-committed
    // ops under loss — must be handled when the loss/partition faults land). Session-request
    // reconstruction below closes the at-most-once SAFETY hole; the lost-reply resend is liveness
    // under loss and is owned by the later fault-sweep milestone.
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

  /// Replace the in-memory log with the given wire entries.
  fn adopt_log(&mut self, entries: &[crate::PreparedEntry]) {
    self.log.clear();
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
    // Adopt only a strictly newer view, or the current view while we have not yet
    // returned to Normal in it. Re-applying a StartView for a view we are already
    // Normal in would rewind `op` and clobber locally-appended ops.
    if m.view().get() < self.view.get()
      || (m.view().get() == self.view.get() && self.status.is_normal())
    {
      return;
    }
    if m.replica() != self.config.primary(m.view()) {
      return; // must come from the view's primary
    }
    assert!(
      m.commit().get() <= m.op().get(),
      "StartView commit must not exceed its op (malformed primary)"
    );
    assert!(
      m.op().get() >= self.commit_min.get(),
      "must not rewind below our committed op"
    );
    self.view = m.view();
    self.adopt_log(m.log_slice());
    self.op = m.op();
    // status is still ViewChange here, so the maybe_checkpoint at advance_commit's tail is a no-op
    // (checkpoints only start in Normal) — a checkpoint must not race the AdoptedStartView
    // durable-view write submitted below.
    self.advance_commit(now, sb, m.commit().get());
    // log_view = view BEFORE submit_durable_view (try_new requires log_view <= view).
    self.log_view = m.view();
    self.status = Status::Normal;
    self.catching_up = false;
    self.svc_from = 0;
    self.dvc_from.clear();
    // Abandon in-flight WAL appends from the old view (see transition_to_view_change_status).
    self.pending.clear();
    // Drop stale per-replica checkpoint reports from the old generation (see
    // transition_to_view_change_status); a backup-turned-... primary rebuilds from fresh PrepareOk.
    self.peer_checkpoint.clear();
    // Supersede any in-flight checkpoint from the old view (its stale superblock completion is then
    // ignored). The view-change root below preserves the durable checkpoint_op via submit_durable_view.
    self.pending_checkpoint = None;
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
  fn try_commit<B: Superblock>(&mut self, _now: Instant, sb: &mut B) {
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
      self.commit_op(next);
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

  /// Applies op `op` on the primary, caches + sends the reply, emits the event.
  fn commit_op(&mut self, op: u64) {
    let entry = self
      .log
      .get(&op)
      .expect("committed op present in log")
      .clone();
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
      Status::Recovering | Status::RecoveringHead => {}
    }
  }

  fn on_prepare<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    p: Prepare,
  ) {
    if p.view().get() > self.view.get() {
      self.catch_up_to_view(now, p.view());
      return;
    }
    if !self.status.is_normal() || p.view() != self.view || self.is_primary() {
      return;
    }
    // Heard from the primary — defer the idle timeout.
    self.note_primary_contact(now);
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

  /// Applies committed ops we hold, up to `min(target, op)`. Backups discard the
  /// reply but emit `Committed` so observers can verify agreement.
  fn advance_commit<B: Superblock>(&mut self, _now: Instant, sb: &mut B, target: u64) {
    // Record the learned commit regardless of whether we hold the ops yet.
    self.commit_max = OpNumber::with(self.commit_max.get().max(target));
    while self.commit_min.get() < target && self.commit_min.get() < self.op.get() {
      let op = self.commit_min.get() + 1;
      let entry = self
        .log
        .get(&op)
        .expect("committed op present in log")
        .clone();
      let reply = self.sm.apply(OpNumber::with(op), &entry.body);
      self.commit_min = OpNumber::with(op);
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
    PreparedEntry, ReadOk, ReplicaId, Request, RequestNumber, SlotStatus, StartView,
    StartViewChange, Superblock, SuperblockDone, View, VsrState, Wal, WalDone,
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
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(op),
      OpNumber::with(commit),
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
  fn recover_rebuilds_log_and_op_from_wal() {
    // A backup appends ops 1,2 durably, then "crashes". recover() from the SAME wal/sb
    // rebuilds op=2 with REAL bodies, view from the superblock, status Normal.
    let mut e = backup();
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let now = Instant::ZERO;
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
    e.handle_storage(now, &mut wal, &mut sb);
    // Drop `e` (crash). Recover a fresh endpoint from the SAME durable wal/sb.
    drop(e);
    let recovered = Endpoint::recover(
      Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
      0,
      NoopSm,
      &mut wal,
      &mut sb,
    );
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

    // recover() restores from the checkpoint snapshot, NOT by replaying from op 0.
    let recovered = Endpoint::recover(cfg(), 0, CountSm::default(), &mut wal, &mut sb);
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

    let recovered = Endpoint::recover(cfg(), 0, CountSm::default(), &mut wal, &mut sb);
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
}

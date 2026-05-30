use alloc::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use crate::{
  ClientId, Commit, Config, DoViewChange, Event, Instant, Message, OpNumber, Outgoing, Peer,
  Prepare, PrepareOk, Prng, Recipient, ReplicaId, Reply, RequestNumber, StateMachine, Status, View,
};

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
  /// Highest committed op known/applied here.
  commit: OpNumber,
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
      commit: OpNumber::new(),
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

  /// The commit number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
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

  /// Feeds an incoming protocol message.
  pub fn handle_message(&mut self, now: Instant, from: Peer, msg: Message) {
    match msg {
      Message::Request(r) => self.on_request(now, from, r),
      Message::Prepare(p) => self.on_prepare(now, p),
      Message::PrepareOk(ok) => self.on_prepare_ok(now, ok),
      Message::Commit(c) => self.on_commit(now, c),
      Message::StartViewChange(m) => self.on_start_view_change(now, m),
      Message::DoViewChange(m) => self.on_do_view_change(now, m),
      Message::StartView(m) => self.on_start_view(now, m),
      Message::GetView(m) => self.on_get_view(now, m),
      Message::Reply(_) => {}
    }
  }

  /// Fires any timers due at `now`, dispatching by status/role.
  pub fn handle_timeout(&mut self, now: Instant) {
    match self.status {
      Status::Normal if self.is_primary() => self.primary_timeouts(now),
      Status::Normal => {
        // backup: bootstrap + fire primary_idle, then re-arm THIS timer only so we
        // re-propose at the primary_idle cadence (not every tick).
        if self.timers.primary_idle.is_none() {
          self.timers.primary_idle = Some(now + PRIMARY_IDLE);
        }
        if self.timers.primary_idle.is_some_and(|d| d <= now) {
          self.on_primary_idle(now);
          self.timers.primary_idle = Some(now + PRIMARY_IDLE);
        }
      }
      Status::ViewChange => self.view_change_timeouts(now),
      Status::Recovering | Status::RecoveringHead => {}
    }
  }

  fn primary_timeouts(&mut self, now: Instant) {
    // Bootstrap the heartbeat the first time we're ticked as primary.
    if self.timers.commit.is_none() {
      self.timers.commit = Some(now + COMMIT_HEARTBEAT);
    }
    if self.timers.commit.is_some_and(|d| d <= now) {
      self.outgoing.push_back(Outgoing::new(
        Recipient::Backups,
        Message::Commit(Commit::new(self.view, self.commit)),
      ));
      self.timers.commit = Some(now + COMMIT_HEARTBEAT); // re-arm THIS timer only
    }
    if self.timers.prepare.is_some_and(|d| d <= now) {
      // Retransmit every un-committed prepare, in op order.
      // NOTE (M3): this only re-sends ops in `commit+1..=op`; a backup that has
      // fallen BELOW `commit` (a gap at/under the commit point) cannot be repaired
      // by retransmission and needs state transfer (GetState/NewState), which is
      // out of scope for M1. Quorum still progresses via the primary + one healthy
      // backup, so this is not an M1 liveness blocker.
      let lo = self.commit.get() + 1;
      let hi = self.op.get();
      for op in lo..=hi {
        if let Some(entry) = self.log.get(&op).cloned() {
          self.outgoing.push_back(Outgoing::new(
            Recipient::Backups,
            Message::Prepare(Prepare::new(
              self.view,
              OpNumber::with(op),
              self.commit,
              entry.client,
              entry.request,
              entry.body,
            )),
          ));
        }
      }
      // re-arm THIS timer only (clear once everything is committed)
      self.timers.prepare = if self.commit.get() < self.op.get() {
        Some(now + PREPARE_RETRANSMIT)
      } else {
        None
      };
    }
  }

  fn on_primary_idle(&mut self, now: Instant) {
    self.propose_next_view(now);
  }

  /// Propose moving to `self.view + 1`: adopt it as the SVC target (if higher than the current
  /// target), set our own bit, broadcast `StartViewChange{target}`, and transition on quorum.
  fn propose_next_view(&mut self, now: Instant) {
    let target = View::with(self.view.get() + 1);
    if target.get() > self.svc_target.get() {
      self.svc_target = target;
      self.svc_from = 0;
    }
    self.join_svc(now);
    self.maybe_start_view_change(now);
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

  fn view_change_timeouts(&mut self, now: Instant) {
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
      self.propose_next_view(now);
      self.arm_timers(now);
    }
  }

  /// A Normal backup heard from its primary this view: defer the idle timeout.
  fn note_primary_contact(&mut self, now: Instant) {
    if self.status.is_normal() && !self.is_primary() {
      self.timers.primary_idle = Some(now + PRIMARY_IDLE);
    }
  }

  fn on_start_view_change(&mut self, now: Instant, m: crate::StartViewChange) {
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
      self.maybe_start_view_change(now);
    }
  }

  fn maybe_start_view_change(&mut self, now: Instant) {
    if (self.svc_from.count_ones() as usize) >= self.config.quorum_view_change() {
      self.transition_to_view_change_status(now, self.svc_target);
    }
  }

  /// Enter `ViewChange` for `view_new`, reset pipeline + quorums, send our DoViewChange.
  fn transition_to_view_change_status(&mut self, now: Instant, view_new: View) {
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
    self.svc_from = 0;
    self.dvc_from.clear();
    self.dvc_quorum = false;
    self.arm_timers(now);
    self.send_do_view_change(now);
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
        self.commit,
        self.config.replica(),
        self.log_entries(),
      )),
    ));
  }

  /// The full in-memory log `[1..=op]` as wire entries.
  fn log_entries(&self) -> alloc::vec::Vec<crate::PreparedEntry> {
    self
      .log
      .iter()
      .map(|(&op, e)| {
        crate::PreparedEntry::new(OpNumber::with(op), e.client, e.request, e.body.clone())
      })
      .collect()
  }

  fn on_do_view_change(&mut self, now: Instant, m: crate::DoViewChange) {
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
        self.commit,
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
      self.start_view_as_new_primary(now);
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
  fn select_canonical_log(&self) -> (alloc::vec::Vec<crate::PreparedEntry>, u64, u64) {
    let dvcs: alloc::vec::Vec<&crate::DoViewChange> = self.dvc_from.values().collect();
    debug_assert!(!dvcs.is_empty(), "selection requires at least one DVC");

    let log_view_star = dvcs.iter().map(|d| d.log_view().get()).max().unwrap_or(0);
    let canonical: alloc::vec::Vec<&crate::DoViewChange> = dvcs
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
    let log: alloc::vec::Vec<crate::PreparedEntry> = chosen
      .log_slice()
      .iter()
      .filter(|entry| entry.op().get() <= op_head)
      .cloned()
      .collect();
    (log, op_head, commit_star)
  }

  /// Adopt the canonical log from the DVC quorum and become the active primary.
  /// Canonical-log selection + nack-prepare truncation are now performed via
  /// `select_canonical_log`.
  fn start_view_as_new_primary(&mut self, now: Instant) {
    // Canonical-log selection + nack-prepare truncation (see `select_canonical_log`).
    let (canonical_log, op_head, commit_star) = self.select_canonical_log();
    self.adopt_log(&canonical_log);
    self.op = OpNumber::with(op_head);
    self.advance_commit(now, commit_star); // apply newly-exposed committed ops

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

    self.log_view = self.view;
    self.status = Status::Normal;
    self.dvc_quorum = true;

    // Rebuild the pipeline for uncommitted ops; the new primary votes for each.
    self.inflight.clear();
    let own = 1u64 << self.config.replica().get();
    for op in (self.commit.get() + 1)..=self.op.get() {
      self.inflight.insert(
        op,
        Inflight {
          oks: own,
          committed: false,
        },
      );
    }

    // Broadcast the canonical log to all backups.
    self.outgoing.push_back(Outgoing::new(
      Recipient::Backups,
      Message::StartView(crate::StartView::new(
        self.view,
        self.op,
        self.commit,
        self.config.replica(),
        self.log_entries(),
      )),
    ));

    self.arm_timers(now);
    self.try_commit(now);
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

  fn on_start_view(&mut self, now: Instant, m: crate::StartView) {
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
      m.op().get() >= self.commit.get(),
      "must not rewind below our committed op"
    );
    self.view = m.view();
    self.adopt_log(m.log_slice());
    self.op = m.op();
    self.advance_commit(now, m.commit().get());
    self.log_view = m.view();
    self.status = Status::Normal;
    self.catching_up = false;
    self.svc_from = 0;
    self.dvc_from.clear();
    self.dvc_quorum = false;
    self.arm_timers(now);
    // Ack every held uncommitted op so the new primary can re-reach quorum in this view.
    for op in (self.commit.get() + 1)..=self.op.get() {
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
          self.commit,
          self.config.replica(),
          self.log_entries(),
        )),
      ));
    }
  }

  fn on_request(&mut self, now: Instant, _from: Peer, r: crate::Request) {
    if !self.status.is_normal() || !self.is_primary() {
      return; // backups ignore; the client retries to the primary
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

    // Accept: assign the next op, append, record, broadcast Prepare.
    session.request = r.request();
    self.op = self.op.next();
    let op = self.op.get();
    self.log.insert(
      op,
      LogEntry {
        client: r.client(),
        request: r.request(),
        body: r.body_bytes(),
      },
    );
    let mut oks = 0u64;
    oks |= 1u64 << self.config.replica().get();
    self.inflight.insert(
      op,
      Inflight {
        oks,
        committed: false,
      },
    );

    self.outgoing.push_back(Outgoing::new(
      Recipient::Backups,
      Message::Prepare(Prepare::new(
        self.view,
        self.op,
        self.commit,
        r.client(),
        r.request(),
        r.body_bytes(),
      )),
    ));

    self.arm_timers(now);
    self.try_commit(now);
  }

  /// Commits the longest contiguous quorum-acked prefix beyond `commit`.
  fn try_commit(&mut self, _now: Instant) {
    let quorum = self.config.quorum() as u32;
    let mut advanced = false;
    loop {
      let next = self.commit.get() + 1;
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
    if advanced {
      // Tell backups the commit advanced (also serves as a heartbeat).
      self.outgoing.push_back(Outgoing::new(
        Recipient::Backups,
        Message::Commit(Commit::new(self.view, self.commit)),
      ));
    }
  }

  /// Applies op `op` on the primary, caches + sends the reply, emits the event.
  fn commit_op(&mut self, op: u64) {
    let entry = self
      .log
      .get(&op)
      .expect("committed op present in log")
      .clone();
    let reply_body = self.sm.apply(OpNumber::with(op), &entry.body);
    self.commit = OpNumber::with(op);
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
        if self.commit.get() < self.op.get() {
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

  fn on_prepare(&mut self, now: Instant, p: Prepare) {
    if p.view().get() > self.view.get() {
      self.catch_up_to_view(now, p.view());
      return;
    }
    if !self.status.is_normal() || p.view() != self.view || self.is_primary() {
      return;
    }
    // Heard from the primary — defer the idle timeout.
    self.note_primary_contact(now);
    // Learn the primary's commit (apply anything we already have).
    self.advance_commit(now, p.commit().get());

    let pop = p.op().get();
    if pop <= self.op.get() {
      // Already have this op; (re)ack so a lost prepare_ok is recovered.
      // Ops are immutable within a view. The higher-view rule (top of this fn)
      // and the `view != self.view` reject mean this re-ack only fires for a
      // current-view prepare, so blind re-ack is safe.
      self.send_prepare_ok(p.op());
      return;
    }
    if pop == self.op.get() + 1 {
      self.append_prepare(p);
      // Drain any buffered, now-contiguous prepares.
      while let Some(next) = self.buffer.remove(&(self.op.get() + 1)) {
        self.append_prepare(next);
      }
    } else {
      // Future op: buffer until the gap fills (primary also retransmits).
      self.buffer.insert(pop, p);
    }
  }

  fn append_prepare(&mut self, p: Prepare) {
    let op = p.op().get();
    self.op = p.op();
    self.log.insert(
      op,
      LogEntry {
        client: p.client(),
        request: p.request(),
        body: p.body_bytes(),
      },
    );
    self.send_prepare_ok(OpNumber::with(op));
  }

  fn send_prepare_ok(&mut self, op: OpNumber) {
    let primary = self.config.primary(self.view);
    self.outgoing.push_back(Outgoing::new(
      Recipient::To(Peer::Replica(primary)),
      Message::PrepareOk(PrepareOk::new(self.view, op, self.config.replica())),
    ));
  }

  /// Applies committed ops we hold, up to `min(target, op)`. Backups discard the
  /// reply but emit `Committed` so observers can verify agreement.
  fn advance_commit(&mut self, _now: Instant, target: u64) {
    while self.commit.get() < target && self.commit.get() < self.op.get() {
      let op = self.commit.get() + 1;
      let entry = self
        .log
        .get(&op)
        .expect("committed op present in log")
        .clone();
      let reply = self.sm.apply(OpNumber::with(op), &entry.body);
      self.commit = OpNumber::with(op);
      self
        .events
        .push_back(Event::Committed(crate::Committed::new(
          OpNumber::with(op),
          entry.client,
          entry.request,
          reply,
        )));
    }
  }

  fn on_prepare_ok(&mut self, now: Instant, ok: PrepareOk) {
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
    if let Some(inflight) = self.inflight.get_mut(&ok.op().get()) {
      inflight.oks |= 1u64 << ok.replica().get();
    }
    self.try_commit(now);
  }

  fn on_commit(&mut self, now: Instant, c: Commit) {
    if c.view().get() > self.view.get() {
      self.catch_up_to_view(now, c.view());
      return;
    }
    if !self.status.is_normal() || c.view() != self.view || self.is_primary() {
      return;
    }
    // Heard from the primary — defer the idle timeout.
    self.note_primary_contact(now);
    self.advance_commit(now, c.commit().get());
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
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    ClientId, Config, DoViewChange, GetView, OpNumber, Prepare, PreparedEntry, ReplicaId, Request,
    RequestNumber, StartView, StartViewChange, View,
  };

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
    assert!(!e.is_primary());
    let now = Instant::ZERO;

    // Prepare op=1, commit=0: append op 1, ack, commit stays 0.
    e.handle_message(now, primary_peer(), prepare(1, 0));
    assert_eq!(e.op(), OpNumber::with(1));
    assert_eq!(e.commit(), OpNumber::with(0));
    match e.poll_message().expect("prepare_ok emitted").into_msg() {
      Message::PrepareOk(ok) => {
        assert_eq!(ok.op(), OpNumber::with(1));
        assert_eq!(ok.replica(), ReplicaId::new(1));
      }
      _ => panic!("expected PrepareOk"),
    }

    // Prepare op=2, commit=1: piggybacked commit applies op 1, then append op 2.
    e.handle_message(now, primary_peer(), prepare(2, 1));
    assert_eq!(e.op(), OpNumber::with(2));
    assert_eq!(e.commit(), OpNumber::with(1));
  }

  #[test]
  fn backup_buffers_out_of_order_prepares() {
    let mut e = backup();
    let now = Instant::ZERO;

    // op=2 arrives before op=1: buffered, head op stays 0.
    e.handle_message(now, primary_peer(), prepare(2, 0));
    assert_eq!(e.op(), OpNumber::with(0));

    // op=1 arrives: append 1, then drain buffered op 2.
    e.handle_message(now, primary_peer(), prepare(1, 0));
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
    let now = Instant::ZERO;
    e.handle_timeout(now); // status=Normal backup → bootstraps primary_idle; not yet due
    let later = now + core::time::Duration::from_millis(300);
    e.handle_timeout(later); // primary_idle due → on_primary_idle → broadcast SVC(view 1), own bit set
    assert_eq!(e.status(), Status::Normal); // 1 of 2 — not yet quorum
    e.handle_message(
      later,
      Peer::Replica(ReplicaId::new(2)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
    );
    assert_eq!(e.status(), Status::ViewChange);
    assert_eq!(e.view(), View::with(1));
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
    let now = Instant::ZERO;
    // drive it into ViewChange(view 1) first (reuse the SVC path):
    e.handle_timeout(now + core::time::Duration::from_millis(300)); // primary_idle → SVC(view1), own bit
    e.handle_message(
      now,
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
      alloc::vec![
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
      Peer::Replica(ReplicaId::new(2)),
      Message::DoViewChange(dvc),
    );
    // replica 1's own DVC (op 0) + replica 2's DVC (op 2) = quorum 2 → adopt op 2, become Normal primary.
    assert_eq!(e.status(), Status::Normal);
    assert!(e.is_primary());
    assert_eq!(e.view(), View::with(1));
    assert_eq!(e.op(), OpNumber::with(2));
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
    let now = Instant::ZERO;
    e.handle_timeout(now + core::time::Duration::from_millis(300)); // primary_idle → SVC
    e.handle_message(
      now,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    );
    while e.poll_message().is_some() {}
    e.handle_message(
      now,
      Peer::Replica(ReplicaId::new(2)),
      Message::DoViewChange(DoViewChange::new(
        View::with(1),
        View::with(0),
        OpNumber::with(2),
        OpNumber::with(1),
        ReplicaId::new(2),
        alloc::vec![
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

    // A retry of request 1 (already adopted+committed) must NOT create a new op (dedup, no re-exec).
    e.handle_message(
      now,
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
    let t = Instant::ZERO + core::time::Duration::from_millis(300);
    e.handle_timeout(t); // primary_idle → propose view 1 (own bit, 1/3)
    e.handle_message(
      t,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    ); // 2/3
    e.handle_message(
      t,
      Peer::Replica(ReplicaId::new(1)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(1))),
    ); // 3/3 → ViewChange(1)
    assert_eq!(e.view(), View::with(1));
    assert_eq!(e.status(), Status::ViewChange);

    // Stuck: fire view_change_status (~500ms after transition) → escalate, proposing view 2.
    let t2 = t + core::time::Duration::from_millis(600);
    e.handle_timeout(t2);
    // Two peers also propose view 2 → quorum → transition to view 2.
    e.handle_message(
      t2,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(2), ReplicaId::new(0))),
    );
    e.handle_message(
      t2,
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
    let now = Instant::ZERO;
    let sv = StartView::new(
      View::with(1),
      OpNumber::with(2),
      OpNumber::with(1),
      ReplicaId::new(1),
      alloc::vec![
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
      Peer::Replica(ReplicaId::new(1)),
      Message::StartView(sv),
    );
    assert_eq!(e.status(), Status::Normal);
    assert_eq!(e.view(), View::with(1));
    assert_eq!(e.log_view(), View::with(1));
    assert_eq!(e.op(), OpNumber::with(2));
    assert_eq!(e.commit(), OpNumber::with(1)); // op 1 applied
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
    let now = Instant::ZERO;
    e.handle_message(
      now,
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
      Peer::Replica(ReplicaId::new(1)),
      Message::StartView(StartView::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(1),
        ReplicaId::new(1),
        alloc::vec![PreparedEntry::new(
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
    e.handle_message(
      Instant::ZERO,
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
    e.handle_message(
      Instant::ZERO,
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
  #[should_panic(expected = "must not rewind below our committed op")]
  fn on_start_view_rewind_below_commit_panics() {
    // Adopt a StartView for view 1 with op 2 (commit 2), then a StartView for view 2 with op 1
    // (< our committed op 2). The second must fail-stop, not silently rewind.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
    e.handle_message(
      Instant::ZERO,
      Peer::Replica(ReplicaId::new(1)), // primary of view 1
      Message::StartView(StartView::new(
        View::with(1),
        OpNumber::with(2),
        OpNumber::with(2),
        ReplicaId::new(1),
        alloc::vec![
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
      Peer::Replica(ReplicaId::new(2)), // primary of view 2
      Message::StartView(StartView::new(
        View::with(2),
        OpNumber::with(1),
        OpNumber::with(1),
        ReplicaId::new(2),
        alloc::vec![PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a")
        )],
      )),
    );
  }
}

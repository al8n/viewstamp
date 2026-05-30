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
  /// ViewChange (prospective primary): collected DoViewChange messages by replica index.
  dvc_from: BTreeMap<u8, DoViewChange>,
  /// ViewChange (prospective primary): the canonical log has been formed this view.
  dvc_quorum: bool,
  /// Freshness nonce for GetView, drawn once from the prng.
  #[allow(dead_code)] // used from M2 T4/T5
  nonce: u64,
  /// In-memory log, keyed by op number.
  ///
  /// M1: these maps are never pruned (committed entries accumulate). Bounded for
  /// M1's finite runs; a checkpoint/GC trim is an M2/M3 follow-up.
  log: BTreeMap<u64, LogEntry>,
  /// Primary pipeline: op → ack tracking.
  ///
  /// M1: these maps are never pruned (committed entries accumulate). Bounded for
  /// M1's finite runs; a checkpoint/GC trim is an M2/M3 follow-up.
  inflight: BTreeMap<u64, Inflight>,
  /// Backup reorder buffer: future prepares awaiting contiguity.
  buffer: BTreeMap<u64, Prepare>,
  /// Client session table.
  ///
  /// M1: these maps are never pruned (committed entries accumulate). Bounded for
  /// M1's finite runs; a checkpoint/GC trim is an M2/M3 follow-up.
  clients: BTreeMap<u128, Session>,
  #[allow(dead_code)] // used from M2 T4/T5
  prng: Prng,
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
    let mut prng = Prng::new(seed);
    let nonce = prng.next_u64();
    Self {
      config,
      status: Status::Normal,
      view: View::new(),
      op: OpNumber::new(),
      commit: OpNumber::new(),
      log_view: View::new(),
      svc_from: 0,
      dvc_from: BTreeMap::new(),
      dvc_quorum: false,
      nonce,
      log: BTreeMap::new(),
      inflight: BTreeMap::new(),
      buffer: BTreeMap::new(),
      clients: BTreeMap::new(),
      prng,
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
      self.outgoing.push_back(Outgoing {
        to: Recipient::Backups,
        msg: Message::Commit(Commit {
          view: self.view,
          commit: self.commit,
        }),
      });
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
          self.outgoing.push_back(Outgoing {
            to: Recipient::Backups,
            msg: Message::Prepare(Prepare {
              view: self.view,
              op: OpNumber::with(op),
              commit: self.commit,
              client: entry.client,
              request: entry.request,
              body: entry.body,
            }),
          });
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
    // Propose moving to the next view (this milestone: single-step; escalation is later).
    self.broadcast_svc(now);
    self.maybe_start_view_change(now);
  }

  /// Broadcast a `StartViewChange` for `view` to the other replicas.
  fn push_svc(&mut self, view: View) {
    self.outgoing.push_back(Outgoing {
      to: Recipient::Backups,
      msg: Message::StartViewChange(crate::StartViewChange {
        view,
        replica: self.config.replica(),
      }),
    });
  }

  /// Set our own SVC bit and broadcast `StartViewChange{view+1}` to the other replicas.
  fn broadcast_svc(&mut self, now: Instant) {
    let target = View::with(self.view.get() + 1);
    self.svc_from |= 1u64 << self.config.replica().get();
    self.push_svc(target);
    // keep the svc retransmit timer alive while collecting
    self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
  }

  fn view_change_timeouts(&mut self, now: Instant) {
    // Retransmit our SVC and DVC so the change makes progress under loss.
    // (Escalation to view+1 is added in a later milestone.)
    if self.timers.svc_message.is_some_and(|d| d <= now) {
      // re-broadcast our SVC for the view we're trying to reach
      self.push_svc(self.view);
      self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
    }
    if self.timers.dvc_message.is_some_and(|d| d <= now) {
      self.send_do_view_change(now);
      self.timers.dvc_message = Some(now + VC_MESSAGE_RETRANSMIT);
    }
  }

  /// A Normal backup heard from its primary this view: defer the idle timeout.
  fn note_primary_contact(&mut self, now: Instant) {
    if self.status.is_normal() && !self.is_primary() {
      self.timers.primary_idle = Some(now + PRIMARY_IDLE);
    }
  }

  fn on_start_view_change(&mut self, now: Instant, m: crate::StartViewChange) {
    // This milestone: only collect proposals for our immediate next view; jumps are later.
    if m.view.get() != self.view.get() + 1 {
      return;
    }
    if m.replica.get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    self.svc_from |= 1u64 << m.replica.get();
    // join the proposal if we haven't yet
    if (self.svc_from & (1u64 << self.config.replica().get())) == 0 {
      self.broadcast_svc(now);
    }
    self.maybe_start_view_change(now);
  }

  fn maybe_start_view_change(&mut self, now: Instant) {
    if self.status.is_normal()
      && (self.svc_from.count_ones() as usize) >= self.config.quorum_view_change()
    {
      self.transition_to_view_change_status(now, View::with(self.view.get() + 1));
    }
  }

  /// Enter `ViewChange` for `view_new`, reset pipeline + quorums, send our DoViewChange.
  fn transition_to_view_change_status(&mut self, now: Instant, view_new: View) {
    debug_assert!(view_new.get() > self.view.get());
    self.view = view_new;
    self.status = Status::ViewChange;
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
    self.outgoing.push_back(Outgoing {
      to: Recipient::To(Peer::Replica(primary)),
      msg: Message::DoViewChange(crate::DoViewChange {
        view: self.view,
        log_view: self.log_view,
        op: self.op,
        commit: self.commit,
        replica: self.config.replica(),
        log: self.log_entries(),
      }),
    });
  }

  /// The full in-memory log `[1..=op]` as wire entries.
  fn log_entries(&self) -> alloc::vec::Vec<crate::PreparedEntry> {
    self
      .log
      .iter()
      .map(|(&op, e)| crate::PreparedEntry {
        op: OpNumber::with(op),
        client: e.client,
        request: e.request,
        body: e.body.clone(),
      })
      .collect()
  }

  fn on_do_view_change(&mut self, now: Instant, m: crate::DoViewChange) {
    if m.view != self.view
      || !self.config.is_primary(self.view)
      || !self.status.is_view_change()
      || self.dvc_quorum
    {
      return;
    }
    if m.replica.get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    // Ensure our own DVC is represented (keyed by replica → a self-addressed DVC is idempotent).
    // Compute the own-DVC into a local FIRST to avoid a self borrow conflict, then insert.
    let own = self.config.replica().get();
    if !self.dvc_from.contains_key(&own) {
      let own_dvc = crate::DoViewChange {
        view: self.view,
        log_view: self.log_view,
        op: self.op,
        commit: self.commit,
        replica: self.config.replica(),
        log: self.log_entries(),
      };
      self.dvc_from.insert(own, own_dvc);
    }
    // Keep the most-advanced DVC per replica.
    let replace = self
      .dvc_from
      .get(&m.replica.get())
      .map(|cur| (m.log_view.get(), m.op.get()) > (cur.log_view.get(), cur.op.get()))
      .unwrap_or(true);
    if replace {
      self.dvc_from.insert(m.replica.get(), m);
    }
    if self.dvc_from.len() >= self.config.quorum_view_change() {
      self.start_view_as_new_primary(now);
    }
  }

  /// Adopt the canonical log from the DVC quorum and become the active primary.
  /// This milestone: single-log selection (highest `(log_view, op)`); nack-prepare truncation
  /// is a later milestone.
  fn start_view_as_new_primary(&mut self, now: Instant) {
    // Canonical = the DVC with the greatest (log_view, op). Clone its log out first.
    let canonical = self
      .dvc_from
      .values()
      .max_by_key(|d| (d.log_view.get(), d.op.get()))
      .expect("dvc quorum non-empty");
    let canonical_op = canonical.op;
    let canonical_log = canonical.log.clone();
    let commit_max = self
      .dvc_from
      .values()
      .map(|d| d.commit.get())
      .max()
      .unwrap_or(0);

    debug_assert!(
      commit_max <= canonical_op.get(),
      "newest-log-view canonical log must hold every committed op (VSR safety invariant)"
    );

    self.adopt_log(&canonical_log);
    self.op = canonical_op;
    self.advance_commit(now, commit_max); // apply newly-exposed committed ops

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
    self.outgoing.push_back(Outgoing {
      to: Recipient::Backups,
      msg: Message::StartView(crate::StartView {
        view: self.view,
        op: self.op,
        commit: self.commit,
        replica: self.config.replica(),
        log: self.log_entries(),
      }),
    });

    self.arm_timers(now);
    self.try_commit(now);
  }

  /// Replace the in-memory log with the given wire entries.
  fn adopt_log(&mut self, entries: &[crate::PreparedEntry]) {
    self.log.clear();
    for e in entries {
      self.log.insert(
        e.op.get(),
        LogEntry {
          client: e.client,
          request: e.request,
          body: e.body.clone(),
        },
      );
    }
  }

  fn on_start_view(&mut self, now: Instant, m: crate::StartView) {
    if m.view.get() < self.view.get() {
      return;
    }
    if m.replica != self.config.primary(m.view) {
      return; // must come from the view's primary
    }
    self.view = m.view;
    self.adopt_log(&m.log);
    self.op = m.op;
    self.advance_commit(now, m.commit.get());
    self.log_view = m.view;
    self.status = Status::Normal;
    self.svc_from = 0;
    self.dvc_from.clear();
    self.dvc_quorum = false;
    self.arm_timers(now);
    // Ack every held uncommitted op so the new primary can re-reach quorum in this view.
    for op in (self.commit.get() + 1)..=self.op.get() {
      self.send_prepare_ok(OpNumber::with(op));
    }
  }
  fn on_get_view(&mut self, _now: Instant, _m: crate::GetView) {}

  fn on_request(&mut self, now: Instant, _from: Peer, r: crate::Request) {
    if !self.status.is_normal() || !self.is_primary() {
      return; // backups ignore; the client retries to the primary
    }
    let key = r.client.get();
    let session = self.clients.entry(key).or_default();

    // Dedup against the session (clients send one request at a time, numbered 1..).
    if r.request.get() < session.request.get() {
      return; // stale
    }
    if r.request.get() == session.request.get() {
      // Duplicate of the latest accepted request.
      // Clone the cached reply data out before dropping the session borrow so
      // that pushing to self.outgoing (which requires &mut self) is borrow-safe.
      let cached = session.reply.as_ref().and_then(|(rn, body)| {
        if *rn == r.request {
          Some((*rn, body.clone()))
        } else {
          None
        }
      });
      if let Some((rn, body)) = cached {
        let reply = Reply {
          view: self.view,
          client: r.client,
          request: rn,
          body,
        };
        self.outgoing.push_back(Outgoing {
          to: Recipient::To(Peer::Client(r.client)),
          msg: Message::Reply(reply),
        });
      }
      return; // either resent the cached reply, or it's still in flight
    }
    if r.request.get() != session.request.get() + 1 {
      return; // gap: client violated one-in-flight; ignore
    }

    // Accept: assign the next op, append, record, broadcast Prepare.
    session.request = r.request;
    self.op = self.op.next();
    let op = self.op.get();
    self.log.insert(
      op,
      LogEntry {
        client: r.client,
        request: r.request,
        body: r.body.clone(),
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

    self.outgoing.push_back(Outgoing {
      to: Recipient::Backups,
      msg: Message::Prepare(Prepare {
        view: self.view,
        op: self.op,
        commit: self.commit,
        client: r.client,
        request: r.request,
        body: r.body,
      }),
    });

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
      self.outgoing.push_back(Outgoing {
        to: Recipient::Backups,
        msg: Message::Commit(Commit {
          view: self.view,
          commit: self.commit,
        }),
      });
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

    self.outgoing.push_back(Outgoing {
      to: Recipient::To(Peer::Client(entry.client)),
      msg: Message::Reply(Reply {
        view: self.view,
        client: entry.client,
        request: entry.request,
        body: reply_body.clone(),
      }),
    });
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
      Status::ViewChange => {
        self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
        self.timers.dvc_message = Some(now + VC_MESSAGE_RETRANSMIT);
      }
      Status::Recovering | Status::RecoveringHead => {}
    }
  }

  fn on_prepare(&mut self, now: Instant, p: Prepare) {
    if !self.status.is_normal() || p.view != self.view || self.is_primary() {
      return;
    }
    // Heard from the primary — defer the idle timeout.
    self.note_primary_contact(now);
    // Learn the primary's commit (apply anything we already have).
    self.advance_commit(now, p.commit.get());

    let pop = p.op.get();
    if pop <= self.op.get() {
      // Already have this op; (re)ack so a lost prepare_ok is recovered.
      // M1 single-view: ops are immutable so a re-received prepare for a held op
      // is identical and blind re-ack is safe. M2 view change will require a
      // view/header check before re-acking.
      self.send_prepare_ok(p.op);
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
    let op = p.op.get();
    self.op = p.op;
    self.log.insert(
      op,
      LogEntry {
        client: p.client,
        request: p.request,
        body: p.body,
      },
    );
    self.send_prepare_ok(OpNumber::with(op));
  }

  fn send_prepare_ok(&mut self, op: OpNumber) {
    let primary = self.config.primary(self.view);
    self.outgoing.push_back(Outgoing {
      to: Recipient::To(Peer::Replica(primary)),
      msg: Message::PrepareOk(PrepareOk {
        view: self.view,
        op,
        replica: self.config.replica(),
      }),
    });
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
    if !self.status.is_normal() || !self.is_primary() || ok.view != self.view {
      return;
    }
    if ok.replica.get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    if let Some(inflight) = self.inflight.get_mut(&ok.op.get()) {
      inflight.oks |= 1u64 << ok.replica.get();
    }
    self.try_commit(now);
  }

  fn on_commit(&mut self, now: Instant, c: Commit) {
    if !self.status.is_normal() || c.view != self.view || self.is_primary() {
      return;
    }
    // Heard from the primary — defer the idle timeout.
    self.note_primary_contact(now);
    self.advance_commit(now, c.commit.get());
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
    ClientId, Config, DoViewChange, PreparedEntry, ReplicaId, Request, StartView, StartViewChange,
  };

  struct NoopSm;
  impl StateMachine for NoopSm {
    fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> Bytes {
      Bytes::new()
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
    Message::Prepare(Prepare {
      view: View::new(),
      op: OpNumber::with(op),
      commit: OpNumber::with(commit),
      client: ClientId::new(7),
      request: RequestNumber::with(op),
      body: Bytes::copy_from_slice(&[op as u8]),
    })
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
    match e.poll_message().expect("prepare_ok emitted").msg {
      Message::PrepareOk(ok) => {
        assert_eq!(ok.op, OpNumber::with(1));
        assert_eq!(ok.replica, ReplicaId::new(1));
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
      Message::StartViewChange(StartViewChange {
        view: View::with(1),
        replica: ReplicaId::new(2),
      }),
    );
    assert_eq!(e.status(), Status::ViewChange);
    assert_eq!(e.view(), View::with(1));
    // it should have emitted a DoViewChange to primary(view 1) = replica 1 (itself).
    let mut saw_dvc = false;
    while let Some(out) = e.poll_message() {
      if let Message::DoViewChange(d) = out.msg {
        assert_eq!(d.view, View::with(1));
        assert_eq!(d.replica, ReplicaId::new(1));
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
      Message::StartViewChange(StartViewChange {
        view: View::with(1),
        replica: ReplicaId::new(0),
      }),
    );
    assert_eq!(e.status(), Status::ViewChange); // now collecting DVCs as primary(view 1)
    while e.poll_message().is_some() {} // discard outgoing so far
    // Feed a DoViewChange from replica 2 with a richer log (log_view 0, op 2, commit 1):
    let dvc = DoViewChange {
      view: View::with(1),
      log_view: View::with(0),
      op: OpNumber::with(2),
      commit: OpNumber::with(1),
      replica: ReplicaId::new(2),
      log: alloc::vec![
        PreparedEntry {
          op: OpNumber::with(1),
          client: ClientId::new(7),
          request: RequestNumber::with(1),
          body: bytes::Bytes::from_static(b"a")
        },
        PreparedEntry {
          op: OpNumber::with(2),
          client: ClientId::new(7),
          request: RequestNumber::with(2),
          body: bytes::Bytes::from_static(b"b")
        },
      ],
    };
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
      if let Message::StartView(sv) = out.msg {
        assert_eq!(sv.op, OpNumber::with(2));
        assert_eq!(sv.log.len(), 2);
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
      Message::StartViewChange(StartViewChange {
        view: View::with(1),
        replica: ReplicaId::new(0),
      }),
    );
    while e.poll_message().is_some() {}
    e.handle_message(
      now,
      Peer::Replica(ReplicaId::new(2)),
      Message::DoViewChange(DoViewChange {
        view: View::with(1),
        log_view: View::with(0),
        op: OpNumber::with(2),
        commit: OpNumber::with(1),
        replica: ReplicaId::new(2),
        log: alloc::vec![
          PreparedEntry {
            op: OpNumber::with(1),
            client: ClientId::new(7),
            request: RequestNumber::with(1),
            body: bytes::Bytes::from_static(b"a")
          },
          PreparedEntry {
            op: OpNumber::with(2),
            client: ClientId::new(7),
            request: RequestNumber::with(2),
            body: bytes::Bytes::from_static(b"b")
          },
        ],
      }),
    );
    assert!(e.is_primary());
    assert_eq!(e.op(), OpNumber::with(2));
    while e.poll_message().is_some() {}

    // A retry of request 1 (already adopted+committed) must NOT create a new op (dedup, no re-exec).
    e.handle_message(
      now,
      Peer::Client(ClientId::new(7)),
      Message::Request(Request {
        client: ClientId::new(7),
        request: RequestNumber::with(1),
        body: bytes::Bytes::from_static(b"a"),
      }),
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
      Message::Request(Request {
        client: ClientId::new(7),
        request: RequestNumber::with(3),
        body: bytes::Bytes::from_static(b"c"),
      }),
    );
    assert_eq!(
      e.op(),
      OpNumber::with(3),
      "a new request after the adopted ones is accepted"
    );
  }

  #[test]
  fn backup_adopts_start_view() {
    // replica 2 of 3 receives a StartView for view 1 from primary(1)=replica 1.
    let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
    let now = Instant::ZERO;
    let sv = StartView {
      view: View::with(1),
      op: OpNumber::with(2),
      commit: OpNumber::with(1),
      replica: ReplicaId::new(1),
      log: alloc::vec![
        PreparedEntry {
          op: OpNumber::with(1),
          client: ClientId::new(7),
          request: RequestNumber::with(1),
          body: bytes::Bytes::from_static(b"a"),
        },
        PreparedEntry {
          op: OpNumber::with(2),
          client: ClientId::new(7),
          request: RequestNumber::with(2),
          body: bytes::Bytes::from_static(b"b"),
        },
      ],
    };
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
      if let Message::PrepareOk(ok) = out.msg {
        if ok.op == OpNumber::with(2) {
          acked_op2 = true;
        }
      }
    }
    assert!(
      acked_op2,
      "backup must ack its held uncommitted ops in the new view"
    );
  }
}

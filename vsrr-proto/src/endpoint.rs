use alloc::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use crate::{
  ClientId, Commit, Config, Event, Instant, Message, OpNumber, Outgoing, Peer, Prepare, PrepareOk,
  Prng, Recipient, ReplicaId, Reply, RequestNumber, StateMachine, Status, View,
};

const PREPARE_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
const COMMIT_HEARTBEAT: core::time::Duration = core::time::Duration::from_millis(50);

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

/// Absolute timer deadlines (M1: primary-side only).
#[derive(Debug, Clone, Default)]
struct Timers {
  /// Retransmit un-acked prepares.
  prepare: Option<Instant>,
  /// Commit heartbeat to backups.
  commit: Option<Instant>,
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
  // used from M2 (backoff jitter); allow removed then
  #[allow(dead_code)]
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
    Self {
      config,
      status: Status::Normal,
      view: View::new(),
      op: OpNumber::new(),
      commit: OpNumber::new(),
      log: BTreeMap::new(),
      inflight: BTreeMap::new(),
      buffer: BTreeMap::new(),
      clients: BTreeMap::new(),
      prng: Prng::new(seed),
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
      Message::Reply(_) => {} // replies are for clients, not replicas
    }
  }

  /// Fires any primary timers due at `now`.
  pub fn handle_timeout(&mut self, now: Instant) {
    if !self.is_primary() {
      return;
    }
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
    self.events.push_back(Event::Committed {
      op: OpNumber::with(op),
      client: entry.client,
      request: entry.request,
      reply: reply_body,
    });
  }

  /// (Re)arms the primary's timers. Backups have none in M1.
  fn arm_timers(&mut self, now: Instant) {
    if !self.is_primary() {
      self.timers.prepare = None;
      self.timers.commit = None;
      return;
    }
    self.timers.commit = Some(now + COMMIT_HEARTBEAT);
    self.timers.prepare = if self.commit.get() < self.op.get() {
      Some(now + PREPARE_RETRANSMIT)
    } else {
      None
    };
  }

  fn on_prepare(&mut self, now: Instant, p: Prepare) {
    if !self.status.is_normal() || p.view != self.view || self.is_primary() {
      return;
    }
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
      self.events.push_back(Event::Committed {
        op: OpNumber::with(op),
        client: entry.client,
        request: entry.request,
        reply,
      });
    }
  }

  fn on_prepare_ok(&mut self, now: Instant, ok: PrepareOk) {
    if !self.status.is_normal() || !self.is_primary() || ok.view != self.view {
      return;
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
    [self.timers.prepare, self.timers.commit]
      .into_iter()
      .flatten()
      .min()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ClientId, Config, ReplicaId};

  struct NoopSm;
  impl StateMachine for NoopSm {
    fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> Bytes {
      Bytes::new()
    }
  }

  #[test]
  fn fresh_endpoint_state() {
    let cfg = Config::new(1, ReplicaId::new(0), 3);
    let e = Endpoint::new(cfg, 99, NoopSm);
    assert_eq!(e.status(), Status::Normal);
    assert_eq!(e.view(), View::new());
    assert_eq!(e.op(), OpNumber::new());
    assert_eq!(e.commit(), OpNumber::new());
    assert!(e.is_primary()); // replica 0 is primary of view 0
  }

  // Helper: build a backup endpoint (replica 1 of 3).
  fn backup() -> Endpoint<NoopSm> {
    Endpoint::new(Config::new(1, ReplicaId::new(1), 3), 0, NoopSm)
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
}

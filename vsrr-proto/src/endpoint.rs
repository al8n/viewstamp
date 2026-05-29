use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::{
  Config, Event, Instant, Message, OpNumber, Outgoing, Peer, Prng, ReplicaId, RequestNumber,
  StateMachine, Status, View,
};

/// One entry in the in-memory log (M1; persistence arrives in M3).
#[derive(Debug, Clone)]
#[allow(dead_code)] // consumed from Task 11; allow removed in Task 15
struct LogEntry {
  client: crate::ClientId,
  request: RequestNumber,
  body: Vec<u8>,
}

/// Primary-side tracking of an in-flight prepare awaiting a prepare_ok quorum.
#[derive(Debug, Clone)]
#[allow(dead_code)] // consumed from Task 11; allow removed in Task 15
struct Inflight {
  /// Bitset of replica indices that have acked (the primary sets its own bit).
  oks: u64,
  committed: bool,
}

/// Per-client session for at-most-once semantics.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // consumed from Task 11; allow removed in Task 15
struct Session {
  /// Highest request number accepted (assigned an op or committed).
  request: RequestNumber,
  /// Cached `(request_number, reply_body)` of the latest committed request.
  reply: Option<(RequestNumber, Vec<u8>)>,
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
  #[allow(dead_code)] // consumed from Task 11; allow removed in Task 15
  log: BTreeMap<u64, LogEntry>,
  /// Primary pipeline: op → ack tracking.
  #[allow(dead_code)] // consumed from Task 11; allow removed in Task 15
  inflight: BTreeMap<u64, Inflight>,
  /// Backup reorder buffer: future prepares awaiting contiguity.
  #[allow(dead_code)] // consumed from Task 12; allow removed in Task 15
  buffer: BTreeMap<u64, crate::Prepare>,
  /// Client session table.
  #[allow(dead_code)] // consumed from Task 11; allow removed in Task 15
  clients: BTreeMap<u128, Session>,
  #[allow(dead_code)] // consumed from Task 15; allow removed in Task 15
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

  /// Feeds an incoming protocol message. (No-op until Task 11.)
  pub fn handle_message(&mut self, _now: Instant, _from: Peer, _msg: Message) {}

  /// Fires any timers that are due at `now`. (No-op until Task 15.)
  pub fn handle_timeout(&mut self, _now: Instant) {}

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
  use crate::{Config, ReplicaId};

  struct NoopSm;
  impl StateMachine for NoopSm {
    fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> alloc::vec::Vec<u8> {
      alloc::vec::Vec::new()
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
}

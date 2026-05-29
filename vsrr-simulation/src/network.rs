use vsrr_proto::{Instant, Message, Peer};

/// Where a delivered message goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
  /// A replica, by index.
  Replica(u8),
  /// A client, by id.
  Client(u128),
}

/// A message in flight on the virtual network.
#[derive(Debug, Clone)]
pub struct InFlight {
  pub deliver_at: Instant,
  pub from: Peer,
  pub target: Target,
  pub msg: Message,
  /// Tie-breaker for deterministic ordering of equal `deliver_at`.
  pub seq: u64,
}

/// Tunable, seeded fault model. All probabilities are out of 1000.
#[derive(Debug, Clone, Copy)]
pub struct Faults {
  /// Base one-way latency added to every message.
  pub latency: core::time::Duration,
  /// Extra random jitter (0..jitter) added per message (enables reorder).
  pub jitter: core::time::Duration,
  /// Per-message drop probability, out of 1000.
  pub drop_per_mille: u32,
}

impl Faults {
  /// No faults: fixed small latency, no jitter, no drops.
  pub const fn none() -> Self {
    Self {
      latency: core::time::Duration::from_millis(1),
      jitter: core::time::Duration::ZERO,
      drop_per_mille: 0,
    }
  }
}

/// The virtual network: a queue of in-flight messages ordered by delivery time.
#[derive(Debug, Default)]
pub struct Network {
  queue: Vec<InFlight>,
  next_seq: u64,
}

impl Network {
  /// Creates an empty network.
  pub fn new() -> Self {
    Self {
      queue: Vec::new(),
      next_seq: 0,
    }
  }

  /// Enqueues a message for delivery (already past drop/latency decisions).
  pub fn enqueue(&mut self, mut m: InFlight) {
    m.seq = self.next_seq;
    self.next_seq += 1;
    self.queue.push(m);
  }

  /// The earliest delivery deadline, if any.
  pub fn next_deadline(&self) -> Option<Instant> {
    self.queue.iter().map(|m| m.deliver_at).min()
  }

  /// Removes and returns all messages due at or before `now`, in deterministic
  /// `(deliver_at, seq)` order.
  pub fn take_due(&mut self, now: Instant) -> Vec<InFlight> {
    let mut due: Vec<InFlight> = self
      .queue
      .iter()
      .filter(|m| m.deliver_at <= now)
      .cloned()
      .collect();
    self.queue.retain(|m| m.deliver_at > now);
    due.sort_by_key(|m| (m.deliver_at.as_nanos(), m.seq));
    due
  }

  /// True iff nothing is in flight.
  pub fn is_empty(&self) -> bool {
    self.queue.is_empty()
  }
}

use viewstamp_proto::{Instant, Message, Peer};

/// Where a delivered message goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
  /// A replica, by index. The index spans the full membership (`0..node_count`), so it is a
  /// `u16` to match [`ReplicaId::get`](viewstamp_proto::ReplicaId::get) — a high member id cannot
  /// truncate or alias a low one.
  Replica(u16),
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
  /// Whether `from` (when it names a replica) was a VOTER, by its own membership, at the instant
  /// this message was handed to the network — recorded once here rather than left to be re-derived
  /// from whatever role that replica holds by the time a later reader asks. `true` for a
  /// non-replica `from` (a client has no voter concept, so no consumer reads this bit for one).
  pub emitter_was_voter: bool,
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
  /// Per-message DUPLICATE probability, out of 1000. When it fires, the (non-dropped) message is
  /// enqueued a SECOND time at an independently-jittered delivery instant — so the receiver may see
  /// the same `Prepare`/`Commit`/`PrepareOk`/… twice, out of order relative to the first copy. This
  /// exercises the protocol's idempotency / re-ack paths (a re-delivered `Prepare` must not double
  /// apply; a re-delivered `PrepareOk` must not double-count the quorum). Default 0 (existing tests
  /// unaffected).
  pub duplicate_per_mille: u32,
  /// Per-message UNBOUNDED-HOLD probability, out of 1000. When it fires, delivery is pushed FAR into
  /// the virtual future (`HOLD_DELAY`, well past the repair-or-truncate grace) instead of
  /// `latency + jitter` — modelling an adversarially-delayed message that OUTLIVES its op's truncation
  /// and re-mint. This is the axis that lets the simulator reach the op-reuse / vote-confusion class: a
  /// `PrepareOk` whose op number was truncated and re-used by the time the held vote arrives, which the
  /// content-addressed vote gate must reject by body checksum. Default 0 (existing schedules unaffected —
  /// no PRNG draw is taken when 0, so the per-seed stream is byte-identical).
  pub hold_per_mille: u32,
}

impl Faults {
  /// No faults: fixed small latency, no jitter, no drops, no duplicates.
  pub const fn none() -> Self {
    Self {
      latency: core::time::Duration::from_millis(1),
      jitter: core::time::Duration::ZERO,
      drop_per_mille: 0,
      duplicate_per_mille: 0,
      hold_per_mille: 0,
    }
  }
}

/// A GRAY-FAILURE delivery profile for one replica: its inter-replica messages still ARRIVE (this is
/// NOT a partition), but each affected message picks up an extra seeded delay drawn uniformly from
/// `[min_extra, max_extra]` on top of the base `latency + jitter`. `inbound`/`outbound` select which
/// legs are degraded (a slow NIC/disk-stalled box can be slow to hear, slow to be heard, or both).
/// The band is sized to sit BELOW the proto's liveness cadences (50 ms commit heartbeat, 200 ms
/// idle view-change), so a slow replica is degraded-but-alive — late acks and late heartbeats, not a
/// legitimate knockout — which is exactly the gray zone the timers/forfeit machinery must tolerate.
#[derive(Debug, Clone, Copy)]
pub struct SlowProfile {
  /// Degrade messages DELIVERED TO this replica (it is slow to hear).
  pub inbound: bool,
  /// Degrade messages SENT BY this replica (it is slow to be heard).
  pub outbound: bool,
  /// The lower edge of the per-message extra-delay band.
  pub min_extra: core::time::Duration,
  /// The upper edge of the per-message extra-delay band (inclusive).
  pub max_extra: core::time::Duration,
}

/// The virtual network: a queue of in-flight messages ordered by delivery time.
#[derive(Debug)]
pub struct Network {
  queue: Vec<InFlight>,
  next_seq: u64,
}

impl Default for Network {
  fn default() -> Self {
    Self::new()
  }
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

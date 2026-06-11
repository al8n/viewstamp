use viewstamp_proto::Instant;

/// A virtual monotonic clock. Time only advances when `advance_to` is called; the
/// simulator jumps it to the next scheduled deadline.
#[derive(Debug, Clone, Default)]
pub struct Clock {
  nanos: u64,
}

impl Clock {
  /// A clock at the epoch.
  pub const fn new() -> Self {
    Self { nanos: 0 }
  }

  /// The current virtual instant.
  pub const fn now(&self) -> Instant {
    Instant::from_nanos(self.nanos)
  }

  /// Advances virtual time to `to` (must not move backward).
  pub fn advance_to(&mut self, to: Instant) {
    debug_assert!(to.as_nanos() >= self.nanos);
    self.nanos = to.as_nanos();
  }
}

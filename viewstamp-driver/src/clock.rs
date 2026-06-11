use std::time::{Duration, Instant as StdInstant};

use viewstamp_proto::Instant;

/// Anchors the proto's monotonic-nanosecond [`Instant`] to a wall-clock epoch captured at startup.
///
/// The driver holds one `Clock` and reads [`Clock::now`] once per wake to feed the coordinator's
/// `handle_*` methods. A proto [`Instant`] deadline returned by a coordinator's `poll_timeout` is
/// mapped back to a `std::time::Instant` (for the runtime's deadline timer) via [`Clock::to_std`].
pub struct Clock {
  base: StdInstant,
}

impl Clock {
  /// Anchor the epoch to the current instant.
  #[must_use]
  pub fn new() -> Self {
    Self {
      base: StdInstant::now(),
    }
  }

  /// The current proto [`Instant`] — nanoseconds elapsed since the epoch (saturating at `u64::MAX`).
  #[must_use]
  pub fn now(&self) -> Instant {
    let nanos = StdInstant::now()
      .saturating_duration_since(self.base)
      .as_nanos();
    Instant::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
  }

  /// Map a proto [`Instant`] deadline back to a `std::time::Instant` on the same epoch, for
  /// the runtime's deadline timer.
  #[must_use]
  pub fn to_std(&self, at: Instant) -> StdInstant {
    self.base + Duration::from_nanos(at.as_nanos())
  }
}

impl Default for Clock {
  fn default() -> Self {
    Self::new()
  }
}

/// `base` plus up to 25% jitter, decorrelating retry/redial schedules across replicas so a
/// common-mode event (one peer restarting, a network blip) does not produce synchronized dial bursts
/// from every dialer. Sub-millisecond wall-clock entropy is plenty of decorrelation for a backoff
/// schedule — no RNG dependency needed. Monotone in `base` with jitter at most `base / 4`, so a
/// doubled base always schedules strictly later than the previous jittered delay (the strict
/// spacing an exponential redial schedule needs).
pub fn jittered(base: Duration) -> Duration {
  let nanos = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map_or(0, |d| d.subsec_nanos());
  base + base * (nanos % 256) / 1024
}

#[cfg(test)]
mod tests {
  use super::Clock;

  #[test]
  fn now_is_monotonic_nondecreasing_from_zero() {
    let clock = Clock::new();
    let a = clock.now();
    let b = clock.now();
    // Anchored at construction, so the first reading is near zero and readings never go back.
    assert!(b >= a);
    assert!(a.as_nanos() < 60_000_000_000); // < 60s since construction
  }

  /// `jittered(b)` stays within `[b, b + b/4]`: never below the base (a redial can't fire early) and
  /// jitter bounded at a quarter of the base — which is what makes a DOUBLED base strictly later
  /// than any jittered delay of the previous base (`2b > 1.25b`), the strict-spacing property the
  /// exponential redial schedules rely on.
  #[test]
  fn jittered_bounds_hold() {
    let base = std::time::Duration::from_millis(200);
    for _ in 0..64 {
      let j = super::jittered(base);
      assert!(j >= base, "jitter never schedules below the base");
      assert!(j <= base + base / 4, "jitter is bounded at base/4");
    }
  }
}

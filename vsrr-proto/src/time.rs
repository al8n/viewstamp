//! Monotonic time primitives for the Sans-I/O core.

use core::time::Duration;

/// A monotonic instant, measured in nanoseconds since a driver-chosen epoch.
///
/// The Sans-I/O core never reads a clock; the driver supplies `now` and converts
/// to/from its real clock at the boundary. `u64` nanoseconds spans ~584 years —
/// ample for monotonic elapsed time — and serializes compactly onto the wire.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Instant(u64);

impl Instant {
  /// The zero instant (epoch).
  pub const ZERO: Self = Self(0);

  /// Creates an instant from nanoseconds since the epoch.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn from_nanos(nanos: u64) -> Self {
    Self(nanos)
  }

  /// Nanoseconds since the epoch.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_nanos(self) -> u64 {
    self.0
  }

  /// The duration elapsed from `earlier` to `self`, saturating at zero if
  /// `earlier` is later than `self`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn saturating_duration_since(self, earlier: Self) -> Duration {
    Duration::from_nanos(self.0.saturating_sub(earlier.0))
  }

  /// `self + d`, or `None` on overflow.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checked_add(self, d: Duration) -> Option<Self> {
    match d.as_nanos() > (u64::MAX as u128) {
      true => None,
      false => match self.0.checked_add(d.as_nanos() as u64) {
        Some(n) => Some(Self(n)),
        None => None,
      },
    }
  }
}

impl core::ops::Add<Duration> for Instant {
  type Output = Self;

  /// Saturating add (never panics; clamps at `u64::MAX` nanos).
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn add(self, d: Duration) -> Self {
    let add = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
    Self(self.0.saturating_add(add))
  }
}

impl core::ops::Sub<Instant> for Instant {
  type Output = Duration;

  #[cfg_attr(not(tarpaulin), inline(always))]
  fn sub(self, earlier: Instant) -> Duration {
    self.saturating_duration_since(earlier)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use core::time::Duration;

  #[test]
  fn arithmetic_and_ordering() {
    let t0 = Instant::from_nanos(1_000);
    let t1 = t0 + Duration::from_nanos(500);
    assert_eq!(t1.as_nanos(), 1_500);
    assert!(t1 > t0);
    assert_eq!(t1.saturating_duration_since(t0), Duration::from_nanos(500));
    assert_eq!(t0.saturating_duration_since(t1), Duration::ZERO);
  }

  #[test]
  fn add_saturates_on_overflow() {
    let t = Instant::from_nanos(u64::MAX);
    assert_eq!((t + Duration::from_nanos(10)).as_nanos(), u64::MAX);
  }
}

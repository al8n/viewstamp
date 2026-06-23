//! Monotonic time primitives for the Sans-I/O core.

use core::time::Duration;

/// A monotonic instant, held as a [`Duration`] since a driver-chosen epoch.
///
/// The Sans-I/O core never reads a clock; the driver supplies `now` and converts
/// to/from its real clock at the boundary. Wrapping a [`core::time::Duration`]
/// (rather than a `std::time::Instant`) keeps the type usable on `no_std` targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(Duration);

impl Default for Instant {
  /// The zero instant (epoch) — delegates to [`Instant::ZERO`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn default() -> Self {
    Self::ZERO
  }
}

impl Instant {
  /// The zero instant (epoch).
  pub const ZERO: Self = Self(Duration::ZERO);

  /// Creates an instant from nanoseconds since the epoch.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn from_nanos(nanos: u64) -> Self {
    Self(Duration::from_nanos(nanos))
  }

  /// Nanoseconds since the epoch, saturating at `u64::MAX`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_nanos(self) -> u64 {
    let nanos = self.0.as_nanos();
    match nanos > u64::MAX as u128 {
      true => u64::MAX,
      false => nanos as u64,
    }
  }

  /// The duration elapsed from `earlier` to `self`, saturating at zero if
  /// `earlier` is later than `self`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn saturating_duration_since(self, earlier: Self) -> Duration {
    match self.0.checked_sub(earlier.0) {
      Some(d) => d,
      None => Duration::ZERO,
    }
  }

  /// `self + d`, or `None` on overflow of the underlying [`Duration`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checked_add(self, d: Duration) -> Option<Self> {
    match self.0.checked_add(d) {
      Some(d) => Some(Self(d)),
      None => None,
    }
  }
}

impl core::ops::Add<Duration> for Instant {
  type Output = Self;

  /// Saturating add (never panics; clamps at [`Duration::MAX`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn add(self, d: Duration) -> Self {
    Self(self.0.saturating_add(d))
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
mod tests;

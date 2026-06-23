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

#[test]
fn add_clamps_the_stored_value_at_the_u64_ceiling() {
  // The prior `u64`-nanosecond representation clamped the STORED value at
  // `u64::MAX` (not merely `as_nanos`), so a saturated instant compares, orders,
  // and subtracts as `u64::MAX`. The `Duration` inner repr must preserve that.
  let max = Instant::from_nanos(u64::MAX);
  let saturated = max + Duration::from_nanos(10);
  assert_eq!(saturated, max);
  assert!(saturated <= max);
  assert_eq!(saturated.saturating_duration_since(max), Duration::ZERO);
  assert_eq!(max.saturating_duration_since(saturated), Duration::ZERO);
}

#[test]
fn checked_add_returns_none_past_the_u64_ceiling() {
  let max = Instant::from_nanos(u64::MAX);
  assert_eq!(max.checked_add(Duration::from_nanos(1)), None);
  // Exactly reaching the ceiling is representable.
  assert_eq!(
    Instant::from_nanos(u64::MAX - 1).checked_add(Duration::from_nanos(1)),
    Some(max),
  );
  // A zero add at the ceiling stays at the ceiling.
  assert_eq!(max.checked_add(Duration::ZERO), Some(max));
}

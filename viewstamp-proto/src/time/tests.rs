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

#[test]
fn checked_add_returns_none_on_a_duration_level_overflow() {
  // Distinct from the u64::MAX-nanosecond ceiling above: this overflows the INNER `Duration`
  // arithmetic itself (`Duration::MAX` is far beyond u64::MAX nanoseconds). The tuple field is
  // visible to this submodule, so it is constructed directly rather than through `from_nanos`.
  let at_duration_ceiling = Instant(Duration::MAX);
  assert_eq!(
    at_duration_ceiling.checked_add(Duration::from_nanos(1)),
    None
  );
}

#[test]
fn as_nanos_saturates_when_the_inner_duration_exceeds_u64_max_nanos() {
  // The public API (`from_nanos`, `Add`, `checked_add`) always clamps the inner `Duration` at
  // `u64::MAX` nanoseconds, but `as_nanos` defends the conversion itself: constructed directly with
  // a `Duration` beyond that range, it still saturates rather than truncating.
  let past_ceiling = Instant(Duration::from_secs(u64::MAX));
  assert_eq!(past_ceiling.as_nanos(), u64::MAX);
}

#[test]
fn default_is_the_zero_instant() {
  assert_eq!(Instant::default(), Instant::ZERO);
}

#[test]
fn subtraction_operator_matches_saturating_duration_since() {
  let t0 = Instant::from_nanos(1_000);
  let t1 = Instant::from_nanos(1_500);
  assert_eq!(t1 - t0, Duration::from_nanos(500));
  // Same saturating-at-zero behavior as the named method when the operands are reversed.
  assert_eq!(t0 - t1, Duration::ZERO);
}

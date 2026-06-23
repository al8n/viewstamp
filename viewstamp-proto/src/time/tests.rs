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

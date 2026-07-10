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

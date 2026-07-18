use super::*;

/// The default config IS the pinned constants — every knob pinned, so the tunable surface
/// cannot silently drift the production defaults.
#[test]
fn defaults_equal_the_pinned_constants() {
  let c = DriverConfig::new();
  assert_eq!(c.redial_backoff_base(), Duration::from_millis(200));
  assert_eq!(c.redial_backoff_cap(), Duration::from_secs(5));
  assert_eq!(c.dial_timeout(), Duration::from_secs(5));
  assert_eq!(c.auth_deadline(), Duration::from_secs(5));
  assert_eq!(c.request_timeout(), Duration::from_millis(250));
  assert_eq!(c.max_inflight(), 4096);
  assert_eq!(c.max_pending_bytes(), 128 * 1024 * 1024);
  assert_eq!(c.events_cap(), 1024);
  assert_eq!(c.max_conns(), 1024);
  assert_eq!(c.health_probe_interval(), Duration::from_millis(250));
  assert_eq!(c.health_proof_max_age(), Duration::from_secs(1));
  assert_eq!(c.reconfigure_timeout(), Duration::from_millis(30 * 250));
  assert_eq!(
    c.cmd_cap(),
    4096 + 1,
    "the command-channel capacity is derived as max_inflight + 1"
  );
  assert_eq!(DriverConfig::default(), c, "Default delegates to new()");
}

/// Overrides take effect, the derived `cmd_cap` follows `max_inflight`, and the zero-clamps hold.
#[test]
fn overrides_apply_and_zero_counts_clamp_to_one() {
  let c = DriverConfig::new()
    .with_redial_backoff_base(Duration::from_millis(50))
    .with_request_timeout(Duration::from_secs(1))
    .with_max_inflight(8);
  assert_eq!(c.redial_backoff_base(), Duration::from_millis(50));
  assert_eq!(c.request_timeout(), Duration::from_secs(1));
  assert_eq!(c.max_inflight(), 8);
  assert_eq!(c.cmd_cap(), 9, "cmd_cap re-derives from the override");

  let clamped = DriverConfig::new()
    .with_max_inflight(0)
    .with_max_pending_bytes(0)
    .with_events_cap(0)
    .with_max_conns(0);
  assert_eq!(clamped.max_inflight(), 1);
  assert_eq!(clamped.max_pending_bytes(), 1);
  assert_eq!(clamped.events_cap(), 1);
  assert_eq!(clamped.max_conns(), 1);

  // The liveness-probe knobs are plain Duration overrides (no clamp).
  let w = DriverConfig::new()
    .with_health_probe_interval(Duration::from_millis(100))
    .with_health_proof_max_age(Duration::from_millis(500));
  assert_eq!(w.health_probe_interval(), Duration::from_millis(100));
  assert_eq!(w.health_proof_max_age(), Duration::from_millis(500));

  let rc = DriverConfig::new().with_reconfigure_timeout(Duration::from_secs(2));
  assert_eq!(rc.reconfigure_timeout(), Duration::from_secs(2));
}

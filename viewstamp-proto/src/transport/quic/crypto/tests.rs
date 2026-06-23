use super::*;

#[test]
fn accept_any_options_build_tls13_configs() {
  let opts = QuicOptions::accept_any_for_test();
  assert!(opts.idle_timeout_millis() >= 1000);
  assert!(opts.has_client_config() && opts.has_server_config());
}

#[test]
fn cluster_tls_builds_mtls_configs_and_carries_mandatory_client_auth() {
  let ca = test_ca();
  let cert0 = ca.issue_replica(0, 0x5151);
  let opts = ClusterTls::new(ca.roots(), cert0.chain(), cert0.key()).build();
  assert!(opts.has_client_config() && opts.has_server_config());
  assert!(opts.requires_client_auth());
}

#[test]
fn quic_options_carry_layout_and_size_the_connection_window() {
  let ca = test_ca();
  let cert0 = ca.issue_replica(0, 0x5151);
  // The builder accepts a layout override and threads it through to QuicOptions.
  let opts = ClusterTls::new(ca.roots(), cert0.chain(), cert0.key())
    .layout(StreamLayout::ControlBulk)
    .build();
  assert_eq!(opts.layout(), StreamLayout::ControlBulk);
  // Connection window must be at least MAX_FRAME_LEN (16 MiB) so a bulk frame
  // cannot exhaust it and block the control stream.
  assert!(opts.connection_receive_window() >= 16 * 1024 * 1024);
}

/// Keep-alive must be armed strictly under the idle timeout on the PRODUCTION constructor path:
/// steady-state consensus traffic is primary→backups only, so without keep-alive pings the
/// backup↔backup mesh edges idle out and the first view change after a quiet period routes to no
/// live connection.  Asserts both the `QuicOptions` value (idle/3, with two-lost-pings margin) and
/// that `build_transport` actually installs it on the `TransportConfig` (quinn exposes no getter,
/// so the latter is pinned through its `Debug` rendering).
#[test]
fn transport_config_arms_keep_alive_under_the_idle_timeout() {
  let ca = test_ca();
  let cert0 = ca.issue_replica(0, 0x5151);
  let opts = ClusterTls::new(ca.roots(), cert0.chain(), cert0.key()).build();
  assert!(opts.keep_alive_interval_millis() > 0, "keep-alive is on");
  assert!(
    opts.keep_alive_interval_millis() * 3 <= opts.idle_timeout_millis(),
    "keep-alive ({} ms) leaves two-lost-pings margin under the idle timeout ({} ms)",
    opts.keep_alive_interval_millis(),
    opts.idle_timeout_millis(),
  );

  let rendered = format!("{:?}", QuicOptions::build_transport(&QuicTuning::new()));
  assert!(
    rendered.contains("keep_alive_interval: Some"),
    "build_transport installs the keep-alive on the TransportConfig: {rendered}"
  );

  // The test-only accept-any path keeps keep-alive OFF (interval 0 disables it), preserving the
  // quiet-connection timer regime the bridge's deterministic quinn-timer tests pin.
  assert_eq!(
    QuicOptions::accept_any_for_test().keep_alive_interval_millis(),
    0,
    "the accept-any test path leaves keep-alive off"
  );
  let rendered = format!(
    "{:?}",
    QuicOptions::build_transport(&QuicTuning::new().with_keep_alive_interval_millis(0))
  );
  assert!(
    rendered.contains("keep_alive_interval: None"),
    "a zero interval leaves keep-alive off: {rendered}"
  );
}

/// The default tuning IS the pinned constants — every value asserted, so the tunable surface
/// cannot silently drift the production defaults.
#[test]
fn quic_tuning_defaults_equal_the_pinned_constants() {
  let t = QuicTuning::new();
  assert_eq!(t.idle_timeout_millis(), 1_000);
  assert_eq!(
    t.keep_alive_interval_millis(),
    1_000 / 3,
    "the default keep-alive derives idle/3"
  );
  assert_eq!(t.initial_rtt_millis(), 50);
  assert_eq!(t.connection_receive_window(), 17 * 1024 * 1024);
  assert_eq!(t.stream_receive_window(), 8 * 1024 * 1024);
  assert_eq!(QuicTuning::default(), t, "Default delegates to new()");

  // The production constructor path without an override carries exactly these defaults.
  let ca = test_ca();
  let cert0 = ca.issue_replica(0, 0x5151);
  let opts = ClusterTls::new(ca.roots(), cert0.chain(), cert0.key()).build();
  assert_eq!(opts.idle_timeout_millis(), 1_000);
  assert_eq!(opts.keep_alive_interval_millis(), 1_000 / 3);
  assert_eq!(opts.initial_rtt_millis(), 50);
  assert_eq!(opts.connection_receive_window(), 17 * 1024 * 1024);
  assert_eq!(opts.stream_receive_window(), 8 * 1024 * 1024);
}

/// A non-default tuning passed through `ClusterTls::tuning` takes effect end to end: the built
/// `QuicOptions` report the overridden values (keep-alive re-derived from the RAISED idle timeout),
/// and the `TransportConfig` actually installed on the rustls-config path carries them (pinned via
/// its `Debug` rendering — quinn exposes no getters). The mandatory-mTLS posture is untouched by
/// tuning: `requires_client_auth` stays `true`.
#[test]
fn a_non_default_tuning_takes_effect_through_cluster_tls() {
  let ca = test_ca();
  let cert0 = ca.issue_replica(0, 0x5151);
  let tuning = QuicTuning::new()
    .with_idle_timeout_millis(4_000)
    .with_initial_rtt_millis(200)
    .with_stream_receive_window(2 * 1024 * 1024);
  let opts = ClusterTls::new(ca.roots(), cert0.chain(), cert0.key())
    .tuning(tuning)
    .build();
  assert_eq!(opts.idle_timeout_millis(), 4_000);
  assert_eq!(
    opts.keep_alive_interval_millis(),
    4_000 / 3,
    "an un-overridden keep-alive re-derives idle/3 from the raised idle timeout"
  );
  assert_eq!(opts.initial_rtt_millis(), 200);
  assert_eq!(opts.stream_receive_window(), 2 * 1024 * 1024);
  assert!(
    opts.requires_client_auth(),
    "tuning cannot weaken the mandatory-mTLS construction"
  );

  let rendered = format!("{:?}", QuicOptions::build_transport(&tuning));
  assert!(
    rendered.contains("initial_rtt: 200ms"),
    "the overridden initial RTT reaches the TransportConfig: {rendered}"
  );
  // `IdleTimeout`/window values render as bare VarInt numbers (milliseconds / bytes).
  assert!(
    rendered.contains("max_idle_timeout: Some(4000)"),
    "the overridden idle timeout reaches the TransportConfig: {rendered}"
  );
  assert!(
    rendered.contains("stream_receive_window: 2097152"),
    "the overridden stream window reaches the TransportConfig: {rendered}"
  );
}

/// The tuning setters clamp instead of failing: zero values (a wedge, not a tuning) raise to 1 and
/// values past the QUIC `VarInt` range clamp down, so `build_transport`'s `VarInt` conversions can
/// never panic on embedder input.
#[test]
fn quic_tuning_setters_clamp_zero_and_varint_overflow() {
  let t = QuicTuning::new()
    .with_idle_timeout_millis(0)
    .with_initial_rtt_millis(0)
    .with_connection_receive_window(0)
    .with_stream_receive_window(u64::MAX);
  assert_eq!(t.idle_timeout_millis(), 1);
  assert_eq!(t.initial_rtt_millis(), 1);
  assert_eq!(t.connection_receive_window(), 1);
  assert_eq!(t.stream_receive_window(), (1 << 62) - 1);
  // The clamped extremes still build a TransportConfig (no VarInt panic).
  let _ = QuicOptions::build_transport(&t);
}

#[test]
fn max_connections_defaults_and_overrides_and_clamps_zero() {
  // The default cap bounds an untrusted-network accept flood without an explicit override.
  assert_eq!(
    QuicOptions::accept_any_for_test().max_connections(),
    DEFAULT_MAX_CONNECTIONS
  );
  // An override threads through.
  assert_eq!(
    QuicOptions::accept_any_for_test()
      .with_max_connections(8)
      .max_connections(),
    8
  );
  // Zero is clamped to 1 so at least one connection is always admissible.
  assert_eq!(
    QuicOptions::accept_any_for_test()
      .with_max_connections(0)
      .max_connections(),
    1
  );
}

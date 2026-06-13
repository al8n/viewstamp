//! Crypto-provider plumbing for the QUIC transport (backed by the same rustls provider as TLS).
//!
//! `QuicOptions` holds the caller-supplied quinn-proto configs and a tuned
//! `TransportConfig` whose timer/window values come from a [`QuicTuning`] (defaults shown):
//!
//! - `max_idle_timeout` = 1 000 ms (> the 200 ms consensus primary-idle).
//! - `keep_alive_interval` = idle/3: steady-state consensus traffic is primary→backups only, so
//!   keep-alive pings are what hold the otherwise zero-traffic backup↔backup mesh edges under the
//!   idle timeout between view changes (quinn's default is no keep-alive).
//! - `initial_rtt` = 50 ms (PTO ~150 ms < the 200 ms consensus primary-idle) so a dropped handshake
//!   datagram retransmits before a backup view-changes off a not-yet-connected primary.
//! - `max_concurrent_bidi_streams` = 8 (each side opens up to 2 send streams under
//!   `ControlBulk`; 8 gives per-side pair headroom across the cluster mesh).
//! - `receive_window` (connection-level) = 17 MiB (16 MiB max frame + 1 MiB headroom)
//!   so a maximum-sized bulk frame on one stream cannot exhaust the connection window
//!   and stall the control stream.
//! - `stream_receive_window` = 8 MiB: a checkpoint can flow in one shot but a single
//!   stream cannot itself consume the full connection window.
//!
//! Use [`ClusterTls`] to build a `QuicOptions` with mandatory mutual TLS over
//! cluster-private roots: the stock WebPki verifiers perform chain-only
//! validation against the cluster CA, so a peer without a valid cert is
//! rejected at the TLS handshake before any stream opens. A geo-replicated or
//! otherwise non-default deployment overrides the timer/window values via
//! [`ClusterTls::tuning`]; the security-relevant construction (roots, mTLS,
//! TLS 1.3, ALPN) is not tunable.

use std::{sync::Arc, time::Duration};

use quinn_proto::{
  ClientConfig, EndpointConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::layout::StreamLayout;

/// The rustls [`CryptoProvider`](rustls::crypto::CryptoProvider) the QUIC TLS configs are built from,
/// selected by the SAME `tls-rustls-*` features `Cargo.toml` wires (so the provider matches the one
/// the byte-stream `tls` layer links and the one `quinn-proto` is compiled against). `ring` takes
/// precedence when present; otherwise the FIPS `aws-lc-rs` provider, else the standard `aws-lc-rs`
/// provider. The `quic` feature requires at least one provider (a `compile_error!` in
/// [`transport`](crate::transport) enforces it), so exactly one of these arms is always live.
///
/// `tls-rustls-aws-lc-rs-fips` uses rustls's dedicated [`default_fips_provider`](rustls::crypto::default_fips_provider),
/// which selects only FIPS-approved cipher suites and asserts the process is in a FIPS-capable build —
/// stronger than the plain `aws_lc_rs::default_provider`, which merely prefers FIPS suites when the
/// `fips` feature is on.
#[cfg(feature = "quic")]
fn active_provider() -> Arc<rustls::crypto::CryptoProvider> {
  #[cfg(feature = "tls-rustls-ring")]
  {
    Arc::new(rustls::crypto::ring::default_provider())
  }
  #[cfg(all(
    feature = "tls-rustls-aws-lc-rs-fips",
    not(feature = "tls-rustls-ring")
  ))]
  {
    Arc::new(rustls::crypto::default_fips_provider())
  }
  #[cfg(all(
    feature = "tls-rustls-aws-lc-rs",
    not(feature = "tls-rustls-ring"),
    not(feature = "tls-rustls-aws-lc-rs-fips")
  ))]
  {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
  }
}

/// Default idle timeout.  Must exceed the 200 ms consensus primary-idle.
///
/// On its own an idle timeout is fatal to the mesh: steady-state consensus traffic is
/// primary→backups only (heartbeats), so the backup↔backup connections carry NOTHING between view
/// changes and would idle out this long after the last one — leaving the NEXT view change (the
/// primary just died) with no live backup↔backup links for `StartViewChange`/`DoViewChange`.
/// [`keep_alive_interval_millis`] is what keeps those zero-traffic edges alive under this timeout.
const IDLE_TIMEOUT_MILLIS: u64 = 1_000;

/// Keep-alive PING interval derived from the idle timeout: one third, so up to two consecutive
/// lost keep-alives still refresh the peer's idle timer in time.  quinn's default is NO keep-alive,
/// under which a healthy-but-quiet connection idles out — and the backup↔backup mesh edges are
/// exactly that between view changes (see [`IDLE_TIMEOUT_MILLIS`]).  A zero result (an idle timeout
/// too small to subdivide) leaves keep-alive off.
const fn keep_alive_interval_millis(idle_timeout_millis: u64) -> u64 {
  idle_timeout_millis / 3
}

/// Default initial RTT estimate for loss recovery BEFORE the first RTT sample.  quinn derives the
/// initial Probe Timeout (PTO) — the delay before a lost handshake packet is first retransmitted —
/// from this value, so it governs how fast a connection recovers from a dropped Initial/Handshake
/// datagram on a link that has not yet measured an RTT.
///
/// quinn's default is 333 ms (a WAN-tuned estimate), which yields an initial PTO of ~1 s.  On a
/// cluster-internal link that is far too slow: a single dropped handshake datagram would stall the
/// handshake for ~1 s, which EXCEEDS the 200 ms consensus primary-idle — so a backup would start a
/// view change before its link to the primary is even up, and a 2-replica cluster cannot reconcile a
/// lone-replica view-change escalation (the higher-view anti-amplification rule), leaving it to
/// escalate views indefinitely instead of converging.  The default is 50 ms (PTO ~150 ms, comfortably
/// under the 200 ms primary-idle, and still ~50× a real datacenter RTT so it does not provoke
/// spurious early retransmits) so a dropped handshake datagram retransmits well before the consensus
/// layer reacts.  The seeded datagram sim (`datagram_sim`) is the regression net for this.
/// A geo-replicated cluster (real RTTs near or above 50 ms) raises it via
/// [`QuicTuning::with_initial_rtt_millis`] — together with the consensus timing — so the estimate
/// stays above the real RTT.
const INITIAL_RTT_MILLIS: u64 = 50;

/// Pinned max concurrent bidi streams.  Each side opens up to 2 send streams
/// under `ControlBulk` (Control + Bulk); 8 gives cluster-mesh headroom for the
/// mutual-dial doubling where both peers open streams concurrently.
pub(crate) const MAX_BIDI_STREAMS: u32 = 8;

/// Connection-level receive window: max frame (16 MiB) plus control headroom
/// (1 MiB) so a single max-sized bulk frame on the Bulk stream cannot exhaust
/// the connection window and block the Control stream.
const CONNECTION_RECEIVE_WINDOW: u64 = 17 * 1024 * 1024;

/// Per-stream receive window: a checkpoint snapshot can arrive in one shot but
/// a single stream is bounded below the connection window so it cannot itself
/// exhaust connection-level flow control.
const STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024;

/// The largest value a QUIC `VarInt` can carry (`2^62 - 1`).  The tuning setters clamp to this so an
/// embedder-supplied window/timeout can never make the `VarInt` conversions in
/// [`QuicOptions::build_transport`] fail at construction time.
const MAX_VARINT_U64: u64 = (1 << 62) - 1;

/// Clamp an embedder-supplied tuning value into `1..=MAX_VARINT_U64`: never zero (a zero timeout or
/// window is a wedge, not a tuning), never past the QUIC `VarInt` range.
const fn clamp_tuning(v: u64) -> u64 {
  if v == 0 {
    1
  } else if v > MAX_VARINT_U64 {
    MAX_VARINT_U64
  } else {
    v
  }
}

/// Embedder-tunable timer and flow-control values for the QUIC `TransportConfig`, with `Default` =
/// the pinned LAN-tuned constants (see each field's constant for the rationale).
/// A geo-replicated cluster — where the defaults' assumptions (sub-50 ms RTT, 200 ms primary-idle
/// headroom) do not hold — overrides them via [`ClusterTls::tuning`].
///
/// **Scope (the security posture).** This carries ONLY performance knobs — timers and window sizes.
/// It cannot reach the security-relevant construction: the cluster-private roots, mandatory mTLS
/// (client-cert verification), TLS 1.3 pinning, and ALPN live exclusively inside
/// [`ClusterTls::build`], which accepts a `QuicTuning` but never lets it near the rustls configs.
/// No tuning value can disable or weaken authentication.
///
/// Setters clamp to `1..=2^62-1` (the QUIC `VarInt` range) so no embedder value can wedge the
/// transport with a zero timeout/window or fail the `VarInt` conversions at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicTuning {
  /// `max_idle_timeout`, milliseconds. Default [`IDLE_TIMEOUT_MILLIS`].
  idle_timeout_millis: u64,
  /// `keep_alive_interval`, milliseconds. `None` (the default) derives idle/3 — the two-lost-pings
  /// margin [`keep_alive_interval_millis`] documents; an explicit `Some(0)` disables keep-alive.
  keep_alive_interval_millis: Option<u64>,
  /// `initial_rtt`, milliseconds. Default [`INITIAL_RTT_MILLIS`].
  initial_rtt_millis: u64,
  /// Connection-level `receive_window`, bytes. Default [`CONNECTION_RECEIVE_WINDOW`].
  connection_receive_window: u64,
  /// Per-stream `stream_receive_window`, bytes. Default [`STREAM_RECEIVE_WINDOW`].
  stream_receive_window: u64,
}

impl QuicTuning {
  /// The default tuning — exactly the constants the transport pins without an override.
  #[must_use]
  pub const fn new() -> Self {
    Self {
      idle_timeout_millis: IDLE_TIMEOUT_MILLIS,
      keep_alive_interval_millis: None,
      initial_rtt_millis: INITIAL_RTT_MILLIS,
      connection_receive_window: CONNECTION_RECEIVE_WINDOW,
      stream_receive_window: STREAM_RECEIVE_WINDOW,
    }
  }

  /// Idle timeout in milliseconds (see `IDLE_TIMEOUT_MILLIS` for the consensus coupling).
  #[inline(always)]
  pub const fn idle_timeout_millis(&self) -> u64 {
    self.idle_timeout_millis
  }

  /// The RESOLVED keep-alive interval in milliseconds: the explicit override when one was set
  /// (`0` = keep-alive off), otherwise idle/3 — derived from the CURRENT idle timeout, so raising
  /// the idle timeout scales the keep-alive with it (see `keep_alive_interval_millis`).
  #[inline(always)]
  pub const fn keep_alive_interval_millis(&self) -> u64 {
    match self.keep_alive_interval_millis {
      Some(ms) => ms,
      None => keep_alive_interval_millis(self.idle_timeout_millis),
    }
  }

  /// Initial RTT estimate in milliseconds (see `INITIAL_RTT_MILLIS` for why the default is
  /// LAN-tuned and what a geo-replicated cluster must raise it to).
  #[inline(always)]
  pub const fn initial_rtt_millis(&self) -> u64 {
    self.initial_rtt_millis
  }

  /// Connection-level receive window in bytes (see `CONNECTION_RECEIVE_WINDOW`).
  #[inline(always)]
  pub const fn connection_receive_window(&self) -> u64 {
    self.connection_receive_window
  }

  /// Per-stream receive window in bytes (see `STREAM_RECEIVE_WINDOW`).
  #[inline(always)]
  pub const fn stream_receive_window(&self) -> u64 {
    self.stream_receive_window
  }

  /// Override the idle timeout (milliseconds; clamped to `1..=2^62-1`). Must stay ABOVE the
  /// consensus primary-idle, or healthy links idle out between heartbeats; with the default
  /// (derived) keep-alive the idle/3 ping interval scales along with it.
  #[must_use]
  pub const fn with_idle_timeout_millis(mut self, millis: u64) -> Self {
    self.idle_timeout_millis = clamp_tuning(millis);
    self
  }

  /// Override the keep-alive interval (milliseconds; `0` disables keep-alive). Without an override
  /// the interval is derived as idle/3. Disabling keep-alive on a production mesh is a liveness
  /// hazard: the zero-traffic backup↔backup edges then idle out between view changes (see
  /// `IDLE_TIMEOUT_MILLIS`).
  #[must_use]
  pub const fn with_keep_alive_interval_millis(mut self, millis: u64) -> Self {
    self.keep_alive_interval_millis = Some(millis);
    self
  }

  /// Override the initial RTT estimate (milliseconds; clamped to `1..=2^62-1`). Keep it at or above
  /// the real inter-replica RTT: an estimate far below it provokes spurious handshake retransmits,
  /// while the consensus primary-idle must in turn stay above the resulting ~3×RTT initial PTO.
  #[must_use]
  pub const fn with_initial_rtt_millis(mut self, millis: u64) -> Self {
    self.initial_rtt_millis = clamp_tuning(millis);
    self
  }

  /// Override the connection-level receive window (bytes; clamped to `1..=2^62-1`). Keep it at or
  /// above `MAX_FRAME_LEN` (16 MiB) plus control headroom so one maximum-sized bulk frame cannot
  /// consume the whole connection window and stall the control stream; a smaller window only
  /// throttles bulk throughput (credit regrants as the reader drains), it cannot deadlock.
  #[must_use]
  pub const fn with_connection_receive_window(mut self, bytes: u64) -> Self {
    self.connection_receive_window = clamp_tuning(bytes);
    self
  }

  /// Override the per-stream receive window (bytes; clamped to `1..=2^62-1`). Sized so a checkpoint
  /// flows in one shot but a single stream stays bounded below the connection window.
  #[must_use]
  pub const fn with_stream_receive_window(mut self, bytes: u64) -> Self {
    self.stream_receive_window = clamp_tuning(bytes);
    self
  }
}

impl Default for QuicTuning {
  fn default() -> Self {
    Self::new()
  }
}

/// Default cap on the number of LIVE connections the bridge holds at once (dialed + accepted). The
/// network is untrusted: an inbound flood of foreign-CA / no-cert Initials would otherwise each
/// allocate a `Connection` before identity validation could reject it. At the cap the bridge
/// statelessly refuses further inbound attempts ([`quinn_proto::Endpoint::refuse`]) instead of
/// allocating. Sized generously for a small voting cluster (≤64 replicas) plus mutual-dial doubling
/// and reconnect headroom; raise it via [`QuicOptions::with_max_connections`] for a larger mesh.
///
/// This is only the cap when no `replica_count`-derived sizing applies: the QUIC coordinator RAISES
/// the effective cap to [`mesh_connection_floor`] at construction, so a default-cap node on a large
/// cluster still admits its whole steady-state mesh (see that fn).
const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// A small constant floor on the connection cap, so even a 1- or 2-replica cluster (whose mutual-dial
/// mesh is tiny) keeps a little accept/reconnect headroom.
const MIN_CONNECTION_FLOOR: usize = 4;

/// The minimum live-connection cap that admits an `replica_count`-replica node's full steady-state
/// mutual-dial mesh, plus reconnect headroom.
///
/// **Formula:** `max(MIN_CONNECTION_FLOOR, 3 * (replica_count - 1))`.
///
/// **Rationale.** The mutual-dial design keeps TWO physical connections per peer pair (each side dials
/// the other and both are kept; see `Bridge::bind_validated`), so in an `N`-member cluster (every
/// member — voting or not — joins the mesh) a node holds `2*(N-1)` steady-state connections. A
/// reconnecting peer can briefly hold a THIRD connection (the new dial / accept overlapping the old one
/// before it idle-times-out or is reaped), so we add one reconnect slot per peer — `(N-1)` — for a
/// total of `3*(N-1)`, comfortably above the `2*(N-1)` bare-mesh requirement; for `N <= 1` it is the floor.
///
/// The coordinator RAISES `max_connections` to this when the caller-configured cap is lower, so the cap
/// can never refuse a legitimate steady-state mesh connection (a liveness failure at scale). It still
/// bounds an untrusted-network flood; it is just sized to the configured membership (`node_count`,
/// voters plus non-voting members) rather than a fixed constant.
pub(crate) const fn mesh_connection_floor(node_count: u16) -> usize {
  let peers = (node_count as usize).saturating_sub(1);
  let mesh_with_reconnect = peers * 3;
  if mesh_with_reconnect > MIN_CONNECTION_FLOOR {
    mesh_with_reconnect
  } else {
    MIN_CONNECTION_FLOOR
  }
}

/// Immutable QUIC config bundle handed to the endpoint builder. Accessor-only;
/// all fields are private and cannot be mutated after construction.
pub struct QuicOptions {
  endpoint: Arc<EndpointConfig>,
  client: Option<ClientConfig>,
  server: Option<Arc<ServerConfig>>,
  idle_timeout_millis: u64,
  /// Keep-alive interval baked into the `TransportConfig` (milliseconds; 0 = off).  Resolved from
  /// the [`QuicTuning`] (explicit override, or idle/3 by [`keep_alive_interval_millis`]).
  keep_alive_interval_millis: u64,
  /// Initial RTT estimate baked into the `TransportConfig` (milliseconds).
  initial_rtt_millis: u64,
  /// Set to `true` by [`ClusterTls::build`]; `false` for the accept-any test
  /// path.
  requires_client_auth: bool,
  /// Stream-layout selector stored for the coordinator and tests.
  layout: StreamLayout,
  /// Connection-level receive window baked into the `TransportConfig` (bytes).
  connection_receive_window: u64,
  /// Per-stream receive window baked into the `TransportConfig` (bytes).
  stream_receive_window: u64,
  /// Cap on the number of live connections the bridge holds at once. Inbound attempts past this are
  /// refused (stateless close) instead of allocating, bounding an untrusted-network accept flood.
  max_connections: usize,
}

impl QuicOptions {
  /// Build from caller-supplied configs and an idle timeout (milliseconds).
  ///
  /// The tuned `TransportConfig` (idle timeout + bidi-stream cap + flow-control
  /// windows; every other value the [`QuicTuning`] default) is constructed
  /// internally and installed on both the server and client.  The layout
  /// defaults to `StreamLayout::ControlBulk`.
  pub fn new(
    endpoint: EndpointConfig,
    client: Option<ClientConfig>,
    server: Option<ServerConfig>,
    idle_timeout_millis: u64,
  ) -> Self {
    Self::new_inner(
      endpoint,
      client,
      server,
      QuicTuning::new().with_idle_timeout_millis(idle_timeout_millis),
      false,
      StreamLayout::default(),
    )
  }

  /// Every production constructor leaves the tuning's keep-alive in effect (the default idle/3 — the
  /// zero-traffic backup↔backup mesh edges need it); only the test-only accept-any path passes an
  /// explicit 0 (see the rationale at its call site).
  fn new_inner(
    endpoint: EndpointConfig,
    client: Option<ClientConfig>,
    server: Option<ServerConfig>,
    tuning: QuicTuning,
    requires_client_auth: bool,
    layout: StreamLayout,
  ) -> Self {
    let transport = Self::build_transport(&tuning);
    let server = server.map(|mut s| {
      s.transport_config(transport.clone());
      Arc::new(s)
    });
    let mut client = client;
    if let Some(ref mut c) = client {
      c.transport_config(transport);
    }
    Self {
      endpoint: Arc::new(endpoint),
      client,
      server,
      idle_timeout_millis: tuning.idle_timeout_millis(),
      keep_alive_interval_millis: tuning.keep_alive_interval_millis(),
      initial_rtt_millis: tuning.initial_rtt_millis(),
      requires_client_auth,
      layout,
      connection_receive_window: tuning.connection_receive_window(),
      stream_receive_window: tuning.stream_receive_window(),
      max_connections: DEFAULT_MAX_CONNECTIONS,
    }
  }

  /// Cheap clone of the endpoint config arc.
  #[inline(always)]
  pub fn endpoint_config(&self) -> Arc<EndpointConfig> {
    self.endpoint.clone()
  }

  /// Cheap clone of the client config used for outbound dials, if any.
  #[inline(always)]
  pub fn client_config(&self) -> Option<ClientConfig> {
    self.client.clone()
  }

  /// Cheap clone of the server config arc, if any.
  #[inline(always)]
  pub fn server_config(&self) -> Option<Arc<ServerConfig>> {
    self.server.clone()
  }

  /// Idle timeout in milliseconds (the value baked into the transport config).
  #[inline(always)]
  pub const fn idle_timeout_millis(&self) -> u64 {
    self.idle_timeout_millis
  }

  /// Keep-alive interval in milliseconds baked into the transport config (0 = keep-alive off).
  /// One third of [`Self::idle_timeout_millis`] by default — the two-lost-pings margin that keeps
  /// the zero-traffic backup↔backup mesh edges alive (see `keep_alive_interval_millis`); an
  /// explicit [`QuicTuning`] override replaces the derivation.
  #[inline(always)]
  pub const fn keep_alive_interval_millis(&self) -> u64 {
    self.keep_alive_interval_millis
  }

  /// Initial RTT estimate in milliseconds baked into the transport config (the value loss recovery
  /// uses before the first real RTT sample; see `INITIAL_RTT_MILLIS`).
  #[inline(always)]
  pub const fn initial_rtt_millis(&self) -> u64 {
    self.initial_rtt_millis
  }

  /// Whether a client config is present.
  #[inline(always)]
  pub const fn has_client_config(&self) -> bool {
    self.client.is_some()
  }

  /// Whether a server config is present.
  #[inline(always)]
  pub const fn has_server_config(&self) -> bool {
    self.server.is_some()
  }

  /// Whether the server config was built with mandatory client-certificate
  /// authentication.  `true` only when constructed via [`ClusterTls::build`];
  /// the accept-any test path leaves this `false`.
  #[inline(always)]
  pub const fn requires_client_auth(&self) -> bool {
    self.requires_client_auth
  }

  /// The stream-layout selector for this options bundle.
  #[inline(always)]
  pub const fn layout(&self) -> StreamLayout {
    self.layout
  }

  /// The connection-level receive window baked into the `TransportConfig`
  /// (bytes).  At least `MAX_FRAME_LEN` (16 MiB) by default so a maximum-sized
  /// bulk frame cannot exhaust the connection window and stall the control
  /// stream.
  #[inline(always)]
  pub const fn connection_receive_window(&self) -> u64 {
    self.connection_receive_window
  }

  /// The per-stream receive window baked into the `TransportConfig` (bytes).
  #[inline(always)]
  pub const fn stream_receive_window(&self) -> u64 {
    self.stream_receive_window
  }

  /// The cap on live connections (dialed + accepted). The bridge refuses inbound attempts once the
  /// table holds this many, bounding an untrusted-network accept flood. Defaults to
  /// `DEFAULT_MAX_CONNECTIONS`; override with [`Self::with_max_connections`].
  #[inline(always)]
  pub const fn max_connections(&self) -> usize {
    self.max_connections
  }

  /// Override the live-connection cap (see [`Self::max_connections`]). Sized for the cluster's
  /// replica count plus mutual-dial doubling and reconnect headroom; a value of 0 is clamped to 1 so
  /// at least one connection is always admissible.
  ///
  /// The QUIC coordinator RAISES the effective cap to the membership-sized
  /// `mesh_connection_floor` at construction whenever the value set here is
  /// lower, so the cap can never refuse a legitimate steady-state mutual-dial mesh connection. Setting
  /// a value ABOVE that floor still takes effect (a larger flood budget); a lower one is floored.
  #[must_use]
  pub const fn with_max_connections(mut self, max: usize) -> Self {
    self.max_connections = if max == 0 { 1 } else { max };
    self
  }

  /// Build the tuned `TransportConfig` shared between server and client.  The timer/window values
  /// come from `tuning` (a resolved keep-alive of 0 leaves keep-alive off — quinn's default); the
  /// stream caps and the closed protocol surfaces below are pinned, not tunable.
  fn build_transport(tuning: &QuicTuning) -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    let idle = IdleTimeout::try_from(Duration::from_millis(tuning.idle_timeout_millis()))
      .expect("idle timeout within VarInt range");
    tc.max_idle_timeout(Some(idle));
    // Keep-alive pings hold the zero-traffic backup↔backup mesh edges under the idle timeout
    // (see `keep_alive_interval_millis`); a resolved 0 means keep-alive off.
    let keep_alive = tuning.keep_alive_interval_millis();
    if keep_alive > 0 {
      tc.keep_alive_interval(Some(Duration::from_millis(keep_alive)));
    }
    tc.initial_rtt(Duration::from_millis(tuning.initial_rtt_millis()));
    tc.max_concurrent_bidi_streams(VarInt::from_u32(MAX_BIDI_STREAMS));
    // Close the protocol surfaces this transport does NOT use, so a buggy / version-skew but
    // fully validated peer cannot pin connection-level receive credit or memory on them and stall
    // the Control/Bulk streams that share the connection window. Both quinn defaults are
    // peer-usable (uni-stream limit 100, datagram-receive buffer Some(...)); consensus rides framed
    // BIDI streams only and never QUIC DATAGRAM frames, so neither is needed.
    //
    // - Incoming UNIDIRECTIONAL streams: advertise a limit of 0, so a peer's `open(Dir::Uni)` is
    //   refused by construction (it cannot mint the stream against a 0 limit) and a peer that forces
    //   one anyway trips `STREAM_LIMIT_ERROR`, which quinn turns into a connection close.
    // - DATAGRAM RECEIVE: `None` stops advertising `max_datagram_size`, so the peer's `datagrams()`
    //   send is `UnsupportedByPeer` and an unsolicited DATAGRAM frame is a protocol violation quinn
    //   rejects — nothing is buffered. (SEND stays at the quinn default but is never exercised: the
    //   bridge issues no `datagrams().send`, and `poll_transmit`'s `max_datagrams` is the UDP-packet
    //   coalescing count, not QUIC DATAGRAM frames.)
    //
    // After this the ignored `Stream(Opened { dir: Dir::Uni })` / `DatagramReceived` /
    // `DatagramsUnblocked` arms in `on_app_event` are unreachable on a conformant path; they remain a
    // defensive ignore.
    tc.max_concurrent_uni_streams(VarInt::from_u32(0));
    tc.datagram_receive_buffer_size(None);
    // Connection-level window: must accommodate a max bulk frame (16 MiB) without
    // blocking the control stream.  A Bulk stream exhausts stream_receive_window
    // before it can exhaust this larger connection window.
    tc.receive_window(
      VarInt::from_u64(tuning.connection_receive_window())
        .expect("connection window within VarInt range (clamped by the tuning setter)"),
    );
    // Per-stream window: large enough for a checkpoint snapshot in one shot but
    // bounded below the connection window so a single stream cannot monopolise it.
    tc.stream_receive_window(
      VarInt::from_u64(tuning.stream_receive_window())
        .expect("stream window within VarInt range (clamped by the tuning setter)"),
    );
    Arc::new(tc)
  }
}

/// Builds a [`QuicOptions`] bundle with mandatory mutual TLS over a
/// cluster-private root CA.
///
/// Both directions are fully authenticated:
///
/// - **Server side** uses [`rustls::server::WebPkiClientVerifier`] rooted at
///   the cluster CA, which makes client certificates mandatory by default.
///   A peer without a cert (or whose cert does not chain to the cluster CA) is
///   rejected at the TLS handshake before any QUIC stream opens.
///
/// - **Client side** uses [`rustls::client::WebPkiServerVerifier`] with the
///   same cluster CA, and presents this node's cert chain for mutual
///   authentication (`with_client_auth_cert`).
///
/// Both configs are TLS 1.3-only with ALPN set to `b"viewstamp"`.
///
/// ## SNI server name
///
/// The stock `WebPkiServerVerifier` validates the SNI `server_name` the dialer
/// supplies against the server cert's Subject Alternative Names.  Mint each
/// replica's cert with a DNS SAN of the form
/// `replica-<n>.<cluster-hex>.viewstamp` and have the coordinator pass that
/// derived name on `connect` so the verifier can match it.
pub struct ClusterTls {
  roots: rustls::RootCertStore,
  chain: Vec<CertificateDer<'static>>,
  key: PrivateKeyDer<'static>,
  layout: StreamLayout,
  tuning: QuicTuning,
}

impl ClusterTls {
  /// Create a new `ClusterTls` builder.
  ///
  /// - `roots` — the cluster-private CA(s); only peers whose cert chains to
  ///   one of these roots will complete the handshake.
  /// - `chain` — this node's certificate chain (leaf first).
  /// - `key` — the private key for the leaf certificate.
  pub fn new(
    roots: rustls::RootCertStore,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
  ) -> Self {
    Self {
      roots,
      chain,
      key,
      layout: StreamLayout::default(),
      tuning: QuicTuning::new(),
    }
  }

  /// Set the stream-layout selector for the built [`QuicOptions`].  The default
  /// is `StreamLayout::ControlBulk`.
  pub fn layout(mut self, layout: StreamLayout) -> Self {
    self.layout = layout;
    self
  }

  /// Override the transport timer/window tuning for the built [`QuicOptions`].  The default is
  /// [`QuicTuning::new`] (the LAN-tuned constants).  Tuning carries ONLY performance knobs — the
  /// mandatory-mTLS construction this builder performs is unaffected by any tuning value (see
  /// [`QuicTuning`]'s scope note).
  pub fn tuning(mut self, tuning: QuicTuning) -> Self {
    self.tuning = tuning;
    self
  }

  /// Consume the builder and produce a [`QuicOptions`] with both a server
  /// config (mandatory client auth) and a client config (mTLS).
  pub fn build(self) -> QuicOptions {
    use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rustls::{client::WebPkiServerVerifier, server::WebPkiClientVerifier};

    // The crypto provider is selected by the `tls-rustls-*` feature, NOT hard-coded — so an
    // aws-lc-rs / FIPS-only build links the matching provider (see `active_provider`).
    let provider = active_provider();
    let roots = Arc::new(self.roots);

    // Server: mandatory client-cert auth via cluster CA.
    let client_verifier =
      WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone())
        .build()
        .expect("WebPkiClientVerifier with valid cluster roots");
    let mut rustls_server = rustls::ServerConfig::builder_with_provider(provider.clone())
      .with_protocol_versions(&[&rustls::version::TLS13])
      .expect("TLS 1.3 is supported by the active provider")
      .with_client_cert_verifier(client_verifier)
      .with_single_cert(self.chain.clone(), self.key.clone_key())
      .expect("valid cluster cert and key");
    rustls_server.alpn_protocols = vec![b"viewstamp".to_vec()];
    let qsc = QuicServerConfig::try_from(Arc::new(rustls_server))
      .expect("QuicServerConfig from cluster-CA rustls ServerConfig");
    let server = ServerConfig::with_crypto(Arc::new(qsc));

    // Client: verify server against cluster CA; present this node's cert.
    let server_verifier = WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
      .build()
      .expect("WebPkiServerVerifier with valid cluster roots");
    let mut rustls_client = rustls::ClientConfig::builder_with_provider(provider)
      .with_protocol_versions(&[&rustls::version::TLS13])
      .expect("TLS 1.3 is supported by the active provider")
      .dangerous()
      .with_custom_certificate_verifier(server_verifier)
      .with_client_auth_cert(self.chain, self.key)
      .expect("valid cluster cert and key for client auth");
    rustls_client.alpn_protocols = vec![b"viewstamp".to_vec()];
    let qcc = QuicClientConfig::try_from(Arc::new(rustls_client))
      .expect("QuicClientConfig from cluster-CA rustls ClientConfig");
    let client = ClientConfig::new(Arc::new(qcc));

    QuicOptions::new_inner(
      EndpointConfig::default(),
      Some(client),
      Some(server),
      self.tuning,
      true,
      self.layout,
    )
  }
}

#[cfg(test)]
impl QuicOptions {
  /// Test-only builder: self-signed cert, accept-any verifier, TLS 1.3 + ALPN
  /// `viewstamp`, default (`ControlBulk`) stream layout.
  ///
  /// The `EndpointConfig` is `default()` — the deterministic rng seed is applied
  /// when the actual `Endpoint` is built.
  pub fn accept_any_for_test() -> Self {
    Self::accept_any_with_layout(StreamLayout::default())
  }

  /// As [`accept_any_for_test`](Self::accept_any_for_test) but with an explicit
  /// stream layout, so a bridge test can drive either `Single` or `ControlBulk`.
  pub fn accept_any_with_layout(layout: StreamLayout) -> Self {
    use crate::transport::tls::test_verifier::AcceptAny;
    use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};

    // Self-signed cert via rcgen 0.14.
    let ck = rcgen::generate_simple_self_signed(vec!["viewstamp.local".into()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(ck.signing_key.serialize_der()).unwrap();

    // Rustls provider: the SAME feature-selected provider the production `build` uses (not hard-coded
    // ring), installed process-wide for any rustls path that consults the default.
    let provider = active_provider();
    let _ = (*provider).clone().install_default();

    // Server config: no client auth; ALPN viewstamp.
    let mut rustls_server = rustls::ServerConfig::builder_with_provider(provider.clone())
      .with_protocol_versions(&[&rustls::version::TLS13])
      .unwrap()
      .with_no_client_auth()
      .with_single_cert(vec![cert], key)
      .unwrap();
    rustls_server.alpn_protocols = vec![b"viewstamp".to_vec()];
    let qsc =
      QuicServerConfig::try_from(Arc::new(rustls_server)).expect("QuicServerConfig from rustls");
    let server = ServerConfig::with_crypto(Arc::new(qsc));

    // Client config: accept-any verifier (test only); ALPN viewstamp.
    let mut rustls_client = rustls::ClientConfig::builder_with_provider(provider)
      .with_protocol_versions(&[&rustls::version::TLS13])
      .unwrap()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(AcceptAny))
      .with_no_client_auth();
    rustls_client.alpn_protocols = vec![b"viewstamp".to_vec()];
    let qcc =
      QuicClientConfig::try_from(Arc::new(rustls_client)).expect("QuicClientConfig from rustls");
    let client = ClientConfig::new(Arc::new(qcc));

    // Keep-alive stays OFF here (and only here, via the explicit 0 override): the bridge's
    // deterministic timer tests pin quinn's exact next-timer identity (idle/drain timers vs the
    // auth-deadline fold-in), which background keep-alive pings would perturb. The production
    // constructors arm it; its behavior is covered by the production-path config test plus the
    // real-time driver loopback.
    Self::new_inner(
      EndpointConfig::default(),
      Some(client),
      Some(server),
      QuicTuning::new().with_keep_alive_interval_millis(0),
      false,
      layout,
    )
  }
}

/// A test-only cluster CA + per-replica certificate issuer (rcgen 0.14).
///
/// `test_ca()` generates a fresh self-signed CA. `issue_replica` issues leaf
/// certs signed by that CA with a DNS SAN of the form
/// `replica-<n>.<cluster-hex>.viewstamp`.  The `cluster-hex` portion is a
/// 32-character zero-padded hex string derived from the cluster id passed to
/// `issue_replica`.
#[cfg(test)]
pub(crate) struct TestClusterCa {
  ca_cert: rcgen::Certificate,
  issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

#[cfg(test)]
impl TestClusterCa {
  /// Build a `RootCertStore` containing the CA certificate.
  pub(crate) fn roots(&self) -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    store
      .add(CertificateDer::from(self.ca_cert.der().to_vec()))
      .expect("CA cert parses as a trust anchor");
    store
  }

  /// Issue a leaf certificate signed by this CA with the SAN
  /// `replica-<n>.<cluster_id_hex>.viewstamp`.
  pub(crate) fn issue_replica(&self, n: u16, cluster: u128) -> TestReplicaCert {
    let san = format!("replica-{n}.{cluster:032x}.viewstamp");
    let mut params =
      rcgen::CertificateParams::new(vec![san]).expect("valid DNS SAN for replica cert");
    params
      .key_usages
      .push(rcgen::KeyUsagePurpose::DigitalSignature);
    params
      .extended_key_usages
      .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    params
      .extended_key_usages
      .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let leaf_key = rcgen::KeyPair::generate().expect("key pair generation succeeds");
    let cert = params
      .signed_by(&leaf_key, &self.issuer)
      .expect("leaf cert signed by cluster CA");
    TestReplicaCert { cert, leaf_key }
  }

  /// Issue a leaf certificate (as [`issue_replica`](Self::issue_replica)) that also carries the
  /// viewstamp identity extension attesting `Peer::Replica(n)` for `cluster` — the input a
  /// [`CertOid`](super::CertOid) verifier parses. The extension is added NON-critical so the stock
  /// cluster-CA WebPki verifier does not reject the chain over it (see [`CertOid`](super::CertOid)).
  pub(crate) fn issue_replica_with_oid(&self, n: u16, cluster: u128) -> TestReplicaCert {
    use super::identity::{IDENTITY_OID, encode_identity_ext};

    let san = format!("replica-{n}.{cluster:032x}.viewstamp");
    let mut params =
      rcgen::CertificateParams::new(vec![san]).expect("valid DNS SAN for replica cert");
    params
      .key_usages
      .push(rcgen::KeyUsagePurpose::DigitalSignature);
    params
      .extended_key_usages
      .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    params
      .extended_key_usages
      .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let content = encode_identity_ext(cluster, crate::Peer::Replica(crate::ReplicaId::new(n)));
    let ext = rcgen::CustomExtension::from_oid_content(IDENTITY_OID, content);
    params.custom_extensions.push(ext);
    let leaf_key = rcgen::KeyPair::generate().expect("key pair generation succeeds");
    let cert = params
      .signed_by(&leaf_key, &self.issuer)
      .expect("leaf cert signed by cluster CA");
    TestReplicaCert { cert, leaf_key }
  }
}

/// A leaf certificate + private key issued by a [`TestClusterCa`].
#[cfg(test)]
pub(crate) struct TestReplicaCert {
  cert: rcgen::Certificate,
  leaf_key: rcgen::KeyPair,
}

#[cfg(test)]
impl TestReplicaCert {
  /// The certificate chain (leaf only; CA is in the trust store).
  pub(crate) fn chain(&self) -> Vec<CertificateDer<'static>> {
    vec![CertificateDer::from(self.cert.der().to_vec())]
  }

  /// The end-entity (leaf) certificate as a single owned DER — the form
  /// [`CertOid`](super::CertOid) parses out of the validated peer chain.
  pub(crate) fn end_entity_der(&self) -> CertificateDer<'static> {
    CertificateDer::from(self.cert.der().to_vec())
  }

  /// The private key for the leaf certificate.
  pub(crate) fn key(&self) -> PrivateKeyDer<'static> {
    PrivateKeyDer::try_from(self.leaf_key.serialize_der())
      .expect("leaf key serialises as a valid private key DER")
  }
}

/// Construct a fresh self-signed cluster CA for tests.
#[cfg(test)]
pub(crate) fn test_ca() -> TestClusterCa {
  let mut params = rcgen::CertificateParams::new(vec![]).expect("empty SAN for CA is valid");
  params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
  params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
  params
    .key_usages
    .push(rcgen::KeyUsagePurpose::DigitalSignature);
  let ca_key = rcgen::KeyPair::generate().expect("CA key pair generation succeeds");
  let ca_cert = params
    .self_signed(&ca_key)
    .expect("self-signed CA cert generation succeeds");
  let issuer = rcgen::Issuer::new(params, ca_key);
  TestClusterCa { ca_cert, issuer }
}

#[cfg(test)]
mod tests {
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
}

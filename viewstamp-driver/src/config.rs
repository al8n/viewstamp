//! Embedder-tunable driver configuration, shared by both drivers.

use std::time::Duration;

use crate::session::{EVENTS_CAP, MAX_INFLIGHT, MAX_PENDING_BYTES, REQUEST_TIMEOUT};

/// Default first redial delay once a peer link is observed lost — the base of the per-peer
/// exponential backoff; doubles per consecutive loss up to [`REDIAL_BACKOFF_CAP`] and resets to
/// this base when the link validates/binds. Shared by both drivers.
pub const REDIAL_BACKOFF_BASE: Duration = Duration::from_millis(200);

/// Default redial backoff ceiling: a dead peer is probed at most this often, so an unreachable or
/// RST-fast replica is never hammered at the base cadence (the per-redial jitter decorrelates
/// dialers after a common-mode loss). Retries continue forever at this bounded cadence — correct
/// for consensus, where a configured peer may always return. Shared by both drivers.
pub const REDIAL_BACKOFF_CAP: Duration = Duration::from_secs(5);

/// Default bound on one TCP connect attempt (stream driver). A connect to a black-holed address
/// otherwise parks the dial task for the kernel's SYN-retry horizon (minutes), and the redial
/// schedule cannot probe again until the attempt resolves.
pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Default per-conn authentication window (stream driver): how long a freshly-connected/accepted
/// socket may remain unvalidated before it is torn down. A peer that completes the socket connect
/// but stalls before the `Labeled`/TLS handshake validates would otherwise pin a `conns` entry (and
/// a coordinator router entry) forever. Matches the QUIC bridge's auth deadline: 5 s is far above
/// any legitimate handshake (the real mesh validates in well under a second over loopback) yet
/// bounded, so a stalled conn frees its slot in seconds.
pub const AUTH_DEADLINE: Duration = Duration::from_secs(5);

/// Default global live-connection cap (stream driver; dialed + accepted). On ACCEPT past this bound
/// the socket is dropped (closed) without registering, so a peer that floods sockets cannot grow
/// `conns` + the coordinator router without bound. 1024 is generous: a full mutual-dial mesh needs
/// only ~`2*(replica_count-1)` steady connections (e.g. 126 for the 64-replica voting cap), so this
/// never refuses a legitimate peer while still bounding an accept flood.
pub(crate) const MAX_CONNS: usize = 1024;

/// Tunable operational parameters for both drivers (the QUIC driver and the stream driver), with
/// `Default` = the constants the drivers pin without an override (each default constant carries
/// the sizing rationale). Pass a non-default config through the drivers' `with_config`
/// constructors; the plain `new` constructors use the defaults.
///
/// Three knobs apply to the STREAM driver only — [`Self::dial_timeout`], [`Self::auth_deadline`],
/// and [`Self::max_conns`]: the QUIC transport owns the equivalent bounds inside
/// `viewstamp-proto` (its auth deadline and its membership-sized connection cap), so the QUIC
/// driver ignores them.
///
/// **What stays FIXED (deliberately not knobs).** Wire-contract and derived values are not
/// configurable, so two replicas can never be configured into disagreeing about the protocol:
/// the frame cap (`MAX_FRAME_LEN`) and hello cap (`MAX_HELLO_LEN`) are the wire contract both
/// ends must share; the per-pass read budget (`STAGE_CHUNK`) is a proto-internal pacing bound;
/// the command-channel capacity is DERIVED ([`Self::cmd_cap`] = `max_inflight + 1`) so the budget,
/// not the queue, is always the binding submit limit; and the QUIC per-peer connection limit and
/// mesh connection floor are membership-derived inside the proto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverConfig {
  /// First redial delay after a loss; doubles up to [`Self::redial_backoff_cap`].
  redial_backoff_base: Duration,
  /// Redial backoff ceiling.
  redial_backoff_cap: Duration,
  /// Bound on one TCP connect attempt (stream driver only).
  dial_timeout: Duration,
  /// Per-conn unvalidated-handshake window before the reap (stream driver only).
  auth_deadline: Duration,
  /// How long a submitted-but-uncommitted request waits before re-broadcast.
  request_timeout: Duration,
  /// Count cap on submitted-but-unresolved requests (the in-flight submit budget).
  max_inflight: usize,
  /// Byte cap across all in-flight request bodies (the budget's second axis).
  max_pending_bytes: usize,
  /// Capacity of the best-effort committed-events channel (dropped-on-full).
  events_cap: usize,
  /// Global live-connection cap (stream driver only).
  max_conns: usize,
}

impl DriverConfig {
  /// The default configuration — exactly the constants the drivers pin without an override.
  #[must_use]
  pub const fn new() -> Self {
    Self {
      redial_backoff_base: REDIAL_BACKOFF_BASE,
      redial_backoff_cap: REDIAL_BACKOFF_CAP,
      dial_timeout: DIAL_TIMEOUT,
      auth_deadline: AUTH_DEADLINE,
      request_timeout: REQUEST_TIMEOUT,
      max_inflight: MAX_INFLIGHT,
      max_pending_bytes: MAX_PENDING_BYTES,
      events_cap: EVENTS_CAP,
      max_conns: MAX_CONNS,
    }
  }

  /// First redial delay once a peer link is observed lost (the `REDIAL_BACKOFF_BASE` default).
  #[inline(always)]
  pub const fn redial_backoff_base(&self) -> Duration {
    self.redial_backoff_base
  }

  /// Redial backoff ceiling (the `REDIAL_BACKOFF_CAP` default).
  #[inline(always)]
  pub const fn redial_backoff_cap(&self) -> Duration {
    self.redial_backoff_cap
  }

  /// Bound on one TCP connect attempt — stream driver only (the `DIAL_TIMEOUT` default).
  #[inline(always)]
  pub const fn dial_timeout(&self) -> Duration {
    self.dial_timeout
  }

  /// Per-conn unvalidated-handshake window — stream driver only (the `AUTH_DEADLINE` default).
  #[inline(always)]
  pub const fn auth_deadline(&self) -> Duration {
    self.auth_deadline
  }

  /// How long a submitted-but-uncommitted request waits before the driver re-broadcasts it (the
  /// proto session table dedups; the `REQUEST_TIMEOUT` default's doc carries the rationale).
  #[inline(always)]
  pub const fn request_timeout(&self) -> Duration {
    self.request_timeout
  }

  /// Count cap on submitted-but-unresolved requests; a submit past it returns
  /// [`crate::DriverError::Busy`].
  #[inline(always)]
  pub const fn max_inflight(&self) -> usize {
    self.max_inflight
  }

  /// Byte cap across all in-flight request bodies; a submit past it returns
  /// [`crate::DriverError::Busy`].
  #[inline(always)]
  pub const fn max_pending_bytes(&self) -> usize {
    self.max_pending_bytes
  }

  /// Capacity of the bounded best-effort committed-events channel (dropped-on-full; reliable
  /// per-submit replies are unaffected).
  #[inline(always)]
  pub const fn events_cap(&self) -> usize {
    self.events_cap
  }

  /// Global live-connection cap — stream driver only (the `MAX_CONNS` default).
  #[inline(always)]
  pub const fn max_conns(&self) -> usize {
    self.max_conns
  }

  /// Capacity of the bounded command channel, DERIVED as `max_inflight + 1` (not a knob): at least
  /// `max_inflight` so the submit budget — not this queue — is the binding limit on concurrent
  /// submits (every reservation the budget admits has a queue slot), and the `+ 1` leaves room for
  /// a `Shutdown` to enqueue alongside a full submit backlog.
  ///
  /// This is the futures-mpsc BUFFER size; the channel actually admits `cmd_cap` plus one
  /// in-flight command per live sender (each sender owns a guaranteed slot on top of the shared
  /// buffer). That slack never weakens the submit bound — a `Submit` cannot exist without a budget
  /// reservation acquired BEFORE it is sent, so at most `max_inflight` of them are alive anywhere
  /// (queued or pending) regardless of channel slack — and it is what lets a `Shutdown` (sent on a
  /// fresh sender clone) always enqueue immediately.
  #[inline(always)]
  pub const fn cmd_cap(&self) -> usize {
    self.max_inflight + 1
  }

  /// Override the redial backoff base (the first post-loss redial delay).
  #[must_use]
  pub const fn with_redial_backoff_base(mut self, base: Duration) -> Self {
    self.redial_backoff_base = base;
    self
  }

  /// Override the redial backoff ceiling (the slowest a dead peer is probed).
  #[must_use]
  pub const fn with_redial_backoff_cap(mut self, cap: Duration) -> Self {
    self.redial_backoff_cap = cap;
    self
  }

  /// Override the TCP connect-attempt bound (stream driver only).
  #[must_use]
  pub const fn with_dial_timeout(mut self, timeout: Duration) -> Self {
    self.dial_timeout = timeout;
    self
  }

  /// Override the per-conn authentication window (stream driver only). Keep it comfortably above a
  /// legitimate handshake on the deployed links, or healthy slow connections are reaped.
  #[must_use]
  pub const fn with_auth_deadline(mut self, deadline: Duration) -> Self {
    self.auth_deadline = deadline;
    self
  }

  /// Override the request retransmit timeout. Geo-replicated clusters (commit latency near or above
  /// the 250 ms default) raise it so steady-state submits are not re-broadcast spuriously.
  #[must_use]
  pub const fn with_request_timeout(mut self, timeout: Duration) -> Self {
    self.request_timeout = timeout;
    self
  }

  /// Override the in-flight submit count cap (clamped to at least 1 so a submit is always
  /// admissible on an empty session).
  #[must_use]
  pub const fn with_max_inflight(mut self, max: usize) -> Self {
    self.max_inflight = if max == 0 { 1 } else { max };
    self
  }

  /// Override the in-flight submit byte cap (clamped to at least 1). Keep it at or above
  /// [`viewstamp_proto::max_request_body_len`] or a lone maximal request is refused `Busy` forever.
  #[must_use]
  pub const fn with_max_pending_bytes(mut self, max: usize) -> Self {
    self.max_pending_bytes = if max == 0 { 1 } else { max };
    self
  }

  /// Override the committed-events channel capacity (clamped to at least 1).
  #[must_use]
  pub const fn with_events_cap(mut self, cap: usize) -> Self {
    self.events_cap = if cap == 0 { 1 } else { cap };
    self
  }

  /// Override the global live-connection cap (stream driver only; clamped to at least 1). Size it
  /// above `2*(replica_count-1)` plus reconnect headroom or the mesh itself is refused.
  #[must_use]
  pub const fn with_max_conns(mut self, max: usize) -> Self {
    self.max_conns = if max == 0 { 1 } else { max };
    self
  }
}

impl Default for DriverConfig {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
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
  }
}

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
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Default per-conn authentication window (stream driver): how long a freshly-connected/accepted
/// socket may remain unvalidated before it is torn down. A peer that completes the socket connect
/// but stalls before the `Labeled`/TLS handshake validates would otherwise pin a `conns` entry (and
/// a coordinator router entry) forever. Matches the QUIC bridge's auth deadline: 5 s is far above
/// any legitimate handshake (the real mesh validates in well under a second over loopback) yet
/// bounded, so a stalled conn frees its slot in seconds.
pub const AUTH_DEADLINE: Duration = Duration::from_secs(5);

/// Default global live-connection cap (stream driver; dialed + accepted). On ACCEPT past this bound
/// the socket is dropped (closed) without registering, so a peer that floods sockets cannot grow
/// `conns` + the coordinator router without bound. 1024 is generous: a full mutual-dial mesh over the
/// configured membership needs only ~`2*(node_count-1)` steady connections (126 for a 64-member
/// cluster), so this never refuses a legitimate peer while still bounding an accept flood.
pub const MAX_CONNS: usize = 1024;

/// Default cadence at which the reconfiguration executor RE-SOLICITS the voter-liveness-probe round
/// while a shrink job is in flight: every `HEALTH_PROBE_INTERVAL` the driver re-sends the outstanding
/// round, RETRANSMITTING its nonce so a reply lost in flight (or one that takes longer than a single
/// interval) is re-requested without discarding the answers already collected. The round itself lives
/// `HEALTH_PROOF_MAX_AGE`, not one interval — a fresh nonce is drawn only once the round expires — so
/// this cadence must stay STRICTLY BELOW `HEALTH_PROOF_MAX_AGE` (the drivers reject a config that
/// violates that). 250 ms sits comfortably above the 50 ms driver loop cadence yet retransmits many
/// times within each round. Probe traffic exists ONLY while a shrink job is active.
pub const HEALTH_PROBE_INTERVAL: Duration = Duration::from_millis(250);

/// Default lifetime of a voter-liveness-probe round — the single bound governing both when the probe
/// nonce is superseded and how long its evidence is trusted. `solicit_health_proofs` retransmits the
/// same nonce until the round reaches this age, then draws a fresh one; `proven_live_voters` fails
/// closed (returns empty) once the outstanding round is older than `HEALTH_PROOF_MAX_AGE`, so a driver
/// that stopped refreshing cannot keep a crashed voter counted. It is therefore the ANSWER window: a
/// live voter's reply must round-trip within it to be recorded. 1 s must exceed `HEALTH_PROBE_INTERVAL`
/// by a healthy round-trip (so a live voter answers well inside the round) yet stay well under
/// `RECONFIGURE_TIMEOUT`, so a genuinely dead successor quorum stalls the shrink fail-closed rather than
/// lingering on stale evidence.
pub const HEALTH_PROOF_MAX_AGE: Duration = Duration::from_secs(1);

/// Default deadline for one `reconfigure_to` call: once this much wall-clock elapses without the plan
/// converging, the executor's cap fires and the call resolves
/// [`ReconfigureError::Timeout`](crate::ReconfigureError::Timeout) carrying the durable partial
/// progress (resumable by re-issuing the same target). Sized at `30 * REQUEST_TIMEOUT` (7.5 s at the
/// default 250 ms): a single change is multiple consensus round-trips — a learner promote also waits
/// out a catch-up-then-promote proof round-trip — and a multi-step plan sequences several of those, so
/// the band must clear many round-trips on a healthy cluster while still bounding a genuine stall (a
/// fail-closed shrink with no live witness, or a learner that never catches up). Raise it for
/// geo-replicated clusters or long learner catch-ups; the operator's `HealthHint` is the faster lever
/// for an intentional shrink.
pub const RECONFIGURE_TIMEOUT: Duration = Duration::from_millis(30 * 250);

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
  /// Cadence at which the reconfiguration executor re-solicits the voter-liveness-probe round while a
  /// shrink job is in flight (retransmits the round's nonce; a fresh round opens only at expiry). Must
  /// be strictly below `health_proof_max_age` — the drivers reject a config that violates it.
  health_probe_interval: Duration,
  /// Lifetime of a voter-liveness-probe round: how long its nonce is retransmitted before a fresh one
  /// is drawn AND how long `proven_live_voters` trusts its evidence (the two are one bound), so a stale
  /// round cannot keep a crashed voter counted.
  health_proof_max_age: Duration,
  /// Deadline for one `reconfigure_to` call before its cap fires and it resolves
  /// [`ReconfigureError::Timeout`](crate::ReconfigureError::Timeout). The driver arms the deadline
  /// `reconfigure_timeout` ahead of the job's first advance and feeds `now >= deadline` to the
  /// executor as its `cap_exhausted` signal.
  reconfigure_timeout: Duration,
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
      health_probe_interval: HEALTH_PROBE_INTERVAL,
      health_proof_max_age: HEALTH_PROOF_MAX_AGE,
      reconfigure_timeout: RECONFIGURE_TIMEOUT,
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

  /// Voter-liveness-probe re-solicit cadence for the reconfiguration executor (the
  /// `HEALTH_PROBE_INTERVAL` default). While a shrink job is in flight the driver retransmits the
  /// outstanding probe round this often; a fresh round opens only when the current one expires.
  #[inline(always)]
  pub const fn health_probe_interval(&self) -> Duration {
    self.health_probe_interval
  }

  /// Lifetime of a voter-liveness-probe round for the reconfiguration executor (the
  /// `HEALTH_PROOF_MAX_AGE` default): how long the round's nonce is retransmitted, and equally how long
  /// `proven_live_voters` trusts its evidence before failing closed.
  #[inline(always)]
  pub const fn health_proof_max_age(&self) -> Duration {
    self.health_proof_max_age
  }

  /// Deadline for one `reconfigure_to` call (the `RECONFIGURE_TIMEOUT` default). The driver arms it
  /// `reconfigure_timeout` ahead of the job's first advance; on expiry the executor's cap fires and
  /// the call resolves [`ReconfigureError::Timeout`](crate::ReconfigureError::Timeout) with the
  /// durable partial progress.
  #[inline(always)]
  pub const fn reconfigure_timeout(&self) -> Duration {
    self.reconfigure_timeout
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
    self.set_redial_backoff_base(base);
    self
  }

  /// In-place form of [`Self::with_redial_backoff_base`] — same semantics, chainable.
  pub const fn set_redial_backoff_base(&mut self, base: Duration) -> &mut Self {
    self.redial_backoff_base = base;
    self
  }

  /// Override the redial backoff ceiling (the slowest a dead peer is probed).
  #[must_use]
  pub const fn with_redial_backoff_cap(mut self, cap: Duration) -> Self {
    self.set_redial_backoff_cap(cap);
    self
  }

  /// In-place form of [`Self::with_redial_backoff_cap`] — same semantics, chainable.
  pub const fn set_redial_backoff_cap(&mut self, cap: Duration) -> &mut Self {
    self.redial_backoff_cap = cap;
    self
  }

  /// Override the TCP connect-attempt bound (stream driver only).
  #[must_use]
  pub const fn with_dial_timeout(mut self, timeout: Duration) -> Self {
    self.set_dial_timeout(timeout);
    self
  }

  /// In-place form of [`Self::with_dial_timeout`] — same semantics, chainable.
  pub const fn set_dial_timeout(&mut self, timeout: Duration) -> &mut Self {
    self.dial_timeout = timeout;
    self
  }

  /// Override the per-conn authentication window (stream driver only). Keep it comfortably above a
  /// legitimate handshake on the deployed links, or healthy slow connections are reaped.
  #[must_use]
  pub const fn with_auth_deadline(mut self, deadline: Duration) -> Self {
    self.set_auth_deadline(deadline);
    self
  }

  /// In-place form of [`Self::with_auth_deadline`] — same semantics, chainable.
  pub const fn set_auth_deadline(&mut self, deadline: Duration) -> &mut Self {
    self.auth_deadline = deadline;
    self
  }

  /// Override the request retransmit timeout. Geo-replicated clusters (commit latency near or above
  /// the 250 ms default) raise it so steady-state submits are not re-broadcast spuriously.
  #[must_use]
  pub const fn with_request_timeout(mut self, timeout: Duration) -> Self {
    self.set_request_timeout(timeout);
    self
  }

  /// In-place form of [`Self::with_request_timeout`] — same semantics, chainable.
  pub const fn set_request_timeout(&mut self, timeout: Duration) -> &mut Self {
    self.request_timeout = timeout;
    self
  }

  /// Override the in-flight submit count cap (clamped to at least 1 so a submit is always
  /// admissible on an empty session).
  #[must_use]
  pub const fn with_max_inflight(mut self, max: usize) -> Self {
    self.set_max_inflight(max);
    self
  }

  /// In-place form of [`Self::with_max_inflight`] — same semantics, chainable.
  pub const fn set_max_inflight(&mut self, max: usize) -> &mut Self {
    self.max_inflight = if max == 0 { 1 } else { max };
    self
  }

  /// Override the in-flight submit byte cap (clamped to at least 1). Keep it at or above
  /// [`viewstamp_proto::max_request_body_len`] or a lone maximal request is refused `Busy` forever.
  #[must_use]
  pub const fn with_max_pending_bytes(mut self, max: usize) -> Self {
    self.set_max_pending_bytes(max);
    self
  }

  /// In-place form of [`Self::with_max_pending_bytes`] — same semantics, chainable.
  pub const fn set_max_pending_bytes(&mut self, max: usize) -> &mut Self {
    self.max_pending_bytes = if max == 0 { 1 } else { max };
    self
  }

  /// Override the committed-events channel capacity (clamped to at least 1).
  #[must_use]
  pub const fn with_events_cap(mut self, cap: usize) -> Self {
    self.set_events_cap(cap);
    self
  }

  /// In-place form of [`Self::with_events_cap`] — same semantics, chainable.
  pub const fn set_events_cap(&mut self, cap: usize) -> &mut Self {
    self.events_cap = if cap == 0 { 1 } else { cap };
    self
  }

  /// Override the global live-connection cap (stream driver only; clamped to at least 1). Size it
  /// above `2*(node_count-1)` plus reconnect headroom or the mesh itself is refused.
  #[must_use]
  pub const fn with_max_conns(mut self, max: usize) -> Self {
    self.set_max_conns(max);
    self
  }

  /// In-place form of [`Self::with_max_conns`] — same semantics, chainable.
  pub const fn set_max_conns(&mut self, max: usize) -> &mut Self {
    self.max_conns = if max == 0 { 1 } else { max };
    self
  }

  /// Override the voter-liveness-probe re-solicit cadence. Keep it at or above the driver loop cadence
  /// (50 ms) and STRICTLY BELOW `health_proof_max_age` (the round lifetime it retransmits within) — the
  /// drivers reject a config where the cadence is not below the round lifetime.
  #[must_use]
  pub const fn with_health_probe_interval(mut self, interval: Duration) -> Self {
    self.set_health_probe_interval(interval);
    self
  }

  /// In-place form of [`Self::with_health_probe_interval`] — same semantics, chainable.
  pub const fn set_health_probe_interval(&mut self, interval: Duration) -> &mut Self {
    self.health_probe_interval = interval;
    self
  }

  /// Override the voter-liveness-probe round lifetime (its combined retransmit-and-evidence window).
  /// Keep it above `health_probe_interval` plus a healthy round-trip (so a live voter's answer lands
  /// within the round) yet under `reconfigure_timeout` (so a dead successor quorum stalls fail-closed).
  /// The drivers reject a config where it is not strictly above `health_probe_interval`.
  #[must_use]
  pub const fn with_health_proof_max_age(mut self, max_age: Duration) -> Self {
    self.set_health_proof_max_age(max_age);
    self
  }

  /// In-place form of [`Self::with_health_proof_max_age`] — same semantics, chainable.
  pub const fn set_health_proof_max_age(&mut self, max_age: Duration) -> &mut Self {
    self.health_proof_max_age = max_age;
    self
  }

  /// Override the `reconfigure_to` deadline. Raise it for geo-replicated clusters or long learner
  /// catch-ups (so a healthy-but-slow change is not cut short with `Timeout`); lower it to fail-fast
  /// an intentionally-fail-closed change (e.g. a shrink with no live witness) sooner.
  #[must_use]
  pub const fn with_reconfigure_timeout(mut self, timeout: Duration) -> Self {
    self.set_reconfigure_timeout(timeout);
    self
  }

  /// In-place form of [`Self::with_reconfigure_timeout`] — same semantics, chainable.
  pub const fn set_reconfigure_timeout(&mut self, timeout: Duration) -> &mut Self {
    self.reconfigure_timeout = timeout;
    self
  }
}

impl Default for DriverConfig {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests;

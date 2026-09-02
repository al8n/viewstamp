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
//! - `stream_receive_window` = 1 MiB: the maximum this transport accepts, sized against
//!   `quinn-proto`'s stream reassembly ceiling for a PACKET-FILLING sender of contiguous
//!   new data — the shape a backlog produces. Other segmentation (sub-packet writes, frames
//!   behind a gap) is excluded from that sizing and can reach the ceiling inside this
//!   window; [`MAX_STREAM_RECEIVE_WINDOW`] states the predicate and what follows. A frame
//!   larger than the window still flows, across the window updates its reader produces as
//!   it drains.
//! - `receive_window` (connection-level) = 17 MiB, clear of the 8 MiB the connection's
//!   streams can hold unread together, so stream-level flow control is what throttles a
//!   slow reader and one class can never starve the other of connection window.
//!
//! Use [`ClusterTls`] to build a `QuicOptions` with mandatory mutual TLS over
//! cluster-private roots: the stock WebPki verifiers perform chain-only
//! validation against the cluster CA, so a peer without a valid cert is
//! rejected at the TLS handshake before any stream opens. A geo-replicated or
//! otherwise non-default deployment overrides the timer/window values via
//! [`ClusterTls::with_tuning`]; the security-relevant construction (roots, mTLS,
//! TLS 1.3, ALPN) is not tunable.

use core::time::Duration;

use std::sync::Arc;

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

/// The QUIC ALPN protocol id every TLS config this module builds negotiates:
/// `viewstamp/<wire version>`, where the version is
/// [`labeled::wire_version`](crate::transport::labeled::wire_version) — the SAME wire-version fence
/// the stream `Labeled` hello and the QUIC `Hello` control-stream preface check.
///
/// A hello (or its QUIC-preface equivalent) is a PREFACE some identity modes send and others don't:
/// the `CertOid` identity mode authenticates purely from the certificate and sends NO preface at
/// all, so without this it would reach `Validated` against a differently-versioned `CertOid` peer
/// (same ALPN, same cert format) without either side ever comparing wire versions — then silently
/// mis-decode or drop the other's consensus frames. Carrying the version in the ALPN instead fences
/// it at TLS's OWN negotiation step, before any QUIC stream even opens, so EVERY identity mode
/// (`Hello`, `CertOid`, and any `dangerous_custom_identity`) is version-fenced identically: a
/// mismatched-version peer fails ALPN negotiation and the connection never completes its handshake.
///
/// Both [`ClusterTls::build`] (production, mandatory mTLS) and the test-only
/// [`QuicOptions::accept_any_with_layout`] set their client AND server `alpn_protocols` from this
/// ONE helper, so they can never drift apart from each other or from the hello's `HELLO_VERSION`.
fn alpn_protocols() -> Vec<Vec<u8>> {
  vec![format!("viewstamp/{}", crate::transport::labeled::wire_version()).into_bytes()]
}

/// Default idle timeout.  Must exceed the 200 ms consensus primary-idle.
///
/// On its own an idle timeout is fatal to the mesh: steady-state consensus traffic is
/// primary→backups only (heartbeats), so the backup↔backup connections carry NOTHING between view
/// changes and would idle out this long after the last one — leaving the NEXT view change (the
/// primary just died) with no live backup↔backup links for `StartViewChange`/`DoViewChange`.
/// `keep_alive_interval_millis` is what keeps those zero-traffic edges alive under this timeout.
pub const DEFAULT_IDLE_TIMEOUT_MILLIS: u64 = 1_000;

/// Keep-alive PING interval derived from the idle timeout: one third, so up to two consecutive
/// lost keep-alives still refresh the peer's idle timer in time.  quinn's default is NO keep-alive,
/// under which a healthy-but-quiet connection idles out — and the backup↔backup mesh edges are
/// exactly that between view changes (see [`DEFAULT_IDLE_TIMEOUT_MILLIS`]).  A zero result (an idle timeout
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
pub const DEFAULT_INITIAL_RTT_MILLIS: u64 = 50;

/// Pinned max concurrent bidi streams.  Each side opens up to 2 send streams
/// under `ControlBulk` (Control + Bulk); 8 gives cluster-mesh headroom for the
/// mutual-dial doubling where both peers open streams concurrently.
pub(crate) const MAX_BIDI_STREAMS: u32 = 8;

/// Connection-level receive window.  Stream-level flow control is the binding constraint: each recv
/// stream holds at most [`MAX_STREAM_RECEIVE_WINDOW`] unread, and a connection carries at most 8 of
/// them (the pinned concurrent-bidi-stream limit), so 17 MiB stays clear of the 8 MiB those streams
/// can hold unread together.  Connection credit therefore never runs out before stream credit does,
/// and one class stalling its reader cannot starve the other of connection window.
pub const DEFAULT_CONNECTION_RECEIVE_WINDOW: u64 = 17 * 1024 * 1024;

/// Number of distinct unread spans `quinn-proto` keeps per recv stream before it refuses more
/// (`MAX_CHUNKS` in its stream reassembler).  A refused insert closes the whole connection with an
/// internal transport error, so this is a ceiling on the SPAN COUNT of an unread backlog — not on
/// its bytes.
///
/// Restated here because `quinn-proto` does not export it. The value is the 0.11 series', read from
/// `connection/assembler.rs`; nothing holds a release to it, so the guarantee comes from the tests
/// instead — a release that moves the bound fails
/// `a_full_stream_window_of_unread_packets_stays_within_the_reassembly_bound`, and one that changes
/// the segmentation this sizing assumes fails the receiver-side span regression.
///
/// The compaction that runs before the refusal merges only POORLY UTILIZED spans — ones whose
/// payload is under 5/6 of the packet they arrived in (in quinn-proto 0.11.17, the version this was
/// verified against) — so spans from a peer that fills its packets survive it, and a backlog already
/// at the ceiling cannot be compacted back under it.  The sizing below therefore holds at this
/// count, not at the higher one that merely triggers a compaction.
pub(crate) const QUINN_REASSEMBLY_MAX_SPANS: u64 = 1024;

/// STREAM-frame payload assumed for a peer that fills its packets, in bytes.  QUIC guarantees a
/// 1200-byte path, which leaves ~1160 bytes for frames once the short header, the packet number and
/// the AEAD tag are paid for; 1024 rounds that down for margin.
pub(crate) const MIN_FILLED_STREAM_FRAME_PAYLOAD: u64 = 1024;

/// Largest per-stream receive window this transport accepts.
///
/// **What the window bounds.** Stream flow control bounds OFFSETS: a peer may not send past
/// `bytes_read + stream_receive_window`, so at most that many bytes sit unread in the reassembler.
/// It does not bound how many spans those bytes arrive as — that is the sender's segmentation
/// choice, and it is what the reassembler's ceiling counts.
///
/// **What this sizing covers.** For a peer that fills its packets, span count is bytes over packet
/// payload, and the window is sized so that stays inside the ceiling:
///
/// ```text
/// MAX_STREAM_RECEIVE_WINDOW / MIN_FILLED_STREAM_FRAME_PAYLOAD <= QUINN_REASSEMBLY_MAX_SPANS
///           1 MiB           /              1024 B             =            1024
/// ```
///
/// That covers the case a bulk transfer actually produces — a sender with a backlog fills every
/// packet — and it is why a window above this must be refused: at 8 MiB the same filled-packet
/// backlog is ~6000 spans and a large transfer dies partway rather than being throttled.
///
/// **What it does NOT cover.** Span count is not a function of bytes. A peer that trickles
/// sub-packet writes, or leaves gaps that compaction cannot merge, reaches the ceiling inside any
/// window worth having: ~2050 writes of a few hundred bytes each, or ~20 KB of gapped one-byte
/// frames, exceed it. No window setting prevents that, so this is a sizing for the supported
/// sender, NOT a guarantee over all legal STREAM segmentation.
///
/// **Supported sender.** This transport's own bridge stages a class's frames in one buffer and
/// writes that whole buffer to quinn in a single call, and the coordinator defers PACKETIZING to one
/// service pass rather than running one per message. So per packetizing pass a class emits
/// packet-filling frames plus at most one short tail — one sub-packet span, however many messages
/// went into it. It is NOT one per coordinator entry: an entry can packetize more than once (the
/// read pass services to release flow-control credit, the pump services at the end), which makes the
/// per-entry count a small constant rather than one.
///
/// Nothing bounds how many such spans ACCUMULATE at a peer. That is the ratio between the sender's
/// pump rate and the receiver's: the receiver drains a 64 KiB budget per pump and re-arms itself
/// while bytes remain, far outpacing a sub-packet sender.
///
/// **Reachability, stated once.** The reassembler — as of quinn-proto 0.11.17, the version this was
/// verified against — compacts when EITHER its raw heap length
/// exceeds 2048 spans OR its over-allocation (allocated bytes minus buffered) exceeds
/// `max(32 KiB, 1.5 x buffered)`, and it refuses the insert only when more than 1024 spans SURVIVE
/// that compaction. Compaction merges only poorly utilized spans, so what survives is whatever
/// cannot merge: spans separated by a gap, and spans already well utilized.
///
/// Sufficient scenarios, none of them necessary on its own:
///
/// - ONE gap, many small frames. A lost packet stops the ordered reader and every small-frame packet
///   arriving before the retransmit fills that gap lands as its own unmergeable span. The count
///   reached is the small-frame packets in flight across that interval — roughly
///   `send rate x (RTT + loss-detection delay)`.
/// - MANY gaps. Poorly utilized spans survive compaction too when a gap separates them, so a pattern
///   of alternating loss reaches the count on far fewer bytes than the single-gap case, and can trip
///   the over-allocation trigger rather than the length one.
/// - Repeated loss. Gaps that are re-created faster than they are filled hold spans across several
///   detection intervals, so the count accumulates instead of resetting each time.
///
/// On a loopback path the first is a handful of packets, measured, because the interval is
/// microseconds; on a high-RTT path carrying a high small-frame rate it is plausible. "Not reached"
/// is a measurement of the paths tested, not a property of the transport.
///
/// **When a peer exceeds it — the claim, exactly.** Recovery is the transport's PRE-EXISTING
/// connection-lost path, not new machinery: quinn closes the connection, the bridge classifies the
/// loss, unbinds the peer's routing and queues it for reaping, the driver's link reconcile redials on
/// a jittered backoff, and consensus retransmission re-drives what was in flight.
///
/// That path is proved at COMPONENT level, and the claim is no wider than that evidence:
///
/// - `quic::loopback::a_modelled_receiver_stall_at_the_reassembly_ceiling_recovers_and_completes_its_operation`
///   drives the refusal and the recovery over real mTLS with real consensus traffic. THREE seams are
///   MODELLED there — the stall that reaches the refusal, the redial schedule, and the client's
///   stale-request rebroadcast (the driver's pending map and `retransmit_stale` do not run in it);
///   the reaping, the re-establishment and the request's completion are real.
/// - `viewstamp-compio`'s `the_link_reconcile_arms_then_redials_an_unbound_peer_on_a_doubling_backoff`
///   proves the redial schedule itself on the real reconcile.
///
/// There is NO end-to-end real-driver test of the refusal, because the refusal was not reached
/// through `handle_udp` on the paths tested — that entrypoint feeds quinn and drains it in the same
/// call. `viewstamp-compio`'s `a_lossy_real_link_keeps_the_cluster_committing_and_recovers` drives
/// real drivers under real relayed packet loss and is loss-tolerance evidence, not evidence for this
/// claim.
///
/// Frame size is not bounded by any of this: a frame spans as many window grants as it needs, so the
/// transport's frame ceiling ([`MAX_FRAME_LEN`](crate::transport::frame::MAX_FRAME_LEN), 16 MiB) is
/// unchanged.
///
/// **Compatibility with `quinn-proto`.** The bridge's reassembly sizing and its unsolicited-half
/// classifier were verified against `quinn-proto` 0.11.17, and both rest on behaviour that crate keeps
/// private: the per-stream span ceiling the window is sized against, the compaction rule that merges
/// only spans under 5/6 utilization, `Readable` being raised for a frame that arrived, and a reset
/// clearing the assembler before the application drains the event. The dependency is a plain `0.11`
/// range, so a newer patch release resolves without ceremony — this repository's own CI resolves fresh
/// and runs the whole QUIC suite against whatever it picks.
///
/// An embedder who pins or upgrades `quinn-proto` themselves does not get that for free. The
/// compatibility check is this crate's QUIC suite (`cargo test -p viewstamp-proto --features
/// quic,tcp,tls,tls-rustls-ring`). Running only part of it, these are the five that fail when the
/// private behaviour moves — two for the SIZING, three for the CLASSIFIER:
///
/// - `a_full_stream_window_of_unread_packets_stays_within_the_reassembly_bound` — the span ceiling;
/// - `a_class_batch_leaves_as_one_sub_packet_span_per_packetizing_pass` — the segmentation the sizing
///   assumes, counted from the receiver's own STREAM-frame counter;
/// - `sub_packet_writes_into_our_opened_streams_recv_half_close_the_connection` and
/// - `gapped_writes_into_our_opened_streams_recv_half_close_the_connection` — `Readable` being raised
///   for a frame that arrived, at the read offset and ahead of a gap;
/// - `data_whose_reset_lands_in_the_same_batch_leaves_the_connection_open` — a reset clearing the
///   assembler before the event is drained.
pub const MAX_STREAM_RECEIVE_WINDOW: u64 =
  QUINN_REASSEMBLY_MAX_SPANS * MIN_FILLED_STREAM_FRAME_PAYLOAD;

/// Per-stream receive window: the maximum this transport accepts
/// ([`MAX_STREAM_RECEIVE_WINDOW`]), sized for a PACKET-FILLING sender of contiguous new data. For
/// that shape — the one a backlog produces — a stalled reader throttles its peer rather than
/// stranding the connection, and a frame larger than the window still flows across the window
/// updates its reader's drain produces. It is NOT a promise over all segmentation: sub-packet or
/// gapped frames reach the reassembler's span ceiling inside this window and close the connection,
/// which then recovers through the path [`MAX_STREAM_RECEIVE_WINDOW`] documents.
pub const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = MAX_STREAM_RECEIVE_WINDOW;

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

/// A per-stream receive window above [`MAX_STREAM_RECEIVE_WINDOW`] was requested.
///
/// Returned rather than clamped: the other tuning values are performance knobs where the nearest
/// legal value is the obvious intent, but this one changes which failure mode a slow reader gets —
/// an over-sized window lets a filled-packet backlog outgrow the reassembler and close the
/// connection instead of throttling the peer. An embedder asking for more bandwidth-delay product
/// than the transport can carry should see that, not a silently different configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("stream receive window {requested} B exceeds the maximum {max} B")]
pub struct StreamWindowTooLarge {
  requested: u64,
  max: u64,
}

impl StreamWindowTooLarge {
  /// The window that was asked for, in bytes.
  #[must_use]
  pub const fn requested(&self) -> u64 {
    self.requested
  }

  /// The largest window the transport accepts, in bytes — [`MAX_STREAM_RECEIVE_WINDOW`].
  #[must_use]
  pub const fn max(&self) -> u64 {
    self.max
  }
}

/// Embedder-tunable timer and flow-control values for the QUIC `TransportConfig`, with `Default` =
/// the pinned LAN-tuned constants (see each field's constant for the rationale).
/// A geo-replicated cluster — where the defaults' assumptions (sub-50 ms RTT, 200 ms primary-idle
/// headroom) do not hold — overrides them via [`ClusterTls::with_tuning`].
///
/// **Scope (the security posture).** This carries ONLY performance knobs — timers and window sizes.
/// It cannot reach the security-relevant construction: the cluster-private roots, mandatory mTLS
/// (client-cert verification), TLS 1.3 pinning, and ALPN live exclusively inside
/// [`ClusterTls::build`], which accepts a `QuicTuning` but never lets it near the rustls configs.
/// No tuning value can disable or weaken authentication.
///
/// Setters clamp to `1..=2^62-1` (the QUIC `VarInt` range) so no embedder value can wedge the
/// transport with a zero timeout/window or fail the `VarInt` conversions at construction. The
/// per-stream window is the one value that is REFUSED rather than clamped above its ceiling — see
/// [`QuicTuning::try_set_stream_receive_window`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicTuning {
  /// `max_idle_timeout`, milliseconds. Default [`DEFAULT_IDLE_TIMEOUT_MILLIS`].
  idle_timeout_millis: u64,
  /// `keep_alive_interval`, milliseconds. `None` (the default) derives idle/3 — the two-lost-pings
  /// margin [`keep_alive_interval_millis`] documents; an explicit `Some(0)` disables keep-alive.
  keep_alive_interval_millis: Option<u64>,
  /// `initial_rtt`, milliseconds. Default [`DEFAULT_INITIAL_RTT_MILLIS`].
  initial_rtt_millis: u64,
  /// Connection-level `receive_window`, bytes. Default [`DEFAULT_CONNECTION_RECEIVE_WINDOW`].
  connection_receive_window: u64,
  /// Per-stream `stream_receive_window`, bytes. Default [`DEFAULT_STREAM_RECEIVE_WINDOW`].
  stream_receive_window: u64,
}

impl QuicTuning {
  /// The default tuning — exactly the constants the transport pins without an override.
  #[must_use]
  pub const fn new() -> Self {
    Self {
      idle_timeout_millis: DEFAULT_IDLE_TIMEOUT_MILLIS,
      keep_alive_interval_millis: None,
      initial_rtt_millis: DEFAULT_INITIAL_RTT_MILLIS,
      connection_receive_window: DEFAULT_CONNECTION_RECEIVE_WINDOW,
      stream_receive_window: DEFAULT_STREAM_RECEIVE_WINDOW,
    }
  }

  /// Idle timeout in milliseconds (see `DEFAULT_IDLE_TIMEOUT_MILLIS` for the consensus coupling).
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

  /// Initial RTT estimate in milliseconds (see `DEFAULT_INITIAL_RTT_MILLIS` for why the default is
  /// LAN-tuned and what a geo-replicated cluster must raise it to).
  #[inline(always)]
  pub const fn initial_rtt_millis(&self) -> u64 {
    self.initial_rtt_millis
  }

  /// Connection-level receive window in bytes (see `DEFAULT_CONNECTION_RECEIVE_WINDOW`).
  #[inline(always)]
  pub const fn connection_receive_window(&self) -> u64 {
    self.connection_receive_window
  }

  /// Per-stream receive window in bytes (see `DEFAULT_STREAM_RECEIVE_WINDOW`).
  #[inline(always)]
  pub const fn stream_receive_window(&self) -> u64 {
    self.stream_receive_window
  }

  /// Override the idle timeout (milliseconds; clamped to `1..=2^62-1`). Must stay ABOVE the
  /// consensus primary-idle, or healthy links idle out between heartbeats; with the default
  /// (derived) keep-alive the idle/3 ping interval scales along with it.
  #[must_use]
  pub const fn with_idle_timeout_millis(mut self, millis: u64) -> Self {
    self.set_idle_timeout_millis(millis);
    self
  }

  /// In-place form of [`Self::with_idle_timeout_millis`] — same clamp/semantics, chainable.
  pub const fn set_idle_timeout_millis(&mut self, millis: u64) -> &mut Self {
    self.idle_timeout_millis = clamp_tuning(millis);
    self
  }

  /// Override the keep-alive interval (milliseconds; `0` disables keep-alive). Without an override
  /// the interval is derived as idle/3. Disabling keep-alive on a production mesh is a liveness
  /// hazard: the zero-traffic backup↔backup edges then idle out between view changes (see
  /// `DEFAULT_IDLE_TIMEOUT_MILLIS`).
  #[must_use]
  pub const fn with_keep_alive_interval_millis(mut self, millis: u64) -> Self {
    self.set_keep_alive_interval_millis(millis);
    self
  }

  /// In-place form of [`Self::with_keep_alive_interval_millis`] — same clamp/semantics, chainable.
  pub const fn set_keep_alive_interval_millis(&mut self, millis: u64) -> &mut Self {
    self.keep_alive_interval_millis = Some(millis);
    self
  }

  /// Override the initial RTT estimate (milliseconds; clamped to `1..=2^62-1`). Keep it at or above
  /// the real inter-replica RTT: an estimate far below it provokes spurious handshake retransmits,
  /// while the consensus primary-idle must in turn stay above the resulting ~3×RTT initial PTO.
  #[must_use]
  pub const fn with_initial_rtt_millis(mut self, millis: u64) -> Self {
    self.set_initial_rtt_millis(millis);
    self
  }

  /// In-place form of [`Self::with_initial_rtt_millis`] — same clamp/semantics, chainable.
  pub const fn set_initial_rtt_millis(&mut self, millis: u64) -> &mut Self {
    self.initial_rtt_millis = clamp_tuning(millis);
    self
  }

  /// Override the connection-level receive window (bytes; clamped to `1..=2^62-1`). Keep it above
  /// what the connection's streams can hold unread together (the concurrent-bidi-stream limit ×
  /// [`MAX_STREAM_RECEIVE_WINDOW`]) so stream-level flow control stays the binding one and a stalled
  /// reader on one class cannot starve the other; a smaller window only throttles bulk throughput
  /// (credit regrants as the reader drains), it cannot deadlock.
  #[must_use]
  pub const fn with_connection_receive_window(mut self, bytes: u64) -> Self {
    self.set_connection_receive_window(bytes);
    self
  }

  /// In-place form of [`Self::with_connection_receive_window`] — same clamp/semantics, chainable.
  pub const fn set_connection_receive_window(&mut self, bytes: u64) -> &mut Self {
    self.connection_receive_window = clamp_tuning(bytes);
    self
  }

  /// Override the per-stream receive window, in bytes.
  ///
  /// Lowering it only throttles a stream — credit regrants as its reader drains. Raising it past
  /// [`MAX_STREAM_RECEIVE_WINDOW`] is refused with [`StreamWindowTooLarge`] rather than clamped:
  /// that ceiling is what keeps a filled-packet backlog inside the reassembly bound, and exceeding
  /// it changes a throttle into a connection close. Zero still raises to 1, like every other tuning
  /// (a zero window is a wedge, and the nearest legal value is unambiguous).
  ///
  /// # Errors
  ///
  /// [`StreamWindowTooLarge`] when `bytes` exceeds [`MAX_STREAM_RECEIVE_WINDOW`]; the tuning is
  /// left unchanged.
  pub const fn try_with_stream_receive_window(
    mut self,
    bytes: u64,
  ) -> Result<Self, StreamWindowTooLarge> {
    match self.try_set_stream_receive_window(bytes) {
      Ok(_) => Ok(self),
      Err(e) => Err(e),
    }
  }

  /// In-place form of [`Self::try_with_stream_receive_window`] — same semantics, chainable.
  ///
  /// # Errors
  ///
  /// [`StreamWindowTooLarge`] when `bytes` exceeds [`MAX_STREAM_RECEIVE_WINDOW`]; the tuning is
  /// left unchanged.
  pub const fn try_set_stream_receive_window(
    &mut self,
    bytes: u64,
  ) -> Result<&mut Self, StreamWindowTooLarge> {
    if bytes > MAX_STREAM_RECEIVE_WINDOW {
      return Err(StreamWindowTooLarge {
        requested: bytes,
        max: MAX_STREAM_RECEIVE_WINDOW,
      });
    }
    self.stream_receive_window = clamp_tuning(bytes);
    Ok(self)
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
  /// uses before the first real RTT sample; see `DEFAULT_INITIAL_RTT_MILLIS`).
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
    self.set_max_connections(max);
    self
  }

  /// In-place form of [`Self::with_max_connections`] — same zero-floor, chainable.
  pub const fn set_max_connections(&mut self, max: usize) -> &mut Self {
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
    // Connection-level window: sized above what this connection's streams can hold unread
    // together, so a Bulk stream exhausts stream_receive_window long before it can exhaust the
    // connection window and starve Control of credit.
    tc.receive_window(
      VarInt::from_u64(tuning.connection_receive_window())
        .expect("connection window within VarInt range (clamped by the tuning setter)"),
    );
    // Per-stream window: what bounds the unread backlog's BYTES, capped by the tuning setter at
    // MAX_STREAM_RECEIVE_WINDOW — the maximum this transport accepts, sized against quinn's stream
    // reassembly ceiling for a packet-filling sender of contiguous new data. Other segmentation is
    // excluded from that sizing (see MAX_STREAM_RECEIVE_WINDOW). A frame larger than the window
    // still flows, across the window updates the reader's drain produces.
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
/// Both configs are TLS 1.3-only with ALPN set to the wire-versioned protocol id `alpn_protocols`
/// builds (`viewstamp/<wire version>`), so a peer at a different wire version fails ALPN
/// negotiation at the handshake rather than connecting and mis-decoding traffic.
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

  /// Select the stream layout for the built [`QuicOptions`].  The default
  /// is `StreamLayout::ControlBulk`.
  #[must_use]
  pub fn with_layout(mut self, layout: StreamLayout) -> Self {
    self.layout = layout;
    self
  }

  /// Override the transport timer/window tuning for the built [`QuicOptions`].  The default is
  /// [`QuicTuning::new`] (the LAN-tuned constants).  Tuning carries ONLY performance knobs — the
  /// mandatory-mTLS construction this builder performs is unaffected by any tuning value (see
  /// [`QuicTuning`]'s scope note).
  #[must_use]
  pub fn with_tuning(mut self, tuning: QuicTuning) -> Self {
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
    rustls_server.alpn_protocols = alpn_protocols();
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
    rustls_client.alpn_protocols = alpn_protocols();
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
    rustls_server.alpn_protocols = alpn_protocols();
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
    rustls_client.alpn_protocols = alpn_protocols();
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
  /// viewstamp identity extension attesting the stable [`MemberId`] `MemberId::new(n)` for `cluster` —
  /// the input a [`CertOid`](super::CertOid) verifier parses. The SAN index and the attested member id
  /// coincide here (the common test fixture where `MemberId == slot`); use
  /// [`issue_replica_with_member_oid`](Self::issue_replica_with_member_oid) to attest a member id that
  /// differs from the SAN index (e.g. one beyond `u16::MAX`). The extension is added NON-critical so the
  /// stock cluster-CA WebPki verifier does not reject the chain over it (see [`CertOid`](super::CertOid)).
  pub(crate) fn issue_replica_with_oid(&self, n: u16, cluster: u128) -> TestReplicaCert {
    self.issue_replica_with_member_oid(n, crate::MemberId::new(u128::from(n)), cluster)
  }

  /// As [`issue_replica_with_oid`](Self::issue_replica_with_oid) but attests an EXPLICIT stable
  /// [`MemberId`] independent of the SAN index `san_index` — so a test can mint a cert whose attested
  /// member id is the full u128 range (including beyond `u16::MAX`), proving the cert-OID identity
  /// carries the whole `MemberId` with no slot narrowing.
  pub(crate) fn issue_replica_with_member_oid(
    &self,
    san_index: u16,
    member: crate::MemberId,
    cluster: u128,
  ) -> TestReplicaCert {
    use super::identity::{AttestedId, IDENTITY_OID, encode_identity_ext};

    let san = format!("replica-{san_index}.{cluster:032x}.viewstamp");
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
    let content = encode_identity_ext(cluster, AttestedId::Replica(member));
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
mod tests;

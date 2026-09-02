//! The `Bridge`: wraps one `quinn_proto::Endpoint`, owns the [`ConnTable`], and
//! runs the Endpoint↔Connection service pump that drives every QUIC connection
//! on this endpoint to fixpoint each tick.
//!
//! quinn-proto's polling contract requires the caller to drain ALL of a
//! connection's poll surfaces every progress step: `poll()` (application
//! events), `poll_endpoint_events()` (endpoint-facing feedback), and
//! `poll_transmit()` (outbound datagrams), plus `handle_timeout`. Omitting any
//! one stalls the connection. In particular, `poll_endpoint_events()` carries
//! `NeedIdentifiers` / `ResetToken` / `RetireConnectionId`, which must be fed
//! back through `Endpoint::handle_event`; that exchange mints the connection
//! IDs / registers the reset tokens a connection needs to keep making progress
//! under CID rotation, migration, and longer lifetimes. The negative control
//! [`service_drains_endpoint_events`] proves this drain is wired and that the
//! flag gates it: a real handshake feeds endpoint events back on both peers,
//! and disabling the drain drives that count to zero. (A *minimal* loopback
//! handshake still completes on its initial CIDs even with the drain off — see
//! that test's docs for why the counter, not handshake completion, is the
//! deterministic observable here.)
//!
//! **One-tick deferral.** Endpoint events drained from a connection in step (2)
//! are NOT fed back into `Endpoint::handle_event` in the same borrow — they are
//! queued in [`Bridge::pending_endpoint_events`] and applied at the TOP of the
//! next `service` call (step 1). This mirrors quinn-proto's reference async
//! driver, where a connection task drains its endpoint events to a channel and
//! the endpoint task applies them on its own scheduling iteration. Feeding them
//! back inline would require holding `&mut endpoint` and `&mut connection`
//! simultaneously, and (once connections are reaped) would reintroduce the
//! connection-ID slab-reuse race the deferral exists to avoid.
//!
//! The terminal `EndpointEvent::Drained` rides the SAME one-tick deferral as
//! every other endpoint event — it is queued into [`Bridge::pending_endpoint_events`]
//! in step (2), never handled inline. This preserves quinn's per-connection FIFO
//! across the slab-free: any earlier endpoint event for the same handle (drained
//! from the same `poll_endpoint_events` pass) is therefore applied in step (1)
//! BEFORE the `Drained` frees the slot, while that handle is still live — handling
//! `Drained` inline would free the slab this pass and then replay the still-deferred
//! earlier event against the freed/reused handle next pass. When the deferred
//! `Drained` is processed in step (1) it is forwarded to `Endpoint::handle_event`
//! (freeing quinn's connection slab slot + CID/reset-token indexes), the local
//! `ConnEntry` is reaped, and any residual queued events for that now-drained handle
//! are purged (defensive: quinn emits nothing after `Drained`, but this guarantees
//! no post-free replay). Dropping `Drained` entirely (the original behaviour) leaked
//! that endpoint-owned state under reconnect / failed-handshake churn.
//!
//! **Inbound memory, per recv stream.** INBOUND ONLY — the send side is separate, below. Two
//! numbers matter: the PEAK a peer can drive it to, and what stays RETAINED once the traffic passes.
//!
//! Peak, with the arithmetic:
//!
//! | | |
//! |---|---|
//! | quinn reassembler, payload | `stream_receive_window` = 1 MiB |
//! | quinn reassembler, allocation ahead of payload — it compacts only once over-allocation passes `max(32 KiB, 1.5 x buffered)` | `1 MiB + max(32 KiB, 1.5 MiB)` = 2.5 MiB |
//! | quinn span bookkeeping — it holds up to `2 x MAX_CHUNKS` = 2048 spans before compacting, and its heap capacity rounds up | ~4096 x ~48 B = 192 KiB |
//! | read scratch, one pass | [`STAGE_CHUNK`] = 64 KiB |
//! | decoder, frame being assembled — reserved to its own size, not doubled past it | `LEN_PREFIX + MAX_FRAME_LEN` = 16 MiB |
//! | decoder, frames one pass completed — the one that was already assembling, plus what a budget can complete | 16 MiB + 64 KiB |
//! | decoder, ready-queue slots — one budget of minimal frames is `STAGE_CHUNK / LEN_PREFIX` = 16384 of them | 16384 x 24 B = 384 KiB |
//!
//! That totals under 36 MiB per recv stream, and a connection carries at most two (Control + Bulk).
//! The last two rows are what one pass can leave queued: `drain_bridge` pops the queue after every
//! `ingest_recv`, so a second frame-sized buffer does not accumulate behind the first, and the
//! decoder itself never holds two — a completed frame IS the buffer that assembled it, handed over
//! rather than copied out of a retained one. Reaching any of this needs a peer actually sending a
//! maximum-sized frame; [`decoder_max`] holds the frame cap down to the hello size until the
//! connection validates.
//!
//! Retained between frames, which is what a long-lived idle connection costs: the decoder carries
//! bounded working capacity and nothing frame-sized — the partial buffer is released above the
//! retained bound as each frame completes, and the ready queue releases its slots as it empties —
//! while quinn's reassembler keeps its heap allocation for the stream's life.
//!
//! **Outbound memory is separate** and separately capped: per class, the staged `outbound` buffer up
//! to `PER_CLASS_OUTBOUND_CAP` (64 MiB, past which the class resets or the connection is reaped),
//! one framed message as the encode temporary (at most `MAX_FRAME_LEN`), and quinn's own send buffer
//! for the connection, bounded by its `send_window`.
//!
//! Reading a budget is also what frees flow-control credit, so the peer's next window opens as the
//! decoder fills: a frame LARGER than the window still arrives, across as many window grants as it
//! takes. The deliverable frame ceiling is the decoder cap alone — [`MAX_FRAME_LEN`], unchanged by
//! the window it crosses.
//!
//! The window bounds the backlog's BYTES, not the number of spans quinn buffers them as; a peer
//! whose segmentation drives the span count past what quinn's reassembler holds gets the connection
//! closed. That path is recoverable, not a wedge: the close arrives as `Event::ConnectionLost`,
//! [`Bridge::on_app_event`] classifies it, unbinds the peer's routing and queues the connection on
//! [`Bridge::lost`] for the coordinator to reap, the driver's redial reconciler re-establishes it on
//! a backoff, and consensus retransmission re-drives what was in flight. See
//! [`MAX_STREAM_RECEIVE_WINDOW`](super::crypto::MAX_STREAM_RECEIVE_WINDOW) for which senders the
//! window's sizing covers and which it does not.
//!
//! The `Bridge` works natively in [`std::time::Instant`] — quinn's time
//! currency. The viewstamp-time adapter lives one layer up (the coordinator).

use core::{net::SocketAddr, time::Duration};

use std::{collections::VecDeque, time::Instant};

use quinn_proto::{
  ClientConfig, ConnectError, ConnectionHandle, DatagramEvent, Dir, EcnCodepoint, Endpoint,
  EndpointEvent, Event, StreamEvent, StreamId, VarInt, WriteError,
};
use rustls::pki_types::CertificateDer;

use super::{
  conn::{ConnEntry, Phase, decoder_max},
  crypto::QuicOptions,
  layout::{StreamClass, StreamLayout},
  table::ConnTable,
};
use crate::{
  MemberId, Message, Peer,
  transport::{
    CloseCause,
    frame::{FrameDecoder, MAX_FRAME_LEN, STAGE_CHUNK, encode_frame},
  },
};

/// Per-class outbound staging cap. When a class's `outbound` would exceed this, the bridge RESETs
/// just that class's send stream (clearing its buffer + reopening on the next write) rather than
/// growing without bound or tearing down the connection — consensus retransmission re-drives the
/// dropped (bulk) message. Pinned at 64 MiB: well above the 16 MiB max frame and 1 MiB stream
/// window, so a single legitimate bulk frame never false-trips it, yet bounded against a wedged
/// peer that stops reading.
const PER_CLASS_OUTBOUND_CAP: usize = 64 * 1024 * 1024;

/// Application error code on a per-stream RESET (a class send stream whose `outbound` overflowed or
/// was stopped/errored). Distinct from the connection-close code (1) so a peer can tell a
/// single-stream reset from a connection teardown.
const STREAM_RESET_CODE: u32 = 2;

/// How long a connection may sit in [`Phase::Authenticating`] (QUIC handshake done, identity not yet
/// bound) before the bridge tears it down. A peer that completes mTLS with a valid cluster cert but
/// never sends a valid `Hello` / never validates would otherwise pin a connection slot forever: quinn's
/// idle timeout (1 s) is refreshed by the peer's keepalive PINGs, so it never trips, and N such peers
/// exhaust `max_connections` (a connection-table-exhaustion DoS reachable WITHIN the non-Byzantine
/// threat model — a buggy or misbehaving but valid-cert member, not a forged cert).
///
/// 5 s is comfortably above any legitimate authentication: the QUIC handshake has ALREADY completed at
/// this point, so the window covers only the one-round-trip control-preface exchange, which lands in
/// ~1 RTT (the 50 ms `initial_rtt`) even across several PTO-driven retransmits (~150 ms PTO). It is
/// also 5× the 1 s `max_idle_timeout`, so a connection making genuine progress is never reaped. Yet it
/// is well-bounded, so a silent valid-cert peer frees its slot in seconds rather than holding it for the
/// connection's keepalive-extended lifetime.
const AUTH_DEADLINE: Duration = Duration::from_secs(5);

/// Maximum number of LIVE connections the bridge keeps for any ONE peer. On validation the bridge reaps
/// the OLDEST same-peer connections beyond this bound (see [`Self::bind_validated`]), so a flapping or
/// crash-looping valid-cert member cannot accumulate UNBOUNDED same-peer connections and consume every
/// `max_connections` slot — which would refuse later legitimate peers and block the mesh (a
/// connection-table-exhaustion DoS reachable WITHIN the non-Byzantine threat model: a buggy/misbehaving
/// but valid-cert member, since the per-connection [`AUTH_DEADLINE`] only reaps connections that never
/// VALIDATE — a peer that re-validates fresh connections keeps each past that gate).
///
/// **Value = 3:** the 2 steady-state mutual-dial connections + 1 reconnect slot. This transport's
/// mutual-dial design keeps TWO physical connections per peer pair — each side dials the other and BOTH
/// validate and deliver frames (see [`ConnTable::bind_peer`](super::table::ConnTable::bind_peer)); the
/// bound MUST preserve that pair, since tearing down the "displaced" connection on rebind breaks
/// steady-state convergence (both connections carry the peer's frames). A reconnecting peer can
/// briefly hold a THIRD connection (the new dial/accept overlapping the old one before it idle-times-out
/// or is reaped), so one reconnect slot of headroom is kept. Reaping is by creation recency
/// ([`ConnEntry::seq`](super::conn::ConnEntry::seq)): the just-validated connection and its mutual-dial
/// sibling are the two NEWEST same-peer connections, so they are always within the kept 3 and never
/// reaped.
///
/// **Consistency with the GLOBAL cap.** The coordinator sizes `max_connections` to
/// `max(caller, mesh_connection_floor(N))` where
/// [`mesh_connection_floor`](super::crypto::mesh_connection_floor) is `max(MIN_CONNECTION_FLOOR, 3*(N-1))`
/// for an `N`-replica cluster. A node has `N-1` peers, each bounded to `PER_PEER_CONN_LIMIT = 3` live
/// connections, so the per-peer bounds sum to `3*(N-1)` — EXACTLY the `3*(N-1)` mesh floor. The two
/// bounds are therefore aligned by construction: the global cap always has room for every peer's full
/// per-peer allotment, so the per-peer reap (not the global refusal) is what bounds one peer's churn,
/// and a peer at its per-peer bound never starves another peer's slots. A caller-raised global cap only
/// adds headroom above this; it never narrows the per-peer guarantee.
const PER_PEER_CONN_LIMIT: usize = 3;

/// `max_datagrams` per [`quinn_proto::Connection::poll_transmit`] call: quinn packs up to this many
/// equal-`segment_size` datagrams into ONE `Transmit` (the last may be shorter), so a
/// congestion-window's worth of consensus/state-transfer traffic drains in a handful of poll calls
/// instead of one call per datagram. 10 matches the cap the quinn runtime itself uses
/// (`MAX_TRANSMIT_SEGMENTS`): past that the per-call buffer grows for no measured gain. The bridge
/// splits a multi-segment `Transmit` back into per-datagram payloads for `out`
/// ([`transmit_segments`]), so drivers keep sending one UDP datagram per popped entry — GSO is not
/// required of them.
const MAX_TRANSMIT_DATAGRAMS: usize = 10;

/// Split one `Transmit`'s contents into its on-the-wire UDP datagrams: every chunk is exactly
/// `segment_size` bytes except the last, which may be shorter (quinn's GSO segment layout). A
/// `segment_size` of 0 cannot come out of quinn (it is `t.size / num_datagrams`-derived and quinn
/// never emits empty datagrams); the `max(1)` keeps `chunks` panic-free anyway.
fn transmit_segments(contents: &[u8], segment_size: usize) -> std::slice::Chunks<'_, u8> {
  contents.chunks(segment_size.max(1))
}

// The per-peer reap keeps `keep` + the `PER_PEER_CONN_LIMIT - 1` newest others; a limit of 0 would
// underflow that "others budget" (the `saturating_sub(1)` guards it, but a 0 limit would also mean "keep
// no connection per peer", which is nonsensical for a mesh). At least one is mandatory.
const _: () = assert!(PER_PEER_CONN_LIMIT >= 1);

/// Why an outbound dial ([`QuicCoordinator::connect`](super::QuicCoordinator::connect)) did not
/// produce a live connection.
///
/// Surfaced (not swallowed) so a caller learns a dial was refused — it can back off, report
/// saturation, or test the cap at the public boundary. `AtCapacity` is the dial counterpart of the
/// inbound accept refusal: the SAME `max_connections` bound governs dialed and accepted connections,
/// so a dial at the cap is skipped here rather than allowed to push the live count past the bound
/// under reconnect / retry churn.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DialError {
  /// The bridge holds `max_connections` live connections already; this dial was skipped (no quinn
  /// `Connection` allocated, nothing inserted) to keep dialed + accepted connections within the cap.
  #[error("connection cap reached ({cap}); dial refused")]
  AtCapacity {
    /// The configured live-connection cap that was hit.
    cap: usize,
  },
  /// quinn refused the dial (e.g. no client config, or an invalid server name).
  #[error("quinn refused the dial: {0}")]
  Connect(#[from] ConnectError),
}

/// The disposition of one per-class recv read in [`Bridge::ingest_recv`]: it classifies the read into
/// exactly one outcome so no recv-fault variant is silently treated as no-data (the FIN-as-EOF wedge),
/// AND so a GRACEFUL finish is told apart from an ABANDONED one — they dispose of the bytes read before
/// the close DIFFERENTLY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant)]
enum RecvFault {
  /// DATA accumulated, or a non-fatal would-block (`ReadError::Blocked`): the stream stays live, the
  /// `scratch` read this pass is decoded normally, and the recv half is read again next pass.
  Open,
  /// The peer GRACEFULLY finished its send half (`Chunks::next` → `Ok(None)`, the consumed FIN). The
  /// bytes read BEFORE the FIN are a COMPLETE final frame, so `scratch` is decoded + delivered, and only
  /// THEN is the connection reaped (Control) / the stream retired (Bulk) — delivery precedes teardown.
  Graceful,
  /// The peer ABANDONED its send half: a peer RESET (`ReadError::Reset`) or a stream already
  /// finished/reset/stopped (`recv.read()` → `ReadableError`). The bytes are gone (a RESET even leaves
  /// `scratch` empty), so `scratch` is DISCARDED and the connection is reaped (Control) / the stream
  /// retired (Bulk) at once.
  Abandoned,
}

/// What teardown a DEFERRED fatal recv close ([`Bridge::pending_fin_close`]) must apply once the
/// already-decoded complete frames are delivered. The close is deferred — rather than run inline —
/// precisely so [`Bridge::ingest_recv`] never drops a complete frame the decoder queued BEFORE the
/// fault: every deliver-before-close fault records its disposition HERE and returns control to the
/// coordinator's frame drain, which delivers the queued frames before [`Bridge::finish_fin_close`]
/// applies this. The torn/over-cap partial is never decoded into a frame, so it is dropped at the close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinDisposition {
  /// Every byte before the close framed cleanly (`partial_len == 0`: a complete final frame, or nothing
  /// when an empty FIN rode no payload; OR the pre-auth `[hello][buffered tail]` whose non-zero
  /// `partial_len` is the legitimately-retained pipelined tail). Run the class-split — Control reaps the
  /// whole connection, Bulk retires the stream in place — via [`Bridge::close_fault_class`].
  Clean,
  /// A graceful FIN left a TORN frame (`partial_len != 0` at the FINAL cap) — the peer finished
  /// mid-frame. An unrecoverable framing failure: reap the WHOLE connection (BOTH classes) via
  /// [`Bridge::close_local`] with [`CloseCause::TruncatedFrame`], exactly as the inline
  /// framing-error path does; only deferred so the complete prefix frames are delivered first.
  Truncated,
  /// The decoder REJECTED the fed bytes — a declared length over the cap (`extend`/`extend_first`
  /// returned `FrameTooLong`). The same whole-connection reap as `Truncated`, but attributed to
  /// [`CloseCause::FrameTooLong`]: an oversized peer frame is a protocol violation an operator
  /// diagnoses differently from a torn FIN, so the two dispositions stay distinguishable through
  /// the per-cause close counters.
  OverCap,
}

/// The three decode-derived facts the fatal-recv close disposition needs, snapshotted from a class
/// decoder WHILE its borrow is live so the disposition decision below can reborrow `self` freely. A POD
/// carrying ONLY the classification — [`decode_and_classify`] that produces it NEVER closes a connection,
/// so the two QUIC decode sites ([`Bridge::ingest_recv`]'s live read and [`Bridge::bind_validated`]'s
/// tail re-decode) share ONE decode+classify step and ONE disposition rule, and no site both decodes and
/// tears down.
#[derive(Debug, Clone, Copy)]
struct RecvDecode {
  /// The decoder REJECTED the fed bytes — a declared length over the cap the bytes decode under
  /// (`extend`/`extend_first` returned `FrameTooLong`). An unrecoverable framing failure: the disposition
  /// is `OverCap` (reap the whole connection, attributed to [`CloseCause::FrameTooLong`]), only DEFERRED
  /// behind any complete frames already queued so they are delivered first.
  frame_error: bool,
  /// At least one COMPLETE frame is queued on this class decoder's ready queue (`has_ready()`), to be
  /// delivered by the coordinator's `next_frame` drain before any teardown.
  has_ready: bool,
  /// A retained `partial` is a TRUNCATED (torn) frame: a graceful FIN landed mid-frame at the cap the
  /// bytes are decoded under. `partial_len != 0 && (final_cap || !has_ready)`, where `final_cap` is read
  /// from the decoder itself ([`FrameDecoder::is_at_final_cap`]): once the decoder is at the full
  /// `MAX_FRAME_LEN` a non-zero partial is ALWAYS torn (a partial Bulk / post-validation Control frame
  /// must not be silently dropped); while still at the small pre-auth hello cap a partial is torn ONLY
  /// when NO first frame completed (the FIN landed mid-HELLO — nothing to authenticate, never
  /// recoverable), because a non-zero partial BEHIND a complete hello is the legitimately-retained
  /// pipelined tail re-decoded post-validation, NOT a truncation (the C fix: `partial_len` alone is
  /// ambiguous — this resolves it from the cap + whether a first frame completed).
  truncated_partial: bool,
}

/// The ONE shared decode+classify step for the two QUIC recv decode sites. Feeds `bytes` to `decoder`
/// (`extend_first` when `use_extend_first`, capping the decode at the FIRST frame for the pre-auth
/// Control hello; `extend` otherwise) and snapshots a [`RecvDecode`] while the decoder borrow is still
/// live, so the caller's disposition decision is free of the borrow.
///
/// It NEVER closes a connection — it only classifies. Centralizing the decode AND the partial-truncation
/// judgement here is what makes the two sites converge: both feed the same decoder method and read the
/// same `(frame_error, has_ready, truncated_partial)`, and the truncation gate reads the cap from the
/// decoder ([`FrameDecoder::is_at_final_cap`]) rather than a per-site flag, removing the last way the two
/// could disagree about whether a retained partial is torn.
#[cfg(feature = "quic")]
fn decode_and_classify(
  decoder: &mut FrameDecoder,
  bytes: &[u8],
  use_extend_first: bool,
) -> RecvDecode {
  let decoded = if use_extend_first {
    decoder.extend_first(bytes)
  } else {
    decoder.extend(bytes)
  };
  let frame_error = decoded.is_err();
  let has_ready = decoder.has_ready();
  // A retained partial is torn only at the FINAL cap, or pre-auth when no first frame completed — read
  // the cap from the decoder so both sites judge it identically (see [`RecvDecode::truncated_partial`]).
  let truncated_partial = decoder.partial_len() != 0 && (decoder.is_at_final_cap() || !has_ready);
  RecvDecode {
    frame_error,
    has_ready,
    truncated_partial,
  }
}

/// Wraps a `quinn_proto::Endpoint` plus its connection table and runs the
/// service pump. The [`QuicCoordinator`](super::QuicCoordinator) that owns this
/// bridge drains the `connected` / `stream_ready` / `lost` event queues (via the
/// `take_*` accessors) and the outbound datagram queue ([`Self::poll_transmit`]).
pub(crate) struct Bridge {
  /// The owned quinn endpoint. Single source of new/accepted connections.
  endpoint: Endpoint,
  /// Pool of live connections keyed by `ConnectionHandle`.
  table: ConnTable,
  /// The client config for outbound dials, snapshotted from `opts` at
  /// construction so [`Self::connect`] can supply it without the caller
  /// re-passing it. `None` if `opts` carried no client config (dial-only).
  client: Option<ClientConfig>,
  /// The stream layout (snapshotted from `opts`), stamped onto every new/accepted [`ConnEntry`] so
  /// each connection knows whether to open the Bulk class in addition to Control.
  layout: StreamLayout,
  /// Cap on live connections (dialed + accepted) held in `table`. An inbound `NewConnection` that
  /// would exceed this is REFUSED (a stateless close) instead of allocating a `Connection`, bounding
  /// an untrusted-network flood of foreign-CA / no-cert Initials before identity validation.
  /// Snapshotted from `opts`.
  max_connections: usize,
  /// Outbound datagrams produced by the endpoint or its connections, awaiting
  /// the driver's `poll_transmit` drain.
  out: VecDeque<(SocketAddr, Vec<u8>)>,
  /// Endpoint events drained from connections on the PREVIOUS `service` iteration, applied at the top
  /// of the next one (the one-tick deferral; see module docs). The terminal `Drained` is queued here
  /// like any other event so quinn's per-connection FIFO survives the slab-free.
  pending_endpoint_events: VecDeque<(ConnectionHandle, EndpointEvent)>,
  /// Count of endpoint events fed back through `Endpoint::handle_event` — the
  /// observable the negative control asserts is non-zero after a handshake.
  endpoint_events_processed: u64,
  /// Count of outbound messages refused because their encoded frame would exceed
  /// [`MAX_FRAME_LEN`]. The receive side reaps a connection on an over-cap frame, so such a message
  /// can never deliver; [`Self::write_framed`] preflights it and drops it here rather than encoding,
  /// framing, and emitting a datagram the peer would only fatal on. Surfaced (not silently swallowed)
  /// so a driver/operator can see a protocol message outgrew the transport frame limit.
  oversized_dropped: u64,
  /// Closes counted by [`CloseCause`] (indexed by [`CloseCause::index`]) at the shared
  /// Closed-transition tail, once per connection — the QUIC analogue of the stream drivers'
  /// per-cause close counters. Read via [`Self::conn_close_count`].
  close_counts: [u64; CloseCause::COUNT],
  /// Connections that just reached `Event::Connected`, drained by the
  /// coordinator via [`Self::take_connected`].
  connected: VecDeque<ConnectionHandle>,
  /// Connections with a readable / newly-writable / newly-peer-opened stream, drained by the
  /// coordinator via [`Self::take_ready_unique`]. Carries `Stream(Readable)`, `Stream(Writable)`,
  /// and bidi `Stream(Opened)`: the coordinator retries both reads and formerly-blocked sends, and
  /// adopts a peer-opened stream on its first frame (quinn emits `Opened`, not `Readable`, for that
  /// first frame). Named `stream_ready` because it covers more than the readable direction. quinn
  /// pushes a `Readable` per received STREAM frame, so a handle can sit here many times; the
  /// coordinator's drain collapses duplicates so each connection is read once per pump.
  stream_ready: VecDeque<ConnectionHandle>,
  /// Connections whose inbound read stopped on its per-pass budget with stream bytes still readable,
  /// queued by [`Self::ingest_recv`] for the NEXT pump — NOT the one draining `stream_ready` now.
  /// [`Self::take_ready_unique`] folds this queue into `stream_ready` at the START of each coordinator
  /// drain, so leftover read work is processed ONE budget per pump (a handle re-deferred here during a
  /// drain waits for the next drain), rather than the whole receive window being consumed in a single
  /// pump. [`Self::has_pending_work`] counts it so a `poll_timeout`-driven driver re-pumps immediately
  /// while leftover remains.
  deferred_ready: VecDeque<ConnectionHandle>,
  /// Connections that just emitted `Event::ConnectionLost`, drained by the
  /// coordinator via [`Self::take_lost`].
  lost: VecDeque<ConnectionHandle>,
  /// Connections with a DEFERRED fatal recv close (graceful FIN, or an over-cap framing error that
  /// queued a complete prefix) on one class this pump: the teardown must run only AFTER that class's
  /// already-decoded complete frames are delivered. [`Self::ingest_recv`] decodes the pre-fault `scratch`
  /// into the class decoder (a final consensus frame that arrived in the SAME read as the FIN is now
  /// queued), records the `(handle, class, disposition)` HERE, and returns `false` so the coordinator's
  /// `drain_bridge` pops those queued frames via [`Self::next_frame`] this same pass. The coordinator
  /// then drains this queue (after the frame delivery) and calls [`Self::finish_fin_close`], which
  /// applies the recorded [`FinDisposition`] — `Clean` runs the class-split (Control reap / Bulk retire),
  /// `Truncated` reaps the whole connection. Delivery strictly precedes teardown, so a vote/commit
  /// written immediately before the peer finished its send half — or queued ahead of a torn/over-cap
  /// frame — is never dropped. A peer RESET / `ClosedStream` does NOT land here (its bytes were
  /// abandoned): those reap inline. The disposition is recorded at fault time so the deferred close
  /// matches the framing decision made then, rather than being re-derived from the class alone.
  pending_fin_close: VecDeque<(ConnectionHandle, StreamClass, FinDisposition)>,
  /// Deferred-service marker for the per-MESSAGE write path: [`Self::write_framed`] sets this
  /// instead of running a full `service` pass per message — the coordinator's `pump` routes every
  /// outgoing message through `write_framed` before its single unconditional pump-end `service`
  /// (the module-doc wakeup invariant), so a per-message pass would be O(messages × connections)
  /// of redundant quinn polling per pump. That pump-end `service` consumes the flag (clears it on
  /// entry) and collects everything the writes staged, including a Bulk-overflow `RESET_STREAM`.
  /// White-box tests that drive `write_framed` directly (no coordinator pump follows) flush via
  /// [`Self::service_if_deferred`], which runs a pass exactly when this is set.
  needs_service: bool,
  /// Test-only: when set, [`Self::service`] skips the `poll_endpoint_events`
  /// drain (step 2). The negative control sets this to prove the flag gates the
  /// drain — with it set, `endpoint_events_processed` stays zero.
  #[cfg(test)]
  skip_endpoint_drain: bool,
  /// Test-only re-entrancy guard for [`Self::service`]: incremented on entry, decremented on exit, and
  /// asserted to never exceed 1. `service` must never be reached from within `service` — every
  /// `close_local` (the auth-reap, the Control-class fatals) is a non-recursive state mutation, so a
  /// mass simultaneous reap does at most one service pass. A re-entry would mean the recursion this
  /// guards against (a per-close `service` rescanning the whole table) had crept back in.
  #[cfg(test)]
  service_depth: u32,
}

impl Bridge {
  /// Build a bridge from `opts`. `rng_seed` seeds the endpoint's connection-ID
  /// / token RNG (`None` = OS entropy).
  ///
  /// MTU discovery is ENABLED (`allow_mtud` + the `TransportConfig` default discovery config).
  /// Consensus traffic routinely exceeds the 1200-byte initial MTU — a `Prepare` carries the client
  /// request body, and a 16 MiB state-transfer frame is ~14k datagrams at 1200 — so staying at the
  /// un-probed floor costs real packet count and per-packet overhead on every bulk path. Cluster
  /// links are not the public internet: replica↔replica paths are datacenter/VPC-grade (path MTU at
  /// or above the standard 1500), so the default probe schedule (up to 1452 bytes) converges
  /// immediately and a black-holed probe merely keeps the connection at the floor — probing is
  /// lossless to correctness either way.
  pub(crate) fn new(opts: &QuicOptions, rng_seed: Option<[u8; 32]>) -> Self {
    let endpoint = Endpoint::new(
      opts.endpoint_config(),
      opts.server_config(),
      /*allow_mtud=*/ true,
      rng_seed,
    );
    Self {
      endpoint,
      table: ConnTable::new(),
      client: opts.client_config(),
      layout: opts.layout(),
      max_connections: opts.max_connections(),
      out: VecDeque::new(),
      pending_endpoint_events: VecDeque::new(),
      endpoint_events_processed: 0,
      oversized_dropped: 0,
      close_counts: [0; CloseCause::COUNT],
      connected: VecDeque::new(),
      stream_ready: VecDeque::new(),
      deferred_ready: VecDeque::new(),
      lost: VecDeque::new(),
      pending_fin_close: VecDeque::new(),
      needs_service: false,
      #[cfg(test)]
      skip_endpoint_drain: false,
      #[cfg(test)]
      service_depth: 0,
    }
  }

  /// Whether the live-connection cap is reached: the table already holds `max_connections` entries
  /// (dialed + accepted). The SINGLE cap predicate — both the inbound accept ([`Self::handle_datagram`])
  /// and the outbound dial ([`Self::connect`]) consult it before allocating a `Connection`, so the
  /// bound governs every connection the bridge holds rather than only the accepted ones.
  fn at_capacity(&self) -> bool {
    self.table.len() >= self.max_connections
  }

  /// Dial `remote`, validating its certificate against `server_name`. `expected` is the peer this
  /// dial is meant to reach — recorded on the entry so the coordinator's binding policy can require
  /// the authenticated identity to match it (match-or-abort). Inserts the new connection into the
  /// table and runs one service pass so the initial handshake datagram is queued for the next
  /// `poll_transmit`.
  ///
  /// Refuses with [`DialError::AtCapacity`] when the bridge is already at the connection cap — BEFORE
  /// allocating a quinn `Connection` — so a dial cannot push the live count past `max_connections`
  /// under reconnect / retry churn (the same bound the accept path enforces). The refusal is returned,
  /// not swallowed, so the coordinator can see it.
  pub(crate) fn connect(
    &mut self,
    now: Instant,
    remote: SocketAddr,
    server_name: &str,
    expected: Peer,
  ) -> Result<ConnectionHandle, DialError> {
    if self.at_capacity() {
      return Err(DialError::AtCapacity {
        cap: self.max_connections,
      });
    }
    let cfg = self
      .client
      .clone()
      .ok_or(ConnectError::NoDefaultClientConfig)?;
    let (h, conn) = self.endpoint.connect(now, cfg, remote, server_name)?;
    self
      .table
      .insert(h, ConnEntry::new(conn, Some(expected), self.layout));
    self.service(now);
    Ok(h)
  }

  /// Feed one inbound UDP datagram from `remote` into the endpoint, routing the
  /// resulting [`DatagramEvent`], then run a service pass.
  ///
  /// - `ConnectionEvent` → delivered to the addressed connection.
  /// - `NewConnection` → accepted while the table is under the connection cap, else REFUSED (a
  ///   stateless close) so an untrusted-network flood cannot allocate unbounded connection state; any
  ///   close/refuse bytes quinn produced are surfaced as an outbound datagram.
  /// - `Response` → a stateless endpoint reply (Retry / version negotiation /
  ///   stateless reset) written into the scratch buffer; forwarded outbound.
  pub(crate) fn handle_datagram(
    &mut self,
    now: Instant,
    remote: SocketAddr,
    ecn: Option<EcnCodepoint>,
    data: &[u8],
  ) {
    let mut scratch = Vec::new();
    let ev = self.endpoint.handle(
      now,
      remote,
      /*local_ip=*/ None,
      ecn,
      bytes::BytesMut::from(data),
      &mut scratch,
    );
    match ev {
      Some(DatagramEvent::ConnectionEvent(h, conn_ev)) => {
        if let Some(e) = self.table.entry(h) {
          e.conn.handle_event(conn_ev);
        }
      }
      Some(DatagramEvent::NewConnection(incoming)) => {
        // Bound inbound accepts: at the connection cap, REFUSE this attempt (a stateless close) rather
        // than allocate a `Connection`/`ConnEntry`. The network is untrusted — a flood of foreign-CA /
        // no-cert Initials would otherwise allocate arbitrary connection state before identity
        // validation could reject it. The SAME `at_capacity` gate bounds the dial path
        // ([`Self::connect`]). `refuse` returns a single close `Transmit` written into `rbuf`.
        if self.at_capacity() {
          // The refusal happens BEFORE any `ConnEntry` exists, so the shared Closed-transition
          // counting never sees it — count it here directly, or the diagnostic stays at zero under
          // exactly the connection-cap saturation it exists to surface.
          self.close_counts[CloseCause::AcceptCapacity.index()] += 1;
          let mut rbuf = Vec::new();
          let t = self.endpoint.refuse(incoming, &mut rbuf);
          debug_assert!(
            t.size <= rbuf.len(),
            "quinn wrote {} into a {}-byte buffer",
            t.size,
            rbuf.len()
          );
          rbuf.truncate(t.size);
          self.out.push_back((t.destination, rbuf));
          self.service(now);
          return;
        }
        let mut abuf = Vec::new();
        match self
          .endpoint
          .accept(incoming, now, &mut abuf, /*server_config=*/ None)
        {
          // An accepted connection has no dialed expectation: the coordinator adopts whatever
          // identity authenticates (subject to the unconditional cluster cross-check).
          Ok((h, conn)) => self
            .table
            .insert(h, ConnEntry::new(conn, None, self.layout)),
          Err(e) => {
            // quinn attaches a refusal/close `Transmit` to `AcceptError`
            // whenever it owes the peer an immediate close (e.g. CID
            // exhaustion or an initial-handshake transport failure). Those
            // bytes are already in `abuf`; surface them so the peer sees the
            // close at once instead of waiting out its retransmit budget.
            if let Some(t) = e.response {
              debug_assert!(
                t.size <= abuf.len(),
                "quinn wrote {} into a {}-byte buffer",
                t.size,
                abuf.len()
              );
              abuf.truncate(t.size);
              self.out.push_back((t.destination, abuf));
            }
          }
        }
      }
      Some(DatagramEvent::Response(t)) => {
        debug_assert!(
          t.size <= scratch.len(),
          "quinn wrote {} into a {}-byte buffer",
          t.size,
          scratch.len()
        );
        scratch.truncate(t.size);
        self.out.push_back((t.destination, scratch));
      }
      None => {}
    }
    self.service(now);
  }

  /// The fixpoint service pump. Drives every connection one progress step:
  ///
  /// 1. Apply the previous tick's deferred endpoint-event feedback FIRST, so a
  ///    connection sees its `NeedIdentifiers`-minted CIDs before it polls. A
  ///    deferred `Drained` here frees the endpoint slab + indexes, reaps the local
  ///    entry, and purges any residual queued events for that handle.
  /// 2. Drain each connection's `poll_endpoint_events()`, deferring the
  ///    `Endpoint::handle_event` round-trip to the next tick — `Drained` included,
  ///    so quinn's per-connection FIFO is preserved across the slab-free (see
  ///    module docs).
  /// 3. Drain each connection's application `poll()` events.
  /// 4. Collect each connection's outbound transmits into `out`.
  ///
  /// Steps (1)–(4) run per connection; the cross-tick loop in the driver re-runs
  /// `service` (via `handle_datagram` / `handle_timeout`) until the connections
  /// quiesce, which is what carries the multi-round-trip handshake to completion.
  ///
  /// The one-tick deferral means endpoint events collected during a `service`
  /// pass are fed back on the NEXT pass. The driver must therefore call into the
  /// bridge again each tick — which `handle_datagram` and `handle_timeout` both
  /// guarantee — rather than sleeping while work is pending.
  ///
  /// **Service-after-mutation invariant (correct-by-construction).** Step 4 is the ONLY place a
  /// connection's queued quinn output (datagrams, STREAM data, and credit/control frames like
  /// `STOP_SENDING` / `RESET_STREAM` / `MAX_DATA`) is collected into `out`. So every quinn-mutating
  /// operation must reach a `service` for that connection THIS pump, or the frame sits in quinn —
  /// invisible to both `out` and `has_pending_work` — until unrelated activity wakes a
  /// `poll_timeout`-driven driver. The guarantee is SYSTEMATIC rather than per-operation: the
  /// [`QuicCoordinator`](super::QuicCoordinator)'s `pump` runs ONE unconditional `service` at pump end,
  /// AFTER `drain_bridge` (all its `ingest_recv` / `flush_stream` / `write_framed` / `bind_validated` /
  /// `close_local` / accept-loop `stop` mutations) AND after its own routing `write_framed`s. So no
  /// mutation a pump performs can strand a queued frame, and a new connection-mutating path needs no
  /// per-operation `service` plumbing to be wakeup-safe. (The per-EVENT bridge entry-points still
  /// `service` inline so the bridge is correct when driven directly by its own white-box unit tests;
  /// the per-MESSAGE `write_framed` instead defers via [`Self::needs_service`] — see that field — and
  /// tests flush it with [`Self::service_if_deferred`].)
  pub(crate) fn service(&mut self, now: Instant) {
    // Re-entrancy guard (test-only): `service` must never run within `service`. Every `close_local`
    // (the auth-reap loop below, the Control-class fatals) is a non-recursive state mutation, so this
    // depth never exceeds 1 — a re-entry would mean the per-close `service` recursion was reintroduced.
    #[cfg(test)]
    {
      assert_eq!(
        self.service_depth, 0,
        "service must not re-enter itself: close_local is a non-recursive state mutation, so a mass \
         auth-reap does at most one service pass"
      );
      self.service_depth += 1;
    }
    // Consume the per-message write deferral: this pass collects everything `write_framed` staged
    // since the last one (the coordinator's pump-end `service` is the production consumer).
    self.needs_service = false;
    // Step 1: apply the previous iteration's deferred endpoint-event feedback
    // BEFORE any poll, mirroring quinn-proto's reference driver ordering. Drain
    // the whole queue (events for any connection) IN FIFO ORDER; materialise
    // nothing extra — each `handle_event` borrows the endpoint, and the table
    // entry borrow is disjoint.
    while let Some((h, ev)) = self.pending_endpoint_events.pop_front() {
      // The terminal `Drained`: forwarding it frees quinn's connection slab slot + CID/reset-token
      // indexes, so the local `ConnEntry` is then reaped. Because it is drained in FIFO order, any
      // earlier same-handle event has already been applied above (while the handle was still live).
      // Purge any residual queued events for this handle — quinn emits nothing after `Drained`, so
      // this is defensive against replaying a freed handle. `remove` is idempotent vs the
      // `lost`/`reap` path, so a later reap of the same handle is a harmless no-op.
      if ev.is_drained() {
        let _ = self.endpoint.handle_event(h, ev);
        self.endpoint_events_processed = self.endpoint_events_processed.saturating_add(1);
        self.table.remove(h);
        self.pending_endpoint_events.retain(|(qh, _)| *qh != h);
        continue;
      }
      if let Some(conn_ev) = self.endpoint.handle_event(h, ev)
        && let Some(e) = self.table.entry(h)
      {
        e.conn.handle_event(conn_ev);
      }
      self.endpoint_events_processed = self.endpoint_events_processed.saturating_add(1);
    }

    for h in self.table.handles() {
      // `handle_timeout` first so any expired timers fire before we poll the
      // connection's resulting events / transmits this same pass.
      if let Some(e) = self.table.entry(h) {
        e.conn.handle_timeout(now);
      }

      // Step 2: drain endpoint-facing events and DEFER each — including the terminal `Drained` — to
      // the next tick (the one-tick deferral; see module docs). Deferring `Drained` rather than
      // freeing the slab inline preserves quinn's per-connection FIFO across the slab-free.
      // The negative control disables this entire step (via the test-only flag) to prove the flag
      // gates the drain.
      #[cfg(test)]
      let drain_endpoint_events = !self.skip_endpoint_drain;
      #[cfg(not(test))]
      let drain_endpoint_events = true;
      if drain_endpoint_events {
        // Collect into a local first so the `e.conn` borrow is released before the queue push, then
        // enqueue in FIFO order. (A `while let` over `poll_endpoint_events` that pushed directly would
        // hold the entry borrow across the `self.pending_endpoint_events` push.)
        let mut events = Vec::new();
        if let Some(e) = self.table.entry(h) {
          while let Some(ev) = e.conn.poll_endpoint_events() {
            events.push(ev);
          }
        }
        for ev in events {
          self.pending_endpoint_events.push_back((h, ev));
        }
      }

      // Step 3: drain application events. `poll()` is pulled into a local so the
      // table-entry borrow is released before `on_app_event` re-borrows `self`.
      loop {
        let next = self.table.entry(h).and_then(|e| e.conn.poll());
        match next {
          Some(ev) => self.on_app_event(now, h, ev),
          None => break,
        }
      }

      // Step 4: collect outbound transmits. `poll_transmit` writes into `tbuf` and reports `t.size`
      // bytes, packing up to `MAX_TRANSMIT_DATAGRAMS` equal-size datagrams per call (`segment_size`
      // is `Some` exactly when more than one was packed) — so a full congestion window drains in a
      // few calls instead of one per datagram. quinn-proto grows `tbuf` to hold the written bytes,
      // so `t.size <= tbuf.len()` is invariantly true. `out` stays one-UDP-datagram-per-entry (what
      // the drivers and the loopback network expect): a single-datagram transmit hands its buffer
      // through OWNED (truncate + take, no copy — quinn regrows the fresh buffer next call); a
      // multi-segment transmit is split into per-segment payloads. The `self.table` entry borrow and
      // the `self.out` push touch disjoint fields, so both live together.
      let mut tbuf = Vec::new();
      while let Some(e) = self.table.entry(h) {
        let Some(t) = e.conn.poll_transmit(now, MAX_TRANSMIT_DATAGRAMS, &mut tbuf) else {
          break;
        };
        debug_assert!(
          t.size <= tbuf.len(),
          "quinn wrote {} into a {}-byte buffer",
          t.size,
          tbuf.len()
        );
        match t.segment_size {
          None => {
            tbuf.truncate(t.size);
            self
              .out
              .push_back((t.destination, std::mem::take(&mut tbuf)));
          }
          Some(seg) => {
            for datagram in transmit_segments(&tbuf[..t.size], seg) {
              self.out.push_back((t.destination, datagram.to_vec()));
            }
            tbuf.clear();
          }
        }
      }
    }

    // Reap any connection that has sat in `Authenticating` past its `AUTH_DEADLINE` (handshake done,
    // identity never bound). Collect the expired handles FIRST, then close them — the collection releases
    // the `handles()` borrow before `close_local` takes `&mut self.table`. `close_local` is now a
    // NON-recursive state mutation (it does NOT re-enter `service`; see its doc), so a mass simultaneous
    // expiry just marks each handle `Closed` and queues `lost` with NO recursion and at most this one
    // service pass — the CONNECTION_CLOSE bytes are collected by the next pass (the coordinator's
    // unconditional pump-end `service`, or the immediate re-pump `lost` triggers via `has_pending_work`).
    // `close_local` is the shared teardown choke-point (issues the quinn `close` so the connection drains
    // to `Drained`, freeing the endpoint slab + the connection-cap slot) and is idempotent on an
    // already-`Closed` entry.
    let expired: Vec<ConnectionHandle> = self
      .table
      .handles()
      .into_iter()
      .filter(|h| {
        self
          .table
          .entry(*h)
          .is_some_and(|e| e.phase.is_authenticating() && e.auth_deadline.is_some_and(|d| now >= d))
      })
      .collect();
    for h in expired {
      self.close_local(now, h, CloseCause::AuthDeadline);
    }
    // Exit the re-entrancy guard (test-only): the depth returns to 0. A `close_local` above that
    // re-entered `service` would have tripped the entry assertion before reaching here.
    #[cfg(test)]
    {
      self.service_depth -= 1;
    }
  }

  /// Route one connection-level application [`Event`] to the per-connection
  /// phase and the coordinator-facing event queues.
  ///
  /// `now` stamps the authentication deadline ([`AUTH_DEADLINE`]) when a connection enters
  /// `Authenticating`, so a peer that completes the handshake but never validates is reaped rather than
  /// pinning a connection slot indefinitely.
  fn on_app_event(&mut self, now: Instant, h: ConnectionHandle, ev: Event) {
    match ev {
      Event::Connected => {
        // The QUIC handshake is complete, but identity is NOT yet bound: move to `Authenticating`,
        // not `Validated`. The coordinator opens the send stream, writes the control preface, and
        // runs `authenticate` + the binding policy; only that promotes the connection to `Validated`.
        // Stamp the auth deadline NOW: a peer that authenticated its cert but never sends a valid
        // preface stays `Authenticating` (its keepalives refresh the idle timeout), so without this
        // deadline it would pin the slot forever — `service` reaps it once the clock passes the deadline.
        if let Some(e) = self.table.entry(h) {
          e.phase = Phase::Authenticating;
          e.auth_deadline = Some(now + AUTH_DEADLINE);
          // I7: the deadline is stamped exactly as the connection ENTERS `Authenticating`, so the
          // deadline-present-iff-authenticating biconditional holds (`true == true`). This is the single
          // site that arms the deadline; every exit (to `Validated` or `Closed`) clears it, and each
          // asserts the same biconditional, so a stale deadline cannot survive an `Authenticating` exit.
          debug_assert!(
            e.auth_deadline.is_some() == e.is_authenticating(),
            "on_connected: an Authenticating entry carries an auth deadline (I7)"
          );
        }
        self.connected.push_back(h);
      }
      Event::Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
        // A peer opened a bidi stream. quinn emits `Opened` (NOT `Readable`) for the FIRST frame on
        // a freshly peer-initiated stream; a `Readable` is emitted only for subsequent frames on an
        // already-known stream. The control preface is written exactly once, so its first (and only)
        // frame arrives as `Opened` — surface the handle here so the coordinator adopts the stream
        // (`accept`) and reads the preface deterministically, rather than waiting on a retransmit.
        self.stream_ready.push_back(h);
      }
      Event::Stream(StreamEvent::Readable { .. }) => {
        self.stream_ready.push_back(h);
      }
      Event::Stream(StreamEvent::Writable { .. }) => {
        // A formerly write-blocked stream may now accept writes; surface it on
        // the same queue so the coordinator retries its pending send.
        self.stream_ready.push_back(h);
      }
      Event::Stream(StreamEvent::Available { dir: Dir::Bi }) => {
        // The peer raised its concurrent-bidi-stream limit (a `MAX_STREAMS` frame), so a bidi `open` that
        // previously returned `None` can now succeed. This unblocks a class with staged `outbound` but no
        // send id — a Bulk stream RESET while every bidi slot was exhausted, whose `flush_outbound` reopen
        // returned `false` and left the frame staged. Surface the handle on the same queue as `Writable`
        // so `drain_bridge` → `flush_stream` reopens the stream now a slot is free; staged `outbound` is
        // otherwise excluded from `has_pending_work` (it retries only on a quinn signal — this one). The
        // signal rides an inbound datagram, which already wakes the driver, so the freshly-queued
        // `stream_ready` entry makes `has_pending_work` true for that same pump. `Available { Dir::Uni }`
        // is irrelevant (this transport opens only bidi streams) — left to the `_` arm below.
        self.stream_ready.push_back(h);
      }
      Event::ConnectionLost { reason } => {
        // A PEER-initiated loss: quinn is already draining this connection toward `Drained`, so no
        // local `close` is re-issued. Run the SHARED teardown tail — mark `Closed`, clear the auth
        // deadline, unbind routing, queue `lost` — so the connection is unrouteable atomically the
        // instant it is lost (symmetric with `close_local`, which differs only by issuing the quinn
        // `close` first). The entry is kept for the drain. The loss reason maps onto the shared
        // close-cause vocabulary: an idle expiry is its own cause (the operator signal that a peer
        // went dark), an application/connection close is the peer ending the conn, and everything
        // else (a transport/protocol error, a version mismatch, a stateless reset, CID exhaustion)
        // is the QUIC layer rejecting the connection — the record layer's analogue.
        let cause = match &reason {
          quinn_proto::ConnectionError::TimedOut => CloseCause::IdleTimeout,
          quinn_proto::ConnectionError::ApplicationClosed(_)
          | quinn_proto::ConnectionError::ConnectionClosed(_)
          | quinn_proto::ConnectionError::LocallyClosed => CloseCause::PeerClosed,
          _ => CloseCause::RecordRejected,
        };
        self.mark_closed_unbind_push(h, cause);
      }
      Event::Stream(StreamEvent::Stopped { id, .. }) => {
        // The peer sent STOP_SENDING on a send stream of OURS. `StreamEvent::Stopped { id }` is for one
        // EXACT stream id (quinn's `received_stop_sending` keys it on that id; see quinn streams/state.rs),
        // so the response must act on that EXACT id — NOT reset "the current stream of that class". A
        // non-matching id is either a STALE stop for an already-retired Bulk stream (UDP reorder: the peer
        // retired our old Bulk recv and STOP'd the OLD id, which arrives after `classes[Bulk].send` already
        // moved to the reopened stream) or a PEER-opened stream's unused send half of ours (the peer's
        // opener-role [`retire_local_send`] `stop`s its unused recv half = our send direction) — neither is
        // the live class.
        //
        // So classify the id only to FIND which class to compare against, then act ONLY when `id` is that
        // class's currently-tracked send id:
        // - Control current id → reap the WHOLE connection (`close_local`). A dead Control send half cannot
        //   be recovered in place — reopening at a higher index mis-maps to Bulk on the peer (the index-0 =
        //   Control invariant); a fresh connection reopens Control at index 0.
        // - Bulk current id → reset just that class (`reset_send_class`): drop its buffer + send id to
        //   reopen on the next write; Control and the connection survive (consensus retransmission re-drives
        //   the dropped Bulk frames).
        // - id does NOT match → `reset` that EXACT send id, leaving the live class untouched. For an
        //   already-retired local stream this is a benign no-op. For a peer-opened unused send half it is
        //   LOAD-BEARING: a received `STOP_SENDING` only sets `stop_reason` (it does not free the send
        //   entry), so the half must be `reset` to reach `ResetSent` and free on `reset_acked`; otherwise it
        //   lingers, the peer-opened stream never fully retires, and we never re-grant `MAX_STREAMS`.
        let class = class_of_index(id);
        let is_current = self
          .table
          .entry(h)
          .is_some_and(|e| e.class_mut(class).send == Some(id));
        if is_current {
          match class {
            StreamClass::Control => self.close_local(now, h, CloseCause::PeerClosed),
            StreamClass::Bulk => self.reset_send_class(h, class),
          }
        } else if let Some(e) = self.table.entry(h) {
          // Free this EXACT stopped send half (a peer-opened unused send half, or an already-retired local
          // stream): `reset` only fails on an absent/already-`ResetSent` stream — a benign no-op there. The
          // queued `RESET_STREAM` reaches the wire via step 4's `poll_transmit` this same `service` pass.
          let _ = e
            .conn
            .send_stream(id)
            .reset(VarInt::from_u32(STREAM_RESET_CODE));
        }
      }
      // Intentionally not consumed here:
      // - `Stream(Opened { dir: Dir::Uni })` / `Stream(Available { dir: Dir::Uni })` — this transport
      //   opens only BIDI streams (Control, then Bulk), so a Uni open/credit signal concerns no stream
      //   we use and strands nothing. The `TransportConfig` advertises a 0 uni-stream limit
      //   (see `build_transport`), so a conformant peer cannot open a uni stream at all and these arms
      //   are unreachable on that path — kept as a defensive ignore.
      // - `Stream(Finished { .. })` — emitted only after a send half is gracefully `finish()`ed, which
      //   the transport NEVER does (a class send stream lives for the connection's lifetime; an overflow
      //   / dead half is RESET, surfaced via the `Stopped` arm above, not finished). It carries no
      //   staged-frame or slot-reuse obligation, so dropping it cannot strand a frame or leak a stream.
      // - `HandshakeDataReady`, `DatagramReceived`, `DatagramsUnblocked` — not part of this transport's
      //   stream/datagram model (consensus rides framed bidi streams, not QUIC datagrams). DATAGRAM
      //   receive is disabled in `build_transport` (`datagram_receive_buffer_size(None)`), so a
      //   conformant peer cannot deliver a DATAGRAM and `DatagramReceived` / `DatagramsUnblocked` are
      //   likewise unreachable — kept as a defensive ignore.
      _ => {}
    }
  }

  /// Pop one outbound datagram (destination + owned bytes), or `None` when the
  /// queue is empty. Owned bytes avoid any caller-buffer sizing concern and
  /// match the storage format already held in `out`.
  pub(crate) fn poll_transmit(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
    self.out.pop_front()
  }

  /// Whether the bridge holds DEFERRED work that the next pump pass must apply WITHOUT waiting on an
  /// inbound datagram or a peer flow-control window — the SINGLE source of truth for "is there
  /// immediate work due now". [`Self::poll_timeout`] reports an immediate deadline iff this is true, so
  /// a `poll_timeout`-driven driver re-pumps at once rather than sleeping past queued work.
  ///
  /// **Every immediate-work queue/buffer the bridge can hold between driver passes is enumerated here
  /// — a new deferred queue MUST be reflected in this one method.** The classification of each:
  ///
  /// - [`Self::pending_endpoint_events`] — IMMEDIATE. Endpoint events (the terminal `Drained`
  ///   included) drained from connections on one `service` pass and applied at the TOP of the next
  ///   (the one-tick deferral; see module docs). A driver sleeping on a connection timer would stop
  ///   ONE pass before a deferred `Drained` frees quinn's slab + the cap slot.
  /// - [`Self::connected`] / [`Self::stream_ready`] / [`Self::lost`] — IMMEDIATE. These coordinator-
  ///   facing queues are drained by `QuicCoordinator::drain_bridge`, but `service` (run AFTER
  ///   `drain_bridge` by `pump`, and re-entered mid-`drain_bridge` by `open_send_and_preface` /
  ///   `bind_validated` / `flush_stream`) can enqueue a fresh `Connected` /
  ///   `Stream(_)` / `ConnectionLost` via `on_app_event` AFTER this pass's `drain_bridge` already ran.
  ///   That leftover is connection auth / read / reap work that progresses with NO inbound datagram,
  ///   so a sleep-until-`poll_timeout` driver must be woken now to drain it.
  /// - [`Self::deferred_ready`] — IMMEDIATE. A read that stopped on its per-pass budget with stream
  ///   bytes still readable ([`Self::ingest_recv`]) defers the connection HERE (not `stream_ready`,
  ///   which the current drain is consuming) so the next pump reads the next budget. Those bytes are
  ///   ALREADY buffered in the connection — draining them needs no further inbound datagram — so a
  ///   driver must be woken now to continue. `drain_bridge` promotes this into `stream_ready` at the
  ///   top of the next pump.
  ///
  /// Excluded (BLOCKED-ON-EXTERNAL — these only progress when an inbound datagram or a peer window
  /// arrives, so forcing an immediate wake would busy-loop with no work actually possible):
  ///
  /// - [`Self::out`] (and the per-connection `classes[].outbound` staging buffers behind it) — the
  ///   driver drains [`Self::poll_transmit`] to exhaustion BEFORE consulting `poll_timeout`, so staged
  ///   bytes are already work-due-now; what remains in `outbound` is BLOCKED on a peer signal and only
  ///   retries when it arrives. Two distinct signals unblock it, both inbound-datagram-carried and both
  ///   surfaced via `stream_ready` (so a fresh entry there makes `has_pending_work` true for the pump
  ///   that signal woke): a `Writable` event (the peer relaxed `MAX_STREAM_DATA` / `MAX_DATA`, so the
  ///   flow-control window reopened) and an `Available { dir: Dir::Bi }` event (the peer raised
  ///   `MAX_STREAMS`, so a class whose send stream was RESET while bidi slots were exhausted can finally
  ///   reopen in `flush_outbound`). Neither is independent deferred state, so neither needs its own
  ///   `has_pending_work` arm.
  /// - The per-connection inbound `classes[].decoder` (frame-decode buffers) — only `ingest_recv`
  ///   feeds them, only from the `stream_ready` drain, which then drains EVERY complete frame in the
  ///   same pass; a decoder holds no undrained complete frame between passes EXCEPT when `ingest_recv`
  ///   stopped on its per-pass read budget with stream bytes still readable, in which case it defers
  ///   the connection onto `deferred_ready` — so that leftover read work is covered by the IMMEDIATE
  ///   `deferred_ready` arm above, not silently deferred. A decoder otherwise only gains bytes when an
  ///   inbound datagram arrives. The peer-opened recv stream is likewise adopted from an inbound
  ///   datagram via the `stream_ready` signal, not held as independent deferred state.
  fn has_pending_work(&self) -> bool {
    !self.pending_endpoint_events.is_empty()
      || !self.connected.is_empty()
      || !self.stream_ready.is_empty()
      || !self.deferred_ready.is_empty()
      || !self.lost.is_empty()
  }

  /// The deadline the driver should sleep until before pumping the bridge again: the earliest quinn
  /// timer across all connections — UNLESS [`Self::has_pending_work`] reports deferred immediate work,
  /// in which case an IMMEDIATE deadline (`now`) is returned so a `poll_timeout`-driven driver
  /// re-pumps at once instead of sleeping on a connection timer.
  ///
  /// `has_pending_work` is the single predicate that enumerates every deferred immediate-work queue
  /// (endpoint-event feedback, the coordinator-facing `connected` / `stream_ready` / `lost` queues,
  /// AND the `deferred_ready` leftover-read queue). A driver that sleeps until the connection-timer
  /// deadline would otherwise stop ONE pass before that work is applied — `Endpoint::handle_event`
  /// would never free quinn's slab / the cap slot, a queued `Connected` / readable / lost would sit
  /// unprocessed, and a half-drained receive stream would stall — until some unrelated event happened
  /// to wake it. Reporting an immediate deadline makes that deferred work observable as work-due-now.
  ///
  /// This cannot busy-loop in steady state: each pump pass DRAINS those queues (the service pass
  /// drains `pending_endpoint_events`; `drain_bridge` promotes `deferred_ready` into `stream_ready`
  /// then drains `connected` / `stream_ready` / `lost`), and a quiescent connection enqueues nothing
  /// onto any of them — a fully-drained receive stream re-defers nothing — so the predicate goes false
  /// and this returns the real next connection timer. Each leftover-read pump consumes a whole budget,
  /// so the `deferred_ready` re-defer makes forward progress every pass, never spins in place. The
  /// staged OUTBOUND datagrams ([`Self::out`]) need no analogous signal — the driver drains
  /// [`Self::poll_transmit`] to exhaustion before consulting `poll_timeout`, so those bytes are already
  /// work-due-now, never deferred to a future pass.
  ///
  /// `&mut self` because quinn's `Connection::poll_timeout` requires it.
  ///
  /// The earliest [`ConnEntry::auth_deadline`] across all connections is folded in as a CONNECTION
  /// TIMER — `min`'d with quinn's own earliest timer — NOT routed through [`Self::has_pending_work`]:
  /// it is a FUTURE deadline (a wake-up time), not immediate work due now. A `poll_timeout`-driven
  /// driver therefore sleeps until exactly the auth deadline and then re-pumps (firing `handle_timeout`
  /// → `service`), which reaps the still-`Authenticating` connection and frees its cap slot. Without
  /// this fold-in such a driver would sleep on quinn's idle timer — which the peer's keepalives keep
  /// refreshing — and never wake to reap the slot.
  pub(crate) fn poll_timeout(&mut self) -> Option<Instant> {
    if self.has_pending_work() {
      return Some(Instant::now());
    }
    min_opt(self.table.min_conn_timeout(), self.earliest_auth_deadline())
  }

  /// The earliest authentication deadline across all `Authenticating` connections, or `None` when none
  /// is pending. Folded into [`Self::poll_timeout`] as a connection timer so a sleeping driver wakes to
  /// reap a connection that authenticated its cert but never validated.
  fn earliest_auth_deadline(&self) -> Option<Instant> {
    self.table.earliest_auth_deadline()
  }

  /// Fire every connection's timers at `now`, then run a service pass so the
  /// resulting events and retransmits are collected.
  pub(crate) fn handle_timeout(&mut self, now: Instant) {
    for h in self.table.handles() {
      if let Some(e) = self.table.entry(h) {
        e.conn.handle_timeout(now);
      }
    }
    self.service(now);
  }

  /// Count of endpoint events fed back through `Endpoint::handle_event` — the observable the
  /// negative control asserts is non-zero after a handshake (the live caller is that test).
  #[cfg_attr(not(test), allow(dead_code))]
  pub(crate) fn endpoint_events_processed(&self) -> u64 {
    self.endpoint_events_processed
  }

  /// Count of outbound messages dropped by [`Self::write_framed`]'s size preflight because their
  /// encoded frame would exceed [`MAX_FRAME_LEN`]. Forwarded to the driver through the coordinator's
  /// public [`QuicCoordinator::oversized_outbound_dropped`](super::QuicCoordinator::oversized_outbound_dropped);
  /// the oversized-frame regression asserts a too-large message bumps this and is never framed/transmitted.
  pub(crate) fn oversized_dropped(&self) -> u64 {
    self.oversized_dropped
  }

  /// The number of connection closes attributed to `cause` so far — every teardown routes through
  /// the shared Closed-transition tail ([`Self::mark_closed_unbind_push`]), which counts exactly
  /// once per connection (the first transition wins; a peer loss racing a local close does not
  /// double-count). Forwarded to the driver through the coordinator's
  /// [`QuicCoordinator::conn_close_count`](super::QuicCoordinator::conn_close_count), mirroring the
  /// stream drivers' per-cause close observability.
  pub(crate) fn conn_close_count(&self, cause: CloseCause) -> u64 {
    self.close_counts[cause.index()]
  }

  /// The number of connections the quinn `Endpoint` still tracks in its slab. The reconnect-churn
  /// regression asserts this stays bounded: a `Drained` connection must be forwarded to
  /// `Endpoint::handle_event` so the endpoint frees its slab slot, not merely reaped from the table.
  #[cfg(test)]
  pub(crate) fn endpoint_open_connections(&self) -> usize {
    self.endpoint.open_connections()
  }

  /// The number of live entries in the local connection table (test observable for the churn and
  /// accept-cap regressions alongside [`Self::endpoint_open_connections`]).
  #[cfg(test)]
  pub(crate) fn table_len(&self) -> usize {
    self.table.handles().len()
  }

  /// The effective live-connection cap (test observable for the mutual-dial-mesh sizing test: the cap
  /// the coordinator derived from `replica_count` must cover the steady-state mesh).
  #[cfg(test)]
  pub(crate) fn max_connections(&self) -> usize {
    self.max_connections
  }

  /// The number of connections deferred on `deferred_ready` (a read that stopped on its per-pass
  /// budget with bytes still readable). The coordinator-level receive-pacing test reads this through
  /// the coordinator to know whether a buffered receive stream still has another budget to drain.
  #[cfg(test)]
  pub(crate) fn deferred_ready_len(&self) -> usize {
    self.deferred_ready.len()
  }

  /// Stage `bytes` directly into connection `h`'s `class` outbound buffer, as a prior partial/blocked
  /// write would have left them — WITHOUT routing each frame through `write_framed`. The
  /// coordinator-level receive-pacing test uses this to enqueue a large burst of tiny pre-framed
  /// frames on a bound connection, then flush them, so the peer buffers a multi-budget receive window.
  #[cfg(test)]
  pub(crate) fn stage_class_outbound(
    &mut self,
    h: ConnectionHandle,
    class: StreamClass,
    bytes: &[u8],
  ) {
    if let Some(e) = self.table.entry(h) {
      e.class_mut(class).outbound.extend(bytes.iter().copied());
    }
  }

  /// Pop the next connection that just reached `Connected`, for the coordinator to write its preface
  /// and start the identity-binding step.
  pub(crate) fn take_connected(&mut self) -> Option<ConnectionHandle> {
    self.connected.pop_front()
  }

  /// Drain this pump's stream-ready work as an ORDER-PRESERVING UNIQUE list: first fold in the reads
  /// deferred on the PREVIOUS pump ([`Self::deferred_ready`]), then drain `stream_ready`, collapsing
  /// duplicate handles to ONE entry. Called ONCE at the top of the coordinator's `drain_bridge`; the
  /// coordinator then reads each returned handle at most once this pump.
  ///
  /// The dedup is load-bearing for the one-budget-per-handle-per-pump bound. quinn pushes a fresh
  /// `Stream(Readable)` for EVERY received STREAM frame (see `Streams::received`), so a connection that
  /// took N datagrams' worth of stream data before this pump sits N times on `stream_ready`; popping
  /// each and reading a budget would drain N budgets in ONE pump — proportional to the buffered window,
  /// not to one budget. Collapsing to one entry per handle reads exactly one budget per connection per
  /// pump; a read that leaves bytes re-defers onto `deferred_ready` (NOT `stream_ready`, which is being
  /// drained now), so the rest waits for the next pump and `poll_timeout` reports immediate meanwhile.
  pub(crate) fn take_ready_unique(&mut self) -> Vec<ConnectionHandle> {
    // Deferred reads from the previous pump are processed alongside this pump's `stream_ready`.
    self.stream_ready.append(&mut self.deferred_ready);
    let mut seen: Vec<ConnectionHandle> = Vec::new();
    while let Some(h) = self.stream_ready.pop_front() {
      if !seen.contains(&h) {
        seen.push(h);
      }
    }
    seen
  }

  /// Pop a single `stream_ready` entry (no dedup, no `deferred_ready` fold-in). Not on the coordinator's
  /// drain path — that uses [`Self::take_ready_unique`]; this is a test observable for draining the
  /// queue one handle at a time.
  #[cfg(test)]
  pub(crate) fn take_stream_ready(&mut self) -> Option<ConnectionHandle> {
    self.stream_ready.pop_front()
  }

  /// Pop the next connection that just emitted `ConnectionLost`, for reaping.
  pub(crate) fn take_lost(&mut self) -> Option<ConnectionHandle> {
    self.lost.pop_front()
  }

  /// Pop the next `(handle, class, disposition)` whose CONTROL/Bulk recv took a deferred fatal close this
  /// pump (a graceful FIN, or an over-cap framing error behind a complete prefix) — its pre-fault frames
  /// are now queued in the decoder and must be DELIVERED before the teardown. The coordinator drains this
  /// AFTER pulling those queued frames via [`Self::next_frame`], then calls [`Self::finish_fin_close`]
  /// with the popped disposition to apply the recorded teardown. See [`Self::pending_fin_close`].
  pub(crate) fn take_pending_fin_close(
    &mut self,
  ) -> Option<(ConnectionHandle, StreamClass, FinDisposition)> {
    self.pending_fin_close.pop_front()
  }

  /// Run the deferred fatal-close teardown for `(h, class)` whose pre-fault frames the coordinator has
  /// now delivered, applying the `disposition` recorded at fault time (NOT re-derived from the class):
  /// - [`FinDisposition::Clean`] → the class-split via [`Self::close_fault_class`] — Control reaps the
  ///   whole connection, Bulk retires the stream in place (the SAME split an abandoned fatal applies,
  ///   only ordered AFTER delivery).
  /// - [`FinDisposition::Truncated`] → reap the WHOLE connection via [`Self::close_local`] for EITHER
  ///   class: a torn or over-cap frame is an unrecoverable framing failure (a partial Bulk frame must not
  ///   be silently dropped while the connection keeps running), the same whole-connection teardown the
  ///   inline framing-error path takes — only deferred so the complete prefix frames are delivered first.
  ///
  /// The recv `sid` is re-read from the entry; a `None` (already gone — e.g. a prior close in this same
  /// drain reaped it) is a no-op. Any `retire_peer_recv` credit/STOP/FIN this queues is collected by the
  /// coordinator's unconditional pump-end [`Bridge::service`].
  /// The SOLE producer choke for the deferred FIN queue, enforcing per-connection disposition
  /// PRECEDENCE: a whole-connection fatal (`OverCap`, `Truncated`) supersedes anything queued for
  /// the same handle. Without it, FIFO application lets a queued `Clean` reach the entry first
  /// (`close_fault_class` marks the connection `Closed` under `PeerClosed`), and the later fatal's
  /// `close_local` becomes an idempotent no-op that never counts — a real over-cap/torn recv fault
  /// silently attributed to a clean peer close. Delivery is unaffected by the purge: complete
  /// frames are delivered by `drain_bridge`'s frame drain, not by the queue entries. An `OverCap`
  /// already queued outranks an incoming `Truncated` (the over-cap rejection is the dominant
  /// protocol-violation fact — the same preference the inline classify applies); a `Clean` is
  /// skipped when any fatal is queued for the handle and deduplicated against an identical
  /// `(handle, class)` `Clean`.
  fn push_fin_close(
    &mut self,
    h: ConnectionHandle,
    class: StreamClass,
    disposition: FinDisposition,
  ) {
    match disposition {
      FinDisposition::OverCap | FinDisposition::Truncated => {
        if disposition == FinDisposition::Truncated
          && self
            .pending_fin_close
            .iter()
            .any(|(hh, _, d)| *hh == h && *d == FinDisposition::OverCap)
        {
          return;
        }
        self.pending_fin_close.retain(|(hh, _, _)| *hh != h);
        self.pending_fin_close.push_back((h, class, disposition));
      }
      FinDisposition::Clean => {
        let superseded = self
          .pending_fin_close
          .iter()
          .any(|(hh, cls, d)| *hh == h && (*d != FinDisposition::Clean || *cls == class));
        if !superseded {
          self
            .pending_fin_close
            .push_back((h, class, FinDisposition::Clean));
        }
      }
    }
  }

  pub(crate) fn finish_fin_close(
    &mut self,
    now: Instant,
    h: ConnectionHandle,
    class: StreamClass,
    disposition: FinDisposition,
  ) {
    // INV-1 at the choke-point: a deferred close is reached only AFTER `drain_bridge` ran this class's
    // `next_frame` delivery loop, so every complete frame the decode queued was delivered BEFORE this
    // teardown. The class decoder's ready queue is therefore empty here — the by-construction
    // postcondition of deliver-before-close. A future reorder that closed before delivering (or skipped
    // the drain on a non-empty decoder) trips this in debug, paying nothing in release. A `None` entry
    // (already reaped earlier in this same drain) has no decoder to check.
    debug_assert!(
      self
        .table
        .entry(h)
        .is_none_or(|e| !e.class_mut(class).decoder.has_ready()),
      "finish_fin_close: the class decoder's ready queue is empty — every complete frame was delivered \
       before the deferred teardown (INV-1)"
    );
    match disposition {
      // A framing failure tears down the whole connection regardless of class — the deferred twin of the
      // inline `close_local` framing-error path; the complete prefix frames were already delivered above.
      // The two fatal dispositions differ only in the attributed cause: a torn FIN vs an over-cap
      // declared length.
      FinDisposition::Truncated => self.close_local(now, h, CloseCause::TruncatedFrame),
      FinDisposition::OverCap => self.close_local(now, h, CloseCause::FrameTooLong),
      FinDisposition::Clean => {
        let Some(sid) = self.table.entry(h).and_then(|e| e.class_mut(class).recv) else {
          return;
        };
        // The return (`None` Control-reaped vs `Some` Bulk-retired) is irrelevant here: this is the
        // post-delivery teardown, not the in-loop read path, so there is no frame-pull to stop.
        let _ = self.close_fault_class(now, h, class, sid);
      }
    }
  }

  /// Whether connection `h` has any complete frame queued for delivery on EITHER class's decoder — the
  /// guard the fatal-recv close path reads to decide between reaping INLINE and DEFERRING. A fatal recv
  /// close ([`Self::ingest_recv`]) may reap inline (`return true`, which makes the coordinator's
  /// `drain_bridge` SKIP the per-class `next_frame` drain for this handle) ONLY when there is nothing to
  /// deliver: with a complete frame already queued — including one queued by the OTHER class earlier in
  /// the same pass — the close MUST instead be deferred so that frame is delivered first.
  fn has_pending_delivery(&mut self, h: ConnectionHandle) -> bool {
    self.table.entry(h).is_some_and(|e| {
      e.class_mut(StreamClass::Control).decoder.has_ready()
        || e.class_mut(StreamClass::Bulk).decoder.has_ready()
    })
  }

  /// The connection handle currently bound to `peer`, if any (the routing lookup).
  pub(crate) fn handle_for(&self, peer: Peer) -> Option<ConnectionHandle> {
    self.table.handle_for(peer)
  }

  /// The peer bound to connection `h`, if any. Used as the `from` when feeding a `Validated`
  /// connection's decoded consensus message to the endpoint.
  pub(crate) fn bound_peer_of(&mut self, h: ConnectionHandle) -> Option<Peer> {
    self.table.entry(h).and_then(|e| e.peer)
  }

  /// Record the attested STABLE [`MemberId`] the coordinator's binding policy resolved for connection
  /// `h`, alongside the slot-keyed [`bind_validated`](Self::bind_validated) routing bind. The two are
  /// set together at validation: the slot is the routing key, the member id is the cross-config
  /// invariant the membership-reconcile re-resolves. A no-op if the entry is gone.
  pub(crate) fn set_attested_member(&mut self, h: ConnectionHandle, member: MemberId) {
    if let Some(e) = self.table.entry(h) {
      e.member = Some(member);
    }
  }

  /// Snapshot of `(handle, attested member, bound routing peer)` for every VALIDATED connection,
  /// for the membership-reconcile pass. See [`ConnTable::validated_member_conns`].
  pub(crate) fn validated_member_conns(&self) -> Vec<(ConnectionHandle, MemberId, Peer)> {
    self.table.validated_member_conns()
  }

  /// Whether connection `h` is in the `Authenticating` phase (QUIC handshake done, identity not yet
  /// bound). The coordinator drives the `authenticate` step only for such connections.
  pub(crate) fn is_authenticating(&mut self, h: ConnectionHandle) -> bool {
    self.table.entry(h).is_some_and(|e| e.is_authenticating())
  }

  /// Whether connection `h` is in the `Validated` phase (identity bound; consensus frames flow).
  pub(crate) fn is_validated(&mut self, h: ConnectionHandle) -> bool {
    self.table.entry(h).is_some_and(|e| e.is_validated())
  }

  /// The peer this connection was DIALED to reach (`Some` on the connect path, `None` on accept).
  /// The binding policy requires the authenticated candidate to equal this on a dialed connection.
  pub(crate) fn dialed_expectation_of(&mut self, h: ConnectionHandle) -> Option<Peer> {
    self.table.entry(h).and_then(|e| e.dialed_expectation)
  }

  /// The peer certificate chain the TLS layer validated for connection `h`, as owned DER (empty when
  /// none was presented or the connection is gone). The coordinator feeds it to `authenticate` so a
  /// `CertOid` scheme can read the CA-attested identity extension out of the end-entity cert.
  pub(crate) fn peer_certs(&mut self, h: ConnectionHandle) -> Vec<CertificateDer<'static>> {
    let Some(e) = self.table.entry(h) else {
      return Vec::new();
    };
    // The rustls quinn backend's `peer_identity()` Any is a `Vec<CertificateDer<'static>>` (the
    // validated peer chain). Downcast it; anything else (or no identity) yields an empty chain.
    match e.conn.crypto_session().peer_identity() {
      Some(any) => any
        .downcast::<Vec<CertificateDer<'static>>>()
        .map(|b| *b)
        .unwrap_or_default(),
      None => Vec::new(),
    }
  }

  /// Every replica peer with a bound (validated) connection, except `except`. The coordinator's
  /// `Backups`/`AllReplicas` fan-out resolves against this — like the stream transport's router,
  /// it reaches only peers it actually holds a connection for, never a bare `0..replica_count`
  /// enumeration of addresses it may not have dialed.
  pub(crate) fn bound_replica_peers(&self, except: Option<Peer>) -> Vec<Peer> {
    self
      .table
      .peers()
      .filter(|p| p.is_replica() && Some(*p) != except)
      .collect()
  }

  /// Open this side's per-class bidi SEND streams and write `preface` as the FIRST frame on the
  /// CONTROL stream. Called by the coordinator on `Connected`, BEFORE any peer is bound, so the
  /// identity preface leads the Control stream. An empty `preface` (the `CertOid` scheme rides in
  /// the cert) opens the streams and marks the preface done without writing bytes. Idempotent: a
  /// no-op once the preface is done.
  ///
  /// The Control stream is ALWAYS opened first (class index 0); under `ControlBulk` the Bulk stream
  /// is opened second (class index 1, no preface). Opening Control-first fixes the per-class
  /// [`StreamId::index`] the peer reads back to assign each accepted stream to a class
  /// ([`Self::ingest_recv`]). The Control stream is given a HIGHER send priority than Bulk so quinn
  /// drains control bytes ahead of bulk bytes under flow-control pressure.
  ///
  /// Both roles open here. quinn lets either side open a bidi stream, so the dialer and the acceptor
  /// each open their OWN send halves immediately on `Connected` — neither waits on the other. The
  /// peer's streams (this side's READ halves) are adopted lazily in [`Self::ingest_recv`]. Under
  /// mutual dial this means each pair has two physical connections, each carrying the per-class send
  /// streams per side.
  ///
  /// The preface is frame-encoded (through the single [`Self::frame_checked`] size gate) and flushed
  /// immediately (a service pass at `now` turns it into datagrams) so the peer can authenticate this
  /// side without waiting on consensus traffic.
  ///
  /// The preface is supplied by [`IdentitySource::write_control_preface`](super::IdentitySource::write_control_preface),
  /// whose size contract is that it produce at most [`MAX_FRAME_LEN`] bytes (the provided `Hello` /
  /// `CertOid` schemes produce a few dozen bytes or none). An over-cap preface — only reachable through
  /// the `dangerous_custom_identity` escape hatch misusing that contract — cannot be framed without the
  /// peer fatally rejecting its declared length, so it is counted ([`Self::oversized_dropped`]) and the
  /// connection is torn down via [`Self::close_local`] rather than panicking or emitting an
  /// un-decodable frame.
  pub(crate) fn open_send_and_preface(
    &mut self,
    now: Instant,
    h: ConnectionHandle,
    preface: &[u8],
  ) {
    // Size-check + frame the preface through the single choke-point BEFORE opening streams. An empty
    // preface (the `CertOid` scheme) frames nothing. An over-cap preface is counted by `frame_checked`
    // and tears the connection down here rather than opening streams on a connection we will close.
    let framed_preface = if preface.is_empty() {
      None
    } else {
      match self.frame_checked(preface.len(), || preface) {
        Some(framed) => Some(framed),
        None => {
          self.close_local(now, h, CloseCause::FrameTooLong);
          return;
        }
      }
    };
    let opened = {
      let Some(e) = self.table.entry(h) else {
        return;
      };
      if e.preface_done {
        return;
      }
      // Control first (index 0). `open` returns `None` only when the concurrent-stream limit is
      // exhausted, which cannot happen for the first streams on a fresh connection
      // (`max_concurrent_bidi_streams` is 8).
      let control = StreamClass::Control;
      if e.class_mut(control).send.is_none() {
        match e.conn.streams().open(Dir::Bi) {
          Some(sid) => e.class_mut(control).send = Some(sid),
          None => return,
        }
      }
      // Control takes precedence over Bulk under flow-control pressure. `set_priority` only fails on
      // a closed stream, which the just-opened id is not.
      if let Some(sid) = e.class_mut(control).send {
        let _ = e
          .conn
          .send_stream(sid)
          .set_priority(class_priority(control));
      }
      // Bulk second (index 1) under ControlBulk; no preface rides Bulk.
      if e.layout.is_control_bulk() {
        let bulk = StreamClass::Bulk;
        if e.class_mut(bulk).send.is_none()
          && let Some(sid) = e.conn.streams().open(Dir::Bi)
        {
          e.class_mut(bulk).send = Some(sid);
          let _ = e.conn.send_stream(sid).set_priority(class_priority(bulk));
        }
      }
      // The Control stream is empty at this point (consensus frames are gated until `Validated`, and
      // a peer is never bound before then), so the preface frame is the first thing on the wire. It was
      // already size-checked + framed above through `frame_checked`.
      if let Some(framed) = framed_preface {
        e.class_mut(control).outbound.extend(framed);
      }
      e.preface_done = true;
      true
    };
    if opened {
      self.flush_outbound(now, h, StreamClass::Control);
      self.service(now);
    }
  }

  /// Bind the authenticated `peer` to connection `h` and promote it to [`Phase::Validated`], then
  /// flush any consensus frames that staged while it was authenticating. The coordinator calls this
  /// once its binding policy accepts the candidate; only after this do routing lookups
  /// ([`Self::handle_for`] / [`Self::bound_replica_peers`]) see the peer.
  ///
  /// **Last-established-wins, the mutual-dial pair kept, older excess reaped.** Under mutual dial a peer
  /// pair holds TWO physical connections — each side dials the other, so on this node `peer` validates on
  /// BOTH the connection THIS side dialed and the connection it ACCEPTED from `peer`. `bind_peer`
  /// re-points the `by_peer` routing index at the most-recently-validated handle (last-wins), so
  /// OUTBOUND traffic rides one of the two; the other connection's recv streams still deliver `peer`'s
  /// frames (the coordinator reads every `Validated` connection bound to a peer). Both are authenticated
  /// as `peer`, so neither of the two is torn down here — closing the "displaced" one would break the
  /// steady-state mesh.
  ///
  /// What IS bounded is the COUNT of live connections per peer ([`PER_PEER_CONN_LIMIT`]): after binding,
  /// the OLDEST live same-peer connections beyond the limit are reaped through [`Self::close_local`]. The
  /// reap is by creation recency ([`ConnEntry::seq`](super::conn::ConnEntry::seq)), so the just-bound `h`
  /// and its mutual-dial sibling (the two NEWEST) are never reaped — the steady-state pair survives by
  /// construction. This is the backstop against a flapping valid-cert member whose reconnects re-validate
  /// past the [`AUTH_DEADLINE`] gate (the const doc gives the full DoS argument); it bounds the count, it
  /// does not reap on a mere rebind.
  pub(crate) fn bind_validated(&mut self, now: Instant, h: ConnectionHandle, peer: Peer) {
    // Idempotency guard, symmetric with `close_local`'s `is_closed` early-return: the validate transition
    // moves a connection FROM `Handshaking`/`Authenticating` TO `Validated`, so a handle already AT the
    // post-state (`Validated`) or torn down (`Closed`) is not re-validated — a duplicate preface frame, or
    // a validate racing a close, is a no-op rather than re-running the reap/flush or resurrecting a closed
    // connection. (Both pre-states are admitted: production validates from `Authenticating`; the bridge's
    // white-box tests drive the table directly from `Handshaking`.)
    if self
      .table
      .entry(h)
      .is_none_or(|e| e.is_validated() || e.phase.is_closed())
    {
      return;
    }
    // Bind `h` as peer's canonical routing slot and SELECT the per-peer excess to reap, grouped in the
    // table's `validate_routing` (bind_peer + excess_peer_conns sequenced exactly as before). The
    // selection EXCLUDES `h`, so the just-bound connection is never a reap candidate even when it is the
    // oldest by `seq` (a slow/split Hello can validate LATE — well after newer reconnects already
    // validated — so insertion recency does NOT track validation recency). The returned handles are the
    // stale OLDEST same-peer excess; closing them through the shared choke-point bounds the per-peer live
    // COUNT to `PER_PEER_CONN_LIMIT`. Empty in the common (within-bound) case.
    let stale = self.table.validate_routing(h, peer, PER_PEER_CONN_LIMIT);
    let mut tail_frame_error = false;
    let mut tail_truncated_partial = false;
    if let Some(e) = self.table.entry(h) {
      e.phase = Phase::Validated;
      // Validated: clear the authentication deadline so this connection is never a reap candidate.
      e.auth_deadline = None;
      // Lift the Control recv decoder from the small pre-authentication cap (`MAX_HELLO_LEN`) to the full
      // `MAX_FRAME_LEN`: post-validation Control carries consensus messages (PrepareOk, votes, small
      // Prepares) that legitimately reach the frame limit, so the hello-sized cap must not survive into
      // the consensus phase or it would wrongly reject a large Control frame. `set_max` only raises the
      // bound — it does not disturb any already-buffered partial or queued frame, so a consensus frame
      // that began arriving in the SAME batch as the hello continues to decode. Bulk was never capped
      // below the full limit (it carries no pre-auth frame).
      let control = e.class_mut(StreamClass::Control);
      control
        .decoder
        .set_max(decoder_max(StreamClass::Control, Phase::Validated));
      // Re-evaluate the pipelined pre-auth tail under the now-raised cap through the SAME shared
      // decode+classify step the live read uses (`use_extend_first = false`: the decoder is now at the
      // final cap, so the tail decodes as ordinary frames). Decoding its COMPLETE frames onto the ready
      // queue immediately is the second half of the cap-raise ("the hello cap no longer applies; admit the
      // buffered tail at the real limit"). On the steady (non-FIN) Control stream this only decodes the
      // tail a pump earlier than the `stream_ready` re-read below would; it MATTERS for a pre-auth
      // graceful FIN, whose recv stream quinn frees after the FIN read so no second read can re-drive the
      // decode — the tail must be drained HERE so `drain_bridge`'s same-pass frame drain delivers it before
      // the deferred FIN reap. Feeding `&[]` adds no new bytes, only draining what `extend_first` buffered.
      // A tail frame over `MAX_FRAME_LEN` was already rejected by `extend_first`'s prefix guard, so this
      // cannot legitimately fail; but a framing error here is still fatal — recorded so the connection is
      // DEFERRED for the post-delivery reap (below), never closed synchronously while the hello + any
      // complete tail frames are still queued for `drain_bridge` to deliver.
      let tail_rec = decode_and_classify(&mut control.decoder, &[], false);
      tail_frame_error = tail_rec.frame_error;
      tail_truncated_partial = tail_rec.truncated_partial;
      // I7: the auth deadline was just cleared and `h` is no longer `Authenticating` (it is `Validated`),
      // so the deadline-present-iff-authenticating biconditional holds for this entry.
      debug_assert!(
        e.auth_deadline.is_some() == e.is_authenticating(),
        "validate: a validated entry carries no auth deadline (I7)"
      );
    }
    if tail_frame_error {
      // A buffered tail that fails to decode even at `MAX_FRAME_LEN` is a framing violation (a
      // hostile/buggy peer, outside the non-Byzantine threat model). DEFER the whole-connection reap
      // through `pending_fin_close` (a `Truncated` disposition) rather than closing synchronously here: the
      // connection just validated, and `drain_bridge`'s same-pass `next_frame` loop must still deliver the
      // hello and any COMPLETE tail frames the cap-raise decoded above BEFORE the reap — a synchronous
      // close would tear the connection down with those frames still queued.
      //
      // This branch is DEFENSIVE: `extend_first`'s prefix guard already rejected an over-`MAX_FRAME_LEN`
      // tail during the pre-auth read (against the same constant the raised cap checks), so a tail that
      // reaches here over-declaring at the raised cap is unconstructable through the live decode path.
      // When it IS reachable, `ingest_recv` already recorded a disposition for `h` — the choke's
      // per-connection precedence keeps exactly one, with the fatal winning.
      self.push_fin_close(h, StreamClass::Control, FinDisposition::OverCap);
      return;
    }
    if tail_truncated_partial {
      // The raised-cap re-decode proves the retained tail is TORN at the FINAL cap. Whether that is a
      // fault depends on whether the stream already FINISHED: `ingest_recv` classified the pre-auth
      // `[hello][partial tail][FIN]` shape as a Clean FIN (a non-zero partial behind a complete hello
      // is normally the legitimately-retained pipelined tail — ambiguous under the small cap), and
      // that queued Clean is the FIN's only record. UPGRADE it to `Truncated` so the reap is
      // attributed to the torn frame, not to a clean peer close. With NO queued Clean the stream has
      // not finished — the partial is an in-flight frame whose remaining bytes are still coming, so
      // nothing is recorded (a later FIN classifies it at the final cap directly).
      if let Some(entry) = self.pending_fin_close.iter_mut().find(|(hh, cls, d)| {
        *hh == h && *cls == StreamClass::Control && *d == FinDisposition::Clean
      }) {
        entry.2 = FinDisposition::Truncated;
      }
    }
    // Close the selected stale excess through the shared teardown choke-point (issues the quinn `close`
    // so each drains to `Drained` and frees its slab + cap slot). `h` is never in this set.
    for stale_h in stale {
      self.close_local(now, stale_h, CloseCause::Superseded);
    }
    // DEFENSIVE (idempotent): each `close_local` above already recovers routing in its teardown tail, so
    // `by_peer[peer]` is restored before this runs. Kept as the localized invariant anchor — re-point an
    // empty slot at the newest live same-peer handle — and run AFTER the closes so it (and the assert
    // below) sees the post-close routing state. A no-op in the steady case (the slot already points at `h`).
    self.table.promote_routing_if_unbound(peer);
    // Postcondition asserts (the consolidation's tripwire): the validate transition leaves the four
    // coupled state pieces jointly consistent. These encode guarantees the tests already prove; a future
    // reorder that broke one would trip here in debug, paying nothing in release.
    debug_assert!(
      self.table.routing_is_live(peer),
      "validate: peer routing is consistent after the reap — no dangling slot, no live-but-unrouteable \
       peer (I1 + I2)"
    );
    debug_assert!(
      self.table.live_peer_count(peer) <= PER_PEER_CONN_LIMIT,
      "validate: the per-peer live connection count is within its bound after the reap (I3)"
    );
    debug_assert!(
      self
        .table
        .entry(h)
        .is_some_and(|e| { e.is_validated() && e.peer == Some(peer) && e.auth_deadline.is_none() }),
      "validate: the just-validated entry is Validated, bound to peer, with no auth deadline (I6 + I7)"
    );
    // Flush BOTH classes: a consensus frame may have staged on Control or Bulk while authenticating.
    let mut progressed = self.flush_outbound(now, h, StreamClass::Control);
    progressed |= self.flush_outbound(now, h, StreamClass::Bulk);
    if progressed {
      self.service(now);
    }
    // Schedule a post-validation READ of `h`: while `Authenticating`, `ingest_recv` SKIPS the Bulk
    // class (only Control carries the identity preface), so any Bulk bytes the peer already sent are
    // adopted-but-unread, backpressured in quinn. Nothing else schedules them: `Readable` fires
    // per-received-STREAM-frame, and if the peer's Hello and its Bulk bytes arrived in the SAME
    // readiness edge that edge is already consumed — without this enqueue the buffered Bulk would sit
    // UNREAD until unrelated later stream traffic woke the connection (a stranded-data liveness bug).
    // Enqueueing `h` on `stream_ready` makes the NEXT pump's `ingest_recv` read the now-allowed Bulk
    // class (the bytes are buffered, never dropped, so the forced read delivers them); `has_pending_work`
    // counts `stream_ready`, so a `poll_timeout`-driven driver re-pumps at once and reads the Bulk with
    // NO external traffic. A no-op for `Single` (no Bulk recv stream) and harmless when no Bulk is
    // buffered (an empty read).
    self.stream_ready.push_back(h);
  }

  /// The shared teardown tail run by BOTH the local-fatal close ([`Self::close_local`]) and the
  /// peer-initiated loss (the `Event::ConnectionLost` arm of [`Self::on_app_event`]): mark the entry
  /// `Closed`, clear its authentication deadline, unbind routing, RECOVER routing to a live same-peer
  /// sibling if one remains, and queue the handle for the reap. Consolidating these coupled mutations in
  /// one place is what makes the close-time invariants hold BY CONSTRUCTION — a reorder or an omission on
  /// one path cannot drift from the other:
  ///
  /// - **`I10` (atomic teardown).** Phase → `Closed` and routing → unbound happen together, so a closed
  ///   connection is unrouteable the instant it is torn down (the entry is KEPT for the drain; only the
  ///   `by_peer` slot is cleared — [`ConnTable::unbind`], not `remove`). The handle is queued on `lost`
  ///   so the coordinator's reap and the next service pass collect it.
  /// - **`I2` (routing present iff a live same-peer entry exists).** `unbind` clears `by_peer[p]` only
  ///   when it pointed at `h`; if it did, re-point it at the NEWEST live same-peer connection
  ///   ([`ConnTable::promote_routing_if_unbound`]) so a peer holding a still-validated mutual-dial
  ///   sibling keeps an outbound route across the loss rather than going unrouteable until a re-dial
  ///   validates. `p` is captured from `entry.peer` BEFORE the unbind; `peer == None` (a `Handshaking`
  ///   connection torn down before binding) has nothing to recover.
  /// - **`I7` (deadline biconditional).** Leaving `Authenticating` clears `auth_deadline`: a `Closed`
  ///   entry's now-past deadline must never contribute to `poll_timeout`, since `now.max(past)` is inert
  ///   and the connection would never reach quinn's future drain timer. ([`ConnTable::earliest_auth_deadline`]
  ///   also filters to `Authenticating` entries; clearing here is defense in depth.)
  ///
  /// Does NOT issue the quinn `close` — that is the local-fatal caller's job (a peer-initiated loss is
  /// already draining). A missing entry still unbinds + queues `lost` (a harmless no-op against the later
  /// reap). Does NOT call `service` (see [`Self::close_local`]'s non-recursion note).
  fn mark_closed_unbind_push(&mut self, h: ConnectionHandle, cause: CloseCause) {
    // Capture the peer BEFORE the teardown: the routing recovery below must promote a sibling for the
    // peer this handle carried, and `unbind` does not change `entry.peer`, but reading it up front keeps
    // the promote independent of any later mutation. `None` for a `Handshaking` connection that never
    // bound a peer — nothing to recover.
    let peer = self.table.entry(h).and_then(|e| e.peer);
    if let Some(e) = self.table.entry(h) {
      // Per-cause close observability, counted exactly once per connection at the Closed
      // TRANSITION: a peer loss racing an already-issued local close (or any repeated teardown of
      // the same handle) finds the entry already `Closed` and does not re-count — the first cause
      // to tear the connection down is the one recorded.
      if !e.phase.is_closed() {
        self.close_counts[cause.index()] += 1;
      }
      e.phase = Phase::Closed;
      e.auth_deadline = None;
      // I7: leaving `Authenticating` for `Closed` clears the deadline, so the
      // deadline-present-iff-authenticating biconditional holds (`false == false`). This is the shared
      // Closed-exit for BOTH the local-fatal close and the peer-initiated loss, so one assert covers
      // both close-time `auth_deadline` mutation sites.
      debug_assert!(
        e.auth_deadline.is_some() == e.is_authenticating(),
        "close: a Closed entry carries no auth deadline (I7)"
      );
    }
    self.table.unbind(h);
    // I2 routing recovery: if `h` was the peer's OUTBOUND route (`by_peer[p] == h`), `unbind` just
    // cleared the slot — re-point it at a live same-peer sibling so a peer holding a still-validated
    // mutual-dial connection is never left unrouteable across the loss. `h` is now `Closed`, so `promote`
    // skips it and lands on the newest live same-peer handle; a no-op when the slot stayed bound (`h` was
    // not the route) or no live sibling remains. `peer == None` (no peer ever bound) skips it entirely.
    if let Some(p) = peer {
      self.table.promote_routing_if_unbound(p);
      // I2 after the teardown: either the slot points at a live same-peer entry (the promoted sibling),
      // or no live same-peer entry remains and the slot is empty — never live-but-unrouteable.
      debug_assert!(
        self.table.routing_is_live(p),
        "close: peer routing recovers to a live sibling (or clears with no live sibling) — I2"
      );
    }
    self.lost.push_back(h);
  }

  /// Tear down connection `h` for a LOCAL fatal decision: issue the quinn `close` at `now`, then run the
  /// shared teardown tail ([`Self::mark_closed_unbind_push`] — phase → `Closed`, unbind routing, queue
  /// `lost`). A subsequent `service` pass flushes the CONNECTION_CLOSE into `out`.
  ///
  /// This is the SINGLE choke-point for every local-fatal teardown (the binding policy's rejection, a
  /// Control-class overflow / dead send half, an inbound framing error, the auth-deadline reap, the
  /// rebind teardown). Issuing the quinn `close` is load-bearing: it arms the connection's drain timer,
  /// so the service pump later drives it to `EndpointEvent::Drained` and the endpoint frees its slab slot,
  /// CID/reset-token indexes, and connection-cap slot. A teardown that only unbound routing would never
  /// drain (the peer may keep the connection alive with keepalives), pinning that state indefinitely.
  ///
  /// **Non-recursive: state mutation only — it does NOT call `service`.** `close_local` is reached both
  /// from outside a `service` pass and from INSIDE one (the auth-deadline reap loop, the Control-class
  /// fatals in [`Self::on_app_event`] / [`Self::ingest_recv`] / [`Self::flush_outbound`]). An inline
  /// `service` would re-enter `service` — and a mass simultaneous auth-deadline expiry would recurse once
  /// per close. Instead the systematic service-after-every-pump collects the CONNECTION_CLOSE: the
  /// coordinator's `pump` runs ONE unconditional `service` at pump end. Queuing `lost` also makes
  /// [`Self::has_pending_work`] true, so a `poll_timeout`-driven driver re-pumps at once to flush a close
  /// issued from `service`'s own reap. (The bridge's white-box tests run a `service` / pump step after a
  /// direct `close_local` to mirror that collection.)
  ///
  /// Idempotent: a second call on an already-`Closed` entry is a no-op (the phase check prevents a
  /// duplicate `close` / `lost` push / `unbind`).
  pub(crate) fn close_local(&mut self, now: Instant, h: ConnectionHandle, cause: CloseCause) {
    if let Some(e) = self.table.entry(h) {
      if e.phase.is_closed() {
        return;
      }
      // Issue the quinn `close` FIRST (arms the drain timer), then run the shared teardown tail. A
      // peer-initiated loss skips this close (it is already draining) but shares the same tail.
      e.conn.close(now, VarInt::from_u32(1), bytes::Bytes::new());
    }
    self.mark_closed_unbind_push(h, cause);
    // No `service` here (see the non-recursion note above): the CONNECTION_CLOSE is collected by the next
    // service pass — the coordinator's pump-end `service`, or the immediate re-pump a `poll_timeout`-driven
    // driver makes because `lost` is now non-empty (`has_pending_work`).
  }

  /// The SINGLE size-checked framing primitive: every encode-and-stage path runs through here, so the
  /// `MAX_FRAME_LEN` preflight lives in exactly one place. `len` is the payload length the caller
  /// computes BEFORE `payload` runs (`view.encoded_len()` for an already wire_size_bound-ADMITTED
  /// consensus message — see `write_framed` — or `preface.len()` for the identity preface); `payload`
  /// produces the bytes ONLY when `len` is within the cap, so a message THIS check alone catches
  /// never additionally pays for `encode_to_bytes`.
  ///
  /// Returns the framed `[u32 len][payload]` bytes, or `None` when `len` exceeds [`MAX_FRAME_LEN`] OR
  /// the bytes `payload` actually produces do. NEITHER check here is a safe ADMISSION gate on its own
  /// for an unbounded `len`: buffa's `encoded_len()` returns a `u32` with unchecked accumulation, so a
  /// message nearing 4 GiB could wrap `len` below the cap — and `payload` (`encode_to_bytes`) then
  /// RUNS and pays for the full multi-GiB allocation before the second (`bytes.len()`) check ever gets
  /// a chance to reject it. A consensus-message caller therefore gates admission BEFORE reaching this
  /// function at all (`write_framed`'s `msg.wire_size_bound()` check, computed structurally from the
  /// message's own fields with saturating arithmetic throughout, so it never wraps); both checks here
  /// remain as cheap framing-correctness backstops for that caller, and are the ONLY (sufficient)
  /// admission gate for the identity-preface caller, whose `preface.len()` is bounded by a small
  /// compile-time constant (`crate::transport::labeled::MAX_HELLO_LEN`-scale) nowhere near the wrap
  /// boundary. Either refusal path bumps [`Self::oversized_dropped`] and frames/stages
  /// nothing: the RECEIVE side (`FrameDecoder` / [`Self::ingest_recv`]) tears the connection down on
  /// an over-cap declared length, so emitting such a frame could only force the peer to close.
  /// Surfacing the drop via the counter (rather than silently swallowing) lets a driver/operator see a
  /// unit outgrew the transport frame limit; consensus retransmission covers a dropped consensus send,
  /// and an oversized unit could never deliver regardless.
  fn frame_checked<T: AsRef<[u8]>>(
    &mut self,
    len: usize,
    payload: impl FnOnce() -> T,
  ) -> Option<Vec<u8>> {
    if len > MAX_FRAME_LEN as usize {
      self.oversized_dropped = self.oversized_dropped.saturating_add(1);
      return None;
    }
    let produced = payload();
    let bytes = produced.as_ref();
    // Backstop: re-check the length `payload` ACTUALLY produced (see the doc comment above for why
    // `len` alone cannot be trusted).
    if bytes.len() > MAX_FRAME_LEN as usize {
      self.oversized_dropped = self.oversized_dropped.saturating_add(1);
      return None;
    }
    let mut framed = Vec::new();
    encode_frame(bytes, &mut framed);
    Some(framed)
  }

  /// Frame-encode `msg` and write it to connection `h`'s `class` bidi SEND stream. The framed bytes
  /// are always appended to the BACK of that class's strict-FIFO `outbound`, then a single
  /// front-draining flush attempts to push the buffer into the class's stream. Appending first
  /// (never writing a fresh frame ahead of already-staged bytes) is what keeps on-wire frame order
  /// equal to call order: when nothing is staged the new frame is the whole buffer and is written
  /// immediately; when an earlier frame is still staged (a prior `Blocked` / partial write) the new
  /// frame queues behind it. Whatever the stream cannot accept (no send stream yet, or `Blocked`)
  /// stays at the front for the next `Writable` retry. The service pass that turns the written
  /// stream bytes into datagrams is DEFERRED ([`Self::needs_service`]): the coordinator routes
  /// per-message through here and runs ONE pump-end `service`, which collects every message this
  /// pump wrote in a single whole-table pass.
  ///
  /// The COORDINATOR picks `class` via [`partition`](super::layout::partition); the bridge only
  /// routes to the right per-class buffer. Per-stream backpressure and fatals are CLASS-AWARE:
  /// - **Bulk** overflow (outbound exceeds [`PER_CLASS_OUTBOUND_CAP`]): reset just the Bulk send
  ///   stream (buffer cleared, stream reopened on the next write). The connection and Control
  ///   survive; consensus retransmission re-drives the dropped message.
  /// - **Control** overflow: reap the whole connection (phase → `Closed`, pushed onto `lost`).
  ///   Control frames carry consensus; a Control overflow means the peer is not consuming
  ///   consensus traffic, and reopening Control at a higher StreamId index would make the peer's
  ///   [`class_of_index`] assign it to Bulk — silently black-holing consensus. A full redial is
  ///   safer: the fresh connection reopens Control at index 0.
  ///
  /// Consensus frames are gated behind identity: a frame is staged ONLY on a `Validated` connection.
  /// While a connection is not yet `Validated` — or once it is `Closed` — `write_framed` stages
  /// NOTHING, so no consensus byte rides out ahead of the identity preface / before the peer is bound,
  /// and no byte is staged onto a connection on its way out. In practice the coordinator's router
  /// cannot even reach a non-`Validated` connection (a peer is bound only at `Validated`, and a local
  /// close unbinds routing atomically), so this gate is a defense-in-depth backstop on top of that.
  pub(crate) fn write_framed(
    &mut self,
    now: Instant,
    h: ConnectionHandle,
    class: StreamClass,
    msg: &Message,
  ) {
    // Defense in depth: NEVER frame or stage onto a non-`Validated` entry. A `Closed` connection has
    // already unbound its routing (so the router cannot resolve it), and an `Authenticating`/`Handshaking`
    // one is not yet bound; staging to either would grow a doomed connection's outbound buffers. The
    // router never reaches such a connection, so this is a structural guard, not a hot path. Frame
    // nothing (and pay no `encode_message`) when the entry is absent or not `Validated`.
    if !self.is_validated(h) {
      return;
    }
    // ADMISSION gate, BEFORE building the pb view at all: `msg.wire_size_bound()` is a saturating
    // `usize` upper bound computed from `msg`'s own fields, so it can never wrap the way buffa's
    // `u32`-returning `encoded_len()` can on an absurd (multi-GiB) variable-length field. Gating here
    // means an oversized message never even reaches `pb_message`/`encode_to_bytes` below — closing
    // the hazard where a wrapped `encoded_len()` estimate would pass a preflight and only THEN pay
    // for (and OOM/panic on) a multi-GiB allocation.
    if msg.wire_size_bound() > MAX_FRAME_LEN as usize {
      self.oversized_dropped = self.oversized_dropped.saturating_add(1);
      return;
    }
    // Admitted: size-check + frame through the single `frame_checked` choke-point (mirrors the
    // byte-stream router's symmetric cap). The wire view is built ONCE here and reused for both the
    // preflight length and the encode `frame_checked` runs on success, rather than rebuilding it per
    // send. `frame_checked`'s own `len > MAX_FRAME_LEN` check is now unreachable via oversize (an
    // admitted message's `encoded_len()` is bounded by `wire_size_bound()`, itself `<= MAX_FRAME_LEN`
    // here), but is retained cheaply — it is shared with the identity-preface caller, and its
    // post-encode backstop (`bytes.len() > MAX_FRAME_LEN`) remains the framing-correctness assertion
    // of last resort. `None` ⇒ refused there, already counted.
    use buffa::Message as _;
    let view = crate::wire::pb_message(msg);
    let Some(framed) = self.frame_checked(view.encoded_len() as usize, || view.encode_to_bytes())
    else {
      return;
    };
    // Per-stream backpressure, class-aware (see the fn doc): a Bulk overflow resets just that stream, a
    // Control overflow reaps the whole connection.
    {
      let Some(e) = self.table.entry(h) else {
        return;
      };
      if e
        .class_mut(class)
        .outbound
        .len()
        .saturating_add(framed.len())
        > PER_CLASS_OUTBOUND_CAP
      {
        match class {
          StreamClass::Bulk => self.reset_send_class(h, class),
          StreamClass::Control => {
            self.close_local(now, h, CloseCause::OutboundOverflow);
            return;
          }
        }
      }
    }
    {
      let Some(e) = self.table.entry(h) else {
        return;
      };
      e.class_mut(class).outbound.extend(framed);
    }
    // Flush the staged frame, then DEFER the service pass UNCONDITIONALLY (not gated on the flush's
    // progress): a Bulk overflow above queued a `RESET_STREAM` that reaches `out` only when a
    // `service` polls the connection, and the follow-on flush's reopen can make no write progress
    // (it can fail or block), so gating on its return would strand that reset. The pass itself is
    // deferred to the coordinator's single pump-end `service` (which always follows the per-message
    // routing this is called from) rather than run inline per message — an inline pass would be
    // O(messages × connections) of redundant whole-table quinn polling per pump. Within-pump
    // visibility holds: everything staged here reaches `out` before the pump returns.
    self.flush_outbound(now, h, class);
    self.needs_service = true;
  }

  /// Run a `service` pass at `now` iff the per-message write path deferred one
  /// ([`Self::needs_service`]) — the white-box stand-in for the coordinator's pump-end `service`,
  /// for tests that drive [`Self::write_framed`] directly and then inspect `out`. Using this (rather
  /// than an unconditional `service`) keeps the flag load-bearing under test: a `write_framed` that
  /// failed to set it would leave its datagrams stranded and fail the test.
  #[cfg(test)]
  pub(crate) fn service_if_deferred(&mut self, now: Instant) {
    if self.needs_service {
      self.service(now);
    }
  }

  /// The CLASS-AWARE teardown for a fatal recv close on connection `h`'s `class` (peer recv `sid`),
  /// shared by the ABANDONED (immediate) and GRACEFUL-FIN (deferred-after-delivery) paths so the
  /// reap-vs-retire split lives in ONE place (the I9 mirror of the SEND-side Control fatals).
  ///
  /// - **Control** → `close_local` the WHOLE connection (a dead index-0 Control recv is unrecoverable in
  ///   place — a reopened peer stream lands at a higher index, which maps to Bulk; a redial reopens
  ///   Control at index 0). Returns `None` to tell the caller the connection is gone.
  /// - **Bulk** → retire just this class in place: [`retire_peer_recv`] closes both halves (the recv half
  ///   is already freed by the read/FIN, so this `finish`es our UNUSED send half so the stream leaves
  ///   quinn's accounting and the peer re-grants `MAX_STREAMS`), then drop the recv id and reset the
  ///   decoder to its class cap (it reopens at a higher index on the peer's next `Opened`); the OTHER class
  ///   and the connection stay alive. Returns `Some(should_service)` — `retire_peer_recv`'s queued
  ///   `STOP_SENDING`/credit/FIN reach the wire only via a later `poll_transmit`, so the caller folds the
  ///   flag into its post-loop `service`.
  fn close_fault_class(
    &mut self,
    now: Instant,
    h: ConnectionHandle,
    class: StreamClass,
    sid: StreamId,
  ) -> Option<bool> {
    if class == StreamClass::Control {
      self.close_local(now, h, CloseCause::PeerClosed);
      return None;
    }
    let Some(e) = self.table.entry(h) else {
      return Some(false);
    };
    let should_service = retire_peer_recv(e, sid);
    let max = decoder_max(class, e.phase);
    let st = e.class_mut(class);
    st.recv = None;
    st.decoder = FrameDecoder::new(max);
    Some(should_service)
  }

  /// Adopt every pending peer-opened recv stream, read each readable class into its decoder through the
  /// shared [`decode_and_classify`] step, and classify any fatal close.
  ///
  /// The returned `bool` means strictly: **this call REAPED the connection INLINE — through
  /// [`Self::close_local`], with NOTHING queued to deliver on either class.** It is `true` ONLY for an
  /// abandoned fatal (peer RESET / `ClosedStream`, whose bytes are discarded) or a `Truncated` close that
  /// found neither this class's ready queue nor the other class's holding any complete frame
  /// ([`Self::has_pending_delivery`]). Every DEFERRED close — a graceful FIN, or a framing error behind
  /// queued frames — instead records its disposition on [`Self::pending_fin_close`] and returns `false`,
  /// so the connection is reaped only AFTER the coordinator's `next_frame` drain delivers the queued
  /// frames. A non-fatal read (would-block, or progress made) also returns `false`.
  ///
  /// So `drain_bridge`'s `if ingest_recv(h) { continue; }` is a skip of a PROVABLY-EMPTY frame drain (the
  /// entry is now `Closed` and its decoders held nothing), NOT a skip that could drop a queued frame —
  /// the deliver-before-close guarantee holds by construction.
  pub(crate) fn ingest_recv(&mut self, now: Instant, h: ConnectionHandle) -> bool {
    let Some(e) = self.table.entry(h) else {
      return false;
    };
    if e.phase.is_closed() || e.phase.is_handshaking() {
      return false;
    }
    // Set whenever a quinn mutation here queues a transmit/credit/control frame that must reach `out`
    // THIS pump: a peer-opened-stream retire (`retire_peer_recv`: a `STOP_SENDING` + recovered
    // flow-control credit, and the empty FIN closing our unused send half) — at the accept-loop boundary
    // AND in the read-side `Reset` arm below — and every per-class read whose `finalize` freed the peer's
    // window (`MAX_DATA` / `MAX_STREAM_DATA`). A single `service(now)` after the borrows are released
    // drains all of it into `out`; without it the frames sit in quinn (not in `out`, not in
    // `has_pending_work`), so a `poll_timeout`-driven driver would not transmit them until unrelated
    // activity woke it.
    let mut should_service = false;
    // Adopt every pending peer-opened bidi stream, assigning each to a class by its StreamId index
    // (index 0 → Control, any higher index → Bulk; see `class_of_index`). `accept` returns `None`
    // once none are pending.
    //
    // A later accepted Bulk id (after the peer RESET its Bulk send stream — a PER_CLASS_OUTBOUND_CAP
    // overflow or a Stopped/ClosedStream on its side — and reopened it at a HIGHER index) replaces the
    // prior one. That replacement is a clean STREAM BOUNDARY: the old recv stream is dead, and its
    // decoder may hold a partial frame from a frame that was mid-transfer when the old stream reset.
    // Two things must happen at the boundary, BEFORE overwriting `recv`, or the read-side `Reset` arm
    // (which would do them) is never reached because the recv id was already replaced:
    //   (a) RETIRE the old peer-opened stream via `retire_peer_recv` — STOP its recv half (discarding
    //       unread data and FREEing its flow-control window/credit, else the orphaned per-stream window
    //       stays pinned for the connection's life) AND `finish` our UNUSED send half. Closing only the
    //       recv half leaves the accepted stream half-open in quinn's remote-stream accounting, so it
    //       never retires and the peer never re-grants `MAX_STREAMS` — after enough peer Bulk
    //       reset/reopen churn the opener's `open(Dir::Bi)` stays exhausted and staged frames strand;
    //       and
    //   (b) RESET that class's decoder, so the stale partial does not get prepended to the new
    //       stream's first bytes (which would misframe the new stream → a spurious `FrameTooLong`
    //       teardown or a misaligned consensus frame).
    // Pre-`Validated`, the Bulk class is NOT read (only Control carries the identity preface), so a
    // Bulk-class peer-opened stream is ADOPTED (its recv id stored so the stream is not lost) but its
    // BYTES are left unread (backpressured) until `Validated`. The retire-on-replace below still runs
    // pre-auth: it retires the OLD (replaced, DEAD) stream — the one the peer already RESET and reopened
    // at a higher index — NOT the live surface. Retiring the dead stream regrants only the credit for the
    // bytes IT already received; the NEW `sid` stays unread, so the surface the withholding peer is
    // streaming remains backpressured (no `MAX_STREAM_DATA` on it). Skipping the retire would instead
    // ORPHAN the old recv half: it would pin its per-stream window and never leave quinn's remote-stream
    // accounting (the peer never re-grants `MAX_STREAMS`), and a second pre-auth Bulk replacement would
    // leak the prior one — so the retire is required in BOTH phases. The only pre-auth difference is that
    // the new stream's bytes are not READ until `Validated`.
    while let Some(sid) = e.conn.streams().accept(Dir::Bi) {
      let class = class_of_index(sid);
      // `Single` is a Control-ONLY receive fence. The send side already routes everything to Control
      // under `Single` (`partition` returns `Control`, and `open_send_and_preface` opens no Bulk send),
      // so a `Single` connection MUST never see a Bulk-class (index ≥ 1) peer-opened stream. A
      // version-skew or buggy valid-cert peer that ran `ControlBulk` and opened its second (Bulk) stream
      // to us is OUTSIDE the `Single` contract: that surface is unconfigured here, so adopting it would
      // let it push consensus/malformed frames or extra flow-control pressure over a class we never agreed
      // to read. REFUSE just that stream — `retire_peer_recv` `stop`s its recv half (discarding its bytes
      // and returning its flow-control credit) and `finish`es our unused send half (so the stream fully
      // retires and the peer re-grants `MAX_STREAMS`) — without adopting `recv` or reading/decoding a
      // byte. This is the gentle, I9-consistent disposition (a Bulk-surface fault retires the stream, it
      // does NOT reap the connection): Control consensus keeps flowing, exactly as it would on a
      // conforming `Single` peer. `retire_peer_recv` queues a `STOP_SENDING`/FIN that only reaches the
      // wire via `poll_transmit`, so arm `should_service`.
      if e.layout.is_single() && class.is_bulk() {
        should_service |= retire_peer_recv(e, sid);
        continue;
      }
      let st = e.class_mut(class);
      if let Some(old) = st.recv
        && old != sid
      {
        // Fully retire the OLD peer-opened stream — close BOTH halves via `retire_peer_recv`: `stop`
        // the recv half (discards its unread bytes, returns its flow-control window as a `STOP_SENDING`
        // + `MAX_DATA`) AND `finish` our UNUSED send half (an empty FIN) so the accepted stream leaves
        // quinn's remote-stream accounting and the peer re-grants `MAX_STREAMS` — closing only the recv
        // half would leave our send half open, the stream never retires, and the peer's bidi credit
        // never returns. Those frames only reach the wire via `poll_transmit`, so set `should_service`
        // to run one `service(now)` after the loop when the retire queued anything — otherwise a Bulk
        // replacement with little/no new readable data would `finalize` nothing, return without
        // servicing, and strand the stop/FIN/credit frames in quinn (invisible to both `out` and
        // `has_pending_work`).
        should_service |= retire_peer_recv(e, old);
        // Re-cap the fresh decoder by class AND phase: Control while not `Validated` stays bounded to
        // `MAX_HELLO_LEN` (a replaced pre-auth Control stream may still only carry a hello), Bulk and a
        // post-validation Control to `MAX_FRAME_LEN`.
        let max = decoder_max(class, e.phase);
        let st = e.class_mut(class);
        st.decoder = FrameDecoder::new(max);
        st.recv = Some(sid);
        continue;
      }
      e.class_mut(class).recv = Some(sid);
    }
    // While AUTHENTICATING, read ONLY the Control class — the identity preface rides Control, and the
    // coordinator does not drain Bulk frames until `Validated`. A valid-cert peer that WITHHELD its
    // Control Hello while STREAMING Bulk would otherwise pin memory: the bridge would keep reading Bulk,
    // regranting flow-control credit, and growing the Bulk decoder (which is never popped pre-`Validated`)
    // until the AUTH_DEADLINE reap. Skipping the Bulk READ leaves its bytes unread, so quinn's per-stream
    // window backpressures the peer. The Bulk recv id is still ADOPTED above (the stream is not lost), and
    // the buffered bytes flow once the connection validates and Bulk is read below — nothing dropped.
    // Layout-safe for `Single` too: the accept loop refuses any Bulk-class peer stream, so `classes[Bulk]`
    // has no recv there and listing Bulk here is an empty skip.
    let read_classes: &[StreamClass] = if self.is_validated(h) {
      &[StreamClass::Control, StreamClass::Bulk]
    } else {
      &[StreamClass::Control]
    };
    // Drain each adopted class's recv stream into its decoder. A reset on a class drops just that
    // class; a framing error reaps the whole connection. `reschedule` is set if any class's read
    // stopped on its per-pass budget with bytes still readable — the connection is then re-enqueued
    // onto `deferred_ready` once after the loop so the NEXT pass continues the drain. `should_service`
    // (already armed above if the accept loop stopped a replaced recv stream) is ALSO set if consuming
    // any read freed the peer's flow-control window (a `finalize` that returned `should_transmit`) — the
    // connection is then serviced once after the loop so the resulting `MAX_DATA` / `MAX_STREAM_DATA`
    // (and the accept-loop stop/credit frames) reach `out` this pump.
    let mut reschedule = false;
    for &class in read_classes {
      let Some(e) = self.table.entry(h) else {
        return false;
      };
      let Some(sid) = e.class_mut(class).recv else {
        continue;
      };
      // Collect assembled chunks into a scratch buffer FIRST — the `Chunks` cursor borrows `e.conn`,
      // so the `e.decoder` feed must happen after that borrow is released. `read(ordered = true)`
      // yields an in-order cursor; a fresh stream with nothing buffered yields `Ok(None)` at once. A
      // `ReadError::Reset` mid-drain means the peer reset this class.
      //
      // Read at most `STAGE_CHUNK` bytes per pass rather than the whole stream window: a single pass
      // over a full `stream_receive_window` packed with tiny frames would otherwise push a window's
      // worth of complete frames onto the decoder's ready queue before `drain_bridge` (which only
      // pops AFTER this returns) drains any. Bounding the read bounds the queue to one budget's worth
      // of frames; `leftover` then reschedules the rest so the stream still fully drains across passes.
      let mut scratch: Vec<u8> = Vec::new();
      // Classify the read into exactly one [`RecvFault`] so NO recv-fault variant is silently treated as
      // no-data (the FIN-as-EOF wedge), AND a GRACEFUL finish is told apart from an ABANDONED one. `Open`
      // for DATA accumulated or a non-fatal would-block (both leave the stream live, same handling). A
      // FATAL close is `Graceful` (FIN: the bytes BEFORE the FIN are a COMPLETE final frame and must be
      // delivered, THEN reap) or `Abandoned` (peer RESET / an already-closed stream: the bytes were
      // thrown away, so discard `scratch` and reap). The class-split below reaps Control / retires Bulk
      // for BOTH fatal variants; only the disposition of `scratch` differs.
      let mut fault = RecvFault::Open;
      let mut leftover = false;
      {
        let mut recv = e.conn.recv_stream(sid);
        match recv.read(/*ordered=*/ true) {
          Ok(mut chunks) => {
            loop {
              if scratch.len() >= STAGE_CHUNK {
                // The budget is spent but the read stopped on neither end-of-data nor a fault: the
                // stream may still hold readable bytes. Mark leftover so the pass reschedules.
                leftover = true;
                break;
              }
              // Cap each assembled chunk so `scratch` never exceeds the budget — the assembler
              // retains the rest for the next pass's fresh cursor.
              let want = STAGE_CHUNK - scratch.len();
              match chunks.next(want) {
                // DATA: accumulate and keep reading this budget.
                Ok(Some(chunk)) => scratch.extend_from_slice(&chunk.bytes),
                // FIN: quinn consumed the peer's final offset — the peer GRACEFULLY finished its send
                // half. Distinct from `Blocked`: the stream is DONE, not merely empty-for-now, and the
                // recv half can never re-deliver. FATAL — for an index-0-fixed Control stream that
                // cannot reopen, treating this as a plain break would strand a routed connection with a
                // dead Control (consensus) recv, the FIN twin of the RESET wedge. GRACEFUL: the data read
                // before this offset is COMPLETE, so `scratch` is decoded + delivered before the reap.
                Ok(None) => {
                  fault = RecvFault::Graceful;
                  break;
                }
                // WOULD-BLOCK: no data right now, stream still open — non-fatal, just stop this pass.
                Err(quinn_proto::ReadError::Blocked) => break,
                // RESET: the peer abandoned its send half — whatever it sent before is gone. FATAL,
                // `scratch` discarded.
                Err(quinn_proto::ReadError::Reset(_)) => {
                  fault = RecvFault::Abandoned;
                  break;
                }
              }
            }
            // `finalize` releases the bytes just read from the flow-control window and queues the
            // resulting `MAX_DATA` / `MAX_STREAM_DATA`; its `ShouldTransmit` says a transmit is now
            // worth doing. Accumulate it so the connection is serviced once after this class loop —
            // the queued credit only reaches the wire via a `poll_transmit`, which `service` runs.
            should_service |= chunks.finalize().should_transmit();
          }
          // `ReadableError` (`ClosedStream`) means the stream was already finished / reset / stopped:
          // there is no live recv half to read, and no bytes to recover. FATAL+ABANDONED, like RESET.
          Err(_) => fault = RecvFault::Abandoned,
        }
      }
      if fault.is_abandoned() {
        // An ABANDONED recv close — a peer RESET (`Err(Reset)`) or an already-closed stream
        // (`recv.read()` `Err`) — discards `scratch`: the peer threw those bytes away (a RESET even
        // guarantees an empty `scratch`), so there is nothing to deliver. Reap (Control) / retire (Bulk)
        // at once; the I9 mirror of the SEND-side Control fatals (`write_framed` overflow,
        // `flush_outbound` `Stopped`/`ClosedStream`, the `on_app_event` peer-STOP arm — all `close_local`
        // for Control). The GRACEFUL (FIN) twin shares this same class-split but runs it AFTER decoding +
        // delivering `scratch` (the [`RecvFault::Graceful`] block below the decode), so a final consensus
        // frame that arrived in the SAME read as the FIN is not lost.
        if let Some(svc) = self.close_fault_class(now, h, class, sid) {
          should_service |= svc;
          continue;
        }
        // Control: the connection was reaped — stop pulling frames from a now-dead connection.
        return true;
      }
      // Decode the read bytes through the ONE shared decode+classify step and snapshot the disposition
      // facts. While `Authenticating` on Control, decode AT MOST the first frame (the hello) under the
      // small pre-auth cap (`use_extend_first`) and leave any pipelined tail buffered RAW: a peer that
      // already validated US may flush queued consensus Control (`Prepare`/`PrepareOk`, larger than the
      // hello cap) directly behind its hello in ONE read pass, and feeding the WHOLE buffer to the capped
      // `extend` would hit that tail's over-cap prefix and tear down a VALID connection before
      // `bind_validated` raises the cap (the coordinator authenticates only AFTER this returns). A FIRST
      // frame declaring over the cap is STILL rejected (the oversized-hello pin attack). Bulk is never read
      // pre-`Validated`, and a `Validated` connection uses the whole-buffer `extend` (all frames, full
      // cap). The snapshot is taken while the decoder borrow is live, so the `self.*` reborrows below (the
      // cross-class delivery check, the deferral push, `close_local`) are free of it; `decode_and_classify`
      // NEVER closes — the disposition decision lives ONLY here.
      let use_extend_first = e.phase.is_authenticating() && class == StreamClass::Control;
      let rec = decode_and_classify(&mut e.class_mut(class).decoder, &scratch, use_extend_first);
      // The disposition decision, made ONCE from the shared `rec` for both fatal recv variants that read
      // bytes — a graceful FIN and an over-cap framing error. `Truncated` vs `Clean` is `FinDisposition`'s
      // contract; the deliver-before-close ordering is `pending_fin_close`'s. Here: a framing error or a
      // torn partial reaps the whole connection (`Truncated`); anything else is `Clean`.
      if fault.is_graceful() || rec.frame_error {
        let truncated = rec.frame_error || rec.truncated_partial;
        // The two fatal classifications are distinguishable facts (`RecvDecode` keeps them as
        // separate fields), so keep them distinguishable in the disposition: an over-cap declared
        // length is a peer protocol violation (`FrameTooLong`), a torn partial at FIN is a
        // truncation — an operator reading the per-cause counters must be able to tell them apart.
        let disposition = if rec.frame_error {
          FinDisposition::OverCap
        } else if rec.truncated_partial {
          FinDisposition::Truncated
        } else {
          FinDisposition::Clean
        };
        // DEFER unless this is a `Truncated` close with NOTHING queued to deliver on either class — a
        // `Clean` close always defers (it delivers its final frame, then reaps via the class-split). The
        // deferred close returns `false`, so `drain_bridge` delivers this class's queued frames (and the
        // pre-auth tail `bind_validated` decodes, and any frame the other class queued this pass) before
        // `finish_fin_close` applies `disposition`. The connection stays live until then, so the other
        // class is still read this pass.
        if !truncated || rec.has_ready || self.has_pending_delivery(h) {
          self.push_fin_close(h, class, disposition);
          continue;
        }
        // A `Truncated` close with nothing to deliver — an over-cap framing error with no complete prefix,
        // or a graceful FIN torn mid-FIRST-frame. Reap INLINE through the shared `close_local` choke-point,
        // returning `true` so the caller stops pulling frames from a now-dead connection. The `if` above
        // established the empty-drain precondition of the `return true` bool contract (`!rec.has_ready &&
        // !has_pending_delivery`); re-assert it so a future reorder that reaped inline with a frame still
        // queued — making `drain_bridge`'s `if ingest_recv { continue }` skip a non-empty drain and DROP
        // that frame — trips here in debug.
        debug_assert!(
          !self.has_pending_delivery(h),
          "ingest_recv: an inline reap (return true) leaves no complete frame queued on either class — \
           the empty-drain precondition of the bool contract"
        );
        let cause = if rec.frame_error {
          CloseCause::FrameTooLong
        } else {
          CloseCause::TruncatedFrame
        };
        self.close_local(now, h, cause);
        return true;
      }
      reschedule |= leftover;
    }
    if reschedule {
      // At least one class's stream still has readable bytes past this pass's budget. Defer the
      // connection to the NEXT pump — NOT `stream_ready`, which `drain_bridge` is draining now: landing
      // it there would let this same drain consume it (and the next budget, and the next…) until the
      // whole receive window is drained in one pump, which is exactly the per-pump-unbounded path this
      // pacing closes. `drain_bridge` promotes `deferred_ready` into `stream_ready` at the TOP of the
      // next pump, so the leftover is read one budget per pump: drain this pump's queued frames, then
      // read the next budget. `has_pending_work` counts `deferred_ready`, so a `poll_timeout`-driven
      // driver wakes immediately while leftover remains; once a pass drains a class fully nothing is
      // re-deferred, the predicate falls back to the real connection timer, and there is no busy-loop —
      // each pass consumes a full budget, so it always makes forward progress.
      self.deferred_ready.push_back(h);
    }
    if should_service {
      // A quinn mutation above queued credit/control frames that only a `poll_transmit` puts on the
      // wire: the accept-loop `stop` (STOP_SENDING + recovered `MAX_DATA` credit) and/or a per-class read
      // whose `finalize` freed the peer's window (`MAX_DATA` / `MAX_STREAM_DATA`). Run one service pass
      // NOW (every borrow of `e.conn` is released — they lived only inside the loops above) so those
      // datagrams land in `out` this pump and the peer/sender unblocks without waiting on unrelated
      // traffic.
      self.service(now);
    }
    false
  }

  /// Pop the next complete raw frame payload off connection `h`'s `class` decoder, or `None` when no
  /// complete frame is buffered for that class. The coordinator interprets the payload by the
  /// connection's phase: the first Control frame of an `Authenticating` connection is the identity
  /// preface (fed to `authenticate`); frames of a `Validated` connection are consensus [`Message`]s.
  pub(crate) fn next_frame(&mut self, h: ConnectionHandle, class: StreamClass) -> Option<Vec<u8>> {
    self
      .table
      .entry(h)
      .and_then(|e| e.class_mut(class).decoder.next_frame())
  }

  /// Retry connection `h`'s staged sends on BOTH classes after a `Writable` event reopened a
  /// flow-control window. Front-drains each class's outbound buffer into its send stream; if any
  /// bytes reach a stream, a service pass at `now` turns the resulting STREAM datagrams into
  /// transmits. The coordinator calls this from its `stream_ready` drain alongside
  /// [`Self::ingest_recv`], since the bridge surfaces both `Readable` and `Writable` (and bidi
  /// `Opened`) on the same queue, without per-class resolution — so both classes are retried.
  ///
  /// This is the SEND-side retry only; it runs BEFORE `ingest_recv` in the drain, so it cannot emit
  /// the inbound-read flow-control credit (that read has not happened yet). `ingest_recv` services its
  /// OWN connection after its reads when consuming them freed the peer's window, so the dropped-credit
  /// path is closed there, not here.
  pub(crate) fn flush_stream(&mut self, now: Instant, h: ConnectionHandle) {
    let mut progressed = self.flush_outbound(now, h, StreamClass::Control);
    progressed |= self.flush_outbound(now, h, StreamClass::Bulk);
    if progressed {
      self.service(now);
    }
  }

  /// Retire connection `h` from ROUTING (a `lost`/closed connection): its `by_peer` slot is cleared
  /// so no further consensus frame is routed to it, but the quinn `Connection` is KEPT in the table
  /// so the service pump can drive it to `Drained` — only then is the endpoint's slab slot freed and
  /// the entry removed (see [`Self::service`]'s Drained arm). The coordinator calls this when it
  /// drains the `lost` queue; the consensus layer redials via a fresh `connect`. Removing the entry
  /// here instead would drop the `Connection` before it emits `Drained`, leaking the endpoint slab.
  ///
  /// Idempotent: a handle the service pump has already drained + removed is simply absent, so this is
  /// a no-op then.
  pub(crate) fn reap(&mut self, h: ConnectionHandle) {
    self.table.unbind(h);
  }

  /// Front-drain `h`'s `class` staged outbound buffer into that class's SEND stream, returning whether
  /// it made progress the caller should turn into a service pass — either bytes reached the stream OR a
  /// Bulk reset queued a `RESET_STREAM` (both produce a frame only `poll_transmit` can emit). A no-op
  /// (returns `false`) when the buffer is empty. If the class has no open send stream but has staged
  /// bytes (the reopen-on-next-use case after a per-stream reset), a fresh stream is opened first and
  /// given the class's send priority. quinn accepts a contiguous slice, so the buffer is made contiguous
  /// and written from the front: on a partial write only the written prefix is dropped (the unwritten
  /// tail stays at the front, order intact); on `Blocked` nothing is dropped; a terminal
  /// `Stopped`/`ClosedStream` on Bulk RESETS just this class's stream (drops the buffer + the send id, to
  /// reopen on the next write) and returns `true` so the caller services the queued `RESET_STREAM`, while
  /// the same fatal on Control reaps the whole connection via `close_local` (which services itself, so
  /// this returns `false`) — neither touches the other class.
  fn flush_outbound(&mut self, now: Instant, h: ConnectionHandle, class: StreamClass) -> bool {
    {
      let Some(e) = self.table.entry(h) else {
        return false;
      };
      if e.class_mut(class).outbound.is_empty() {
        return false;
      }
      // Reopen-on-next-use: a class with staged bytes but no send stream (just reset, or never
      // opened) opens a fresh stream now and re-applies its priority. `open` only fails on stream
      // exhaustion, in which case the bytes stay staged for a later retry.
      if e.class_mut(class).send.is_none() {
        match e.conn.streams().open(Dir::Bi) {
          Some(sid) => {
            e.class_mut(class).send = Some(sid);
            let prio = class_priority(class);
            let _ = e.conn.send_stream(sid).set_priority(prio);
          }
          None => return false,
        }
      }
    }
    let Some(e) = self.table.entry(h) else {
      return false;
    };
    let sid = match e.classes[class.as_index()].send {
      Some(sid) => sid,
      None => return false,
    };
    // Drain the staged bytes, looping the write. quinn's `Send::write` is bounded by the peer's
    // FLOW-CONTROL window (`max_data - pending`), NOT the congestion window (which only paces
    // `poll_transmit` on the wire). The loop drains everything the current window allows in one pass and,
    // on a genuine `Blocked`, leaves the rest staged — quinn registers the stream for the `Writable` that
    // fires when the peer relaxes its window. (Looping is defensive for a configuration where the
    // CONNECTION window binds first, which a single `Ok(partial)` would not register for a retry.) The
    // loop terminates: every `Ok(n > 0)` front-drains `n` bytes; `Ok(0)` / `Blocked` / empty / fatal break.
    let mut progressed = false;
    loop {
      // `make_contiguous` returns a single front-anchored slice over the whole remaining buffer;
      // quinn's `write` wants `&[u8]`. The slice borrows the class's `outbound` (a field of
      // `e.classes`), so the write holds a separate re-borrow of `e.conn` — disjoint fields of the
      // same `&mut ConnEntry`. Indexing `e.classes` directly (not via `class_mut`, a whole-`e`
      // reborrow) is what lets the borrow checker split the two.
      let bytes: &[u8] = e.classes[class.as_index()].outbound.make_contiguous();
      if bytes.is_empty() {
        break;
      }
      match e.conn.send_stream(sid).write(bytes) {
        Ok(0) => break,
        Ok(n) => {
          // Drop the written prefix from the front; loop to push the next window's worth.
          e.classes[class.as_index()].outbound.drain(..n);
          progressed = true;
        }
        // `Blocked`: the window is exhausted; quinn registered the stream for the next `Writable`.
        // Leave the remaining buffer staged for that retry (normal flow control, NOT a reset trigger).
        Err(WriteError::Blocked) => break,
        // `Stopped`/`ClosedStream`: the send half is dead. Class-aware response:
        // - Bulk: reset just this stream (drop the buffer + send id, reopen on the next write);
        //   the connection and Control survive.
        // - Control: reap the whole connection. A dead Control send half cannot be recovered
        //   in-place — reopening at a higher index mis-maps to Bulk on the peer. A full redial
        //   reopens Control at index 0 on a fresh connection.
        //
        // Return `true` (progress) on the Bulk reset so the caller runs a `service(now)`: `reset_send_class`
        // queued a `RESET_STREAM`, which only reaches `out` via a `poll_transmit`. Returning `false` here
        // would let a caller that gates servicing on the return value (`write_framed` / `bind_validated` /
        // `flush_stream` on a class that made no other progress) strand that `RESET_STREAM` in quinn until
        // unrelated traffic — the same dropped-control-frame gap as the accept-loop `stop`. The Control
        // branch routes through `close_local`, which services the connection itself, so its returned
        // value does not gate the close — `false` is correct there (no further outbound on a connection
        // being torn down).
        Err(_) => match class {
          StreamClass::Bulk => {
            self.reset_send_class(h, class);
            return true;
          }
          StreamClass::Control => {
            self.close_local(now, h, CloseCause::PeerClosed);
            return false;
          }
        },
      }
    }
    progressed
  }

  /// Per-STREAM reset for one class's SEND half: fully retire the class's locally-opened bidi stream
  /// (close BOTH the send AND the unused recv half via [`retire_local_send`] — which `stop`s the unused
  /// recv half so its local `Recv` entry does not leak; see that fn), clear its staged `outbound`, and
  /// drop the send id so the next write reopens a fresh stream. Deliberately does NOT close the connection
  /// or touch the other class — a Bulk overflow/stall must not tear down Control, and consensus
  /// retransmission re-drives whatever the dropped frames carried. Only called for [`StreamClass::Bulk`];
  /// a Control-class fatal reaches [`Self::close_local`] instead. Idempotent on a class with no open send
  /// stream (just clears the buffer).
  fn reset_send_class(&mut self, h: ConnectionHandle, class: StreamClass) {
    let Some(e) = self.table.entry(h) else {
      return;
    };
    if let Some(sid) = e.class_mut(class).send {
      retire_local_send(e, sid);
    }
    let st = e.class_mut(class);
    st.outbound.clear();
    st.send = None;
  }
}

/// Fully retire a PEER-OPENED (accepted) bidi stream that the bridge is done reading, closing BOTH of
/// its halves so the stream leaves quinn's remote-stream accounting and the peer's concurrency credit
/// returns. Returns `true` iff a quinn mutation here queued a wire frame (`STOP_SENDING` and/or the
/// empty-FIN `STREAM`), so the caller can run one `service` pass to carry it to the wire.
///
/// **Why both halves.** This transport uses each bidi stream ONE-WAY: the OPENER writes its send half,
/// the ACCEPTOR (us, for a peer-opened id) reads its recv half. quinn inserts BOTH a send AND a recv
/// entry for an accepted bidi stream, and only decrements its `allocated_remote_count` — the trigger
/// that grows the remote-stream window and emits `MAX_STREAMS` — once the stream is FULLY freed, which
/// for a remote bidi requires both that side's recv AND send entries to be gone (`stream_freed`'s
/// `fully_free` predicate in quinn). Closing only the recv half (`stop` / read-to-reset) leaves our
/// UNUSED send half open, so the stream never retires, the credit never returns, and after enough
/// peer Bulk reset/reopen churn the opener's `open(Dir::Bi)` stays exhausted forever — staged Bulk /
/// state-transfer frames then strand until the whole connection is replaced. So we also close the
/// unused send half: a never-written half is gracefully `finish()`ed (empty FIN); once the peer ACKs
/// it quinn frees our send entry, and with the recv half also gone the stream fully retires.
///
/// `stop` / `finish` each error only on an already-closed/absent half (the peer's reset may have
/// disposed the recv; an earlier retire may have finished the send) — a benign no-op that queues
/// nothing, so it does not contribute to the returned "queued a frame" signal.
fn retire_peer_recv(e: &mut ConnEntry, sid: StreamId) -> bool {
  // STOP the recv half: discards unread bytes and returns its flow-control window/credit (a
  // `STOP_SENDING` + `MAX_DATA`). No-op once the recv is gone (e.g. the read-side `Reset` arm already
  // freed it when it read the peer's RESET).
  let mut queued = e
    .conn
    .recv_stream(sid)
    .stop(VarInt::from_u32(STREAM_RESET_CODE))
    .is_ok();
  // FINISH our UNUSED send half (we never wrote it): an empty-FIN `STREAM` frame. This is the half the
  // bug left open — without it the accepted stream never fully retires and the peer never re-grants
  // `MAX_STREAMS`. `finish` only fails when the send half is already gone (a prior retire / a peer STOP
  // we already reacted to), which queues nothing.
  queued |= e.conn.send_stream(sid).finish().is_ok();
  queued
}

/// Fully retire a LOCALLY-OPENED bidi stream this side is done writing, closing BOTH halves: `reset` the
/// SEND half (the side we used) AND `stop` the UNUSED recv half (the side we never read). The
/// opener-role mirror of [`retire_peer_recv`].
///
/// **Why both halves.** This transport uses each bidi stream ONE-WAY: the OPENER (us, for a
/// locally-opened id) writes its send half; the peer (the acceptor) reads it and, per [`retire_peer_recv`]
/// run on the peer, `finish`es its own unused send half — delivering a FIN on OUR unused recv half. The
/// bridge never reads locally-opened recv ids ([`Bridge::ingest_recv`] only `accept`s + reads PEER-opened
/// ids), so without an explicit `stop` here that FIN is never consumed and our local `Recv` entry lingers
/// in quinn's `recv` map. Under sustained Bulk reset/reopen churn that is ONE leaked `Recv` per retired
/// stream — unbounded local stream-state growth until the connection closes (the peer's `MAX_STREAMS`
/// credit DOES return, via our `RESET_STREAM`, so the leak is invisible to the bidi-credit budget; it is
/// pure local-state accumulation). `stop` discards the recv assembler and frees the `Recv` entry on the
/// peer's FIN/RESET (state.rs `received`/`received_reset`: a stopped stream is disposed the instant its
/// final frame arrives), or immediately if the final offset is already known (`RecvStream::stop` frees on
/// the spot when `!final_offset_unknown`).
///
/// `reset` / `stop` each error only on an already-closed/absent half (the stream may already be gone) — a
/// benign no-op. The frames this queues (`RESET_STREAM` + `STOP_SENDING`) reach the wire only via a
/// `poll_transmit`, so the caller MUST run a `service` pass after — every [`reset_send_class`] call site
/// already does (a Bulk-overflow `write_framed` services unconditionally; `flush_outbound`'s Bulk fatal
/// returns `true` so its caller services; the `Stopped` arm services its own connection).
fn retire_local_send(e: &mut ConnEntry, sid: StreamId) {
  // RESET the send half: the peer sees a `RESET_STREAM` and frees its accepted recv half. No-op if the
  // send stream is already closed/gone (a prior retire) — the goal is reached either way.
  let _ = e
    .conn
    .send_stream(sid)
    .reset(VarInt::from_u32(STREAM_RESET_CODE));
  // STOP the UNUSED recv half (we never read it): the half the leak left open. `stop` marks it stopped so
  // quinn frees its local `Recv` entry on the peer's FIN/RESET (the acceptor's `finish`/`reset`) rather
  // than retaining it for a read that never comes. No-op once the recv is already gone.
  let _ = e
    .conn
    .recv_stream(sid)
    .stop(VarInt::from_u32(STREAM_RESET_CODE));
}

/// The earlier of two optional instants: the `min` when both are `Some`, the present one when only one
/// is, `None` when neither. Used by [`Bridge::poll_timeout`] to fold the auth deadline in alongside
/// quinn's earliest connection timer without either masking the other.
fn min_opt(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
  match (a, b) {
    (Some(a), Some(b)) => Some(a.min(b)),
    (a, None) => a,
    (None, b) => b,
  }
}

/// The send priority for a class: Control (1) drains ahead of Bulk (0) under flow-control pressure.
const fn class_priority(class: StreamClass) -> i32 {
  match class {
    StreamClass::Control => 1,
    StreamClass::Bulk => 0,
  }
}

/// Map a peer-opened bidi [`StreamId`] to the class it carries, by its per-initiator index: the peer
/// opens Control FIRST (index 0) then Bulk (index 1). Index 0 is therefore Control; any higher index
/// is Bulk.
///
/// **The index-0 = Control invariant is now ENFORCED, not merely assumed.** Any Control-class fatal —
/// SEND overflow in [`Bridge::write_framed`], a SEND `Stopped`/`ClosedStream` in
/// [`Bridge::flush_outbound`], a peer STOP surfaced as `Event::Stream(StreamEvent::Stopped)`, a RECV
/// framing error OR a RECV `Reset`/`ClosedStream` in [`Bridge::ingest_recv`] — tears down the WHOLE
/// connection via [`Bridge::close_local`] instead of reopening the stream: `close_local` issues the
/// quinn `close`, drains the connection, and frees its endpoint slab + cap slot. This means Control is
/// never reopened at a higher index on a live connection, so the only id this function will ever see at
/// index 0 is the original Control stream.
///
/// Why "any index ≥ 1 → Bulk": a per-STREAM reset on Bulk reopens a fresh Bulk stream, which quinn
/// mints at the next monotonic index (2, 3, …). Mapping every non-zero index to Bulk lets a reopened
/// Bulk stream keep landing on the Bulk recv without special-casing the index. The peer never opens a
/// second Control stream (the enforcement above ensures it), so no higher index is ever Control.
fn class_of_index(sid: StreamId) -> StreamClass {
  if sid.index() == 0 {
    StreamClass::Control
  } else {
    StreamClass::Bulk
  }
}

#[cfg(test)]
mod tests;

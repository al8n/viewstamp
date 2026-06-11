//! Per-connection state for the QUIC transport.

use std::{collections::VecDeque, time::Instant};

use quinn_proto::{Connection, StreamId};

use super::layout::{StreamClass, StreamLayout};
use crate::{
  Peer,
  transport::{
    frame::{FrameDecoder, MAX_FRAME_LEN},
    labeled::MAX_HELLO_LEN,
  },
};

/// The per-frame length cap for a recv decoder, as a function of the stream class AND the connection
/// phase. The Control class is held at a SMALL pre-authentication cap ([`MAX_HELLO_LEN`]) until the
/// connection is [`Phase::Validated`]: while `Authenticating`, the only legitimate Control frame is the
/// peer's identity hello, so a valid-cert but buggy/hostile peer must not be able to declare (and have
/// the bridge buffer + flow-control-credit) a multi-megabyte first Control frame before it validates.
/// The [`FrameDecoder`] rejects an over-cap DECLARED length before retaining any of that frame's body,
/// so this cap bounds the pre-auth Control buffer to a few dozen bytes for free. Once `Validated`, the
/// Control class carries consensus messages up to [`MAX_FRAME_LEN`], so the cap is raised. Bulk carries
/// no pre-auth frame (it is not even read until `Validated`), so it is always at the full cap.
pub(crate) const fn decoder_max(class: StreamClass, phase: Phase) -> u32 {
  match class {
    StreamClass::Control if !phase.is_validated() => MAX_HELLO_LEN as u32,
    StreamClass::Control | StreamClass::Bulk => MAX_FRAME_LEN,
  }
}

/// Per-stream-class half-stream state: the bidi stream THIS side opened for the class (the send
/// half), the bidi stream the PEER opened for the class (the recv half, adopted lazily), the inbound
/// frame decoder for that recv half, and the strict-FIFO outbound staging buffer for that send half.
///
/// One [`StreamState`] exists per [`StreamClass`] in [`ConnEntry::classes`]. Under `Single` only the
/// `Control` slot is used; under `ControlBulk` both slots carry an independent pair of half-streams,
/// so a stall (or per-stream reset) on Bulk never touches Control.
pub(crate) struct StreamState {
  /// The bidi stream THIS side opened for this class (`streams().open(Dir::Bi)`); this side writes
  /// it. `None` until [`open_send_and_preface`](super::bridge::Bridge::open_send_and_preface) opens
  /// it on `Connected` (and re-`None` after a per-stream reset, reopened on the next write).
  pub(crate) send: Option<StreamId>,
  /// The bidi stream the PEER opened for this class (`streams().accept(Dir::Bi)`); this side reads
  /// it. `None` until [`ingest_recv`](super::bridge::Bridge::ingest_recv) adopts the peer-opened id
  /// whose [`StreamId::index`] matches this class — the peer opens Control first (index 0) then Bulk
  /// (index 1), so the index, not accept order, fixes the class.
  pub(crate) recv: Option<StreamId>,
  pub(crate) decoder: FrameDecoder,
  /// Strict-FIFO staging buffer for framed bytes that could not be written yet (no send stream
  /// open, or quinn reported `Blocked`). Drained from the FRONT so on-wire frame order is the
  /// order `write_framed` was called for this class.
  pub(crate) outbound: VecDeque<u8>,
}

impl StreamState {
  /// A fresh half-stream state whose recv decoder is bounded at `decoder_max` bytes. The Control class
  /// is created at the small pre-authentication cap; Bulk at the full frame cap (see [`decoder_max`]).
  fn new(decoder_max: u32) -> Self {
    Self {
      send: None,
      recv: None,
      decoder: FrameDecoder::new(decoder_max),
      outbound: VecDeque::new(),
    }
  }
}

/// Per-connection lifecycle phase. Consensus-stream I/O is unreachable until [`Phase::Validated`].
///
/// Transitions: `Handshaking → Authenticating → Validated → Closed` (or to `Closed` from any earlier
/// phase on failure). The QUIC handshake completing only carries a connection to `Authenticating`:
/// the identity-binding step (the coordinator's [`IdentitySource`](super::identity::IdentitySource)
/// `authenticate` + binding policy) is what promotes it to `Validated`, after which consensus frames
/// flow. The control-stream preface is written in `Authenticating`; consensus frames are gated until
/// `Validated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant)]
pub(crate) enum Phase {
  /// TLS handshake in progress; no streams, no data exchanged yet.
  Handshaking,
  /// QUIC handshake complete, but peer identity not yet bound. The control-stream preface is sent
  /// here and the peer's first control frame is routed to `authenticate`; no consensus frame flows.
  Authenticating,
  /// Identity bound; the per-peer bidi streams carry consensus messages.
  Validated,
  /// Connection is being torn down; no further I/O.
  Closed,
}

/// One pooled QUIC connection: the quinn state, its lifecycle phase, the bound peer (once known),
/// the per-class bidi half-streams, and the stream layout that fixes how many classes are live.
///
/// **Per-class streams.** quinn-proto's `streams().open(Dir::Bi)` mints a stream id owned by *this*
/// side, while `streams().accept(Dir::Bi)` adopts the id the *peer* opened — these are distinct ids
/// (different initiator bit). So a side WRITES the stream it opened and READS the stream the peer
/// opened; conflating them means each side reads its own write half and never sees the peer's
/// frames. [`Self::classes`] holds one [`StreamState`] per [`StreamClass`]: under `Single` only the
/// `Control` slot is used; under `ControlBulk` both `Control` and `Bulk` carry independent
/// half-stream pairs, so latency-critical control traffic and bulk state-transfer cannot head-of-line
/// block one another. The send half of each class is opened locally Control-first, Bulk-second, which
/// fixes the per-class [`StreamId::index`] both sides agree on for recv-class assignment.
///
/// All fields are `pub(crate)` — `ConnEntry` is an internal plumbing struct whose sole mutator is
/// the bridge. Accessors would add boilerplate with no encapsulation benefit.
pub(crate) struct ConnEntry {
  pub(crate) conn: Connection,
  pub(crate) phase: Phase,
  /// The peer this connection was DIALED to reach (`Some` on the connect path, `None` on accept).
  /// The coordinator's binding policy requires the authenticated candidate to equal this on a dialed
  /// connection (match-or-abort); an accepted connection adopts whatever candidate authenticates.
  pub(crate) dialed_expectation: Option<Peer>,
  /// The authenticated, coordinator-bound peer. `None` until the identity-binding step promotes the
  /// connection to [`Phase::Validated`]; routing and frame surfacing key off this being `Some`.
  pub(crate) peer: Option<Peer>,
  /// Whether this side's control-stream preface frame has been written. The preface is the FIRST
  /// frame on the Control send stream; consensus frames are gated behind it (and behind `Validated`).
  pub(crate) preface_done: bool,
  /// The stream layout for this connection: `Single` uses only the `Control` class; `ControlBulk`
  /// opens both. Snapshotted from `QuicOptions` at construction so the bridge knows whether to open
  /// the Bulk send stream and accept a Bulk recv stream.
  pub(crate) layout: StreamLayout,
  /// Per-class half-stream state, indexed by [`StreamClass::as_index`] (0 = Control, 1 = Bulk). The
  /// `Bulk` slot is unused under `Single`.
  pub(crate) classes: [StreamState; 2],
  /// Monotonic creation sequence, assigned by [`ConnTable::insert`](super::table::ConnTable::insert)
  /// from a strictly-increasing per-table counter. It is a RECENCY order over the table's connections —
  /// a higher `seq` was created later. The per-peer connection bound uses it to identify the OLDEST
  /// same-peer connections to reap: under this transport's mutual-dial design a peer legitimately holds
  /// TWO connections (each side dialed the other; see [`ConnTable::bind_peer`](super::table::ConnTable::bind_peer)),
  /// and a reconnecting peer may briefly hold more, so a flapping valid-cert member could otherwise
  /// accumulate UNBOUNDED same-peer connections and exhaust the global cap. On validation the bridge
  /// keeps the most-recent [`PER_PEER_CONN_LIMIT`](super::bridge::PER_PEER_CONN_LIMIT) (which always
  /// include the just-bound connection and its mutual-dial sibling — both the newest) and reaps the
  /// older excess. Unrelated to quinn's `ConnectionHandle` (a slab index that may be reused after a
  /// drain); `seq` is never reused.
  pub(crate) seq: u64,
  /// Deadline by which this connection must reach [`Phase::Validated`], stamped when it ENTERS
  /// [`Phase::Authenticating`] (the QUIC handshake completed) and CLEARED whenever it LEAVES
  /// `Authenticating` — on `Validated` (bound) or on `Closed` (reaped / lost). A peer that completed mTLS
  /// with a valid cluster cert but never sends a valid `Hello` would otherwise sit in `Authenticating`
  /// forever (its keepalive PINGs refresh quinn's idle timeout) and N such peers exhaust `max_connections`
  /// (the connection-table-exhaustion DoS the [`AUTH_DEADLINE`](super::bridge) const documents). The bridge
  /// `close_local`s any connection still `Authenticating` past this deadline; it is folded into
  /// `poll_timeout` as a connection timer scoped to `Authenticating` entries.
  ///
  /// Clearing it on every `Authenticating` exit — with the `is_authenticating()` filter in
  /// [`ConnTable::earliest_auth_deadline`](super::table::ConnTable::earliest_auth_deadline) — keeps a stale
  /// PAST deadline from ever being reported (a past instant cannot advance a `poll_timeout`-driven driver's
  /// clock, stalling the drain). `None` while `Handshaking` and once `Validated`/`Closed`.
  pub(crate) auth_deadline: Option<Instant>,
}

impl ConnEntry {
  /// Wraps a freshly-minted `quinn_proto::Connection` in a `Handshaking` entry.
  /// `dialed_expectation` is `Some(peer)` on the connect path (the peer this side dialed) and `None`
  /// on the accept path. `layout` fixes how many stream classes this connection opens.
  pub(crate) fn new(
    conn: Connection,
    dialed_expectation: Option<Peer>,
    layout: StreamLayout,
  ) -> Self {
    Self {
      conn,
      phase: Phase::Handshaking,
      dialed_expectation,
      peer: None,
      preface_done: false,
      layout,
      // The recv decoders start at the pre-authentication caps (`Handshaking` is not `Validated`):
      // Control bounded to `MAX_HELLO_LEN`, Bulk to `MAX_FRAME_LEN`. `bind_validated` raises Control to
      // the full cap once the peer's identity is established.
      classes: [
        StreamState::new(decoder_max(StreamClass::Control, Phase::Handshaking)),
        StreamState::new(decoder_max(StreamClass::Bulk, Phase::Handshaking)),
      ],
      auth_deadline: None,
      // Placeholder; the recency sequence is assigned by `ConnTable::insert` from its monotonic
      // counter the moment the entry enters the table (the single insertion choke-point).
      seq: 0,
    }
  }

  /// The per-class [`StreamState`] for `class` (a fixed index into [`Self::classes`]).
  #[inline(always)]
  pub(crate) fn class_mut(&mut self, class: StreamClass) -> &mut StreamState {
    &mut self.classes[class.as_index()]
  }

  /// True when identity has been bound and the bidi streams may carry consensus frames.
  #[inline(always)]
  pub(crate) fn is_validated(&self) -> bool {
    self.phase.is_validated()
  }

  /// True while the QUIC handshake is complete but identity is not yet bound (the preface /
  /// `authenticate` window).
  #[inline(always)]
  pub(crate) fn is_authenticating(&self) -> bool {
    self.phase.is_authenticating()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn phase_predicates_are_correct() {
    assert!(Phase::Handshaking.is_handshaking());
    assert!(!Phase::Handshaking.is_authenticating());
    assert!(!Phase::Handshaking.is_validated());
    assert!(!Phase::Handshaking.is_closed());

    assert!(Phase::Authenticating.is_authenticating());
    assert!(!Phase::Authenticating.is_handshaking());
    assert!(!Phase::Authenticating.is_validated());
    assert!(!Phase::Authenticating.is_closed());

    assert!(Phase::Validated.is_validated());
    assert!(!Phase::Validated.is_handshaking());
    assert!(!Phase::Validated.is_authenticating());
    assert!(!Phase::Validated.is_closed());

    assert!(Phase::Closed.is_closed());
    assert!(!Phase::Closed.is_handshaking());
    assert!(!Phase::Closed.is_authenticating());
    assert!(!Phase::Closed.is_validated());
  }
}

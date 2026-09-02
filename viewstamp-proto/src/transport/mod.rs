//! Network transport, folded into the proto as feature-gated Sans-I/O modules.
//!
//! The consensus [`Endpoint`](crate::Endpoint) stays sovereign — it speaks
//! [`Peer`](crate::Peer)/[`Recipient`](crate::Recipient) only. The `tcp`/`tls` features add, on
//! top, a per-socket byte-record layer, a cluster+identity handshake, a per-socket pipe, a
//! per-peer router, and the composing coordinator. Modeled on `memberlist-proto`.

#[cfg(all(
  feature = "quic",
  not(any(
    feature = "tls-rustls-ring",
    feature = "tls-rustls-aws-lc-rs",
    feature = "tls-rustls-aws-lc-rs-fips"
  ))
))]
compile_error!(
  "feature `quic` requires a crypto provider: enable one of \
  `tls-rustls-ring`, `tls-rustls-aws-lc-rs`, or `tls-rustls-aws-lc-rs-fips`"
);

mod conn;
mod coordinator;
mod frame;
mod labeled;
#[cfg(test)]
mod loopback;
mod passthrough;
#[cfg(feature = "quic")]
mod quic;
mod router;
mod stream;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod testutil;
#[cfg(feature = "tls")]
mod tls;
pub use conn::Conn;
pub use coordinator::StreamCoordinator;
pub use frame::{MAX_FRAME_LEN, max_request_body_len};
pub use labeled::{LabelOptions, Labeled};
pub use passthrough::Passthrough;
#[cfg(feature = "quic")]
pub use quic::{
  AttestedId, CertOid, ClusterTls, DEFAULT_CONNECTION_RECEIVE_WINDOW, DEFAULT_IDLE_TIMEOUT_MILLIS,
  DEFAULT_INITIAL_RTT_MILLIS, DEFAULT_STREAM_RECEIVE_WINDOW, DialError, Hello, Identified,
  IdentityConfig, IdentityCtx, IdentityOutcome, IdentitySource, MAX_STREAM_RECEIVE_WINDOW,
  ProvidedIdentity, QuicCoordinator, QuicOptions, QuicTuning, StreamLayout, StreamWindowTooLarge,
};
pub use router::{ConnId, PeerRouter};
pub use stream::{Intake, StreamTransport};
#[cfg(feature = "tls")]
pub use tls::{TlsOptions, TlsRecords};

/// Why the transport closed a connection, drained alongside its [`ConnId`] from
/// [`StreamCoordinator::poll_conn_closed`] / [`PeerRouter::poll_closed`]. Transport diagnostics —
/// the conn lifecycle never reaches the consensus event stream. A driver also uses these causes to
/// label closes it decides itself (an auth-deadline reap, an out-queue overflow, an at-capacity
/// accept drop), so one vocabulary covers every close site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Display, derive_more::IsVariant)]
#[display("{}", self.as_str())]
#[repr(u8)]
pub enum CloseCause {
  /// The record layer rejected the stream (a TLS reject, a cluster-handshake mismatch, or a
  /// handshake that stalled without progress).
  RecordRejected,
  /// An inbound frame declared a length over the frame cap.
  FrameTooLong,
  /// A complete inbound frame failed to decode as a [`Message`](crate::Message).
  BadFrame,
  /// The peer finished mid-frame (a partial frame remained buffered at EOF).
  TruncatedFrame,
  /// The peer finished cleanly (EOF on a frame boundary).
  PeerClosed,
  /// Queued outbound exceeded the per-conn cap (or the record layer refused part of a frame).
  OutboundOverflow,
  /// The handshake-authenticated identity failed the binding policy (a dialed conn validated as a
  /// different peer than it dialed).
  IdentityRejected,
  /// The conn never validated within the driver's authentication deadline.
  AuthDeadline,
  /// An accepted socket was dropped at the driver's live-connection cap before registration.
  AcceptCapacity,
  /// The transport's own idle timeout expired with no peer traffic (a QUIC `TimedOut` loss).
  IdleTimeout,
  /// A live conn was retired by newer state — a fresher validated conn for the same peer won the
  /// duplicate race, or a membership change removed/re-slotted the member it was bound to.
  Superseded,
  /// A STREAM frame was observable on the reverse direction of a stream THIS side opened. Each class
  /// uses only the send half of the stream it opens — the peer's frames ride the streams it opens
  /// itself — so a frame arriving on that half is a protocol violation no conforming peer produces.
  /// Recorded for what the transport OBSERVED: a peer whose reset releases the data first is not
  /// counted here, and its connection stays open.
  UnsolicitedStream,
}

impl CloseCause {
  /// The number of causes — sizes a per-cause counter array (`[u64; CloseCause::COUNT]`).
  pub const COUNT: usize = Self::UnsolicitedStream as usize + 1;

  /// The dense counter-array slot of this cause (`0..COUNT`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn index(self) -> usize {
    self as usize
  }

  /// The stable string name of this cause (snake_case, serialization-stable).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::RecordRejected => "record_rejected",
      Self::FrameTooLong => "frame_too_long",
      Self::BadFrame => "bad_frame",
      Self::TruncatedFrame => "truncated_frame",
      Self::PeerClosed => "peer_closed",
      Self::OutboundOverflow => "outbound_overflow",
      Self::IdentityRejected => "identity_rejected",
      Self::AuthDeadline => "auth_deadline",
      Self::AcceptCapacity => "accept_capacity",
      Self::IdleTimeout => "idle_timeout",
      Self::Superseded => "superseded",
      Self::UnsolicitedStream => "unsolicited_stream",
    }
  }
}

impl From<&TransportError> for CloseCause {
  /// The cause a conn records when this error closes it (the `Conn` close sites are the callers, so
  /// the error→cause mapping lives in one place).
  fn from(e: &TransportError) -> Self {
    match e {
      TransportError::FrameTooLong { .. } => Self::FrameTooLong,
      TransportError::TruncatedFrame { .. } => Self::TruncatedFrame,
      TransportError::RecordRejected => Self::RecordRejected,
      TransportError::Decode(_) => Self::BadFrame,
    }
  }
}

/// An error from the transport layer (framing or a terminal record-layer reject).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
  /// A framed unit exceeded the configured maximum length.
  #[error("frame length {len} exceeds the maximum of {max}")]
  FrameTooLong {
    /// The offending length.
    len: u32,
    /// The configured cap.
    max: u32,
  },
  /// The connection closed mid-frame (a partial frame remained buffered at EOF).
  #[error("connection closed mid-frame ({remaining} bytes buffered)")]
  TruncatedFrame {
    /// Bytes left dangling.
    remaining: usize,
  },
  /// The record layer rejected the stream (TLS reject, or a handshake mismatch).
  #[error("record layer rejected the connection")]
  RecordRejected,
  /// A framed message failed to decode.
  #[error("message decode failed: {0}")]
  Decode(#[from] crate::CodecError),
}

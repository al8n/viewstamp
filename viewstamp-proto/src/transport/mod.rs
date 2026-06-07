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
mod testutil;
#[cfg(feature = "tls")]
mod tls;
pub use conn::Conn;
pub use coordinator::StreamCoordinator;
pub use labeled::{LabelOptions, Labeled};
pub use passthrough::Passthrough;
#[cfg(feature = "quic")]
pub use quic::{
  CertOid, ClusterTls, DialError, Hello, Identified, IdentityConfig, IdentityCtx, IdentityOutcome,
  IdentitySource, ProvidedIdentity, QuicCoordinator, QuicOptions, StreamLayout,
};
pub use router::{ConnId, PeerRouter};
pub use stream::{Intake, StreamTransport};
#[cfg(feature = "tls")]
pub use tls::{TlsOptions, TlsRecords};

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

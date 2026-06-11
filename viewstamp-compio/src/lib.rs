//! Proactor (compio) QUIC driver for `viewstamp-proto`.
//!
//! A single compio task owns a [`viewstamp_proto::QuicCoordinator`] plus the embedder's
//! [`viewstamp_proto::Wal`]/[`viewstamp_proto::Superblock`] and a UDP socket, and drives consensus
//! over real I/O. The driver is generic over the state machine, storage, and identity source — it
//! bundles no backend.

mod bridge;
mod clock;
mod config;
mod driver;
mod handle;
mod session;
mod stream_driver;

pub use clock::Clock;
pub use config::DriverConfig;
pub use driver::CompioQuicDriver;
pub use handle::{Command, Handle, Reply};
pub use stream_driver::CompioStreamDriver;

/// Errors surfaced to the application through the [`Handle`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DriverError {
  /// The driver task has stopped, so the command channel is closed.
  #[error("driver has shut down")]
  DriverGone,
  /// The driver dropped the request's reply channel without answering (e.g. shutdown mid-flight).
  #[error("reply channel dropped before a reply was produced")]
  ReplyDropped,
  /// The in-flight submit budget is full: too many submitted-but-not-yet-resolved requests, by count
  /// or by total request bytes (see the node-local session caps). A `submit` never blocks
  /// indefinitely — under sustained backpressure it returns this immediately; the caller should shed
  /// load or retry later (e.g. after outstanding submits commit and free budget).
  #[error("submit budget full (too many in-flight requests); retry later")]
  Busy,
  /// The request body exceeds the largest size the transport can deliver: the per-message frame limit
  /// minus the protocol overhead a client request incurs on the wire (the `Request` the client sends
  /// AND the larger `Prepare` the primary replicates from it). Such a body would frame to more than the
  /// transport accepts and be dropped on its way to the backups, so no commit could ever arrive — the
  /// submit is REJECTED up front (without reserving budget or enqueueing a command) rather than left to
  /// hang forever. Trim the body to at most
  /// [`viewstamp_proto::max_request_body_len()`](viewstamp_proto::max_request_body_len) and retry.
  #[error(
    "request body exceeds the largest deliverable size (frame limit minus protocol overhead)"
  )]
  RequestTooLarge,
  /// Binding the UDP socket failed.
  #[error("binding the UDP socket failed: {0}")]
  Bind(#[source] std::io::Error),
  /// Dialing a configured peer failed.
  #[error("dialing peer {peer:?} failed")]
  Connect {
    /// The peer that could not be dialed.
    peer: viewstamp_proto::Peer,
  },
}

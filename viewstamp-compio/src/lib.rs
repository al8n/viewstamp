//! Proactor (compio) QUIC driver for `viewstamp-proto`.
//!
//! A single compio task owns a [`viewstamp_proto::QuicCoordinator`] plus the embedder's
//! [`viewstamp_proto::Wal`]/[`viewstamp_proto::Superblock`] and a UDP socket, and drives consensus
//! over real I/O. The driver is generic over the state machine, storage, and identity source — it
//! bundles no backend.
//!
//! # Scaling across cores
//!
//! One consensus group is one serial state machine: a single [`CompioQuicDriver`] /
//! [`CompioStreamDriver`] owns its endpoint, storage, and socket, and `run()` drives them on one
//! thread. The compio runtime's `spawn` takes plain `!Send` futures and never migrates a task, so
//! every task a driver creates — the run loop, its persistent recv/accept task, the per-connection
//! bridges — stays on the thread that spawned it, by construction. There is no parallelism inside
//! a group, and none would help: consensus applies committed operations in log order, so one
//! group's throughput ceiling is one core by design.
//!
//! Scale-out is therefore N INDEPENDENT groups, not more threads in one group: one driver plus
//! one compio `Runtime` per thread (optionally pinned to a core via the runtime builder's
//! `thread_affinity`), each driver binding its own socket/port and forming its own replica mesh.
//! Groups share nothing — separate endpoints, separate WAL/superblock stores, separate sockets —
//! so N groups scale to N cores with no cross-group coordination.
//!
//! [`Handle`]s are the only objects meant to cross threads: a `Handle` is `Send + Sync` and O(1)
//! to clone, so any thread may `submit` to any group and await the committed reply — the bounded
//! command channel and the per-submit reply channel do the crossing.
//!
//! The one footgun: a compio socket attaches to the proactor of the thread that CONSTRUCTS it,
//! exactly once, so each driver must be constructed AND run on its own thread — build it inside
//! that thread's `Runtime` (e.g. at the top of its `block_on`), never on a coordinator thread
//! that then ships it elsewhere. The stream driver enforces this structurally: its `Rc`
//! connection factories make the driver `!Send`, so it cannot leave the thread that built it. The
//! QUIC driver has no equivalent structural guard, so keeping construction and `run()` on one
//! thread is the embedder's contract there. (A runnable multi-group example is future work; the
//! single-group embedding is `examples/three_node.rs`.)

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

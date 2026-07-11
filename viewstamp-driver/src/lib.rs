#![doc(html_logo_url = "https://raw.githubusercontent.com/al8n/viewstamp/main/art/logo_72x72.png")]
//! Runtime-agnostic driver core shared by the viewstamp driver crates.
//!
//! A driver binds `viewstamp-proto`'s Sans-I/O consensus endpoint to a real runtime; this crate is
//! the runtime-independent half of that job, shared by every driver: the embedder-facing
//! [`Handle`] and its [`Command`] protocol, the in-flight submit budget the handle reserves
//! against, the [`DriverConfig`] tuning surface, the [`Clock`] anchoring the proto's monotonic
//! instants to std time, the session run-loop helpers (endpoint construction, pending-submit
//! bookkeeping, retransmission, committed-event delivery), the [`DriverError`] type drivers
//! surface to the application, and the edge-batching [`aggregator`] coalescing many caller units
//! into one consensus op per submit.

mod aggregate;
mod clock;
mod config;
mod handle;
mod reconcile;
mod reconfigure;
mod session;

pub use aggregate::{
  AggregatorPump, BatchConfig, BatchError, BatchHandle, DEFAULT_MAX_QUEUED_BYTES,
  DEFAULT_MAX_QUEUED_UNITS, NeverReady, NoStall, OutcomeUnknownReason, RefusedReason,
  ReplyLostReason, aggregator, aggregator_with_stall,
};
pub use clock::Clock;
pub use config::{DIAL_TIMEOUT, DriverConfig, MAX_CONNS};
pub use handle::{Command, Handle, Reply};
pub use reconcile::MembershipReconciler;
pub use reconfigure::{
  AdvanceOutcome, HealthHint, LoopBackend, LoopController, ReconfigureBackend, ReconfigureError,
  ReconfigureJob, ReconfigureProgress, StepOutcome, run_reconfigure,
};
pub use session::ReservationGuard;

#[doc(hidden)]
pub use clock::jittered;
#[doc(hidden)]
pub use config::{
  ACK_WINDOW, AUTH_DEADLINE, RECONFIGURE_TIMEOUT, REDIAL_BACKOFF_BASE, REDIAL_BACKOFF_CAP,
};
#[doc(hidden)]
pub use session::{
  EVENTS_CAP, InflightBudget, MAX_INFLIGHT, MAX_PENDING_BYTES, Pending, PendingMap,
  REQUEST_TIMEOUT, build_endpoint, deliver_event, drain_pending, pending_scan_interval,
  reap_and_collect_retransmits,
};

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
  /// This node is no longer part of the recovered cluster membership: its stable
  /// [`MemberId`](viewstamp_proto::MemberId) ([`Config::local`](viewstamp_proto::Config)) did not
  /// resolve to any slot in the DURABLE root's membership, so a reconfiguration removed it (the
  /// `Endpoint::recover` → [`Recovered::Retired`](viewstamp_proto::Recovered) path). A retired node
  /// cannot run a replica loop; the driver refuses to start rather than booting a node the cluster
  /// has dropped. Carries the local member id and the epoch it was retired at.
  #[error("node {local} is retired at epoch {epoch}: it is absent from the recovered membership")]
  Retired {
    /// The local member id the recovered membership no longer contains.
    local: viewstamp_proto::MemberId,
    /// The configuration epoch this node was retired at.
    epoch: viewstamp_proto::Epoch,
  },
  /// The configured connection cap cannot admit the configured peer mesh. The mesh is
  /// mutual-dial: every replica dials each configured peer AND must accept each peer's dial back
  /// (an inbound socket is admission-controlled until its handshake validates, so the cap must
  /// leave room for it) — the floor is therefore TWICE the peer count. Mesh links are consensus
  /// liveness and never load-shed, so a cap below that floor is a misconfiguration the
  /// constructor refuses rather than a load condition the driver could shed its way out of.
  #[error(
    "max_conns ({max_conns}) is below twice the configured peer count ({peers}); the cap must admit every dialed AND accepted mesh connection"
  )]
  CapBelowPeerMesh {
    /// The configured connection cap.
    max_conns: usize,
    /// The configured peer-mesh size; the cap must be at least twice this.
    peers: usize,
  },
}

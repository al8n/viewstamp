//! Stream-layout selector and message partition for the QUIC transport.
//!
//! A `StreamLayout` names the set of per-connection QUIC streams the coordinator
//! opens.  `Single` collapses everything onto one bidirectional stream (the
//! Phase-A/B default).  `ControlBulk` opens two streams: a `Control` stream for
//! latency-critical small messages (heartbeats, votes, solicitations) and a
//! `Bulk` stream for state-transfer and large log carriers so they cannot
//! head-of-line block a heartbeat on the same stream.
//!
//! The partition is a pure function — no I/O, no state — so it is cheap to call
//! in the coordinator's hot send path and trivial to test.

use crate::Message;

/// Which set of QUIC streams to open per peer connection.
///
/// `ControlBulk` is the default and separates latency-sensitive control traffic
/// (heartbeats, votes, solicitations) from bulk state-transfer traffic on
/// distinct streams so that a large state-transfer frame cannot block a
/// heartbeat.  `Single` collapses all traffic onto one stream and is kept for
/// environments where a single bidi stream per peer is sufficient (e.g. a
/// minimal test harness or a future client endpoint).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, derive_more::IsVariant)]
#[non_exhaustive]
pub enum StreamLayout {
  /// One bidirectional stream per peer: all messages share one control stream.
  Single,
  /// Two bidirectional streams per peer: a low-latency control stream for small
  /// messages and a bulk stream for state-transfer / large log carriers.
  #[default]
  ControlBulk,
}

/// Which of the two stream classes carries a message under `ControlBulk`.
///
/// Under `Single` the coordinator always uses `Control` (index 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant)]
pub(crate) enum StreamClass {
  /// The low-latency stream: heartbeats, votes, solicitations, small prepares.
  Control,
  /// The bulk stream: state-transfer and large log carriers.
  Bulk,
}

impl StreamClass {
  /// Stable index into a per-class array (`[StreamState; 2]`).
  pub(crate) const fn as_index(self) -> usize {
    match self {
      Self::Control => 0,
      Self::Bulk => 1,
    }
  }
}

/// `Prepare` body bytes above this threshold route to the Bulk stream so a
/// large operation body cannot head-of-line block a heartbeat on the Control
/// stream.  Sized well under the bulk stream_receive_window (8 MiB).
pub(crate) const PREPARE_BULK_THRESHOLD: usize = 64 * 1024;

/// Pure: which stream class carries `msg` under `layout`.
///
/// `Single` → always `Control` (one stream, no partition).
/// `ControlBulk` rules:
/// - State-transfer / whole-log carriers (`SyncCheckpoint`, `DoViewChange`,
///   `StartView`, `RecoveryResponse`) → `Bulk`.
/// - A `Prepare` whose body exceeds `PREPARE_BULK_THRESHOLD` → `Bulk`.
/// - A `PrepareBatch` whose encoded size exceeds `PREPARE_BULK_THRESHOLD` →
///   `Bulk` (the batched retransmit of the same prepares; its whole frame is
///   what would occupy the stream, so the threshold applies to the encoding).
/// - Everything else → `Control`: `Commit` / heartbeat, `PrepareOk`, `Reply`,
///   `StartViewChange`, `GetView`, `RequestPrepare`, `Recovery`, `RequestSync`,
///   `Request`, and small `Prepare`s / `PrepareBatch`es.
///
/// The COORDINATOR's send-path router ([`write_to_peer`](super::QuicCoordinator)) is the live caller.
pub(crate) fn partition(msg: &Message, layout: StreamLayout) -> StreamClass {
  if layout.is_single() {
    return StreamClass::Control;
  }
  match msg {
    // State-transfer and whole-log carriers belong on the Bulk stream.
    Message::SyncCheckpoint(_)
    | Message::DoViewChange(_)
    | Message::StartView(_)
    | Message::RecoveryResponse(_) => StreamClass::Bulk,
    // A large prepare body must not block a heartbeat on Control.
    Message::Prepare(p) if p.body().len() > PREPARE_BULK_THRESHOLD => StreamClass::Bulk,
    // The batched retransmit aggregates many prepare bodies into one frame — the same
    // must-not-block-a-heartbeat rule, applied to the frame the batch actually occupies the
    // stream with (its exact pre-encode size, `encoded_len`).
    Message::PrepareBatch(_) if msg.encoded_len() > PREPARE_BULK_THRESHOLD => StreamClass::Bulk,
    // All other messages — Commit/heartbeat, PrepareOk, Reply, StartViewChange,
    // GetView, RequestPrepare, Recovery, RequestSync, Request, and small
    // Prepares / PrepareBatches — ride Control.
    _ => StreamClass::Control,
  }
}

#[cfg(test)]
mod tests;

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
mod tests {
  use bytes::Bytes;

  use super::*;
  use crate::{
    ClientId, Message, OpNumber, ReplicaId, RequestNumber, View,
    message::{Commit, DoViewChange, PrepareOk, RecoveryResponse, StartView, SyncCheckpoint},
  };

  fn view(v: u64) -> View {
    View::with(v)
  }
  fn op(n: u64) -> OpNumber {
    OpNumber::with(n)
  }
  fn client() -> ClientId {
    ClientId::new(1)
  }
  fn replica() -> ReplicaId {
    ReplicaId::new(0)
  }
  fn req() -> RequestNumber {
    RequestNumber::with(1)
  }

  fn commit_msg() -> Message {
    Message::Commit(Commit::new(view(1), op(1), op(0)))
  }

  fn prepare_ok_msg() -> Message {
    Message::PrepareOk(PrepareOk::new(view(1), op(1), replica(), op(0), 0))
  }

  fn prepare_msg(body: Bytes) -> Message {
    use crate::message::Prepare;
    Message::Prepare(Prepare::new(
      view(1),
      op(1),
      op(0),
      op(0),
      client(),
      req(),
      body,
    ))
  }

  fn prepare_batch_msg(body: Bytes) -> Message {
    use crate::{PreparedEntry, message::PrepareBatch};
    Message::PrepareBatch(PrepareBatch::new(
      view(1),
      op(0),
      op(0),
      vec![PreparedEntry::new(op(1), client(), req(), body)],
    ))
  }

  fn sync_checkpoint_msg() -> Message {
    let snapshot = Bytes::from(vec![0u8; 1024]);
    Message::SyncCheckpoint(SyncCheckpoint::new(
      view(1),
      op(1),
      0,
      replica(),
      99,
      snapshot,
    ))
  }

  fn do_view_change_msg() -> Message {
    // DoViewChange always routes to Bulk regardless of log size (it is a whole-log carrier).
    Message::DoViewChange(DoViewChange::new(
      view(2),
      view(1),
      op(10),
      op(5),
      replica(),
      vec![],
    ))
  }

  fn start_view_msg() -> Message {
    Message::StartView(StartView::new(view(2), op(10), op(5), replica(), vec![]))
  }

  fn recovery_response_msg() -> Message {
    Message::RecoveryResponse(RecoveryResponse::new(
      view(1),
      op(5),
      op(3),
      replica(),
      7,
      vec![],
    ))
  }

  #[test]
  fn control_and_bulk_classify_as_expected() {
    let l = StreamLayout::ControlBulk;

    // Small latency-critical messages → Control.
    assert_eq!(partition(&commit_msg(), l), StreamClass::Control);
    assert_eq!(partition(&prepare_ok_msg(), l), StreamClass::Control);

    // State-transfer carriers → Bulk.
    assert_eq!(partition(&sync_checkpoint_msg(), l), StreamClass::Bulk);
    assert_eq!(partition(&do_view_change_msg(), l), StreamClass::Bulk);
    assert_eq!(partition(&start_view_msg(), l), StreamClass::Bulk);
    assert_eq!(partition(&recovery_response_msg(), l), StreamClass::Bulk);

    // Small Prepare → Control; body len well under PREPARE_BULK_THRESHOLD.
    let small_body = Bytes::from(vec![0u8; 100]);
    assert_eq!(partition(&prepare_msg(small_body), l), StreamClass::Control);

    // Large Prepare (body > 64 KiB) → Bulk to avoid blocking heartbeats.
    let big_body = Bytes::from(vec![0u8; PREPARE_BULK_THRESHOLD + 1]);
    assert_eq!(partition(&prepare_msg(big_body), l), StreamClass::Bulk);

    // Small PrepareBatch (encoded size well under the threshold) → Control; a batch whose
    // encoding exceeds it → Bulk (the batched-retransmit analogue of the Prepare rule).
    let small_batch = prepare_batch_msg(Bytes::from(vec![0u8; 100]));
    assert!(small_batch.encoded_len() <= PREPARE_BULK_THRESHOLD);
    assert_eq!(partition(&small_batch, l), StreamClass::Control);
    let big_batch = prepare_batch_msg(Bytes::from(vec![0u8; PREPARE_BULK_THRESHOLD + 1]));
    assert!(big_batch.encoded_len() > PREPARE_BULK_THRESHOLD);
    assert_eq!(partition(&big_batch, l), StreamClass::Bulk);
    assert_eq!(
      partition(&big_batch, StreamLayout::Single),
      StreamClass::Control
    );

    // Single collapses everything to Control regardless of message type.
    let big_body2 = Bytes::from(vec![0u8; PREPARE_BULK_THRESHOLD + 1]);
    assert_eq!(
      partition(&sync_checkpoint_msg(), StreamLayout::Single),
      StreamClass::Control
    );
    assert_eq!(
      partition(&prepare_msg(big_body2), StreamLayout::Single),
      StreamClass::Control
    );
  }
}

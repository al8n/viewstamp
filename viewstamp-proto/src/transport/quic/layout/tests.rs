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
  Message::Commit(Commit::new(view(1), op(1), op(0), crate::Epoch::new(0), 0))
}

fn prepare_ok_msg() -> Message {
  Message::PrepareOk(PrepareOk::new(
    view(1),
    op(1),
    replica(),
    op(0),
    0,
    crate::Epoch::new(0),
    0,
  ))
}

fn prepare_msg(body: Bytes) -> Message {
  use crate::message::Prepare;
  Message::Prepare(Prepare::new(
    view(1),
    op(1),
    op(0),
    op(0),
    crate::Epoch::new(0),
    0,
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
    crate::Epoch::new(0),
    0,
    vec![PreparedEntry::new(op(1), client(), req(), body)],
  ))
}

fn sync_checkpoint_msg() -> Message {
  let snapshot = Bytes::from(vec![0u8; 1024]);
  Message::SyncCheckpoint(SyncCheckpoint::new(
    view(1),
    op(1),
    0,
    crate::Epoch::new(0),
    0,
    replica(),
    99,
    snapshot,
    Bytes::new(),
  ))
}

fn do_view_change_msg() -> Message {
  // DoViewChange always routes to Bulk regardless of log size (it is a whole-log carrier).
  Message::DoViewChange(DoViewChange::new(
    view(2),
    view(1),
    op(10),
    op(5),
    crate::Epoch::new(0),
    0,
    replica(),
    vec![],
  ))
}

fn start_view_msg() -> Message {
  Message::StartView(StartView::new(
    view(2),
    op(10),
    op(5),
    crate::Epoch::new(0),
    0,
    replica(),
    vec![],
  ))
}

fn recovery_response_msg() -> Message {
  Message::RecoveryResponse(RecoveryResponse::new(
    view(1),
    op(5),
    op(3),
    crate::Epoch::new(0),
    0,
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

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

  // Small PrepareBatch (size bound well under the threshold) → Control; a batch whose
  // size bound exceeds it → Bulk (the batched-retransmit analogue of the Prepare rule).
  let small_batch = prepare_batch_msg(Bytes::from(vec![0u8; 100]));
  assert!(small_batch.wire_size_bound() <= PREPARE_BULK_THRESHOLD);
  assert_eq!(partition(&small_batch, l), StreamClass::Control);
  let big_batch = prepare_batch_msg(Bytes::from(vec![0u8; PREPARE_BULK_THRESHOLD + 1]));
  assert!(big_batch.wire_size_bound() > PREPARE_BULK_THRESHOLD);
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

/// Reverting `partition`'s `PrepareBatch` arm to size by [`Message::encoded_len`] (the exact
/// protobuf length) instead of [`Message::wire_size_bound`] (the saturating structural bound)
/// would still pass `control_and_bulk_classify_as_expected` above, because that test's fixtures
/// put both measures on the same side of `PREPARE_BULK_THRESHOLD`. This test does not: it finds a
/// body length `B` for which the EXACT encoding lands AT OR UNDER the threshold while the
/// structural bound lands OVER it — the two measures straddle the threshold — so only a
/// bound-based classification routes this exact batch `Bulk`.
///
/// The straddle exists because `wire_size_bound` charges every scalar field (`view`/`commit`/
/// `checkpoint_op`/`epoch`) its WORST-CASE varint width, while `prepare_batch_msg`'s fixture
/// values are all small (0 or 1) and so actually encode in 1-2 bytes each: a fixed overhead gap
/// between the two measures for this one-entry shape. `B` is found by backing off from the
/// threshold rather than hard-coded, so the test keeps deriving a real straddle even if that gap
/// shifts (e.g. a field added to either overhead model).
#[test]
fn prepare_batch_straddles_bulk_threshold_by_wire_size_bound() {
  // Back off from the threshold one byte at a time until the EXACT encoding fits at or under it.
  // `encoded_len` is non-decreasing in the body length here, so the first hit is the largest B in
  // the straddle window. A generous probe cap keeps this a bounded search rather than a silent
  // infinite loop if the overhead model ever changes shape.
  const MAX_PROBES: usize = 1024;
  let batch = (0..MAX_PROBES)
    .map(|probed| {
      let body_len = PREPARE_BULK_THRESHOLD
        .checked_sub(probed)
        .expect("PREPARE_BULK_THRESHOLD underflowed while searching for a straddling body length");
      prepare_batch_msg(Bytes::from(vec![0u8; body_len]))
    })
    .find(|candidate| candidate.encoded_len() <= PREPARE_BULK_THRESHOLD)
    .unwrap_or_else(|| {
      panic!(
        "no body length within {MAX_PROBES} bytes below PREPARE_BULK_THRESHOLD produced \
         encoded_len() <= threshold — the encoded_len overhead model may have grown"
      )
    });

  // Setup: the exact encoding is at or under the threshold ...
  assert!(
    batch.encoded_len() <= PREPARE_BULK_THRESHOLD,
    "encoded_len() {} expected <= threshold {}",
    batch.encoded_len(),
    PREPARE_BULK_THRESHOLD
  );
  // ... while the structural bound over-charges past it: the straddle this test exists to build.
  assert!(
    batch.wire_size_bound() > PREPARE_BULK_THRESHOLD,
    "wire_size_bound() {} expected > threshold {} — no straddle at this body length; the gap \
     between wire_size_bound and encoded_len may have shrunk to zero",
    batch.wire_size_bound(),
    PREPARE_BULK_THRESHOLD
  );

  // The property under test: classification uses the bound, not the exact length, so this
  // straddling batch still routes Bulk. Reverting `partition` to `encoded_len() >
  // PREPARE_BULK_THRESHOLD` classifies this exact batch `Control` and fails this assertion.
  assert_eq!(
    partition(&batch, StreamLayout::ControlBulk),
    StreamClass::Bulk
  );
}

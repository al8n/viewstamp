use bytes::Bytes;

use super::{convert, messages_a, messages_b, pb};
use crate::{
  BlockAddress, BlockResponse, ClientId, Commit, DoViewChange, Epoch, EpochAhead, GetView,
  LearnerProof, LearnerStatus, MemberId, Nack, OpNumber, Prepare, PrepareBatch, PrepareOk,
  PreparedEntry, ReconfigurePayload, Recovery, RecoveryResponse, RepairBatch, ReplicaId, Reply,
  Request, RequestLearnerProof, RequestNumber, RequestPrepare, RequestPrepareRange, RequestSync,
  StartView, StartViewChange, SyncCheckpoint, View,
};
use buffa::Message as _;

#[test]
fn generated_envelope_round_trips_a_default_request() {
  let msg = pb::Message {
    body: Some(pb::message::Body::Request(Box::new(pb::Request {
      client: bytes::Bytes::from_static(&[1u8; 16]),
      request: 7,
      body: bytes::Bytes::from_static(b"payload"),
      ..Default::default()
    }))),
    ..Default::default()
  };
  let bytes = msg.encode_to_bytes();
  let back = pb::Message::decode_from_slice(&bytes).expect("well-formed envelope decodes");
  assert_eq!(back, msg);
}

/// A representative `Body::Present` entry for the rejection tests below to mutate one wire field
/// at a time.
fn some_entry() -> PreparedEntry {
  PreparedEntry::new(
    OpNumber::with(1),
    ClientId::new(1),
    RequestNumber::with(1),
    Bytes::from_static(b"z"),
  )
}

#[test]
fn prepared_entry_present_round_trips() {
  let e = PreparedEntry::new(
    OpNumber::with(3),
    ClientId::new(9),
    RequestNumber::with(2),
    Bytes::from_static(b"xy"),
  );
  let back = convert::entry_from(convert::pb_entry(&e)).expect("round-trip");
  assert_eq!(back, e);
}

#[test]
fn prepared_entry_repairing_round_trips() {
  let e = PreparedEntry::repairing(
    OpNumber::with(11),
    ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
    RequestNumber::with(6),
    0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708,
  );
  let back = convert::entry_from(convert::pb_entry(&e)).expect("round-trip");
  assert_eq!(back, e);
}

#[test]
fn prepared_entry_reconfigure_round_trips() {
  let payload = ReconfigurePayload::new(
    3,
    1,
    std::vec![MemberId::new(1), MemberId::new(2)].into_boxed_slice(),
    7,
  );
  let e = PreparedEntry::reconfigure(
    OpNumber::with(12),
    ClientId::RECONFIGURATION,
    RequestNumber::with(4),
    payload,
  );
  let back = convert::entry_from(convert::pb_entry(&e)).expect("round-trip");
  assert_eq!(back, e);
}

/// A representative 3-entry log spanning all three body states (`Present`, `Repairing`,
/// `Reconfigure`) — reused by every log-carrying round-trip test below so the three states aren't
/// re-declared per test.
fn mixed_log() -> std::vec::Vec<PreparedEntry> {
  std::vec![
    PreparedEntry::new(
      OpNumber::with(1),
      ClientId::new(1),
      RequestNumber::with(1),
      Bytes::from_static(b"a"),
    ),
    PreparedEntry::repairing(
      OpNumber::with(2),
      ClientId::new(2),
      RequestNumber::with(2),
      0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00,
    ),
    PreparedEntry::reconfigure(
      OpNumber::with(3),
      ClientId::RECONFIGURATION,
      RequestNumber::with(3),
      ReconfigurePayload::new(
        2,
        0,
        std::vec![MemberId::new(1), MemberId::new(2)].into_boxed_slice(),
        0,
      ),
    ),
  ]
}

#[test]
fn log_round_trips_a_mixed_batch() {
  let log = mixed_log();
  let back = convert::log_from(convert::pb_log(&log)).expect("round-trip");
  assert_eq!(back, log);
}

#[test]
fn entry_with_undersized_client_id_rejects() {
  let mut w = convert::pb_entry(&some_entry());
  w.client = Bytes::from_static(&[0u8; 15]);
  assert!(convert::entry_from(w).is_err());
}

#[test]
fn entry_with_oversized_checksum_rejects() {
  let repairing = PreparedEntry::repairing(
    OpNumber::with(1),
    ClientId::new(1),
    RequestNumber::with(1),
    0,
  );
  let mut w = convert::pb_entry(&repairing);
  w.body_state = Some(pb::prepared_entry::BodyState::RepairingChecksum(
    Bytes::from_static(&[0u8; 17]),
  ));
  assert!(convert::entry_from(w).is_err());
}

#[test]
fn replica_from_rejects_an_oversized_value() {
  assert!(convert::replica_from(70_000, "test.replica").is_err());
}

#[test]
fn reconfigure_with_oversized_replica_count_rejects() {
  let mut w = convert::pb_reconfigure(&ReconfigurePayload::new(
    1,
    0,
    std::vec![MemberId::new(1)].into_boxed_slice(),
    0,
  ));
  w.replica_count = 300;
  assert!(convert::reconfigure_from(w).is_err());
}

#[test]
fn entry_without_body_state_rejects() {
  let mut w = convert::pb_entry(&some_entry());
  w.body_state = None;
  assert!(convert::entry_from(w).is_err());
}

// ── rows 1–12: client, normal-protocol, view-change, and recovery messages ──

#[test]
fn request_round_trips() {
  let m = Request::new(
    ClientId::new(0x1111_2222_3333_4444_5555_6666_7777_8888),
    RequestNumber::with(21),
    Bytes::from_static(b"request-body"),
  );
  let back = messages_a::request_from(messages_a::pb_request(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn prepare_round_trips() {
  let m = Prepare::new(
    View::with(101),
    OpNumber::with(102),
    OpNumber::with(103),
    OpNumber::with(104),
    Epoch::new(105),
    0xAAAA_1111_2222_3333_4444_5555_6666_7777,
    ClientId::new(0xBBBB_1111_2222_3333_4444_5555_6666_7777),
    RequestNumber::with(106),
    Bytes::from_static(b"prepare-body"),
  );
  let back = messages_a::prepare_from(messages_a::pb_prepare(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn prepare_ok_round_trips() {
  let m = PrepareOk::new(
    View::with(201),
    OpNumber::with(202),
    ReplicaId::new(203),
    OpNumber::with(204),
    0xCCCC_1111_2222_3333_4444_5555_6666_7777,
    Epoch::new(205),
    0xDDDD_1111_2222_3333_4444_5555_6666_7777,
  );
  let back = messages_a::prepare_ok_from(messages_a::pb_prepare_ok(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn reply_round_trips() {
  let m = Reply::new(
    View::with(301),
    ClientId::new(0xEEEE_1111_2222_3333_4444_5555_6666_7777),
    RequestNumber::with(302),
    Bytes::from_static(b"reply-body"),
  );
  let back = messages_a::reply_from(messages_a::pb_reply(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn commit_round_trips() {
  let m = Commit::new(
    View::with(401),
    OpNumber::with(402),
    OpNumber::with(403),
    Epoch::new(404),
    0xFFFF_1111_2222_3333_4444_5555_6666_7777,
  );
  let back = messages_a::commit_from(messages_a::pb_commit(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn start_view_change_round_trips() {
  let m = StartViewChange::new(
    View::with(501),
    ReplicaId::new(502),
    Epoch::new(503),
    0x1010_1111_2222_3333_4444_5555_6666_7777,
  );
  let back =
    messages_a::start_view_change_from(messages_a::pb_start_view_change(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn do_view_change_round_trips() {
  let m = DoViewChange::new(
    View::with(601),
    View::with(602),
    OpNumber::with(603),
    OpNumber::with(604),
    Epoch::new(605),
    0x2020_1111_2222_3333_4444_5555_6666_7777,
    ReplicaId::new(606),
    mixed_log(),
  )
  .with_checkpoint_op(OpNumber::with(607));
  let back =
    messages_a::do_view_change_from(messages_a::pb_do_view_change(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn start_view_round_trips() {
  let m = StartView::new(
    View::with(701),
    OpNumber::with(702),
    OpNumber::with(703),
    Epoch::new(704),
    0x3030_1111_2222_3333_4444_5555_6666_7777,
    ReplicaId::new(705),
    mixed_log(),
  )
  .with_checkpoint_op(OpNumber::with(706));
  let back = messages_a::start_view_from(messages_a::pb_start_view(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn get_view_round_trips() {
  let m = GetView::new(
    View::with(801),
    ReplicaId::new(802),
    803,
    Epoch::new(804),
    0x4040_1111_2222_3333_4444_5555_6666_7777,
  );
  let back = messages_a::get_view_from(messages_a::pb_get_view(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn request_prepare_round_trips() {
  let m = RequestPrepare::new(
    View::with(901),
    OpNumber::with(902),
    ReplicaId::new(903),
    0x5050_1111_2222_3333_4444_5555_6666_7777,
  );
  let back =
    messages_a::request_prepare_from(messages_a::pb_request_prepare(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn recovery_round_trips() {
  let m = Recovery::new(
    ReplicaId::new(1001),
    1002,
    Epoch::new(1003),
    0x6060_1111_2222_3333_4444_5555_6666_7777,
  );
  let back = messages_a::recovery_from(messages_a::pb_recovery(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn recovery_response_round_trips() {
  let m = RecoveryResponse::new(
    View::with(1101),
    OpNumber::with(1102),
    OpNumber::with(1103),
    Epoch::new(1104),
    0x7070_1111_2222_3333_4444_5555_6666_7777,
    ReplicaId::new(1105),
    1106,
    mixed_log(),
  )
  .with_checkpoint_op(OpNumber::with(1107));
  let back =
    messages_a::recovery_response_from(messages_a::pb_recovery_response(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn prepare_ok_with_undersized_prepare_checksum_rejects() {
  let m = PrepareOk::new(
    View::with(1),
    OpNumber::with(1),
    ReplicaId::new(1),
    OpNumber::with(0),
    0xAB,
    Epoch::new(0),
    0,
  );
  let mut w = messages_a::pb_prepare_ok(&m);
  w.prepare_checksum = Bytes::from_static(&[0u8; 15]);
  assert!(messages_a::prepare_ok_from(w).is_err());
}

#[test]
fn start_view_change_with_oversized_replica_rejects() {
  let m = StartViewChange::new(View::with(1), ReplicaId::new(1), Epoch::new(0), 0);
  let mut w = messages_a::pb_start_view_change(&m);
  w.replica = 70_000;
  assert!(messages_a::start_view_change_from(w).is_err());
}

// ── rows 13–24: sync, windowed repair, batching, learner, block, and nack messages ──

#[test]
fn request_sync_round_trips() {
  let m = RequestSync::new(
    View::with(1201),
    OpNumber::with(1202),
    ReplicaId::new(1203),
    1204,
    true,
    0x8181_1111_2222_3333_4444_5555_6666_7777,
  );
  let back = messages_b::request_sync_from(messages_b::pb_request_sync(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn sync_checkpoint_round_trips() {
  let m = SyncCheckpoint::new(
    View::with(1301),
    OpNumber::with(1302),
    0x8282_1111_2222_3333_4444_5555_6666_7777,
    Epoch::new(1303),
    0x8383_1111_2222_3333_4444_5555_6666_7777,
    ReplicaId::new(1304),
    1305,
    Bytes::from_static(b"snapshot-body"),
    Bytes::from_static(b"membership-body"),
  );
  let back =
    messages_b::sync_checkpoint_from(messages_b::pb_sync_checkpoint(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn request_prepare_range_round_trips() {
  let m = RequestPrepareRange::new(
    View::with(1401),
    OpNumber::with(1402),
    OpNumber::with(1403),
    ReplicaId::new(1404),
    0x8484_1111_2222_3333_4444_5555_6666_7777,
  );
  let back = messages_b::request_prepare_range_from(messages_b::pb_request_prepare_range(&m))
    .expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn repair_batch_round_trips() {
  let m = RepairBatch::new(
    View::with(1501),
    OpNumber::with(1502),
    OpNumber::with(1503),
    0x8585_1111_2222_3333_4444_5555_6666_7777,
    mixed_log(),
  );
  let back = messages_b::repair_batch_from(messages_b::pb_repair_batch(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn prepare_batch_round_trips() {
  let m = PrepareBatch::new(
    View::with(1601),
    OpNumber::with(1602),
    OpNumber::with(1603),
    Epoch::new(1604),
    0x8686_1111_2222_3333_4444_5555_6666_7777,
    mixed_log(),
  );
  let back = messages_b::prepare_batch_from(messages_b::pb_prepare_batch(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn learner_status_round_trips() {
  let m = LearnerStatus::new(
    ReplicaId::new(1701),
    OpNumber::with(1702),
    OpNumber::with(1703),
    Epoch::new(1704),
    0x8787_1111_2222_3333_4444_5555_6666_7777,
  );
  let back =
    messages_b::learner_status_from(messages_b::pb_learner_status(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn epoch_ahead_round_trips() {
  let m = EpochAhead::new(Epoch::new(1801), OpNumber::with(1802));
  let back = messages_b::epoch_ahead_from(messages_b::pb_epoch_ahead(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn request_learner_proof_round_trips() {
  let m = RequestLearnerProof::new(
    ReplicaId::new(1901),
    OpNumber::with(1902),
    1903,
    Epoch::new(1904),
    0x8888_1111_2222_3333_4444_5555_6666_7777,
  );
  let back = messages_b::request_learner_proof_from(messages_b::pb_request_learner_proof(&m))
    .expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn learner_proof_round_trips() {
  let m = LearnerProof::new(
    ReplicaId::new(2001),
    2002,
    OpNumber::with(2003),
    Epoch::new(2004),
    0x8989_1111_2222_3333_4444_5555_6666_7777,
  );
  let back = messages_b::learner_proof_from(messages_b::pb_learner_proof(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn request_block_round_trips() {
  let addr = BlockAddress::from_bytes(0x8B8B_1111_2222_3333_4444_5555_6666_7777u128.to_be_bytes());
  let back =
    messages_b::request_block_from(messages_b::pb_request_block(&addr)).expect("round-trip");
  assert_eq!(back, addr);
}

#[test]
fn block_response_round_trips_when_absent() {
  let addr = BlockAddress::from_bytes(0x8C8C_1111_2222_3333_4444_5555_6666_7777u128.to_be_bytes());
  let m = BlockResponse::new(addr, None);
  let back =
    messages_b::block_response_from(messages_b::pb_block_response(&m)).expect("round-trip");
  assert_eq!(back, m);
  assert!(back.is_absent());
}

#[test]
fn block_response_round_trips_when_present_empty() {
  let addr = BlockAddress::from_bytes(0x8C8C_1111_2222_3333_4444_5555_6666_7777u128.to_be_bytes());
  let m = BlockResponse::new(addr, Some(Bytes::new()));
  let back =
    messages_b::block_response_from(messages_b::pb_block_response(&m)).expect("round-trip");
  assert_eq!(back, m);
  assert!(back.is_present());
  assert_eq!(back.block(), Some(&b""[..]));
}

#[test]
fn block_response_round_trips_when_present_with_data() {
  let addr = BlockAddress::from_bytes(0x8C8C_1111_2222_3333_4444_5555_6666_7777u128.to_be_bytes());
  let m = BlockResponse::new(addr, Some(Bytes::from_static(b"block-data")));
  let back =
    messages_b::block_response_from(messages_b::pb_block_response(&m)).expect("round-trip");
  assert_eq!(back, m);
  assert_eq!(back.block(), Some(&b"block-data"[..]));
}

#[test]
fn nack_round_trips() {
  let m = Nack::new(
    View::with(2101),
    OpNumber::with(2102),
    ReplicaId::new(2103),
    0x8A8A_1111_2222_3333_4444_5555_6666_7777,
  );
  let back = messages_b::nack_from(messages_b::pb_nack(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn sync_checkpoint_with_undersized_checkpoint_id_rejects() {
  let m = SyncCheckpoint::new(
    View::with(1),
    OpNumber::with(1),
    0xAB,
    Epoch::new(0),
    0,
    ReplicaId::new(1),
    0,
    Bytes::new(),
    Bytes::new(),
  );
  let mut w = messages_b::pb_sync_checkpoint(&m);
  w.checkpoint_id = Bytes::from_static(&[0u8; 15]);
  assert!(messages_b::sync_checkpoint_from(w).is_err());
}

#[test]
fn block_response_with_oversized_addr_rejects() {
  let m = BlockResponse::new(BlockAddress::from_bytes([0u8; 16]), None);
  let mut w = messages_b::pb_block_response(&m);
  w.addr = Bytes::from_static(&[0u8; 17]);
  assert!(messages_b::block_response_from(w).is_err());
}

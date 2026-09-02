use std::{boxed::Box, fmt::Write as _};

use bytes::Bytes;

use super::{
  MAX_UNKNOWN_FIELDS, convert, decode_message, encode_message, messages_a, messages_b, pb,
};
use crate::{
  BlockAddress, BlockResponse, ClientId, CodecError, Commit, DoViewChange, Epoch, EpochAhead,
  GetView, HealthProof, LearnerProof, LearnerStatus, MemberId, Message, Nack, OpNumber, Prepare,
  PrepareBatch, PrepareOk, PreparedEntry, ReconfigurePayload, Recovery, RecoveryResponse,
  RepairBatch, ReplicaId, Reply, ReplyBody, ReplyOutcome, ReplyTooLarge, Request,
  RequestHealthProof, RequestLearnerProof, RequestNumber, RequestPrepare, RequestPrepareRange,
  RequestSync, StartView, StartViewChange, SyncCheckpoint, View,
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

#[test]
fn a_reconfiguration_client_entry_with_an_untyped_present_body_is_rejected() {
  // A RECONFIGURATION-client op is typed `Reconfigure` on the wire (or header-only
  // `RepairingChecksum`) by construction; a `Present` state under that client id is a
  // malformed/corrupted entry. Admitting it would seed an UNTYPED log entry that commit
  // recognition and the voter-admission screens cannot classify — `entry_from` refuses it at the
  // seam instead.
  let w = pb::PreparedEntry {
    op: 1,
    client: Bytes::copy_from_slice(&ClientId::RECONFIGURATION.get().to_be_bytes()),
    request: 1,
    body_state: Some(pb::prepared_entry::BodyState::Present(Bytes::from_static(
      b"x",
    ))),
    ..Default::default()
  };
  assert!(
    convert::entry_from(w).is_err(),
    "a RECONFIGURATION-client entry carried as an untyped Present body is refused"
  );
  // The two legitimate carriages for the same client id still convert (the positive control).
  let typed = PreparedEntry::reconfigure(
    OpNumber::with(1),
    ClientId::RECONFIGURATION,
    RequestNumber::with(1),
    ReconfigurePayload::new(
      2,
      0,
      std::vec![MemberId::new(1), MemberId::new(2)].into_boxed_slice(),
      0,
    ),
  );
  assert_eq!(
    convert::entry_from(convert::pb_entry(&typed)).expect("the typed carriage round-trips"),
    typed
  );
  let header_only = PreparedEntry::repairing(
    OpNumber::with(2),
    ClientId::RECONFIGURATION,
    RequestNumber::with(2),
    7,
  );
  assert_eq!(
    convert::entry_from(convert::pb_entry(&header_only))
      .expect("the header-only carriage round-trips"),
    header_only
  );
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
fn log_from_rejects_a_log_over_the_protocol_maximum() {
  // A valid peer never sends a log deeper than MAX_HEADER_ONLY_BAND_DEPTH (the deepest
  // header-only band any single view-change carrier can legitimately hold) in one message;
  // log_from rejects a wire count above it BEFORE converting a single entry — pinning the
  // domain's own protocol maximum, not an invented looser one. Default (body-state-less) entries
  // are used since only the COUNT matters for this bound (each would separately reject at
  // entry_from for its absent body_state, but the length check must fire first, before any
  // per-entry conversion runs).
  let over = crate::message::MAX_HEADER_ONLY_BAND_DEPTH + 1;
  let w = std::vec![pb::PreparedEntry::default(); over];
  assert!(convert::log_from(w).is_err());
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
fn reconfigure_from_rejects_members_over_the_protocol_maximum() {
  // Every member occupies a u16 ReplicaId slot, so a wire member count above u16::MAX can never
  // validate at Membership::validate_structure regardless of the voting/learner split;
  // reconfigure_from rejects it before the per-member conversion allocates.
  let over = u16::MAX as usize + 1;
  let mut w = convert::pb_reconfigure(&ReconfigurePayload::new(
    1,
    0,
    std::vec![MemberId::new(1)].into_boxed_slice(),
    0,
  ));
  w.members = std::vec![Bytes::from_static(&[0u8; 16]); over];
  assert!(convert::reconfigure_from(w).is_err());
}

#[test]
fn reconfigure_from_accepts_a_normal_sized_membership_and_still_round_trips() {
  // Regression guard: the new over-max rejection must not disturb an ordinary membership size —
  // paired with `reconfigure_body_round_trips_through_the_wire_codec`
  // (`src/message/tests.rs`), which exercises the full round trip through the domain type.
  let members: std::vec::Vec<MemberId> = (1..=5u128).map(MemberId::new).collect();
  let payload = ReconfigurePayload::new(3, 2, members.into_boxed_slice(), 0);
  let back = convert::reconfigure_from(convert::pb_reconfigure(&payload)).expect("round-trip");
  assert_eq!(back, payload);
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
    ReplyOutcome::from_applied(Bytes::from_static(b"reply-body")),
  );
  let back = messages_a::reply_from(messages_a::pb_reply(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn an_empty_reply_body_survives_the_wire_as_a_present_outcome() {
  // Presence is the reason the outcome is a oneof: an EMPTY body is a real result, and must not
  // decode back as "no outcome" (which the conversion rejects).
  let m = Reply::new(
    View::with(1),
    ClientId::new(2),
    RequestNumber::with(3),
    ReplyOutcome::Ok(ReplyBody::empty()),
  );
  let back = messages_a::reply_from(messages_a::pb_reply(&m)).expect("round-trip");
  assert_eq!(back, m);
  assert_eq!(back.outcome().as_ok().map(ReplyBody::len), Some(0));
}

#[test]
fn a_refused_reply_round_trips_with_both_lengths() {
  let err = ReplyTooLarge::new(ReplyBody::max_len() + 7, ReplyBody::max_len());
  let m = Reply::new(
    View::with(4),
    ClientId::new(5),
    RequestNumber::with(6),
    ReplyOutcome::TooLarge(err),
  );
  let back = messages_a::reply_from(messages_a::pb_reply(&m)).expect("round-trip");
  assert_eq!(back, m);
  assert_eq!(back.outcome().as_too_large(), Some(&err));
}

#[test]
fn a_reply_with_no_outcome_is_rejected() {
  // A wire reply whose oneof is absent names no outcome this build can deliver — a peer from a
  // pre-outcome era, or a corrupt envelope. It is refused at the conversion, never defaulted to an
  // empty body.
  let w = pb::Reply {
    view: 1,
    client: convert::u128_bytes(2),
    request: 3,
    outcome: None,
    ..Default::default()
  };
  assert!(matches!(
    messages_a::reply_from(w),
    Err(CodecError::Malformed {
      what: "Reply.outcome"
    })
  ));
}

#[test]
fn a_reply_body_past_the_bound_is_rejected_at_the_conversion() {
  // No compliant peer emits one — its own choke would have produced a refusal instead — so an
  // over-bound body on the wire is malformed, not a success to admit.
  let w = pb::Reply {
    view: 1,
    client: convert::u128_bytes(2),
    request: 3,
    outcome: Some(pb::reply::Outcome::Body(Bytes::from(std::vec![
      0u8;
      ReplyBody::max_len() + 1
    ]))),
    ..Default::default()
  };
  assert!(matches!(
    messages_a::reply_from(w),
    Err(CodecError::Malformed { what: "Reply.body" })
  ));
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
  // Membership-bearing, so the producing op is stamped (the codec refuses the pair split apart);
  // presence survives the round trip verbatim.
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
  )
  .with_config_install_op(OpNumber::with(1300));
  let back =
    messages_b::sync_checkpoint_from(messages_b::pb_sync_checkpoint(&m)).expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn sync_checkpoint_without_a_membership_round_trips_with_no_install_op() {
  // The membership-less answer (a same-config sync, or a donor withholding inside the
  // commit-first window): no producing op is stamped, none is encoded, and the round trip
  // reconstructs the same absent state.
  let m = SyncCheckpoint::new(
    View::with(1311),
    OpNumber::with(1312),
    0x8282_1111_2222_3333_4444_5555_6666_7777,
    Epoch::new(1313),
    0x8383_1111_2222_3333_4444_5555_6666_7777,
    ReplicaId::new(1314),
    1315,
    Bytes::from_static(b"snapshot-body"),
    Bytes::new(),
  );
  let w = messages_b::pb_sync_checkpoint(&m);
  assert_eq!(
    w.config_install_op, None,
    "an unstamped answer encodes NO producing-op field"
  );
  let back = messages_b::sync_checkpoint_from(w).expect("round-trip");
  assert_eq!(back, m);
  assert_eq!(back.config_install_op(), None);
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
fn request_health_proof_round_trips() {
  let m = RequestHealthProof::new(
    ReplicaId::new(2101),
    2102,
    Epoch::new(2103),
    0x8a8a_1111_2222_3333_4444_5555_6666_7777,
  );
  let back = messages_b::request_health_proof_from(messages_b::pb_request_health_proof(&m))
    .expect("round-trip");
  assert_eq!(back, m);
}

#[test]
fn health_proof_round_trips() {
  let m = HealthProof::new(
    ReplicaId::new(2201),
    2202,
    Epoch::new(2203),
    0x8b8b_1111_2222_3333_4444_5555_6666_7777,
  );
  let back = messages_b::health_proof_from(messages_b::pb_health_proof(&m)).expect("round-trip");
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

/// A stamped membership-bearing wire shape for the producing-op pairing tests to mutate.
fn membership_bearing_pb_sync_checkpoint() -> pb::SyncCheckpoint {
  messages_b::pb_sync_checkpoint(
    &SyncCheckpoint::new(
      View::with(21),
      OpNumber::with(22),
      0x23,
      Epoch::new(24),
      0x25,
      ReplicaId::new(26),
      27,
      Bytes::from_static(b"snapshot-body"),
      Bytes::from_static(b"membership-body"),
    )
    .with_config_install_op(OpNumber::with(9)),
  )
}

#[test]
fn sync_checkpoint_with_a_membership_but_an_absent_install_op_rejects() {
  // The producing-op field cleared under an attached membership — byte-for-byte what a sender
  // whose encoder predates the field emits (proto3 encodes nothing for an unset optional field).
  // Implicit presence would have decoded this as op 0 and let a genesis-lineage laggard install
  // the membership under a producing op no reconfigure ever committed; the conversion refuses the
  // envelope wholesale instead.
  let mut w = membership_bearing_pb_sync_checkpoint();
  w.config_install_op = None;
  assert!(matches!(
    messages_b::sync_checkpoint_from(w),
    Err(CodecError::Malformed { .. })
  ));
}

#[test]
fn a_membership_bearing_envelope_without_the_install_op_field_rejects_at_decode_message() {
  // The same refusal at the public choke point every transport decodes through, on the actual
  // encoded bytes such a sender would put on the wire.
  let mut w = membership_bearing_pb_sync_checkpoint();
  w.config_install_op = None;
  let envelope = pb::Message {
    body: Some(pb::message::Body::SyncCheckpoint(Box::new(w))),
    ..Default::default()
  };
  assert!(matches!(
    decode_message(envelope.encode_to_bytes()),
    Err(CodecError::Malformed { .. })
  ));
}

#[test]
fn sync_checkpoint_with_an_install_op_but_no_membership_rejects() {
  // The other half of the pairing: a producing op asserted with NO membership attached is the
  // same malformed split, refused symmetrically (no compliant sender produces it — the serve path
  // stamps the op exactly when it attaches the membership).
  let mut w = membership_bearing_pb_sync_checkpoint();
  w.membership = Bytes::new();
  assert!(matches!(
    messages_b::sync_checkpoint_from(w),
    Err(CodecError::Malformed { .. })
  ));
}

#[test]
fn sync_checkpoint_with_a_present_zero_install_op_is_distinct_from_absence() {
  // A genesis/offline-born configuration's producing point is genuinely 0. Explicit presence
  // keeps that claim on the wire — the stamped-zero encoding carries the field where the
  // unstamped encoding carries nothing — and the round trip reconstructs `Some(0)`, never
  // collapsing it into the refused absent state.
  let stamped = membership_bearing_pb_sync_checkpoint();
  let mut zeroed = stamped.clone();
  zeroed.config_install_op = Some(0);
  let mut absent = stamped;
  absent.config_install_op = None;
  assert_eq!(
    zeroed.encode_to_bytes().len(),
    absent.encode_to_bytes().len() + 2,
    "the explicit zero occupies its own tag + varint byte on the wire"
  );
  let back = messages_b::sync_checkpoint_from(zeroed).expect("a stamped zero round-trips");
  assert_eq!(back.config_install_op(), Some(OpNumber::new()));
}

#[test]
fn block_response_with_oversized_addr_rejects() {
  let m = BlockResponse::new(BlockAddress::from_bytes([0u8; 16]), None);
  let mut w = messages_b::pb_block_response(&m);
  w.addr = Bytes::from_static(&[0u8; 17]);
  assert!(messages_b::block_response_from(w).is_err());
}

// ── the public seam: encode_message / decode_message ──

/// One exemplar of each of [`Message`]'s 26 variants, in declaration order, built with small
/// deterministic field values. Shared by the round-trip and golden-vector tests below so both
/// exercise identical values — a golden mismatch and a round-trip failure can never disagree
/// about what was encoded.
fn one_of_each_message() -> std::vec::Vec<Message> {
  let client = ClientId::new(0x40);
  let config_id = 0x50u128;
  let prepare_checksum = 0x60u128;
  let checkpoint_id = 0x70u128;
  let addr = BlockAddress::from_bytes(0x90u128.to_be_bytes());
  let body = Bytes::from_static(b"body");
  let snapshot = Bytes::from_static(b"snapshot");
  let membership = Bytes::from_static(b"membership");

  std::vec![
    Message::Request(Request::new(client, RequestNumber::with(80), body.clone())),
    Message::Prepare(Prepare::new(
      View::with(10),
      OpNumber::with(11),
      OpNumber::with(12),
      OpNumber::with(13),
      Epoch::new(14),
      config_id,
      client,
      RequestNumber::with(80),
      body.clone(),
    )),
    Message::PrepareOk(PrepareOk::new(
      View::with(10),
      OpNumber::with(11),
      ReplicaId::new(30),
      OpNumber::with(13),
      prepare_checksum,
      Epoch::new(14),
      config_id,
    )),
    Message::Reply(Reply::new(
      View::with(10),
      client,
      RequestNumber::with(80),
      ReplyOutcome::from_applied(body.clone()),
    )),
    Message::Commit(Commit::new(
      View::with(10),
      OpNumber::with(12),
      OpNumber::with(13),
      Epoch::new(14),
      config_id,
    )),
    Message::StartViewChange(StartViewChange::new(
      View::with(10),
      ReplicaId::new(30),
      Epoch::new(14),
      config_id,
    )),
    Message::DoViewChange(
      DoViewChange::new(
        View::with(10),
        View::with(15),
        OpNumber::with(11),
        OpNumber::with(12),
        Epoch::new(14),
        config_id,
        ReplicaId::new(30),
        mixed_log(),
      )
      .with_checkpoint_op(OpNumber::with(13)),
    ),
    Message::StartView(
      StartView::new(
        View::with(10),
        OpNumber::with(11),
        OpNumber::with(12),
        Epoch::new(14),
        config_id,
        ReplicaId::new(30),
        mixed_log(),
      )
      .with_checkpoint_op(OpNumber::with(13)),
    ),
    Message::GetView(GetView::new(
      View::with(10),
      ReplicaId::new(30),
      16,
      Epoch::new(14),
      config_id,
    )),
    Message::RequestPrepare(RequestPrepare::new(
      View::with(10),
      OpNumber::with(11),
      ReplicaId::new(30),
      config_id,
    )),
    Message::Recovery(Recovery::new(
      ReplicaId::new(30),
      16,
      Epoch::new(14),
      config_id,
    )),
    Message::RecoveryResponse(
      RecoveryResponse::new(
        View::with(10),
        OpNumber::with(11),
        OpNumber::with(12),
        Epoch::new(14),
        config_id,
        ReplicaId::new(30),
        16,
        mixed_log(),
      )
      .with_checkpoint_op(OpNumber::with(13)),
    ),
    Message::RequestSync(RequestSync::new(
      View::with(10),
      OpNumber::with(13),
      ReplicaId::new(30),
      16,
      true,
      config_id,
    )),
    Message::SyncCheckpoint(
      SyncCheckpoint::new(
        View::with(10),
        OpNumber::with(13),
        checkpoint_id,
        Epoch::new(14),
        config_id,
        ReplicaId::new(30),
        16,
        snapshot.clone(),
        membership.clone(),
      )
      // Membership-bearing, so the producing op is stamped (12 — at/below the checkpoint op 13,
      // the shape the serve gate emits); the codec refuses the pair split apart.
      .with_config_install_op(OpNumber::with(12)),
    ),
    Message::RequestPrepareRange(RequestPrepareRange::new(
      View::with(10),
      OpNumber::with(17),
      OpNumber::with(18),
      ReplicaId::new(30),
      config_id,
    )),
    Message::RepairBatch(RepairBatch::new(
      View::with(10),
      OpNumber::with(12),
      OpNumber::with(13),
      config_id,
      mixed_log(),
    )),
    Message::PrepareBatch(PrepareBatch::new(
      View::with(10),
      OpNumber::with(12),
      OpNumber::with(13),
      Epoch::new(14),
      config_id,
      mixed_log(),
    )),
    Message::LearnerStatus(LearnerStatus::new(
      ReplicaId::new(30),
      OpNumber::with(19),
      OpNumber::with(20),
      Epoch::new(14),
      config_id,
    )),
    Message::EpochAhead(EpochAhead::new(Epoch::new(14), OpNumber::with(13))),
    Message::RequestLearnerProof(RequestLearnerProof::new(
      ReplicaId::new(31),
      OpNumber::with(21),
      16,
      Epoch::new(14),
      config_id,
    )),
    Message::LearnerProof(LearnerProof::new(
      ReplicaId::new(30),
      16,
      OpNumber::with(22),
      Epoch::new(14),
      config_id,
    )),
    Message::RequestHealthProof(RequestHealthProof::new(
      ReplicaId::new(31),
      17,
      Epoch::new(14),
      config_id,
    )),
    Message::HealthProof(HealthProof::new(
      ReplicaId::new(30),
      17,
      Epoch::new(14),
      config_id
    )),
    Message::RequestBlock(addr),
    Message::BlockResponse(BlockResponse::new(addr, Some(Bytes::from_static(b"block")))),
    Message::Nack(Nack::new(
      View::with(10),
      OpNumber::with(11),
      ReplicaId::new(30),
      config_id,
    )),
  ]
}

/// Every [`Message`] variant survives the PUBLIC seam — `decode_message(encode_message(&m))` —
/// with value identity, not just the per-variant conversion pair the earlier tests in this file
/// exercise directly.
#[test]
fn public_seam_round_trips_every_variant() {
  for m in one_of_each_message() {
    let back = decode_message(encode_message(&m)).unwrap_or_else(|e| {
      panic!(
        "{}: decode_message(encode_message(&m)) erred: {e:?}",
        m.kind_str()
      )
    });
    assert_eq!(back, m, "{} did not round-trip", m.kind_str());
  }
}

/// A degenerate EMPTY envelope (zero fields, no `Message.body` oneof arm) decodes cleanly and
/// classifies as the forward-compatible [`CodecError::UnknownMessage`], NOT `Malformed`: the codec
/// keeps no witness of a skipped unknown field, so "body absent" cannot be narrowed to "body absent
/// AND an unknown field was seen", and a zero-field envelope shares the newer-peer disposition. It
/// carries nothing, no current peer sends it, and dropping it (rather than tearing a stream down) is
/// equally correct — pinned deliberately as the documented degenerate case.
#[test]
fn an_empty_envelope_classifies_as_unknown_message() {
  let frame = pb::Message::default().encode_to_bytes();
  match decode_message(frame) {
    Err(CodecError::UnknownMessage) => {}
    other => panic!("expected CodecError::UnknownMessage, got {other:?}"),
  }
}

/// A newer peer's message arrives as a single unknown length-delimited field (field 99, wire type 2)
/// with no known `Message.body` oneof arm set — byte-identical IN KIND to a HELLO-1 node receiving a
/// field-25 body it does not yet know. A clean, bounded parse yields an absent body, which
/// classifies as the forward-compatible [`CodecError::UnknownMessage`] (dropped by transports), NOT
/// `Malformed` (which would terminate a stream connection).
#[test]
fn an_unknown_body_envelope_classifies_as_unknown_message() {
  // Field 99, wire type 2: tag = (99 << 3) | 2 = 794, varint [0x9A, 0x06]; length 2; payload 2 bytes.
  let frame = Bytes::from_static(&[0x9A, 0x06, 0x02, 0xAA, 0xBB]);
  match decode_message(frame) {
    Err(CodecError::UnknownMessage) => {}
    other => panic!("expected CodecError::UnknownMessage, got {other:?}"),
  }
}

/// A frame whose leading tag names an invalid protobuf wire type (7) violates the wire grammar inside
/// buffa (stage 1) and must surface as [`CodecError::Malformed`] — NOT the forward-compat
/// `UnknownMessage`, which is reserved for a CLEANLY-parsed envelope that merely lacks a known body.
/// Guards the terminate-vs-drop boundary from the corruption side.
#[test]
fn a_corrupt_wire_type_maps_to_malformed_not_unknown_message() {
  // Field 1, wire type 7 (invalid): tag = (1 << 3) | 7 = 15 = 0x0F.
  let frame = Bytes::from_static(&[0x0F]);
  match decode_message(frame) {
    Err(CodecError::Malformed { .. }) => {}
    other => panic!("expected CodecError::Malformed, got {other:?}"),
  }
}

/// A valid tiny envelope followed by `count` copies of an unknown field: field number 1000 (well
/// outside the 24 known `Message.body` arms), wire type 0 (varint). Tag = `(1000 << 3) | 0` =
/// 8000, varint-encoded as `[0xC0, 0x3E]`; value = varint(1) = `[0x01]`.
fn frame_with_unknown_fields(count: usize) -> Bytes {
  let valid = encode_message(&Message::EpochAhead(EpochAhead::new(
    Epoch::new(1),
    OpNumber::with(1),
  )));
  let mut buf = valid.to_vec();
  for _ in 0..count {
    buf.extend_from_slice(&[0xC0, 0x3E, 0x01]);
  }
  Bytes::from(buf)
}

/// A frame packed with more unknown fields than [`MAX_UNKNOWN_FIELDS`] must be rejected rather
/// than materialize an unbounded number of `UnknownField` entries — but exactly at the allowance
/// it still decodes, so this pins the boundary at the configured limit, not some unrelated
/// failure (a frame this small would never legitimately trip any OTHER rejection).
#[test]
fn unknown_field_flood_is_bounded() {
  assert!(
    decode_message(frame_with_unknown_fields(MAX_UNKNOWN_FIELDS)).is_ok(),
    "exactly MAX_UNKNOWN_FIELDS unknown fields must still decode"
  );
  assert!(
    decode_message(frame_with_unknown_fields(MAX_UNKNOWN_FIELDS + 1)).is_err(),
    "one more than MAX_UNKNOWN_FIELDS must be rejected"
  );
}

/// `count` copies of a minimal unknown varint field (field 1000, wire type 0) with NO valid body —
/// the degenerate flood used to prove the anti-flood bound precedes the absent-body classification.
fn frame_of_only_unknown_fields(count: usize) -> Bytes {
  let mut buf = std::vec::Vec::new();
  for _ in 0..count {
    buf.extend_from_slice(&[0xC0, 0x3E, 0x01]);
  }
  Bytes::from(buf)
}

/// THE FLOOD / FORWARD-COMPAT BOUNDARY FALSIFIER: the anti-flood bound fires strictly BEFORE the
/// absent-body classification, so an unknown-field flood can never launder itself into the
/// conn-surviving `UnknownMessage` disposition. At the allowance, a body-less envelope decodes
/// cleanly and — its body absent — classifies as the forward-compatible
/// [`CodecError::UnknownMessage`] (dropped, conn survives). One field past it, buffa rejects the
/// frame inside its own bounded decode as [`CodecError::Malformed`] — terminal on a stream conn —
/// before the absent body is ever reached. Were this to regress to a dropped `UnknownMessage` one
/// past the allowance, a flood would be silently absorbed instead of terminating the connection: the
/// anti-flood guarantee, gone.
#[test]
fn the_flood_bound_precedes_the_absent_body_classification() {
  match decode_message(frame_of_only_unknown_fields(MAX_UNKNOWN_FIELDS)) {
    Err(CodecError::UnknownMessage) => {}
    other => panic!("expected UnknownMessage at the allowance, got {other:?}"),
  }
  match decode_message(frame_of_only_unknown_fields(MAX_UNKNOWN_FIELDS + 1)) {
    Err(CodecError::Malformed { .. }) => {}
    other => panic!("expected Malformed one past the allowance, got {other:?}"),
  }
}

/// Dropping the last byte of a valid frame must surface as [`CodecError::Truncated`], not any
/// other variant and not a panic.
#[test]
fn truncated_envelope_maps_to_truncated() {
  let m = Message::EpochAhead(EpochAhead::new(Epoch::new(9), OpNumber::with(3)));
  let full = encode_message(&m);
  let short = full.slice(..full.len() - 1);
  match decode_message(short) {
    Err(CodecError::Truncated { .. }) => {}
    other => panic!("expected CodecError::Truncated, got {other:?}"),
  }
}

/// A wire-conversion rejection (here: a 15-byte `config_id`, one byte short of the canonical 16)
/// surfaces as [`CodecError::Malformed`] naming the offending field.
#[test]
fn malformed_fields_map_to_malformed() {
  let bad = pb::Prepare {
    config_id: Bytes::from_static(&[0u8; 15]),
    ..Default::default()
  };
  let frame = pb::Message {
    body: Some(pb::message::Body::from(bad)),
    ..Default::default()
  }
  .encode_to_bytes();
  match decode_message(frame) {
    Err(CodecError::Malformed { what }) => assert_eq!(what, "Prepare.config_id"),
    other => panic!("expected CodecError::Malformed(\"Prepare.config_id\"), got {other:?}"),
  }
}

/// Renders `bytes` as a lowercase hex string for the golden vectors below (no `hex` dependency in
/// this crate).
fn hex(bytes: &[u8]) -> std::string::String {
  let mut s = std::string::String::with_capacity(bytes.len() * 2);
  for b in bytes {
    let _ = write!(s, "{b:02x}");
  }
  s
}

/// The inverse of [`hex`]: parses a lowercase hex string back into bytes, for the golden vectors'
/// decode-direction check below.
fn unhex(s: &str) -> std::vec::Vec<u8> {
  (0..s.len())
    .step_by(2)
    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("golden vector is valid hex"))
    .collect()
}

/// Golden byte vectors: `encode_message` output for one exemplar of every [`Message`] variant
/// (see [`one_of_each_message`]), pinned byte-for-byte in declaration order, and the inverse —
/// `decode_message` on each pinned vector must reproduce the same exemplar. A later DELIBERATE
/// wire-format change updates these vectors consciously; an accidental one fails here first.
#[test]
fn golden_byte_vectors() {
  let golden: [&str; 26] = [
    "0a1a0a100000000000000000000000000000004010501a04626f6479", // Request
    "1236080a100b180c200d280e3210000000000000000000000000000000503a100000000000000000000000000000004040504a04626f6479", // Prepare
    "1a2e080a100b181e200d2a1000000000000000000000000000000060300e3a1000000000000000000000000000000050", // PrepareOk
    "221c080a12100000000000000000000000000000004018502204626f6479", // Reply
    "2a1a080a100c180d200e2a1000000000000000000000000000000050",     // Commit
    "3218080a101e180e221000000000000000000000000000000050",         // StartViewChange
    "3ab701080a100f180b200c280d300e3a1000000000000000000000000000000050401e4a19080112100000000000000000000000000000000118012201614a28080212100000000000000000000000000000000218022a10112233445566778899aabbccddeeff004a5008031210ffffffffffffffffffffffffffffffff1803323808021a10000000000000000000000000000000011a1000000000000000000000000000000002221000000000000000000000000000000000", // DoViewChange
    "42b501080a100b180c200d280e321000000000000000000000000000000050381e4219080112100000000000000000000000000000000118012201614228080212100000000000000000000000000000000218022a10112233445566778899aabbccddeeff00425008031210ffffffffffffffffffffffffffffffff1803323808021a10000000000000000000000000000000011a1000000000000000000000000000000002221000000000000000000000000000000000", // StartView
    "4a1a080a101e1810200e2a1000000000000000000000000000000050", // GetView
    "5218080a100b181e221000000000000000000000000000000050",     // RequestPrepare
    "5a18081e1010180e221000000000000000000000000000000050",     // Recovery
    "62b701080a100b180c200d280e321000000000000000000000000000000050381e40104a19080112100000000000000000000000000000000118012201614a28080212100000000000000000000000000000000218022a10112233445566778899aabbccddeeff004a5008031210ffffffffffffffffffffffffffffffff1803323808021a10000000000000000000000000000000011a1000000000000000000000000000000002221000000000000000000000000000000000", // RecoveryResponse
    "6a1c080a100d181e20102801321000000000000000000000000000000050", // RequestSync
    "7246080a100d1a1000000000000000000000000000000070200e2a1000000000000000000000000000000050301e38104208736e617073686f744a0a6d656d62657273686970500c", // SyncCheckpoint
    "7a1a080a10111812201e2a1000000000000000000000000000000050", // RequestPrepareRange
    "8201af01080a100c180d2210000000000000000000000000000000502a19080112100000000000000000000000000000000118012201612a28080212100000000000000000000000000000000218022a10112233445566778899aabbccddeeff002a5008031210ffffffffffffffffffffffffffffffff1803323808021a10000000000000000000000000000000011a1000000000000000000000000000000002221000000000000000000000000000000000", // RepairBatch
    "8a01b101080a100c180d200e2a10000000000000000000000000000000503219080112100000000000000000000000000000000118012201613228080212100000000000000000000000000000000218022a10112233445566778899aabbccddeeff00325008031210ffffffffffffffffffffffffffffffff1803323808021a10000000000000000000000000000000011a1000000000000000000000000000000002221000000000000000000000000000000000", // PrepareBatch
    "92011a081e10131814200e2a1000000000000000000000000000000050", // LearnerStatus
    "9a0104080e100d",                                             // EpochAhead
    "a2011a081f10151810200e2a1000000000000000000000000000000050", // RequestLearnerProof
    "aa011a081e10101816200e2a1000000000000000000000000000000050", // LearnerProof
    "ca0118081f1011180e221000000000000000000000000000000050",     // RequestHealthProof
    "d20118081e1011180e221000000000000000000000000000000050",     // HealthProof
    "b201120a1000000000000000000000000000000090",                 // RequestBlock
    "ba01190a10000000000000000000000000000000901205626c6f636b",   // BlockResponse
    "c20118080a100b181e221000000000000000000000000000000050",     // Nack
  ];
  let msgs = one_of_each_message();
  assert_eq!(
    msgs.len(),
    golden.len(),
    "one_of_each_message count drifted from the golden table"
  );
  for (m, expected) in msgs.iter().zip(golden) {
    assert_eq!(
      hex(&encode_message(m)),
      expected,
      "{} golden encoding mismatch",
      m.kind_str()
    );
    let decoded = decode_message(Bytes::from(unhex(expected))).unwrap_or_else(|e| {
      panic!(
        "{}: decode_message on its own golden vector erred: {e:?}",
        m.kind_str()
      )
    });
    assert_eq!(
      &decoded,
      m,
      "{} golden vector did not decode back to the exemplar",
      m.kind_str()
    );
  }
}

/// One `Reply.outcome` arm as raw wire bytes: the `body` arm (field 4) carrying `payload`, or the
/// `too_large` arm (field 5) carrying an encoded `ReplyTooLarge{len, max}`.
fn outcome_arm_bytes(field: u8, payload: &[u8]) -> std::vec::Vec<u8> {
  let mut out = std::vec![(field << 3) | 2, payload.len() as u8];
  out.extend_from_slice(payload);
  out
}

/// Builds a raw `Message` envelope carrying a `Reply` whose `outcome` arms are exactly `arms`, in
/// the given order. A compliant encoder emits exactly one; more than one is the shape the decoder
/// must refuse, whatever the order or repetition.
fn reply_envelope_with_arms(arms: &[std::vec::Vec<u8>]) -> Bytes {
  let mut reply = std::vec![0x08, 0x01]; // view = 1
  reply.push(0x12); // client, length-delimited
  reply.push(16);
  reply.extend_from_slice(&[0u8; 16]);
  reply.extend_from_slice(&[0x18, 0x01]); // request = 1
  for arm in arms {
    reply.extend_from_slice(arm);
  }
  // `Message.body`'s `reply` arm is field 4, length-delimited.
  let mut envelope = std::vec![0x22];
  envelope.push(reply.len() as u8);
  envelope.extend_from_slice(&reply);
  Bytes::from(envelope)
}

/// The `body` arm carrying a short payload.
fn body_arm() -> std::vec::Vec<u8> {
  outcome_arm_bytes(4, b"ok")
}

/// The `too_large` arm carrying `ReplyTooLarge { len: 9, max: 8 }`.
fn too_large_arm() -> std::vec::Vec<u8> {
  outcome_arm_bytes(5, &[0x08, 0x09, 0x10, 0x08])
}

#[test]
fn a_single_outcome_arm_decodes_in_either_form() {
  // The control for the rejection tests below: each arm ALONE is a well-formed reply, so a
  // rejection there is about the repetition and nothing else.
  let with_body = decode_message(reply_envelope_with_arms(&[body_arm()])).expect("one body arm");
  assert_eq!(
    with_body
      .try_unwrap_reply_ref()
      .expect("a Reply")
      .outcome()
      .as_ok()
      .map(ReplyBody::as_bytes),
    Some(&b"ok"[..])
  );
  let with_refusal =
    decode_message(reply_envelope_with_arms(&[too_large_arm()])).expect("one too_large arm");
  assert_eq!(
    with_refusal
      .try_unwrap_reply_ref()
      .expect("a Reply")
      .outcome()
      .as_too_large(),
    Some(&ReplyTooLarge::new(9, 8))
  );
}

#[test]
fn a_reply_carrying_two_outcome_arms_is_rejected_in_either_order() {
  // Protobuf's merge rule makes the LAST arm win, so accepting this would let the sender decide —
  // by field order alone — whether the client sees a committed op's body or its terminal refusal.
  for (order, arms) in [
    (
      "body then too_large",
      std::vec![body_arm(), too_large_arm()],
    ),
    (
      "too_large then body",
      std::vec![too_large_arm(), body_arm()],
    ),
  ] {
    assert!(
      matches!(
        decode_message(reply_envelope_with_arms(&arms)),
        Err(CodecError::Malformed {
          what: "Reply.outcome (repeated)"
        })
      ),
      "a Reply carrying both outcome arms ({order}) must be refused, not resolved by order"
    );
  }
}

#[test]
fn a_reply_repeating_one_outcome_arm_is_rejected() {
  // The same rule for a repeated SAME arm: one occurrence, or the frame is not the canonical shape
  // this build acts on. (A repeated `body` is last-wins; a repeated `too_large` MERGES its fields,
  // so a second occurrence could rewrite either length.)
  for (kind, arms) in [
    ("body", std::vec![body_arm(), body_arm()]),
    ("too_large", std::vec![too_large_arm(), too_large_arm()]),
  ] {
    assert!(
      matches!(
        decode_message(reply_envelope_with_arms(&arms)),
        Err(CodecError::Malformed {
          what: "Reply.outcome (repeated)"
        })
      ),
      "a Reply repeating its {kind} arm must be refused"
    );
  }
}

#[test]
fn two_reply_arms_that_merge_into_one_reply_are_counted_together() {
  // Two `Message.body` reply arms MERGE into a single decoded `Reply`, so a sender could split the
  // two outcome arms across them and reach the same fork. The scan counts occurrences across every
  // reply arm the envelope holds, so the split is refused exactly like the adjacent pair.
  let first = reply_envelope_with_arms(&[body_arm()]);
  let second = reply_envelope_with_arms(&[too_large_arm()]);
  let mut split = std::vec::Vec::new();
  split.extend_from_slice(&first);
  split.extend_from_slice(&second);
  assert!(
    matches!(
      decode_message(Bytes::from(split)),
      Err(CodecError::Malformed {
        what: "Reply.outcome (repeated)"
      })
    ),
    "outcome arms split across two merging reply arms must be refused too"
  );
}

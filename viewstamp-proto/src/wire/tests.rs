use bytes::Bytes;

use super::{convert, pb};
use crate::{ClientId, MemberId, OpNumber, PreparedEntry, ReconfigurePayload, RequestNumber};
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
fn log_round_trips_a_mixed_batch() {
  let log = std::vec![
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
  ];
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

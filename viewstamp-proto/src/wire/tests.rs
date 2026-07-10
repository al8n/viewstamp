use super::pb;
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

use super::*;
use crate::{
  ClientId, Instant, Message, Peer, ReplicaId, RequestNumber, encode_message,
  message::Request,
  transport::{frame::encode_frame, stream::RecordIo},
};

fn req_msg() -> Message {
  Message::Request(Request::new(
    ClientId::new(1),
    RequestNumber::with(1),
    bytes::Bytes::from_static(b"x"),
  ))
}

/// A record layer that buffers input as plaintext and surfaces at most `chunk` bytes per
/// `read_plaintext`, returning `Pending` while more than `chunk` remains buffered (to drive
/// the Conn Intake loop), else `Done`. `chunk = usize::MAX` => always `Done`, drains fully.
struct FakeRecords {
  buf: Vec<u8>,
  outbound: usize,
  chunk: usize,
  handshaking: bool,
  from: Peer,
}
impl FakeRecords {
  fn new(chunk: usize, from: Peer) -> Self {
    Self {
      buf: Vec::new(),
      outbound: 0,
      chunk,
      handshaking: false,
      from,
    }
  }
  /// Overrides the handshaking flag `RecordIo::is_handshaking` reports (default false), so a test can
  /// drive Conn's stalled-handshake-is-fatal branch.
  fn handshaking(mut self, v: bool) -> Self {
    self.handshaking = v;
    self
  }
}
impl RecordIo for FakeRecords {
  fn handle_transport_data(&mut self, input: &[u8], _: Instant) -> Intake {
    self.buf.extend_from_slice(input);
    if self.buf.len() > self.chunk {
      Intake::Pending(input.len())
    } else {
      Intake::Done
    }
  }
  fn poll_transport_transmit(&mut self, _: &mut Vec<u8>) -> usize {
    let n = self.outbound;
    self.outbound = 0;
    n
  }
  fn read_plaintext(&mut self, out: &mut Vec<u8>) -> usize {
    let n = self.buf.len().min(self.chunk);
    out.extend_from_slice(&self.buf[..n]);
    self.buf.drain(..n);
    n
  }
  fn write_plaintext(&mut self, plaintext: &[u8]) -> usize {
    self.outbound += plaintext.len();
    plaintext.len()
  }
  fn buffered_outbound(&self) -> usize {
    self.outbound
  }
  fn is_handshaking(&self) -> bool {
    self.handshaking
  }
  fn peer_identity(&self) -> Option<Peer> {
    Some(self.from)
  }
  fn peer_has_closed(&self) -> bool {
    false
  }
  fn send_close_notify(&mut self) {}
  fn clear_outbound(&mut self) {}
  fn is_secure() -> bool {
    false
  }
}

#[test]
fn decodes_two_messages_from_one_read() {
  let from = Peer::Replica(ReplicaId::new(2));
  let mut frames = Vec::new();
  encode_frame(&encode_message(&req_msg()), &mut frames);
  encode_frame(&encode_message(&req_msg()), &mut frames);
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.mark_validated(from);
  let closed = conn.handle_data(&frames, false, Instant::ZERO).unwrap();
  assert!(!closed);
  let mut out = Vec::new();
  conn.poll_decoded(&mut out).unwrap();
  assert_eq!(out.len(), 2);
  assert_eq!(out[0].0, from);
}

#[test]
fn intake_pending_loop_reassembles_a_large_frame() {
  let from = Peer::Replica(ReplicaId::new(0));
  let mut frame = Vec::new();
  encode_frame(&encode_message(&req_msg()), &mut frame);
  // chunk smaller than the frame forces multiple Pending iterations.
  let mut conn = Conn::from_parts(FakeRecords::new(4, from));
  conn.mark_validated(from);
  let closed = conn.handle_data(&frame, false, Instant::ZERO).unwrap();
  assert!(!closed);
  let mut out = Vec::new();
  conn.poll_decoded(&mut out).unwrap();
  assert_eq!(
    out.len(),
    1,
    "the frame reassembles across Pending iterations"
  );
}

#[test]
fn mid_frame_eof_is_truncation() {
  let from = Peer::Replica(ReplicaId::new(0));
  let mut frame = Vec::new();
  encode_frame(&encode_message(&req_msg()), &mut frame);
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.mark_validated(from);
  // EOF mid-frame: the peer finished but the conn is not yet closed; finalize reports truncation.
  let fin = conn.handle_data(&frame[..3], true, Instant::ZERO).unwrap();
  assert!(fin);
  assert!(!conn.is_closed());
  let err = conn.finalize().unwrap_err();
  assert!(matches!(err, TransportError::TruncatedFrame { .. }));
  assert!(conn.is_closed());
}

#[test]
fn a_complete_final_frame_is_delivered_then_closed() {
  let from = Peer::Replica(ReplicaId::new(0));
  let mut frame = Vec::new();
  encode_frame(&encode_message(&req_msg()), &mut frame);
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.mark_validated(from);
  // A complete frame arrives in the SAME read that signals EOF.
  let fin = conn.handle_data(&frame, true, Instant::ZERO).unwrap();
  assert!(fin);
  assert!(
    !conn.is_closed(),
    "close is deferred until frames are drained"
  );
  let mut out = Vec::new();
  conn.poll_decoded(&mut out).unwrap();
  assert_eq!(out.len(), 1, "the final frame is delivered, not dropped");
  assert_eq!(out[0].0, from);
  conn.finalize().unwrap();
  assert!(conn.is_closed());
}

#[test]
fn an_oversized_frame_closes_the_conn() {
  let from = Peer::Replica(ReplicaId::new(0));
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.mark_validated(from);
  let mut bad = Vec::new();
  bad.extend_from_slice(&u32::MAX.to_be_bytes()); // a frame header claiming a huge length
  // The over-cap declared length is rejected at intake, before any body can accumulate.
  let err = conn.handle_data(&bad, false, Instant::ZERO).unwrap_err();
  assert!(matches!(err, TransportError::FrameTooLong { .. }));
  assert!(
    conn.is_closed(),
    "an oversized frame must close the conn so it gets reaped"
  );
}

#[test]
fn an_oversized_frame_in_a_large_read_is_rejected() {
  let from = Peer::Replica(ReplicaId::new(0));
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.mark_validated(from);
  let mut huge = Vec::new();
  huge.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes()); // over-cap declared length
  huge.extend_from_slice(&std::vec![0u8; 200 * 1024]); // a large trailing body
  let err = conn.handle_data(&huge, false, Instant::ZERO).unwrap_err();
  assert!(matches!(err, TransportError::FrameTooLong { .. }));
  assert!(
    conn.is_closed(),
    "the oversized frame is rejected and the conn closed"
  );
}

#[test]
fn a_zero_length_frame_is_dropped_as_an_empty_envelope() {
  let from = Peer::Replica(ReplicaId::new(0));
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.mark_validated(from);
  let mut zeros = Vec::new();
  zeros.extend_from_slice(&0u32.to_be_bytes()); // a single zero-length frame
  conn.handle_data(&zeros, false, Instant::ZERO).unwrap();
  let mut out = Vec::new();
  // A zero-length frame decodes to an EMPTY envelope with no body — the degenerate forward-compat
  // UnknownMessage case — so it is DROPPED and the conn stays Validated, not terminated. (A newer
  // peer's unrecognized message and this degenerate empty frame share one disposition: skip it.)
  conn
    .poll_decoded(&mut out)
    .expect("an empty envelope is skipped, not fatal");
  assert!(out.is_empty(), "an empty envelope yields no message");
  assert!(
    !conn.is_closed(),
    "the conn survives an empty (forward-compat) frame"
  );
  assert!(conn.is_validated());
}

#[test]
fn an_unknown_body_frame_is_skipped_and_a_following_message_still_delivers() {
  let from = Peer::Replica(ReplicaId::new(2));
  let mut frames = Vec::new();
  // A forward-compat unknown-body envelope (field 99, wire type 2 — a Message.body variant this build
  // does not know, IN KIND identical to a peer receiving a newer oneof arm) decodes cleanly to an
  // absent body -> CodecError::UnknownMessage. The conn must SKIP it (as QUIC drops an unknown
  // datagram), not terminate...
  encode_frame(
    &bytes::Bytes::from_static(&[0x9A, 0x06, 0x02, 0xAA, 0xBB]),
    &mut frames,
  );
  // ...and still deliver the recognized consensus message that follows it in the SAME buffer.
  encode_frame(&encode_message(&req_msg()), &mut frames);
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.mark_validated(from);
  let closed = conn.handle_data(&frames, false, Instant::ZERO).unwrap();
  assert!(!closed);
  let mut out = Vec::new();
  conn
    .poll_decoded(&mut out)
    .expect("an unknown-body frame is skipped, not fatal");
  assert_eq!(out.len(), 1, "only the recognized message is delivered");
  assert_eq!(out[0].0, from);
  assert!(
    conn.is_validated(),
    "the conn stays Validated after skipping an unknown frame"
  );
  assert!(!conn.is_closed());
}

#[test]
fn a_malformed_frame_closes_the_conn() {
  let from = Peer::Replica(ReplicaId::new(0));
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.mark_validated(from);
  // A framed but genuinely CORRUPT payload (field 1 tag naming wire type 7, an invalid protobuf wire
  // type) is a fault, not a newer peer — decode_message rejects it as Malformed, so poll_decoded
  // terminates the conn. This is the corruption side of the drop-vs-terminate split, the guarantee
  // the (now forward-compat) zero-length-frame test above no longer carries.
  let mut framed = Vec::new();
  encode_frame(&bytes::Bytes::from_static(&[0x0F]), &mut framed);
  conn.handle_data(&framed, false, Instant::ZERO).unwrap();
  let mut out = Vec::new();
  assert!(
    conn.poll_decoded(&mut out).is_err(),
    "a corrupt frame must fail to decode and terminate the conn"
  );
  assert!(
    out.is_empty(),
    "no message is delivered from a corrupt frame"
  );
  assert!(conn.is_closed());
}

#[test]
fn many_frames_in_one_read_all_decode() {
  let from = Peer::Replica(ReplicaId::new(1));
  // A single read carrying many small frames buffers them all; poll_decoded yields every one.
  let mut frames = Vec::new();
  let count = 2000;
  for _ in 0..count {
    encode_frame(&encode_message(&req_msg()), &mut frames);
  }
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.mark_validated(from);
  conn.handle_data(&frames, false, Instant::ZERO).unwrap();
  let mut out = Vec::new();
  conn.poll_decoded(&mut out).unwrap();
  assert_eq!(out.len(), count, "every frame in the read is decoded");
}

#[test]
fn handshake_gate_blocks_decode() {
  // A conn that was never validated buffers plaintext but decodes nothing.
  let from = Peer::Replica(ReplicaId::new(0));
  let mut frames = Vec::new();
  encode_frame(&encode_message(&req_msg()), &mut frames);
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.handle_data(&frames, false, Instant::ZERO).unwrap();
  let mut out = Vec::new();
  conn.poll_decoded(&mut out).unwrap();
  assert!(out.is_empty(), "no Message decoded while still Handshaking");
}

#[test]
fn a_short_write_closes_the_conn() {
  use crate::transport::testutil::MockRecords;
  let from = Peer::Replica(ReplicaId::new(0));
  let mut frame = Vec::new();
  encode_frame(&encode_message(&req_msg()), &mut frame);
  // Cap the record layer below the frame so write_framed short-writes (the out-of-contract path
  // the router's projective cap normally prevents).
  let records = MockRecords::new(false, Some(from)).with_write_cap(frame.len() - 1);
  let mut conn = Conn::from_parts(records);
  conn.mark_validated(from);
  conn.write_framed(&frame);
  assert!(
    conn.is_closed(),
    "a short write is terminal: the conn closes so no partial frame is transmitted"
  );
  let mut out = Vec::new();
  assert_eq!(
    conn.poll_transmit(&mut out),
    0,
    "a closed conn transmits nothing — the partial bytes never reach the wire"
  );
}

#[test]
fn queued_outbound_counts_a_labeled_handshake_hello() {
  use crate::{LabelOptions, Labeled, Passthrough};
  const CLUSTER: u128 = 0xABCD;
  let a_id = Peer::Replica(ReplicaId::new(0));
  let d_id = Peer::Replica(ReplicaId::new(7));

  // A standalone dialer with the acceptor's identity tells us how many bytes the acceptor's own
  // hello occupies once queued into its inner layer (the eager dialer flush is the same encoding).
  let acceptor_hello_len = {
    let probe: Labeled<Passthrough> =
      Labeled::dialer(Passthrough::new(), &LabelOptions::new(CLUSTER, a_id));
    probe.buffered_outbound()
  };
  assert!(acceptor_hello_len > 0, "a hello is non-empty");

  // The remote dialer's hello bytes, to drive the acceptor through validation.
  let dialer_wire = {
    let mut dialer: Labeled<Passthrough> =
      Labeled::dialer(Passthrough::new(), &LabelOptions::new(CLUSTER, d_id));
    let mut wire = Vec::new();
    dialer.poll_transport_transmit(&mut wire);
    wire
  };

  let acceptor: Labeled<Passthrough> =
    Labeled::acceptor(Passthrough::new(), &LabelOptions::new(CLUSTER, a_id));
  let mut conn = Conn::from_parts(acceptor);
  assert_eq!(
    conn.queued_outbound(),
    0,
    "an acceptor has not queued its hello before it validates the remote"
  );
  // Feeding the dialer hello makes the acceptor validate the peer and queue its own hello into the
  // inner layer — which queued_outbound() now observes via the record layer's real buffer.
  conn
    .handle_data(&dialer_wire, false, Instant::ZERO)
    .unwrap();
  assert!(
    conn.queued_outbound() >= acceptor_hello_len,
    "queued_outbound reflects the acceptor's queued handshake hello, not a separate counter"
  );
}

#[test]
fn a_bound_raw_conn_decodes_inbound_with_the_bound_peer() {
  let mut conn = Conn::from_parts(crate::Passthrough::new());
  let who = Peer::Replica(ReplicaId::new(3));
  conn.mark_validated(who); // the router validates + binds the trusted identity
  let mut frames = Vec::new();
  encode_frame(&encode_message(&req_msg()), &mut frames);
  conn.handle_data(&frames, false, Instant::ZERO).unwrap();
  let mut out = Vec::new();
  conn.poll_decoded(&mut out).unwrap();
  assert_eq!(out.len(), 1, "a bound raw conn decodes inbound frames");
  assert_eq!(out[0].0, who, "inbound is tagged with the bound peer");
}

#[test]
fn handle_data_on_an_already_closed_conn_is_a_no_op() {
  let from = Peer::Replica(ReplicaId::new(0));
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.mark_closed_for_test();
  let fin = conn.handle_data(b"anything", false, Instant::ZERO).unwrap();
  assert!(
    fin,
    "an already-closed conn reports itself as finished without touching the record layer"
  );
}

#[test]
fn a_record_layer_failure_closes_the_conn_with_record_rejected() {
  use crate::transport::testutil::MockRecords;
  let from = Peer::Replica(ReplicaId::new(0));
  let mut conn = Conn::from_parts(MockRecords::new(false, Some(from)).failing());
  conn.mark_validated(from);
  let err = conn.handle_data(b"x", false, Instant::ZERO).unwrap_err();
  assert!(matches!(err, TransportError::RecordRejected));
  assert!(conn.is_closed(), "a record-layer failure closes the conn");
}

#[test]
fn an_oversized_frame_discovered_mid_pending_intake_closes_the_conn() {
  let from = Peer::Replica(ReplicaId::new(0));
  // chunk=2 forces the record layer to surface plaintext only 2 bytes at a time, so the 4-byte
  // over-cap length prefix only becomes fully visible to the decoder on the SECOND drain, while the
  // record layer is still reporting Pending (more than `chunk` remains buffered after the first read)
  // — driving the decode-error arm reached from the Pending branch, not the Done branch.
  let mut conn = Conn::from_parts(FakeRecords::new(2, from));
  conn.mark_validated(from);
  let mut bad = Vec::new();
  bad.extend_from_slice(&u32::MAX.to_be_bytes());
  bad.extend_from_slice(&[0xAA; 4]); // trailing bytes so the record layer keeps reporting Pending
  let err = conn.handle_data(&bad, false, Instant::ZERO).unwrap_err();
  assert!(matches!(err, TransportError::FrameTooLong { .. }));
  assert!(
    conn.is_closed(),
    "the over-cap length discovered while still Pending closes the conn"
  );
}

#[test]
fn a_handshaking_stall_with_no_progress_is_a_fatal_record_reject() {
  let from = Peer::Replica(ReplicaId::new(0));
  // chunk=0 makes read_plaintext always drain 0 bytes: the second intake iteration (n==0, nothing
  // drained) hits the stalled-handshake guard.
  let mut conn = Conn::from_parts(FakeRecords::new(0, from).handshaking(true));
  let err = conn.handle_data(&[0x01], false, Instant::ZERO).unwrap_err();
  assert!(matches!(err, TransportError::RecordRejected));
  assert!(
    conn.is_closed(),
    "a handshake that stalls with no progress is a fatal reject, not a silent hang"
  );
}

#[test]
fn a_post_handshake_stall_with_no_progress_breaks_without_closing() {
  let from = Peer::Replica(ReplicaId::new(0));
  let mut conn = Conn::from_parts(FakeRecords::new(0, from)); // handshaking=false (default)
  let fin = conn.handle_data(&[0x01], false, Instant::ZERO).unwrap();
  assert!(!fin, "no EOF / peer-close signal was raised");
  assert!(
    !conn.is_closed(),
    "a post-handshake stall with no progress just stops this round; it is not terminal"
  );
}

#[test]
fn finalize_is_idempotent_once_already_closed() {
  let from = Peer::Replica(ReplicaId::new(0));
  let mut frame = Vec::new();
  encode_frame(&encode_message(&req_msg()), &mut frame);
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
  conn.mark_validated(from);
  conn.handle_data(&frame, true, Instant::ZERO).unwrap();
  let mut out = Vec::new();
  conn.poll_decoded(&mut out).unwrap();
  conn.finalize().unwrap();
  assert!(conn.is_closed());
  // A second finalize on an already-closed conn is an idempotent success, not an error.
  assert!(
    conn.finalize().is_ok(),
    "finalize is idempotent once the conn is already closed"
  );
}

#[test]
fn write_framed_is_rejected_before_the_conn_is_validated() {
  let from = Peer::Replica(ReplicaId::new(0));
  let mut frame = Vec::new();
  encode_frame(&encode_message(&req_msg()), &mut frame);
  let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from)); // never mark_validated
  assert!(
    !conn.write_framed(&frame),
    "write_framed on a not-yet-validated conn reports no close"
  );
  assert_eq!(
    conn.queued_outbound(),
    0,
    "a not-yet-validated conn never queues an application frame"
  );
}

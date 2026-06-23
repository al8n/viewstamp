use super::*;
use crate::Instant;

#[test]
fn passthrough_is_a_transparent_pipe() {
  let mut p = Passthrough::new();
  assert!(!p.is_handshaking());
  assert!(!Passthrough::is_secure());
  assert_eq!(
    p.handle_transport_data(b"hello", Instant::ZERO),
    Intake::Done
  );
  let mut got = Vec::new();
  assert_eq!(p.read_plaintext(&mut got), 5);
  assert_eq!(&got, b"hello");
  assert_eq!(p.read_plaintext(&mut Vec::new()), 0);
  p.write_plaintext(b"world");
  let mut out = Vec::new();
  assert_eq!(p.poll_transport_transmit(&mut out), 5);
  assert_eq!(&out, b"world");
  assert!(!p.peer_has_closed());
}

#[test]
fn clear_outbound_discards_queued_bytes() {
  let mut p = Passthrough::new();
  p.write_plaintext(b"abc");
  p.clear_outbound();
  assert_eq!(p.poll_transport_transmit(&mut Vec::new()), 0);
}

#[test]
fn a_huge_direct_intake_applies_backpressure_and_is_bounded() {
  let mut p = Passthrough::new();
  let huge = std::vec![0u8; RECV_LIMIT + 4096];
  // A single oversized read cannot be fully staged: it returns Pending (backpressure) having
  // accepted at most RECV_LIMIT.
  let intake = p.handle_transport_data(&huge, Instant::ZERO);
  match intake {
    Intake::Pending(n) => assert!(n <= RECV_LIMIT, "accepts at most the recv limit"),
    other => panic!("expected Pending backpressure, got {other:?}"),
  }
  let mut out = Vec::new();
  let drained = p.read_plaintext(&mut out);
  assert!(drained <= RECV_LIMIT, "buffered at most the recv limit");
}

#[test]
fn a_huge_direct_write_is_bounded() {
  let mut p = Passthrough::new();
  let huge = std::vec![0u8; SEND_LIMIT + 4096];
  let accepted = p.write_plaintext(&huge);
  assert!(accepted <= SEND_LIMIT, "accepts at most the send limit");
  assert!(
    accepted < huge.len(),
    "an oversized write is short: the count signals the cap"
  );
  let mut out = Vec::new();
  let n = p.poll_transport_transmit(&mut out);
  assert!(n <= SEND_LIMIT, "outbound is bounded by the send limit");
}

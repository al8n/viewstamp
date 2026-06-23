use super::*;
use crate::{ClientId, Instant, MemberId, Peer, ReplicaId};

const CLUSTER: u128 = 0xABCD;

fn opts(who: Peer) -> LabelOptions {
  LabelOptions::new(CLUSTER, who)
}

// Shuttle every queued outbound byte of `from` into `to`.
fn pump<R: StreamTransport>(from: &mut R, to: &mut R) {
  let mut wire = Vec::new();
  from.poll_transport_transmit(&mut wire);
  if !wire.is_empty() {
    assert_ne!(
      to.handle_transport_data(&wire, Instant::ZERO),
      Intake::Failed
    );
  }
}

#[test]
fn handshake_settles_identity_both_directions() {
  let d_id = Peer::Member(MemberId::new(1));
  let a_id = Peer::Member(MemberId::new(0));
  let mut dialer: Labeled<crate::Passthrough> =
    Labeled::dialer(crate::Passthrough::new(), &opts(d_id));
  let mut acceptor: Labeled<crate::Passthrough> =
    Labeled::acceptor(crate::Passthrough::new(), &opts(a_id));

  assert!(acceptor.is_handshaking());
  pump(&mut dialer, &mut acceptor);
  assert!(!acceptor.is_handshaking());
  assert_eq!(acceptor.peer_identity(), Some(d_id));
  pump(&mut acceptor, &mut dialer);
  assert!(!dialer.is_handshaking());
  assert_eq!(dialer.peer_identity(), Some(a_id));

  dialer.write_plaintext(b"msg");
  pump(&mut dialer, &mut acceptor);
  let mut got = Vec::new();
  acceptor.read_plaintext(&mut got);
  assert_eq!(&got, b"msg");
}

#[test]
fn pipelined_prefix_and_message_in_one_segment() {
  // Once settled, a side queues its hello prefix and then a message; the peer receives both in ONE
  // handle_transport_data. Driven on the acceptor: it queues its hello when it validates the dialer
  // and is then settled, so a following app write rides out in the same segment as the prefix.
  let a_id = Peer::Member(MemberId::new(0));
  let mut dialer: Labeled<crate::Passthrough> = Labeled::dialer(
    crate::Passthrough::new(),
    &opts(Peer::Member(MemberId::new(1))),
  );
  let mut acceptor: Labeled<crate::Passthrough> =
    Labeled::acceptor(crate::Passthrough::new(), &opts(a_id));
  pump(&mut dialer, &mut acceptor); // acceptor validates the dialer, queues its hello, settles
  assert!(!acceptor.is_handshaking());
  acceptor.write_plaintext(b"hello"); // accepted now, queued right after the acceptor's prefix
  let mut wire = Vec::new();
  acceptor.poll_transport_transmit(&mut wire); // [prefix][hello] in one buffer
  assert_eq!(
    dialer.handle_transport_data(&wire, Instant::ZERO),
    Intake::Done
  );
  assert_eq!(dialer.peer_identity(), Some(a_id));
  let mut got = Vec::new();
  dialer.read_plaintext(&mut got);
  assert_eq!(&got, b"hello");
}

#[test]
fn wrong_cluster_is_rejected() {
  let mut dialer: Labeled<crate::Passthrough> = Labeled::dialer(
    crate::Passthrough::new(),
    &LabelOptions::new(0x1111, Peer::Member(MemberId::new(1))),
  );
  let mut acceptor: Labeled<crate::Passthrough> = Labeled::acceptor(
    crate::Passthrough::new(),
    &LabelOptions::new(0x2222, Peer::Member(MemberId::new(0))),
  );
  let mut wire = Vec::new();
  dialer.poll_transport_transmit(&mut wire);
  assert_eq!(
    acceptor.handle_transport_data(&wire, Instant::ZERO),
    Intake::Failed
  );
}

#[test]
fn client_identity_round_trips() {
  let c = Peer::Client(ClientId::new(0xDEAD_BEEF));
  let mut dialer: Labeled<crate::Passthrough> =
    Labeled::dialer(crate::Passthrough::new(), &opts(c));
  let mut acceptor: Labeled<crate::Passthrough> = Labeled::acceptor(
    crate::Passthrough::new(),
    &opts(Peer::Member(MemberId::new(0))),
  );
  pump(&mut dialer, &mut acceptor);
  assert_eq!(acceptor.peer_identity(), Some(c));
}

#[test]
fn a_replica_id_above_a_byte_round_trips_through_the_hello() {
  // The replica id rides the hello as a 16-byte big-endian field (the full MemberId range), so an
  // index above a single byte encodes and classifies back to the same id. The classifier reports the
  // exact consumed length (HELLO_LEN for any hello), and a hello buffered one byte short is
  // Incomplete, not accepted on a truncated id.
  let r = Peer::Replica(ReplicaId::new(300));
  let mut hello = Vec::new();
  encode_hello(CLUSTER, HelloId::from_peer(r), &mut hello);
  assert_eq!(
    hello.len(),
    HELLO_LEN,
    "a replica hello carries a 16-byte id (HELLO_LEN total)"
  );
  match classify_hello(&hello, CLUSTER) {
    HelloOutcome::Accepted(HelloId::Replica(m), consumed) => {
      assert_eq!(m, u128::from(300u16), "the raw replica id round-trips");
      assert_eq!(consumed, HELLO_LEN);
    }
    _ => panic!("a complete replica hello must be accepted"),
  }
  // One byte short of the full id is Incomplete (never accepted on a half-read id).
  assert!(matches!(
    classify_hello(&hello[..hello.len() - 1], CLUSTER),
    HelloOutcome::Incomplete
  ));
  // And it round-trips end-to-end through the dialer/acceptor pump. The dialer announces a legacy
  // `Peer::Replica(300)` (widened to the 16-byte field); the acceptor now attests by stable id, so
  // it surfaces the same bit pattern as `Peer::Member(MemberId::new(300))`.
  let mut dialer: Labeled<crate::Passthrough> =
    Labeled::dialer(crate::Passthrough::new(), &opts(r));
  let mut acceptor: Labeled<crate::Passthrough> = Labeled::acceptor(
    crate::Passthrough::new(),
    &opts(Peer::Member(MemberId::new(0))),
  );
  pump(&mut dialer, &mut acceptor);
  assert_eq!(
    acceptor.peer_identity(),
    Some(Peer::Member(MemberId::new(300)))
  );
}

#[test]
fn forwards_is_secure_from_inner() {
  assert!(!Labeled::<crate::Passthrough>::is_secure());
}

#[test]
fn dialer_is_handshaking_until_it_learns_the_peer() {
  let d_id = Peer::Member(MemberId::new(1));
  let a_id = Peer::Member(MemberId::new(0));
  let mut dialer: Labeled<crate::Passthrough> =
    Labeled::dialer(crate::Passthrough::new(), &opts(d_id));
  let mut acceptor: Labeled<crate::Passthrough> =
    Labeled::acceptor(crate::Passthrough::new(), &opts(a_id));
  // The dialer has not yet learned the remote identity -> still handshaking (route must skip it).
  assert!(
    dialer.is_handshaking(),
    "a dialer is handshaking until it authenticates the remote"
  );
  pump(&mut dialer, &mut acceptor); // dialer prefix -> acceptor validates + queues its reply
  pump(&mut acceptor, &mut dialer); // acceptor reply -> dialer validates the remote identity
  assert!(
    !dialer.is_handshaking(),
    "after consuming the acceptor hello, the dialer is established"
  );
  assert_eq!(dialer.peer_identity(), Some(a_id));
}

#[test]
fn an_unflushed_local_hello_keeps_the_conn_handshaking() {
  use crate::transport::testutil::MockRecords;
  // An acceptor whose inner accepts no plaintext (write_cap 0), so the local hello prefix can
  // never flush. The inner is NOT handshaking and a valid remote hello validates the peer, yet
  // the conn must stay handshaking until our own identity has actually reached the wire.
  let a_id = Peer::Member(MemberId::new(0));
  let opts = LabelOptions::new(CLUSTER, a_id);
  let mut acceptor: Labeled<MockRecords> = Labeled::acceptor(MockRecords::new(false, None), &opts);
  // Reinstall the inner with a zero write cap (the default acceptor inner has no cap).
  acceptor.inner = MockRecords::new(false, None).with_write_cap(0);

  let d_id = Peer::Member(MemberId::new(1));
  let mut hello = Vec::new();
  encode_hello(CLUSTER, HelloId::from_peer(d_id), &mut hello);
  assert_ne!(
    acceptor.handle_transport_data(&hello, Instant::ZERO),
    Intake::Failed,
    "a valid remote hello is accepted, not rejected"
  );
  assert_eq!(
    acceptor.peer_identity(),
    Some(d_id),
    "the remote identity is validated (peer is set)"
  );
  assert!(
    !acceptor.inner.is_handshaking(),
    "the inner record layer is settled"
  );
  assert!(
    !acceptor.prefix_flushed,
    "the local hello prefix short-wrote, so it is not flushed"
  );
  assert!(
    acceptor.is_handshaking(),
    "an unflushed local hello keeps the conn handshaking despite a validated peer"
  );
}

#[test]
fn buffered_outbound_counts_the_queued_hello() {
  // A dialer queues its hello into the inner layer eagerly at construction, so the inner's
  // buffered-outbound count (which the router's cap reads) already reflects the hello — it is not
  // an off-the-books prefix that escapes the cap accounting.
  let d_id = Peer::Member(MemberId::new(1));
  let dialer: Labeled<crate::Passthrough> = Labeled::dialer(crate::Passthrough::new(), &opts(d_id));
  let mut hello = Vec::new();
  encode_hello(CLUSTER, HelloId::from_peer(d_id), &mut hello);
  assert!(
    dialer.buffered_outbound() >= hello.len(),
    "the queued hello is included in the record layer's buffered-outbound count"
  );
}

#[test]
fn a_huge_invalid_handshake_segment_is_rejected_bounded() {
  let mut acceptor: Labeled<crate::Passthrough> = Labeled::acceptor(
    crate::Passthrough::new(),
    &opts(Peer::Member(MemberId::new(0))),
  );
  // A first segment far larger than MAX_HELLO_LEN that does not start a valid hello.
  let junk = std::vec![0xABu8; 100 * 1024];
  assert_eq!(
    acceptor.handle_transport_data(&junk, Instant::ZERO),
    Intake::Failed
  );
}

#[test]
fn an_acceptor_rejects_app_plaintext_before_its_hello_is_queued() {
  // An acceptor with no remote hello yet is handshaking (peer is None), so application plaintext is
  // rejected and the inner buffers nothing — poll_transport_transmit could emit no app bytes ahead
  // of the identity prefix. Once a valid remote hello settles it, the local hello is already queued
  // and a subsequent app write is accepted in full.
  let a_id = Peer::Member(MemberId::new(0));
  let mut acceptor: Labeled<crate::Passthrough> =
    Labeled::acceptor(crate::Passthrough::new(), &opts(a_id));
  assert!(acceptor.is_handshaking());
  assert_eq!(
    acceptor.write_plaintext(b"app-data-ahead"),
    0,
    "app plaintext is rejected before the acceptor has settled"
  );
  assert_eq!(
    acceptor.buffered_outbound(),
    0,
    "nothing is queued ahead of the hello"
  );

  let d_id = Peer::Member(MemberId::new(1));
  let mut hello = Vec::new();
  encode_hello(CLUSTER, HelloId::from_peer(d_id), &mut hello);
  assert_ne!(
    acceptor.handle_transport_data(&hello, Instant::ZERO),
    Intake::Failed
  );
  assert!(!acceptor.is_handshaking(), "the acceptor is now settled");
  let mut local_hello = Vec::new();
  encode_hello(CLUSTER, HelloId::from_peer(a_id), &mut local_hello);
  assert!(
    acceptor.buffered_outbound() >= local_hello.len(),
    "the local hello is queued before any app data"
  );
  assert_eq!(
    acceptor.write_plaintext(b"app"),
    3,
    "app plaintext is accepted in full once settled"
  );
}

#[test]
fn clear_outbound_is_terminal_and_blocks_app_plaintext() {
  // Clearing the outbound discards the queued local hello. The layer must then become terminal: it
  // can never report settled, accept application plaintext, or emit any wire byte — otherwise a
  // direct caller could clear the hello yet still have app bytes ride out with no identity prefix.
  let a_id = Peer::Member(MemberId::new(0));
  let mut acceptor: Labeled<crate::Passthrough> =
    Labeled::acceptor(crate::Passthrough::new(), &opts(a_id));

  // Settle the acceptor: a valid remote hello sets `peer`, queues + flushes the local hello, and
  // drops `is_handshaking()`.
  let d_id = Peer::Member(MemberId::new(1));
  let mut hello = Vec::new();
  encode_hello(CLUSTER, HelloId::from_peer(d_id), &mut hello);
  assert_ne!(
    acceptor.handle_transport_data(&hello, Instant::ZERO),
    Intake::Failed
  );
  assert!(!acceptor.is_handshaking(), "the acceptor settled");
  let mut local_hello = Vec::new();
  encode_hello(CLUSTER, HelloId::from_peer(a_id), &mut local_hello);
  assert!(
    acceptor.buffered_outbound() >= local_hello.len(),
    "the local hello is queued before clear_outbound"
  );

  acceptor.clear_outbound();
  assert!(
    acceptor.is_handshaking(),
    "a cleared layer is terminal: it never reports settled again"
  );
  assert_eq!(
    acceptor.write_plaintext(b"app"),
    0,
    "a cleared layer accepts no application plaintext"
  );
  let mut out = Vec::new();
  assert_eq!(
    acceptor.poll_transport_transmit(&mut out),
    0,
    "a cleared layer emits nothing"
  );
  assert!(
    out.is_empty(),
    "no application bytes can be emitted after the hello was cleared"
  );
}

#[test]
fn clear_outbound_is_terminal_for_inbound_too() {
  // The inbound mirror of the outbound terminal guarantee: after clear_outbound, no inbound feed can
  // surface plaintext and no staged inbound bytes survive. A direct caller could otherwise clear the
  // layer, then feed a fresh valid hello plus an application tail and still have read_plaintext
  // surface that tail past the now-terminal layer.
  let a_id = Peer::Member(MemberId::new(0));
  let mut acceptor: Labeled<crate::Passthrough> =
    Labeled::acceptor(crate::Passthrough::new(), &opts(a_id));

  // Settle the acceptor via a valid remote hello, then stage some post-settle app plaintext that has
  // arrived but not yet been drained — clear_outbound must drop it too.
  let d_id = Peer::Member(MemberId::new(1));
  let mut hello = Vec::new();
  encode_hello(CLUSTER, HelloId::from_peer(d_id), &mut hello);
  assert_ne!(
    acceptor.handle_transport_data(&hello, Instant::ZERO),
    Intake::Failed
  );
  assert!(!acceptor.is_handshaking(), "the acceptor settled");
  assert_ne!(
    acceptor.handle_transport_data(b"staged-but-undrained", Instant::ZERO),
    Intake::Failed,
    "post-settle app bytes are accepted into the inbound staging"
  );

  acceptor.clear_outbound();

  // Feeding a fresh valid hello plus an application tail must be a terminal reject, surfacing nothing.
  let mut hello_plus_tail = Vec::new();
  encode_hello(CLUSTER, HelloId::from_peer(d_id), &mut hello_plus_tail);
  hello_plus_tail.extend_from_slice(b"app-tail");
  assert_eq!(
    acceptor.handle_transport_data(&hello_plus_tail, Instant::ZERO),
    Intake::Failed,
    "a cleared layer rejects all inbound feed"
  );
  let mut out = Vec::new();
  assert_eq!(
    acceptor.read_plaintext(&mut out),
    0,
    "a cleared layer surfaces no plaintext — neither the staged bytes nor the fed tail"
  );
  assert!(
    out.is_empty(),
    "no inbound plaintext escapes a cleared layer"
  );
}

#[test]
fn a_failed_intake_is_terminal() {
  // A Failed intake must leave the layer terminal atomically: failure and the terminal flag are set
  // together, so a direct caller that ignores the Failed cannot afterwards surface inner-staged
  // plaintext or do any I/O. Here an acceptor is fed a byte that is not a valid hello header, so
  // consume_inbound rejects and handle_transport_data routes through fail().
  let a_id = Peer::Member(MemberId::new(0));
  let mut acceptor: Labeled<crate::Passthrough> =
    Labeled::acceptor(crate::Passthrough::new(), &opts(a_id));
  assert_eq!(
    acceptor.handle_transport_data(&[0x00], Instant::ZERO),
    Intake::Failed,
    "an invalid hello header is a terminal reject"
  );
  // The layer is now terminal: it surfaces no plaintext, accepts no app write, re-rejects any feed,
  // and never reports settled again.
  let mut out = Vec::new();
  assert_eq!(
    acceptor.read_plaintext(&mut out),
    0,
    "a failed layer surfaces no plaintext"
  );
  assert!(out.is_empty());
  assert_eq!(
    acceptor.handle_transport_data(b"anything", Instant::ZERO),
    Intake::Failed,
    "a further feed stays terminal"
  );
  assert_eq!(
    acceptor.write_plaintext(b"app"),
    0,
    "a failed layer accepts no application plaintext"
  );
  assert!(
    acceptor.is_handshaking(),
    "a failed layer never reports settled again"
  );
}

#[test]
fn an_inner_failure_is_terminal() {
  use crate::transport::testutil::MockRecords;
  // When the inner record layer fails, Labeled must itself become terminal, not merely forward the
  // Failed: a direct caller ignoring it must not be able to drain inner-staged plaintext afterwards.
  let a_id = Peer::Member(MemberId::new(0));
  let mut acceptor: Labeled<MockRecords> =
    Labeled::acceptor(MockRecords::new(false, None), &opts(a_id));
  acceptor.inner = MockRecords::new(false, None).failing();
  assert_eq!(
    acceptor.handle_transport_data(b"anything", Instant::ZERO),
    Intake::Failed,
    "an inner failure propagates as Failed"
  );
  let mut out = Vec::new();
  assert_eq!(
    acceptor.read_plaintext(&mut out),
    0,
    "the layer is terminal: no plaintext is surfaced after an inner failure"
  );
  assert!(out.is_empty());
  assert_eq!(
    acceptor.write_plaintext(b"app"),
    0,
    "a failed layer accepts no application plaintext"
  );
  assert!(acceptor.is_handshaking());
}

#[test]
fn the_local_hello_is_never_partial_because_app_writes_are_gated() {
  // The structural consequence of gating app writes: because no app write can pre-fill the inner
  // while the acceptor is handshaking, the local hello always writes into an empty inner buffer.
  // So immediately after settling, with no prior accepted app write, the full hello is queued and
  // present — never truncated behind app bytes.
  let a_id = Peer::Member(MemberId::new(0));
  let mut acceptor: Labeled<crate::Passthrough> =
    Labeled::acceptor(crate::Passthrough::new(), &opts(a_id));
  assert_eq!(
    acceptor.write_plaintext(b"would-jump-the-hello"),
    0,
    "the pre-settle app write is rejected, so it cannot pre-fill the inner"
  );

  let d_id = Peer::Member(MemberId::new(1));
  let mut hello = Vec::new();
  encode_hello(CLUSTER, HelloId::from_peer(d_id), &mut hello);
  assert_ne!(
    acceptor.handle_transport_data(&hello, Instant::ZERO),
    Intake::Failed
  );
  assert!(!acceptor.is_handshaking());
  let mut local_hello = Vec::new();
  encode_hello(CLUSTER, HelloId::from_peer(a_id), &mut local_hello);
  assert_eq!(
    acceptor.buffered_outbound(),
    local_hello.len(),
    "only the full hello is queued — no app bytes precede or truncate it"
  );
}

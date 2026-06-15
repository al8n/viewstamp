//! The cluster + sender-identity handshake decorator over any [`StreamTransport`].

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use crate::{ClientId, Instant, Peer, ReplicaId};

use super::stream::{Intake, RecordIo, StreamTransport};

const HELLO_TAG: u8 = 0x0C;
const HELLO_VERSION: u8 = 2;
const PEER_REPLICA: u8 = 0;
const PEER_CLIENT: u8 = 1;
/// The maximum encoded length of a hello: tag+ver+cluster(16)+peer_tag = 19, then a 16-byte id = 35
/// (BOTH a replica and a client carry a 16-byte id: the replica field is a full 16-byte
/// [`MemberId`](crate::MemberId), not a 2-byte slot). This is the EXACT upper bound of
/// [`encode_hello`], so no valid hello ever exceeds it. Two callers rely on it: the TCP byte-stream path
/// bounds its reassembly buffer (an unparsed prefix longer than this is a malformed stream → reject),
/// and the QUIC transport sizes its pre-authentication Control frame decoder to this cap (a peer cannot
/// pin a larger first Control frame before its identity validates).
pub(crate) const MAX_HELLO_LEN: usize = 1 + 1 + 16 + 1 + 16;
/// The fixed length of any complete hello: a replica and a client now share the 16-byte id field, so
/// every valid hello is exactly [`MAX_HELLO_LEN`].
const HELLO_LEN: usize = MAX_HELLO_LEN;

/// Immutable handshake options: this node's cluster id and its own claimed identity. The inner
/// record layer is built by the driver and passed straight to [`Labeled::dialer`]/[`Labeled::acceptor`],
/// so these options carry no inner-layer configuration of their own.
#[derive(Debug, Clone, Copy)]
pub struct LabelOptions {
  cluster: u128,
  who: Peer,
}

impl LabelOptions {
  /// Creates handshake options.
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn new(cluster: u128, who: Peer) -> Self {
    Self { cluster, who }
  }
  /// The cluster id this node advertises and requires.
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn cluster(&self) -> u128 {
    self.cluster
  }
  /// This node's own claimed identity.
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn who(&self) -> Peer {
    self.who
  }
}

/// The identity a hello attests, in the codec's own slot-agnostic vocabulary: a replica's claim is a
/// raw 16-byte id and a client's is a [`ClientId`]. The codec is shared by two transports that
/// interpret the replica id differently — the QUIC identity layer reads it as a stable
/// [`MemberId`](crate::MemberId) (the full u128), while the TCP [`Labeled`] decorator maps it back to a
/// [`ReplicaId`] slot (rejecting an id that does not fit u16). Keeping the codec free of either type
/// lets `labeled` stay quic-feature-independent while still carrying the full u128 either consumer
/// needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelloId {
  /// A replica's attested identity as a raw 16-byte id (the QUIC layer reads it as a `MemberId`).
  Replica(u128),
  /// A client's attested identity.
  Client(ClientId),
}

impl HelloId {
  /// The replica id from a [`Peer`] is its slot widened to the 16-byte field (the TCP slot domain).
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn from_peer(who: Peer) -> Self {
    match who {
      Peer::Replica(r) => Self::Replica(u128::from(r.get())),
      Peer::Client(c) => Self::Client(c),
    }
  }
}

pub(crate) fn encode_hello(cluster: u128, id: HelloId, out: &mut Vec<u8>) {
  out.push(HELLO_TAG);
  out.push(HELLO_VERSION);
  out.extend_from_slice(&cluster.to_be_bytes());
  match id {
    HelloId::Replica(m) => {
      out.push(PEER_REPLICA);
      out.extend_from_slice(&m.to_be_bytes());
    }
    HelloId::Client(c) => {
      out.push(PEER_CLIENT);
      out.extend_from_slice(&c.get().to_be_bytes());
    }
  }
}

pub(crate) enum HelloOutcome {
  /// Validated; carries (claimed identity, bytes consumed from the buffer head).
  Accepted(HelloId, usize),
  /// The prefix is not yet fully buffered.
  Incomplete,
  /// Terminal reject (bad header / cluster mismatch / bad peer encoding).
  Rejected,
}

/// Validates the prefix at the head of `buf` against `expected_cluster`. The replica and client id
/// fields are both 16 bytes, so a complete hello is exactly [`HELLO_LEN`] (consumed length) and the
/// replica claim is the FULL 16-byte id — no slot narrowing happens here (the QUIC layer reads it as a
/// `MemberId`; the TCP `Labeled` decorator narrows to a slot in its own domain).
pub(crate) fn classify_hello(buf: &[u8], expected_cluster: u128) -> HelloOutcome {
  if buf.len() < 18 {
    if !buf.is_empty() && buf[0] != HELLO_TAG {
      return HelloOutcome::Rejected;
    }
    if buf.len() >= 2 && buf[1] != HELLO_VERSION {
      return HelloOutcome::Rejected;
    }
    return HelloOutcome::Incomplete;
  }
  if buf[0] != HELLO_TAG || buf[1] != HELLO_VERSION {
    return HelloOutcome::Rejected;
  }
  let cluster = u128::from_be_bytes(buf[2..18].try_into().expect("16 bytes"));
  if cluster != expected_cluster {
    return HelloOutcome::Rejected;
  }
  let kind = match buf.get(18) {
    None => return HelloOutcome::Incomplete,
    Some(&PEER_REPLICA) => PEER_REPLICA,
    Some(&PEER_CLIENT) => PEER_CLIENT,
    Some(_) => return HelloOutcome::Rejected,
  };
  // Both kinds carry a 16-byte id at offsets 19..35 (consumed length HELLO_LEN).
  if buf.len() < HELLO_LEN {
    return HelloOutcome::Incomplete;
  }
  let id = u128::from_be_bytes(buf[19..HELLO_LEN].try_into().expect("16 bytes"));
  let claimed = match kind {
    PEER_REPLICA => HelloId::Replica(id),
    _ => HelloId::Client(ClientId::new(id)),
  };
  HelloOutcome::Accepted(claimed, HELLO_LEN)
}

/// The cluster+identity handshake decorator over an inner record layer `R`.
#[derive(Debug)]
pub struct Labeled<R> {
  inner: R,
  cluster: u128,
  who: Peer,
  outbound_prefix: Vec<u8>,
  prefix_flushed: bool,
  is_acceptor: bool,
  inbound_raw: Vec<u8>,
  peer: Option<Peer>,
  post_tail: Vec<u8>,
  /// Set whenever the layer goes terminal — by `clear_outbound` or by a fatal `fail()`. Once set,
  /// every `RecordIo` method becomes a no-op or terminal result, so the layer can neither do
  /// I/O nor surface staged data — even for a direct caller reaching past the `Conn` gate. This is
  /// what makes a `Failed` intake atomically terminal: failure and this flag are set together.
  aborted: bool,
}

impl<R: StreamTransport> Labeled<R> {
  /// Wraps a driver-built inner record layer in the dialing (active) side of the cluster+identity
  /// handshake. The local hello is queued into the inner layer eagerly, so the dialer announces its
  /// identity ahead of any application data.
  pub fn dialer(inner: R, opts: &LabelOptions) -> Self {
    let mut this = Self::wrap(inner, opts, false);
    this.queue_prefix();
    this.flush_prefix_into_inner();
    this
  }

  /// Wraps a driver-built inner record layer in the accepting (passive) side of the handshake. The
  /// local hello is queued only once a valid remote hello validates the peer (see `consume_inbound`),
  /// so an acceptor never emits its identity before it has authenticated who it is talking to.
  pub fn acceptor(inner: R, opts: &LabelOptions) -> Self {
    Self::wrap(inner, opts, true)
  }

  fn wrap(inner: R, opts: &LabelOptions, is_acceptor: bool) -> Self {
    Self {
      inner,
      cluster: opts.cluster(),
      who: opts.who(),
      outbound_prefix: Vec::new(),
      prefix_flushed: false,
      is_acceptor,
      inbound_raw: Vec::new(),
      peer: None,
      post_tail: Vec::new(),
      aborted: false,
    }
  }

  fn queue_prefix(&mut self) {
    encode_hello(
      self.cluster,
      HelloId::from_peer(self.who),
      &mut self.outbound_prefix,
    );
  }

  /// Hands the queued prefix to the inner write path exactly once. The hello is at most
  /// `MAX_HELLO_LEN`, so a fresh inner outbound always accepts it whole; should the inner ever
  /// short-write it, the prefix is left queued and `prefix_flushed` stays false so the handshake
  /// cannot falsely report a flushed prefix — the conn keeps handshaking and is later reaped.
  fn flush_prefix_into_inner(&mut self) {
    if self.prefix_flushed || self.outbound_prefix.is_empty() {
      return;
    }
    let prefix = core::mem::take(&mut self.outbound_prefix);
    let accepted = self.inner.write_plaintext(&prefix);
    if accepted == prefix.len() {
      self.prefix_flushed = true;
    } else {
      self.outbound_prefix = prefix;
    }
  }

  /// Drives the layer terminal: marks it aborted and drops every Labeled-owned staging buffer (the
  /// outbound prefix and all inbound staging), then clears the inner. The single source of truth for
  /// the terminal transition, shared by `clear_outbound` and `fail`.
  fn go_terminal(&mut self) {
    self.aborted = true;
    self.outbound_prefix.clear();
    self.inbound_raw.clear();
    self.post_tail.clear();
    self.inner.clear_outbound();
  }

  /// Marks the layer terminal and returns the fatal intake result. Routing every failure through here
  /// guarantees a `Failed` result always leaves the layer terminal, so no subsequent `RecordIo`
  /// method can surface staged data or do I/O after a failure.
  fn fail(&mut self) -> Intake {
    self.go_terminal();
    Intake::Failed
  }

  /// Pulls inner plaintext, runs the gate. `Err(())` on reject; the caller routes it through `fail`.
  fn consume_inbound(&mut self) -> Result<(), ()> {
    if self.peer.is_some() {
      return Ok(());
    }
    let mut surfaced = Vec::new();
    self.inner.read_plaintext(&mut surfaced);
    if surfaced.is_empty() {
      return Ok(());
    }
    // Copy at most enough to classify the hello (bounded by MAX_HELLO_LEN); the remainder is the
    // post-hello tail, meaningful only once the hello validates.
    let want = MAX_HELLO_LEN.saturating_sub(self.inbound_raw.len());
    let take = want.min(surfaced.len());
    self.inbound_raw.extend_from_slice(&surfaced[..take]);
    let leftover = &surfaced[take..];
    match classify_hello(&self.inbound_raw, self.cluster) {
      HelloOutcome::Accepted(claimed, consumed) => {
        // The TCP transport routes by SLOT: map the codec's raw replica id back to a `ReplicaId`,
        // rejecting an id that does not fit u16. A TCP hello always encodes a slot (its `who` widened),
        // so a >u16 id is a malformed/foreign peer for this slot-based path, not a stable `MemberId` to
        // resolve (that resolution is the QUIC identity layer's job, against an active membership).
        let peer = match claimed {
          HelloId::Replica(m) => match u16::try_from(m) {
            Ok(slot) => Peer::Replica(ReplicaId::new(slot)),
            Err(_) => return Err(()),
          },
          HelloId::Client(c) => Peer::Client(c),
        };
        let mut tail = self.inbound_raw.split_off(consumed);
        tail.extend_from_slice(leftover);
        self.inbound_raw = Vec::new();
        self.post_tail.extend_from_slice(&tail);
        self.peer = Some(peer);
        if self.is_acceptor {
          self.queue_prefix();
          self.flush_prefix_into_inner();
        }
        Ok(())
      }
      HelloOutcome::Incomplete => {
        // A valid hello fits within MAX_HELLO_LEN; reaching the cap (or a leftover beyond it) without
        // a complete valid hello is a reject — the tail is never retained.
        if self.inbound_raw.len() >= MAX_HELLO_LEN || !leftover.is_empty() {
          Err(())
        } else {
          Ok(())
        }
      }
      HelloOutcome::Rejected => Err(()),
    }
  }
}

impl<R: StreamTransport> RecordIo for Labeled<R> {
  fn handle_transport_data(&mut self, input: &[u8], now: Instant) -> Intake {
    if self.aborted {
      return Intake::Failed;
    }
    let intake = self.inner.handle_transport_data(input, now);
    if matches!(intake, Intake::Failed) {
      return self.fail();
    }
    if self.consume_inbound().is_err() {
      return self.fail();
    }
    intake
  }

  fn poll_transport_transmit(&mut self, out: &mut Vec<u8>) -> usize {
    if self.aborted {
      return 0;
    }
    self.inner.poll_transport_transmit(out)
  }
  fn read_plaintext(&mut self, out: &mut Vec<u8>) -> usize {
    if self.aborted {
      return 0;
    }
    let mut n = self.post_tail.len();
    out.append(&mut self.post_tail);
    n += self.inner.read_plaintext(out);
    n
  }
  fn write_plaintext(&mut self, plaintext: &[u8]) -> usize {
    // Application plaintext is accepted only once the label handshake is settled — peer identified,
    // local hello queued ahead of any app data, inner record layer past its own handshake. Until then
    // accept nothing, so a direct caller cannot queue app bytes before the identity prefix. The hello
    // itself is queued via flush_prefix_into_inner calling the inner layer directly, so it is
    // unaffected. A cleared (aborted) layer also accepts nothing: its hello was discarded, so any app
    // bytes would ride out with no identity prefix ahead of them.
    if self.aborted || self.is_handshaking() {
      return 0;
    }
    self.inner.write_plaintext(plaintext)
  }

  fn buffered_outbound(&self) -> usize {
    // The hello was queued into the inner layer, so the inner's count already includes it.
    self.inner.buffered_outbound()
  }

  fn is_handshaking(&self) -> bool {
    // Unsettled until the remote label is validated (`peer` set) for BOTH roles — not only
    // acceptors. A dialer must not route application frames before it has authenticated the peer
    // it actually reached, so the identity binding is a routing precondition, not a reactive abort.
    // Also unsettled until the local hello prefix is fully queued into the inner layer: a
    // short/unflushed hello means the remote has not seen our identity yet, so the conn is not
    // established and must not be mistaken for one. A cleared (aborted) layer never settles again, so
    // it can never validate and an already-validated conn's next write short-writes and closes.
    self.aborted || self.peer.is_none() || !self.prefix_flushed || self.inner.is_handshaking()
  }
  fn peer_identity(&self) -> Option<Peer> {
    if self.aborted {
      return None;
    }
    self.peer
  }
  fn peer_has_closed(&self) -> bool {
    if self.aborted {
      return true;
    }
    self.inner.peer_has_closed()
  }
  fn send_close_notify(&mut self) {
    if self.aborted {
      return;
    }
    self.inner.send_close_notify();
  }
  fn clear_outbound(&mut self) {
    // Discards the queued local hello, so the hello-before-app invariant can no longer hold on this
    // layer: drive it terminal (see `aborted`). `go_terminal` drops every Labeled-owned staging buffer
    // too — the outbound prefix and ALL inbound staging — so no method can later surface bytes that
    // were already staged here before it was cleared, then clears the inner layer's own.
    self.go_terminal();
  }
  fn is_secure() -> bool {
    R::is_secure()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ClientId, Instant, Peer, ReplicaId};

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
    let d_id = Peer::Replica(ReplicaId::new(1));
    let a_id = Peer::Replica(ReplicaId::new(0));
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
    let a_id = Peer::Replica(ReplicaId::new(0));
    let mut dialer: Labeled<crate::Passthrough> = Labeled::dialer(
      crate::Passthrough::new(),
      &opts(Peer::Replica(ReplicaId::new(1))),
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
      &LabelOptions::new(0x1111, Peer::Replica(ReplicaId::new(1))),
    );
    let mut acceptor: Labeled<crate::Passthrough> = Labeled::acceptor(
      crate::Passthrough::new(),
      &LabelOptions::new(0x2222, Peer::Replica(ReplicaId::new(0))),
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
      &opts(Peer::Replica(ReplicaId::new(0))),
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
    // And it round-trips end-to-end through the dialer/acceptor pump.
    let mut dialer: Labeled<crate::Passthrough> =
      Labeled::dialer(crate::Passthrough::new(), &opts(r));
    let mut acceptor: Labeled<crate::Passthrough> = Labeled::acceptor(
      crate::Passthrough::new(),
      &opts(Peer::Replica(ReplicaId::new(0))),
    );
    pump(&mut dialer, &mut acceptor);
    assert_eq!(acceptor.peer_identity(), Some(r));
  }

  #[test]
  fn forwards_is_secure_from_inner() {
    assert!(!Labeled::<crate::Passthrough>::is_secure());
  }

  #[test]
  fn dialer_is_handshaking_until_it_learns_the_peer() {
    let d_id = Peer::Replica(ReplicaId::new(1));
    let a_id = Peer::Replica(ReplicaId::new(0));
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
    let a_id = Peer::Replica(ReplicaId::new(0));
    let opts = LabelOptions::new(CLUSTER, a_id);
    let mut acceptor: Labeled<MockRecords> =
      Labeled::acceptor(MockRecords::new(false, None), &opts);
    // Reinstall the inner with a zero write cap (the default acceptor inner has no cap).
    acceptor.inner = MockRecords::new(false, None).with_write_cap(0);

    let d_id = Peer::Replica(ReplicaId::new(1));
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
    let d_id = Peer::Replica(ReplicaId::new(1));
    let dialer: Labeled<crate::Passthrough> =
      Labeled::dialer(crate::Passthrough::new(), &opts(d_id));
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
      &opts(Peer::Replica(ReplicaId::new(0))),
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
    let a_id = Peer::Replica(ReplicaId::new(0));
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

    let d_id = Peer::Replica(ReplicaId::new(1));
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
    let a_id = Peer::Replica(ReplicaId::new(0));
    let mut acceptor: Labeled<crate::Passthrough> =
      Labeled::acceptor(crate::Passthrough::new(), &opts(a_id));

    // Settle the acceptor: a valid remote hello sets `peer`, queues + flushes the local hello, and
    // drops `is_handshaking()`.
    let d_id = Peer::Replica(ReplicaId::new(1));
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
    let a_id = Peer::Replica(ReplicaId::new(0));
    let mut acceptor: Labeled<crate::Passthrough> =
      Labeled::acceptor(crate::Passthrough::new(), &opts(a_id));

    // Settle the acceptor via a valid remote hello, then stage some post-settle app plaintext that has
    // arrived but not yet been drained — clear_outbound must drop it too.
    let d_id = Peer::Replica(ReplicaId::new(1));
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
    let a_id = Peer::Replica(ReplicaId::new(0));
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
    let a_id = Peer::Replica(ReplicaId::new(0));
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
    let a_id = Peer::Replica(ReplicaId::new(0));
    let mut acceptor: Labeled<crate::Passthrough> =
      Labeled::acceptor(crate::Passthrough::new(), &opts(a_id));
    assert_eq!(
      acceptor.write_plaintext(b"would-jump-the-hello"),
      0,
      "the pre-settle app write is rejected, so it cannot pre-fill the inner"
    );

    let d_id = Peer::Replica(ReplicaId::new(1));
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
}

//! The cluster + sender-identity handshake decorator over any [`StreamTransport`].

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use crate::{ClientId, Instant, MemberId, Peer};

use super::stream::{Intake, RecordIo, StreamTransport};

const HELLO_TAG: u8 = 0x0C;
/// The single wire-version fence: the hello is the ONE place a peer's wire version is checked. Every
/// message after it rides the protobuf envelope (`crate::wire`; `encode_message`/`decode_message`),
/// which carries no per-message version of its own — a cross-version peer is refused here, at the
/// handshake, before any consensus traffic flows. Bumped 2 → 3 for the protobuf envelope cutover.
const HELLO_VERSION: u8 = 3;

/// Exposes [`HELLO_VERSION`] to sibling transport layers OUTSIDE this module — namely the QUIC
/// transport's ALPN (`transport::quic::crypto::alpn_protocols`), which folds it into the negotiated
/// protocol id so a QUIC identity mode that sends no hello preface at all (`CertOid`) is still
/// version-fenced, at the TLS handshake, exactly like the stream `Labeled` hello and the QUIC
/// `Hello` control-stream preface. Both derive from this ONE source of truth, so a future
/// `HELLO_VERSION` bump updates the ALPN in lockstep automatically. `quic`-gated: it is otherwise
/// unused (the byte-stream transport's own version fence is the hello itself), and `quic` implies
/// `tcp`, so this is reachable everywhere `labeled` compiles WITH the one feature that calls it.
#[cfg(feature = "quic")]
#[cfg_attr(not(tarpaulin), inline(always))]
pub(crate) const fn wire_version() -> u8 {
  HELLO_VERSION
}
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
/// raw 16-byte id and a client's is a [`ClientId`]. BOTH transports now read the replica id as a
/// stable [`MemberId`](crate::MemberId) (the full u128): the QUIC identity layer and the TCP
/// [`Labeled`] decorator each surface a [`Peer::Member`](crate::Peer::Member) and resolve it to a
/// routing slot against the active membership. Keeping the codec free of either typed id lets
/// `labeled` stay quic-feature-independent while still carrying the full u128 either consumer needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelloId {
  /// A replica's attested identity as a raw 16-byte id (the QUIC layer reads it as a `MemberId`).
  Replica(u128),
  /// A client's attested identity.
  Client(ClientId),
}

impl HelloId {
  /// The replica claim from a [`Peer`] is the FULL 16-byte id: a [`Peer::Member`] carries its stable
  /// [`MemberId`] verbatim (the TCP transport now attests by stable id, mirroring QUIC), while a legacy
  /// [`Peer::Replica`] slot is widened to the same field. Both encode the identical wire byte pattern,
  /// so the [`encode_hello`] codec is unchanged.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn from_peer(who: Peer) -> Self {
    match who {
      Peer::Member(m) => Self::Replica(m.get()),
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
        // The TCP transport now attests by stable MemberId: keep the full u128, no slot narrowing.
        // The coordinator resolves MemberId→slot via endpoint.slot_of() at binding.
        let peer = match claimed {
          HelloId::Replica(m) => Peer::Member(MemberId::new(m)),
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
mod tests;

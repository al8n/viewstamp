//! The super-state-machine: the consensus [`Endpoint`] composed with per-peer conns + the router.
//! Storage stays external (the third orthogonal axis) — `handle_*` take `&mut W, &mut B`.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use bytes::Bytes;

use crate::message::Request;
use crate::{
  Endpoint, Event, Instant, Message, Outgoing, Peer, Recipient, StateMachine, Superblock, Wal,
};

use super::CloseCause;
use super::conn::Conn;
use super::frame::STAGE_CHUNK;
use super::router::{ConnId, PeerRouter};
use super::stream::StreamTransport;

/// Owns the consensus endpoint, the per-peer conns, and the router; pumps inbound transport data
/// through the endpoint and routes the endpoint's outgoing messages back out. Transport (`R`) and
/// storage (`W`/`B`, external) are independent axes.
pub struct StreamCoordinator<S, R> {
  endpoint: Endpoint<S>,
  router: PeerRouter<R>,
}

impl<S, R> core::fmt::Debug for StreamCoordinator<S, R> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("StreamCoordinator").finish_non_exhaustive()
  }
}

impl<S, R> StreamCoordinator<S, R> {
  /// Creates a coordinator around a (driver-built) endpoint, with an empty conn table.
  pub fn new(endpoint: Endpoint<S>) -> Self {
    Self {
      endpoint,
      router: PeerRouter::new(),
    }
  }

  /// Creates a coordinator with an explicit per-conn outbound PLAINTEXT staging cap instead of the
  /// default, then derives the backlog cap from it (see [`Self::max_outbound_backlog`]).
  ///
  /// Test/internal support, NOT a stable embedder API (hence `#[doc(hidden)]`): a tuned `cap` sizes
  /// only the per-conn plaintext staging buffer and the backlog accumulation threshold. It does NOT
  /// shrink the record layer's single-chunk bound (`2 * SEND_LIMIT` for `TlsRecords`), so the
  /// advertised `≤ 4x` memory bound holds only at the DEFAULT cap (where `SEND_LIMIT` equals the
  /// staging cap). Below `SEND_LIMIT` the fixed record-layer chunk dominates the peak. Exists so
  /// cross-crate tests can drive the backlog logic with a tiny cap.
  #[doc(hidden)]
  pub fn with_outbound_cap(endpoint: Endpoint<S>, cap: usize) -> Self {
    Self {
      endpoint,
      router: PeerRouter::with_outbound_cap(cap),
    }
  }

  /// A reference to the underlying endpoint (status/view/etc.).
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn endpoint(&self) -> &Endpoint<S> {
    &self.endpoint
  }
}

impl<S, R> StreamCoordinator<S, R>
where
  S: StateMachine,
  R: StreamTransport,
{
  /// Registers a conn this node dialed.
  pub fn register_dialed(&mut self, peer: Peer, conn: Conn<R>) -> ConnId {
    self.router.register_dialed(peer, conn)
  }
  /// Registers an accepted conn (canonical only if no live conn exists for its peer).
  pub fn register_accepted(&mut self, peer: Peer, conn: Conn<R>) -> ConnId {
    self.router.register_accepted(peer, conn)
  }

  /// Feeds one inbound transport read for `id`, ordered advance -> validate -> decode -> feed, so a
  /// frame can never decode before identity validation. Drives the endpoint, then pumps out. The
  /// driver should hand in reasonably-sized reads, but the transport bounds its own intake staging
  /// regardless of how much arrives in a single read.
  pub fn handle_conn_data<W: Wal, B: Superblock>(
    &mut self,
    id: ConnId,
    bytes: &[u8],
    eof: bool,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
  ) {
    // Feed the driver read in bounded chunks, decoding and draining between each, so the transport's
    // per-conn intake memory (record staging, the frame decoder's complete-frame queue) stays
    // bounded regardless of how much the driver hands in at once.
    let mut rest = bytes;
    loop {
      let take = rest.len().min(STAGE_CHUNK);
      let (chunk, tail) = rest.split_at(take);
      rest = tail;
      let last = rest.is_empty();
      let peer_finished = match self.router.conn_mut(id) {
        Some(conn) if !conn.is_closed() => {
          conn.handle_data(chunk, eof && last, now).unwrap_or(false)
        }
        Some(_) => break,
        None => return,
      };
      self.router.note_established(id);
      let mut decoded: Vec<(Peer, Message)> = Vec::new();
      if let Some(conn) = self.router.conn_mut(id) {
        let _ = conn.poll_decoded(&mut decoded);
      }
      for (from, msg) in decoded {
        self.deliver_inbound(now, wal, sb, from, msg);
      }
      // Finalize a peer-finished conn BEFORE pumping the output its final frames produced. A final
      // chunk can carry a complete request AND EOF; the endpoint's response to that request is now in
      // the outgoing backlog. Closing the conn here (after draining its buffered frames) means the
      // pump below — whose leading reap_closed() reaps this just-finalized conn and promotes a
      // validated standby for the same peer — routes that response to the standby, instead of
      // queueing it on a conn that is immediately closed and discarded (black-holing the response
      // until a later pump). A conn with no standby still closes and the response is dropped, which
      // is correct: the peer is gone.
      if peer_finished {
        if let Some(conn) = self.router.conn_mut(id) {
          let _ = conn.finalize();
        }
      }
      // Pump after each chunk so the endpoint's outgoing backlog, drained into a transient Vec by
      // pump, is bounded to one chunk's responses rather than the whole read.
      self.pump();
      if last {
        break;
      }
    }
    self.pump();
  }

  /// Submit a client request originating at this node's local application.
  ///
  /// Delivers it to this replica (served iff this replica is the primary) and broadcasts to the other
  /// replicas so whichever is primary serves it — mirroring the simulation client. `sender_matches`
  /// accepts a replica-relayed `Request`, and `on_request` serves only at the primary + dedups by client
  /// session, so a relayed copy executes at most once. The committed reply surfaces through
  /// [`Self::poll_event`] as [`crate::Event::Committed`] once this replica applies the op.
  ///
  /// A request whose body exceeds [`max_request_body_len`](super::frame::max_request_body_len) is
  /// DROPPED here — not delivered to the endpoint and not routed to backups (the same transport-ingress
  /// gate `Self::deliver_inbound` applies to a relayed inbound `Request`). Such a body would frame
  /// past [`MAX_FRAME_LEN`](super::frame::MAX_FRAME_LEN) as the resulting `Prepare`, so the primary
  /// could append an op it can never replicate; rejecting it before any session/log mutation keeps the
  /// consensus core transport-agnostic while the transport owns the deliverability bound.
  pub fn submit_client_request<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    request: Request,
  ) {
    if request.body().len() > super::frame::max_request_body_len() {
      return;
    }
    let self_id = self.endpoint.replica();
    self.endpoint.handle_message(
      now,
      wal,
      sb,
      Peer::Client(request.client()),
      Message::Request(request.clone()),
    );
    self
      .router
      .route(Recipient::Backups, &Message::Request(request), self_id);
    self.pump();
  }

  /// Deliver one decoded inbound `(from, msg)` to the consensus endpoint, enforcing the transport's
  /// deliverable-body bound at this ingress: a `Message::Request` whose body exceeds
  /// [`max_request_body_len`](super::frame::max_request_body_len) is DROPPED before it reaches the
  /// endpoint, so no op is appended, no client session row is created, and no `Prepare` is routed.
  ///
  /// This ingress accepts a `Request` RELAYED by another replica (not only one straight from the
  /// client). A buggy or version-skewed member could relay a `Request` that fits the
  /// `Request` frame yet whose resulting `Prepare` would exceed [`MAX_FRAME_LEN`](super::frame::MAX_FRAME_LEN)
  /// — the primary would log an op it can then never replicate (the oversized `Prepare` is dropped by
  /// the send path), wedging that op. Gating at the coordinator — which owns `MAX_FRAME_LEN` — keeps the
  /// consensus core (`Endpoint`) transport-agnostic: it never learns the frame limit. Every other
  /// message kind is forwarded unchanged.
  fn deliver_inbound<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    from: Peer,
    msg: Message,
  ) {
    if let Message::Request(r) = &msg {
      if r.body().len() > super::frame::max_request_body_len() {
        return;
      }
    }
    self.endpoint.handle_message(now, wal, sb, from, msg);
  }

  /// Drives timers, then pumps.
  pub fn handle_timeout<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    self.endpoint.handle_timeout(now, wal, sb);
    self.pump();
  }

  /// Drives storage completions, then pumps.
  pub fn handle_storage<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    self.endpoint.handle_storage(now, wal, sb);
    self.pump();
  }

  /// Reaps closed conns first so `peers` holds only live conns when `route` resolves, then drains
  /// `poll_message` into an owned Vec (releasing the endpoint borrow) and routes each via the
  /// router. Routing inside the poll loop would not borrow-check.
  ///
  /// The leading reap removes conns closed by OTHER paths (an inbound reject, a finalized
  /// peer-finished conn) before any routing resolves. A route that itself closes a peer's
  /// authoritative conn (outbound overflow or a short write) now reaps and promotes its own closes
  /// before it returns, so `peers` is never left pointing at a closed conn between two routes in the
  /// same pump — no trailing reap is needed here for correctness.
  fn pump(&mut self) {
    self.router.reap_closed();
    let mut outgoing: Vec<Outgoing> = Vec::new();
    while let Some(o) = self.endpoint.poll_message() {
      outgoing.push(o);
    }
    let self_id = self.endpoint.replica();
    for o in outgoing {
      self.router.route(o.to(), o.msg_ref(), self_id);
    }
  }

  /// The next conn's queued outbound bytes (round-robin fair across conns).
  pub fn poll_conn_transmit(&mut self) -> Option<(ConnId, Bytes)> {
    self.router.poll_transmit()
  }

  /// The per-conn wire-byte ACCUMULATION threshold the driver tolerates before declaring a stalled
  /// socket — 2x the [`PeerRouter`](crate::PeerRouter)'s per-conn `outbound_cap` staging size. This is
  /// NOT a per-chunk size bound and NOT the out-queue peak: the driver's always-admit-one rule admits a
  /// single chunk (a legitimately produced wire unit whose ciphertext size it deliberately does not
  /// predict) whenever the queue is at/under this and closes a conn only when its already-queued backlog
  /// is strictly over it, so a lone chunk of any size is never refused and exactly one chunk is admitted
  /// past the threshold. The real per-conn out-queue PEAK is `backlog_cap + max_single_wire_chunk`,
  /// where the max single wire chunk is bounded by the RECORD LAYER's send buffer, NOT by a tuned cap:
  /// for `TlsRecords` it is a FIXED `2 * SEND_LIMIT` (`set_buffer_limit`, independent of `outbound_cap`);
  /// for passthrough it is the staging cap. Only at the DEFAULT cap (where `SEND_LIMIT` equals the
  /// staging cap) does the TLS peak reduce to `4x` the cap; a custom cap below `SEND_LIMIT` does not
  /// shrink that fixed TLS chunk. The 2x threshold is the minimum that still admits a concurrent chunk
  /// while one maximal chunk drains, so a heartbeat/retransmit produced during a large drain is not
  /// false-closed.
  pub fn max_outbound_backlog(&self) -> usize {
    self.router.max_outbound_backlog()
  }
  /// Drains the next ConnId the coordinator has internally closed/reaped, with the [`CloseCause`]
  /// the conn recorded when it closed (a record-layer reject, a malformed frame, a failed identity,
  /// or an outbound-cap overflow), so the driver can tear down the matching socket, redial a dialed
  /// peer, and attribute the close.
  pub fn poll_conn_closed(&mut self) -> Option<(ConnId, CloseCause)> {
    self.router.poll_closed()
  }
  /// The next application event from the endpoint.
  pub fn poll_event(&mut self) -> Option<Event> {
    self.endpoint.poll_event()
  }
  /// The endpoint's next timer deadline.
  pub fn poll_timeout(&self) -> Option<Instant> {
    self.endpoint.poll_timeout()
  }
  /// Whether a conn has been validated (driver redial-vs-give-up signal).
  pub fn is_conn_validated(&self, id: ConnId) -> bool {
    self.router.is_validated(id)
  }

  /// The number of outgoing protocol messages the transport refused to send because their encoded
  /// frame would exceed `MAX_FRAME_LEN` (the inbound frame cap). Every protocol message is bounded
  /// under the cap by construction (header-only view-change carriers, the byte-bounded
  /// `RepairBatch`, chunked state-sync for over-frame checkpoints), so this stays `0` in a correct
  /// build; the transport refuses an oversized message visibly instead of emitting a frame the peer
  /// would reject or silently dropping it, and a non-zero count is an operator's bug signal.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn oversized_outbound_dropped(&self) -> u64 {
    self.router.oversized_dropped()
  }

  /// Read access to the conn table, for lifecycle tests.
  #[cfg(test)]
  pub(crate) fn router_ref(&self) -> &PeerRouter<R> {
    &self.router
  }

  /// Feeds one message through the inbound ingress (`deliver_inbound`, so the deliverable-body gate
  /// applies) then pumps — the test shortcut for the decode path.
  #[cfg(test)]
  pub(crate) fn inject_message_for_test<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    from: Peer,
    msg: Message,
  ) {
    self.deliver_inbound(now, wal, sb, from, msg);
    self.pump();
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::message::Request;
  use crate::transport::Passthrough;
  use crate::transport::stream::RecordIo;
  use crate::transport::testutil::{CountSm, TestSb, TestWal};
  use crate::{ClientId, Config, LabelOptions, Labeled, ReplicaId, RequestNumber};

  fn req() -> Message {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"x"),
    ))
  }
  fn conn() -> Conn<Passthrough> {
    Conn::from_parts(Passthrough::new())
  }

  fn labeled_conn(cluster: u128, me: u8, accept: bool) -> Conn<Labeled<Passthrough>> {
    let opts = LabelOptions::new(cluster, Peer::Replica(ReplicaId::new(me)));
    if accept {
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    } else {
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    }
  }

  #[test]
  fn inbound_request_produces_outbound_to_a_backup() {
    let cfg = Config::try_new(0xABCD, ReplicaId::new(0), 3).unwrap(); // replica 0 = primary of view 0
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord =
      StreamCoordinator::<CountSm, Passthrough>::new(Endpoint::new(cfg, 1, CountSm::default()));
    // A raw Passthrough has no handshake identity; registration validates it immediately (it trusts
    // the registered peer), so each backup conn is a routing target without any extra nudge.
    coord.register_dialed(Peer::Replica(ReplicaId::new(1)), conn());
    coord.register_dialed(Peer::Replica(ReplicaId::new(2)), conn());
    coord.inject_message_for_test(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(),
    );
    // The Prepare may emit immediately or after a storage/timer nudge; drive a few ticks.
    let mut now = Instant::ZERO;
    let mut produced = coord.poll_conn_transmit().is_some();
    for _ in 0..10 {
      if produced {
        break;
      }
      now = now + core::time::Duration::from_millis(50);
      coord.handle_storage(now, &mut wal, &mut sb);
      coord.handle_timeout(now, &mut wal, &mut sb);
      produced = coord.poll_conn_transmit().is_some();
    }
    assert!(
      produced,
      "an inbound request must produce outbound transport bytes to a backup"
    );
  }

  /// A relayed (replica-sent) `Request` whose body is ONE byte over the deliverable maximum is dropped
  /// at the transport ingress BEFORE the endpoint: no op is appended and no `Prepare` is routed to any
  /// backup. The hazard: a buggy / version-skewed member relays a `Request` that fits its own frame
  /// but whose resulting `Prepare` would exceed `MAX_FRAME_LEN`, so the primary would log an op it
  /// can never replicate. The
  /// at-maximum body, by contrast, is served and routed — the boundary is usable, not rejected
  /// off-by-one. The ingress gate keeps the consensus `Endpoint` itself transport-agnostic.
  #[test]
  fn a_relayed_over_max_request_is_dropped_at_ingress_with_no_side_effects() {
    use crate::transport::frame::{MAX_FRAME_LEN, max_request_body_len};

    // Replica 0 is the primary of view 0, so an admitted relayed Request would be served.
    let cfg = Config::try_new(0xABCD, ReplicaId::new(0), 3).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord =
      StreamCoordinator::<CountSm, Passthrough>::new(Endpoint::new(cfg, 1, CountSm::default()));
    // Two raw Passthrough backups (validated on register), so a served Prepare HAS somewhere to route —
    // proving the over-max case routes NOTHING, not merely that no conn was available.
    coord.register_dialed(Peer::Replica(ReplicaId::new(1)), conn());
    coord.register_dialed(Peer::Replica(ReplicaId::new(2)), conn());
    assert_eq!(coord.endpoint().op().get(), 0, "no op before any request");

    // A relayed Request (from a configured REPLICA — the replica-relayed ingress this gate guards)
    // whose body is one byte past the deliverable maximum: its resulting Prepare would exceed
    // MAX_FRAME_LEN.
    let over = Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from(vec![0u8; max_request_body_len() + 1]),
    ));
    coord.inject_message_for_test(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      over,
    );

    // No side effects: the op head did not advance, so no op was appended and no `Prepare` minted for
    // it. Pump STORAGE ONLY (never `handle_timeout`) so the primary's heartbeat does not fire — then
    // `poll_conn_transmit` reflects only what this request produced, which is nothing.
    let mut now = Instant::ZERO;
    for _ in 0..5 {
      now = now + core::time::Duration::from_millis(50);
      coord.handle_storage(now, &mut wal, &mut sb);
    }
    assert_eq!(
      coord.endpoint().op().get(),
      0,
      "an over-max relayed request appends no op (dropped before the endpoint)"
    );
    assert!(
      coord.poll_conn_transmit().is_none(),
      "an over-max relayed request routes no Prepare to any backup (no side effects)"
    );

    // The BOUNDARY: a body of EXACTLY max_request_body_len() is served (op appended) and routed.
    let at_max = Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from(vec![0u8; max_request_body_len()]),
    ));
    assert!(
      max_request_body_len() < MAX_FRAME_LEN as usize,
      "the deliverable max is under the frame cap by the request overhead"
    );
    coord.inject_message_for_test(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      at_max,
    );
    assert_eq!(
      coord.endpoint().op().get(),
      1,
      "an at-maximum relayed request IS served (one op appended): the boundary is usable"
    );
    // Drive the append to completion via STORAGE so the resulting Prepare is routed to the backups
    // (still no `handle_timeout`, so the transmit observed is the Prepare, not a heartbeat).
    let mut routed = coord.poll_conn_transmit().is_some();
    for _ in 0..10 {
      if routed {
        break;
      }
      now = now + core::time::Duration::from_millis(50);
      coord.handle_storage(now, &mut wal, &mut sb);
      routed = coord.poll_conn_transmit().is_some();
    }
    assert!(
      routed,
      "an at-maximum relayed request IS routed to a backup (the gate admits exactly the max)"
    );
  }

  // A single large valid read (more than one STAGE_CHUNK of framed messages) is fully processed:
  // handle_conn_data feeds it to the conn in bounded chunks, decoding between each, and the conn
  // stays open because every frame decodes cleanly.
  #[test]
  fn a_large_multi_chunk_read_is_processed_without_closing_the_conn() {
    use crate::transport::frame::encode_frame;
    let cfg = Config::try_new(0xABCD, ReplicaId::new(0), 3).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord =
      StreamCoordinator::<CountSm, Passthrough>::new(Endpoint::new(cfg, 1, CountSm::default()));
    // A raw Passthrough validates on register; inbound decodes are tagged with the bound peer.
    let id = coord.register_dialed(Peer::Replica(ReplicaId::new(1)), conn());
    // Build more than one 64 KiB STAGE_CHUNK worth of framed messages so the read spans chunks.
    let mut frames = Vec::new();
    while frames.len() <= 64 * 1024 {
      encode_frame(&req().encode(), &mut frames);
    }
    coord.handle_conn_data(id, &frames, false, Instant::ZERO, &mut wal, &mut sb);
    assert!(
      coord.router_ref().conn(id).is_some(),
      "a large valid multi-chunk read keeps the conn open"
    );
    assert!(coord.is_conn_validated(id), "the conn stays validated");
  }

  // max_outbound_backlog is 2x the router's per-conn outbound_cap staging size — the driver's
  // accumulation threshold (not the out-queue peak), config-independent of any record-layer ciphertext
  // prediction. A default-cap coordinator reports 2x the default 64 MiB staging cap.
  #[test]
  fn max_outbound_backlog_is_twice_the_router_outbound_cap() {
    let cfg = Config::try_new(0xABCD, ReplicaId::new(0), 3).unwrap();
    let coord =
      StreamCoordinator::<CountSm, Passthrough>::new(Endpoint::new(cfg, 1, CountSm::default()));
    const DEFAULT_CAP: usize = 64 * 1024 * 1024;
    assert_eq!(
      coord.max_outbound_backlog(),
      DEFAULT_CAP * 2,
      "the coordinator reports 2x the router's per-conn outbound_cap staging size (the accumulation \
       threshold)"
    );
  }

  // A peer presenting the wrong cluster id is rejected and the conn reaped.
  #[test]
  fn wrong_cluster_conn_is_reaped() {
    let cfg = Config::try_new(0xAAAA, ReplicaId::new(0), 3).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord = StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(Endpoint::new(
      cfg,
      1,
      CountSm::default(),
    ));
    let id = coord.register_accepted(
      Peer::Replica(ReplicaId::new(1)),
      labeled_conn(0xAAAA, 0, true),
    );
    // A peer that dials with the WRONG cluster (0xBBBB) sends its hello.
    let mut wrong = Labeled::<Passthrough>::dialer(
      Passthrough::new(),
      &LabelOptions::new(0xBBBB, Peer::Replica(ReplicaId::new(1))),
    );
    let mut hello = Vec::new();
    wrong.poll_transport_transmit(&mut hello);
    coord.handle_conn_data(id, &hello, false, Instant::ZERO, &mut wal, &mut sb);
    assert!(
      coord.router_ref().conn(id).is_none(),
      "wrong-cluster conn must be reaped"
    );
  }

  // A conn the coordinator reaps internally (here: a wrong-cluster hello fails the Labeled identity
  // handshake, so the record layer rejects + closes it) surfaces through poll_conn_closed exactly
  // once — with the record-reject cause — so the driver can tear down the still-open socket, redial,
  // and attribute the close. After the single drained entry, poll_conn_closed yields None (no
  // spurious closes for the surviving healthy table).
  #[test]
  fn an_internally_reaped_conn_surfaces_through_poll_conn_closed() {
    let cfg = Config::try_new(0xAAAA, ReplicaId::new(0), 3).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord = StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(Endpoint::new(
      cfg,
      1,
      CountSm::default(),
    ));
    // Nothing reaped yet on a fresh table.
    assert_eq!(coord.poll_conn_closed(), None, "no closed conn initially");
    let id = coord.register_accepted(
      Peer::Replica(ReplicaId::new(1)),
      labeled_conn(0xAAAA, 0, true),
    );
    // A peer that dials with the WRONG cluster (0xBBBB) sends its hello; the acceptor rejects it.
    let mut wrong = Labeled::<Passthrough>::dialer(
      Passthrough::new(),
      &LabelOptions::new(0xBBBB, Peer::Replica(ReplicaId::new(1))),
    );
    let mut hello = Vec::new();
    wrong.poll_transport_transmit(&mut hello);
    coord.handle_conn_data(id, &hello, false, Instant::ZERO, &mut wal, &mut sb);
    assert!(
      coord.router_ref().conn(id).is_none(),
      "the wrong-cluster conn is reaped"
    );
    assert_eq!(
      coord.poll_conn_closed(),
      Some((id, CloseCause::RecordRejected)),
      "the reaped conn's id and record-reject cause surface through poll_conn_closed"
    );
    assert_eq!(
      coord.poll_conn_closed(),
      None,
      "the closed signal is drained exactly once (no duplicate / no spurious id)"
    );
  }

  // A bad frame (a length-prefixed payload that fails Message::decode) closes the conn at the decode
  // boundary, and the reap surfaces (id, BadFrame) through poll_conn_closed — the typed cause a
  // driver attributes the close to, instead of a bare id.
  #[test]
  fn a_bad_frame_close_yields_its_cause_through_poll_conn_closed() {
    let cfg = Config::try_new(0xABCD, ReplicaId::new(0), 3).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord =
      StreamCoordinator::<CountSm, Passthrough>::new(Endpoint::new(cfg, 1, CountSm::default()));
    // A raw Passthrough validates on register, so the garbage frame reaches the decode stage.
    let id = coord.register_dialed(Peer::Replica(ReplicaId::new(1)), conn());
    assert_eq!(coord.poll_conn_closed(), None, "no closed conn initially");
    // A well-formed frame header carrying an undecodable payload: decode fails, the conn closes.
    let mut frames = Vec::new();
    crate::transport::frame::encode_frame(&[0xFF; 8], &mut frames);
    coord.handle_conn_data(id, &frames, false, Instant::ZERO, &mut wal, &mut sb);
    assert!(
      coord.router_ref().conn(id).is_none(),
      "the bad-frame conn is reaped"
    );
    assert_eq!(
      coord.poll_conn_closed(),
      Some((id, CloseCause::BadFrame)),
      "a bad-frame close surfaces its decode cause through poll_conn_closed"
    );
    assert_eq!(coord.poll_conn_closed(), None, "drained exactly once");
  }

  // After a conn closes and is reaped, a freshly-registered redial is present in the table but is
  // NOT authoritative until its handshake validates (note_established is the sole writer of `peers`).
  #[test]
  fn a_redial_is_registered_but_not_authoritative_until_validated() {
    let cfg = Config::try_new(0xABCD, ReplicaId::new(0), 3).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord = StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(Endpoint::new(
      cfg,
      1,
      CountSm::default(),
    ));
    let p = Peer::Replica(ReplicaId::new(1));
    let a = coord.register_dialed(p, labeled_conn(0xABCD, 0, false));
    // Close A with a wrong-cluster inbound, which reaps it.
    let mut wrong = Labeled::<Passthrough>::dialer(
      Passthrough::new(),
      &LabelOptions::new(0x9999, Peer::Replica(ReplicaId::new(1))),
    );
    let mut hello = Vec::new();
    wrong.poll_transport_transmit(&mut hello);
    coord.handle_conn_data(a, &hello, false, Instant::ZERO, &mut wal, &mut sb);
    assert!(coord.router_ref().conn(a).is_none(), "A reaped");
    let b = coord.register_dialed(p, labeled_conn(0xABCD, 0, false));
    assert!(
      coord.router_ref().conn(b).is_some(),
      "the redial is in the table"
    );
    assert_eq!(
      coord.router_ref().authoritative(p),
      None,
      "a not-yet-validated redial is not authoritative"
    );
  }

  // A still-handshaking conn receives no app bytes (the prepare is not routed to it).
  #[test]
  fn route_skips_a_handshaking_conn() {
    let cfg = Config::try_new(0xABCD, ReplicaId::new(0), 3).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord = StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(Endpoint::new(
      cfg,
      1,
      CountSm::default(),
    ));
    // The only backup conn is an acceptor that has NOT yet validated an inbound hello -> handshaking.
    coord.register_accepted(
      Peer::Replica(ReplicaId::new(1)),
      labeled_conn(0xABCD, 0, true),
    );
    coord.register_accepted(
      Peer::Replica(ReplicaId::new(2)),
      labeled_conn(0xABCD, 0, true),
    );
    coord.inject_message_for_test(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(),
    );
    let mut now = Instant::ZERO;
    for _ in 0..5 {
      now = now + core::time::Duration::from_millis(50);
      coord.handle_storage(now, &mut wal, &mut sb);
      coord.handle_timeout(now, &mut wal, &mut sb);
    }
    assert!(
      coord.poll_conn_transmit().is_none(),
      "no app bytes routed to a handshaking conn"
    );
  }

  // A single handle_conn_data delivering a complete request AND eof, with a validated standby for
  // the same peer, must finalize the peer-finished conn BEFORE pumping the response, so the response
  // routes to the promoted standby in the SAME call — not black-holed on a conn that is immediately
  // closed and discarded. A primary answers a GetView with a StartView addressed back to the
  // requesting replica; that response is the one whose routing must survive the EOF.
  #[test]
  fn a_final_frame_response_routes_to_a_promoted_standby_in_the_same_call() {
    use crate::transport::frame::encode_frame;
    use crate::{GetView, View};
    // Replica 0 is the primary of view 0, so it answers a GetView(view 0) synchronously.
    let cfg = Config::try_new(0xABCD, ReplicaId::new(0), 3).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord =
      StreamCoordinator::<CountSm, Passthrough>::new(Endpoint::new(cfg, 1, CountSm::default()));
    let peer = Peer::Replica(ReplicaId::new(1));
    // Two raw Passthrough conns for the same peer: the first becomes a live standby, the second (last
    // established) is authoritative. A raw conn validates on register, so both are routing-eligible.
    let standby = coord.register_dialed(peer, conn());
    let authoritative = coord.register_dialed(peer, conn());
    assert_eq!(
      coord.router_ref().authoritative(peer),
      Some(authoritative),
      "last-established conn is authoritative; the first is a live standby"
    );
    // A complete GetView frame AND eof arrive together on the authoritative conn.
    let get_view = Message::GetView(GetView::new(View::with(0), ReplicaId::new(1), 0x1234));
    let mut framed = Vec::new();
    encode_frame(&get_view.encode(), &mut framed);
    coord.handle_conn_data(
      authoritative,
      &framed,
      true,
      Instant::ZERO,
      &mut wal,
      &mut sb,
    );
    // The peer-finished conn was reaped and the standby promoted BEFORE the StartView was routed.
    assert!(
      coord.router_ref().conn(authoritative).is_none(),
      "the peer-finished conn is finalized and reaped in the same call"
    );
    assert_eq!(
      coord.router_ref().authoritative(peer),
      Some(standby),
      "the validated standby is promoted before the response is routed"
    );
    // The StartView response is queued on the promoted standby, not black-holed on the closed conn.
    assert!(
      coord.router_ref().conn(standby).unwrap().queued_outbound() > 0,
      "the final-frame response routed to the standby in the same call"
    );
    let drained = coord.poll_conn_transmit();
    assert_eq!(
      drained.map(|(id, _)| id),
      Some(standby),
      "poll_conn_transmit drains the response from the promoted standby"
    );
  }
}

//! The super-state-machine: the consensus [`Endpoint`] composed with per-peer conns + the router.
//! Storage stays external (the third orthogonal axis) — `handle_*` take `&mut W, &mut B`.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use bytes::Bytes;

use crate::{Endpoint, Event, Instant, Message, Outgoing, Peer, StateMachine, Superblock, Wal};

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
        self.endpoint.handle_message(now, wal, sb, from, msg);
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
  /// frame would exceed `MAX_FRAME_LEN` (the inbound frame cap). A message this large — e.g. a
  /// large checkpoint awaiting the deferred snapshot/message chunking — cannot be framed yet, so the
  /// transport refuses it visibly instead of emitting a frame the peer would reject or silently
  /// dropping it; a non-zero, growing count is the operator's signal that chunking is required.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn oversized_outbound_dropped(&self) -> u64 {
    self.router.oversized_dropped()
  }

  /// Read access to the conn table, for lifecycle tests.
  #[cfg(test)]
  pub(crate) fn router_ref(&self) -> &PeerRouter<R> {
    &self.router
  }

  /// Feeds one message straight to the endpoint then pumps (test shortcut for the decode path).
  #[cfg(test)]
  pub(crate) fn inject_message_for_test<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    from: Peer,
    msg: Message,
  ) {
    self.endpoint.handle_message(now, wal, sb, from, msg);
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

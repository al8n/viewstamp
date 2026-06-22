//! The super-state-machine: the consensus [`Endpoint`] composed with per-peer conns + the router.
//! Storage stays external (the third orthogonal axis) — `handle_*` take `&mut W, &mut B`.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use bytes::Bytes;

use std::collections::BTreeSet;

use crate::{
  Endpoint, Event, Instant, MemberId, Message, OpNumber, Outgoing, Peer, Recipient, SingleChange,
  SingleVoterDelta, StateMachine, Superblock, Wal, endpoint::ProposeMembershipError,
  message::Request,
};

use super::{
  CloseCause,
  conn::Conn,
  frame::STAGE_CHUNK,
  router::{ConnId, PeerRouter},
  stream::StreamTransport,
};

/// Owns the consensus endpoint, the per-peer conns, and the router; pumps inbound transport data
/// through the endpoint and routes the endpoint's outgoing messages back out. Transport (`R`) and
/// storage (`W`/`B`, external) are independent axes.
pub struct StreamCoordinator<S, R> {
  endpoint: Endpoint<S, SingleChange>,
  router: PeerRouter<R>,
  /// The `config_id` the routing table was last reconciled against — the cheap scalar gate on
  /// [`Self::reconcile_routing`] (a no-op unless the membership actually changed). Seeded from the
  /// endpoint's `config_id` at construction.
  last_reconciled_config_id: u128,
}

impl<S, R> core::fmt::Debug for StreamCoordinator<S, R> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("StreamCoordinator").finish_non_exhaustive()
  }
}

impl<S, R> StreamCoordinator<S, R> {
  /// Creates a coordinator around a (driver-built) endpoint, with an empty conn table.
  pub fn new(endpoint: Endpoint<S, SingleChange>) -> Self {
    let last_reconciled_config_id = endpoint.config_id();
    Self {
      endpoint,
      router: PeerRouter::new(),
      last_reconciled_config_id,
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
  pub fn with_outbound_cap(endpoint: Endpoint<S, SingleChange>, cap: usize) -> Self {
    let last_reconciled_config_id = endpoint.config_id();
    Self {
      endpoint,
      router: PeerRouter::with_outbound_cap(cap),
      last_reconciled_config_id,
    }
  }

  /// A reference to the underlying endpoint (status/view/etc.).
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn endpoint(&self) -> &Endpoint<S, SingleChange> {
    &self.endpoint
  }
}

impl<S, R> StreamCoordinator<S, R>
where
  S: StateMachine,
{
  /// Proposes a single-member reconfiguration to the consensus endpoint.
  ///
  /// Delegates directly to [`Endpoint::propose_membership`]. The coordinator owns `&mut self.endpoint`
  /// so the call is sequenced after any in-progress pump — no concurrent borrow is possible.
  pub fn propose_membership<W: Wal>(
    &mut self,
    now: Instant,
    wal: &mut W,
    delta: SingleVoterDelta,
  ) -> Result<OpNumber, ProposeMembershipError> {
    self.endpoint.propose_membership(now, wal, delta)
  }

  /// The set of voter [`MemberId`]s that acknowledged an in-flight prepare within the last
  /// `window` ops, as a liveness hint for the reconfiguration executor.
  pub fn recently_acked_voters(&self, window: u64) -> BTreeSet<MemberId> {
    self.endpoint.recently_acked_voters(window)
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
      self.try_note_established_member(id);
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
      if peer_finished && let Some(conn) = self.router.conn_mut(id) {
        let _ = conn.finalize();
      }
      // A frame this chunk delivered may have installed a new membership; reconcile routing against it
      // BEFORE the pump routes the chunk's responses, so they never ride a stale slot table. Cheap when
      // unchanged (a scalar config_id compare), so running it per chunk costs nothing in the steady case.
      self.reconcile_routing();
      // Pump after each chunk so the endpoint's outgoing backlog, drained into a transient Vec by
      // pump, is bounded to one chunk's responses rather than the whole read.
      self.pump();
      if last {
        break;
      }
    }
    self.pump();
  }

  /// Drives the identity-validation step after a transport-data advance: if the conn is now
  /// settled and not yet validated, classify the handshake identity into one of three cases:
  ///
  /// - `Some(Peer::Member(m))` — resolve `m` to a slot via `endpoint.slot_of`; abort with
  ///   `IdentityRejected` if the member is not in the active membership, otherwise bind via
  ///   `router.note_established_member` (stores the stable `MemberId` for the reconcile pass).
  /// - `Some(Peer::Client(_))` — fall through to the router's transport-neutral `note_established`;
  ///   clients are not membership-tracked and must not be rejected here.
  /// - `Some(Peer::Replica(_)) | None` — abort with `IdentityRejected`. A raw slot claim carries no
  ///   stable `MemberId`, so the coordinator cannot reconcile it across a membership change: after a
  ///   slot shift the stale binding would remain routable and bypass the reconciler entirely. A
  ///   reconfiguration-capable coordinator therefore requires every replica conn to attest a stable
  ///   `MemberId`; a slot-only claim is invalid at this level.
  fn try_note_established_member(&mut self, id: ConnId) {
    let (settled, hs_identity, validated, closed) = match self.router.conn(id) {
      Some(conn) => (
        !conn.is_handshaking(),
        conn.handshake_identity(),
        conn.is_validated(),
        conn.is_closed(),
      ),
      None => return,
    };
    if closed || validated || !settled {
      return;
    }
    match hs_identity {
      Some(Peer::Member(m)) => {
        // Reject a peer claiming to be THIS node. An accepted conn has no dialed expectation,
        // so without this guard a duplicate-id or misconfigured member presenting a valid cluster
        // cert for our own member_id would bind AS this node. The same guard exists in the QUIC
        // coordinator (quic/mod.rs). Checked BEFORE slot_of: a node IS in its own membership,
        // so resolving first would admit the self-claim.
        if m == self.endpoint.local() {
          if let Some(conn) = self.router.conn_mut(id) {
            conn.abort(CloseCause::IdentityRejected);
          }
          return;
        }
        match self.endpoint.slot_of(m) {
          None => {
            if let Some(conn) = self.router.conn_mut(id) {
              conn.abort(CloseCause::IdentityRejected);
            }
          }
          Some(slot) => {
            self.router.note_established_member(id, m, slot);
          }
        }
      }
      Some(Peer::Client(_)) => {
        self.router.note_established(id);
      }
      Some(Peer::Replica(_)) | None => {
        if let Some(conn) = self.router.conn_mut(id) {
          conn.abort(CloseCause::IdentityRejected);
        }
      }
    }
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
    // A removed local member owns no slot; route nothing (graceful no-op, not a panic).
    let Some(self_id) = self.endpoint.local_slot_opt() else {
      return;
    };
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
    if let Message::Request(r) = &msg
      && r.body().len() > super::frame::max_request_body_len()
    {
      return;
    }
    self.endpoint.handle_message(now, wal, sb, from, msg);
  }

  /// Drives timers, then pumps.
  pub fn handle_timeout<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    self.endpoint.handle_timeout(now, wal, sb);
    // A timeout-driven advance may have installed a new membership; reconcile routing against it
    // BEFORE the pump, so no current-config output rides a stale slot table.
    self.reconcile_routing();
    self.pump();
  }

  /// Drives storage completions, then pumps.
  pub fn handle_storage<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    self.endpoint.handle_storage(now, wal, sb);
    // A storage-completion advance (e.g. a reconfig op becoming durable) may have installed a new
    // membership; reconcile routing against it BEFORE the pump.
    self.reconcile_routing();
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
    // A removed local member owns no slot; route nothing (graceful no-op, not a panic).
    let Some(self_id) = self.endpoint.local_slot_opt() else {
      return;
    };
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

  /// The `config_id` of the currently active membership — a cheap scalar read, no clone required.
  pub fn membership_config_id(&self) -> u128 {
    self.endpoint.config_id()
  }

  /// A clone of the endpoint's currently-installed membership. Called at most once per config
  /// change in `rekey_peers`; the hot path uses `membership_config_id()` to detect whether a
  /// clone is needed at all.
  pub fn live_membership(&self) -> crate::Membership {
    self.endpoint.membership_clone()
  }

  /// Reconcile the routing table against the currently-installed membership, closing every bound slot
  /// whose attested member no longer occupies that slot (a member removed, or shifted to a different
  /// slot). Called inside every endpoint-advancing entry (`handle_conn_data` / `handle_timeout` /
  /// `handle_storage`) AFTER the advance — which may have installed a `MembershipChanged` or a
  /// cross-epoch sync membership — and BEFORE the pump, so no current-config output is ever routed on a
  /// stale slot table.
  ///
  /// Cheap by default: a scalar `config_id` compare short-circuits when the membership is unchanged, so
  /// the conn walk runs only on the rare pass that installed a new config. A stream conn now attests
  /// its STABLE [`MemberId`](crate::MemberId) (the `Labeled` handshake carries `Peer::Member`, which the
  /// coordinator bound to a slot via `endpoint.slot_of` at establishment), so the reconcile re-resolves
  /// each VALIDATED conn's attested member against the NEW membership: a member that is gone (`slot_of`
  /// returns `None`) or now lives at a DIFFERENT slot than the conn is bound to has THAT conn closed via
  /// [`Self::close_conn_by_id`]. Resolving the stable id is exact across a slot shift — a conn that
  /// stays at the same slot is left untouched, and a member that merely moved is closed so it re-binds
  /// under its new slot on the next handshake — rather than diffing slot occupants between two
  /// membership snapshots.
  ///
  /// The walk is over EVERY validated conn (`router.validated_member_conns`), NOT just the authoritative
  /// routing target per slot, so a same-peer STANDBY (a second validated conn the last-established-wins
  /// rule had displaced) is closed too. Closing it by ID is load-bearing: closing only the authoritative
  /// conn would leave a stale standby that the next pump's `reap` could PROMOTE under the old slot —
  /// without rechecking its attested member, and with `last_reconciled_config_id` already advanced — so
  /// it would stay routable for the current config and blackhole `To(slot)`/fanout after a slot shift.
  ///
  /// Safety is unchanged: this retires only ROUTING. A stale-epoch frame arriving on a not-yet-closed
  /// conn is still dropped by the endpoint's `sender_matches` / `epoch_authority_admits` ingress gates.
  pub fn reconcile_routing(&mut self) {
    let current = self.endpoint.config_id();
    if current == self.last_reconciled_config_id {
      return;
    }
    for (id, member, bound_peer) in self.router.validated_member_conns() {
      match self.endpoint.slot_of(member) {
        // Removed (or for a member outside the new config): close this conn so it leaves routing.
        None => self.close_conn_by_id(id),
        // Shifted to a different slot than this conn is bound to: close so it re-binds under the new
        // slot on its next handshake (and so a displaced standby cannot be promoted under the old slot).
        Some(new_slot) if crate::Peer::Replica(new_slot) != bound_peer => self.close_conn_by_id(id),
        // Slot unchanged: leave the conn bound (no churn for an unmoved retained member).
        Some(_) => {}
      }
    }
    self.last_reconciled_config_id = current;
  }

  /// Close a specific conn by [`ConnId`], so a stale/shifted member's conn — authoritative OR a
  /// displaced same-peer standby — leaves routing and cannot be promoted under its old slot. A no-op
  /// when the id is unknown.
  pub fn close_conn_by_id(&mut self, id: ConnId) {
    if let Some(conn) = self.router.conn_mut(id) {
      conn.abort(CloseCause::IdentityRejected);
    }
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

  /// Drives `try_note_established_member` directly for unit tests that need to exercise the
  /// identity-seal logic without going through the full `handle_conn_data` decode path.
  #[cfg(test)]
  pub(crate) fn try_note_established_for_test(&mut self, id: ConnId) {
    self.try_note_established_member(id);
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
  use std::vec;

  use super::*;
  use crate::{
    ClientId, Config, LabelOptions, Labeled, MemberId, ReplicaId, RequestNumber, SingleChange,
    message::Request,
    transport::{
      Passthrough,
      stream::RecordIo,
      testutil::{CountSm, MockRecords, TestSb, TestWal, genesis},
    },
  };

  fn req() -> Message {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"x"),
    ))
  }

  fn labeled_conn(cluster: u128, me: u16, accept: bool) -> Conn<Labeled<Passthrough>> {
    let opts = LabelOptions::new(cluster, Peer::Member(MemberId::new(me as u128)));
    if accept {
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    } else {
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    }
  }

  /// Registers a conn that presents `Peer::Member(MemberId::new(member_idx))` as its handshake
  /// identity and triggers validation through the coordinator seal. After this call the conn is
  /// authoritative for `Peer::Replica(ReplicaId::new(member_idx))` (assumes the genesis membership
  /// assigns `MemberId::new(i)` to slot `i`). Drives a zero-byte `handle_conn_data` so
  /// `try_note_established_member` fires without needing a real inbound frame.
  fn register_and_validate_member(
    coord: &mut StreamCoordinator<CountSm, MockRecords>,
    wal: &mut TestWal,
    sb: &mut TestSb,
    member_idx: u128,
  ) -> ConnId {
    let member = MemberId::new(member_idx);
    let id = coord.register_accepted(
      Peer::Replica(ReplicaId::new(member_idx as u16)),
      Conn::from_parts(MockRecords::new(false, Some(Peer::Member(member)))),
    );
    coord.handle_conn_data(id, &[], false, Instant::ZERO, wal, sb);
    id
  }

  #[test]
  fn inbound_request_produces_outbound_to_a_backup() {
    let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap(); // replica 0 = primary of view 0
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
    // Register backup conns attesting Peer::Member so try_note_established_member validates them
    // through note_established_member (the production path that stores the stable MemberId).
    register_and_validate_member(&mut coord, &mut wal, &mut sb, 1);
    register_and_validate_member(&mut coord, &mut wal, &mut sb, 2);
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
    let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
    // Two backup conns validated through the coordinator seal, so a served Prepare HAS somewhere to
    // route — proving the over-max case routes NOTHING, not merely that no conn was available.
    register_and_validate_member(&mut coord, &mut wal, &mut sb, 1);
    register_and_validate_member(&mut coord, &mut wal, &mut sb, 2);
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
    let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
    // Register and validate the conn through the coordinator seal, then feed inbound frames.
    let id = register_and_validate_member(&mut coord, &mut wal, &mut sb, 1);
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
    let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
    let coord = StreamCoordinator::<CountSm, Passthrough>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
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
    let cfg = Config::try_new(0xAAAA, MemberId::new(0)).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord =
      StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(
        Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
      );
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
    let cfg = Config::try_new(0xAAAA, MemberId::new(0)).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord =
      StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(
        Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
      );
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
    let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
    // Register and validate through the coordinator seal so the garbage frame reaches decode.
    let id = register_and_validate_member(&mut coord, &mut wal, &mut sb, 1);
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
    let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord =
      StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(
        Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
      );
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
    let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord =
      StreamCoordinator::<CountSm, Labeled<Passthrough>>::new(
        Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
      );
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
    use crate::{GetView, View, transport::frame::encode_frame};
    // Replica 0 is the primary of view 0, so it answers a GetView(view 0) synchronously.
    let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
    let peer = Peer::Replica(ReplicaId::new(1));
    // Two conns validated through the coordinator seal for the same peer (member 1 = slot 1):
    // the first becomes a live standby, the second (last-established via note_established_member)
    // is authoritative.
    let standby = register_and_validate_member(&mut coord, &mut wal, &mut sb, 1);
    let authoritative = register_and_validate_member(&mut coord, &mut wal, &mut sb, 1);
    assert_eq!(
      coord.router_ref().authoritative(peer),
      Some(authoritative),
      "last-established conn is authoritative; the first is a live standby"
    );
    // A complete GetView frame AND eof arrive together on the authoritative conn.
    let get_view = Message::GetView(GetView::new(
      View::with(0),
      ReplicaId::new(1),
      0x1234,
      crate::Epoch::new(0),
      0,
    ));
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

  // A settled conn whose handshake_identity is Peer::Replica(slot) is NOT auto-validated on
  // register and is rejected by try_note_established_member. The coordinator requires every replica
  // conn to attest a stable MemberId (via Peer::Member) so reconcile_routing can close stale bindings on
  // membership changes; a raw slot claim carries no stable id and would bypass reconciliation.
  // This test drives the production shape WITHOUT reset_validated_for_test: the conn is never
  // auto-validated because note_established blocks Peer::Replica identities at the router level.
  #[test]
  fn a_settled_replica_slot_claim_is_rejected_with_identity_rejected() {
    let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
    let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
    let slot = ReplicaId::new(1);
    // A settled MockRecords reporting Peer::Replica(slot). note_established blocks Peer::Replica
    // identity, so the conn is NOT auto-validated on register — no reset helper needed.
    let id = coord.register_dialed(
      Peer::Replica(slot),
      Conn::from_parts(MockRecords::new(false, Some(Peer::Replica(slot)))),
    );
    assert!(
      !coord.is_conn_validated(id),
      "a Peer::Replica conn is not auto-validated on register (the bypass is closed)"
    );
    assert!(
      coord
        .router_ref()
        .authoritative(Peer::Replica(slot))
        .is_none(),
      "a non-auto-validated conn is not authoritative"
    );
    // Drive the identity-seal: a Peer::Replica claim must be aborted.
    coord.try_note_established_for_test(id);
    assert!(
      coord
        .router_ref()
        .conn(id)
        .map(|c| c.is_closed())
        .unwrap_or(true),
      "a settled Peer::Replica claim is aborted by try_note_established_member"
    );
    assert!(
      !coord.is_conn_validated(id),
      "an aborted Peer::Replica conn is not validated (not a routing target)"
    );
  }

  // A settled conn whose handshake_identity is None (raw transport, no identity claim) is also
  // not auto-validated and is rejected by try_note_established_member — note_established blocks
  // Peer::Replica identity (which is what `(None, _) => expected` resolves to for a slot-registered
  // conn), so the coordinator seal classifies it as None and aborts it.
  #[test]
  fn a_settled_none_identity_is_rejected_with_identity_rejected() {
    let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
    let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
    let slot = ReplicaId::new(2);
    // MockRecords with identity=None registered as Peer::Replica: note_established would resolve
    // (None, _) => expected = Peer::Replica(slot), which is now blocked — so the conn is NOT
    // auto-validated on register. No reset helper needed.
    let id = coord.register_accepted(
      Peer::Replica(slot),
      Conn::from_parts(MockRecords::new(false, None)),
    );
    assert!(
      !coord.is_conn_validated(id),
      "a None-identity conn registered for a replica slot is not auto-validated (bypass closed)"
    );
    assert!(
      coord
        .router_ref()
        .authoritative(Peer::Replica(slot))
        .is_none(),
      "a non-auto-validated conn is not authoritative"
    );
    coord.try_note_established_for_test(id);
    assert!(
      coord
        .router_ref()
        .conn(id)
        .map(|c| c.is_closed())
        .unwrap_or(true),
      "a settled None-identity conn is aborted by try_note_established_member"
    );
    assert!(
      !coord.is_conn_validated(id),
      "an aborted None-identity conn is not validated (not a routing target)"
    );
  }

  // A settled conn whose handshake_identity is Peer::Client IS auto-validated on register (note_established
  // does not block Client identities) and is never rejected by try_note_established_member: clients
  // are not membership-tracked and must be preserved.
  #[test]
  fn a_settled_client_identity_is_preserved_and_not_rejected() {
    let cfg = Config::try_new(0xABCD, MemberId::new(0)).unwrap();
    let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
    let cid = ClientId::new(0xDEAD_BEEF);
    // A settled MockRecords that reports Peer::Client: note_established allows Client, so the conn
    // IS auto-validated on register. try_note_established_member then early-returns (already validated).
    let id = coord.register_accepted(
      Peer::Client(cid),
      Conn::from_parts(MockRecords::new(false, Some(Peer::Client(cid)))),
    );
    assert!(
      coord.is_conn_validated(id),
      "a Peer::Client conn IS auto-validated on register (clients are not blocked)"
    );
    // try_note_established_member is a no-op for already-validated conns: clients are preserved.
    coord.try_note_established_for_test(id);
    assert!(
      coord.is_conn_validated(id),
      "a Peer::Client conn is not rejected by try_note_established_member"
    );
    assert!(
      coord
        .router_ref()
        .conn(id)
        .map(|c| !c.is_closed())
        .unwrap_or(false),
      "a Peer::Client conn stays open after try_note_established_member"
    );
  }

  // An accepted conn attesting THIS node's own MemberId is aborted with IdentityRejected before
  // slot_of is consulted. A node IS in its own active membership, so without this guard a peer
  // presenting a valid cluster cert for our member_id would bind AS this node — then frames from
  // it would be delivered under this node's own `from` slot, satisfying sender_matches for a
  // network-supplied self-identifying message. Mirrors the guard in the QUIC coordinator.
  #[test]
  fn an_accepted_conn_attesting_the_local_member_id_is_aborted() {
    let local_member = MemberId::new(0); // endpoint.local() is member 0 in this config
    let cfg = Config::try_new(0xABCD, local_member).unwrap();
    let mut coord = StreamCoordinator::<CountSm, MockRecords>::new(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    );
    // A settled acceptor whose handshake identity claims to be the LOCAL member.
    // note_established does not auto-validate Peer::Member identities (only Peer::Client and
    // Peer::Replica, and the latter is blocked), so the conn is not auto-validated on register.
    // Instead, try_note_established_member must classify and abort it.
    let id = coord.register_accepted(
      Peer::Replica(ReplicaId::new(0)),
      Conn::from_parts(MockRecords::new(false, Some(Peer::Member(local_member)))),
    );
    assert!(
      !coord.is_conn_validated(id),
      "a Peer::Member conn is not auto-validated on register (handshake identity, not a routing key)"
    );
    // Drive validation: the local-member guard must abort before slot_of is called.
    coord.try_note_established_for_test(id);
    assert!(
      coord
        .router_ref()
        .conn(id)
        .map(|c| c.is_closed())
        .unwrap_or(true),
      "a conn attesting the local MemberId is aborted (IdentityRejected)"
    );
    assert!(
      !coord.is_conn_validated(id),
      "an aborted self-attesting conn is not a routing target"
    );
    // No authoritative conn for the local slot — the abort did not install a self-routing entry.
    assert!(
      coord
        .router_ref()
        .authoritative(Peer::Replica(ReplicaId::new(0)))
        .is_none(),
      "no authoritative conn for the local slot after the self-attest abort"
    );
  }
}

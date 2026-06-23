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
mod tests;

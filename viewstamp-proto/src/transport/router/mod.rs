//! The transport-neutral per-peer connection table: canonical-conn discipline, encode-once
//! fan-out, bounded outbound, and fair round-robin transmit.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use crate::{MemberId, Message, Peer, Recipient, ReplicaId};

use super::{
  CloseCause,
  conn::Conn,
  frame::{MAX_FRAME_LEN, encode_frame},
  stream::StreamTransport,
};

/// A monotonic connection handle (never reused, so a stale handle can't alias a fresh conn).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnId(u64);

impl ConnId {
  /// Wraps a raw handle value. The router is the sole authority that ALLOCATES live handles (monotonic,
  /// never reused), so a value built here is only ever a tag / lookup key: an unknown id simply misses
  /// (`conn`/`conn_mut` return `None`) and never aliases a live conn.
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn new(raw: u64) -> Self {
    Self(raw)
  }

  /// The raw handle.
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn get(self) -> u64 {
    self.0
  }
}

#[derive(Debug)]
struct Entry<R> {
  conn: Conn<R>,
  peer: Peer,
  /// Whether this node dialed the conn (as opposed to accepting it).
  dialed: bool,
  /// The stable [`MemberId`] the handshake attested for this conn, set by the coordinator after
  /// `note_established_member` validates the identity. The router stores it opaquely for the
  /// membership-reconcile pass; only the coordinator (which owns the endpoint) resolves it.
  attested_member: Option<MemberId>,
}

/// Default per-conn outbound byte cap. MUST be ≥ `MAX_FRAME_LEN` (16 MiB) so a single legitimate
/// max-size frame never leaves a healthy conn already over-cap; 64 MiB leaves headroom for a few
/// queued frames between driver drains.
const DEFAULT_OUTBOUND_CAP: usize = 64 * 1024 * 1024;

/// Per-peer connection table keyed by [`Peer`]; the authoritative pointer per peer drives all
/// routing, so `Backups`/`AllReplicas` never fan out to a stale half-open conn.
#[derive(Debug)]
pub struct PeerRouter<R> {
  conns: BTreeMap<ConnId, Entry<R>>,
  peers: BTreeMap<Peer, ConnId>,
  next: u64,
  cursor: ConnId,
  outbound_cap: usize,
  /// Count of outgoing messages refused because their encoded frame would exceed `MAX_FRAME_LEN`.
  /// Surfaced (not silently swallowed) so a driver/operator can observe that a protocol message
  /// outgrew the transport frame limit and was never sent.
  oversized_dropped: u64,
  /// ConnIds the router has internally removed, each with WHY it closed (a record-layer reject, a
  /// malformed frame, a failed identity validation, or an outbound-cap overflow). Drained via
  /// `poll_closed` so a driver can tear down the still-open socket and redial a dialed peer —
  /// otherwise a conn the proto closed internally is a silent partition until the socket happens to
  /// fail.
  closed: VecDeque<(ConnId, CloseCause)>,
}

impl<R> Default for PeerRouter<R> {
  fn default() -> Self {
    Self::new()
  }
}

impl<R> PeerRouter<R> {
  /// Creates an empty table with the default outbound cap.
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn new() -> Self {
    Self {
      conns: BTreeMap::new(),
      peers: BTreeMap::new(),
      next: 0,
      cursor: ConnId(0),
      outbound_cap: DEFAULT_OUTBOUND_CAP,
      oversized_dropped: 0,
      closed: VecDeque::new(),
    }
  }

  /// Creates an empty table with an explicit per-conn outbound PLAINTEXT staging cap.
  ///
  /// Test/internal support, NOT a stable embedder API (hence `#[doc(hidden)]`): `cap` tunes only the
  /// per-conn plaintext staging cap and the backlog accumulation threshold ([`Self::max_outbound_backlog`]).
  /// It does NOT reduce the record layer's single-chunk bound (`2 * SEND_LIMIT` for `TlsRecords`),
  /// so the advertised `≤ 4x` peak holds only at the DEFAULT cap (where `SEND_LIMIT` equals the
  /// staging cap); a smaller `cap` is dominated by that fixed record-layer chunk. Exists so
  /// cross-crate tests can drive the backlog logic with a tiny cap.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn with_outbound_cap(cap: usize) -> Self {
    Self {
      conns: BTreeMap::new(),
      peers: BTreeMap::new(),
      next: 0,
      cursor: ConnId(0),
      outbound_cap: cap,
      oversized_dropped: 0,
      closed: VecDeque::new(),
    }
  }

  /// The number of outgoing messages refused because their encoded frame would exceed
  /// `MAX_FRAME_LEN` — surfaced so a driver/operator can see a protocol message outgrew the
  /// transport frame limit and was not sent (rather than it being silently counted as delivered).
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn oversized_dropped(&self) -> u64 {
    self.oversized_dropped
  }

  /// Drains the next ConnId the router has internally removed, with the [`CloseCause`] the conn
  /// recorded when it closed (a record-layer reject, a malformed frame, a failed identity
  /// validation, or an outbound-cap overflow). The driver reconciles each: tear down the still-open
  /// socket and redial a dialed peer, else the proto-closed conn is a silent partition until the
  /// socket happens to fail.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn poll_closed(&mut self) -> Option<(ConnId, CloseCause)> {
    self.closed.pop_front()
  }

  fn alloc(&mut self) -> ConnId {
    let id = ConnId(self.next);
    self.next += 1;
    id
  }

  /// The authoritative conn for `peer`, if any.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn authoritative(&self, peer: Peer) -> Option<ConnId> {
    self.peers.get(&peer).copied()
  }

  /// Every replica SLOT that currently has an authoritative (validated, routable) conn — the membership
  /// reconcile pass's source set. Collected owned so the caller can close a slot's conn (a disjoint
  /// `&mut` borrow) inside the iteration.
  pub fn bound_replica_slots(&self) -> Vec<ReplicaId> {
    self
      .peers
      .keys()
      .filter_map(|p| match p {
        Peer::Replica(r) => Some(*r),
        _ => None,
      })
      .collect()
  }

  /// A shared reference to a conn by handle.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn conn(&self, id: ConnId) -> Option<&Conn<R>> {
    self.conns.get(&id).map(|e| &e.conn)
  }

  /// A mutable reference to a conn by handle.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn conn_mut(&mut self, id: ConnId) -> Option<&mut Conn<R>> {
    self.conns.get_mut(&id).map(|e| &mut e.conn)
  }

  /// All live handles (snapshot, for the pump's split-borrow iteration).
  pub fn ids(&self) -> Vec<ConnId> {
    self.conns.keys().copied().collect()
  }
}

impl<R> PeerRouter<R> {
  /// The per-conn wire-byte ACCUMULATION threshold the driver tolerates before declaring a stalled
  /// socket: 2x the per-conn `outbound_cap` staging size. This is NOT the peak out-queue size and NOT a
  /// single-chunk size bound. The driver's always-admit-one rule admits one chunk whenever the queue is
  /// at/under this threshold and closes a conn only when its already-queued backlog is strictly OVER it,
  /// so a single legitimately produced wire chunk of any size is never refused — and exactly ONE chunk
  /// is admitted past the threshold.
  ///
  /// The real per-conn out-queue peak is therefore `backlog_cap + max_single_wire_chunk`, where the
  /// max single wire chunk is bounded by the RECORD LAYER's send buffer (NOT by this router cap). The
  /// router's `poll_transmit` makes exactly one `poll_transport_transmit` call per chunk and returns
  /// that one drain as the `Bytes` (it does NOT aggregate multiple record-layer drains into one larger
  /// chunk). For `TlsRecords` that one encrypted chunk is bounded by `set_buffer_limit(Some(2 *
  /// SEND_LIMIT))` — a FIXED `2 * SEND_LIMIT`, independent of a tuned `outbound_cap`; for a passthrough
  /// (`tcp`) layer the chunk is the staging cap (1x). Because the TLS chunk term is fixed, only at the
  /// DEFAULT cap (where `SEND_LIMIT` equals `outbound_cap`, so `backlog_cap = 2 * SEND_LIMIT`) does the
  /// TLS peak reduce to `2 * SEND_LIMIT + 2 * SEND_LIMIT = 4x` the cap. A custom cap BELOW `SEND_LIMIT`
  /// does NOT shrink the TLS chunk, so the fixed record-layer term then dominates the peak.
  ///
  /// 2x is the minimum that still admits a concurrent chunk WHILE one maximal chunk (≤2x) drains: a
  /// heartbeat / retransmit / request produced during a large drain finds the queue at ≤2x and is
  /// admitted rather than false-closed. A 1x threshold would close as soon as that second chunk arrived
  /// while the maximal chunk was still in flight.
  pub(crate) fn max_outbound_backlog(&self) -> usize {
    self.outbound_cap.saturating_mul(2)
  }
}

/// Whether an encoded frame of `len` bytes is admissible under [`MAX_FRAME_LEN`] —
/// [`PeerRouter::route`]'s post-encode framing-correctness backstop, checked against the bytes the
/// encode actually produces (admission itself is [`Message::wire_size_bound`]'s job, checked
/// BEFORE the view is built).
fn frame_fits(len: usize) -> bool {
  len <= MAX_FRAME_LEN as usize
}

impl<R: StreamTransport> PeerRouter<R> {
  /// Registers a conn this node dialed (it becomes authoritative for `peer` once its handshake
  /// validates that identity — see `note_established`). It is NOT a routing target while handshaking.
  pub fn register_dialed(&mut self, peer: Peer, conn: Conn<R>) -> ConnId {
    let id = self.alloc();
    self.conns.insert(
      id,
      Entry {
        conn,
        peer,
        dialed: true,
        attested_member: None,
      },
    );
    // Validate immediately: a raw / already-settled conn becomes authoritative on connect; a
    // still-handshaking Labeled/TLS conn is a no-op here and validates later on inbound.
    self.note_established(id);
    id
  }

  /// Registers an accepted conn. Its peer is whatever its handshake authenticates (the `peer`
  /// argument is the driver's registration hint, used only as a placeholder / for raw transports).
  /// It is NOT a routing target until `note_established` validates and adopts its identity.
  pub fn register_accepted(&mut self, peer: Peer, conn: Conn<R>) -> ConnId {
    let id = self.alloc();
    self.conns.insert(
      id,
      Entry {
        conn,
        peer,
        dialed: false,
        attested_member: None,
      },
    );
    // Validate immediately: a raw / already-settled conn becomes authoritative on connect; a
    // still-handshaking Labeled/TLS conn is a no-op here and validates later on inbound.
    self.note_established(id);
    id
  }

  /// On establishment, bind the routing key to the handshake-authenticated identity and install it
  /// as authoritative — this is the ONLY place `peers` is written, so the authoritative map holds
  /// only established, identity-validated conns. A dialed conn that authenticates as a DIFFERENT
  /// peer than it dialed is aborted (a misconfigured address map). An accepted conn ADOPTS its
  /// authenticated identity. A raw transport with no handshake identity trusts the registered peer.
  /// The last conn to establish for an identity becomes authoritative (a genuine redial thus takes
  /// over a stale conn once it validates; a dead conn is reaped). This is the transport analogue of
  /// the proto's ingress sender-binding backstop.
  pub fn note_established(&mut self, id: ConnId) {
    let (record_settled, hs_identity, expected, dialed, closed, validated) =
      match self.conns.get(&id) {
        Some(e) => (
          !e.conn.is_handshaking(),
          e.conn.handshake_identity(),
          e.peer,
          e.dialed,
          e.conn.is_closed(),
          e.conn.is_validated(),
        ),
        None => return,
      };
    // Wait for the record/identity handshake to settle; validate each conn exactly once.
    if closed || validated || !record_settled {
      return;
    }
    let identity = match (hs_identity, dialed) {
      // Dialed + identity-bearing: the authenticated identity must match the dialed expectation.
      (Some(a), true) => {
        if a != expected {
          if let Some(e) = self.conns.get_mut(&id) {
            e.conn.abort(CloseCause::IdentityRejected);
          }
          return;
        }
        a
      }
      // Accepted + identity-bearing: adopt the authenticated identity.
      (Some(a), false) => a,
      // Raw transport (no handshake identity): trust the registered peer.
      (None, _) => expected,
    };
    // Peer::Replica and Peer::Member identities are NOT auto-validated here.
    // - Peer::Replica: a raw slot claim carries no stable MemberId; the coordinator seal
    //   (try_note_established_member) classifies and aborts it as Peer::Replica | None.
    // - Peer::Member: a handshake-attested stable id is NEVER a routing key; the coordinator
    //   resolves it to Peer::Replica(slot) via note_established_member (slot_of lookup).
    // Only Peer::Client falls through and is bound normally here.
    if matches!(identity, Peer::Replica(_) | Peer::Member(_)) {
      return;
    }
    if let Some(e) = self.conns.get_mut(&id) {
      e.peer = identity;
      e.conn.mark_validated(identity);
    }
    self.peers.insert(identity, id);
  }

  /// Coordinator-level establishment for a conn whose handshake attested a stable [`MemberId`].
  /// Resolves the routing slot externally (the coordinator owns the endpoint and calls `slot_of`)
  /// and passes it here alongside the attested member; the router binds the routing key as
  /// `Peer::Replica(resolved_slot)` and records `member` for the reconcile pass.
  ///
  /// Behaves like [`Self::note_established`] for the dialed-identity-mismatch / already-validated /
  /// not-yet-settled guards; the identity mismatch check compares `Peer::Replica(resolved_slot)`
  /// against the REGISTERED peer (which is the DIALED slot for a dialed conn).
  pub fn note_established_member(
    &mut self,
    id: ConnId,
    member: MemberId,
    resolved_slot: ReplicaId,
  ) {
    let (record_settled, expected, dialed, closed, validated) = match self.conns.get(&id) {
      Some(e) => (
        !e.conn.is_handshaking(),
        e.peer,
        e.dialed,
        e.conn.is_closed(),
        e.conn.is_validated(),
      ),
      None => return,
    };
    if closed || validated || !record_settled {
      return;
    }
    let routing_peer = Peer::Replica(resolved_slot);
    if dialed && routing_peer != expected {
      if let Some(e) = self.conns.get_mut(&id) {
        e.conn.abort(CloseCause::IdentityRejected);
      }
      return;
    }
    if let Some(e) = self.conns.get_mut(&id) {
      e.peer = routing_peer;
      e.attested_member = Some(member);
      e.conn.mark_validated(routing_peer);
    }
    self.peers.insert(routing_peer, id);
  }

  /// Bind a validated conn under the never-routable `Peer::Member(member)` QUARANTINE key: an
  /// authenticated member whose stable id the active membership does NOT resolve to a slot (a member
  /// offline across a rolling replacement, one removed while offline, a not-yet-added one). The
  /// endpoint's `as_replica()` returns `None` for a `Peer::Member`, so a quarantined conn is dropped
  /// at every vote / lead / view / fanout gate by construction while it rides the no-authority
  /// config-learning lane (state-sync serve + the epoch-ahead hint) to rejoin or learn its own
  /// retirement.
  ///
  /// Behaves like [`Self::note_established_member`] for the already-validated / not-yet-settled /
  /// closed guards. Quarantine is for ACCEPTED inbound ONLY: we dial only members we expect to
  /// resolve, so a DIALED conn whose member no longer resolves is a stale target — reject it rather
  /// than quarantine (the accept path is the one that admits a member which cannot yet resolve us).
  pub fn note_established_quarantined(&mut self, id: ConnId, member: MemberId) {
    let (record_settled, dialed, closed, validated) = match self.conns.get(&id) {
      Some(e) => (
        !e.conn.is_handshaking(),
        e.dialed,
        e.conn.is_closed(),
        e.conn.is_validated(),
      ),
      None => return,
    };
    if closed || validated || !record_settled {
      return;
    }
    if dialed {
      if let Some(e) = self.conns.get_mut(&id) {
        e.conn.abort(CloseCause::IdentityRejected);
      }
      return;
    }
    let routing_peer = Peer::Member(member);
    if let Some(e) = self.conns.get_mut(&id) {
      e.peer = routing_peer;
      e.attested_member = Some(member);
      e.conn.mark_validated(routing_peer);
    }
    self.peers.insert(routing_peer, id);
  }

  /// Whether a conn has been validated (its identity confirmed and bound). The driver uses this to
  /// decide redial-vs-give-up.
  pub fn is_validated(&self, id: ConnId) -> bool {
    self.conns.get(&id).is_some_and(|e| e.conn.is_validated())
  }

  /// Snapshot of `(conn id, attested member, current bound routing peer)` for EVERY validated conn
  /// that has a stored attested member — the membership-reconcile pass's source set. The walk is over
  /// ALL conns, not just the authoritative routing target per slot, so a same-peer STANDBY (a second
  /// validated conn last-established-wins had displaced) is included alongside the authoritative one.
  /// The reconcile pass closes a stale/shifted member's conns BY ID, so a standby cannot be promoted
  /// under the old slot after the authoritative one is reaped. Collected owned so the caller can close
  /// a conn (a disjoint `&mut` borrow) inside the iteration.
  pub fn validated_member_conns(&self) -> Vec<(ConnId, MemberId, Peer)> {
    self
      .conns
      .iter()
      .filter(|(_, e)| e.conn.is_validated())
      .filter_map(|(id, e)| Some((*id, e.attested_member?, e.peer)))
      .collect()
  }

  /// Routes one outgoing message. Encodes + frames it ONCE, then fans the shared bytes to each
  /// target conn (no per-recipient re-encode). A conn whose queued outbound is at/over the cap is
  /// closed (the driver redials; VSR retransmits). Closed conns are skipped. Returns the number of
  /// conns closed by this route (cap overflow OR a record-layer short write).
  ///
  /// Before returning, `route` reaps any conn it closed during this fan-out and promotes a validated
  /// standby for each affected peer, so `peers` is never left pointing at a conn this call just
  /// closed. A subsequent `route` for the same peer in the same pump therefore resolves to the
  /// promoted standby rather than a stale closed conn — closing the same-pump black-hole at every
  /// call site by construction, not only in the coordinator's pump.
  pub fn route(&mut self, to: Recipient, msg: &Message, self_id: ReplicaId) -> usize {
    use buffa::Message as _;
    // Symmetric frame cap, ADMITTED before building the pb view at all: the transport never emits a
    // frame larger than it would accept inbound, so a message whose frame would exceed MAX_FRAME_LEN
    // is refused here WITHOUT paying for building the view or a full encode + copy of an oversized
    // buffer the peer would only reject as FrameTooLong. EVERY protocol message is bounded under the
    // cap by construction — header-only view-change carriers, the byte-bounded RepairBatch serve,
    // and the state-sync checkpoint (bounded to [`max_unchunked_snapshot_len`] before shipping;
    // over-frame checkpoints are fetched block-by-block, never shipped as one oversized frame) — so a
    // refusal here is a REAL bug; it is counted visibly (the oversized-dropped counter) rather than
    // emitting a doomed frame or silently swallowing the send and wedging liveness. VSR
    // retransmission covers a refused send.
    //
    // `wire_size_bound()` is the admission gate, NOT `encoded_len()`: buffa's `encoded_len()` returns
    // a `u32` with unchecked accumulation, so an absurd (multi-GiB) variable-length field could wrap
    // it to a small estimate that passes a preflight — and only THEN does `encode_to_bytes()` below
    // allocate/copy the multi-GiB encoding, long before any post-encode length check runs.
    // `wire_size_bound()` is computed structurally from `msg`'s own fields with saturating
    // arithmetic throughout, so it never wraps and refuses an oversized message before the view is
    // even built.
    if msg.wire_size_bound() > MAX_FRAME_LEN as usize {
      self.oversized_dropped = self.oversized_dropped.saturating_add(1);
      return 0;
    }
    // Admitted: build the view once here and reuse it for the encode below, rather than rebuilding
    // it per send.
    let view = crate::wire::pb_message(msg);
    let encoded = view.encode_to_bytes();
    // Framing-correctness backstop: re-check the bytes the encode ACTUALLY produced before they
    // reach `encode_frame`'s own `u32` length prefix. Unreachable via OVERSIZE now that
    // `wire_size_bound` gates admission above (a message ~4 GiB nowhere near fits `MAX_FRAME_LEN`
    // and is already refused), but retained cheaply as the framing-correctness assertion of last
    // resort.
    if !frame_fits(encoded.len()) {
      self.oversized_dropped = self.oversized_dropped.saturating_add(1);
      return 0;
    }
    let mut framed = Vec::with_capacity(4 + encoded.len());
    encode_frame(&encoded, &mut framed);
    let mut dropped = 0;
    for id in self.resolve(to, self_id) {
      if let Some(e) = self.conns.get_mut(&id) {
        if !e.conn.is_validated() {
          continue;
        }
        if e.conn.queued_outbound().saturating_add(framed.len()) > self.outbound_cap {
          e.conn.abort(CloseCause::OutboundOverflow);
          dropped += 1;
          continue;
        }
        // write_framed closes the conn on a short write; count that the same as a cap overflow so the
        // reap below removes it and promotes a standby in this very pass.
        if e.conn.write_framed(&framed) {
          dropped += 1;
        }
      }
    }
    // Reap AFTER the fan-out loop (so the iteration over `conns`/`peers` is already complete and
    // cannot be invalidated): any conn this route just closed is removed and a validated standby is
    // promoted for its peer, leaving `peers` pointing only at validated conns by the time we return.
    if dropped > 0 {
      self.reap_closed();
    }
    dropped
  }

  /// Reaps every currently-closed conn (a no-op for live conns). The coordinator calls this each
  /// pump so a conn closed on the OUTBOUND path (overflow) or by an inbound reject is removed —
  /// otherwise it lingers in the table and silently black-holes routing to its peer.
  pub fn reap_closed(&mut self) {
    for id in self.ids() {
      self.reap(id);
    }
  }

  fn resolve(&self, to: Recipient, self_id: ReplicaId) -> Vec<ConnId> {
    match to {
      Recipient::To(peer) => self.authoritative(peer).into_iter().collect(),
      Recipient::Backups => self.replica_conns(Some(self_id)),
      Recipient::AllReplicas => self.replica_conns(None),
    }
  }

  fn replica_conns(&self, except: Option<ReplicaId>) -> Vec<ConnId> {
    self
      .peers
      .iter()
      .filter_map(|(peer, id)| match peer {
        Peer::Replica(r) if except != Some(*r) => Some(*id),
        _ => None,
      })
      .collect()
  }

  /// Drains the next conn's queued outbound, round-robin across conns from a rotating cursor (no
  /// global FIFO), so one slow peer cannot head-of-line-block the others. Returns `(ConnId, bytes)`.
  pub fn poll_transmit(&mut self) -> Option<(ConnId, Bytes)> {
    let after: Vec<ConnId> = self.conns.range(self.cursor..).map(|(k, _)| *k).collect();
    let before: Vec<ConnId> = self.conns.range(..self.cursor).map(|(k, _)| *k).collect();
    for id in after.into_iter().chain(before) {
      let mut out = Vec::new();
      if let Some(e) = self.conns.get_mut(&id) {
        if e.conn.is_closed() {
          continue;
        }
        e.conn.poll_transmit(&mut out);
        if !out.is_empty() {
          self.cursor = ConnId(id.get().wrapping_add(1));
          return Some((id, Bytes::from(out)));
        }
      }
    }
    None
  }

  /// Removes a closed conn's slot. If it was the authoritative conn for its peer, drop the mapping
  /// and promote a surviving established, live conn for that same peer (a redial-race standby that
  /// last-established-wins had displaced) — so reaping the authoritative conn never strands a usable
  /// replacement and black-holes the peer. The `peers` drop is equality-guarded so a dying conn
  /// cannot clobber a fresh mapping. Returns whether a slot was removed.
  pub fn reap(&mut self, id: ConnId) -> bool {
    let (cause, peer) = match self.conns.get(&id) {
      Some(e) => (e.conn.close_cause(), e.peer),
      None => return false,
    };
    // `close_cause` is `Some` iff the conn is terminal, so this is the is-closed gate AND the
    // cause read in one: a conn cannot be reaped without the cause its close transition recorded.
    let Some(cause) = cause else {
      return false;
    };
    let was_authoritative = self.peers.get(&peer).copied() == Some(id);
    self.conns.remove(&id);
    // Record every removal so a driver can reconcile: tear down the matching socket and redial a
    // dialed peer. `reap` is the single removal site (`reap_closed` and `route` both funnel through
    // it), so recording here covers every internal-close path — overflow, short write, and inbound
    // reject — exactly once per removed conn.
    self.closed.push_back((id, cause));
    if was_authoritative {
      self.peers.remove(&peer);
      let replacement = self
        .conns
        .iter()
        .find(|(_, x)| x.peer == peer && x.conn.is_validated())
        .map(|(cid, _)| *cid);
      if let Some(rid) = replacement {
        self.peers.insert(peer, rid);
      }
    }
    true
  }
}

#[cfg(test)]
mod tests;

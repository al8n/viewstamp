//! The transport-neutral per-peer connection table: canonical-conn discipline, encode-once
//! fan-out, bounded outbound, and fair round-robin transmit.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use crate::{Message, Peer, Recipient, ReplicaId};

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
    if let Some(e) = self.conns.get_mut(&id) {
      e.peer = identity;
      e.conn.mark_validated(identity);
    }
    self.peers.insert(identity, id);
  }

  /// Whether a conn has been validated (its identity confirmed and bound). The driver uses this to
  /// decide redial-vs-give-up.
  pub fn is_validated(&self, id: ConnId) -> bool {
    self.conns.get(&id).is_some_and(|e| e.conn.is_validated())
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
    // Symmetric frame cap, preflighted BEFORE encoding: the transport never emits a frame larger
    // than it would accept inbound, so a message whose frame would exceed MAX_FRAME_LEN is refused
    // here WITHOUT paying for a full encode + copy of an oversized buffer the peer would only
    // reject as FrameTooLong. EVERY protocol message is bounded under the cap by construction —
    // header-only view-change carriers, the byte-bounded RepairBatch serve, and chunked state-sync
    // (an over-frame checkpoint travels as SyncCheckpointMeta + SyncChunk pulls, never one frame) —
    // so a refusal here is a REAL bug; it is counted visibly (the oversized-dropped counter) rather
    // than emitting a doomed frame or silently swallowing the send and wedging liveness. VSR
    // retransmission covers a refused send. `encoded_len()` is the exact length `encode()` would
    // produce.
    if msg.encoded_len() > MAX_FRAME_LEN as usize {
      self.oversized_dropped = self.oversized_dropped.saturating_add(1);
      return 0;
    }
    let encoded = msg.encode();
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
mod tests {
  use super::*;
  use crate::{
    LabelOptions, Labeled, Message, OpNumber, Peer, Recipient, ReplicaId, View, message::Commit,
    transport::stream::RecordIo,
  };

  fn conn() -> Conn<crate::Passthrough> {
    Conn::from_parts(crate::Passthrough::new())
  }

  /// Registers a raw `Passthrough` conn (which reports `is_handshaking()==false` and no handshake
  /// identity) and drives `note_established`, which validates it against the registered identity.
  fn established(r: &mut PeerRouter<crate::Passthrough>, identity: Peer) -> ConnId {
    let id = r.register_dialed(identity, conn());
    r.note_established(id);
    id
  }

  #[test]
  fn redial_supersedes_a_closed_conn() {
    let peer = Peer::Replica(ReplicaId::new(1));
    let mut r = PeerRouter::<crate::Passthrough>::new();
    let a = established(&mut r, peer);
    r.conn_mut(a).unwrap().mark_closed_for_test();
    let b = established(&mut r, peer);
    assert_eq!(r.authoritative(peer), Some(b));
  }

  #[test]
  fn last_established_conn_is_authoritative() {
    let peer = Peer::Replica(ReplicaId::new(2));
    let mut r = PeerRouter::<crate::Passthrough>::new();
    let _a = established(&mut r, peer);
    let b = established(&mut r, peer);
    assert_eq!(r.authoritative(peer), Some(b));
  }

  #[test]
  fn reap_is_equality_guarded() {
    let peer = Peer::Replica(ReplicaId::new(3));
    let mut r = PeerRouter::<crate::Passthrough>::new();
    let a = established(&mut r, peer);
    r.conn_mut(a).unwrap().mark_closed_for_test();
    let b = established(&mut r, peer);
    r.reap(a);
    assert_eq!(r.authoritative(peer), Some(b));
    assert!(r.conn(a).is_none());
  }

  #[test]
  fn ids_lists_all_live_conns() {
    let mut r = PeerRouter::<crate::Passthrough>::new();
    let a = r.register_dialed(Peer::Replica(ReplicaId::new(0)), conn());
    let b = r.register_dialed(Peer::Replica(ReplicaId::new(1)), conn());
    let ids = r.ids();
    assert!(ids.contains(&a) && ids.contains(&b) && ids.len() == 2);
  }

  #[test]
  fn max_outbound_backlog_is_twice_the_outbound_cap() {
    // The accumulation threshold the driver reads is 2x the router's ACTUAL per-conn outbound_cap
    // staging size (the minimum that still admits a concurrent chunk while one maximal ~2x-expanded
    // wire chunk drains), so it tracks a configured cap, not just the default. It is the threshold, not
    // the peak: the always-admit-one rule admits one chunk past it, so the real peak is `backlog_cap +
    // one max wire chunk`.
    let default = PeerRouter::<crate::Passthrough>::new();
    assert_eq!(default.max_outbound_backlog(), DEFAULT_OUTBOUND_CAP * 2);
    let custom = PeerRouter::<crate::Passthrough>::with_outbound_cap(4096);
    assert_eq!(
      custom.max_outbound_backlog(),
      4096 * 2,
      "max_outbound_backlog is 2x a custom cap set via with_outbound_cap"
    );
  }

  fn commit_msg() -> Message {
    Message::Commit(Commit::new(
      View::with(1),
      OpNumber::with(5),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    ))
  }

  #[test]
  fn backups_fan_out_to_all_replica_conns_once() {
    let mut r = PeerRouter::<crate::Passthrough>::new();
    let p0 = Peer::Replica(ReplicaId::new(0));
    let p2 = Peer::Replica(ReplicaId::new(2));
    let c0 = established(&mut r, p0);
    let c2 = established(&mut r, p2);
    let dropped = r.route(Recipient::Backups, &commit_msg(), ReplicaId::new(1));
    assert_eq!(dropped, 0);
    assert!(r.conn(c0).unwrap().queued_outbound() > 0);
    assert!(r.conn(c2).unwrap().queued_outbound() > 0);
  }

  #[test]
  fn overflow_drops_the_conn() {
    let mut r = PeerRouter::<crate::Passthrough>::with_outbound_cap(8);
    let p = Peer::Replica(ReplicaId::new(0));
    let c = established(&mut r, p);
    for _ in 0..100 {
      r.route(Recipient::To(p), &commit_msg(), ReplicaId::new(1));
    }
    // The over-cap route aborts the conn and reaps it within route() itself; with no standby for the
    // peer, its authoritative mapping is dropped too (the driver redials).
    assert!(r.conn(c).is_none(), "an overflow-closed conn is reaped");
    assert_eq!(
      r.authoritative(p),
      None,
      "no standby exists, so the peer has no authoritative conn after the overflow close"
    );
  }

  #[test]
  fn a_reaped_conn_surfaces_through_poll_closed_exactly_once() {
    // The outbound-cap overflow path is the easiest reaping to trigger deterministically: a conn
    // whose queued outbound exceeds the cap is aborted + reaped inside route(). Its id must surface
    // through poll_closed — WITH the overflow cause the abort recorded — exactly once, then None.
    let mut r = PeerRouter::<crate::Passthrough>::with_outbound_cap(8);
    let p = Peer::Replica(ReplicaId::new(0));
    assert_eq!(r.poll_closed(), None, "no closed conn before any reap");
    let c = established(&mut r, p);
    // A single framed message larger than the 8-byte cap aborts + reaps the conn on the first route.
    r.route(Recipient::To(p), &commit_msg(), ReplicaId::new(1));
    assert!(r.conn(c).is_none(), "the over-cap conn is reaped");
    assert_eq!(
      r.poll_closed(),
      Some((c, CloseCause::OutboundOverflow)),
      "the reaped conn's id and overflow cause are drained for driver reconciliation"
    );
    assert_eq!(
      r.poll_closed(),
      None,
      "drained exactly once, no duplicate id"
    );
  }

  #[test]
  fn an_outbound_message_that_would_exceed_the_cap_aborts_the_conn() {
    let mut r = PeerRouter::<crate::Passthrough>::with_outbound_cap(8);
    let peer = Peer::Replica(ReplicaId::new(0));
    let c = established(&mut r, peer);
    // a single framed message larger than the 8-byte cap aborts on the first route (queued 0 + framed > cap)
    r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9));
    assert!(
      r.conn(c).map(|x| x.is_closed()).unwrap_or(true),
      "an over-cap outbound message aborts the conn before queueing"
    );
  }

  /// Establishes an accepting `Labeled<Passthrough>` conn for `dialer_id` by feeding it the dialer's
  /// hello, so it validates the remote, queues its own hello into the inner layer, and becomes a
  /// routing target whose `buffered_outbound` already holds the hello.
  fn established_labeled(
    r: &mut PeerRouter<Labeled<crate::Passthrough>>,
    local_id: Peer,
    dialer_id: Peer,
  ) -> ConnId {
    let opts = LabelOptions::new(0xABCD, local_id);
    let dialer_wire = {
      let mut dialer: Labeled<crate::Passthrough> = Labeled::dialer(
        crate::Passthrough::new(),
        &LabelOptions::new(0xABCD, dialer_id),
      );
      let mut wire = Vec::new();
      dialer.poll_transport_transmit(&mut wire);
      wire
    };
    let mut conn = Conn::from_parts(Labeled::acceptor(crate::Passthrough::new(), &opts));
    conn
      .handle_data(&dialer_wire, false, crate::Instant::ZERO)
      .unwrap();
    let id = r.register_accepted(dialer_id, conn);
    r.note_established(id);
    id
  }

  #[test]
  fn the_cap_accounts_for_the_queued_handshake_hello() {
    let dialer_id = Peer::Replica(ReplicaId::new(1));
    // Probe the hello length and a single framed message length, then size a small cap so exactly
    // one application frame fits ALONGSIDE the queued hello.
    let hello_len = {
      let probe: Labeled<crate::Passthrough> = Labeled::dialer(
        crate::Passthrough::new(),
        &LabelOptions::new(0xABCD, Peer::Replica(ReplicaId::new(0))),
      );
      probe.buffered_outbound()
    };
    let framed_len = {
      let mut framed = Vec::new();
      encode_frame(&commit_msg().encode(), &mut framed);
      framed.len()
    };
    let cap = hello_len + framed_len;
    let mut r = PeerRouter::<Labeled<crate::Passthrough>>::with_outbound_cap(cap);
    let c = established_labeled(&mut r, Peer::Replica(ReplicaId::new(0)), dialer_id);
    assert!(
      r.conn(c).unwrap().queued_outbound() >= hello_len,
      "the established acceptor has its hello queued in the outbound buffer"
    );
    // One frame fits exactly under the cap (hello + framed == cap), so the conn must NOT close —
    // the hello is counted but does not falsely push a legitimate first frame over the boundary.
    let dropped = r.route(Recipient::To(dialer_id), &commit_msg(), ReplicaId::new(9));
    assert_eq!(
      dropped, 0,
      "a frame that fits beside the hello is not dropped"
    );
    assert!(
      !r.conn(c).unwrap().is_closed(),
      "the conn stays open: hello + one frame is within the cap"
    );
    // A second frame now pushes buffered_outbound + framed over the cap -> the intended abort, which
    // route() folds into its own reap pass, so the conn (no standby for this peer) is gone afterward.
    let dropped = r.route(Recipient::To(dialer_id), &commit_msg(), ReplicaId::new(9));
    assert_eq!(dropped, 1, "the frame that exceeds the cap aborts the conn");
    assert!(
      r.conn(c).is_none(),
      "exceeding the cap (counting the hello) aborts the conn, which route() reaps in the same pass"
    );
  }

  #[test]
  fn poll_transmit_is_round_robin() {
    let mut r = PeerRouter::<crate::Passthrough>::new();
    let c0 = established(&mut r, Peer::Replica(ReplicaId::new(0)));
    let c1 = established(&mut r, Peer::Replica(ReplicaId::new(1)));
    r.route(Recipient::AllReplicas, &commit_msg(), ReplicaId::new(9)); // self not present -> both
    let first = r.poll_transmit().unwrap().0;
    let second = r.poll_transmit().unwrap().0;
    assert!((first == c0 && second == c1) || (first == c1 && second == c0));
    assert_ne!(first, second);
  }

  #[test]
  fn accepted_conn_adopts_its_authenticated_identity() {
    use crate::transport::testutil::MockRecords;
    let mut r = PeerRouter::<MockRecords>::new();
    let placeholder = Peer::Replica(ReplicaId::new(9));
    let real = Peer::Replica(ReplicaId::new(2));
    let id = r.register_accepted(
      placeholder,
      Conn::from_parts(MockRecords::new(false, Some(real))),
    );
    r.note_established(id);
    assert_eq!(
      r.authoritative(real),
      Some(id),
      "adopts the authenticated identity"
    );
    assert_eq!(
      r.authoritative(placeholder),
      None,
      "the placeholder mapping is dropped"
    );
  }

  #[test]
  fn dialed_conn_identity_mismatch_is_aborted() {
    use crate::transport::testutil::MockRecords;
    let mut r = PeerRouter::<MockRecords>::new();
    let id = r.register_dialed(
      Peer::Replica(ReplicaId::new(5)),
      Conn::from_parts(MockRecords::new(
        false,
        Some(Peer::Replica(ReplicaId::new(2))),
      )),
    );
    r.note_established(id);
    assert!(
      r.conn(id).map(|c| c.is_closed()).unwrap_or(true),
      "a dialed conn that validates as a different replica is aborted"
    );
  }

  #[test]
  fn a_redial_does_not_steal_a_live_conn() {
    // The redial uses a still-handshaking conn (a raw conn would validate on register), so it is
    // registered but not yet authoritative while `old` is live and validated.
    use crate::transport::testutil::MockRecords;
    let mut r = PeerRouter::<MockRecords>::new();
    let peer = Peer::Replica(ReplicaId::new(1));
    let old = r.register_dialed(peer, Conn::from_parts(MockRecords::new(false, Some(peer))));
    assert_eq!(r.authoritative(peer), Some(old), "the settled conn is live");
    let _new = r.register_dialed(peer, Conn::from_parts(MockRecords::new(true, None)));
    assert_eq!(
      r.authoritative(peer),
      Some(old),
      "a not-yet-validated redial is not authoritative"
    );
  }

  #[test]
  fn a_validated_redial_is_promoted_over_a_live_conn() {
    let mut r = PeerRouter::<crate::Passthrough>::new();
    let peer = Peer::Replica(ReplicaId::new(1));
    let _old = established(&mut r, peer);
    let new = established(&mut r, peer);
    assert_eq!(
      r.authoritative(peer),
      Some(new),
      "the validated redial is promoted to authoritative"
    );
  }

  #[test]
  fn reaping_the_authoritative_conn_promotes_a_live_replacement() {
    let mut r = PeerRouter::<crate::Passthrough>::new();
    let peer = Peer::Replica(ReplicaId::new(1));
    let old = established(&mut r, peer);
    let new = established(&mut r, peer); // last-established wins; `old` is now a live standby
    assert_eq!(r.authoritative(peer), Some(new));
    r.conn_mut(new).unwrap().mark_closed_for_test();
    r.reap(new);
    assert_eq!(
      r.authoritative(peer),
      Some(old),
      "reaping the authoritative conn promotes the surviving live replacement"
    );
  }

  #[test]
  fn route_does_not_reach_an_unestablished_conn() {
    let mut r = PeerRouter::<Labeled<crate::Passthrough>>::new();
    let peer = Peer::Replica(ReplicaId::new(1));
    let opts = LabelOptions::new(0xABCD, Peer::Replica(ReplicaId::new(0)));
    let c = r.register_dialed(
      peer,
      Conn::from_parts(Labeled::dialer(crate::Passthrough::new(), &opts)),
    );
    // The dialer has not validated the remote yet -> not established -> not in `peers` -> route
    // resolves no target, so no app frame is written.
    let before = r.conn(c).unwrap().queued_outbound();
    r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9));
    assert_eq!(
      r.conn(c).unwrap().queued_outbound(),
      before,
      "no application frame is routed to a not-yet-validated dialed conn"
    );
  }

  #[test]
  fn old_conn_traffic_does_not_steal_authority_after_a_redial() {
    let mut r = PeerRouter::<crate::Passthrough>::new();
    let peer = Peer::Replica(ReplicaId::new(1));
    let old = established(&mut r, peer);
    let new = established(&mut r, peer);
    assert_eq!(r.authoritative(peer), Some(new));
    r.note_established(old); // a later inbound on the old conn must NOT re-promote it
    assert_eq!(
      r.authoritative(peer),
      Some(new),
      "old-conn traffic does not steal authority back"
    );
  }

  #[test]
  fn a_conn_aborted_by_route_is_reaped_and_a_standby_is_promoted_in_the_same_pass() {
    // route() aborts the authoritative conn on outbound overflow and reaps+promotes within the SAME
    // call, repointing the peer to a validated standby instead of black-holing it until a later pump.
    // The cap fits exactly one framed message, so the first route to a conn is queued and the second
    // overflows and aborts it.
    let framed_len = {
      let mut framed = Vec::new();
      encode_frame(&commit_msg().encode(), &mut framed);
      framed.len()
    };
    let mut r = PeerRouter::<crate::Passthrough>::with_outbound_cap(framed_len);
    let peer = Peer::Replica(ReplicaId::new(1));
    let standby = established(&mut r, peer); // a validated conn for `peer`
    let authoritative = established(&mut r, peer); // last-established wins; `standby` is now live but not authoritative
    assert_eq!(r.authoritative(peer), Some(authoritative));
    // First route to the authoritative conn fits exactly under the cap; the second overflows it.
    assert_eq!(
      r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9)),
      0
    );
    // The standby is untouched while it is not authoritative: route(To) only reaches the authoritative.
    assert_eq!(r.conn(standby).unwrap().queued_outbound(), 0);
    // The over-cap route aborts the authoritative conn AND, before returning, reaps it and promotes
    // the surviving validated standby for the same peer — no external reap needed.
    let dropped = r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9));
    assert_eq!(
      dropped, 1,
      "the over-cap route aborts the authoritative conn"
    );
    assert!(
      r.conn(authoritative).is_none(),
      "the route-aborted conn is reaped within route() itself"
    );
    assert_eq!(
      r.authoritative(peer),
      Some(standby),
      "the validated standby is promoted by route(), not black-holed"
    );
    // Routing is not black-holed: the NEXT route reaches the promoted standby and one frame fits.
    let dropped = r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9));
    assert_eq!(dropped, 0, "the promoted standby accepts the next route");
    assert!(
      r.conn(standby).unwrap().queued_outbound() > 0,
      "the next message is queued on the promoted standby"
    );
    assert_eq!(
      r.poll_transmit().map(|(id, _)| id),
      Some(standby),
      "poll_transmit drains the promoted standby (routing is not black-holed)"
    );
  }

  #[test]
  fn poll_transmit_skips_a_closed_conn() {
    let mut r = PeerRouter::<crate::Passthrough>::new();
    let peer = Peer::Replica(ReplicaId::new(1));
    let c = established(&mut r, peer);
    r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9)); // queue bytes on `c`
    r.conn_mut(c).unwrap().mark_closed_for_test(); // close WITHOUT clearing (mirrors a TLS abort)
    assert!(
      r.poll_transmit().is_none(),
      "a closed conn is not polled for its queued bytes"
    );
  }

  /// Registers a `MockRecords` conn validated for `identity` (it is not handshaking and bears the
  /// identity, so `note_established` adopts it), with a settable write cap so a test can drive the
  /// record-layer short-write path past the router's per-conn cap check.
  fn established_mock(
    r: &mut PeerRouter<crate::transport::testutil::MockRecords>,
    identity: Peer,
    write_cap: usize,
  ) -> ConnId {
    use crate::transport::testutil::MockRecords;
    let records = MockRecords::new(false, Some(identity)).with_write_cap(write_cap);
    let id = r.register_dialed(identity, Conn::from_parts(records));
    r.note_established(id);
    id
  }

  #[test]
  fn a_route_time_short_write_close_is_reaped_and_a_standby_promoted_in_the_same_pass() {
    use crate::transport::testutil::MockRecords;
    // route()'s short-write close (AFTER the per-conn cap check) counts the same as a cap overflow, so
    // route() removes the closed conn and promotes a validated standby before it returns. The router
    // cap is the default (large), so the pre-write cap branch does NOT fire; the authoritative conn's
    // record layer has write_cap 0, so write_framed short-writes and closes it.
    let mut r = PeerRouter::<MockRecords>::new();
    let peer = Peer::Replica(ReplicaId::new(1));
    let standby = established_mock(&mut r, peer, usize::MAX); // accepts writes; a live standby
    let authoritative = established_mock(&mut r, peer, 0); // short-writes any frame → closes
    assert_eq!(
      r.authoritative(peer),
      Some(authoritative),
      "last-established wins; the short-writing conn is authoritative"
    );
    // The router cap is large, so the cap branch is NOT what closes the conn — the short write is. The
    // route reaps the short-write-closed conn and promotes the validated standby within the same call.
    let dropped = r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9));
    assert_eq!(
      dropped, 1,
      "a route-time short-write close is counted like a cap overflow"
    );
    assert!(
      r.conn(authoritative).is_none(),
      "the short-write-closed conn is reaped within route() itself"
    );
    assert_eq!(
      r.authoritative(peer),
      Some(standby),
      "the validated standby is promoted by route(), not black-holed"
    );
    // Routing is not black-holed: the NEXT route reaches the promoted standby and is queued.
    let dropped = r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9));
    assert_eq!(dropped, 0, "the promoted standby accepts the next route");
    assert!(
      r.conn(standby).unwrap().queued_outbound() > 0,
      "the next message is queued on the promoted standby"
    );
  }

  #[test]
  fn two_same_peer_outputs_in_one_pump_are_not_black_holed_when_the_first_closes_the_conn() {
    use crate::transport::testutil::MockRecords;
    // The black-hole this fix closes: two outputs for the SAME peer routed back-to-back (as a single
    // pump drains two endpoint messages for that peer). The FIRST route closes the authoritative conn
    // (here a record-layer short write, with a large router cap so only the short-write branch fires);
    // a validated standby for the peer exists. Because route() reaps+promotes its own close before
    // returning, the SECOND output must reach the promoted standby instead of resolving to the stale
    // closed conn and being dropped.
    let mut r = PeerRouter::<MockRecords>::new();
    let peer = Peer::Replica(ReplicaId::new(1));
    let standby = established_mock(&mut r, peer, usize::MAX); // accepts writes; a live standby
    let authoritative = established_mock(&mut r, peer, 0); // short-writes any frame → closes on first route
    assert_eq!(
      r.authoritative(peer),
      Some(authoritative),
      "last-established wins; the short-writing conn is authoritative"
    );

    // FIRST output: closes the authoritative conn on its short write. route() reaps it and promotes
    // the validated standby before returning, so peers is already repointed when this call ends.
    let dropped = r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9));
    assert_eq!(dropped, 1, "the first output closes the authoritative conn");
    assert!(
      r.conn(authoritative).is_none(),
      "route() reaped the closed conn before the second output is routed"
    );
    assert_eq!(
      r.authoritative(peer),
      Some(standby),
      "the standby is already promoted after the first route, not after a later pump"
    );

    // SECOND output (same peer, same pump): resolves to the promoted standby — NOT the stale closed
    // conn — so it is queued rather than black-holed.
    let dropped = r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9));
    assert_eq!(dropped, 0, "the second output is delivered, not dropped");
    assert!(
      r.conn(standby).unwrap().queued_outbound() > 0,
      "the second same-pump output is queued on the promoted standby"
    );
    assert_eq!(
      r.poll_transmit().map(|(id, _)| id),
      Some(standby),
      "poll_transmit drains the second output from the promoted standby (not black-holed)"
    );
  }

  #[test]
  fn an_oversized_outbound_frame_is_dropped_and_the_conn_stays_open() {
    use crate::{ClientId, Request, RequestNumber, transport::frame::MAX_FRAME_LEN};
    // A locally produced message whose encoded frame exceeds MAX_FRAME_LEN (the inbound cap) is
    // refused rather than queued — the peer would reject it as FrameTooLong, so emitting it would
    // needlessly close an otherwise healthy conn. The conn must stay open with nothing queued, and
    // the oversize must be surfaced via the oversized-dropped counter (not silently counted as sent).
    // A body of MAX_FRAME_LEN bytes plus the message header encodes to strictly more than
    // MAX_FRAME_LEN. Only ONE such message is allocated, and the preflight check is asserted via the
    // cheap encoded_len() so no second 16 MiB copy is made.
    let mut r = PeerRouter::<crate::Passthrough>::new();
    let peer = Peer::Replica(ReplicaId::new(1));
    let c = established(&mut r, peer);
    let body = bytes::Bytes::from(std::vec![0u8; MAX_FRAME_LEN as usize]);
    let huge = Message::Request(Request::new(ClientId::new(1), RequestNumber::with(1), body));
    assert!(
      huge.encoded_len() > MAX_FRAME_LEN as usize,
      "the crafted message's encoded length exceeds the frame cap (checked without encoding)"
    );
    assert_eq!(r.oversized_dropped(), 0, "no oversize recorded yet");
    let dropped = r.route(Recipient::To(peer), &huge, ReplicaId::new(9));
    assert_eq!(dropped, 0, "an oversized frame is skipped, not a close");
    assert_eq!(
      r.oversized_dropped(),
      1,
      "the refused oversized message is surfaced via the oversized-dropped counter"
    );
    assert!(
      !r.conn(c).unwrap().is_closed(),
      "the conn stays open: an oversized local frame is refused, the conn is not closed"
    );
    assert_eq!(
      r.conn(c).unwrap().queued_outbound(),
      0,
      "nothing is queued for a frame the peer would reject as FrameTooLong"
    );
    // A normal-sized message still routes fine on the same conn afterwards (it stayed healthy) and
    // does not bump the oversized counter.
    let dropped = r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9));
    assert_eq!(dropped, 0);
    assert_eq!(
      r.oversized_dropped(),
      1,
      "a normal message does not increment the oversized counter"
    );
    assert!(
      r.conn(c).unwrap().queued_outbound() > 0,
      "a normal message is queued on the still-open conn"
    );
  }
}

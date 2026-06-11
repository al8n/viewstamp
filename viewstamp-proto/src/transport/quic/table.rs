//! Connection table mapping peer identities to active QUIC connections.

use std::collections::HashMap;

use quinn_proto::ConnectionHandle;

use super::conn::ConnEntry;
use crate::Peer;

/// In-memory pool of active QUIC connections, keyed by `quinn_proto::ConnectionHandle`.
///
/// A secondary `by_peer` index lets the bridge look up the handle for a known peer in O(1).
/// `bind_peer` follows a last-established-wins policy so a reconnect silently displaces a
/// stale entry without leaking the old mapping.
pub(crate) struct ConnTable {
  conns: HashMap<ConnectionHandle, ConnEntry>,
  by_peer: HashMap<Peer, ConnectionHandle>,
  /// Strictly-increasing counter stamped onto each inserted [`ConnEntry::seq`] to give the table's
  /// connections a creation-recency order. Only ever incremented (never reset), so a `seq` uniquely and
  /// monotonically orders connections by creation even as `ConnectionHandle`s (slab indices) are reused
  /// across drains. The per-peer connection bound consults it to reap the OLDEST same-peer excess.
  next_seq: u64,
}

impl ConnTable {
  pub(crate) fn new() -> Self {
    Self {
      conns: HashMap::new(),
      by_peer: HashMap::new(),
      next_seq: 0,
    }
  }

  /// Inserts a freshly-created connection entry into the table, stamping it with the next monotonic
  /// recency [`seq`](ConnEntry::seq). This is the SINGLE insertion choke-point (both the dial and the
  /// accept path route here), so every live connection carries a unique, creation-ordered `seq` — what
  /// the per-peer connection bound uses to identify the oldest same-peer connections to reap.
  pub(crate) fn insert(&mut self, h: ConnectionHandle, mut entry: ConnEntry) {
    entry.seq = self.next_seq;
    self.next_seq += 1;
    self.conns.insert(h, entry);
  }

  /// Returns a mutable reference to the entry for `h`, if present.
  pub(crate) fn entry(&mut self, h: ConnectionHandle) -> Option<&mut ConnEntry> {
    self.conns.get_mut(&h)
  }

  /// Returns the handle bound to `p`, if any. The value is copied — the caller may mutate
  /// the table without borrow conflicts.
  pub(crate) fn handle_for(&self, p: Peer) -> Option<ConnectionHandle> {
    self.by_peer.get(&p).copied()
  }

  /// Every peer currently bound to a connection (the routing fan-out source).
  pub(crate) fn peers(&self) -> impl Iterator<Item = Peer> + '_ {
    self.by_peer.keys().copied()
  }

  /// Associates peer `p` with connection handle `h`. Last-established-wins: if `p` was previously
  /// bound to a different handle, the old mapping is silently replaced.
  /// Also sets `entry.peer` so the entry and the index stay consistent.
  ///
  /// The previously-bound connection is NOT torn down: under this transport's mutual-dial design a peer
  /// legitimately holds TWO physical connections (each side dials the other, and `p` validates on both),
  /// and both deliver `p`'s inbound frames — only the OUTBOUND routing target (`by_peer[p]`) moves to
  /// `h`. A truly stale connection is reaped by its own lifecycle (idle-timeout `ConnectionLost`, or the
  /// auth-deadline reap) rather than on rebind.
  pub(crate) fn bind_peer(&mut self, h: ConnectionHandle, p: Peer) {
    self.by_peer.insert(p, h);
    if let Some(entry) = self.conns.get_mut(&h) {
      entry.peer = Some(p);
    }
  }

  /// The OLDEST live same-peer connections to reap so that at most `limit` connections for peer `p`
  /// remain — the per-peer bound that keeps a flapping/crash-looping valid member from accumulating
  /// UNBOUNDED same-peer connections and exhausting the global connection cap.
  ///
  /// `keep` is the just-validated handle the caller is binding as canonical: it is EXCLUDED from the
  /// candidate set so it can never be reaped, even when it is the oldest by [`seq`](ConnEntry::seq).
  /// Insertion recency (`seq`) is NOT validation recency: a connection inserted EARLY can validate LATE
  /// (a slow/split Hello arriving just before the auth deadline while newer reconnects already validated),
  /// so the just-bound connection may legitimately hold the smallest `seq`. Reaping it would tear down the
  /// just-canonical connection and — since `bind_peer` already pointed the routing slot at it — drop the
  /// peer's outbound routing while other live same-peer connections remain. Excluding it makes the kept
  /// set `keep` + the (`limit - 1`) newest OTHERS — which include the mutual-dial sibling, so the
  /// steady-state pair survives by construction.
  ///
  /// Counts only NON-`Closed` same-peer entries other than `keep` (a `Closed` entry is already draining
  /// out). Returns the oldest excess (smallest `seq`) when that count exceeds `limit - 1`, else an empty
  /// vec (the common within-bound case).
  pub(crate) fn excess_peer_conns(
    &self,
    p: Peer,
    keep: ConnectionHandle,
    limit: usize,
  ) -> Vec<ConnectionHandle> {
    let mut live: Vec<(u64, ConnectionHandle)> = self
      .conns
      .iter()
      .filter(|(h, e)| **h != keep && e.peer == Some(p) && !e.phase.is_closed())
      .map(|(h, e)| (e.seq, *h))
      .collect();
    // `keep` is always retained, so the OTHERS may fill at most `limit - 1` slots. A `limit` of 0 is not
    // used (`PER_PEER_CONN_LIMIT >= 1`), so `limit - 1` never underflows in practice; guard anyway.
    let others_budget = limit.saturating_sub(1);
    if live.len() <= others_budget {
      return Vec::new();
    }
    // Oldest first (ascending `seq`); drop the `others_budget` newest from the tail, return the rest.
    live.sort_unstable_by_key(|(seq, _)| *seq);
    live.truncate(live.len() - others_budget);
    live.into_iter().map(|(_, h)| h).collect()
  }

  /// The TABLE-owned half of the validate transition: bind peer `p`'s canonical routing slot to the
  /// just-validated handle `h` (last-established-wins) and SELECT the oldest same-peer excess to reap so
  /// that, once the caller closes them, at most `limit` live connections remain for `p`. Returns the
  /// excess handles (oldest-first, EXCLUDING `h`) for the caller to tear down through its close
  /// choke-point — the table never issues a quinn `close` itself.
  ///
  /// This groups the two coupled table mutations — [`Self::bind_peer`] and the [`Self::excess_peer_conns`]
  /// selection — so their joint postcondition is asserted in one place. The third routing step,
  /// [`Self::promote_routing_if_unbound`], stays at the CALLER (run AFTER it closes the returned excess),
  /// since it can only assert against the POST-close routing state this pre-close method cannot see. So
  /// this asserts only `I1` (the slot points at the live `h`) and `I3` selection soundness; the caller
  /// asserts the joint `I2`/[`Self::routing_is_live`] post-close. The `debug_assert!`s are a by-construction
  /// tripwire, no behaviour change.
  pub(crate) fn validate_routing(
    &mut self,
    h: ConnectionHandle,
    p: Peer,
    limit: usize,
  ) -> Vec<ConnectionHandle> {
    self.bind_peer(h, p);
    // I1: the slot now points at `h`, which is a live entry bound to `p`. (`bind_peer` set both halves;
    // `h` is the just-validated connection, so it is neither `Closed` nor bound to another peer.)
    debug_assert!(
      self.by_peer.get(&p).copied() == Some(h)
        && self
          .conns
          .get(&h)
          .is_some_and(|e| e.peer == Some(p) && !e.phase.is_closed()),
      "validate_routing: by_peer[p] must point at the just-bound live handle h"
    );
    let excess = self.excess_peer_conns(p, h, limit);
    // I3 (selection soundness): the returned excess never includes `h`, and closing exactly those brings
    // the live same-peer count within `limit`. `excess_peer_conns` counts the SAME live set, so
    // subtracting the count it selected is its by-construction postcondition. Asserted here pre-close;
    // the bridge asserts the realized `live_peer_count(p) <= limit` AFTER it closes them.
    debug_assert!(
      !excess.contains(&h),
      "validate_routing: the just-bound handle is never selected for reaping"
    );
    debug_assert!(
      self.live_peer_count(p).saturating_sub(excess.len()) <= limit,
      "validate_routing: closing the selected excess must leave peer p within its per-peer limit"
    );
    excess
  }

  /// Re-point peer `p`'s routing slot at its NEWEST live (non-`Closed`) connection when the slot is
  /// currently UNBOUND but such a connection still exists — the defensive backstop that keeps a per-peer
  /// reap from ever leaving a peer with live connections but no `by_peer` entry.
  ///
  /// A no-op when the slot is already bound (the common case: the just-bound canonical handle is
  /// excluded from the reap, so its binding survives) or when no live same-peer connection remains
  /// (nothing to route to). Promotes the highest-[`seq`](ConnEntry::seq) live same-peer handle, matching
  /// the last-established-wins routing policy.
  pub(crate) fn promote_routing_if_unbound(&mut self, p: Peer) {
    if self.by_peer.contains_key(&p) {
      return;
    }
    let newest = self
      .conns
      .iter()
      .filter(|(_, e)| e.peer == Some(p) && !e.phase.is_closed())
      .max_by_key(|(_, e)| e.seq)
      .map(|(h, _)| *h);
    if let Some(h) = newest {
      self.by_peer.insert(p, h);
    }
  }

  /// Whether peer `p`'s routing is consistent: the secondary `by_peer` index agrees with the primary
  /// `conns` map. This is the JOINT routing invariant the lifecycle couples:
  ///
  /// - `I1`: if `by_peer[p]` is present it points at a non-`Closed` entry whose `peer == Some(p)` — no
  ///   slot dangles at a reaped/foreign connection.
  /// - `I2`: if ANY live (non-`Closed`) same-peer entry exists, `by_peer[p]` is present — a peer with
  ///   live connections is never left unrouteable.
  ///
  /// Which live connection the present slot points at is the LAST-ESTABLISHED-WINS choice
  /// ([`Self::bind_peer`] binds the most-recently-VALIDATED handle), NOT necessarily the highest-`seq`
  /// one: under reconnect churn the most-recently-validated connection can be the OLDEST by creation
  /// `seq` (a slow/split Hello that validates late), so this predicate must NOT demand the newest-`seq`
  /// target — that would wrongly trip on the legitimate delayed-validation routing state. The narrower
  /// "promote picks the newest" guarantee belongs to [`Self::promote_routing_if_unbound`] (which only
  /// re-points an UNBOUND slot), not to this joint invariant.
  ///
  /// A read-only predicate the validate transition `debug_assert!`s as its routing postcondition,
  /// encoding a guarantee the table's mutators already uphold — a by-construction tripwire, no behaviour.
  #[cfg_attr(not(debug_assertions), allow(dead_code))]
  pub(crate) fn routing_is_live(&self, p: Peer) -> bool {
    let any_live = self
      .conns
      .values()
      .any(|e| e.peer == Some(p) && !e.phase.is_closed());
    match self.by_peer.get(&p).copied() {
      // I1: a present slot must point at a live entry bound to `p`.
      Some(bound) => self
        .conns
        .get(&bound)
        .is_some_and(|e| e.peer == Some(p) && !e.phase.is_closed()),
      // I2: an absent slot is only consistent when NO live same-peer entry exists.
      None => !any_live,
    }
  }

  /// The number of live (non-`Closed`) connections currently bound to peer `p`. The per-peer connection
  /// bound (`I3`: at most [`PER_PEER_CONN_LIMIT`](super::bridge::PER_PEER_CONN_LIMIT) live connections
  /// per peer) is `debug_assert!`ed against this after the validate transition's reap. A `Closed` entry
  /// (already draining out) is excluded, matching `excess_peer_conns`'s live count.
  #[cfg_attr(not(debug_assertions), allow(dead_code))]
  pub(crate) fn live_peer_count(&self, p: Peer) -> usize {
    self
      .conns
      .values()
      .filter(|e| e.peer == Some(p) && !e.phase.is_closed())
      .count()
  }

  /// Removes the connection entry for `h` and clears its `by_peer` slot — but only when
  /// the slot still points at `h`. A race where `bind_peer` already re-bound the peer to a
  /// newer handle leaves the peer index intact.
  pub(crate) fn remove(&mut self, h: ConnectionHandle) {
    if let Some(entry) = self.conns.remove(&h)
      && let Some(p) = entry.peer
      && self.by_peer.get(&p).copied() == Some(h)
    {
      self.by_peer.remove(&p);
    }
  }

  /// Clears `h`'s `by_peer` routing slot (when it still points at `h`) but KEEPS the connection entry
  /// in the table. Used when a connection is closed/lost: routing to its peer must stop AT ONCE, but
  /// the quinn `Connection` is retained so the service pump can drive it to `Drained` — the point at
  /// which the endpoint frees its slab slot and the entry is finally removed. Dropping the entry here
  /// instead would discard the `Connection` before it ever emits `Drained`, permanently leaking the
  /// endpoint-owned slab + CID/reset-token state.
  pub(crate) fn unbind(&mut self, h: ConnectionHandle) {
    if let Some(entry) = self.conns.get(&h)
      && let Some(p) = entry.peer
      && self.by_peer.get(&p).copied() == Some(h)
    {
      self.by_peer.remove(&p);
    }
  }

  /// Iterates mutably over all `(handle, entry)` pairs. Used by the bridge's test helpers to scan
  /// for a validated connection; no production caller needs whole-table iteration.
  #[cfg_attr(not(test), allow(dead_code))]
  pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (&ConnectionHandle, &mut ConnEntry)> {
    self.conns.iter_mut()
  }

  /// Snapshot of every live connection handle. Collected into an owned `Vec` so
  /// the bridge's service pump can iterate handles while taking a disjoint
  /// `&mut` borrow of an individual entry inside the loop (the per-handle
  /// `entry(h)` borrow would otherwise conflict with an iterator that holds the
  /// whole map borrowed).
  pub(crate) fn handles(&self) -> Vec<ConnectionHandle> {
    self.conns.keys().copied().collect()
  }

  /// The number of live connection entries (dialed + accepted). The bridge consults this against its
  /// connection cap before accepting an inbound attempt.
  pub(crate) fn len(&self) -> usize {
    self.conns.len()
  }

  /// The earliest `Connection::poll_timeout()` across all entries, or `None`
  /// when no connection currently has an armed timer. Takes `&mut self` because
  /// quinn-proto's `Connection::poll_timeout` requires `&mut`.
  pub(crate) fn min_conn_timeout(&mut self) -> Option<std::time::Instant> {
    self
      .conns
      .values_mut()
      .filter_map(|e| e.conn.poll_timeout())
      .min()
  }

  /// The earliest [`ConnEntry::auth_deadline`] across the connections still in [`Phase::Authenticating`],
  /// or `None` when none is pending. The bridge folds this into its `poll_timeout` so a sleeping driver
  /// wakes to reap a connection that authenticated but never validated.
  ///
  /// The phase filter is load-bearing, not a cleanliness nicety: an auth deadline is only relevant
  /// WHILE a connection is authenticating. A `Closed` (reaped) or `Validated` entry's deadline — which
  /// the reap leaves in the PAST — must never contribute, or `poll_timeout` would keep reporting that
  /// past instant; a `poll_timeout`-driven driver does `now = now.max(deadline)`, and a past deadline
  /// does not advance the clock, so it would never reach quinn's future close/drain timer and the
  /// reaped connection would never drain (its slab + cap slot leaking until unrelated traffic moved the
  /// clock). Scoping the fold-in to `is_authenticating()` entries makes a stale deadline structurally
  /// unable to stall the drain. (The bridge ALSO clears the deadline on leaving `Authenticating`, so
  /// no stale value exists in the first place — this filter is the by-construction backstop.)
  pub(crate) fn earliest_auth_deadline(&self) -> Option<std::time::Instant> {
    self
      .conns
      .values()
      .filter(|e| e.phase.is_authenticating())
      .filter_map(|e| e.auth_deadline)
      .min()
  }
}

#[cfg(test)]
mod tests {
  use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Instant,
  };

  use quinn_proto::Endpoint;

  use super::*;
  use crate::{Peer, ReplicaId, transport::quic::crypto::QuicOptions};

  /// Builds a quinn-proto `Endpoint` from `QuicOptions::accept_any_for_test()` and returns it
  /// together with the client config so tests can dial two connections on the same endpoint
  /// (and thus get distinct `ConnectionHandle` values).
  fn make_endpoint() -> (Endpoint, quinn_proto::ClientConfig) {
    let opts = QuicOptions::accept_any_for_test();
    let ep = Endpoint::new(
      opts.endpoint_config(),
      opts.server_config(),
      /*allow_mtud=*/ false,
      /*rng_seed=*/ None,
    );
    let client_cfg = opts
      .client_config()
      .expect("accept_any_for_test provides a client config");
    (ep, client_cfg)
  }

  /// Dials a connection on `ep` to a dummy address and wraps it in a `ConnEntry`.
  fn dial(
    ep: &mut Endpoint,
    cfg: quinn_proto::ClientConfig,
    port: u16,
  ) -> (ConnectionHandle, ConnEntry) {
    let remote: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port));
    let (h, conn) = ep
      .connect(Instant::now(), cfg, remote, "viewstamp.local")
      .expect("connect on a fresh endpoint must succeed");
    (
      h,
      ConnEntry::new(
        conn,
        None,
        crate::transport::quic::layout::StreamLayout::default(),
      ),
    )
  }

  #[test]
  fn peer_index_is_none_before_bind_and_some_after() {
    let (mut ep, cfg) = make_endpoint();
    let mut table = ConnTable::new();
    let (h, entry) = dial(&mut ep, cfg, 4433);
    let peer = Peer::Replica(ReplicaId::new(0));

    table.insert(h, entry);
    assert_eq!(table.handle_for(peer), None, "no binding yet");

    table.bind_peer(h, peer);
    assert_eq!(table.handle_for(peer), Some(h), "bound after bind_peer");

    // entry.peer must also be set
    assert_eq!(
      table.entry(h).and_then(|e| e.peer),
      Some(peer),
      "entry.peer set by bind_peer"
    );
  }

  #[test]
  fn remove_clears_both_maps() {
    let (mut ep, cfg) = make_endpoint();
    let mut table = ConnTable::new();
    let (h, entry) = dial(&mut ep, cfg, 4433);
    let peer = Peer::Replica(ReplicaId::new(1));

    table.insert(h, entry);
    table.bind_peer(h, peer);
    assert_eq!(table.handle_for(peer), Some(h));

    table.remove(h);
    assert!(table.entry(h).is_none(), "entry removed");
    assert_eq!(table.handle_for(peer), None, "by_peer cleared");
  }

  #[test]
  fn remove_does_not_clobber_rebound_peer() {
    let (mut ep, cfg1) = make_endpoint();
    // Clone the QuicOptions to get a second client config from the same endpoint.
    let cfg2 = QuicOptions::accept_any_for_test()
      .client_config()
      .expect("client config");

    let mut table = ConnTable::new();
    // Dial two connections on the same endpoint — they get distinct handles.
    let (h1, entry1) = dial(&mut ep, cfg1, 4433);
    let (h2, entry2) = dial(&mut ep, cfg2, 4434);
    assert_ne!(
      h1, h2,
      "two dials on the same endpoint must yield distinct handles"
    );

    let peer = Peer::Replica(ReplicaId::new(2));

    table.insert(h1, entry1);
    table.insert(h2, entry2);
    table.bind_peer(h1, peer);
    // Re-bind the peer to a newer connection (last-established-wins).
    table.bind_peer(h2, peer);
    assert_eq!(table.handle_for(peer), Some(h2));

    // Removing the OLD handle must NOT clear the peer→h2 mapping.
    table.remove(h1);
    assert_eq!(
      table.handle_for(peer),
      Some(h2),
      "by_peer not clobbered by removing old handle"
    );
  }

  /// Dial `n` distinct connections on `ep`, insert each (so the table stamps a monotonic `seq` in
  /// dial order), bind them all to `peer`, and force each entry to `Validated`. Returns the handles in
  /// creation order (oldest first), so a test can name which the per-peer reap must keep vs drop.
  fn insert_validated_for(
    ep: &mut Endpoint,
    table: &mut ConnTable,
    peer: Peer,
    base_port: u16,
    n: usize,
  ) -> Vec<ConnectionHandle> {
    let mut handles = Vec::new();
    for i in 0..n {
      let cfg = QuicOptions::accept_any_for_test()
        .client_config()
        .expect("client config");
      let (h, entry) = dial(ep, cfg, base_port + i as u16);
      table.insert(h, entry);
      table.bind_peer(h, peer);
      table.entry(h).expect("just inserted").phase = super::super::conn::Phase::Validated;
      handles.push(h);
    }
    handles
  }

  /// The per-peer connection bound's selection: `excess_peer_conns` returns the OLDEST live same-peer
  /// connections beyond the limit (keeping the `limit` newest), ALWAYS retains the `keep` handle, and
  /// excludes `Closed` entries. The kept set is `keep` + the `limit - 1` newest others, so the
  /// steady-state mutual-dial pair the limit preserves is never reaped.
  #[test]
  fn excess_peer_conns_reaps_oldest_beyond_the_limit_and_keeps_the_newest() {
    let (mut ep, _cfg) = make_endpoint();
    let mut table = ConnTable::new();
    let peer = Peer::Replica(ReplicaId::new(1));
    let other = Peer::Replica(ReplicaId::new(2));

    // A different peer's connection must never be a candidate for `peer`'s reap (slot isolation).
    let other_handles = insert_validated_for(&mut ep, &mut table, other, 5500, 2);

    // Five same-peer connections (h0 oldest … h4 newest, by insertion/seq order).
    let h = insert_validated_for(&mut ep, &mut table, peer, 5600, 5);

    // Within bound: a peer with exactly `limit` connections has nothing to reap (keep = the newest, the
    // common case where the just-bound is the most recent).
    assert!(
      table.excess_peer_conns(peer, h[4], 5).is_empty(),
      "at exactly the limit there is no excess"
    );
    assert!(
      table.excess_peer_conns(peer, h[4], 6).is_empty(),
      "under the limit there is no excess"
    );

    // Over bound with limit=3 (the production PER_PEER_CONN_LIMIT), keep = h4 (newest): the two OLDEST
    // (h0, h1) are returned oldest-first; the three NEWEST (h2, h3, h4 — which include the just-bound +
    // its mutual-dial sibling) are kept.
    let excess = table.excess_peer_conns(peer, h[4], 3);
    assert_eq!(
      excess,
      std::vec![h[0], h[1]],
      "the two oldest are reaped, in order"
    );
    assert!(
      !excess.contains(&h[4]) && !excess.contains(&h[3]) && !excess.contains(&h[2]),
      "the three newest same-peer connections (the kept limit) are never reaped"
    );

    // DELAYED VALIDATION: keep = h0 (the OLDEST by seq — a slow/split Hello that validated LATE). The
    // just-bound handle must be EXCLUDED however old it is, so it is never returned; the reap then drops
    // the oldest of the OTHERS (h1, h2 — the two oldest remaining once h0 is kept) and keeps h0 + the two
    // newest others (h3, h4).
    let excess_old = table.excess_peer_conns(peer, h[0], 3);
    assert!(
      !excess_old.contains(&h[0]),
      "the just-bound handle is never reaped even when it is the oldest by seq"
    );
    assert_eq!(
      excess_old,
      std::vec![h[1], h[2]],
      "with keep=h0 the oldest OTHERS (h1, h2) are reaped, h0 + the two newest others survive"
    );

    // The OTHER peer's connections are never named, whatever `peer`'s excess is.
    for oh in &other_handles {
      assert!(
        !excess.contains(oh),
        "a different peer's connection must not be reaped to bound this peer"
      );
    }
    assert!(
      table.excess_peer_conns(other, other_handles[1], 1).len() == 1,
      "the other peer is bounded independently (2 conns, keep the newest, limit 1 → 1 excess)"
    );

    // A `Closed` entry is excluded from BOTH the count and the result: closing the two oldest drops the
    // live same-peer count to 3 == limit, so nothing more is reaped (no double-reap of a draining conn).
    for &c in &excess {
      table.entry(c).expect("entry").phase = super::super::conn::Phase::Closed;
    }
    assert!(
      table.excess_peer_conns(peer, h[4], 3).is_empty(),
      "Closed connections are not counted (live count is back to the limit) and are never re-reaped"
    );
  }

  /// `promote_routing_if_unbound` re-points a peer's routing slot at its NEWEST live connection when the
  /// slot is unbound but a live same-peer connection still exists — and is a no-op when the slot is
  /// already bound or no live connection remains.
  #[test]
  fn promote_routing_rebinds_newest_live_when_slot_unbound() {
    let (mut ep, _cfg) = make_endpoint();
    let mut table = ConnTable::new();
    let peer = Peer::Replica(ReplicaId::new(1));

    // Three same-peer connections (h0 oldest … h2 newest). `insert_validated_for` binds each, so the slot
    // currently points at the last-bound h2.
    let h = insert_validated_for(&mut ep, &mut table, peer, 5700, 3);
    assert_eq!(table.handle_for(peer), Some(h[2]), "last-bound is routed");
    // The joint routing invariant holds in the steady state: the slot points at the newest live one (h2).
    assert!(
      table.routing_is_live(peer),
      "routing_is_live: bound to the newest live same-peer connection"
    );
    assert_eq!(table.live_peer_count(peer), 3, "three live same-peer conns");

    // Already-bound: a no-op (the slot is not disturbed).
    table.promote_routing_if_unbound(peer);
    assert_eq!(
      table.handle_for(peer),
      Some(h[2]),
      "an already-bound slot is left untouched"
    );

    // Simulate a reap that cleared the routing slot (e.g. the bound target was closed + unbound) while
    // older live same-peer connections remain. Promotion must re-point at the NEWEST remaining live one.
    table.entry(h[2]).expect("entry").phase = super::super::conn::Phase::Closed;
    table.unbind(h[2]);
    assert_eq!(table.handle_for(peer), None, "slot cleared by the unbind");
    table.promote_routing_if_unbound(peer);
    assert_eq!(
      table.handle_for(peer),
      Some(h[1]),
      "the newest remaining LIVE same-peer connection (h1) is promoted into the routing slot"
    );
    // After the close+unbind+promote, the joint routing invariant is restored: the slot is bound to the
    // newest REMAINING live one (h1), and the closed h2 no longer counts toward the live total.
    assert!(
      table.routing_is_live(peer),
      "routing_is_live: re-pointed at the newest remaining live connection after a reap"
    );
    assert_eq!(
      table.live_peer_count(peer),
      2,
      "the Closed h2 is excluded from the live count"
    );

    // No live connection remains: promotion does nothing (the slot stays empty).
    let mut empty = ConnTable::new();
    let lonely = Peer::Replica(ReplicaId::new(9));
    empty.promote_routing_if_unbound(lonely);
    assert_eq!(
      empty.handle_for(lonely),
      None,
      "with no live same-peer connection the slot stays unbound"
    );
    // No slot + no live entry is the vacuously-live routing state.
    assert!(
      empty.routing_is_live(lonely),
      "routing_is_live: an unbound peer with no live connection is vacuously live"
    );
    assert_eq!(empty.live_peer_count(lonely), 0, "no live connections");
  }

  /// `validate_routing` composes the table-owned validate steps exactly as the bridge sequences them:
  /// bind the just-validated handle as canonical, then select the oldest same-peer excess to reap. The
  /// DELAYED-validation case — the OLDEST-by-`seq` handle validates late — is the one a reorder broke:
  /// the just-bound handle must be excluded from the reap however old it is, the slot must point at it,
  /// and after the caller closes the selected excess and runs the post-close `promote_routing_if_unbound`
  /// the joint routing invariant (`routing_is_live`) must hold with the live count at the limit. This
  /// mirrors the bridge's `delayed_validation_…_keeps_routing_live` at the table level.
  #[test]
  fn validate_routing_keeps_routing_live_on_delayed_validation() {
    let (mut ep, _cfg) = make_endpoint();
    let mut table = ConnTable::new();
    let peer = Peer::Replica(ReplicaId::new(1));

    // Five same-peer connections (h0 oldest … h4 newest by insertion/seq). `insert_validated_for` binds
    // each, so the slot currently points at the last-bound h4.
    let h = insert_validated_for(&mut ep, &mut table, peer, 5800, 5);

    // DELAYED VALIDATION: h0 (the OLDEST) validates last. Binding it canonical points the slot at h0 and
    // selects the oldest OTHERS to reap (h1, h2 — keeping h0 + the two newest others h3, h4 under limit 3).
    let excess = table.validate_routing(h[0], peer, 3);
    assert_eq!(
      table.handle_for(peer),
      Some(h[0]),
      "the just-validated handle becomes the canonical routing target"
    );
    assert_eq!(
      excess,
      std::vec![h[1], h[2]],
      "with keep=h0 the oldest OTHERS (h1, h2) are selected oldest-first; h0 + the two newest survive"
    );
    assert!(
      !excess.contains(&h[0]),
      "the just-bound handle is never selected even when it is the oldest by seq"
    );

    // Simulate the caller's teardown: close (mark Closed) + unbind each selected excess, then run the
    // post-close promote the bridge runs. The slot already points at the live h0, so promote is a no-op.
    for &c in &excess {
      table.entry(c).expect("entry").phase = super::super::conn::Phase::Closed;
      table.unbind(c);
    }
    table.promote_routing_if_unbound(peer);

    // The joint routing invariant holds post-close: the slot points at the live (just-validated) h0 —
    // last-established-wins, NOT the newest by seq — and no live same-peer entry is left unrouteable.
    assert!(
      table.routing_is_live(peer),
      "routing_is_live: slot points at the live just-validated handle, no live entry left unrouteable"
    );
    assert_eq!(
      table.live_peer_count(peer),
      3,
      "the per-peer live count settles at the limit (the two oldest others are Closed)"
    );
  }

  /// Property test: across a randomized sequence of validate / close transitions over several peers, the
  /// table's routing invariants hold at EVERY checkpoint. Each iteration applies one transition and then
  /// asserts the joint routing invariant ([`ConnTable::routing_is_live`], I1 + I2) and the per-peer bound
  /// ([`ConnTable::live_peer_count`] <= the limit, I3) for the peer it touched — and I3 for ALL peers,
  /// since it is a global per-peer bound. The two transitions mirror exactly what the bridge does:
  ///
  /// - VALIDATE a fresh same-peer connection: insert (stamping the next `seq`), then `validate_routing`
  ///   (bind canonical + select the oldest excess), mark the new handle `Validated`, close the selected
  ///   excess (mark `Closed` + unbind, as `close_local` does to the table), then the post-close promote.
  /// - LOSE the currently-routed connection and re-point: mark it `Closed` + unbind (as a peer-initiated
  ///   loss / local close does), then promote the newest remaining live same-peer handle.
  ///
  /// A reorder that broke the coupling — promoting before the close, reaping the just-bound handle, not
  /// promoting after a close — would leave a checkpoint with a dangling slot or a live-but-unrouteable
  /// peer, tripping `routing_is_live`. The sequence is seeded so a failure reproduces deterministically.
  #[test]
  fn routing_invariants_hold_across_random_validate_and_close_sequences() {
    use crate::Prng;

    // Mirrors `super::super::bridge::PER_PEER_CONN_LIMIT` (private to that module); kept in sync here so
    // the table-level property exercises the same bound the bridge passes to `validate_routing`.
    const LIMIT: usize = 3;

    let (mut ep, _cfg) = make_endpoint();
    let mut table = ConnTable::new();
    let peers = [
      Peer::Replica(ReplicaId::new(0)),
      Peer::Replica(ReplicaId::new(1)),
      Peer::Replica(ReplicaId::new(2)),
    ];

    let mut prng = Prng::new(0x00C0_FFEE_1234_5678);
    let mut port: u16 = 6000;

    for _ in 0..600 {
      let peer = peers[prng.below(peers.len() as u64) as usize];

      // 2/3 of the time validate a fresh connection (drives growth + the reap); 1/3 lose the routed one.
      if prng.chance(2, 3) {
        let cfg = QuicOptions::accept_any_for_test()
          .client_config()
          .expect("client config");
        let (h, entry) = dial(&mut ep, cfg, port);
        port = port.wrapping_add(1);
        table.insert(h, entry);

        // The TABLE half of the validate transition, sequenced exactly as `bind_validated` runs it.
        let excess = table.validate_routing(h, peer, LIMIT);
        table.entry(h).expect("just inserted").phase = super::super::conn::Phase::Validated;
        for c in excess {
          // `close_local`'s table effect: mark Closed + unbind (the entry is kept for the drain).
          if let Some(e) = table.entry(c) {
            e.phase = super::super::conn::Phase::Closed;
          }
          table.unbind(c);
        }
        table.promote_routing_if_unbound(peer);
      } else if let Some(routed) = table.handle_for(peer) {
        // Lose the routed connection, then re-point at the newest remaining live same-peer handle —
        // exactly the close + promote the lifecycle performs.
        if let Some(e) = table.entry(routed) {
          e.phase = super::super::conn::Phase::Closed;
        }
        table.unbind(routed);
        table.promote_routing_if_unbound(peer);
      }

      // Checkpoint: routing is consistent for the touched peer, and EVERY peer is within its bound.
      assert!(
        table.routing_is_live(peer),
        "routing_is_live must hold after every validate/close+promote transition"
      );
      for &p in &peers {
        assert!(
          table.live_peer_count(p) <= LIMIT,
          "the per-peer live connection count must stay within the limit for every peer"
        );
        // I1 holds for every peer too: a present slot never dangles at a reaped/foreign entry.
        assert!(
          table.routing_is_live(p) || table.handle_for(p).is_none(),
          "a present routing slot never points at a Closed/foreign entry (I1)"
        );
      }
    }
  }
}

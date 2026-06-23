//! Connection table mapping peer identities to active QUIC connections.

use std::collections::HashMap;

use quinn_proto::ConnectionHandle;

use super::conn::ConnEntry;
use crate::{MemberId, Peer};

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

  /// Snapshot of every VALIDATED connection that has an attested member id, as
  /// `(handle, attested member, bound routing peer)`. The membership-reconcile pass iterates this to
  /// re-resolve each connection's stable member against the new membership; collected owned so the
  /// caller can take a disjoint per-handle borrow (a `close_local`) inside the loop. Every connection
  /// the mutual-dial pair holds for a member is included (not just the authoritative one), so a
  /// removed/shifted member's stale connections are ALL closed, not only its routing target.
  pub(crate) fn validated_member_conns(&self) -> Vec<(ConnectionHandle, MemberId, Peer)> {
    self
      .conns
      .iter()
      .filter(|(_, e)| e.phase.is_validated())
      .filter_map(|(h, e)| Some((*h, e.member?, e.peer?)))
      .collect()
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
mod tests;

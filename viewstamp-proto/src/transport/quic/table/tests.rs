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

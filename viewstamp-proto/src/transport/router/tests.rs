use super::*;
use crate::{
  LabelOptions, Labeled, MemberId, Message, OpNumber, Peer, Recipient, ReplicaId, View,
  encode_message, message::Commit, transport::stream::RecordIo,
};

fn conn() -> Conn<crate::Passthrough> {
  Conn::from_parts(crate::Passthrough::new())
}

/// Registers a raw `Passthrough` conn and validates it. For `Peer::Replica` identities, uses
/// `note_established_member` (raw slot auto-validation is blocked at the router level); for all
/// other identities, `note_established` suffices (clients, Member-bearing conns).
fn established(r: &mut PeerRouter<crate::Passthrough>, identity: Peer) -> ConnId {
  let id = r.register_dialed(identity, conn());
  match identity {
    Peer::Replica(slot) => {
      r.note_established_member(id, crate::MemberId::new(slot.get() as u128), slot);
    }
    _ => {
      r.note_established(id);
    }
  }
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

/// Establishes an accepting `Labeled<Passthrough>` conn for `dialer_member` by feeding it the
/// dialer's hello, so it validates the remote, queues its own hello into the inner layer, and
/// becomes a routing target (bound to `Peer::Replica(slot)`) whose `buffered_outbound` already
/// holds the hello. Mirrors the production order — register the still-handshaking acceptor, drive
/// its handshake, THEN bind via `note_established_member` — so the register-time auto-establish
/// (which would adopt the raw `Peer::Member` handshake identity) is a no-op on the handshaking conn.
fn established_labeled(
  r: &mut PeerRouter<Labeled<crate::Passthrough>>,
  local_member: MemberId,
  dialer_member: MemberId,
) -> ConnId {
  let opts = LabelOptions::new(0xABCD, Peer::Member(local_member));
  let dialer_wire = {
    let mut dialer: Labeled<crate::Passthrough> = Labeled::dialer(
      crate::Passthrough::new(),
      &LabelOptions::new(0xABCD, Peer::Member(dialer_member)),
    );
    let mut wire = Vec::new();
    dialer.poll_transport_transmit(&mut wire);
    wire
  };
  let dialer_slot = ReplicaId::new(dialer_member.get() as u16);
  let conn = Conn::from_parts(Labeled::acceptor(crate::Passthrough::new(), &opts));
  let id = r.register_accepted(Peer::Replica(dialer_slot), conn);
  r.conn_mut(id)
    .unwrap()
    .handle_data(&dialer_wire, false, crate::Instant::ZERO)
    .unwrap();
  r.note_established_member(id, dialer_member, dialer_slot);
  id
}

#[test]
fn reconcile_closes_a_displaced_standby_by_id_so_it_cannot_be_promoted_stale() {
  // Two validated conns for the SAME member (MemberId 1, bound at slot 1): the second to establish
  // is authoritative, the first is a live STANDBY the last-established-wins rule displaced. This is
  // exactly the standby-promotion hazard the membership reconcile must defeat.
  let member = MemberId::new(1);
  let mut r = PeerRouter::<Labeled<crate::Passthrough>>::new();
  let standby = established_labeled(&mut r, MemberId::new(0), member);
  let authoritative = established_labeled(&mut r, MemberId::new(0), member);
  let slot1 = Peer::Replica(ReplicaId::new(1));
  assert_eq!(
    r.authoritative(slot1),
    Some(authoritative),
    "last-established wins; the first conn is a live standby"
  );

  // The reconcile snapshot walks EVERY validated conn (not just the authoritative one), so BOTH the
  // authoritative conn and the displaced standby appear — keyed by their conn id, with the member
  // and the slot they are currently bound to.
  let snapshot = r.validated_member_conns();
  assert_eq!(
    snapshot.len(),
    2,
    "both validated conns are in the snapshot"
  );
  assert!(
    snapshot
      .iter()
      .all(|(_, m, peer)| *m == member && *peer == slot1),
    "both conns carry the same attested member and current slot-1 binding"
  );

  // Drive the coordinator's reconcile decision: member 1 SHIFTED from slot 1 to slot 2. The
  // coordinator closes each conn whose bound slot != the member's new slot — BY ID, so the standby
  // is closed too, not just the authoritative conn.
  let new_slot = ReplicaId::new(2);
  for (id, _m, bound_peer) in snapshot {
    if Peer::Replica(new_slot) != bound_peer
      && let Some(conn) = r.conn_mut(id)
    {
      conn.abort(CloseCause::IdentityRejected);
    }
  }
  // The next pump reaps the closed conns. Because BOTH were closed, reap cannot promote the standby
  // back under the stale slot 1 — the bug a close-only-the-authoritative reconcile would leave open.
  r.reap_closed();
  assert!(
    r.conn(authoritative).is_none(),
    "the authoritative conn is closed and reaped"
  );
  assert!(
    r.conn(standby).is_none(),
    "the displaced standby is also closed and reaped — it cannot be promoted under the stale slot"
  );
  assert_eq!(
    r.authoritative(slot1),
    None,
    "no validated conn survives for the stale slot 1, so routing recovers (the member re-binds at \
     slot 2 on its next handshake)"
  );
}

#[test]
fn the_cap_accounts_for_the_queued_handshake_hello() {
  // The dialer attests `MemberId(1)`, which resolves to routing slot 1; the routing key the test
  // sends to is therefore `Peer::Replica(slot 1)`.
  let dialer_id = Peer::Replica(ReplicaId::new(1));
  // Probe the hello length and a single framed message length, then size a small cap so exactly
  // one application frame fits ALONGSIDE the queued hello.
  let hello_len = {
    let probe: Labeled<crate::Passthrough> = Labeled::dialer(
      crate::Passthrough::new(),
      &LabelOptions::new(0xABCD, Peer::Member(MemberId::new(0))),
    );
    probe.buffered_outbound()
  };
  let framed_len = {
    let mut framed = Vec::new();
    encode_frame(&encode_message(&commit_msg()), &mut framed);
    framed.len()
  };
  let cap = hello_len + framed_len;
  let mut r = PeerRouter::<Labeled<crate::Passthrough>>::with_outbound_cap(cap);
  let c = established_labeled(&mut r, MemberId::new(0), MemberId::new(1));
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
  // note_established adopts the handshake-authenticated identity for non-Replica peers (Replica
  // identities are deferred to note_established_member, so this test uses a Client identity).
  use crate::{ClientId, transport::testutil::MockRecords};
  let mut r = PeerRouter::<MockRecords>::new();
  let cid = ClientId::new(0xCAFE);
  let placeholder = Peer::Client(ClientId::new(0));
  let real = Peer::Client(cid);
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
  // The first conn is validated via note_established_member (Peer::Replica requires it); the
  // redial is still-handshaking, so it is registered but not yet authoritative while `old` is live.
  use crate::transport::testutil::MockRecords;
  let mut r = PeerRouter::<MockRecords>::new();
  let slot = ReplicaId::new(1);
  let peer = Peer::Replica(slot);
  let old = r.register_dialed(peer, Conn::from_parts(MockRecords::new(false, Some(peer))));
  r.note_established_member(old, crate::MemberId::new(1), slot);
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
    encode_frame(&encode_message(&commit_msg()), &mut framed);
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

/// Registers a `MockRecords` conn validated for `identity`. For `Peer::Replica` identities,
/// uses `note_established_member` (raw slot auto-validation is blocked at the router level);
/// other identities go through `note_established`. Settable write cap drives the short-write path.
fn established_mock(
  r: &mut PeerRouter<crate::transport::testutil::MockRecords>,
  identity: Peer,
  write_cap: usize,
) -> ConnId {
  use crate::transport::testutil::MockRecords;
  let records = MockRecords::new(false, Some(identity)).with_write_cap(write_cap);
  let id = r.register_dialed(identity, Conn::from_parts(records));
  match identity {
    Peer::Replica(slot) => {
      r.note_established_member(id, crate::MemberId::new(slot.get() as u128), slot);
    }
    _ => {
      r.note_established(id);
    }
  }
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
  // MAX_FRAME_LEN. Only ONE such message is allocated, and the preflight is asserted via the cheap
  // wire_size_bound() — the ADMISSION gate `route()` actually checks, BEFORE building the pb view
  // or encoding — so no second 16 MiB copy is made.
  let mut r = PeerRouter::<crate::Passthrough>::new();
  let peer = Peer::Replica(ReplicaId::new(1));
  let c = established(&mut r, peer);
  let body = bytes::Bytes::from(std::vec![0u8; MAX_FRAME_LEN as usize]);
  let huge = Message::Request(Request::new(ClientId::new(1), RequestNumber::with(1), body));
  assert!(
    huge.wire_size_bound() > MAX_FRAME_LEN as usize,
    "the crafted message's wire_size_bound() exceeds the frame cap (checked without encoding)"
  );
  assert!(
    huge.encoded_len() > MAX_FRAME_LEN as usize,
    "the crafted message's encoded length also exceeds the frame cap (sanity check)"
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

#[test]
fn conn_id_new_wraps_a_raw_handle() {
  let id = ConnId::new(42);
  assert_eq!(id.get(), 42, "new/get round-trip the raw handle value");
}

#[test]
fn default_router_starts_with_no_conns() {
  let r: PeerRouter<crate::Passthrough> = Default::default();
  assert!(
    r.ids().is_empty(),
    "a Default-built router starts with no conns, same as new()"
  );
  assert_eq!(r.oversized_dropped(), 0);
}

#[test]
fn bound_replica_slots_lists_only_established_replica_peers() {
  use crate::ClientId;
  let mut r = PeerRouter::<crate::Passthrough>::new();
  let _p0 = established(&mut r, Peer::Replica(ReplicaId::new(0)));
  let _p2 = established(&mut r, Peer::Replica(ReplicaId::new(2)));
  // A validated Client conn is bound too, but must not appear among the replica slots.
  r.register_dialed(Peer::Client(ClientId::new(9)), conn());
  let mut slots = r.bound_replica_slots();
  slots.sort();
  assert_eq!(
    slots,
    std::vec![ReplicaId::new(0), ReplicaId::new(2)],
    "bound_replica_slots lists exactly the established replica slots, excluding a client peer"
  );
}

#[test]
fn note_established_on_an_unknown_id_is_a_no_op() {
  let mut r = PeerRouter::<crate::Passthrough>::new();
  r.note_established(ConnId::new(999));
  assert!(
    r.ids().is_empty(),
    "an unknown id creates no conn and installs no routing entry"
  );
}

#[test]
fn note_established_member_on_an_unknown_id_is_a_no_op() {
  let mut r = PeerRouter::<crate::Passthrough>::new();
  r.note_established_member(ConnId::new(999), MemberId::new(1), ReplicaId::new(1));
  assert_eq!(
    r.authoritative(Peer::Replica(ReplicaId::new(1))),
    None,
    "an unknown id installs no routing entry"
  );
}

#[test]
fn note_established_member_is_a_no_op_once_the_conn_is_already_closed() {
  let mut r = PeerRouter::<crate::Passthrough>::new();
  let peer = Peer::Replica(ReplicaId::new(1));
  let id = r.register_dialed(peer, conn());
  r.conn_mut(id).unwrap().mark_closed_for_test();
  r.note_established_member(id, MemberId::new(1), ReplicaId::new(1));
  assert_eq!(
    r.authoritative(peer),
    None,
    "a closed conn is never validated by note_established_member"
  );
  assert!(
    r.conn(id).unwrap().is_closed(),
    "the conn stays closed, untouched by the no-op"
  );
}

#[test]
fn note_established_member_aborts_a_dialed_conn_that_settles_as_a_different_slot() {
  let mut r = PeerRouter::<crate::Passthrough>::new();
  let dialed_slot = ReplicaId::new(1);
  let resolved_slot = ReplicaId::new(2);
  let id = r.register_dialed(Peer::Replica(dialed_slot), conn());
  r.note_established_member(id, MemberId::new(2), resolved_slot);
  assert!(
    r.conn(id).unwrap().is_closed(),
    "a dialed conn that settles as a DIFFERENT slot than it dialed is aborted"
  );
  assert_eq!(
    r.authoritative(Peer::Replica(resolved_slot)),
    None,
    "the mismatched conn is never installed as authoritative"
  );
}

#[test]
fn route_skips_a_conn_closed_before_it_is_reaped() {
  let mut r = PeerRouter::<crate::Passthrough>::new();
  let peer = Peer::Replica(ReplicaId::new(1));
  let id = established(&mut r, peer);
  // Aborted directly, WITHOUT an intervening reap: `peers` still points at `id`, but the conn is no
  // longer validated (mirrors the window between an inbound reject and the next reap_closed()).
  r.conn_mut(id).unwrap().abort(CloseCause::IdentityRejected);
  assert_eq!(
    r.authoritative(peer),
    Some(id),
    "the stale mapping survives until reaped"
  );
  let dropped = r.route(Recipient::To(peer), &commit_msg(), ReplicaId::new(9));
  assert_eq!(
    dropped, 0,
    "a closed-but-not-yet-reaped conn is skipped, not counted as a drop"
  );
  assert_eq!(
    r.conn(id).unwrap().queued_outbound(),
    0,
    "nothing is queued to the closed conn"
  );
}

#[test]
fn backups_exclude_the_local_replica_and_any_client_conn() {
  use crate::ClientId;
  let mut r = PeerRouter::<crate::Passthrough>::new();
  let p0 = established(&mut r, Peer::Replica(ReplicaId::new(0)));
  let self_conn = established(&mut r, Peer::Replica(ReplicaId::new(1)));
  let p2 = established(&mut r, Peer::Replica(ReplicaId::new(2)));
  let client_conn = r.register_dialed(Peer::Client(ClientId::new(5)), conn());
  let dropped = r.route(Recipient::Backups, &commit_msg(), ReplicaId::new(1)); // self_id = 1
  assert_eq!(dropped, 0);
  assert!(
    r.conn(p0).unwrap().queued_outbound() > 0,
    "replica 0 receives the backup fan-out"
  );
  assert!(
    r.conn(p2).unwrap().queued_outbound() > 0,
    "replica 2 receives the backup fan-out"
  );
  assert_eq!(
    r.conn(self_conn).unwrap().queued_outbound(),
    0,
    "the local replica (self_id) is excluded even though it has a validated conn"
  );
  assert_eq!(
    r.conn(client_conn).unwrap().queued_outbound(),
    0,
    "a validated non-replica (Client) peer is never a backup fan-out target"
  );
}

#[test]
fn reap_on_an_unknown_id_returns_false() {
  let mut r = PeerRouter::<crate::Passthrough>::new();
  assert!(
    !r.reap(ConnId::new(777)),
    "reaping an id that was never registered is a no-op"
  );
}

#[test]
fn frame_fits_pins_the_boundary_the_post_encode_backstop_relies_on() {
  use crate::transport::frame::MAX_FRAME_LEN;
  // `route()`'s post-encode backstop re-checks the bytes it actually produced against this exact
  // predicate — the same one the preflight above checks the `encoded_len()` estimate against. A
  // real message that disagrees between the two (the u32-wraparound the backstop guards against)
  // cannot be constructed in a unit test short of allocating a message nearing 4 GiB, so this pins
  // the boundary the predicate itself enforces directly.
  assert!(
    frame_fits(MAX_FRAME_LEN as usize),
    "exactly at the cap fits"
  );
  assert!(
    !frame_fits(MAX_FRAME_LEN as usize + 1),
    "one byte over the cap does not fit"
  );
}

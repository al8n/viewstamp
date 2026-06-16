//! Identity resolution on recover: `recover` resolves THIS node by its stable `MemberId` against the
//! DURABLE root's membership and returns [`Recovered::{Active, Retired}`] (present → `Active` at its
//! resolved slot; absent → `Retired`; a legacy root bridges to the passed genesis).

use super::{super::*, *};
use crate::{
  Config, Epoch, MemberId, Membership, Message, OpNumber, Recovery, ReplicaId, View, VsrState,
};
use std::collections::VecDeque;

/// A v4 durable root carrying `membership` at `(view = 0, log_view = 0, commit, checkpoint_op = 0)`
/// with an empty committed band. The fixture membership uses `config_id = 0` (matching the other
/// endpoint fixtures), so the scalar epoch is the membership's epoch.
fn v4_root(membership: Membership, commit: u64) -> VsrState {
  let epoch = membership.epoch();
  VsrState::try_new_v4(
    View::new(),
    View::new(),
    OpNumber::with(commit),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
    epoch,
    epoch,
    membership,
  )
  .expect("valid v4 root")
}

/// A `TestSb` whose durable root is `state`.
fn sb_with_state(state: VsrState) -> TestSb {
  TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  }
}

#[test]
fn recover_resolves_self_by_member_id_and_returns_active() {
  // A v4 root whose membership CONTAINS this node's MemberId. The local member is `MemberId::new(7)`,
  // placed at slot 2 of a 3-voter membership — so recover must resolve self by MEMBER ID (not by a
  // config replica index) and land it in slot 2.
  let members = std::vec![MemberId::new(5), MemberId::new(6), MemberId::new(7)];
  let membership = Membership::from_durable_parts(Epoch::new(0), 3, 0, members, 0).unwrap();
  let state = v4_root(membership, 0);
  let mut wal = TestWal::default();
  let mut sb = sb_with_state(state);
  // The Config's local member is MemberId::new(7) (the `1` is the legacy ctor index, irrelevant to
  // membership resolution now).
  let cfg = Config::try_new(1, MemberId::new(7)).unwrap();

  let recovered = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb);
  let e = match recovered {
    Recovered::Active(e) => e,
    Recovered::Retired(_) => panic!("self IS in the membership → Active"),
  };
  assert_eq!(
    e.replica(),
    ReplicaId::new(2),
    "MemberId(7) occupies slot 2 of the durable membership",
  );
}

#[test]
fn recover_returns_retired_when_self_absent() {
  // A v4 root whose membership does NOT contain this node's MemberId — a reconfiguration removed it.
  // recover must return Retired carrying the local id + the epoch it was retired at, WITHOUT touching
  // the WAL (no reads submitted).
  let members = std::vec![MemberId::new(5), MemberId::new(6), MemberId::new(7)];
  let membership = Membership::from_durable_parts(Epoch::new(4), 3, 0, members, 0).unwrap();
  let state = v4_root(membership, 0);
  let mut wal = TestWal::default();
  let mut sb = sb_with_state(state);
  // Local member 99 is absent from the durable membership.
  let cfg = Config::try_new(1, MemberId::new(99)).unwrap();

  let recovered = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb);
  let retired = match recovered {
    Recovered::Retired(r) => r,
    Recovered::Active(_) => panic!("self is ABSENT from the durable membership → Retired"),
  };
  assert_eq!(retired.local(), MemberId::new(99), "carries the local id");
  assert_eq!(
    retired.epoch(),
    Epoch::new(4),
    "retired at the recovered membership's epoch",
  );
  assert_eq!(
    wal.poll(),
    None,
    "a retired node submits no reads (the WAL completion queue is empty)",
  );
}

#[test]
fn recover_bridges_a_legacy_root_to_the_passed_genesis() {
  // A legacy (v1-3) root carries NO membership (`membership_opt().is_none()`), so recover BRIDGES to
  // the passed genesis membership. `genesis(3)` places MemberId::new(i) at slot i, so the local
  // MemberId::new(1) is present at slot 1 → Active.
  let legacy = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::new(),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
  )
  .unwrap();
  assert!(
    legacy.membership_opt().is_none(),
    "a v1-3 root has no durable membership",
  );
  let mut wal = TestWal::default();
  let mut sb = sb_with_state(legacy);
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();

  let recovered = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb);
  let e = match recovered {
    Recovered::Active(e) => e,
    Recovered::Retired(_) => panic!("legacy root bridges to the passed genesis; self IS present"),
  };
  assert_eq!(
    e.replica(),
    ReplicaId::new(1),
    "the bridged genesis places MemberId(1) at slot 1",
  );
}

#[test]
fn recover_prefers_the_root_membership_over_the_passed_param() {
  // The EFFECTIVE-membership rule: when the root is v4, the DURABLE membership wins — the passed
  // param is ignored. The durable membership places MemberId(1) at slot 0 (a different slot than the
  // passed `genesis(3)`'s slot 1), proving the root's membership, not the param, is used.
  let members = std::vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)];
  let durable = Membership::from_durable_parts(Epoch::new(0), 3, 0, members, 0).unwrap();
  let state = v4_root(durable, 0);
  let mut wal = TestWal::default();
  let mut sb = sb_with_state(state);
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();

  // Pass a DIFFERENT genesis (the standard `genesis(3)`, MemberId(i) at slot i → MemberId(1) at slot
  // 1). The durable root places MemberId(1) at slot 0, so the resolved slot proves which won.
  let e = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb).expect_active();
  assert_eq!(
    e.replica(),
    ReplicaId::new(0),
    "the durable v4 root's membership wins (slot 0), not the passed param (slot 1)",
  );
}

#[test]
fn recover_resolves_a_learner_self_to_active() {
  // A node that is a non-voting LEARNER in the durable membership still recovers Active (it is
  // present, just non-voting). 2 voters + 1 learner; the local member is the learner at slot 2.
  let members = std::vec![MemberId::new(10), MemberId::new(11), MemberId::new(12)];
  let membership = Membership::from_durable_parts(Epoch::new(0), 2, 1, members, 0).unwrap();
  let state = v4_root(membership, 0);
  let mut wal = TestWal::default();
  let mut sb = sb_with_state(state);
  let cfg = Config::try_new(2, MemberId::new(12)).unwrap();

  let e = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb).expect_active();
  assert_eq!(e.replica(), ReplicaId::new(2), "learner self at slot 2");
  assert!(e.is_learner(), "slot 2 is a learner in 2v+1l");
}

#[test]
#[should_panic(expected = "must occupy a slot in its own membership")]
fn new_panics_when_the_local_member_is_absent_from_its_membership() {
  // A FRESH endpoint whose local MemberId is NOT in its genesis membership is a caller
  // misconfiguration. It must fail FAST at construction — in RELEASE too, an unconditional assert,
  // not a debug-only one — rather than `expect`-panic LATER via `local_slot()` on an already-running
  // node (`replica()`, timers, ingress). Contrast `recover`, where absence is the legitimate
  // `Recovered::Retired` outcome (a node removed by reconfiguration), tested above.
  let cfg = Config::try_new(1, MemberId::new(99)).unwrap(); // local 99 is absent from genesis(3) = {0,1,2}
  let _ = Endpoint::new(cfg, genesis(3), 0, NoopSm);
}

// ── all-`RecoveringHead` re-formation escalation ──────────────────────────────────────────
//
// A coordinated offline all-restart into a bumped epoch can wedge the cluster with a voting quorum in
// `RecoveringHead`: no `Normal` node answers a `Recovery`, and `RecoveringHead` had no escalation
// path. The bounded, evidence-gated escalation fires iff `epoch > prev_epoch ∧ G1 ∧ G2`, evaluated
// only in `recover_head_timeouts`.

/// The successor membership of an offline restart that KEEPS the 3 voters `{MemberId 0,1,2}` (so this
/// node stays a voter) but bumps the epoch via [`Membership::reconfigure`] — the durable backward link
/// `prev_epoch == genesis epoch < successor epoch`, the on-axis condition the gate's `epoch >
/// prev_epoch` term detects.
fn successor_membership() -> Membership {
  genesis(3)
    .reconfigure(
      3,
      0,
      std::vec![MemberId::new(0), MemberId::new(1), MemberId::new(2)],
    )
    .expect("valid successor membership")
}

/// Drive replica 1 of 3 into `RecoveringHead` AT A BUMPED EPOCH (`epoch > prev_epoch`), recovering
/// from an offline-restart successor root pre-written by [`prepare_restart`]. The WAL holds dense ops `1..=2`
/// with the HEAD (op 2) permanently faulty, so recovery cannot trust its head → `RecoveringHead`. The
/// successor's `(epoch, config_id)` are returned so a test can mint peer `Recovery` messages that pass
/// the strict ingress gate.
fn recovering_head_post_reconfig() -> (Endpoint<NoopSm>, ScriptedWal, TestSb, Epoch, u128) {
  let successor = successor_membership();
  let (epoch, config_id) = (successor.epoch(), successor.config_id());
  // The predecessor v4 root (genesis epoch), then the successor root chained off it. `prepare_restart`
  // preserves the consensus frontier and sets `prev_epoch = genesis epoch`, `epoch = successor epoch`.
  let cur = v4_root(genesis(3), 0);
  let succ_state = crate::endpoint::prepare_restart(
    &cur,
    3,
    0,
    std::vec![MemberId::new(0), MemberId::new(1), MemberId::new(2)],
  )
  .expect("successor root");
  assert!(
    succ_state.epoch() > succ_state.prev_epoch(),
    "the successor root is on-axis: epoch > prev_epoch",
  );
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // head read never clears → permanently faulty
  let mut sb = sb_with_state(succ_state);
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap(); // local = MemberId 1 → slot 1 (a voter)
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb).expect_active();
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() != Status::Recovering {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "setup: faulty head at a bumped epoch → RecoveringHead",
  );
  assert!(
    r.membership.epoch() > r.prev_epoch,
    "the recovered endpoint is on-axis: membership epoch > prev_epoch",
  );
  (r, wal, sb, epoch, config_id)
}

/// A peer `Recovery` solicitation from voter `slot`, carrying the successor `(epoch, config_id)` so it
/// passes `sender_matches` (the `from` binds to `slot`) and the strict `epoch_authority_admits` gate.
fn peer_recovery(slot: u16, epoch: Epoch, config_id: u128) -> (Peer, Message) {
  (
    Peer::Replica(ReplicaId::new(slot)),
    Message::Recovery(Recovery::new(
      ReplicaId::new(slot),
      0xC0DE,
      epoch,
      config_id,
    )),
  )
}

#[test]
fn recovering_head_tally_of_a_peer_recovery_emits_nothing_but_sets_the_bit() {
  // The G2 tally arm: a peer `Recovery` delivered to a `RecoveringHead` voter records the sender's
  // voter slot in `peers_recovering` with ZERO egress (it has no canonical head to hand out, and the
  // tally must be byte-identity-safe — off the `emit` chokepoint).
  let (mut r, mut wal, mut sb, epoch, config_id) = recovering_head_post_reconfig();
  while r.poll_message().is_some() {} // discard the entry-time solicitation
  let now = Instant::ZERO;
  let (from, msg) = peer_recovery(0, epoch, config_id); // replica 0 is a co-recovering voter
  r.handle_message(now, &mut wal, &mut sb, from, msg);
  assert_eq!(
    r.poll_message(),
    None,
    "a tallied peer Recovery emits NOTHING (no answer, no egress)",
  );
  let bit = 1u64 << 0;
  assert_eq!(
    r.recover.as_ref().map(|rec| rec.peers_recovering & bit),
    Some(bit),
    "the co-recovering voter's slot bit is set in peers_recovering",
  );
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "the tally does not change status (it does not participate)",
  );
}

#[test]
fn over_fire_guard_no_co_recovering_peers_never_escalates() {
  // The G2 guard: a single voter in `RecoveringHead` with `epoch > prev_epoch` true and `G1` long
  // matured, but NO co-recovering peers (`peers_recovering` stays 0 every window), must NOT escalate —
  // the gate stays false because the co-recovering-quorum evidence (G2) is absent. Many ticks, no SVC.
  let (mut r, mut wal, mut sb, _epoch, _config_id) = recovering_head_post_reconfig();
  while r.poll_message().is_some() {}
  let mut now = Instant::ZERO;
  // Tick far past RECOVER_HEAD_REFORM_ATTEMPTS windows; never feed a peer Recovery.
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize + 8) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb);
    // Every tick re-broadcasts our OWN Recovery solicitation (drained) but must never emit an SVC.
    while let Some(out) = r.poll_message() {
      assert!(
        !matches!(out.msg_ref(), Message::StartViewChange(_)),
        "over-fire: a RecoveringHead voter with no co-recovering peers must not escalate",
      );
    }
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "without G2 the node stays RecoveringHead (no escalation)",
    );
  }
  // G1 matured (reform_attempts saturated up), G2 still 0 — the gate is unmet by construction.
  assert!(
    r.recover
      .as_ref()
      .is_some_and(|rec| rec.reform_attempts >= RECOVER_HEAD_REFORM_ATTEMPTS),
    "G1 matured over the ticks",
  );
  assert_eq!(
    r.recover.as_ref().map(|rec| rec.peers_recovering),
    Some(0),
    "G2 evidence is absent (no co-recovering voter was ever tallied)",
  );
}

#[test]
fn solo_voting_set_never_escalates_despite_a_bumped_epoch() {
  // A SOLO voting set (`replica_count == 1`) in `RecoveringHead` at a bumped epoch must NEVER escalate
  // into a view change: a single voter has no quorum to re-form among, and `quorum - 1 == 0` makes the
  // co-recovering-peer check (G2) VACUOUSLY true — so ONLY the `replica_count() > 1` guard stops it. A
  // solo replica that cannot read its head is genuinely stuck (no peer to repair from), exactly as
  // `forfeit` holds a solo primary rather than abdicating to a non-existent quorum. It stays
  // `RecoveringHead`, never `ViewChange`. (Remove the guard and this test escalates — G1 matures and G2
  // is vacuous, so the guard is the sole thing preventing the unsupported solo view change.)
  let cur = v4_root(genesis(1), 0);
  let succ = crate::endpoint::prepare_restart(&cur, 1, 0, std::vec![MemberId::new(0)])
    .expect("solo successor root");
  assert!(
    succ.epoch() > succ.prev_epoch(),
    "the solo successor is on-axis: epoch > prev_epoch",
  );
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // head read never clears → permanently faulty
  let mut sb = sb_with_state(succ);
  let cfg = Config::try_new(0, MemberId::new(0)).unwrap(); // local = MemberId 0 → slot 0 (the only voter)
  let mut now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(1), 0, NoopSm, &mut wal, &mut sb).expect_active();
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() != Status::Recovering {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "solo: faulty head at a bumped epoch → RecoveringHead",
  );
  while r.poll_message().is_some() {}
  // Drive far past `RECOVER_HEAD_REFORM_ATTEMPTS` windows; the solo guard must hold every tick.
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize + 8) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb);
    while let Some(out) = r.poll_message() {
      assert!(
        !matches!(out.msg_ref(), Message::StartViewChange(_)),
        "a solo voting set must not escalate into a view change",
      );
    }
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "a solo voting set stays RecoveringHead (the replica_count > 1 guard blocks escalation)",
    );
  }
  assert!(
    r.recover
      .as_ref()
      .is_some_and(|rec| rec.reform_attempts >= RECOVER_HEAD_REFORM_ATTEMPTS),
    "G1 matured — so only the solo guard, not an unmet G1, prevented escalation",
  );
}

#[test]
fn a_learner_never_escalates_a_recovering_head_wedge() {
  // A non-voting LEARNER that faults its head reaches `RecoveringHead` too, but it must NEVER join the
  // active view-change / SVC / DVC path. The gate's `is_voter(self.local_slot())` blocks it even when
  // G1 matures AND a co-recovering VOTER quorum is tallied (G2) at a bumped epoch. (Remove the
  // is_voter guard and this escalates — every other gate term holds for a learner in a 2v+1l set.)
  let members = std::vec![MemberId::new(10), MemberId::new(11), MemberId::new(12)];
  let cur = v4_root(
    Membership::from_durable_parts(Epoch::new(0), 2, 1, members.clone(), 0).unwrap(),
    0,
  );
  let succ = crate::endpoint::prepare_restart(&cur, 2, 1, members).expect("2v+1l successor root");
  assert!(succ.epoch() > succ.prev_epoch(), "the successor is on-axis");
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), u8::MAX);
  let mut sb = sb_with_state(succ);
  let cfg = Config::try_new(2, MemberId::new(12)).unwrap(); // local = the LEARNER at slot 2
  let mut now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb).expect_active();
  assert!(
    r.is_learner(),
    "the local node is a learner (slot 2 in 2v+1l)"
  );
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() != Status::Recovering {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "a learner with a faulty head at a bumped epoch → RecoveringHead",
  );
  let (epoch, config_id) = (r.membership.epoch(), r.membership.config_id());
  while r.poll_message().is_some() {}
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize + 8) {
    let (from, msg) = peer_recovery(0, epoch, config_id); // a co-recovering VOTER → satisfies G2
    r.handle_message(now, &mut wal, &mut sb, from, msg);
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb);
    while let Some(out) = r.poll_message() {
      assert!(
        !matches!(out.msg_ref(), Message::StartViewChange(_)),
        "a learner must never escalate into a view change",
      );
    }
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "the learner stays RecoveringHead (the is_voter guard blocks escalation)",
    );
  }
}

#[test]
fn a_self_looped_recovery_does_not_count_toward_g2() {
  // The G2 tally counts only OTHER voters: a looped-back LOCAL `Recovery` (sender == self) must NOT set
  // its own bit, else a node could satisfy the OTHER-voters quorum alone (decisive for a 2-voter set
  // where `quorum - 1 == 1`). Feed a `RecoveringHead` voter its OWN `Recovery`; `peers_recovering`
  // stays 0. A DIFFERENT voter's `Recovery` then sets its bit, confirming the tally still works.
  let (mut r, mut wal, mut sb, epoch, config_id) = recovering_head_post_reconfig(); // 3v, local slot 1
  let now = Instant::ZERO;
  let (from_self, msg_self) = peer_recovery(1, epoch, config_id); // slot 1 == the local slot — a self-loop
  r.handle_message(now, &mut wal, &mut sb, from_self, msg_self);
  assert_eq!(
    r.recover.as_ref().map(|rec| rec.peers_recovering),
    Some(0),
    "a self-looped Recovery is not tallied (only OTHER voters count toward G2)",
  );
  let (from_other, msg_other) = peer_recovery(0, epoch, config_id); // slot 0 — a genuine OTHER voter
  r.handle_message(now, &mut wal, &mut sb, from_other, msg_other);
  assert_eq!(
    r.recover.as_ref().map(|rec| rec.peers_recovering),
    Some(1u64 << 0),
    "an OTHER voter's Recovery sets exactly its own bit",
  );
}

#[test]
fn under_fire_co_recovering_quorum_escalates_to_view_change_at_view_plus_one() {
  // The fire path: a `RecoveringHead` voter with `epoch > prev_epoch`, `G1` matured, AND a
  // co-recovering voting quorum (`peers_recovering` reaches quorum-1 via tallied peer `Recovery`)
  // escalates into a view change at `view + 1` and (on the next solicitation window) broadcasts a
  // StartViewChange. Every wedged voter recovered the same durable view, so all converge on view+1.
  let (mut r, mut wal, mut sb, epoch, config_id) = recovering_head_post_reconfig();
  while r.poll_message().is_some() {}
  let start_view = r.view();
  let start_log_view = r.log_view();
  let mut now = Instant::ZERO;
  // Mature G1 WITHOUT firing: tick (REFORM_ATTEMPTS - 2) windows with no co-recovering peers, so each
  // window the intersection is empty (G2 unmet) and reform_attempts climbs. Stays RecoveringHead. Two
  // windows are left for the co-recovering feed — G2 is a TWO-window intersection (freshness guard).
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize - 2) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb);
    while r.poll_message().is_some() {}
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "not yet escalating (G1 maturing)"
    );
  }
  // WINDOW 1 of the feed: tally the OTHER-voter quorum (quorum-1 = 1 other voter for N=3; feed both to
  // be unambiguous), then tick. This window's snapshot becomes `peers_recovering_prev`; the intersection
  // with the still-empty PRIOR window is 0, so the gate does NOT fire yet — one window is not enough.
  for slot in [0u16, 2] {
    let (from, msg) = peer_recovery(slot, epoch, config_id);
    r.handle_message(now, &mut wal, &mut sb, from, msg);
  }
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb);
  while r.poll_message().is_some() {}
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "one window of co-recovering evidence is not enough — the two-window intersection is still empty",
  );
  // WINDOW 2: tally the SAME quorum again, then tick. Now `peers_recovering & peers_recovering_prev`
  // holds the quorum (co-recovering across BOTH windows) → G2 met, G1 matured → escalate.
  for slot in [0u16, 2] {
    let (from, msg) = peer_recovery(slot, epoch, config_id);
    r.handle_message(now, &mut wal, &mut sb, from, msg);
  }
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb);
  assert_eq!(
    r.status(),
    Status::ViewChange,
    "the gate fired: a quorum co-recovering across two windows escalated into a view change",
  );
  assert_eq!(
    r.view(),
    start_view.next(),
    "the escalation targets view + 1 (the uniform convergence target)",
  );
  // SAFETY-LOAD-BEARING: the escalation bumps `view` but NOT `log_view` — so the escalator enters the
  // view change as an EQUAL co-canonical donor (same `log_view` as the rest), never a privileged
  // higher-generation one. That is what makes a spurious escalation harmless: the escalator cannot win
  // `select_canonical_log` in any way that truncates a committed op the quorum holds (its only droppable
  // op is its own strictly-uncommitted faulty tail). G2's freshness only avoids unnecessary escalations;
  // committed-op safety never depends on it.
  assert_eq!(
    r.log_view(),
    start_log_view,
    "escalation preserves log_view (the escalator is an equal co-canonical donor, cannot truncate committed data)",
  );
  assert!(
    r.recover.is_none(),
    "retire_recover_and_escalate drops the recover state (and its re-formation counters)",
  );
  // The durable-view write is staged before participation; complete it, then the SVC retransmit
  // window broadcasts a StartViewChange for view + 1.
  r.handle_storage(now, &mut wal, &mut sb);
  while r.poll_message().is_some() {} // discard the deferred DVC / transition chatter
  now = now + VC_MESSAGE_RETRANSMIT;
  r.handle_timeout(now, &mut wal, &mut sb);
  let svc = core::iter::from_fn(|| r.poll_message())
    .find_map(|out| match out.into_msg() {
      Message::StartViewChange(svc) => Some(svc),
      _ => None,
    })
    .expect("the escalated voter broadcasts a StartViewChange");
  assert_eq!(
    svc.view(),
    start_view.next(),
    "the StartViewChange targets view + 1",
  );

  // A2 re-arm: a FRESH recover() resets the counters, re-enters RecoveringHead at the new view, and the
  // gate can fire AGAIN (epoch > prev_epoch is still true) — re-formation is not one-shot.
  let succ_state = sb.state(); // the durable root now names view + 1 (the escalation persisted it)
  let mut wal2 = ScriptedWal::with_entries(2);
  wal2.script_read_fault(OpNumber::with(2), u8::MAX);
  let mut sb2 = sb_with_state(succ_state);
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now2 = Instant::ZERO;
  let mut r2 = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal2, &mut sb2).expect_active();
  for _ in 0..16 {
    r2.handle_storage(now2, &mut wal2, &mut sb2);
    if r2.status() != Status::Recovering {
      break;
    }
  }
  assert_eq!(
    r2.status(),
    Status::RecoveringHead,
    "re-wedged after a fresh recover()"
  );
  assert!(
    r2.recover
      .as_ref()
      .is_some_and(|rec| rec.reform_attempts == 0
        && rec.peers_recovering == 0
        && rec.peers_recovering_prev == 0),
    "a fresh recover() resets G1/G2 (incl. both intersection windows) to zero",
  );
  let re_view = r2.view();
  let mut t = Instant::ZERO;
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize - 2) {
    t = t + RECOVER_HEAD_SOLICIT;
    r2.handle_timeout(t, &mut wal2, &mut sb2);
    while r2.poll_message().is_some() {}
  }
  // Two consecutive windows of the co-recovering quorum (the two-window intersection), then it fires.
  for _ in 0..2 {
    for slot in [0u16, 2] {
      let (from, msg) = peer_recovery(slot, epoch, config_id);
      r2.handle_message(t, &mut wal2, &mut sb2, from, msg);
    }
    t = t + RECOVER_HEAD_SOLICIT;
    r2.handle_timeout(t, &mut wal2, &mut sb2);
    while r2.poll_message().is_some() {}
  }
  assert_eq!(
    r2.status(),
    Status::ViewChange,
    "the gate RE-FIRES on a fresh incarnation (re-formation re-arms at any view)",
  );
  assert_eq!(
    r2.view(),
    re_view.next(),
    "the re-fire targets the new view + 1",
  );
}

#[test]
fn a_single_window_stale_recovery_does_not_escalate() {
  // R5: a STALE same-epoch Recovery — a single late message from a voter that has SINCE returned to
  // Normal (and stopped re-broadcasting) — appears in at most ONE solicitation window. G2 is the
  // TWO-window intersection (`peers_recovering & peers_recovering_prev`), so a single-window bit is
  // dropped and never reaches the co-recovering quorum. With the OLD single-window snapshot this would
  // escalate (G1 matured + the quorum present this window); the intersection makes it inert.
  let (mut r, mut wal, mut sb, epoch, config_id) = recovering_head_post_reconfig();
  while r.poll_message().is_some() {}
  let mut now = Instant::ZERO;
  // Mature G1 well past the bound with EMPTY windows — so only the missing two-window evidence can hold
  // the gate, not an unmet G1.
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize + 4) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb);
    while r.poll_message().is_some() {}
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "G1 maturing with no co-recovering evidence"
    );
  }
  // ONE window with the FULL co-recovering quorum tallied, then tick. The prior window was empty, so the
  // intersection is 0 → NO escalation despite G1 long matured and the quorum present this window.
  for slot in [0u16, 2] {
    let (from, msg) = peer_recovery(slot, epoch, config_id);
    r.handle_message(now, &mut wal, &mut sb, from, msg);
  }
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb);
  while let Some(out) = r.poll_message() {
    assert!(
      !matches!(out.msg_ref(), Message::StartViewChange(_)),
      "a single-window (stale-shaped) co-recovering Recovery must not escalate",
    );
  }
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "a single-window co-recovering quorum does not escalate (the two-window intersection drops it)",
  );
}

#[test]
fn a_since_recovered_peer_drops_out_of_the_two_window_intersection() {
  // The complement: a voter co-recovering in window N-1 but NOT in window N (it recovered to Normal and
  // stopped broadcasting) is dropped by the intersection — the prev-window bit ALONE is insufficient.
  // This confirms G2 is an AND of two windows, not an OR-accumulator, and models the exact R5 timeline.
  let (mut r, mut wal, mut sb, epoch, config_id) = recovering_head_post_reconfig();
  while r.poll_message().is_some() {}
  let mut now = Instant::ZERO;
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize - 1) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb);
    while r.poll_message().is_some() {}
  }
  // Window N-1: the quorum is co-recovering (tallied), then tick (it becomes `prev`).
  for slot in [0u16, 2] {
    let (from, msg) = peer_recovery(slot, epoch, config_id);
    r.handle_message(now, &mut wal, &mut sb, from, msg);
  }
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb);
  while r.poll_message().is_some() {}
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "one window alone does not fire"
  );
  // Window N: the peers have recovered — NOTHING is tallied — then tick. fresh = 0 (empty) & prev (Q) =
  // 0 → no escalation. The prev-window evidence does not linger.
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb);
  while let Some(out) = r.poll_message() {
    assert!(
      !matches!(out.msg_ref(), Message::StartViewChange(_)),
      "a peer present only in the PRIOR window must not escalate (the intersection is an AND)",
    );
  }
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "a since-recovered peer drops out of the two-window intersection",
  );
}

#[test]
fn an_escalation_carries_a_repairing_committed_op_into_the_view_change() {
  // PRIMARY committed-op-loss fix, exercised in the re-formation escalation path. A RecoveringHead voter holds a
  // COMMITTED op whose recovery read FAULTED but whose durable header survives — kept header-only as
  // `Body::Repairing`, NOT dropped to a bare hole. When it escalates the wedge into a view change, that op
  // must be CARRIED: its existence + identity flow into the DoViewChange / StartView log_slice so a new
  // primary peer-repairs it and never re-mints its op number. Dropping it would lose it if this voter then
  // solo/minimal-forms the next view (the seed-774 intersection class).
  //
  // Setup: a SEALED offline-restart successor (commit 2, dense band [h1, h2]); WAL head 3. op 1 reads clean
  // (Present); op 2 (committed, durable band header) read FAULTS → kept as `Body::Repairing`; op 3 (the
  // uncommitted tail head) faults → RecoveringHead. commit_max == 2, so op 2 is the interior committed op.
  let successor = crate::endpoint::prepare_restart(
    &sealed_root(2),
    3,
    0,
    std::vec![MemberId::new(0), MemberId::new(1), MemberId::new(2)],
  )
  .expect("sealed successor root");
  let (epoch, config_id) = (successor.epoch(), successor.membership().config_id());
  let mut wal = ScriptedWal::with_entries(3);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // committed interior → kept as Repairing
  wal.script_read_fault(OpNumber::with(3), u8::MAX); // uncommitted head → RecoveringHead
  let mut sb = sb_with_state(successor);
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb).expect_active();
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() != Status::Recovering {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "faulty head at a bumped epoch → RecoveringHead",
  );
  assert_eq!(r.commit_max(), OpNumber::with(2), "op 2 is KNOWN committed");
  // op 2 is KEPT as a Repairing committed hole (durable header), NOT in rec.faulty — so the escalation
  // gate's committed-band guard stays satisfied (a held committed op is vouched, never unvouchable).
  assert!(
    r.log
      .get(&2)
      .is_some_and(|e| matches!(e.body, Body::Repairing(_))),
    "op 2 is kept header-only as Body::Repairing (durable header preserved), not dropped",
  );
  assert!(
    r.recover
      .as_ref()
      .is_some_and(|rec| !rec.faulty.contains(&2)),
    "the held committed op is NOT in rec.faulty (it is Repairing, vouched by its durable header)",
  );
  while r.poll_message().is_some() {}
  // Mature G1, then feed a co-recovering voting quorum across two windows — the exact `under_fire...` inputs.
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize - 2) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb);
    while r.poll_message().is_some() {}
  }
  for _window in 0..2 {
    for slot in [0u16, 2] {
      let (from, msg) = peer_recovery(slot, epoch, config_id);
      r.handle_message(now, &mut wal, &mut sb, from, msg);
    }
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb);
  }
  assert_eq!(
    r.status(),
    Status::ViewChange,
    "G1 + a two-window co-recovering quorum → escalate (the committed band is intact)",
  );
  // THE CARRY: op 2 survived the escalation as a Repairing committed op, and it is EXPOSED in the log_slice
  // a DoViewChange / StartView carries — so a new primary sees op 2 exists and peer-repairs it, never
  // re-mints its op number. (FAIL-BEFORE the PRIMARY fix: op 2 was dropped to a bare hole, omitted here.)
  assert!(
    r.log
      .get(&2)
      .is_some_and(|e| matches!(e.body, Body::Repairing(_))),
    "op 2 is CARRIED through the escalation as a Repairing committed op (not dropped)",
  );
  assert!(
    r.log_entries().iter().any(|e| e.op() == OpNumber::with(2)),
    "op 2 is exposed in the DoViewChange / StartView log_slice — its existence flows into the view change",
  );
}

#[test]
fn an_unvouchable_committed_op_blocks_escalation_into_a_wedge() {
  // BELT-AND-SUSPENDERS committed-op-loss defense, complementing the PRIMARY keep-as-Repairing fix. A
  // RecoveringHead voter that holds a faulty COMMITTED op it CANNOT vouch — a StaleCommitted slot or one it
  // never held, routed to `rec.faulty` (NOT the durable-header Repairing path) — must NOT escalate: as the
  // solo/minimal-quorum primary for view+1 it would OMIT that op from its DoViewChange and lose it. The
  // gate `committed_band_intact` (no rec.faulty op <= commit_max) refuses, converting a rare committed LOSS
  // into a resolvable liveness WEDGE — it stays RecoveringHead soliciting, so a peer that holds the op
  // re-establishes the head and supplies it.
  //
  // Setup: an offline-restart successor with durable commit 1 (op 1 KNOWN committed) but an EMPTY band — op 1 has no
  // canonical header (the writer never held it). On recover op 1 classifies StaleCommitted → `rec.faulty`;
  // op 2 (head) faults → RecoveringHead. op 1 (<= commit_max 1) is the unvouchable committed hole. The
  // co-recovering-quorum inputs are IDENTICAL to `under_fire...` (which escalates at commit 0) — so the
  // ONLY difference that withholds the escalation is the unvouchable committed op.
  let successor = crate::endpoint::prepare_restart(
    &v4_root(genesis(3), 1),
    3,
    0,
    std::vec![MemberId::new(0), MemberId::new(1), MemberId::new(2)],
  )
  .expect("successor root (commit 1, empty band)");
  let (epoch, config_id) = (successor.epoch(), successor.membership().config_id());
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // head → RecoveringHead
  let mut sb = sb_with_state(successor);
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb).expect_active();
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() != Status::Recovering {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "faulty head at a bumped epoch → RecoveringHead",
  );
  assert_eq!(r.commit_max(), OpNumber::with(1), "op 1 is KNOWN committed");
  assert!(
    r.recover
      .as_ref()
      .is_some_and(|rec| rec.faulty.contains(&1)),
    "op 1 (committed, no canonical header) classifies StaleCommitted → rec.faulty (the unvouchable hole)",
  );
  while r.poll_message().is_some() {}
  // Mature G1 (no co-recovering peers — each window's intersection is empty).
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize - 2) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb);
    while r.poll_message().is_some() {}
    assert_eq!(
      r.status(),
      Status::RecoveringHead,
      "G1 maturing, not yet a candidate"
    );
  }
  // Window 1 of the co-recovering feed: tick (this window becomes `prev`; intersection with the empty prior
  // window is still 0).
  for slot in [0u16, 2] {
    let (from, msg) = peer_recovery(slot, epoch, config_id);
    r.handle_message(now, &mut wal, &mut sb, from, msg);
  }
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb);
  while r.poll_message().is_some() {}
  // Window 2: feed the SAME quorum. The two-window intersection now holds the quorum — G2 IS satisfied.
  for slot in [0u16, 2] {
    let (from, msg) = peer_recovery(slot, epoch, config_id);
    r.handle_message(now, &mut wal, &mut sb, from, msg);
  }
  let g2 = r
    .recover
    .as_ref()
    .map(|rec| (rec.peers_recovering & rec.peers_recovering_prev).count_ones())
    .unwrap_or(0);
  assert!(
    g2 >= 1,
    "non-vacuity: G2 is satisfied — a co-recovering voter quorum spans both windows ({g2} voters)",
  );
  // The deciding tick: G1 matured + G2 satisfied — the SAME inputs `under_fire...` escalates on. The ONLY
  // thing withholding the escalation here is the unvouchable committed op (committed_band_intact == false).
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb);
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "the unvouchable committed op blocks the escalation (committed_band_intact is false) — wedge, not loss",
  );
  assert!(
    r.recover.is_some(),
    "the recover incarnation is retained — still RecoveringHead and soliciting for the missing committed op",
  );
}

// ── committed-frontier seal (`seal_committed_frontier`) ────────────────────────────────────
//
// An offline-restart successor root copies `cur.commit()` — the DURABLE-root commit, which LAGS the in-memory
// `commit_max` between checkpoints (commit advances in memory via `advance_commit`; the durable root's
// commit is persisted only at a checkpoint boundary or a view-change durable-view write). With
// `checkpoint_ops > RECOVER_TAIL_WINDOW` a client-acked committed op K can sit MORE than
// `RECOVER_TAIL_WINDOW` ops above a node's stale durable commit C0. After a coordinated restart EVERY
// node has the same stale C0, so no peer holds a higher commit to repair from, and the bounded recover
// tail window (`hi = head.min(commit_max + RECOVER_TAIL_WINDOW)`, floored at the durable commit) caps
// `self.op` at `C0 + RECOVER_TAIL_WINDOW < K` — K is stranded below the re-formed head, its op-number
// freed and overwritten: a committed-op LOSS with zero storage faults.
//
// `seal_committed_frontier` closes this: called on every node while it is still up and `Normal`, it
// persists `commit_max` (+ its committed-band headers) into the durable root, so the successor
// `prepare_restart` derives carries the true committed prefix and every committed op is read back.

/// A v4 root carrying `genesis(3)` at `(view = 0, log_view = 0, commit, checkpoint_op = 0)` with the
/// dense committed band `1..=commit` (one canonical header per op). Body `[op as u8]` matches what
/// `ScriptedWal::with_entries` stores, so a recover off the successor reads each op back header-matched.
/// This is the SHAPE a SEALED root has — `commit == commit_max`, every committed op vouched.
fn sealed_root(commit: u64) -> VsrState {
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let headers: std::vec::Vec<Header> = (1..=commit).map(mk).collect();
  let genesis = genesis(3);
  let epoch = genesis.epoch();
  VsrState::try_new_v4(
    View::new(),
    View::new(),
    OpNumber::with(commit),
    OpNumber::new(),
    0,
    headers,
    epoch,
    epoch,
    genesis,
  )
  .expect("valid sealed v4 root")
}

#[test]
fn seal_committed_frontier_persists_commit_max_into_the_durable_root() {
  // (a) THE SEAL MECHANISM. A `Normal` node whose in-memory `commit_max` is K = RECOVER_TAIL_WINDOW + 2
  // sits above a STALE low durable-root commit C0 = 0 (the between-checkpoints lag). `seal_committed_frontier`
  // must persist `commit_max` into the durable root, so a successor `prepare_restart` derives off the
  // SEALED root carries the true committed prefix K — not the stale C0.
  let k = RECOVER_TAIL_WINDOW + 2;
  let mut e = Endpoint::new(
    Config::with_checkpoint_ops(1, MemberId::new(1), crate::MAX_CHECKPOINT_OPS).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
  );
  // Force the held-frontier shape: in-memory `commit_max == op == K`, `checkpoint_op == 0`. The durable
  // root (`TestSb::default()` → `VsrState::new()`) still names the STALE commit C0 == 0 — the lag.
  e.force_state_for_test(0, k, k, 0, &[]);
  let mut sb = TestSb::default();
  assert_eq!(
    sb.state().commit(),
    OpNumber::new(),
    "precondition: the durable root commit is the STALE C0 == 0 (below commit_max == K)"
  );
  assert_eq!(
    e.commit_max(),
    OpNumber::with(k),
    "precondition: the in-memory known-committed frontier is K, above the durable root"
  );

  let now = Instant::ZERO;
  assert!(
    e.seal_committed_frontier(&mut sb),
    "the seal fired (the node is Normal with no durable work in flight)"
  );
  assert!(
    e.pending_sb_for_test(),
    "the seal armed a durable-root write"
  );
  // A second seal while the first write is still in flight REFUSES (the in-flight-storage guard) — the
  // load-bearing protection against a seal racing or landing behind other outstanding durable work
  // (a queued checkpoint root, an append) and reverting it.
  assert!(
    !e.seal_committed_frontier(&mut sb),
    "a seal is refused while a durable-root write is in flight"
  );
  // Drive the seal's superblock write to completion, exactly as a recover/view-change test drains it.
  let mut wal = ScriptedWal::with_entries(0);
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(
    !e.pending_sb_for_test(),
    "the seal's durable-root write completed"
  );
  // THE CORE assertion: the durable root now names the known-committed frontier K, not the stale C0.
  // (FAIL-BEFORE: with `seal_committed_frontier` a no-op the root stays at C0 == 0.)
  assert_eq!(
    sb.state().commit(),
    OpNumber::with(k),
    "the seal persisted commit_max == K into the durable root (FAIL-BEFORE: stayed at C0 == 0)"
  );
}

#[test]
fn sealed_successor_root_carries_the_committed_frontier_across_a_restart() {
  // (b) THE END-TO-END FIX. Take the SEALED root (commit == K, dense headers 1..=K), run `prepare_restart`
  // to derive the offline-restart successor (bumped epoch, commit PRESERVED == K), recover a fresh node off the
  // successor + a WAL holding 1..=K, and assert the recovered head reads the FULL committed band — K
  // survives the coordinated restart.
  let k = RECOVER_TAIL_WINDOW + 2;
  let sealed = sealed_root(k);
  assert_eq!(
    sealed.commit(),
    OpNumber::with(k),
    "precondition: the sealed root names the committed frontier K"
  );
  let successor = crate::endpoint::prepare_restart(
    &sealed,
    3,
    0,
    std::vec![MemberId::new(0), MemberId::new(1), MemberId::new(2)],
  )
  .expect("successor root off the sealed predecessor");
  assert_eq!(
    successor.commit(),
    OpNumber::with(k),
    "prepare_restart PRESERVES the committed frontier — the successor still names K"
  );
  assert!(
    successor.epoch() > successor.prev_epoch(),
    "the successor is on-axis (bumped epoch), the realistic offline restart"
  );

  // The WAL holds canonical ops 1..=K (head == K), each body [op] header-matched, so recover reads the
  // full sealed band back. A large checkpoint interval matches the regime in which the hazard is reachable.
  let mut wal = ScriptedWal::with_entries(k);
  let mut sb = sb_with_state(successor);
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), crate::MAX_CHECKPOINT_OPS).unwrap();
  let now = Instant::ZERO;
  let mut r =
    Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut wal, &mut sb).expect_active();
  // The recovered head reads up to the sealed committed frontier K, not C0 + RECOVER_TAIL_WINDOW.
  assert_eq!(
    r.op(),
    OpNumber::with(k),
    "recover off the SEALED successor reads the full committed band (self.op == K), so K is not stranded"
  );
  assert!(
    r.op().get() > RECOVER_TAIL_WINDOW,
    "the committed op K above the window is held, not capped away"
  );
  for _ in 0..(k + 8) {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(r.status(), Status::Normal, "tail consistent → Normal");
  assert_eq!(
    r.op(),
    OpNumber::with(k),
    "the full committed band frontier is preserved into Normal — K SURVIVES the offline restart"
  );
  assert_eq!(
    r.commit_max(),
    OpNumber::with(k),
    "the recovered node carries the durable known-committed frontier K"
  );
  // The top op K (above the old window cap) is read + cached, not a hole — it is genuinely held.
  assert!(
    r.log
      .get(&k)
      .is_some_and(|e| e.body.as_present() == Some(&[k as u8][..])),
    "the committed op K is read + cached with its canonical body (survived end to end)"
  );
  assert!(
    !r.has_repair_hole_for_test(k),
    "K is HELD, not a repair hole"
  );
}

#[test]
fn unsealed_successor_strands_a_committed_op_above_the_window() {
  // (c) THE BUG WITNESS (non-vacuity). WITHOUT the seal the successor copies the STALE durable commit
  // C0 == 0 even though the WAL holds a committed op K = RECOVER_TAIL_WINDOW + 2. On recover the tail
  // window floors at the durable commit C0, so `hi = head.min(C0 + RECOVER_TAIL_WINDOW)` caps `self.op`
  // at C0 + RECOVER_TAIL_WINDOW < K — K is STRANDED below the re-formed head, its op-number freed and
  // overwritten on the next round: a committed-op loss. This pins WHY the seal is needed; it is today's
  // pre-seal recover behaviour for a stale root.
  let k = RECOVER_TAIL_WINDOW + 2;
  // The UNSEALED predecessor: a v4 root whose durable commit is the STALE C0 == 0, with NO committed
  // header above C0 (the band was never sealed). `prepare_restart` faithfully copies that stale commit.
  let unsealed = v4_root(genesis(3), 0);
  assert_eq!(
    unsealed.commit(),
    OpNumber::new(),
    "the unsealed predecessor carries the STALE durable commit C0 == 0"
  );
  let successor = crate::endpoint::prepare_restart(
    &unsealed,
    3,
    0,
    std::vec![MemberId::new(0), MemberId::new(1), MemberId::new(2)],
  )
  .expect("successor root off the unsealed predecessor");
  assert_eq!(
    successor.commit(),
    OpNumber::new(),
    "WITHOUT the seal the successor inherits the stale C0 == 0 (the committed frontier was NOT sealed)"
  );

  // The WAL HOLDS the committed op K (head == K, every body header-matched) — the bytes are durably on
  // disk — but the root vouches NO commit above C0, so recover cannot know K is committed and the window
  // bounds the read.
  let mut wal = ScriptedWal::with_entries(k);
  let mut sb = sb_with_state(successor);
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), crate::MAX_CHECKPOINT_OPS).unwrap();
  let now = Instant::ZERO;
  let mut r =
    Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut wal, &mut sb).expect_active();
  // THE HAZARD: the recovered head is capped at C0 + RECOVER_TAIL_WINDOW, STRICTLY BELOW K — the held
  // committed op K is stranded above the read frontier (the loss the seal prevents).
  assert_eq!(
    r.op(),
    OpNumber::with(RECOVER_TAIL_WINDOW),
    "the unsealed stale root caps recover at C0 + RECOVER_TAIL_WINDOW < K — K is stranded above the window"
  );
  assert!(
    r.op().get() < k,
    "the recovered head is BELOW the held committed op K — without the seal K is not read back"
  );
  for _ in 0..(RECOVER_TAIL_WINDOW + 8) {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "the capped recover still reaches Normal"
  );
  assert!(
    !r.log.contains_key(&k),
    "the stranded committed op K is NOT in the recovered cache — its slot is free to be overwritten"
  );
}

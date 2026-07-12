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
    std::vec::Vec::new(),
    OpNumber::new(),
  )
  .expect("valid v4 root")
  // Pin the geometry a running node's `durable_root` write stamps, so recovery sees a FORMATTED,
  // geometry-recorded store (a real non-virgin root always carries it). `checkpoint_ops` matches the
  // default recover config; `wal_capacity` is the ring-less test WAL's `u64::MAX` (the `Wal::capacity`
  // default these tests run over), so recovery's capacity fence compares equal.
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX)
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  // The Config's local member is MemberId::new(7) (the `1` is the legacy ctor index, irrelevant to
  // membership resolution now).
  let cfg = Config::try_new(1, MemberId::new(7)).unwrap();

  let recovered = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb, &mut blocks)
    .expect("recover accepts this store");
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  // Local member 99 is absent from the durable membership.
  let cfg = Config::try_new(1, MemberId::new(99)).unwrap();

  let recovered = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb, &mut blocks)
    .expect("recover accepts this store");
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
  // A root carrying NO durable membership (`membership_opt().is_none()`) makes recover BRIDGE to the
  // passed genesis membership. `genesis(3)` places MemberId::new(i) at slot i, so the local
  // MemberId::new(1) is present at slot 1 → Active. The root carries a NON-ZERO view so it is not the
  // empty `VsrState::new()` a wiped voter fails-stops on — a ran store holds durable state. It records
  // its WAL geometry so the non-virgin geometry fence admits it (a raw geometry-unrecorded legacy root
  // is instead refused fail-closed — see `recover_refuses_a_non_virgin_root_with_unrecorded_geometry`);
  // membership-absence, not the geometry, is what selects the bridge.
  let legacy = VsrState::try_new(
    View::with(1),
    View::with(1),
    OpNumber::new(),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  assert!(
    legacy.membership_opt().is_none(),
    "a membership-less root has no durable membership",
  );
  assert_ne!(
    legacy,
    VsrState::new(),
    "a ran legacy root is not the empty wiped-store shape"
  );
  let mut wal = TestWal::default();
  let mut sb = sb_with_state(legacy);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();

  let recovered = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb, &mut blocks)
    .expect("recover accepts this store");
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();

  // Pass a DIFFERENT genesis (the standard `genesis(3)`, MemberId(i) at slot i → MemberId(1) at slot
  // 1). The durable root places MemberId(1) at slot 0, so the resolved slot proves which won.
  let e = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb, &mut blocks)
    .expect("recover accepts this store")
    .expect_active();
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let cfg = Config::try_new(2, MemberId::new(12)).unwrap();

  let e = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb, &mut blocks)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(e.replica(), ReplicaId::new(2), "learner self at slot 2");
  assert!(e.is_learner(), "slot 2 is a learner in 2v+1l");
}

#[test]
fn recover_into_a_post_reconfiguration_epoch_restores_the_predecessor_lineage() {
  // CONSENSUS-LIVENESS: a node recovering into a post-reconfiguration (E+1) membership must RESTORE
  // the predecessor (E) `config_id` into its in-memory lineage from the durable root — so a retained
  // OLD-epoch laggard's catch-up (RequestSync/RequestPrepare carrying the E `config_id`) is still
  // ADMITTED after the E+1 donors restart. Without persisting it, recovery would seed every lineage slot
  // with only the CURRENT id and REJECT the laggard, stranding it.
  //
  // Build a REAL genesis (a hash-chained `config_id`, not the fixture's 0) so the predecessor and forked
  // ids are genuinely distinct, pre-write the successor root via `prepare_restart` (which now carries the
  // predecessor `config_id` in the durable lineage), and recover from it.
  let members = std::vec![MemberId::new(0), MemberId::new(1), MemberId::new(2)];
  let genesis_mem = Membership::genesis(3, 0, members.clone()).expect("genesis");
  let predecessor_config_id = genesis_mem.config_id();
  let successor_mem = genesis_mem
    .reconfigure(
      3,
      0,
      std::vec![MemberId::new(0), MemberId::new(1), MemberId::new(3)],
    )
    .expect("successor");
  let successor_config_id = successor_mem.config_id();
  assert_ne!(
    predecessor_config_id, successor_config_id,
    "the swap chains the config_id, so E and E+1 differ"
  );

  // The predecessor (genesis) durable root, then the successor root chained off it via prepare_restart.
  let cur = VsrState::try_new_v4(
    View::new(),
    View::new(),
    OpNumber::new(),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
    genesis_mem.epoch(),
    genesis_mem.epoch(),
    genesis_mem,
    std::vec::Vec::new(), // genesis: no predecessor lineage
    OpNumber::new(),      // genesis: no reconfigure has installed the membership
  )
  .expect("genesis root")
  // The predecessor durable root records its geometry; `prepare_restart` carries it into the successor
  // root, so the recovered store is geometry-recorded (the default recover config's interval + the
  // ring-less test WAL's `u64::MAX`).
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let succ_state = crate::endpoint::prepare_restart(
    &cur,
    3,
    0,
    std::vec![MemberId::new(0), MemberId::new(1), MemberId::new(3)],
  )
  .expect("successor root");
  // The successor root's durable lineage carries the predecessor id (the anti-stranding fix).
  assert_eq!(
    succ_state.prior_config_ids().first().copied(),
    Some(predecessor_config_id),
    "the successor durable root persists the predecessor config_id in its lineage",
  );

  let mut wal = TestWal::default();
  let mut sb = sb_with_state(succ_state);
  let mut blocks = crate::block_store::MemBlockStore::new();
  // The local member (MemberId 3) is the newly-added voter in the successor — present → Active.
  let cfg = Config::try_new(2, MemberId::new(3)).unwrap();
  let e = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb, &mut blocks)
    .expect("recover accepts this store")
    .expect_active();

  // The recovered node is at E+1, and its lineage ADMITS both the current and the predecessor config_id,
  // while REJECTING an unrelated/forked id — exactly the cross-epoch catch-up admission a laggard needs.
  assert_eq!(
    e.membership.config_id(),
    successor_config_id,
    "recovered into the E+1 successor membership"
  );
  assert!(
    e.in_lineage_for_test(successor_config_id),
    "the current (E+1) config_id is admitted"
  );
  assert!(
    e.in_lineage_for_test(predecessor_config_id),
    "the predecessor (E) config_id is admitted — a retained old-epoch laggard's catch-up is accepted",
  );
  assert!(
    !e.in_lineage_for_test(0xDEAD_BEEF_F00D_u128),
    "an unrelated/forked config_id is rejected (the lineage discriminator still bites)",
  );
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
  let _ = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, NoopSm, u64::MAX);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap(); // local = MemberId 1 → slot 1 (a voter)
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb, &mut blocks)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery(&mut r, &mut wal, &mut sb, &mut blocks, now);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  while r.poll_message().is_some() {} // discard the entry-time solicitation
  let now = Instant::ZERO;
  let (from, msg) = peer_recovery(0, epoch, config_id); // replica 0 is a co-recovering voter
  r.handle_message(now, &mut wal, &mut sb, &mut blocks, from, msg);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  while r.poll_message().is_some() {}
  let mut now = Instant::ZERO;
  // Tick far past RECOVER_HEAD_REFORM_ATTEMPTS windows; never feed a peer Recovery.
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize + 8) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let cfg = Config::try_new(0, MemberId::new(0)).unwrap(); // local = MemberId 0 → slot 0 (the only voter)
  let mut now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(1), 0, NoopSm, &mut wal, &mut sb, &mut blocks)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery(&mut r, &mut wal, &mut sb, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "solo: faulty head at a bumped epoch → RecoveringHead",
  );
  while r.poll_message().is_some() {}
  // Drive far past `RECOVER_HEAD_REFORM_ATTEMPTS` windows; the solo guard must hold every tick.
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize + 8) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let cfg = Config::try_new(2, MemberId::new(12)).unwrap(); // local = the LEARNER at slot 2
  let mut now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb, &mut blocks)
    .expect("recover accepts this store")
    .expect_active();
  assert!(
    r.is_learner(),
    "the local node is a learner (slot 2 in 2v+1l)"
  );
  drive_recovery(&mut r, &mut wal, &mut sb, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "a learner with a faulty head at a bumped epoch → RecoveringHead",
  );
  let (epoch, config_id) = (r.membership.epoch(), r.membership.config_id());
  while r.poll_message().is_some() {}
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize + 8) {
    let (from, msg) = peer_recovery(0, epoch, config_id); // a co-recovering VOTER → satisfies G2
    r.handle_message(now, &mut wal, &mut sb, &mut blocks, from, msg);
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let (from_self, msg_self) = peer_recovery(1, epoch, config_id); // slot 1 == the local slot — a self-loop
  r.handle_message(now, &mut wal, &mut sb, &mut blocks, from_self, msg_self);
  assert_eq!(
    r.recover.as_ref().map(|rec| rec.peers_recovering),
    Some(0),
    "a self-looped Recovery is not tallied (only OTHER voters count toward G2)",
  );
  let (from_other, msg_other) = peer_recovery(0, epoch, config_id); // slot 0 — a genuine OTHER voter
  r.handle_message(now, &mut wal, &mut sb, &mut blocks, from_other, msg_other);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  while r.poll_message().is_some() {}
  let start_view = r.view();
  let start_log_view = r.log_view();
  let mut now = Instant::ZERO;
  // Mature G1 WITHOUT firing: tick (REFORM_ATTEMPTS - 2) windows with no co-recovering peers, so each
  // window the intersection is empty (G2 unmet) and reform_attempts climbs. Stays RecoveringHead. Two
  // windows are left for the co-recovering feed — G2 is a TWO-window intersection (freshness guard).
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize - 2) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
    r.handle_message(now, &mut wal, &mut sb, &mut blocks, from, msg);
  }
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
    r.handle_message(now, &mut wal, &mut sb, &mut blocks, from, msg);
  }
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
  r.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while r.poll_message().is_some() {} // discard the deferred DVC / transition chatter
  now = now + VC_MESSAGE_RETRANSMIT;
  r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
  let mut blocks2 = crate::block_store::MemBlockStore::new();
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now2 = Instant::ZERO;
  let mut r2 = Endpoint::recover(
    cfg,
    genesis(3),
    0,
    NoopSm,
    &mut wal2,
    &mut sb2,
    &mut blocks2,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery(&mut r2, &mut wal2, &mut sb2, &mut blocks2, now2);
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
    r2.handle_timeout(t, &mut wal2, &mut sb2, &mut blocks2);
    while r2.poll_message().is_some() {}
  }
  // Two consecutive windows of the co-recovering quorum (the two-window intersection), then it fires.
  for _ in 0..2 {
    for slot in [0u16, 2] {
      let (from, msg) = peer_recovery(slot, epoch, config_id);
      r2.handle_message(t, &mut wal2, &mut sb2, &mut blocks2, from, msg);
    }
    t = t + RECOVER_HEAD_SOLICIT;
    r2.handle_timeout(t, &mut wal2, &mut sb2, &mut blocks2);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  while r.poll_message().is_some() {}
  let mut now = Instant::ZERO;
  // Mature G1 well past the bound with EMPTY windows — so only the missing two-window evidence can hold
  // the gate, not an unmet G1.
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize + 4) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
    r.handle_message(now, &mut wal, &mut sb, &mut blocks, from, msg);
  }
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  while r.poll_message().is_some() {}
  let mut now = Instant::ZERO;
  for _ in 0..(RECOVER_HEAD_REFORM_ATTEMPTS as usize - 1) {
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
    while r.poll_message().is_some() {}
  }
  // Window N-1: the quorum is co-recovering (tallied), then tick (it becomes `prev`).
  for slot in [0u16, 2] {
    let (from, msg) = peer_recovery(slot, epoch, config_id);
    r.handle_message(now, &mut wal, &mut sb, &mut blocks, from, msg);
  }
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
  while r.poll_message().is_some() {}
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "one window alone does not fire"
  );
  // Window N: the peers have recovered — NOTHING is tallied — then tick. fresh = 0 (empty) & prev (Q) =
  // 0 → no escalation. The prev-window evidence does not linger.
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
    // The sealed predecessor records its geometry; `prepare_restart` carries it into the successor,
    // so the recovered store is geometry-recorded (default interval + the ring-less WAL's `u64::MAX`).
    &sealed_root(2).with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX),
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb, &mut blocks)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery(&mut r, &mut wal, &mut sb, &mut blocks, now);
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
    r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
    while r.poll_message().is_some() {}
  }
  for _window in 0..2 {
    for slot in [0u16, 2] {
      let (from, msg) = peer_recovery(slot, epoch, config_id);
      r.handle_message(now, &mut wal, &mut sb, &mut blocks, from, msg);
    }
    now = now + RECOVER_HEAD_SOLICIT;
    r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb, &mut blocks)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery(&mut r, &mut wal, &mut sb, &mut blocks, now);
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
    r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
    r.handle_message(now, &mut wal, &mut sb, &mut blocks, from, msg);
  }
  now = now + RECOVER_HEAD_SOLICIT;
  r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
  while r.poll_message().is_some() {}
  // Window 2: feed the SAME quorum. The two-window intersection now holds the quorum — G2 IS satisfied.
  for slot in [0u16, 2] {
    let (from, msg) = peer_recovery(slot, epoch, config_id);
    r.handle_message(now, &mut wal, &mut sb, &mut blocks, from, msg);
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
  r.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
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
    std::vec::Vec::new(),
    OpNumber::new(),
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
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::with_checkpoint_ops(1, MemberId::new(1), crate::MAX_CHECKPOINT_OPS).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  // Force the held-frontier shape: in-memory `commit_max == op == K`, `checkpoint_op == 0`. The durable
  // root (`TestSb::default()` → `VsrState::new()`) still names the STALE commit C0 == 0 — the lag.
  e.force_state_for_test(0, k, k, 0, &[]);
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
  // The sealed predecessor records its geometry (the MAX checkpoint interval this scenario recovers
  // under + the ring-less WAL's `u64::MAX`); `prepare_restart` carries it into the successor.
  let sealed = sealed_root(k).with_wal_geometry(crate::MAX_CHECKPOINT_OPS, u64::MAX);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), crate::MAX_CHECKPOINT_OPS).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect("recover accepts this store")
  .expect_active();
  // The single-pass read window is bounded by the ring capacity (`op_head.min(checkpoint_op + capacity)` ==
  // op_head here), so the whole sealed band up to K is materialized up front — the recovered head reads up
  // to the sealed committed frontier K, not `checkpoint_op + RECOVER_TAIL_WINDOW`.
  assert_eq!(
    r.op(),
    OpNumber::with(k),
    "recover off the SEALED successor reads the full committed band (self.op == K), so K is not stranded"
  );
  for _ in 0..(k + 8) {
    r.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
fn an_unsealed_successor_reads_the_held_committed_op_but_not_its_committed_status() {
  // (c) THE SEAL'S RESIDUAL VALUE, once the recover-read window is bounded by the WAL ring `capacity`
  // (`op_head.min(checkpoint_op + capacity)`) rather than the durable commit. WITHOUT the seal the
  // successor copies the STALE durable commit C0 == 0 even though the WAL holds a committed op K =
  // RECOVER_TAIL_WINDOW + 2. Recover now reads the FULL VERIFIED held tail up to the WAL head regardless of
  // the stale commit, so K is READ + HELD (`self.op == K`, cached), NOT stranded: the committed-op loss is
  // prevented by the capacity-bounded window itself, not only by the seal (K rides its held header through
  // any later view change, exactly as a sealed-and-recovered committed tail does). What the seal still
  // buys is the KNOWN-committed frontier: a SEALED successor recovers `commit_max == K` and applies K
  // outright, whereas this UNSEALED one holds K with `commit_max` still at the stale C0 == 0 — K survives
  // but is re-committed rather than applied on recovery. This is the seal's non-vacuous, still-load-bearing
  // effect (`commit_max == K` vs `C0`), now that the read window no longer strands the op.
  let k = RECOVER_TAIL_WINDOW + 2;
  // The UNSEALED predecessor: a v4 root whose durable commit is the STALE C0 == 0, with NO committed
  // header above C0 (the band was never sealed). `prepare_restart` faithfully copies that stale commit.
  // This scenario recovers under the MAX checkpoint interval (to size the read window past `k`), so the
  // predecessor root must pin THAT geometry — a running node stamps `config.checkpoint_ops()`, and
  // recovery fences a mismatch. Re-stamp over `v4_root`'s default interval, keeping the ring-less test
  // WAL's `u64::MAX` capacity.
  let unsealed = v4_root(genesis(3), 0).with_wal_geometry(crate::MAX_CHECKPOINT_OPS, u64::MAX);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), crate::MAX_CHECKPOINT_OPS).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect("recover accepts this store")
  .expect_active();
  // The single-pass read window is bounded by the ring capacity (== op_head here), so the full held tail up
  // to K is materialized regardless of the stale durable commit C0.
  assert_eq!(
    r.op(),
    OpNumber::with(k),
    "recover reads the full held tail (self.op == K) regardless of the stale durable commit"
  );
  for _ in 0..(k + 8) {
    r.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(r.status(), Status::Normal, "recover reaches Normal");
  // #31: the capacity-bounded window reads the FULL held tail — K is NOT stranded, even off an unsealed root.
  assert_eq!(
    r.op(),
    OpNumber::with(k),
    "recover reads the held committed op K back (self.op == K) despite the stale durable commit — no loss"
  );
  assert!(
    r.log
      .get(&k)
      .is_some_and(|e| e.body.as_present() == Some(&[k as u8][..])),
    "K is read + cached with its canonical body (held), not freed for overwrite"
  );
  // The seal's RESIDUAL, still-load-bearing effect: WITHOUT it `commit_max` stays the stale C0 == 0, so K
  // is held but not KNOWN-committed (re-committed via a later view change rather than applied on recovery).
  // A SEALED successor instead recovers `commit_max == K` (the (b) test).
  assert_eq!(
    r.commit_max(),
    OpNumber::new(),
    "without the seal the recovered node's known-committed frontier stays the stale C0 == 0"
  );
}

#[test]
fn endpoint_constructs_under_the_single_change_marker() {
  // The reconfiguration capability is a COMPILE-TIME type-state: `Endpoint<S, R: Reconfig>` carries a
  // zero-sized `R` marker, so a `SingleChange` endpoint constructs by naming the marker explicitly via
  // the generic `with_reconfig` constructor. It behaves identically to a default endpoint — the marker
  // gates only the (later) reconfiguration API surface, never the consensus state — so a freshly-built
  // one is Normal at view 0. (The bare `new` is the ergonomic `RestartOnly` entry point; the explicit
  // marker rides `with_reconfig` because a struct default type parameter cannot be inferred for an
  // associated function's return type.)
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  assert_eq!(e.status(), Status::Normal, "a fresh endpoint is Normal");
  assert_eq!(e.view(), View::new(), "a fresh endpoint is at view 0");
  assert_eq!(
    e.replica(),
    ReplicaId::new(1),
    "MemberId(1) occupies slot 1 of genesis(3)",
  );
}

#[test]
fn the_default_reconfig_marker_is_restart_only() {
  // The default type parameter `R = RestartOnly` keeps the bare `Endpoint<S>` spelling resolving:
  // every existing call site (drivers, simulation, the rest of these tests) constructs `Endpoint<S>`
  // via the bare `new`/`recover` and must compile and behave UNCHANGED. The two spellings are the SAME
  // type, so a `RestartOnly` endpoint built via the generic `with_reconfig` and a defaulted one built
  // via `new` are interchangeable, and both observe the same fresh state.
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let defaulted =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let cfg2 = Config::try_new(1, MemberId::new(1)).unwrap();
  let explicit = Endpoint::<CountSm, RestartOnly>::genesis_unchecked(
    cfg2,
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  // `Endpoint<S>` IS `Endpoint<S, RestartOnly>`: this assignment type-checks only if the bare `new`
  // produced `Endpoint<CountSm, RestartOnly>` (the default) and the explicit marker is the same type.
  let _same_type: Endpoint<CountSm> = explicit;
  let _also_default: Endpoint<CountSm> = defaulted;
  assert_eq!(_also_default.status(), Status::Normal);
  assert_eq!(_also_default.view(), View::new());
  assert_eq!(_also_default.op(), OpNumber::new());
}

#[test]
fn a_reconfigure_log_entry_carries_the_successor_membership_in_memory() {
  // The in-memory `LogEntry` for a reconfiguration op keeps the proposing primary's `(client,
  // request)` identity and wraps the successor membership as a `Body::Reconfigure`, mirroring the wire
  // `PreparedEntry`. The proposing path (a later task) mints these; this pins the in-memory shape.
  let payload = crate::message::ReconfigurePayload::new(
    3,
    1,
    std::vec![
      MemberId::new(1),
      MemberId::new(2),
      MemberId::new(3),
      MemberId::new(4),
    ]
    .into_boxed_slice(),
    0,
  );
  let entry = LogEntry::reconfigure(
    crate::ClientId::new(0x42),
    crate::RequestNumber::with(7),
    payload.clone(),
  );
  assert_eq!(entry.client, crate::ClientId::new(0x42));
  assert_eq!(entry.request, crate::RequestNumber::with(7));
  assert_eq!(
    entry.body.as_reconfigure(),
    Some(&payload),
    "the in-memory body is the successor membership"
  );
  // The op's content address folds the successor membership in, exactly as the wire entry's does.
  assert_eq!(
    entry.body.body_checksum(),
    crate::message::Body::Reconfigure(payload).body_checksum(),
  );
}

// ── peer_checkpoint is keyed by stable MemberId, so a slot-shifting removal cannot poison the floors ──
//
// `peer_checkpoint` (the per-peer durable-checkpoint reports feeding the GC prune floor
// `quorum_checkpoint_op` and the force-sync floor `max_peer_checkpoint_op`) is keyed by stable
// `MemberId`. A low-index `RemoveVoter` shifts the routing slots of every higher voter; keying by the
// stable id is what keeps a REMOVED member's stale report out of both floors and a RETAINED voter's
// report attributed to THAT voter after its slot shifts — never misread as whoever now occupies its old
// slot. (If `peer_checkpoint` were slot-keyed, `install_membership` would leave the old entries in place
// and both floors would misattribute them — committed-op loss via premature GC, or a permanent sync
// wedge to a checkpoint no current donor can serve.)

/// A 5-voter primary (local `MemberId 0` at slot 0) over `NoopSm`, with its own durable checkpoint set
/// to `own_checkpoint` and the other four voter slots seeded with reports via the production recorder.
/// `reports[i]` is recorded against slot `i+1` (slots `1..=4`), keyed by the stable id at that slot.
fn primary5_with_seeded_reports(own_checkpoint: u64, reports: [u64; 4]) -> Endpoint<NoopSm> {
  let cfg = Config::try_new(0, MemberId::new(0)).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(5), 0, NoopSm, u64::MAX);
  assert!(e.is_primary(), "MemberId 0 at slot 0 is the view-0 primary");
  e.set_own_checkpoint_for_test(own_checkpoint);
  for (i, &op) in reports.iter().enumerate() {
    e.inject_peer_checkpoint_for_test((i + 1) as u8, op);
  }
  e
}

#[test]
fn a_removed_members_report_does_not_lift_the_force_sync_floor_after_a_slot_shift() {
  // Seed a HIGH report (999) from the soon-removed low-index voter `MemberId 1` (slot 1) and modest
  // reports (50) from the retained voters {2,3,4}. Own checkpoint 5.
  let mut e = primary5_with_seeded_reports(5, [999, 50, 50, 50]);
  // Pre-swap sanity: the high removed-member report DOES dominate the force-sync floor while it is a
  // current member — this is the value that MUST disappear once it is removed.
  assert_eq!(
    e.max_peer_checkpoint_op(),
    OpNumber::with(999),
    "while MemberId 1 is a current voter its report sets the force-sync floor"
  );

  // Commit-shaped low-index removal: drop `MemberId 1`. Slots close up — {0,2,3,4} now occupy {0,1,2,3}
  // — so every retained higher voter shifts down one slot. Local `MemberId 0` stays slot 0 (the primary).
  let successor = e
    .membership
    .apply_delta(&crate::SingleVoterDelta::RemoveVoter(MemberId::new(1)))
    .expect("RemoveVoter(1) on the 5-voter genesis is valid");
  e.install_membership(Some(OpNumber::with(7)), successor);
  assert_eq!(e.membership.replica_count(), 4, "shrank to 4 voters");
  assert_eq!(
    e.membership.slot_of(MemberId::new(2)),
    Some(ReplicaId::new(1)),
    "the retained voter MemberId 2 shifted from slot 2 to slot 1",
  );
  assert_eq!(
    e.membership.slot_of(MemberId::new(1)),
    None,
    "MemberId 1 is no longer a member",
  );

  // The removed member's stale 999 is keyed under `MemberId 1`, which is no longer a current member, so
  // `max_peer_checkpoint_op` (current-members-only) EXCLUDES it. The floor falls to the max retained
  // report (50) — no current donor could serve 999, and clearing a repair hole to it would wedge sync.
  // MUTATION-CHECK: a slot-keyed `peer_checkpoint` iterating `.values()` would still include the stale
  // 999 (it lives under `ReplicaId 1`) and this assert would FAIL (the floor would read 999).
  assert_eq!(
    e.max_peer_checkpoint_op(),
    OpNumber::with(50),
    "a removed member's stale report must not lift the force-sync floor after a slot shift",
  );
  // The retained voter's report FOLLOWED its stable id across the slot shift (slot 2 → slot 1).
  assert_eq!(
    e.peer_checkpoint_by_member_for_test(MemberId::new(2)),
    50,
    "the retained voter MemberId 2's report is still attributed to it after its slot shifted",
  );
  assert_eq!(
    e.peer_checkpoint_by_member_for_test(MemberId::new(1)),
    999,
    "the removed member's stale entry lingers under its own id (inert — excluded by the floor consumers)",
  );
}

#[test]
fn a_slot_shift_does_not_misattribute_a_retained_voters_quorum_report() {
  // Own checkpoint 5; the soon-removed low-index voter `MemberId 1` (slot 1) reports a LOW 5, and the
  // retained voters {2,3,4} report a HIGH 50. Under correct stable-id keying the post-removal quorum
  // floor (4 voters, quorum 3) is the 3rd-highest of {own 5, m2 50, m3 50, m4 50} = 50.
  let mut e = primary5_with_seeded_reports(5, [5, 50, 50, 50]);

  let successor = e
    .membership
    .apply_delta(&crate::SingleVoterDelta::RemoveVoter(MemberId::new(1)))
    .expect("RemoveVoter(1) on the 5-voter genesis is valid");
  e.install_membership(Some(OpNumber::with(7)), successor);

  // The retained voters' reports follow their stable ids across the one-slot shift, so the quorum-th
  // order statistic over the CURRENT voter set is 50.
  // MUTATION-CHECK: with a slot-keyed `peer_checkpoint` (no re-key on install), the post-swap loop reads
  // physical slots 0..3 untranslated — slot 1 now yields the REMOVED member's stale low 5 (misattributed
  // to the voter that shifted into slot 1), displacing a retained 50 — and the quorum floor collapses to
  // 5, failing this assert. That premature-low floor is the GC-loss hazard the re-key closes.
  assert_eq!(
    e.quorum_checkpoint_op(),
    OpNumber::with(50),
    "a retained voter's report must not be misattributed after its slot shifted",
  );
  assert_eq!(
    e.peer_checkpoint_by_member_for_test(MemberId::new(2)),
    50,
    "retained voter MemberId 2 still attributed to its own report after shifting slot 2 → slot 1",
  );
}

// CONSENSUS-CRITICAL (committed-op loss): the per-op commit-vote bitset `Inflight::oks` is slot-keyed
// and SURVIVES the in-place commit-first SwapEpoch swap (the still-Normal primary's pipeline is not
// cleared on the retained-node path). `try_commit` counts `oks.count_ones() >= membership.quorum()`
// against the NEW (post-swap, possibly SMALLER) voter set — so a REMOVED voter's stale pre-swap ack
// must NOT count toward the successor commit quorum, or a tail op minted after the Reconfigure op could
// commit + reply WITHOUT any retained backup holding it, then be lost in the E+1 view change. The swap
// re-keys `oks` by stable `MemberId` (drop the removed voter's bit), so the tail op must RE-GATHER a
// current-config quorum.
#[test]
fn a_removed_voters_pre_swap_ack_does_not_commit_a_tail_op_after_the_swap() {
  // 4-voter cluster {0,1,2,3}; local `MemberId 0` at slot 0 is the view-0 primary. We remove the
  // HIGHEST voter `MemberId 3` (slot 3) so the retained voters {0,1,2} keep their slots — isolating the
  // "removed voter's stale bit" effect from any slot shift.
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(4), 0, NoopSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  assert!(e.is_primary(), "MemberId 0 at slot 0 is the view-0 primary");
  assert_eq!(e.membership.quorum(), 3, "4 voters → old commit quorum 3");

  // Commit op 1 (a stand-in for the committed reconfigure-prefix) on the OLD quorum of 3 — own vote
  // (slot 0) + a retained backup (slot 1) + the soon-removed voter (slot 3). This advances commit_min
  // to 1, so op 2 below is the post-reconfiguration TAIL op (minted strictly after the prefix).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from(std::vec![1u8]),
    )),
  );
  assert_eq!(e.op(), OpNumber::with(1), "op 1 (prefix) is minted");
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the durable own append records the primary's own vote
  }
  let id_op1 = crate::storage::prepare_identity(
    ClientId::new(9),
    RequestNumber::with(1),
    crate::storage::fnv1a_128(&[1u8]),
  );
  for backup in [1u16, 3] {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(backup)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(1),
        ReplicaId::new(backup),
        OpNumber::new(),
        id_op1,
        Epoch::new(0),
        0,
      )),
    );
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "op 1 commits on the OLD quorum of 3 (own + slot 1 + slot 3)"
  );

  // Mint the TAIL op 2 (client 9, request 2). Pump storage so the primary's own vote (slot 0) lands.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(2),
      Bytes::from(std::vec![2u8]),
    )),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "op 2 (the post-reconfig tail) is minted"
  );
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  let id_op2 = crate::storage::prepare_identity(
    ClientId::new(9),
    RequestNumber::with(2),
    crate::storage::fnv1a_128(&[2u8]),
  );
  // The tail op gets ONE more ack — from the voter being REMOVED (slot 3). own(slot 0) + slot 3 = 2
  // bits, still BELOW the old quorum of 3, so it does NOT commit yet.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(2),
      ReplicaId::new(3),
      OpNumber::new(),
      id_op2,
      Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.inflight.get(&2).map(|i| i.oks),
    Some((1u64 << 0) | (1u64 << 3)),
    "pre-swap, the tail op carries own(slot 0) + the removed voter(slot 3)"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the tail op is below the OLD quorum of 3 (2 bits) — not committed pre-swap"
  );

  // Commit the reconfigure: REMOVE `MemberId 3`. New voter set {0,1,2}, quorum 2. The swap re-keys the
  // surviving `inflight.oks` by stable MemberId — the removed voter's slot-3 bit is DROPPED, leaving only
  // the primary's own vote.
  let successor = e
    .membership
    .apply_delta(&crate::SingleVoterDelta::RemoveVoter(MemberId::new(3)))
    .expect("RemoveVoter(3) on the 4-voter genesis is valid");
  let (new_epoch, new_config_id) = (successor.epoch(), successor.config_id());
  e.install_membership(Some(OpNumber::with(1)), successor);
  assert_eq!(e.membership.quorum(), 2, "3 voters → new commit quorum 2");

  // THE FIX: the removed voter's stale bit was dropped at the swap, so the tail op now carries only the
  // primary's own vote (1 bit) — BELOW the new quorum of 2. It does NOT commit on the post-swap quorum.
  // MUTATION-CHECK: delete the `rekey_slot_quorums_for_swap` call in `install_membership` and the stale
  // slot-3 bit survives; `count_ones() == 2 >= quorum(2)` commits the tail op here (with NO retained
  // backup holding it — committed-op loss across the E+1 view change), and this assert FAILS.
  assert_eq!(
    e.inflight.get(&2).map(|i| i.oks),
    Some(1u64 << 0),
    "the swap dropped the removed voter's slot-3 bit — only the primary's own vote remains"
  );
  e.try_commit(now, &mut sb, &mut blocks);
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the removed voter's stale ack does NOT count toward the new quorum — the tail op stays uncommitted"
  );

  // A RETAINED current-config backup (`MemberId 1`, still slot 1) acks the tail op at the NEW epoch:
  // own(slot 0) + slot 1 = 2 bits == the new quorum of 2 → the tail op commits on a CURRENT-config quorum.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(2),
      ReplicaId::new(1),
      OpNumber::new(),
      id_op2,
      new_epoch,
      new_config_id,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "a retained current-config voter's ack forms a current-config quorum → the tail op commits"
  );
}

//! The single-writer live-reconfiguration PROPOSAL path and the COMMIT-FIRST epoch swap.
//!
//! `propose_membership` mints a `Body::Reconfigure` op on the primary exactly as a client request is
//! minted (assign op, append, broadcast a `Prepare`), latches `reconfigure_inflight` so only one
//! change is in flight, and gates on primacy + a `Normal` status + a valid single-voter delta — the
//! first group of tests pins the mint, the latch, and the emitted `Prepare`.
//!
//! The second group pins the commit-first epoch swap: the Reconfigure op commits under the OLD epoch
//! (the bitsets/quorums read a stable membership across its whole lifecycle), and ONLY at commit is a
//! `SwapEpoch` durable root staged carrying the successor membership. The in-memory membership is NOT
//! swapped eagerly at commit — `install_membership` is DEFERRED to `on_sb_done` when that root is
//! durable (the durable-epoch-before-participate fence, mirroring the durable-view-before-participate
//! fence). The Reconfigure op is consensus-layer and is NEVER delivered to `S::apply`.

use super::*;
use crate::{
  Config, Event, MemberId, Message, ReplicaId, SingleVoterDelta, Status, View,
  message::ReconfigurePayload,
};

/// A 3-voter `SingleChange` endpoint whose local member is slot 0 — the primary of view 0. A fresh
/// endpoint is `Normal` at view 0, and slot 0 leads view 0, so this is the proposing primary.
fn single_change_primary() -> Endpoint<CountSm, SingleChange> {
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  Endpoint::<CountSm, SingleChange>::with_reconfig(cfg, genesis(3), 0, CountSm::default())
}

/// A 3-voter `SingleChange` endpoint whose local member is slot 1 — a BACKUP under view 0.
fn single_change_backup() -> Endpoint<CountSm, SingleChange> {
  let cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  Endpoint::<CountSm, SingleChange>::with_reconfig(cfg, genesis(3), 0, CountSm::default())
}

#[test]
fn propose_membership_on_the_primary_mints_a_reconfigure_op_and_latches_inflight() {
  let mut e = single_change_primary();
  let mut wal = TestWal::default();
  let now = Instant::ZERO;

  // The successor the delta produces — the SAME membership `propose_membership` derives via
  // `apply_delta`, so its `ReconfigurePayload` is what the op must carry.
  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter is a valid delta on a 3-voter cluster");
  let expected_payload = ReconfigurePayload::from_membership(&successor, 0);

  let before_op = e.op();
  let op = e
    .propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the primary mints the reconfiguration op");

  // The op is the head's successor and is latched as the single in-flight change.
  assert_eq!(op.get(), before_op.get() + 1, "op == old self.op + 1");
  assert_eq!(e.op(), op, "the head advanced to the minted op");
  assert_eq!(
    e.reconfigure_inflight,
    Some(op),
    "the single-writer latch holds the minted op",
  );

  // The in-memory log entry is the successor membership, content-addressed like any op.
  let entry = e.log.get(&op.get()).expect("the minted op is in the log");
  assert_eq!(
    entry.body,
    Body::Reconfigure(expected_payload.clone()),
    "the in-memory body is the successor membership",
  );

  // A `Prepare` carrying the reconfiguration body is broadcast to the backups.
  let out = e.poll_message().expect("a Prepare is emitted");
  assert!(out.to().is_backups(), "the Prepare is broadcast to backups");
  match out.into_msg() {
    Message::Prepare(p) => {
      assert_eq!(p.op(), op, "the Prepare carries the minted op");
      assert_eq!(
        p.view(),
        View::new(),
        "the Prepare carries the current view"
      );
      // The Prepare body is the canonical reconfiguration encoding: its checksum folds the successor
      // membership into the op identity exactly as the in-memory `Body::Reconfigure` does.
      assert_eq!(
        crate::storage::fnv1a_128(p.body()),
        Body::Reconfigure(expected_payload).body_checksum(),
        "the Prepare body content-addresses the successor membership",
      );
    }
    other => panic!("expected a Prepare, got {other:?}"),
  }
}

#[test]
fn propose_membership_on_a_backup_is_rejected_not_primary() {
  let mut e = single_change_backup();
  let mut wal = TestWal::default();
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::AddVoter(MemberId::new(3)),
    ),
    Err(ProposeMembershipError::NotPrimary),
    "only the primary proposes a reconfiguration",
  );
  assert_eq!(e.reconfigure_inflight, None, "no op was minted");
}

#[test]
fn propose_membership_while_not_normal_is_rejected_not_normal() {
  let mut e = single_change_primary();
  // A primary mid-recovery is not Normal — it must not mint a reconfiguration op.
  e.status = Status::Recovering;
  let mut wal = TestWal::default();
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::AddVoter(MemberId::new(3)),
    ),
    Err(ProposeMembershipError::NotNormal),
    "a non-Normal primary does not propose",
  );
  assert_eq!(e.reconfigure_inflight, None, "no op was minted");
}

#[test]
fn a_second_proposal_while_one_is_in_flight_is_rejected_already_in_flight() {
  let mut e = single_change_primary();
  let mut wal = TestWal::default();
  let now = Instant::ZERO;

  let op = e
    .propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the first proposal mints an op");

  // A second proposal while the first is uncommitted is refused — single change at a time.
  assert_eq!(
    e.propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(4))),
    Err(ProposeMembershipError::AlreadyInFlight),
    "only one reconfiguration is in flight at a time",
  );
  assert_eq!(
    e.reconfigure_inflight,
    Some(op),
    "the latch still holds the FIRST minted op",
  );
  assert_eq!(
    e.op(),
    op,
    "the head did not advance for the refused proposal"
  );
}

#[test]
fn an_invalid_delta_is_rejected_with_the_underlying_membership_error() {
  let mut e = single_change_primary();
  let mut wal = TestWal::default();
  // Removing a voter that is not a member is structurally invalid — surfaced as `Invalid`.
  match e.propose_membership(
    Instant::ZERO,
    &mut wal,
    SingleVoterDelta::RemoveVoter(MemberId::new(99)),
  ) {
    Err(ProposeMembershipError::Invalid(crate::MembershipError::UnknownMember)) => {}
    other => panic!("expected Invalid(UnknownMember), got {other:?}"),
  }
  assert_eq!(e.reconfigure_inflight, None, "no op was minted");
}

// === commit-first epoch swap ===

/// The `prepare_checksum` a backup at slot `replica` would report for the Reconfigure op carrying
/// `payload` — `prepare_identity(RECONFIGURATION, request=op, payload.body_checksum())`. A
/// content-addressed `PrepareOk` must carry exactly this, or the primary's vote gate drops it.
fn reconfigure_ack(op: u64, payload: &ReconfigurePayload, replica: u16) -> Message {
  reconfigure_ack_at(op, payload, replica, crate::Epoch::new(0), 0)
}

/// Like [`reconfigure_ack`] but stamped with an explicit `(epoch, config_id)` — for an ack cast under a
/// SUCCESSOR configuration (after an epoch swap installed E+1), where the strict ingress gate requires
/// the ack to match the primary's current epoch/config_id, not the genesis one.
fn reconfigure_ack_at(
  op: u64,
  payload: &ReconfigurePayload,
  replica: u16,
  epoch: crate::Epoch,
  config_id: u128,
) -> Message {
  Message::PrepareOk(crate::PrepareOk::new(
    View::new(),
    OpNumber::with(op),
    ReplicaId::new(replica),
    OpNumber::new(),
    crate::storage::prepare_identity(
      ClientId::RECONFIGURATION,
      RequestNumber::with(op),
      Body::Reconfigure(payload.clone()).body_checksum(),
    ),
    epoch,
    config_id,
  ))
}

/// Propose `AddVoter(3)` on a fresh 3-voter SingleChange primary and drive it to COMMIT — but stop
/// the instant it commits, BEFORE the staged `SwapEpoch` root is made durable. Returns the endpoint,
/// its storage, the minted op, and the successor membership / payload.
///
/// Commit lifecycle: propose (mint + own Prepare) → the primary's own append lands (own vote) → one
/// backup `PrepareOk` (2-of-3 quorum) → `try_commit` recognizes the Reconfigure op and stages the
/// `SwapEpoch` root. With the synchronous `TestSb`, that root write is QUEUED in `sb.done` but only
/// dispatched by a LATER `handle_storage` — so on return the epoch is NOT yet swapped (the fence).
fn proposed_and_committed_swap() -> (
  Endpoint<CountSm, SingleChange>,
  TestWal,
  TestSb,
  OpNumber,
  Membership,
  ReconfigurePayload,
) {
  let mut e = single_change_primary();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter is a valid delta on a 3-voter cluster");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  let op = e
    .propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the primary mints the reconfiguration op");
  while e.poll_message().is_some() {} // drop the broadcast Prepare
  // The primary's own WAL append lands → its own vote is recorded (1 of 3).
  e.handle_storage(now, &mut wal, &mut sb);
  // One backup ack reaches the 2-of-3 commit quorum → the op commits and stages SwapEpoch.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    reconfigure_ack(op.get(), &payload, 1),
  );
  (e, wal, sb, op, successor, payload)
}

#[test]
fn reconfigure_payload_body_round_trips_through_decode() {
  // `on_prepare` decodes a RECONFIGURATION Prepare's flat wire body back to a `ReconfigurePayload`
  // and stores a typed `Body::Reconfigure` — so the encode→decode round trip must be the identity.
  let successor = genesis(3)
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(7)))
    .unwrap();
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let bytes = payload.encode_body();
  let decoded = ReconfigurePayload::decode_body(&bytes).expect("the canonical body decodes");
  assert_eq!(
    decoded, payload,
    "encode_body ∘ decode_body is the identity"
  );
}

#[test]
fn at_commit_the_swap_is_staged_but_the_epoch_is_not_yet_swapped() {
  // The DURABLE-EPOCH-BEFORE-PARTICIPATE FENCE: at commit the node recognizes the Reconfigure op,
  // clears the in-flight latch, and STAGES a SwapEpoch root — but does NOT advance its epoch /
  // voter-set in memory. The membership stays the OLD one until the root is durable.
  let (e, _wal, _sb, op, _successor, _payload) = proposed_and_committed_swap();

  assert_eq!(
    e.commit(),
    op,
    "the Reconfigure op committed (commit_min advanced to it)"
  );
  assert_eq!(
    e.reconfigure_inflight, None,
    "the single-writer latch was cleared at commit"
  );
  assert!(
    e.pending_swap_for_test(),
    "a SwapEpoch successor is staged awaiting its durable root"
  );
  assert!(
    e.pending_sb_for_test(),
    "the SwapEpoch root write is in flight on the superblock"
  );
  // THE FENCE: the in-memory epoch / membership is STILL the old configuration.
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "the epoch is NOT swapped eagerly at commit (still the old epoch)"
  );
  assert_eq!(
    e.membership.replica_count(),
    3,
    "the voter set is unchanged until the root is durable"
  );
  assert_eq!(
    e.prev_epoch,
    crate::Epoch::new(0),
    "prev_epoch not yet moved"
  );
}

#[test]
fn the_swap_epoch_root_durably_records_the_reconfigure_op_as_committed() {
  // The durable SwapEpoch root MUST record the committed `Reconfigure` op as committed: a node that
  // recovers an E+1 membership from this root reads `state.commit()` as its `commit_max`, and the
  // durable-epoch-before-participate + exact-catch-up premise demand that a node advertising E+1
  // durably proves the reconfigure op committed. On the PRIMARY commit path `commit_max` is raised
  // only AFTER the `try_commit` loop, but the swap stages DURING the loop — so the root's `commit`
  // must be lifted to cover the just-committed op at stage time.
  let (_e, _wal, sb, op, _successor, _payload) = proposed_and_committed_swap();
  // The synchronous `TestSb` publishes the SwapEpoch root state at `submit_write`, so `sb.state()` IS
  // the durable root the primary just minted. Its `commit` proves the reconfigure op committed.
  assert!(
    sb.state().commit() >= op,
    "the durable SwapEpoch root records the reconfigure op (op {}) as committed, but its commit is {}",
    op.get(),
    sb.state().commit().get(),
  );
  // And the root's committed-band headers reach the reconfigure op: a recovering node cross-checks the
  // band against its WAL, so an omitted header would leave the committed reconfigure op unproven.
  assert!(
    sb.state()
      .committed_headers_slice()
      .iter()
      .any(|h| h.op() == op),
    "the SwapEpoch root's committed-band headers include the reconfigure op (op {})",
    op.get(),
  );
}

#[test]
fn a_recovery_from_the_swap_epoch_root_reads_the_reconfigure_op_as_committed() {
  // End-to-end: after the primary stages+writes the SwapEpoch root (but BEFORE it installs in memory),
  // a crash+recover off that durable root must read the reconfigure op as committed (`commit_max`).
  // The recovered node holds the predecessor membership (the swap was never installed), and the
  // committed reconfigure op sits durably in its log — so re-reaching it re-stages the swap. The
  // load-bearing property here is that the recovered `commit_max` covers the op (no committed-loss).
  let (_e, wal, sb, op, _successor, _payload) = proposed_and_committed_swap();
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  let (mut rwal, mut rsb) = (wal, sb);
  let recovered = Endpoint::<CountSm, SingleChange>::recover_with_reconfig(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    &mut rwal,
    &mut rsb,
  );
  let r = match recovered {
    Recovered::Active(e) => e,
    Recovered::Retired(_) => panic!("the proposer is still in the recovered membership → Active"),
  };
  assert!(
    r.commit_max() >= op,
    "recovery reads the reconfigure op (op {}) as committed (commit_max {}), so it is never lost",
    op.get(),
    r.commit_max().get(),
  );
}

#[test]
fn the_reconfigure_op_is_never_delivered_to_the_state_machine() {
  // A Reconfigure op is consensus-layer: it must NOT reach `S::apply`. Drive it to commit AND make
  // the SwapEpoch root durable, then assert the CountSm applied NOTHING for it.
  let (mut e, mut wal, mut sb, _op, _successor, _payload) = proposed_and_committed_swap();
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb); // land the SwapEpoch root → install
  assert!(
    e.sm_for_test().applied().is_empty(),
    "the Reconfigure op was never applied to the state machine"
  );
}

#[test]
fn on_the_durable_root_the_epoch_swaps_and_membership_changed_is_emitted() {
  // Once the SwapEpoch root lands, `install_membership` runs: epoch == old+1, prev_epoch == old, the
  // successor membership is active, and a `MembershipChanged` event is emitted.
  let (mut e, mut wal, mut sb, op, successor, _payload) = proposed_and_committed_swap();
  // Drain any pre-swap events (the committed-op band, etc.) so the swap event is observable cleanly.
  while e.poll_event().is_some() {}

  e.handle_storage(Instant::ZERO, &mut wal, &mut sb); // land the SwapEpoch root

  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the epoch swapped to old + 1 once the root is durable"
  );
  assert_eq!(
    e.prev_epoch,
    crate::Epoch::new(0),
    "prev_epoch is the old epoch (the lineage backward link)"
  );
  assert_eq!(
    e.membership, successor,
    "the successor membership (4 voters, chained config_id) is now active"
  );
  assert_eq!(
    e.membership.replica_count(),
    4,
    "the new voter is in the set"
  );
  assert!(
    !e.pending_swap_for_test(),
    "the staged successor was consumed by the install"
  );

  // A MembershipChanged event names the committing op, the new epoch, and the new config_id.
  let ev = e
    .poll_event()
    .expect("a MembershipChanged event is emitted at the durable swap");
  match ev {
    Event::MembershipChanged(changed) => {
      assert_eq!(changed.op(), op, "the event names the committing op");
      assert_eq!(changed.epoch(), crate::Epoch::new(1), "the new epoch");
      assert_eq!(
        changed.config_id(),
        successor.config_id(),
        "the new config_id"
      );
      // The role is derived purely from the new committed membership: the retained primary stays a voter.
      assert!(
        changed.self_is_voter(),
        "the retained primary is a voter in the new configuration"
      );
      assert!(!changed.self_is_learner(), "a voter is not also a learner");
    }
    other => panic!("expected MembershipChanged, got {other:?}"),
  }
}

#[test]
fn the_durable_swap_forces_a_checkpoint_so_the_cross_epoch_serve_gate_holds() {
  // The live epoch swap FORCES a checkpoint at the first post-swap `commit_min` (M >= N), so the new
  // epoch begins at a checkpoint that EMBEDS the reconfigure op N and carries the E+1 membership. That
  // makes the cross-epoch state-sync serve gate `checkpoint_op (M) >= config_install_op (N)` true BY
  // CONSTRUCTION — a quiescent donor can never withhold the E+1 membership from a cross-epoch laggard.
  let (mut e, mut wal, mut sb, op, _successor, _payload) = proposed_and_committed_swap();
  let now = Instant::ZERO;

  // No checkpoint precedes the swap: the lone reconfigure op (op 1) sits far below the default cadence
  // boundary, so any checkpoint that lands is the FORCED one.
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::new(),
    "no ordinary-cadence checkpoint has fired yet"
  );

  // Land the SwapEpoch root → `install_membership` sets `config_install_op = N`, then `force_checkpoint`
  // submits the owed checkpoint at `commit_min` (== N here).
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.config_install_op, op,
    "the install recorded the reconfigure op as config_install_op = N"
  );
  // Drain the two-write forced checkpoint (snapshot → durable root) to completion.
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb);
  }

  assert!(
    e.checkpoint_op() >= e.config_install_op,
    "a forced checkpoint landed at the reconfigure op: checkpoint_op {} >= config_install_op {}",
    e.checkpoint_op().get(),
    e.config_install_op.get(),
  );
  assert_eq!(
    e.checkpoint_op(),
    op,
    "the forced checkpoint is at M == N (commit_min at swap time)"
  );
}

#[test]
fn a_speculative_cross_epoch_reply_is_deferred_while_a_swap_epoch_root_is_in_flight() {
  // Finding 1 — the SINGLE-SUPERBLOCK-WRITER fence at the sync-answer ingress. A Normal speculative
  // cross-epoch sync must NOT stage its `pending_install`/`SyncRepersist` while THIS node's OWN
  // reconfigure commit has a `SwapEpoch` root in flight: that root's completion (`on_sb_done`'s SwapEpoch
  // arm) UNCONDITIONALLY forces a checkpoint, which would OVERWRITE the sync's `pending_checkpoint`
  // tracker and ORPHAN the staged `pending_install` (a permanent outstanding sync). So the sync answer is
  // DEFERRED while `pending_sb` is set, the sync stays armed (forced + crossing-required + target), and a
  // re-solicited reply installs the crossing cleanly once the SwapEpoch root + its forced checkpoint land.
  //
  // The node's OWN swap goes to E+1; the speculative sync crosses BEYOND it to E+2 (a further
  // reconfiguration the cluster already ran), so the re-solicited reply genuinely INSTALLS a crossing (to
  // E+2) rather than being subsumed by the node's own E+1 swap. The node is a BACKUP so the install lands
  // without a primary step-down.
  let n1: u64 = 1; // the node's own reconfigure op (E -> E+1)
  let m2: u64 = 2; // the E+2 cluster crossing checkpoint (> the node's forced E+1 checkpoint at M1 == N1)
  let genesis_mem = genesis(3);
  let successor_e1 = genesis_mem
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid (E+1)");
  let successor_e2 = successor_e1
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(4)))
    .expect("a second AddVoter off the E+1 successor is valid (E+2)");

  // A Normal BACKUP (slot 1) that committed its OWN reconfigure op N1 (op == commit_min == N1), checkpoint 0.
  let cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  let mut e = Endpoint::<CountSm>::new(cfg, genesis_mem.clone(), 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.force_state_for_test(0, n1, n1, 0, &[]);

  // STAGE the node's own E+1 swap → it submits the SwapEpoch durable root (queued on the synchronous
  // `TestSb`, dispatched only by a later `handle_storage`), so `pending_sb` is the in-flight SwapEpoch root.
  e.stage_epoch_swap(OpNumber::with(n1), successor_e1.clone(), &mut sb);
  assert!(
    e.pending_swap_for_test(),
    "the node's own E+1 swap is staged awaiting its durable root"
  );
  assert!(
    e.pending_sb_for_test(),
    "the SwapEpoch root write is in flight on the superblock"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "the durable-epoch-before-participate fence: still the OLD epoch until the root lands"
  );

  // Arm a speculative cross-epoch sync toward E+2 (target = the E+2 crossing checkpoint M2). Models the
  // node having heard a higher-epoch (E+2) hint while its own E+1 swap root is still in flight.
  e.arm_cross_epoch_sync_for_test(m2);
  let nonce = e.sync_nonce_for_test();

  // --- THE DEFER: an E+2 successor-membership SyncCheckpoint arrives WHILE the SwapEpoch root is in flight. ---
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(m2),
    &std::collections::BTreeMap::new(),
    &CountSm::default().snapshot(),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  let membership_body =
    ReconfigurePayload::from_membership(&successor_e2, successor_e1.config_id()).encode_body();
  let cross_msg = |nonce: u64| {
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(m2),
      cross_id,
      successor_e2.epoch(),
      successor_e2.config_id(),
      ReplicaId::new(0),
      nonce,
      cross_env.clone(),
      membership_body.clone(),
    ))
  };
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    cross_msg(nonce),
  );
  assert!(
    e.pending_install.is_none(),
    "the sync answer was DEFERRED while the SwapEpoch root is in flight — nothing staged (no orphaned install)"
  );
  assert!(
    e.pending_checkpoint.is_none(),
    "no SyncRepersist checkpoint was staged either (the defer is BEFORE the two-write submit)"
  );
  assert_eq!(
    e.state_syncs_applied(),
    0,
    "no sync installed during the defer window"
  );
  assert!(
    e.sync_is_forced_for_test()
      && e.sync_requires_cross_epoch_for_test()
      && e.sync_target_for_test() == Some(m2),
    "the cross-epoch sync stays ARMED (forced + crossing-required + target) for the re-fetch once the root lands"
  );

  // --- Land the SwapEpoch root → install E+1 → its UNCONDITIONAL forced checkpoint at M1 == N1 lands. ---
  e.handle_storage(now, &mut wal, &mut sb); // SwapEpoch root → install_membership(N1) + force_checkpoint
  assert_eq!(
    e.membership.epoch(),
    successor_e1.epoch(),
    "the node's own swap installed E+1"
  );
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb); // drain the forced checkpoint (snapshot -> root)
  }
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(n1),
    "the forced checkpoint landed at M1 == N1 (the SwapEpoch arm's checkpoint), superblock now FREE"
  );
  assert!(
    !e.pending_sb_for_test() && e.pending_checkpoint.is_none(),
    "no superblock root is in flight after the swap-checkpoint completes"
  );

  // --- THE RE-SOLICIT: the same crossing reply now installs cleanly — crosses E+1 -> E+2. ---
  let nonce2 = e.sync_nonce_for_test(); // the still-armed sync's (unchanged) nonce
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    cross_msg(nonce2),
  );
  assert!(
    e.pending_install.is_some(),
    "with the root cleared, the re-solicited reply STAGED the crossing install (no longer deferred)"
  );
  for _ in 0..3 {
    e.handle_storage(now, &mut wal, &mut sb); // the two-write re-persist -> durable root -> install
  }
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the crossing install completed cleanly — no stuck pending_install"
  );
  assert!(
    e.pending_install.is_none(),
    "the install drained — no orphaned pending_install survived the defer"
  );
  assert_eq!(
    e.membership, successor_e2,
    "the laggard CROSSED to E+2 via the speculative sync, beyond its own E+1 swap"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(m2),
    "the crossing committed through the E+2 crossing checkpoint M2"
  );
}

#[test]
fn a_cross_epoch_crossing_consumes_a_locally_staged_swap_so_no_stale_swap_re_fires() {
  // DURABLE-LINEAGE-CORRUPTION regression. A replica can COMMIT its OWN `Reconfigure` op N (E0->E1) and
  // stage `pending_swap` (the E1 successor), then enter a non-Normal state BEFORE its SwapEpoch root
  // installs. A higher-epoch heartbeat in that state routes through `enter_cross_epoch_peer_fetch`, which
  // PRESERVES `pending_swap` (`reset_for_view_transition` keeps the committed change). The verified
  // cross-epoch `SyncCheckpoint` then installs the SAME successor HERE via `install_membership(None, E1)`
  // (the crossing), advancing `self.membership` to E1 while the stale E0->E1 `pending_swap` sits intact.
  //
  // The BUG: after the sync root completes, `on_sb_done`'s tail `maybe_swap_epoch` would re-submit that
  // STALE SwapEpoch against the now-already-E1 membership — minting a DUPLICATE SwapEpoch root stamped
  // with the live E1 config as its OWN predecessor, pushing E1's predecessor (genesis) into the lineage
  // ring a SECOND time, emitting a bogus `MembershipChanged`, and evicting legitimate older ancestors.
  //
  // The FIX is two complementary parts: (1) `maybe_swap_epoch` validates the staged successor still
  // CHAINS from the live config (`recompute_config_id(.., self.membership.config_id()) ==
  // successor.config_id()`) and DROPS a stale swap; (2) the crossing install CONSUMES `pending_swap`
  // directly. This test pins that the crossing leaves NO second SwapEpoch root, NO double lineage push,
  // NO bogus `MembershipChanged`, and the legitimate ancestors are retained.
  let n1: u64 = 2; // the node's OWN reconfigure op N (E0 -> E1); committed band is ops (0 .. N].
  let genesis_mem = genesis(3);
  let successor_e1 = genesis_mem
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid (E+1)");
  let genesis_config_id = genesis_mem.config_id();

  // A BACKUP (slot 1) at E0, Normal, that committed its own reconfigure op N (op == commit_min == N),
  // checkpoint 0 — the commit-first window where the SwapEpoch root has NOT yet installed.
  let cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  let mut e = Endpoint::<CountSm>::new(cfg, genesis_mem.clone(), 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.force_state_for_test(0, n1, n1, 0, &[]);

  // STAGE the node's OWN E0->E1 swap (submits the SwapEpoch root; `pending_swap` latched).
  e.stage_epoch_swap(OpNumber::with(n1), successor_e1.clone(), &mut sb);
  assert!(
    e.pending_swap_for_test(),
    "the node's own E1 swap is staged"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "the durable-epoch-before-participate fence: still E0 until the root lands"
  );
  // The genesis lineage ring is seeded with the genesis id in every slot (the `with_reconfig` seed).
  assert_eq!(
    e.lineage_ring_for_test(),
    [genesis_config_id; crate::endpoint::LINEAGE_RING],
    "pre-crossing: the genesis lineage ring",
  );

  // A higher-epoch heartbeat in a non-Normal state routes the laggard into the cross-epoch peer-fetch.
  // `enter_cross_epoch_peer_fetch` clears the in-flight SwapEpoch root (its stale completion is ignored)
  // but PRESERVES `pending_swap` via `reset_for_view_transition` — the exact precondition of the bug.
  e.enter_cross_epoch_peer_fetch(now, OpNumber::with(n1));
  assert!(
    e.pending_swap_for_test(),
    "the cross-epoch peer-fetch PRESERVES the staged swap (reset_for_view_transition keeps it)",
  );
  assert!(
    !e.pending_sb_for_test(),
    "the in-flight SwapEpoch root was cleared by the peer-fetch entry",
  );
  assert!(
    e.status() == Status::Recovering && e.sync_requires_cross_epoch_for_test(),
    "the laggard is Recovering with a forced crossing-required sync armed",
  );

  // The verified crossing SyncCheckpoint: the E1 successor (the SAME one the staged swap holds),
  // chained off the genesis predecessor (config_id 0), at the crossing op N. `apply_sync` reconstructs
  // + VERIFIES it (the config_id hash-chain), so this is the cross-epoch crossing install.
  let nonce = e.sync_nonce_for_test();
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(n1),
    &std::collections::BTreeMap::new(),
    &CountSm::default().snapshot(),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  let membership_body =
    ReconfigurePayload::from_membership(&successor_e1, genesis_config_id).encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(n1),
      cross_id,
      successor_e1.epoch(),
      successor_e1.config_id(),
      ReplicaId::new(0),
      nonce,
      cross_env.clone(),
      membership_body.clone(),
    )),
  );
  assert!(
    e.pending_install.is_some(),
    "the crossing reply STAGED the install (a forced crossing-required sync admits it)",
  );

  // Drive the two-write re-persist to its durable root → `install_sync` runs `install_membership(None,
  // E1)` (the crossing) and (the FIX) consumes the stale `pending_swap`; then `on_sb_done`'s tail
  // `maybe_swap_epoch` runs against the now-E1 membership.
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb);
  }

  // The crossing landed: E1 is installed, the sync completed exactly once.
  assert_eq!(
    e.membership, successor_e1,
    "the laggard CROSSED to E1 via the verified sync",
  );
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the crossing install completed exactly once",
  );

  // (1) NO stale staged swap survives the crossing — the staged E0->E1 swap was consumed.
  assert!(
    !e.pending_swap_for_test(),
    "the crossing CONSUMED the stale staged swap — none remains to re-fire",
  );
  // (2) NO second SwapEpoch root: with the swap consumed, the superblock is idle — no write in flight.
  assert!(
    !e.pending_sb_for_test() && e.pending_checkpoint.is_none(),
    "no SwapEpoch (nor any) root is in flight after the crossing — the stale swap did NOT re-submit",
  );
  // (3) The genesis (E1's predecessor) is pushed into the lineage ring EXACTLY ONCE (by the crossing
  // install), NOT a second time by a re-fired stale swap. A double push would shift genesis into a
  // SECOND ring slot, evicting an older ancestor. The post-crossing ring keeps genesis at slot 0 and
  // the retained genesis tail below it (the seed) — never two distinct pushes of the same predecessor.
  assert_eq!(
    e.lineage_ring_for_test(),
    [genesis_config_id; crate::endpoint::LINEAGE_RING],
    "the lineage ring is pushed once (genesis -> slot 0); no second stale-swap push evicts an ancestor",
  );
  assert!(
    e.in_lineage_for_test(genesis_config_id),
    "the legitimate genesis ancestor is still admissible (no eviction)",
  );

  // (4) NO bogus `MembershipChanged`: a cross-epoch crossing install emits none (the laggard synced PAST
  // the Reconfigure op), and the consumed stale swap emits none either. Only `StateSyncCompleted`.
  let mut saw_membership_changed = false;
  let mut saw_state_sync_completed = false;
  while let Some(ev) = e.poll_event() {
    match ev {
      Event::MembershipChanged(_) => saw_membership_changed = true,
      Event::StateSyncCompleted(_) => saw_state_sync_completed = true,
      _ => {}
    }
  }
  assert!(
    !saw_membership_changed,
    "NO MembershipChanged: the crossing install names no local op, and the stale swap did not re-fire",
  );
  assert!(
    saw_state_sync_completed,
    "the crossing is observable via StateSyncCompleted (the legitimate signal)",
  );
}

#[test]
fn recovery_pays_the_checkpoint_debt_with_no_traffic() {
  // The restart-survivable half of the swap-checkpoint: a crash BETWEEN the SwapEpoch root and the forced
  // checkpoint leaves a durable root with the E+1 membership AHEAD of the checkpoint — `config_install_op = N` but
  // `checkpoint_op < N`. That self-describing DEBT must DRIVE ITSELF to closure on recover with ZERO
  // subsequent traffic (a quiescent recovered donor has no Commit heartbeat to advance it), or it
  // withholds the E+1 membership forever. `recover` (a) drives the committed band to `>= N`, then (b)
  // forces the owed checkpoint, so `checkpoint_op >= config_install_op` becomes durable unassisted.
  let n = 2u64; // the reconfigure op N — the committed band is ops (0 .. N].
  let genesis_mem = genesis(3);
  let successor = genesis_mem
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter is a valid delta on a 3-voter cluster");

  // The committed-band headers the durable root names — ops 1..=N, matching the WAL bodies `[op]` that
  // `ScriptedWal::with_entries` writes (so recovery's band cross-check passes and the bodies fill).
  let mk_header = |op: u64| {
    crate::Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  // The durable SwapEpoch root captured in the crash window: the SUCCESSOR membership is active
  // (epoch 1), `config_install_op = N`, but `checkpoint_op = 0` — the checkpoint is BELOW N (the debt).
  // `commit = N` records that the band through N is committed, so recovery carries the frontier and
  // re-applies the band.
  let swap_root = crate::VsrState::try_new_v4(
    View::new(),
    View::new(),
    OpNumber::with(n), // commit — the band through N is known committed
    OpNumber::new(),   // checkpoint_op = 0 — BELOW N: the debt
    0,                 // genesis checkpoint id (no snapshot to read)
    std::vec![mk_header(1), mk_header(2)],
    successor.epoch(),
    genesis_mem.epoch(),
    successor.clone(),
    std::vec![genesis_mem.config_id()],
    OpNumber::with(n), // config_install_op = N, ABOVE the checkpoint
  )
  .expect("a SwapEpoch root carrying config_install_op above its checkpoint is valid");

  // Recover replica 1 — a BACKUP of view 0 in the successor (slot 0 leads), so `complete_recovery`
  // resumes Normal (NOT the abdicate-to-view-change primary branch) and pays the debt immediately.
  let cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  let mut wal = ScriptedWal::with_entries(n); // ops 1..=N held, clean reads
  let mut sb = TestSb {
    state: swap_root,
    done: std::collections::VecDeque::new(),
    checkpoint: None, // checkpoint_op == 0 → no snapshot; recover restores the genesis SM
  };
  let now = Instant::ZERO;
  let mut e =
    Endpoint::<CountSm>::recover(cfg, genesis_mem, 9, CountSm::default(), &mut wal, &mut sb)
      .expect_active();

  // The recovered node is in the debt window: at the successor epoch, gate owed.
  assert_eq!(
    e.config_install_op,
    OpNumber::with(n),
    "recover restores config_install_op = N from the durable root"
  );

  // Drive the recovery reads to completion — this reaches Normal AND runs `maybe_pay_checkpoint_debt`
  // from `complete_recovery`, which proactively advances the band and forces the owed checkpoint. After
  // this point there is NO further traffic: ONLY recovery storage completions are pumped.
  drive_recovery(&mut e, &mut wal, &mut sb, now);
  assert_eq!(e.status(), Status::Normal, "the backup resumed Normal");

  // With ZERO messages/heartbeats, the band was driven to >= N (the debt-pay's proactive advance_commit).
  assert!(
    e.commit().get() >= n,
    "the debt drove commit_min to >= N ({}) with no traffic",
    e.commit().get()
  );

  // Pump the forced checkpoint's two superblock writes (snapshot → root) to durability — still NO
  // messages. The debt clears the instant `checkpoint_op >= config_install_op` is durable.
  for _ in 0..6 {
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert!(
    e.checkpoint_op() >= e.config_install_op,
    "the debt is PAID with no traffic: checkpoint_op {} >= config_install_op {} (a donor can now serve E+1)",
    e.checkpoint_op().get(),
    e.config_install_op.get(),
  );
}

#[test]
fn a_second_proposal_in_the_committed_swap_window_is_rejected_already_in_flight() {
  // The single-change-at-a-time contract spans propose THROUGH install, not just propose-through-commit.
  // After the first reconfiguration COMMITS, `stage_epoch_swap` clears `reconfigure_inflight` — but the
  // staged `pending_swap` (and its in-flight SwapEpoch root) are still outstanding. A second proposal
  // here must STILL be refused: if it committed before the first installed, `stage_epoch_swap` would
  // overwrite the first's staged successor and the first `on_sb_done` would clear the second — losing
  // the second committed swap across the epoch boundary.
  let (mut e, mut wal, mut sb, _op, _successor, _payload) = proposed_and_committed_swap();
  let now = Instant::ZERO;

  // The first change committed + staged its swap; the proposal latch is already clear, but the
  // committed-but-not-installed swap is outstanding (the SwapEpoch root is in flight).
  assert_eq!(
    e.reconfigure_inflight, None,
    "the proposal latch cleared at commit"
  );
  assert!(
    e.pending_swap_for_test(),
    "a committed-but-not-installed swap is outstanding"
  );

  // A second proposal in this window is refused — the swap window keeps the single change in flight.
  assert_eq!(
    e.propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(4))),
    Err(ProposeMembershipError::AlreadyInFlight),
    "a second reconfiguration is refused while the first's swap is committed-but-not-installed",
  );

  // Once the swap INSTALLS (the SwapEpoch root lands), the window closes and a new proposal succeeds.
  e.handle_storage(now, &mut wal, &mut sb); // land the SwapEpoch root → install
  assert!(
    !e.pending_swap_for_test(),
    "the swap installed — the window is closed"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the first change installed (E+1)"
  );
  // A fresh single change is now proposable. (Member 4 is a fresh voter id on the new 4-voter config.)
  let next = e.propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(4)));
  assert!(
    next.is_ok(),
    "after the first swap installs, a new reconfiguration is admitted: {next:?}",
  );
}

#[test]
fn a_carried_uncommitted_reconfigure_blocks_a_new_proposal_after_a_view_change() {
  // CONSENSUS-SAFETY: an uncommitted `Reconfigure` op that rides the canonical log into a NEW view
  // must keep blocking a second reconfiguration until it re-commits. `reset_for_view_transition` clears
  // the `reconfigure_inflight` latch, and `start_view_as_new_primary` rebuilds the uncommitted-tail
  // `inflight` WITHOUT re-latching a carried `Reconfigure` op — so a latch-only gate would let the new
  // primary mint a SECOND reconfiguration before the first re-commits, overlapping two changes across the
  // epoch boundary. The structural gate (`has_pending_reconfigure`, which reads the uncommitted log tail)
  // is what forecloses it. Here replica 1 becomes primary of view 1 and adopts an uncommitted `Reconfigure`
  // op (op 2) carried ONLY by replica 2's DVC; replica 1's own DVC holds op 0, so op 2 is peer-learned.
  let mut e = Endpoint::<CountSm, SingleChange>::with_reconfig(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  // The carried op's successor membership, chained off the genesis config (config_id 0 in the fixture) —
  // exactly what the original proposer pinned. The DVC carries this as a typed `Body::Reconfigure` entry.
  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter is a valid delta on a 3-voter cluster");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  // (1) Drive replica 1 into ViewChange(1): its idle timer proposes, one peer's SVC reaches the SVC
  // quorum (2 of 3).
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}

  // (2) A DVC from replica 2 carries op 1 (committed) + op 2 (the uncommitted `Reconfigure`). commit* = 1,
  // so op 2 is adopted as the uncommitted tail. The new primary forms its view carrying the Reconfigure.
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::reconfigure(
        OpNumber::with(2),
        ClientId::RECONFIGURATION,
        RequestNumber::with(2),
        payload.clone(),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  assert!(e.is_primary(), "replica 1 is now the primary of view 1");
  assert_eq!(e.op(), OpNumber::with(2), "the Reconfigure op was adopted");
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "op 1 applied; the carried Reconfigure op 2 is still uncommitted"
  );

  // THE LATCH IS GONE (the hazard's precondition): `reset_for_view_transition` cleared it and the adoption path did
  // not re-latch a carried Reconfigure. A latch-only gate would now (wrongly) admit a second proposal.
  assert_eq!(
    e.reconfigure_inflight, None,
    "the proposal latch did NOT survive the view change (the hazard's precondition)"
  );
  assert!(
    !e.pending_swap_for_test(),
    "no committed-but-not-installed swap exists (the carried op never committed)"
  );
  // The STRUCTURAL truth still holds: the uncommitted log tail carries the Reconfigure op.
  assert!(
    e.has_pending_reconfigure_for_test(),
    "the carried uncommitted Reconfigure is recognized as in-flight from the log, not the latch"
  );
  assert_eq!(
    e.log
      .get(&2)
      .expect("op 2 is in the new primary's log")
      .body,
    Body::Reconfigure(payload),
    "the carried op rode the canonical log as a typed Body::Reconfigure",
  );

  // Drain the new-primary storage so it is a settled Normal primary (the durable-view write lands), then
  // a fresh proposal MUST be refused — the carried change is still in flight (TODAY this wrongly succeeds).
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  assert!(e.is_primary() && e.status().is_normal());
  assert_eq!(
    e.propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(4))),
    Err(ProposeMembershipError::AlreadyInFlight),
    "a second reconfiguration is refused while a carried uncommitted Reconfigure rides the new view",
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "the refused proposal minted no op (the head did not advance)"
  );
}

/// A `SingleChange` new primary of view 1 (replica 1 of 3) left in the DURABLE-VIEW-before-participate
/// window: status `Normal`, primary, but its `StartViewAsPrimary` superblock write is STILL in flight
/// (the `StepSb` has not flushed it), so `pending_durable_view()` holds. The op-2 AdoptVote WAL append
/// has completed (storage pumped) so only the view write keeps the window open. Mirrors the non-reconfig
/// `primed_new_primary_in_pending_view_window`, with the `SingleChange` capability so `propose_membership`
/// is in scope.
fn single_change_primed_new_primary_pending_view()
-> (Endpoint<CountSm, SingleChange>, TestWal, StepSb) {
  let mut e = Endpoint::<CountSm, SingleChange>::with_reconfig(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
  );
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b"),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  e.handle_storage(now, &mut wal, &mut sb); // op-2 AdoptVote append completes; the view write stays inflight
  while e.poll_message().is_some() {}
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert!(
    e.pending_durable_view_for_test(),
    "the durable-view write is still pending (the window is open)"
  );
  (e, wal, sb)
}

#[test]
fn propose_membership_while_a_durable_view_write_is_pending_is_a_retryable_busy() {
  // CONSENSUS-SAFETY: `propose_membership` must honour the SAME op-admission fences `on_request`
  // does — here the durable-view-before-participate fence. A proposal that minted straight through a
  // pending view-CHANGING superblock write would advertise a `Prepare` for a view this node has not yet
  // durably entered (and could roll back on crash) — the exact violation the fence exists to prevent.
  // The verdict is RETRYABLE (`Busy`), so the caller retries once the view is durable, NOT a permanent
  // rejection. (Op 2 is an uncommitted plain client op here, NOT a reconfiguration, so the refusal is the
  // admission fence — not `AlreadyInFlight`.)
  let (mut e, mut wal, mut sb) = single_change_primed_new_primary_pending_view();
  let now = Instant::ZERO;
  let head_before = e.op();

  assert_eq!(
    e.propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(3))),
    Err(ProposeMembershipError::Busy),
    "a proposal during the durable-view window is refused retryably, not minted",
  );
  assert_eq!(
    e.op(),
    head_before,
    "no op was minted (the head did not advance)"
  );
  assert_eq!(
    e.reconfigure_inflight, None,
    "the proposal was refused before any latch was set"
  );

  // Once the durable-view write LANDS (the window closes), a fresh proposal is admitted — proving the
  // `Busy` verdict was a transient retry signal, not a permanent rejection. Flush the SB then drain.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  assert!(
    !e.pending_durable_view_for_test(),
    "the durable-view write landed — the window is closed"
  );
  // The committed prefix must be applied for the proposal to pass `on_request`'s commit-gap fence too;
  // drive op 2 to commit (a backup ack) so the proposal is unambiguously admitted on the open path.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    client_ack(2, 2),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  let admitted = e.propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(3)));
  assert!(
    admitted.is_ok(),
    "after the durable-view write lands and the prefix applies, the proposal is admitted: {admitted:?}",
  );
}

#[test]
fn a_client_request_bearing_the_reserved_reconfiguration_id_is_dropped_at_ingress() {
  // CONSENSUS-SAFETY (the reserved-client ingress fence): [`ClientId::RECONFIGURATION`] is the high
  // sentinel under which the cluster mints its INTERNAL `Body::Reconfigure` ops via `propose_membership`.
  // Nothing makes it a real client, so no genuine client `Request` ever carries it. If `on_request`
  // accepted one, the primary would mint it as an ordinary `Body::Present` op and broadcast a `Prepare`
  // under the reserved id; every backup would reconstruct that prepare's bytes via `from_committed_body`
  // (which keys on this id) as a typed `Body::Reconfigure` and, on commit, STAGE a membership change —
  // while the primary applied the same op as a state-machine command. That BYPASSES `propose_membership`
  // entirely (the AddVoter XI-b gate, the PromoteLearner catch-up gate, the single-change gate, the
  // predecessor-delta validation, the single-writer latch) and forks the committed log (the same op typed
  // `Present` on the primary and `Reconfigure` on the backups). The fence DROPS it at ingress.
  //
  // The body is a VALID `ReconfigurePayload` encoding (the worst case: were it accepted and type-erased,
  // backups would decode it cleanly into a real membership swap), so the test exercises the genuine
  // hazard, not a malformed-body short-circuit.
  let mut e = single_change_primary();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  // A decodable reconfigure body (the AddVoter(3) successor, chained off the current config — exactly
  // what `propose_membership` would encode), wrapped in a client `Request` under the reserved id.
  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter is a valid delta on a 3-voter cluster");
  let payload = ReconfigurePayload::from_membership(&successor, e.membership.config_id());
  let reserved_body = payload.encode_body();

  let head_before = e.op();
  let epoch_before = e.membership.epoch();
  let config_id_before = e.membership.config_id();
  assert!(
    e.is_primary() && e.status().is_normal(),
    "precondition: Normal primary that would mint"
  );

  // (1) DIRECT client path: a client sends the reserved-id request straight to the primary.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::RECONFIGURATION),
    Message::Request(Request::new(
      ClientId::RECONFIGURATION,
      RequestNumber::with(1),
      reserved_body.clone(),
    )),
  );
  assert_eq!(
    e.op(),
    head_before,
    "the reserved-id request minted NO op (the head did not advance)"
  );
  assert!(
    e.poll_message().is_none(),
    "no Prepare and no Reply is emitted for a reserved-id client request"
  );
  assert_eq!(
    e.reconfigure_inflight, None,
    "no single-writer reconfiguration latch was set (propose_membership was bypassed)"
  );
  assert!(
    e.session_request_for_test(ClientId::RECONFIGURATION.get())
      .is_none(),
    "no session row was minted under the reserved client id"
  );

  // (2) REPLICA-RELAYED client path: a voting replica forwards the same reserved-id request (the
  // mesh-relay ingress, tagged with the relaying replica's id, not the client's). Same drop.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::Request(Request::new(
      ClientId::RECONFIGURATION,
      RequestNumber::with(1),
      reserved_body,
    )),
  );
  assert_eq!(
    e.op(),
    head_before,
    "the relayed reserved-id request minted NO op either"
  );
  assert!(
    e.poll_message().is_none(),
    "no Prepare and no Reply for the relayed reserved-id request"
  );
  assert_eq!(
    e.reconfigure_inflight, None,
    "still no reconfiguration latch"
  );

  // No membership change was committed OR staged from either request: the epoch/config_id are unchanged
  // and the committed log holds no Reconfigure op (drive any queued storage first so a would-be staged
  // swap would have surfaced).
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  assert_eq!(
    e.membership.epoch(),
    epoch_before,
    "the membership epoch is unchanged — no reconfiguration installed"
  );
  assert_eq!(
    e.membership.config_id(),
    config_id_before,
    "the config_id is unchanged — no reconfiguration installed"
  );
  assert!(
    e.committed_reconfigure_op_numbers().is_empty(),
    "no Reconfigure op was committed from a reserved-id client request"
  );

  // PROOF the fence is the cause, not a coincidentally-empty primary: the SAME endpoint still mints a
  // genuine client op (a non-reserved id) — so the drop is specific to the reserved sentinel, not a
  // wedged/closed mint path.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from(std::vec![1u8]),
    )),
  );
  assert!(
    e.op().get() > head_before.get(),
    "a genuine (non-reserved) client request DOES mint — the fence is specific to the reserved id"
  );
}

/// A WAL that reports ZERO ring capacity — so minting ANY op above the prune floor trips the
/// stall-before-wrap admission fence (`unpruned_window > capacity()`). Appends still land (the test only
/// needs the capacity verdict), mirroring `RingWal` with a degenerate capacity.
#[derive(Default)]
struct ZeroCapWal {
  inner: TestWal,
}
impl Wal for ZeroCapWal {
  fn op_head(&self) -> OpNumber {
    self.inner.op_head()
  }
  fn capacity(&self) -> u64 {
    0
  }
  fn header(&self, op: OpNumber) -> Option<Header> {
    self.inner.header(op)
  }
  fn status(&self, op: OpNumber) -> SlotStatus {
    self.inner.status(op)
  }
  fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes) {
    self.inner.submit_append(id, op, header, body)
  }
  fn submit_read(&mut self, id: OpId, op: OpNumber) {
    self.inner.submit_read(id, op)
  }
  fn truncate(&mut self, above: OpNumber) {
    self.inner.truncate(above)
  }
  fn prune(&mut self, below: OpNumber) {
    self.inner.prune(below)
  }
  fn poll(&mut self) -> Option<WalDone> {
    self.inner.poll()
  }
}

#[test]
fn propose_membership_at_wal_capacity_is_a_retryable_at_capacity() {
  // CONSENSUS-SAFETY: `propose_membership` honours the WAL stall-before-wrap admission fence too.
  // A fresh primary minting op 1 onto a ZERO-capacity ring would overflow it (`unpruned_window 1 >
  // capacity 0`), so the proposal is refused — RETRYABLY (`AtCapacity`), since the stall self-releases as
  // the quorum checkpoints forward. A bare mint would have ignored this back-pressure entirely.
  let mut e = single_change_primary();
  let mut wal = ZeroCapWal::default();
  let now = Instant::ZERO;

  assert_eq!(
    e.propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(3))),
    Err(ProposeMembershipError::AtCapacity),
    "a proposal that would overflow the WAL ring is refused retryably, not minted",
  );
  assert_eq!(e.op(), OpNumber::new(), "no op was minted");
  assert_eq!(e.reconfigure_inflight, None, "no latch was set");
  // The admission gate ran BEFORE delta validation, so even with capacity free the same proposal is fine
  // — proving the refusal was the capacity fence, not the delta. (An unbounded WAL has room for op 1.)
  let mut roomy = TestWal::default();
  assert!(
    e.propose_membership(
      now,
      &mut roomy,
      SingleVoterDelta::AddVoter(MemberId::new(3))
    )
    .is_ok(),
    "with WAL capacity, the identical proposal is admitted",
  );
}

#[test]
fn a_backup_committing_the_same_reconfigure_installs_the_identical_successor() {
  // A backup recognizes a RECONFIGURATION-client Prepare, stores a typed `Body::Reconfigure`, commits
  // it via the backup apply loop, and installs the IDENTICAL successor (same epoch, same config_id) at
  // its OWN durable root — convergence, since every replica chains from the identical OLD membership.
  let mut e = single_change_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .unwrap();
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let op = 1u64;

  // The primary's Prepare for the Reconfigure op (flat wire body = the encoded successor), commit 0.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(op),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ClientId::RECONFIGURATION,
      RequestNumber::with(op),
      payload.encode_body(),
    )),
  );
  // The backup stored a TYPED Reconfigure entry (decision (a): one representation everywhere).
  assert_eq!(
    e.log.get(&op).expect("the op is in the backup log").body,
    Body::Reconfigure(payload.clone()),
    "the backup stores a typed Body::Reconfigure, not Body::Present",
  );
  e.handle_storage(now, &mut wal, &mut sb); // the backup's append lands (deferred PrepareOk)
  while e.poll_message().is_some() {}

  // The primary's Commit advances the backup's commit to the Reconfigure op → it commits + stages
  // SwapEpoch. The epoch is still old here (the fence holds on the backup too).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(op),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "the fence: epoch unchanged at backup commit"
  );
  assert!(
    e.pending_swap_for_test(),
    "the backup staged its own SwapEpoch root"
  );

  e.handle_storage(now, &mut wal, &mut sb); // land the backup's SwapEpoch root → install
  assert_eq!(
    e.membership, successor,
    "the backup installed the IDENTICAL successor (same epoch + config_id) as the primary"
  );
  assert_eq!(e.membership.epoch(), crate::Epoch::new(1));
  assert!(
    e.sm_for_test().applied().is_empty(),
    "the backup never applied the Reconfigure op"
  );
}

#[test]
fn the_primary_advertises_the_committed_reconfigure_through_the_swap_window_so_a_backup_converges()
{
  // CONVERGENCE: a commit-first SwapEpoch is an EPOCH change, NOT a view change — `self.view` stays
  // durable through it. So the durable-view-before-participate fence MUST NOT suppress the primary
  // while its `SwapEpoch` root is in flight: the primary keeps participating AT the predecessor epoch,
  // advertising the committed Reconfigure op on its `Commit` heartbeat, which is exactly what lets a
  // still-old-epoch backup commit that op, stage its OWN swap, and converge. (Before the fence was
  // decoupled from the SwapEpoch, that heartbeat was suppressed — the backup never learned the op
  // committed, and a later failover re-minted its op number as a client op: op-number reuse.)
  let (mut primary, mut pwal, mut psb, op, successor, payload) = proposed_and_committed_swap();
  let now = Instant::ZERO;

  // The primary committed the Reconfigure op and is now in the SwapEpoch window: a SwapEpoch root is in
  // flight (`pending_sb`) and the successor is staged (`pending_swap`) — but this is an EPOCH write, so
  // it does NOT raise the durable-view fence. The view is still durable; the primary may participate.
  assert!(
    primary.pending_swap_for_test(),
    "the primary staged its SwapEpoch successor at commit"
  );
  assert!(
    primary.pending_sb_for_test(),
    "the SwapEpoch root write is in flight on the superblock"
  );
  assert!(
    !primary.pending_durable_view_for_test(),
    "a SwapEpoch root must NOT raise the durable-view fence (the view is durable through an epoch swap)"
  );
  assert_eq!(
    primary.membership.epoch(),
    crate::Epoch::new(0),
    "the epoch is still the predecessor's (the install is deferred to the durable root)"
  );

  // Fire the primary's heartbeat tick WHILE the SwapEpoch root is still in flight. The fence no longer
  // gates `primary_timeouts`/`try_commit` on this epoch write, so the primary emits its commit-advertise
  // `Commit` AT epoch E carrying the committed Reconfigure op — the message a backup needs.
  while primary.poll_message().is_some() {} // clear any residue
  primary.handle_timeout(now + COMMIT_HEARTBEAT, &mut pwal, &mut psb);
  let commit_msg = core::iter::from_fn(|| primary.poll_message())
    .map(|out| out.into_msg())
    .find(|m| matches!(m, Message::Commit(_)))
    .expect(
      "the primary advertises its commit through the SwapEpoch window (the fence is decoupled)",
    );
  let Message::Commit(commit) = &commit_msg else {
    unreachable!("filtered to Commit above")
  };
  assert!(
    commit.commit() >= op,
    "the advertised Commit reaches the committed Reconfigure op {} (got commit {})",
    op.get(),
    commit.commit().get()
  );
  assert_eq!(
    commit.epoch(),
    crate::Epoch::new(0),
    "the heartbeat advertises the PREDECESSOR epoch (the primary participates at E through the swap)"
  );

  // A fresh backup that already holds the Reconfigure op in its log (via the primary's earlier Prepare)
  // receives that exact `Commit` — and converges: it commits the op and stages its OWN SwapEpoch.
  let mut backup = single_change_backup();
  let (mut bwal, mut bsb) = (TestWal::default(), TestSb::default());
  backup.handle_message(
    now,
    &mut bwal,
    &mut bsb,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::new(),
      op,
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ClientId::RECONFIGURATION,
      RequestNumber::with(op.get()),
      payload.encode_body(),
    )),
  );
  backup.handle_storage(now, &mut bwal, &mut bsb); // the backup's append lands
  while backup.poll_message().is_some() {}

  // Deliver the PRIMARY'S OWN heartbeat Commit (not a hand-rolled one) — the convergence signal.
  backup.handle_message(now, &mut bwal, &mut bsb, primary_peer(), commit_msg);
  assert_eq!(
    backup.commit(),
    op,
    "the backup committed the Reconfigure op off the primary's swap-window heartbeat"
  );
  assert!(
    backup.pending_swap_for_test(),
    "the backup staged its OWN SwapEpoch — convergence reached the still-old-epoch backup"
  );
  assert_eq!(
    backup.membership.epoch(),
    crate::Epoch::new(0),
    "the backup's epoch is still the predecessor's until its own root lands (the fence holds per node)"
  );

  // Land the backup's SwapEpoch root → it installs the IDENTICAL successor the primary staged.
  backup.handle_storage(now, &mut bwal, &mut bsb);
  assert_eq!(
    backup.membership, successor,
    "the backup installed the identical successor — the live single change converges cluster-wide"
  );
  assert_eq!(backup.membership.epoch(), crate::Epoch::new(1));
}

// === the XI-b CP overlap (exact durable catch-up) ===
//
// The CP-relevant intersection is the OLD WRITE quorum `quorum(n)` (who held an E-committed op) vs
// the NEW VIEW-CHANGE quorum `quorum_view_change(n')` (who elects the E+1 leader). The naive count
// bound is NOT ≥1 for a 3→2 shrink (`quorum(3)+quorum_view_change(2) = 2+1 = 3`, not `> 3`) nor an
// odd→even 3→4 grow (`2+2 = 4`, not `> 4`), so safety is STRUCTURAL: EXACT-durable-catch-up-through-
// the-Reconfigure-op for EVERY E+1 participant. T5 already enforces it by construction — a node's
// `self.membership.epoch()` becomes E+1 ONLY via `install_membership`, run ONLY from `on_sb_done`'s
// `SwapEpoch` arm once the durable root proves the Reconfigure op committed (the single-writer
// invariant on `self.membership`). So every E+1 voter — retained OR newly added — durably committed
// the Reconfigure op, hence holds the FULL E-committed prefix `<=` that op (commit-first puts the
// whole prefix on a node before its E+1 vote can count). Any E+1 DVC-quorum member therefore holds
// any E-committed op `o`, so `o` rides `select_canonical_log`'s union and is never nack-truncated.
//
// The audit of the strict E+1 emission paths (PrepareOk, StartViewChange, DoViewChange, StartView,
// Commit, Prepare) found NO gap, so no `may_participate_under_new_epoch` gate was added:
//   - Every strict path stamps `self.membership.epoch()` / `self.membership.config_id()`, which are
//     E+1 only AFTER `install_membership` — i.e. only after this node's durable SwapEpoch root landed.
//     There is no path that stamps an E+1 strict message while still at E in memory.
//   - The five vote/authority paths (Prepare, PrepareOk, Commit, DoViewChange, StartView) are all in
//     `Message::advertises_authoritative_view()`, so the single `emit` chokepoint blocks them while a
//     durable-view/SwapEpoch root is in flight (`pending_sb.is_some()`). StartViewChange is a
//     request-to-change, not a vote, so it is deliberately NOT gated there — but it carries no E+1
//     authority claim until the membership is installed, and the install IS the durable swap.
//   - The one window where a swap is staged behind an in-flight CHECKPOINT root (so `pending_sb` is
//     None but `pending_checkpoint` is Some, and the `emit` fence does not block) does NOT participate
//     under E+1: `self.membership` is STILL E there (the install runs only at the SwapEpoch root), so
//     anything emitted is stamped E and participates correctly under E. There is no E+1 participation
//     before the durable swap because `self.membership` is literally still the predecessor.
// These tests pin the resulting CP property end to end: a real E-committed op survives a real E+1
// view change for both the shrink (removed voter in the old write quorum) and the grow.

/// The `PrepareOk` a backup at slot `replica` reports for a plain client op `o` (client 7, request
/// `o`, body `[o]`) — the content-addressed vote shape the commit quorum accepts.
fn client_ack(o: u64, replica: u16) -> Message {
  Message::PrepareOk(crate::PrepareOk::new(
    View::new(),
    OpNumber::with(o),
    ReplicaId::new(replica),
    OpNumber::new(),
    crate::storage::prepare_identity(
      ClientId::new(7),
      RequestNumber::with(o),
      crate::storage::fnv1a_128(&[o as u8]),
    ),
    crate::Epoch::new(0),
    0,
  ))
}

/// Drive a fresh 3-voter `SingleChange` primary (slot 0) to: (1) COMMIT a plain client op `o == 1`
/// under the OLD (E=0) 3-voter config, held by the 2-of-3 write quorum {slot 0, the acking backup};
/// then (2) propose `delta`, commit the Reconfigure op `r == 2`, and make its `SwapEpoch` root DURABLE
/// — so on return `self.membership` is the E+1 successor (the epoch swap is installed). Returns the
/// post-swap endpoint, its storage, and the committed client op `o`.
///
/// Op `o` committed BEFORE the reconfiguration, so by commit-first every replica that reaches E+1
/// (it durably committed `r > o`) holds `o`. The DVC-quorum injection in each CP test then models the
/// E+1 view-change quorum and asserts `o` survives `select_canonical_log`.
fn committed_op_then_swapped(
  delta: SingleVoterDelta,
  ack_backup: u16,
) -> (Endpoint<CountSm, SingleChange>, TestWal, TestSb, u64) {
  let mut e = single_change_primary();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let o = 1u64;

  // (1) Commit the client op `o` under E=0: mint + own append (own vote) + one backup ack (2-of-3).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(o),
      Bytes::from(std::vec![o as u8]),
    )),
  );
  while e.poll_message().is_some() {} // drop the broadcast Prepare
  e.handle_storage(now, &mut wal, &mut sb); // primary's own append durable → own vote
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(ack_backup)),
    client_ack(o, ack_backup),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(o),
    "the client op committed under E=0"
  );
  e.handle_storage(now, &mut wal, &mut sb); // drain any commit-tail superblock work
  while e.poll_message().is_some() {}

  // (2) Propose + commit + durably-swap the reconfiguration (op r == 2). The successor is chained off
  // the OLD membership exactly as `propose_membership` does, so the ack content-addresses it.
  let successor = e
    .membership
    .apply_delta(&delta)
    .expect("a valid single-voter delta on the 3-voter cluster");
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let r = e
    .propose_membership(now, &mut wal, delta)
    .expect("the primary mints the reconfiguration op");
  while e.poll_message().is_some() {} // drop the broadcast Prepare
  e.handle_storage(now, &mut wal, &mut sb); // primary's own append durable → own vote
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(ack_backup)),
    reconfigure_ack(r.get(), &payload, ack_backup),
  );
  assert_eq!(e.commit(), r, "the Reconfigure op committed under E=0");
  // Make the SwapEpoch root durable → install the successor. `self.membership` is now E+1.
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.membership, successor, "the E+1 successor is installed");
  assert!(!e.pending_swap_for_test(), "the staged swap was consumed");
  while e.poll_event().is_some() {}
  while e.poll_message().is_some() {}

  (e, wal, sb, o)
}

#[test]
fn cp_overlap_3_to_2_remove_voter_in_the_old_write_quorum() {
  // 3→2 RemoveVoter where the old WRITE quorum INCLUDES the removed voter. This is the case the naive
  // count bound FAILS: `quorum(3) + quorum_view_change(2) = 2 + 1 = 3`, NOT `> 3`. The old write
  // quorum {slot 0, the removed voter (slot 2)} and an E+1 DVC quorum {slot 1} are DISJOINT — only the
  // exact-durable-catch-up structure preserves the op: slot 1 reached E+1 by durably committing the
  // Reconfigure op (op 2), so it holds the full prefix `<= 2`, including the client op `o == 1`.
  //
  // Remove the HIGHEST-slot voter (member 2, slot 2) so the retained voters keep their slots
  // (`{member0→slot0, member1→slot1}`); the acking backup for both commits is slot 1 (a RETAINED
  // voter that is in the E+1 DVC quorum), and the old write quorum that committed `o` is {slot 0
  // (primary), slot 1}, with the removed voter slot 2 ALSO an old-write-quorum holder of `o`.
  let (mut e, _wal, _sb, o) =
    committed_op_then_swapped(SingleVoterDelta::RemoveVoter(MemberId::new(2)), 1);

  // The post-swap config is the 2-voter E+1 membership.
  assert_eq!(e.membership.replica_count(), 2, "E+1 is a 2-voter config");
  assert_eq!(e.membership.epoch(), crate::Epoch::new(1), "swapped to E+1");
  assert_eq!(
    e.membership.quorum_view_change(),
    1,
    "quorum_view_change(2) == 1 — a single DVC is a full E+1 view-change quorum",
  );

  // The E+1 DVC quorum is the single retained voter slot 1 (the worst case: it is DISJOINT from the
  // removed voter's old write quorum). By exact catch-up it durably committed the Reconfigure op
  // (op 2), so its DVC carries the full prefix `[1..=2]` — including the client op `o`. (A real DVC's
  // epoch/config_id stamping is irrelevant to `select_canonical_log`, which reads only the carried
  // log + frontier + the LOCAL membership's quorum sizes.)
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc(1, 0, 2, 2));
  let (log, op_head, commit_star, _) = e.select_canonical_log();

  // THE CP PROPERTY (a DurabilityChecker-style assertion): the committed op `o`'s identity is in the
  // post-view-change canonical log, above the truncation floor, in the committed band.
  assert!(
    commit_star >= o,
    "commit* >= o: the surviving E+1 voter vouches o committed, got {commit_star}",
  );
  assert!(
    op_head >= o,
    "op_head >= o: o is at/below the canonical head, got {op_head}"
  );
  assert!(
    log.iter().any(|entry| entry.op().get() == o),
    "the committed op o == {o} survives in the canonical log (never nack-truncated)",
  );

  // NON-VACUITY (the hazard exact-catch-up forecloses): had the lone E+1 survivor NOT durably
  // committed the Reconfigure op — a lag-bound shortcut where it reached E+1 holding only the prefix
  // BELOW `o` — its DVC would carry an empty/low log and report a sub-`o` commit. `select_canonical_log`
  // on THAT quorum truncates `o`: with a single donor at head 0 / commit 0, `op_head` clamps to 0, so
  // `o` is gone. This witnesses that the survival above is BECAUSE the survivor holds the reconfigure-op
  // prefix (the structural gate), not because `select_canonical_log` always keeps `o`.
  let mut hazard = single_change_primary();
  hazard.membership = e.membership.clone(); // the same E+1 2-voter config (same quorum sizes)
  hazard
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc_offset(1, 0, 0, 0, 0)); // a survivor that holds NOTHING (head 0)
  let (hazard_log, hazard_head, hazard_commit, _) = hazard.select_canonical_log();
  assert_eq!(
    hazard_commit, 0,
    "the lag-shortcut survivor vouches nothing committed"
  );
  assert!(
    hazard_head < o,
    "without the reconfigure-op prefix, o is above the canonical head"
  );
  assert!(
    !hazard_log.iter().any(|entry| entry.op().get() == o),
    "the hazard control confirms o is DROPPED when the survivor lacks the reconfigure-op prefix — \
     so the survival above is load-bearing on exact catch-up",
  );
}

#[test]
fn cp_overlap_3_to_4_add_voter_dvc_quorum_excludes_the_new_voter() {
  // 3→4 AddVoter (odd→even grow). The naive bound is exactly the count
  // `quorum(3) + quorum_view_change(4) = 2 + 2 = 4`, NOT `> 4` — so a 4-voter DVC quorum is not
  // guaranteed by COUNTING to intersect `o`'s old write quorum across ALL of V'. Two structural cases:
  // (a) the DVC quorum EXCLUDES the new voter d → it is `⊆ V` (the old 3 voters), and
  //     `quorum(3) + quorum_view_change(4) = 4 > 3 = |V|`, so it intersects `o`'s old write quorum
  //     WITHIN the retained voters → some retained DVC member holds `o`;
  // (b) the DVC quorum INCLUDES d → d holds `o` by exact catch-up (it committed the Reconfigure op).
  // This test pins case (a): a 2-of-4 DVC quorum of RETAINED voters {slot 0, slot 1}, excluding the
  // new voter (slot 3). Slot 1 is in `o`'s old write quorum, so it carries `o`.
  let (mut e, _wal, _sb, o) =
    committed_op_then_swapped(SingleVoterDelta::AddVoter(MemberId::new(3)), 1);

  assert_eq!(e.membership.replica_count(), 4, "E+1 is a 4-voter config");
  assert_eq!(e.membership.epoch(), crate::Epoch::new(1), "swapped to E+1");
  assert_eq!(
    e.membership.quorum_view_change(),
    2,
    "quorum_view_change(4) == 2",
  );

  // A 2-of-4 E+1 DVC quorum of RETAINED voters {slot 0, slot 1}, EXCLUDING the new voter (slot 3).
  // Both retained voters committed the Reconfigure op (op 2) to reach E+1, so each carries `[1..=2]`
  // — including the client op `o`. Slot 0 is the primary (also an old-write-quorum holder of `o`),
  // slot 1 was the ack backup; their old write quorum {slot 0, slot 1} held `o`.
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc(0, 0, 2, 2));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc(1, 0, 2, 2));
  let (log, op_head, commit_star, _) = e.select_canonical_log();

  assert!(commit_star >= o, "commit* >= o, got {commit_star}");
  assert!(op_head >= o, "op_head >= o, got {op_head}");
  assert!(
    log.iter().any(|entry| entry.op().get() == o),
    "the committed op o == {o} survives the 3→4 grow view change (DVC quorum excludes the new voter)",
  );
}

#[test]
fn cp_overlap_3_to_4_add_voter_dvc_quorum_includes_the_new_voter() {
  // Case (b) of the 3→4 grow: the E+1 DVC quorum INCLUDES the newly added voter d (slot 3). By exact
  // catch-up d durably committed the Reconfigure op (op 2) to become a voter at all, so it holds the
  // full prefix `<= 2`, including the client op `o == 1`. The op survives even though `o`'s old write
  // quorum was entirely WITHIN the original 3 voters and the DVC quorum here is {slot 1, the new
  // voter slot 3}: slot 3 (and slot 1) both carry `o`.
  let (mut e, _wal, _sb, o) =
    committed_op_then_swapped(SingleVoterDelta::AddVoter(MemberId::new(3)), 1);

  assert_eq!(e.membership.replica_count(), 4, "E+1 is a 4-voter config");

  // A 2-of-4 DVC quorum {slot 1 (retained), slot 3 (the NEW voter)}. The new voter holds `[1..=2]`
  // by exact catch-up — the "B includes d → d holds o" case of the §overlap proof.
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc(1, 0, 2, 2));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(3), dvc(3, 0, 2, 2));
  let (log, op_head, commit_star, _) = e.select_canonical_log();

  assert!(commit_star >= o, "commit* >= o, got {commit_star}");
  assert!(op_head >= o, "op_head >= o, got {op_head}");
  assert!(
    log.iter().any(|entry| entry.op().get() == o),
    "the committed op o == {o} survives when the E+1 DVC quorum includes the new voter d",
  );
}

#[test]
fn restart_only_endpoint_has_no_propose_membership_surface() {
  // The capability is a COMPILE-TIME type-state: `propose_membership` lives on `Endpoint<S,
  // SingleChange>` only, so a `RestartOnly` endpoint cannot call it. This is a runtime stand-in for
  // that proof — a `RestartOnly` endpoint constructs but exposes no proposal path. (The negative is
  // enforced by the type system, not asserted here; the `single_change_*` fixtures above exercise the
  // positive surface that a `RestartOnly` endpoint lacks.)
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  let e = Endpoint::new(cfg, genesis(3), 0, CountSm::default());
  assert_eq!(e.replica(), ReplicaId::new(0), "slot 0 is the local member");
}

// === catch-up-then-promote (the non-voting LearnerStatus gate) ===

/// A 3-voter + 1-learner `SingleChange` endpoint whose local member is slot 0 — the primary of view 0.
/// The learner is member 3 at slot 3 (`replica_count == 3`, so id 3 is the first non-voting member).
fn single_change_primary_with_learner() -> Endpoint<CountSm, SingleChange> {
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  Endpoint::<CountSm, SingleChange>::with_reconfig(
    cfg,
    genesis_with_learners(3, 1),
    0,
    CountSm::default(),
  )
}

/// A learner's progress report carrying `durable_commit_min` (and a matching durable head), self-id
/// slot `replica`, under the genesis epoch/config (so the strict ingress gate admits it).
fn learner_status(replica: u16, durable_commit_min: u64) -> Message {
  Message::LearnerStatus(crate::LearnerStatus::new(
    ReplicaId::new(replica),
    OpNumber::with(durable_commit_min),
    OpNumber::with(durable_commit_min),
    crate::Epoch::new(0),
    0,
  ))
}

/// Mint one client op on the primary so its head advances to `op == 1` (the proposal-time head the
/// promote gate measures the learner's frontier against). The op need not commit — `mint_op` advances
/// `self.op` on append.
fn mint_one_client_op(e: &mut Endpoint<CountSm, SingleChange>, wal: &mut TestWal, sb: &mut TestSb) {
  e.handle_message(
    Instant::ZERO,
    wal,
    sb,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from(std::vec![1u8]),
    )),
  );
  while e.poll_message().is_some() {}
}

#[test]
fn on_learner_status_records_peer_progress_monotone_and_touches_no_vote_state() {
  // A `LearnerStatus` is a NON-VOTING progress report: `on_learner_status` records the durable frontier
  // into `peer_progress` (keyed by the stable MemberId) and touches NOTHING else — no inflight vote
  // tracker, no DVC/SVC map, no quorum bitset. And the update is MONOTONE: a reordered LOWER report
  // never lowers a recorded value.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let learner = MemberId::new(3);

  assert!(
    e.peer_progress.is_empty(),
    "no progress recorded at construction"
  );

  // A report of durable frontier 5 from the learner (slot 3) is recorded under its MemberId.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(3)),
    learner_status(3, 5),
  );
  assert_eq!(
    e.peer_progress.get(&learner),
    Some(&OpNumber::with(5)),
    "the durable frontier is recorded keyed by the stable MemberId",
  );

  // The vote/quorum state is untouched — `peer_progress` is the ONLY thing a status report mutates.
  // No inflight vote tracker, and (crucially) NO ViewChange collection was created: a status report is
  // not a vote, so it never touches the DVC/SVC plane (the `view_change` Option stays `None` in Normal).
  assert!(
    e.inflight.is_empty(),
    "no inflight vote tracker was touched"
  );
  assert!(
    e.view_change.is_none(),
    "no DoViewChange/view-change vote collection was created by a progress report"
  );

  // A REORDERED lower report (durable frontier 2) does NOT lower the recorded 5 — monotone.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(3)),
    learner_status(3, 2),
  );
  assert_eq!(
    e.peer_progress.get(&learner),
    Some(&OpNumber::with(5)),
    "a reordered lower report never lowers the recorded value (monotone)",
  );

  // A higher report (7) DOES advance it.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(3)),
    learner_status(3, 7),
  );
  assert_eq!(
    e.peer_progress.get(&learner),
    Some(&OpNumber::with(7)),
    "a higher report advances the recorded frontier",
  );
}

#[test]
fn promote_learner_is_rejected_target_not_caught_up_until_a_status_covers_the_head() {
  // The catch-up-then-promote gate: `propose_membership(PromoteLearner(behind))` is refused with
  // `TargetNotCaughtUp` while the target has no report (or one below the head); once a `LearnerStatus`
  // reports the learner covering the prospective Reconfigure op's predecessor frontier (the head), the
  // promotion SUCCEEDS and mints the op.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let learner = MemberId::new(3);

  // Advance the head to op 1 so the gate's threshold (`>= self.op`) is a non-trivial 1.
  mint_one_client_op(&mut e, &mut wal, &mut sb);
  assert_eq!(e.op(), OpNumber::with(1), "the head advanced to op 1");

  // (a) No report at all → the learner has never proven any durable frontier → rejected.
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::TargetNotCaughtUp),
    "an unreported learner is not caught up",
  );
  assert_eq!(e.reconfigure_inflight, None, "no op was minted");
  assert_eq!(e.op(), OpNumber::with(1), "the head did not advance");

  // (b) A report BELOW the head (durable frontier 0 < head 1) → still rejected.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(3)),
    learner_status(3, 0),
  );
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::TargetNotCaughtUp),
    "a learner below the head is not caught up",
  );
  assert_eq!(e.reconfigure_inflight, None, "still no op minted");

  // (c) A report COVERING the head (durable frontier 1 == head) → the promotion mints the op. By
  // commit-first, the learner that durably committed the Reconfigure op then holds the full prefix.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(3)),
    learner_status(3, 1),
  );
  let op = e
    .propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner),
    )
    .expect("a caught-up learner is promotable — the op mints");
  assert_eq!(
    op,
    OpNumber::with(2),
    "the Reconfigure op minted at head + 1"
  );
  assert_eq!(
    e.reconfigure_inflight,
    Some(op),
    "the single-writer latch holds the minted promote op",
  );
  // The minted op carries the successor membership where member 3 is now a voter (4 voters).
  let entry = e.log.get(&op.get()).expect("the promote op is in the log");
  let payload = entry.body.as_reconfigure().expect("a Body::Reconfigure op");
  assert_eq!(
    payload.replica_count(),
    4,
    "the learner was promoted into the voting set"
  );
}

#[test]
fn promote_learner_rejects_a_tail_gap_learner_whose_durable_op_lags_its_durable_commit() {
  // The catch-up-then-promote gate must require the durably-HELD prefix, not just commit KNOWLEDGE. A
  // recovered learner can report a high `durable_commit_min` while its `durable_op` (the ops it actually
  // persisted) lags — recovery admits a `commit_max > op` tail-gap. `on_learner_status` records
  // `min(durable_commit_min, durable_op)`, so such a learner is NOT promotable: promoting it would enter
  // the successor voter set without the E-committed prefix the XI-b old-write-quorum / new-view-change
  // intersection relies on, risking committed-op loss or a view-change wedge in E+1.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let learner = MemberId::new(3);
  mint_one_client_op(&mut e, &mut wal, &mut sb);
  assert_eq!(e.op(), OpNumber::with(1), "the head advanced to op 1");

  // A TAIL-GAP report: durable_commit_min = 1 (COVERS the head) but durable_op = 0 (the learner has NOT
  // durably persisted op 1) — the recovered `commit_max > op` shape.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(3)),
    Message::LearnerStatus(crate::LearnerStatus::new(
      ReplicaId::new(3),
      OpNumber::with(1), // durable_commit_min COVERS the head
      OpNumber::new(),   // durable_op = 0 — does NOT durably hold the prefix
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::TargetNotCaughtUp),
    "a tail-gap learner (durable commit covers the head but durable_op lags) is NOT caught up — \
     min(durable_commit_min, durable_op) = 0 < head 1",
  );
  assert_eq!(
    e.reconfigure_inflight, None,
    "no op was minted for a tail-gap learner"
  );

  // Positive control: once durable_op ALSO covers the head, the learner durably HOLDS the full prefix →
  // promotable (the monotone update raises the recorded frontier to 1).
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(3)),
    Message::LearnerStatus(crate::LearnerStatus::new(
      ReplicaId::new(3),
      OpNumber::with(1),
      OpNumber::with(1), // durable_op now COVERS the head
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    )
    .is_ok(),
    "once the learner durably holds the full prefix (durable_op == head), the promotion mints the op",
  );
}

#[test]
fn a_non_promote_delta_is_unaffected_by_the_catch_up_gate() {
  // The gate is `PromoteLearner`-specific: an `AddVoter` (a brand-new voter, not a promotion) mints
  // WITHOUT any `peer_progress` entry — there is no learner to have caught up. (The new voter's own
  // catch-up is enforced structurally by commit-first, exactly as the CP-overlap tests pin.)
  let mut e = single_change_primary_with_learner();
  let mut wal = TestWal::default();
  assert!(e.peer_progress.is_empty(), "no progress recorded");
  let op = e
    .propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::AddVoter(MemberId::new(4)),
    )
    .expect("AddVoter is unaffected by the promote gate");
  assert_eq!(e.reconfigure_inflight, Some(op), "the AddVoter op minted");
}

// === the AddVoter XI-b admission gate (the sibling of the catch-up-then-promote gate) ===

/// A 1-voter `SingleChange` endpoint whose sole member is slot 0 — the primary of view 0. The only
/// voter is the whole write quorum AND the whole view-change quorum, so a direct `AddVoter` here would
/// produce a 2-voter successor with `quorum_view_change == 1`.
fn single_change_primary_solo() -> Endpoint<CountSm, SingleChange> {
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  Endpoint::<CountSm, SingleChange>::with_reconfig(cfg, genesis(1), 0, CountSm::default())
}

/// An `n`-voter `SingleChange` endpoint whose local member is slot 0 — the primary of view 0.
fn single_change_primary_n(n: u8) -> Endpoint<CountSm, SingleChange> {
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  Endpoint::<CountSm, SingleChange>::with_reconfig(cfg, genesis(n), 0, CountSm::default())
}

#[test]
fn add_voter_from_a_single_voter_cluster_is_rejected_breaks_quorum_intersection() {
  // The XI-b safety gate: a DIRECT 1->2 `AddVoter` from a single-voter cluster is REFUSED. The new
  // voter holds NO committed prefix, and the 2-voter successor's view-change quorum is 1, so the new
  // voter could form an E+1 view-change quorum ALONE (electing itself leader with an empty log) and
  // drop the old committed prefix — committed-op loss. (Contrast `PromoteLearner`, whose target durably
  // caught up before promotion.)
  let mut e = single_change_primary_solo();
  let mut wal = TestWal::default();
  assert_eq!(
    e.membership.replica_count(),
    1,
    "the cluster is a single voter"
  );
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::AddVoter(MemberId::new(1)),
    ),
    Err(ProposeMembershipError::AddVoterBreaksQuorumIntersection),
    "a brand-new voter that alone satisfies the successor view-change quorum is refused",
  );
  assert_eq!(e.reconfigure_inflight, None, "no op was minted");
  assert_eq!(e.op(), OpNumber::new(), "the head did not advance");
}

#[test]
fn add_voter_from_two_or_more_voters_is_admitted() {
  // For any predecessor of 2+ voters the change is SAFE: the successor view-change quorum
  // (`quorum_view_change >= 2`) necessarily includes a predecessor voter, and the overlap lemma
  // `quorum(n) + quorum_view_change(n+1) > n` makes that predecessor contingent intersect every
  // E-committed write quorum — so the committed prefix is preserved. Confirm 2->3, and at least one
  // larger (3->4), mint.
  for n in [2u8, 3] {
    let mut e = single_change_primary_n(n);
    let mut wal = TestWal::default();
    assert!(
      e.membership
        .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(u128::from(n))))
        .expect("the successor is structurally valid")
        .quorum_view_change()
        >= 2,
      "the {}->{} successor has a view-change quorum of at least 2",
      n,
      n + 1,
    );
    let op = e
      .propose_membership(
        Instant::ZERO,
        &mut wal,
        SingleVoterDelta::AddVoter(MemberId::new(u128::from(n))),
      )
      .unwrap_or_else(|e| panic!("AddVoter from {n} voters is admitted, got {e:?}"));
    assert_eq!(
      e.reconfigure_inflight,
      Some(op),
      "the {n}-voter AddVoter op minted",
    );
  }
}

#[test]
fn the_safe_path_add_learner_then_promote_grows_a_single_voter_cluster() {
  // The SAFE way to add a voter to a single-voter cluster (the path the rejected direct `AddVoter`
  // points the operator to): `AddLearner` the new node, let it durably catch up to the head, THEN
  // `PromoteLearner`. The learner holds the full E-committed prefix before it ever becomes a voter, so
  // the XI-b intersection is preserved by construction (the catch-up-then-promote gate, not the
  // empty-log direct admission).
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  let mut e =
    Endpoint::<CountSm, SingleChange>::with_reconfig(cfg, genesis(1), 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let newcomer = MemberId::new(1);

  // (1) AddLearner is admitted (no voter-count change, no catch-up gate) and mints the op.
  let add_learner_op = e
    .propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::AddLearner(newcomer),
    )
    .expect("AddLearner on a single-voter cluster is admitted");
  assert_eq!(
    e.reconfigure_inflight,
    Some(add_learner_op),
    "the AddLearner op is latched in flight",
  );

  // Commit + install the AddLearner so the new node is an actual learner under the successor epoch.
  // The sole voter (slot 0, this primary) is the whole commit quorum, so its own durable append
  // commits the op; landing the SwapEpoch root installs the successor (now 1 voter + 1 learner).
  e.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb); // own append durable → own vote → commit
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb); // land the SwapEpoch root → install
  assert_eq!(
    e.membership.learner_count(),
    1,
    "the newcomer is now a learner under the successor epoch",
  );
  assert_eq!(
    e.membership.replica_count(),
    1,
    "the voting set is still a single voter (a learner is non-voting)",
  );
  let learner_slot = e
    .membership
    .slot_of(newcomer)
    .expect("the learner occupies a slot");

  // Advance the head so the catch-up gate's threshold is a non-trivial value.
  mint_one_client_op(&mut e, &mut wal, &mut sb);
  let head = e.op();
  assert!(head.get() >= 1, "the head advanced");

  // (2) PromoteLearner is REFUSED until the learner reports a durable frontier covering the head.
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(newcomer)
    ),
    Err(ProposeMembershipError::TargetNotCaughtUp),
    "the learner has not yet reported durable catch-up",
  );

  // (3) The learner reports `peer_progress` covering the head → PromoteLearner SUCCEEDS. By
  // commit-first, the learner that durably commits the promote op then holds the entire prefix. The
  // report carries the endpoint's CURRENT (post-AddLearner-swap) epoch/config_id so the strict ingress
  // gate admits it (the cluster has advanced to E+1, unlike the genesis `learner_status` fixture).
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(learner_slot),
    Message::LearnerStatus(crate::LearnerStatus::new(
      learner_slot,
      head,
      head,
      e.membership.epoch(),
      e.membership.config_id(),
    )),
  );
  let promote_op = e
    .propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(newcomer),
    )
    .expect("a caught-up learner is promotable — the safe path grows the cluster to 2 voters");
  let entry = e
    .log
    .get(&promote_op.get())
    .expect("the promote op is logged");
  let payload = entry.body.as_reconfigure().expect("a Body::Reconfigure op");
  assert_eq!(
    payload.replica_count(),
    2,
    "the safe path grew the single-voter cluster to 2 voters via catch-up-then-promote",
  );
}

// === the four Raft §6 single-change reconfiguration hazards ===

// (a) REMOVED-LEADER abdication. When the committed Reconfigure op removes THIS node (the primary of
// its view) from the voter set, the durable swap installs a successor in which it is no longer a
// voter. It must go SILENT as primary — retire the Normal-primary cadence (commit heartbeat + prepare
// retransmit + the forfeit grace) and clear the deferred-forfeit latch — so the surviving voters'
// idle timers elect an E+1 primary. `abdicate_if_primary` alone does not suffice: under the NEW
// membership `is_primary()` is already false (the removed node has no voter slot), so it early-returns;
// the cadence is retired directly in `install_membership`.

/// Drive a fresh 3-voter SingleChange primary (slot 0, member 0 — primary of view 0) to remove
/// ITSELF, committing the Reconfigure op under E=0 and making its `SwapEpoch` root DURABLE, so on
/// return `self.membership` is the E+1 successor in which member 0 is absent. The acking backup is
/// slot 1 (a retained voter), so the 2-of-3 commit quorum forms without the removed node's body. The
/// removed node's own Prepare-retransmit/commit-heartbeat timers were armed by the proposal mint.
fn removed_self_primary() -> (Endpoint<CountSm, SingleChange>, TestWal, TestSb, Membership) {
  let mut e = single_change_primary();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::RemoveVoter(MemberId::new(0)))
    .expect("removing one of three voters is valid");
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let op = e
    .propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::RemoveVoter(MemberId::new(0)),
    )
    .expect("the primary mints the self-removal Reconfigure op");
  // Drive the commit/prepare cadence once so the Normal-primary timers are armed (the thing the
  // abdication must retire). `handle_timeout` on a Normal primary bootstraps + arms `commit`.
  e.handle_timeout(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  e.handle_storage(now, &mut wal, &mut sb); // own append durable → own vote
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    reconfigure_ack(op.get(), &payload, 1),
  );
  assert_eq!(
    e.commit(),
    op,
    "the self-removal Reconfigure op committed under E=0"
  );
  assert!(
    e.commit_or_prepare_timer_armed_for_test(),
    "the Normal-primary cadence is armed before the swap (the abdication must retire it)",
  );
  e.handle_storage(now, &mut wal, &mut sb); // land the SwapEpoch root → install the successor
  (e, wal, sb, successor)
}

#[test]
fn a_removed_primary_retires_its_normal_primary_cadence_on_the_swap() {
  let (e, _wal, _sb, successor) = removed_self_primary();

  // The swap installed the 2-voter successor in which member 0 (this node) is absent.
  assert_eq!(
    e.membership, successor,
    "the E+1 successor (member 0 removed) is active"
  );
  assert_eq!(e.membership.epoch(), crate::Epoch::new(1), "swapped to E+1");
  assert_eq!(e.membership.replica_count(), 2, "E+1 is a 2-voter config");
  assert!(
    e.membership.slot_of(MemberId::new(0)).is_none(),
    "the removed node has no slot in the successor",
  );

  // ABDICATION: it is no longer the primary (robustly false for an absent local member, not a panic),
  // the Normal-primary cadence is retired, and the forfeit sub-states are clear (so the
  // `pending_forfeit`/`forfeit_armed` invariant — both imply a Normal primary — holds).
  assert!(
    !e.is_primary(),
    "a removed node is not the primary (no panic on an absent slot)"
  );
  assert!(
    !e.commit_or_prepare_timer_armed_for_test(),
    "the commit heartbeat + prepare retransmit are retired — the removed primary goes silent",
  );
  assert!(
    !e.forfeit_armed_for_test(),
    "the forfeit grace timer is retired"
  );
  assert!(
    !e.pending_forfeit_for_test(),
    "the deferred-forfeit latch is clear"
  );
}

#[test]
fn a_surviving_voter_elects_a_new_primary_without_the_removed_node() {
  // The other half of the abdication: with the old primary silent, a SURVIVING voter's idle timer
  // fires and it proposes the next view — the cluster elects an E+1 primary from the new voter set.
  // Model the survivor as a fresh endpoint in the E+1 2-voter membership {member1→slot0,
  // member2→slot1}: member 2 is slot 1, the BACKUP under view 0 (whose primary is slot 0). Its idle
  // timer then fires and it proposes view 1 (whose primary is slot 1 = itself).
  let (_removed, _wal, _sb, successor) = removed_self_primary();
  assert!(
    successor.slot_of(MemberId::new(2)).is_some(),
    "member 2 is a retained voter in the successor",
  );
  let survivor_cfg = Config::try_new(1, MemberId::new(2)).expect("valid cluster config");
  let mut survivor = Endpoint::<CountSm, SingleChange>::with_reconfig(
    survivor_cfg,
    successor,
    0,
    CountSm::default(),
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());

  // It starts Normal as a backup; its idle timer has not yet fired.
  assert_eq!(survivor.status(), Status::Normal);
  assert!(
    !survivor.is_primary(),
    "member 2 (slot 1) is a backup under view 0"
  );
  survivor.handle_timeout(Instant::ZERO, &mut wal, &mut sb); // bootstrap primary_idle (not yet due)
  let later = Instant::ZERO + core::time::Duration::from_millis(300);
  survivor.handle_timeout(later, &mut wal, &mut sb); // idle due → propose view 1, broadcast SVC

  // The survivor broadcast a StartViewChange for the next view — the election the silent removed
  // primary no longer suppresses.
  let mut saw_svc = false;
  while let Some(out) = survivor.poll_message() {
    if let Message::StartViewChange(svc) = out.into_msg() {
      assert_eq!(
        svc.view(),
        View::with(1),
        "the survivor proposes the next view"
      );
      saw_svc = true;
    }
  }
  assert!(
    saw_svc,
    "a surviving voter's idle timer elects a new primary once the removed primary goes silent",
  );
}

/// A 3-voter `SingleChange` BACKUP (slot 2, member 2 — a backup under view 0, NOT the primary) that
/// learns + commits `RemoveVoter(member 2)` from the primary and installs the E+1 2-voter successor in
/// which member 2 is absent. Modeled on the backup-install path (`on_prepare` of the Reconfigure op,
/// then the primary's `Commit`, then the backup's own durable `SwapEpoch` root). On return the backup's
/// `self.membership` is the successor; the removed BACKUP must now go silent on its WHOLE voter timer
/// plane (the `retire_backup_cadence` half of the removed-node abdication), the case distinct from the
/// removed-PRIMARY case (`removed_self_primary`, which retires the primary cadence).
fn removed_self_backup() -> (Endpoint<CountSm, SingleChange>, TestWal, TestSb, Membership) {
  let cfg = Config::try_new(2, MemberId::new(2)).expect("slot 2 backup of the 3-voter set");
  let mut e =
    Endpoint::<CountSm, SingleChange>::with_reconfig(cfg, genesis(3), 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  // Remove member 2 (the HIGHEST-slot voter, so the retained voters keep their slots {0,1}); the local
  // node is member 2, so the successor drops it entirely (`slot_of(2) == None`).
  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::RemoveVoter(MemberId::new(2)))
    .expect("removing one of three voters is valid");
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let op = 1u64;

  // The primary's Prepare for the Reconfigure op (flat wire body = the encoded successor) → the backup
  // stores a typed Body::Reconfigure and arms its backup timer plane (the idle/vote timers the swap
  // must retire).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(op),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ClientId::RECONFIGURATION,
      RequestNumber::with(op),
      payload.encode_body(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // the backup's append lands (deferred PrepareOk)
  while e.poll_message().is_some() {}

  // The primary's Commit advances the backup's commit to the Reconfigure op → it commits + stages its
  // own SwapEpoch root (still at the OLD epoch — the fence holds on the backup).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(op),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    e.pending_swap_for_test(),
    "the backup staged its own SwapEpoch root"
  );
  e.handle_storage(now, &mut wal, &mut sb); // land the backup's SwapEpoch root → install the successor
  (e, wal, sb, successor)
}

#[test]
fn a_removed_backup_voter_stays_silent_on_the_primary_idle_plane() {
  // A `RemoveVoter` of a BACKUP voter (not the primary): after the swap the removed backup is a NON-VOTER
  // (absent from the configuration), so the voter timer plane gated on `is_voter()` — `primary_idle`
  // foremost — must be retired and stay non-serviceable. The removed node must NOT arm or service
  // `PrimaryIdle`, must NOT propose/enter a view change when the primary goes quiet, and must NOT panic
  // on a `local_slot()` that no longer exists (the bug the `is_voter()` gate fixed: `!is_learner()` is
  // wrongly TRUE for an absent member, which would let it arm a consensus timer and then panic).
  let (mut e, mut wal, mut sb, successor) = removed_self_backup();

  // The swap installed the 2-voter successor in which member 2 (this node) is absent.
  assert_eq!(
    e.membership, successor,
    "the E+1 successor (member 2 removed) is active"
  );
  assert_eq!(e.membership.epoch(), crate::Epoch::new(1), "swapped to E+1");
  assert_eq!(e.membership.replica_count(), 2, "E+1 is a 2-voter config");
  assert!(
    e.membership.slot_of(MemberId::new(2)).is_none(),
    "the removed backup has no slot in the successor",
  );

  // It is a NON-VOTER now (the single-source predicate the timer plane reads), and never the primary —
  // both robustly false for an absent local member, NOT a panic on `local_slot()`.
  assert!(
    !e.is_voter(),
    "a removed backup is not a voter (no slot in the successor)"
  );
  assert!(!e.is_primary(), "a removed backup is not the primary");

  // The removal site retired the backup voter timer plane: the `primary_idle` deadline (and the
  // vote/escalation timers) is cleared, so no armed consensus deadline lingers on a removed node.
  assert!(
    !e.primary_idle_armed_for_test(),
    "the removed backup holds NO armed primary_idle deadline (retire_backup_cadence ran)",
  );

  // A fully-removed node transitions to the structural `Retired` state: it arms/services no timer and
  // its ingress drops every message, so it reaches no voter path (nor any panicking `local_slot()`) by
  // construction. Advance FAR past PRIMARY_IDLE and tick: `handle_timeout`'s Retired arm is a no-op —
  // no view change, no StartViewChange, no panic.
  assert_eq!(
    e.status(),
    Status::Retired,
    "a fully-removed node is Retired"
  );
  let view_before = e.view();
  let later = Instant::ZERO + core::time::Duration::from_millis(10_000);
  e.handle_timeout(later, &mut wal, &mut sb); // far past PRIMARY_IDLE — must not arm/fire a VC, must not panic
  assert_eq!(
    e.status(),
    Status::Retired,
    "the removed node stays Retired — it proposes no view change",
  );
  assert_eq!(
    e.view(),
    view_before,
    "the removed backup's view is unchanged (it entered no view change)",
  );
  assert!(
    !e.primary_idle_armed_for_test(),
    "ticking far past PRIMARY_IDLE re-armed NOTHING — the idle plane stays retired on the non-voter",
  );
  let mut saw_svc = false;
  while let Some(out) = e.poll_message() {
    if matches!(
      out.into_msg(),
      Message::StartViewChange(_) | Message::DoViewChange(_)
    ) {
      saw_svc = true;
    }
  }
  assert!(
    !saw_svc,
    "a removed backup broadcasts NO StartViewChange/DoViewChange — it is silent on the voter timer plane",
  );
}

// (b) DISRUPTIVE-REMOVED-SERVER + the multi-epoch `in_lineage` chain. A removed server's stale
// E-epoch SVC/DVC is inadmissible at the surviving E+1 cluster (epoch-strict ingress drops it;
// commit-first collapsed the pre-commit disruption window). SEPARATELY, `in_lineage` admits a BOUNDED
// window of recent prior `config_id`s so a legitimate replica lagging by a small number of live
// single-changes can still adopt across the epoch boundary, while a forked/long-stale config_id is
// rejected.

#[test]
fn in_lineage_admits_the_recent_prior_config_ids_but_rejects_a_forked_one() {
  // Walk a node through two consecutive single-change swaps so its lineage ring holds the two prior
  // config_ids. `in_lineage` admits the current id AND the retained prior ids; a forked/unknown id is
  // rejected (config_id is the lineage discriminator).
  let (mut e, mut wal, mut sb, _op, _successor, _payload) = proposed_and_committed_swap();
  let genesis_config_id = 0u128; // the fixture genesis carries config_id 0 (see the `genesis` helper)
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb); // land swap #1 → E=1 install
  let config_1 = e.membership.config_id();
  assert_ne!(
    config_1, genesis_config_id,
    "the first swap chained a new config_id"
  );

  // The current id and the immediately-prior (genesis) id are both in lineage.
  assert!(
    e.in_lineage_for_test(config_1),
    "the current config_id is in lineage"
  );
  assert!(
    e.in_lineage_for_test(genesis_config_id),
    "the immediately-prior config_id is admitted (a 1-epoch laggard can catch up)",
  );
  // A forked/unknown config_id is NOT in the chain — rejected.
  assert!(
    !e.in_lineage_for_test(0xDEAD_BEEF),
    "a forked/unknown config_id is rejected — config_id is the lineage discriminator",
  );

  // A SECOND swap: propose+commit+install RemoveVoter on the current (E=1, 4-voter) config.
  let now = Instant::ZERO;
  let succ2 = e
    .membership
    .apply_delta(&SingleVoterDelta::RemoveVoter(MemberId::new(1)))
    .expect("removing a voter from the 4-voter E=1 config is valid");
  let payload2 = ReconfigurePayload::from_membership(&succ2, e.membership.config_id());
  let op2 = e
    .propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::RemoveVoter(MemberId::new(1)),
    )
    .expect("the primary mints the second Reconfigure op");
  while e.poll_message().is_some() {}
  e.handle_storage(now, &mut wal, &mut sb); // own append → own vote
  // Commit with a quorum of the E=1 4-voter config (quorum 3): the primary (slot 0) + acks from slots
  // 2 and 3 (slot 1 is the one being removed). The acks must be stamped E=1 / config_1 — the primary's
  // CURRENT configuration — or the strict ingress gate drops them.
  for r in [2u16, 3] {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(r)),
      reconfigure_ack_at(op2.get(), &payload2, r, crate::Epoch::new(1), config_1),
    );
  }
  assert_eq!(
    e.commit(),
    op2,
    "the second Reconfigure op committed under E=1"
  );
  e.handle_storage(now, &mut wal, &mut sb); // land swap #2 → E=2 install
  let config_2 = e.membership.config_id();
  assert_eq!(e.membership.epoch(), crate::Epoch::new(2), "swapped to E=2");

  // After the second swap: current (config_2) and the two retained prior ids (config_1, genesis) are
  // in lineage — a node lagging by up to two live single-changes can still catch up.
  assert!(
    e.in_lineage_for_test(config_2),
    "the current id is in lineage"
  );
  assert!(
    e.in_lineage_for_test(config_1),
    "the 1-prior id is retained"
  );
  assert!(
    e.in_lineage_for_test(genesis_config_id),
    "the 2-prior id is still retained (the ring holds 2 prior ids)",
  );
}

#[test]
fn a_stale_old_epoch_svc_is_dropped_by_ingress_at_the_e_plus_1_survivor() {
  // The disruptive-removed-server containment: at an E+1 survivor, a StartViewChange stamped with the
  // OLD epoch (E=0) is inadmissible — `epoch_authority_admits` is STRICT on `(epoch, config_id)` for a
  // vote/lead message, so a removed server's stale E-epoch SVC cannot pull the survivor into a view
  // change. The same SVC at the survivor's CURRENT epoch DOES register (proving the drop is the epoch
  // gate, not some other guard).
  let (mut e, mut wal, mut sb, _op, _successor, _payload) = proposed_and_committed_swap();
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb); // land the swap → the survivor is now at E=1
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the survivor is at E+1"
  );
  let now = Instant::ZERO;
  // This node is slot 0 of the E=1 4-voter config (the primary of view 0), so feed the SVC to a BACKUP
  // survivor to observe a view-change transition cleanly. Re-home onto slot 1.
  let backup_cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  let mut backup = Endpoint::<CountSm, SingleChange>::with_reconfig(
    backup_cfg,
    e.membership.clone(),
    0,
    CountSm::default(),
  );

  // A stale OLD-epoch (E=0) SVC for view 1 from a removed/forked server: dropped at the strict gate.
  backup.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0), // OLD epoch — inadmissible at the E+1 survivor
      backup.membership.config_id(),
    )),
  );
  assert_eq!(
    backup.status(),
    Status::Normal,
    "a stale OLD-epoch SVC does not pull the E+1 survivor into a view change",
  );

  // Positive control: the SAME SVC at the survivor's CURRENT epoch (E=1) is admitted and counts.
  backup.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(1), // current epoch — admitted
      backup.membership.config_id(),
    )),
  );
  // With its own bit (proposing view 1) plus replica 2's admitted SVC, the 4-voter SVC quorum is not
  // yet met (quorum 3), but the message was ADMITTED — observable as the adopted SVC target.
  assert_eq!(
    backup.svc_target_for_test(),
    View::with(1),
    "the same SVC at the matching epoch IS admitted (the drop above was the epoch gate)",
  );
}

// (c) AVAILABILITY (single change in flight). The single-writer `reconfigure_inflight` latch
// serializes: it is SET at propose and CLEARED at the commit's `stage_epoch_swap`, and a second
// proposal mid-flight is refused `AlreadyInFlight`.

#[test]
fn the_in_flight_latch_cycles_set_at_propose_then_cleared_at_commit_stage() {
  let mut e = single_change_primary();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  assert_eq!(e.reconfigure_inflight, None, "no change in flight at rest");

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .unwrap();
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let op = e
    .propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the primary mints the Reconfigure op");
  // SET at propose.
  assert_eq!(
    e.reconfigure_inflight,
    Some(op),
    "the latch is set at propose"
  );

  // A second proposal mid-flight is refused, and the latch still holds the FIRST op.
  assert_eq!(
    e.propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(4))),
    Err(ProposeMembershipError::AlreadyInFlight),
    "a second change mid-flight is refused",
  );
  assert_eq!(
    e.reconfigure_inflight,
    Some(op),
    "the latch still holds the first op mid-flight"
  );

  // Drive the first op to commit → `stage_epoch_swap` CLEARS the latch (before the durable root even
  // lands — the swap is staged the instant the op commits).
  while e.poll_message().is_some() {}
  e.handle_storage(now, &mut wal, &mut sb); // own append → own vote
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    reconfigure_ack(op.get(), &payload, 1),
  );
  assert_eq!(e.commit(), op, "the Reconfigure op committed");
  assert_eq!(
    e.reconfigure_inflight, None,
    "the latch is CLEARED at the commit's stage_epoch_swap (before the durable root lands)",
  );
  assert!(
    e.pending_swap_for_test(),
    "the successor is staged for its durable swap"
  );

  // Land the SwapEpoch root so the swap installs and the superblock is free again (a mint cannot emit
  // a Prepare while a durable root write is in flight — the durable-view-before-participate fence).
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(!e.pending_swap_for_test(), "the swap installed");
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the epoch swapped to E+1"
  );
  while e.poll_message().is_some() {}
  while e.poll_event().is_some() {}

  // The latch is free again: a NEXT change (now under the E+1 config) can be proposed — the latch
  // re-arms, confirming the in-flight serialization is per-change, not permanent.
  let op2 = e
    .propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(4)))
    .expect("a new change is proposable once the prior one installed");
  assert_eq!(
    e.reconfigure_inflight,
    Some(op2),
    "the latch re-arms for the next change"
  );
}

#[test]
fn a_view_change_truncating_an_uncommitted_proposal_releases_the_in_flight_latch() {
  // A proposing primary latches `reconfigure_inflight` at propose. If its uncommitted `Reconfigure` op
  // never commits because a view change deposes it, the latch MUST release — otherwise a future
  // `propose_membership` (after the node regains primacy) is blocked `AlreadyInFlight` FOREVER on a
  // proposal that never committed (the proposed-but-never-committed deadlock). `stage_epoch_swap` (which
  // clears the latch) only runs at COMMIT, so the release must come from `reset_for_view_transition`.
  let mut e = single_change_primary();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  // Propose on the view-0 primary → the latch is set on the uncommitted op (it is NOT driven to commit).
  let op = e
    .propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the primary mints the Reconfigure op");
  assert_eq!(
    e.reconfigure_inflight,
    Some(op),
    "the latch holds the uncommitted proposal"
  );
  assert!(
    !e.pending_swap_for_test(),
    "no swap is staged — the op has not committed"
  );
  while e.poll_message().is_some() {}

  // A higher-view `Commit` (view 1) deposes the proposer: `catch_up_to_view` runs the view-transition
  // reset. The uncommitted op is abandoned with the old generation.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::Commit(Commit::new(
      View::with(1),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    !e.status().is_normal(),
    "the proposer left Normal on the higher-view Commit"
  );
  // THE PROPERTY: the proposal latch was RELEASED by the view transition (the op never committed, so it
  // must not block forever).
  assert_eq!(
    e.reconfigure_inflight, None,
    "the in-flight latch is released when a view change abandons the uncommitted proposal",
  );
  assert!(
    !e.pending_swap_for_test(),
    "no committed-but-not-installed swap exists (the op never committed)"
  );
}

// (d) VIEW-CHANGE-DURING-CHANGE. A Reconfigure op uncommitted when a view change fires rides
// `select_canonical_log` like any entry: truncated if uncommitted-and-not-canonical, carried if on
// the canonical DVC quorum and re-driven by the new primary (whose commit then fires the swap).

#[test]
fn an_uncommitted_non_canonical_reconfigure_op_is_truncated_and_the_cluster_stays_at_the_old_epoch()
{
  // (d)(i) A backup (slot 1, primary of view 1) holds an UNCOMMITTED Reconfigure op at the head. A view
  // change to view 1 forms on a DVC quorum that does NOT carry that op (a nack quorum truncates the
  // uncommitted tail). The op is dropped, the cluster stays at the OLD epoch (E=0), and no committed
  // op is lost (`assert_committed_survives` backstops the truncation).
  let mut e = Endpoint::<CountSm, SingleChange>::with_reconfig(
    Config::try_new(1, MemberId::new(1)).expect("valid cluster config"),
    genesis(3),
    0,
    CountSm::default(),
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  // Seed an uncommitted Reconfigure op at op 1 (a RECONFIGURATION-client Prepare from the view-0
  // primary), held but never committed.
  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .unwrap();
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ClientId::RECONFIGURATION,
      RequestNumber::with(1),
      payload.encode_body(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // the append lands
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the uncommitted Reconfigure op is held at the head"
  );
  assert!(
    e.log.get(&1).expect("op 1 is held").body.is_reconfigure(),
    "it is a typed Body::Reconfigure entry",
  );
  while e.poll_message().is_some() {}

  // Drive a real view change to view 1 (slot 1 is primary of view 1) via the SVC path, so status +
  // the catching_up discriminant are set correctly. Inject a DVC quorum whose canonical generation
  // reports commit 0 / op 0 — NONE carry op 1 — so the nack-truncation drops it.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb); // primary_idle → propose view 1, own SVC bit
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "slot 1 is collecting DVCs as primary of view 1"
  );
  while e.poll_message().is_some() {}
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc(1, 0, 0, 0));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(2), dvc(2, 0, 0, 0));
  let (log, op_head, commit_star, _) = e.select_canonical_log();
  assert_eq!(
    commit_star, 0,
    "the canonical quorum vouches nothing committed"
  );
  assert_eq!(
    op_head, 0,
    "the uncommitted Reconfigure op is truncated below the head"
  );
  assert!(
    !log.iter().any(|entry| entry.op().get() == 1),
    "the uncommitted non-canonical Reconfigure op is dropped from the canonical log",
  );
  // The cluster stays at the OLD epoch — no swap was staged from an uncommitted op.
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "the cluster stays at E=0"
  );
  assert!(
    !e.pending_swap_for_test(),
    "no epoch swap is staged for the truncated op"
  );
}

#[test]
fn a_canonical_reconfigure_op_survives_a_view_change_and_its_swap_fires_when_recommitted() {
  // (d)(ii) A Reconfigure op carried through a view change ON the canonical DVC quorum (header-only, as
  // every real DVC carries its log) must be re-driven by the new primary and, when it commits under
  // the new view, fire the commit-first epoch swap. This exercises the peer-repair reconstruction: the
  // adopted header-only entry is repaired with the RECONFIGURATION body, which must be rebuilt as a
  // typed Body::Reconfigure (not an opaque Body::Present) so `commit_reconfigure` recognizes it.
  let mut e = Endpoint::<CountSm, SingleChange>::with_reconfig(
    Config::try_new(1, MemberId::new(1)).expect("valid cluster config"),
    genesis(3),
    0,
    CountSm::default(),
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  let successor = genesis(3)
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .unwrap();
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let reconfig_checksum = Body::Reconfigure(payload.clone()).body_checksum();

  // Drive slot 1 into ViewChange as primary of view 1 via the real SVC path (its own DVC carries op 0
  // — it holds nothing yet). The canonical donor (replica 2) carries the Reconfigure op at op 1
  // HEADER-ONLY (a `Repairing` entry with the canonical RECONFIGURATION checksum) at log_view 0,
  // vouching commit 0 (uncommitted tail — it re-commits under the new view). With the new primary's
  // own DVC, the 2-of-3 quorum forms and the canonical generation (log_view 0) unions in op 1.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb); // primary_idle → propose view 1, own SVC bit
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "slot 1 collects DVCs as primary of view 1"
  );
  while e.poll_message().is_some() {}
  let reconfig_entry = crate::PreparedEntry::repairing(
    OpNumber::with(1),
    ClientId::RECONFIGURATION,
    RequestNumber::with(1),
    reconfig_checksum,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(crate::DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(1),
      OpNumber::new(), // commit 0 — the op is uncommitted, re-committed under the new view
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![reconfig_entry.clone()],
    )),
  );
  // The new primary adopted op 1 (header-only) and is forming view 1.
  assert_eq!(e.view(), View::with(1));
  assert!(e.is_primary(), "slot 1 is the new primary of view 1");
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the Reconfigure op rode the view change"
  );
  assert!(
    e.has_repair_hole_for_test(1),
    "the header-only Reconfigure op is a repair hole awaiting its body",
  );
  e.handle_storage(now, &mut wal, &mut sb); // land the durable-view write → start_view_participate
  while e.poll_message().is_some() {}

  // Answer the new primary's RequestPrepare for op 1 with the canonical RECONFIGURATION body (a holder
  // serves it; commit >= op vouches it). The fill must rebuild a typed Body::Reconfigure.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::Prepare(Prepare::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(1), // commit >= op: vouches the served op
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ClientId::RECONFIGURATION,
      RequestNumber::with(1),
      payload.encode_body(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // the RepairFill append lands → the body is in the log
  assert!(
    e.log.get(&1).expect("op 1 is filled").body.is_reconfigure(),
    "the repaired RECONFIGURATION op is rebuilt as a typed Body::Reconfigure (not an opaque Present)",
  );
  assert!(!e.has_repair_hole_for_test(1), "the hole is filled");

  // Now drive op 1 to commit under view 1: the new primary's own append cast its vote on the fill;
  // one backup ack reaches the 2-of-3 quorum → the op commits → the commit-first swap STAGES.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(crate::PrepareOk::new(
      View::with(1),
      OpNumber::with(1),
      ReplicaId::new(2),
      OpNumber::new(),
      crate::storage::prepare_identity(
        ClientId::RECONFIGURATION,
        RequestNumber::with(1),
        reconfig_checksum,
      ),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the carried Reconfigure op re-committed under view 1"
  );
  assert!(
    e.pending_swap_for_test(),
    "the commit-first epoch swap STAGED — the new primary recognized the re-committed Reconfigure op",
  );
  // The Reconfigure op was NEVER applied to the state machine (it is consensus-layer).
  assert!(
    e.sm_for_test().applied().is_empty(),
    "the re-committed Reconfigure op was not applied to the state machine",
  );
  e.handle_storage(now, &mut wal, &mut sb); // land the SwapEpoch root → install
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the epoch swapped to E+1 when the carried Reconfigure op re-committed under the new view",
  );
  assert_eq!(
    e.membership, successor,
    "the successor membership is installed"
  );
}

#[test]
fn a_committed_swap_survives_a_view_change_and_still_installs() {
  // F2 — a view change DURING the COMMITTED swap window must NOT cancel the swap. A node commits the
  // `Reconfigure` op (so `commit_min` advances PAST it and `commit_reconfigure` will never run for it
  // again), stages `pending_swap`, but its `SwapEpoch` root is still in flight when a view change fires.
  // Because the op is already committed, the new view's `advance_commit` starts ABOVE it — there is NO
  // re-commit to re-stage the swap. So the staged successor MUST survive the transition and install once
  // the view's durable root lands, or the committed membership change is lost forever (the cluster stays
  // in the old epoch after a committed reconfiguration). Distinct from
  // `a_canonical_reconfigure_op_survives_a_view_change_and_its_swap_fires_when_recommitted`, where the op
  // rode the view change UNCOMMITTED and re-committed under the new view.
  //
  // Driven over an ASYNC superblock (`StepSb`) so the `SwapEpoch` root stays in flight across the
  // transition: the backup (slot 1) commits + stages, then becomes the new primary of view 1.
  let mut e = Endpoint::<CountSm, SingleChange>::with_reconfig(
    Config::try_new(1, MemberId::new(1)).expect("valid cluster config"),
    genesis(3),
    0,
    CountSm::default(),
  );
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
  let now = Instant::ZERO;

  let successor = genesis(3)
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .unwrap();
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let op = 1u64;

  // (1) The view-0 primary's Prepare for the Reconfigure op (flat wire body = encoded successor).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(op),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ClientId::RECONFIGURATION,
      RequestNumber::with(op),
      payload.encode_body(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // the backup's append lands
  sb.flush(); // the append is durable
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}

  // (2) The primary's Commit advances the backup's commit to the Reconfigure op → it commits (commit_min
  // moves PAST it) + stages the swap. The `SwapEpoch` root is submitted but NOT yet flushed — it is in
  // flight across the view change to come.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(op),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(op),
    "the Reconfigure op committed (commit_min advanced to it)"
  );
  assert!(
    e.pending_swap_for_test(),
    "the backup staged its swap (committed, not yet installed)"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "the fence: the epoch is NOT swapped yet (the root is in flight)"
  );

  // (3) A view change to view 1 fires DURING the committed swap window (slot 1 is primary of view 1).
  // Drive it via the real SVC path so status + the catching_up discriminant are set correctly; the
  // SendDoViewChange durable-view root SUPERSEDES the in-flight SwapEpoch root on the superblock.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb); // primary_idle → propose view 1, own SVC bit
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "slot 1 collects DVCs as primary of view 1"
  );
  // THE F2 PROPERTY (part 1): the committed swap SURVIVED the view-transition reset — it was NOT
  // cancelled (the committed change is not lost).
  assert!(
    e.pending_swap_for_test(),
    "the committed-but-not-installed swap survives the view transition (it is not cancelled)",
  );
  while e.poll_message().is_some() {}

  // (4) A peer DVC for view 1 carrying the committed prefix `[1..=1]` reaches the 2-of-3 quorum (the new
  // primary's own DVC is auto-inserted) → formation. The DVC's view is the CURRENT view (1), its log_view
  // 0, op 1, commit 1 — the committed Reconfigure op rides as a `Present` entry.
  let peer_dvc = crate::DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(1),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![crate::PreparedEntry::new(
      OpNumber::with(1),
      ClientId::RECONFIGURATION,
      RequestNumber::with(1),
      payload.encode_body(),
    )],
  );
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(peer_dvc),
  );
  assert!(e.is_primary(), "slot 1 formed view 1 as the new primary");
  assert_eq!(
    e.status(),
    Status::Normal,
    "slot 1 formed view 1 (Normal primary)"
  );
  assert_eq!(e.view(), View::with(1));
  // The swap is STILL staged — it has not yet re-submitted (the durable-view root is in flight).
  assert!(
    e.pending_swap_for_test(),
    "the swap is still staged through formation (awaiting the durable-view root)"
  );

  // (5) Drain storage: the SendDoViewChange / StartViewAsPrimary durable-view root lands, `on_sb_done`
  // re-submits the staged SwapEpoch (`maybe_swap_epoch`), and that root then installs the successor.
  for _ in 0..8 {
    sb.flush();
    e.handle_storage(later, &mut wal, &mut sb);
    while e.poll_message().is_some() {}
    if !e.pending_swap_for_test() {
      break;
    }
  }

  // THE F2 PROPERTY (part 2): after the view change completes and storage drains, the epoch DID swap —
  // the committed reconfiguration installed despite the interrupting view change.
  assert!(
    !e.pending_swap_for_test(),
    "the staged swap was consumed by the install after the view change"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the epoch swapped to E+1 after the interrupting view change (the committed change is not lost)",
  );
  assert_eq!(
    e.membership, successor,
    "the successor membership installed post-view-change"
  );
}

#[test]
fn a_lost_reconfigure_prepare_is_retransmitted_and_then_commits() {
  // CONSENSUS-LIVENESS: a `Reconfigure` op rides the prepare-retransmit channel like a client op. The
  // primary mints the change, the one-shot `Prepare` is DROPPED (no backup hears it), and the op then
  // sits uncommitted in `(commit_min, op]` — blocking every later proposal via `has_pending_reconfigure`.
  // The retransmit tick MUST re-ship it (with its reconfiguration body) or the change stalls forever
  // until a view change happens to truncate it. The body the retransmit carries must content-address the
  // successor membership, so a backup replaying it through `on_prepare` rebuilds a typed `Body::Reconfigure`.
  let mut e = single_change_primary();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter is a valid delta on a 3-voter cluster");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  let op = e
    .propose_membership(now, &mut wal, SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the primary mints the reconfiguration op");
  // DROP the one-shot broadcast Prepare: no backup ever hears the initial transmission.
  while e.poll_message().is_some() {}
  // The primary's own append lands (its own vote), but with the Prepare dropped no quorum forms — the
  // Reconfigure op is stuck uncommitted in the un-acked window.
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(
    e.commit() < op,
    "the Reconfigure op is uncommitted (its only Prepare was dropped, so no quorum acked it)"
  );

  // Fire the prepare-retransmit tick: it MUST re-ship the Reconfigure op (TODAY it skips the op because
  // its body is `Body::Reconfigure`, not `Body::Present` — the op is never resent and the change stalls).
  e.handle_timeout(now + super::super::PREPARE_RETRANSMIT, &mut wal, &mut sb);
  let mut retransmitted_body: Option<bytes::Bytes> = None;
  while let Some(out) = e.poll_message() {
    match out.into_msg() {
      Message::PrepareBatch(b) => {
        for entry in b.log_slice() {
          if entry.op() == op {
            assert_eq!(
              entry.client(),
              ClientId::RECONFIGURATION,
              "the retransmitted op is the reconfiguration op"
            );
            retransmitted_body = entry.body().map(bytes::Bytes::copy_from_slice);
          }
        }
      }
      Message::Prepare(p) if p.op() == op => {
        retransmitted_body = Some(p.body_bytes());
      }
      _ => {}
    }
  }
  let body = retransmitted_body
    .expect("the dropped reconfiguration Prepare is re-shipped on the retransmit tick");
  assert_eq!(
    crate::storage::fnv1a_128(&body),
    Body::Reconfigure(payload.clone()).body_checksum(),
    "the retransmitted body content-addresses the successor membership (a backup rebuilds Body::Reconfigure)",
  );

  // The re-shipped Prepare is now received by a backup quorum: feed the primary the resulting acks so the
  // change commits + stages its swap (the retransmit actually unblocks ordered commit, not just re-emits).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    reconfigure_ack(op.get(), &payload, 1),
  );
  assert_eq!(
    e.commit(),
    op,
    "the Reconfigure op committed once the retransmit reached a quorum"
  );
  assert!(
    e.pending_swap_for_test(),
    "the commit-first swap staged — the retransmitted reconfiguration op was recognized at commit"
  );
  e.handle_storage(now, &mut wal, &mut sb); // land the SwapEpoch root → install
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the epoch swapped to E+1 — the once-dropped reconfiguration installed via the retransmit",
  );
  assert_eq!(
    e.membership, successor,
    "the successor membership installed"
  );
}

#[test]
fn header_only_adoption_preserves_the_new_primarys_local_reconfigure_body() {
  // CONSENSUS-SAFETY: a new primary that is the SOLE holder of a carried (uncommitted) reconfiguration
  // body must PRESERVE its local `Body::Reconfigure` when the canonical DVC/StartView carrier is
  // header-only (`Body::Repairing` — every real view-change carrier is). `adopt_log` preserves a matching
  // LOCAL body when the incoming entry is header-only; if that preservation recognizes only `Body::Present`,
  // a replica holding the op as `Body::Reconfigure` has its local payload IGNORED and overwritten by the
  // incoming `Repairing` — an unfillable hole instead of recommit+install, the only live payload dropped.
  //
  // Replica 1 becomes the primary of view 1. It holds op 2 LOCALLY as `Body::Reconfigure` (it received the
  // view-0 Prepare for it). The canonical log of view 1 carries op 2 HEADER-ONLY (its own DVC, built by
  // `log_entries()`, is all `Repairing`). Adoption must keep replica 1's local reconfiguration body.
  let mut e = Endpoint::<CountSm, SingleChange>::with_reconfig(
    Config::try_new(1, MemberId::new(1)).expect("valid cluster config"),
    genesis(3),
    0,
    CountSm::default(),
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter is a valid delta on a 3-voter cluster");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  // (1) Replica 1 (a view-0 backup) receives the view-0 primary's Prepares: a client op at op 1, then the
  // reconfiguration op at op 2. It now holds op 2 LOCALLY as a typed `Body::Reconfigure`.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ClientId::new(7),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"a"),
    )),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(1),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ClientId::RECONFIGURATION,
      RequestNumber::with(2),
      payload.encode_body(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  assert_eq!(
    e.log.get(&2).expect("op 2 is held locally").body,
    Body::Reconfigure(payload.clone()),
    "replica 1 holds the reconfiguration op LOCALLY as a typed Body::Reconfigure",
  );

  // (2) Drive replica 1 into ViewChange(1): its idle timer proposes a view change, one peer's SVC reaches
  // the 2-of-3 SVC quorum.
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}

  // (3) Two DVCs reach the new primary. Replica 1's OWN DVC (folded in) carries op 2 header-only
  // (`log_entries()` is all `Repairing`). Replica 2's DVC carries op 1 + op 2 ALSO header-only — it is the
  // canonical carrier but, like every real carrier, body-less. So no incoming entry carries the
  // reconfiguration BODY: only replica 1's LOCAL `Body::Reconfigure` has it. `commit* = 1`, so op 2 is the
  // uncommitted tail (not nack-truncated: replica 2 vouches `op == 2`, no nack quorum below it).
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::repairing(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        Body::Present(bytes::Bytes::from_static(b"a")).body_checksum(),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::RECONFIGURATION,
        RequestNumber::with(2),
        Body::Reconfigure(payload.clone()).body_checksum(),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  assert!(e.is_primary(), "replica 1 is now the primary of view 1");
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "the reconfiguration op was adopted"
  );

  // THE BUG: adoption must NOT overwrite replica 1's local `Body::Reconfigure` with the incoming
  // header-only `Repairing` (TODAY the preserve only recognizes `Body::Present`, so op 2 becomes an
  // unfillable hole). Replica 1 is the only live holder of the reconfiguration body — it must keep it.
  assert_eq!(
    e.log
      .get(&2)
      .expect("op 2 is in the new primary's log")
      .body,
    Body::Reconfigure(payload.clone()),
    "header-only adoption PRESERVED the new primary's local Body::Reconfigure (not overwritten to a hole)",
  );
  assert!(
    e.has_pending_reconfigure_for_test(),
    "the carried uncommitted reconfiguration is recognized as in-flight from the preserved log entry"
  );

  // (4) Drive the new primary to settle + recommit the carried reconfiguration: drain its durable-view
  // write, then feed it the acks for op 2 under view 1 so it commits + stages the swap, and install.
  for _ in 0..8 {
    e.handle_storage(now, &mut wal, &mut sb);
    while e.poll_message().is_some() {}
    if e.commit() >= OpNumber::with(2) {
      break;
    }
    // The new primary re-commits op 2 once a quorum re-acks it under view 1.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::PrepareOk(crate::PrepareOk::new(
        View::with(1),
        OpNumber::with(2),
        ReplicaId::new(2),
        OpNumber::new(),
        crate::storage::prepare_identity(
          ClientId::RECONFIGURATION,
          RequestNumber::with(2),
          Body::Reconfigure(payload.clone()).body_checksum(),
        ),
        crate::Epoch::new(0),
        0,
      )),
    );
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "the carried reconfiguration op re-committed under the new view (its preserved body let it commit)"
  );
  for _ in 0..8 {
    e.handle_storage(now, &mut wal, &mut sb);
    while e.poll_message().is_some() {}
    if !e.pending_swap_for_test() {
      break;
    }
  }
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the epoch swapped to E+1 — the preserved reconfiguration installed (no unfillable hole)",
  );
  assert_eq!(
    e.membership, successor,
    "the successor membership installed"
  );
}

/// Build a DONOR at E+1 holding a durable checkpoint, where a RETAINED member's slot SHIFTED across the
/// swap. Genesis is a 4-voter cluster `[0,1,2,3]` led by `MemberId 0` (slot 0). A `RemoveVoter(MemberId 1)`
/// commits under E (4 voters, quorum 3), then the swap lands E+1 = `[0,2,3]` (voter slots 0,1,2) and FORCES
/// a checkpoint embedding the reconfigure op `N`. The donor `MemberId 0` keeps slot 0 (still primary); the
/// retained `MemberId 2` SHIFTED from old slot 2 to new slot 1 — the cross-epoch slot-shifted laggard.
/// Returns `(donor, wal, sb, predecessor_config_id, checkpoint_op)`.
fn donor_at_e1_with_shifted_member() -> (Endpoint<CountSm, SingleChange>, TestWal, TestSb, u128, u64)
{
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  let mut e =
    Endpoint::<CountSm, SingleChange>::with_reconfig(cfg, genesis(4), 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let predecessor_config_id = e.membership.config_id();

  // E+1 successor: remove the LOW-indexed MemberId 1, shifting MemberId 2 (slot 2 -> 1) and MemberId 3
  // (slot 3 -> 2). The donor MemberId 0 keeps slot 0.
  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::RemoveVoter(MemberId::new(1)))
    .expect("RemoveVoter(1) on a 4-voter cluster is valid (leaves 3 voters)");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  // Propose + commit under E (quorum 3 of 4: the primary's own vote + acks from slots 1 and 2).
  let op = e
    .propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::RemoveVoter(MemberId::new(1)),
    )
    .expect("the primary mints the reconfiguration op");
  while e.poll_message().is_some() {}
  e.handle_storage(now, &mut wal, &mut sb); // the primary's own append lands (own vote)
  for acker in [1u16, 2u16] {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(acker)),
      reconfigure_ack(op.get(), &payload, acker),
    );
  }
  // Drain the SwapEpoch root + its forced checkpoint (snapshot -> durable root) to completion.
  for _ in 0..8 {
    e.handle_storage(now, &mut wal, &mut sb);
    while e.poll_message().is_some() {}
  }
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the donor swapped to E+1"
  );
  assert_eq!(e.membership, successor, "the donor installed E+1 = [0,2,3]");
  assert!(
    e.checkpoint_op().get() >= op.get() && e.checkpoint_op().get() > 0,
    "a forced checkpoint embedding the reconfigure op landed (checkpoint_op {} >= N {})",
    e.checkpoint_op().get(),
    op.get(),
  );
  let checkpoint_op = e.checkpoint_op().get();
  (e, wal, sb, predecessor_config_id, checkpoint_op)
}

#[test]
fn a_slot_shifted_cross_epoch_request_sync_is_served_not_dropped_at_the_sender_binding() {
  // FINDING 1 — the cross-epoch RequestSync sender binding. After a slot-shifting reconfiguration, a
  // RETAINED laggard solicits a cross-epoch checkpoint with a RequestSync stamping its OLD slot (its slot
  // in its own stale membership) and the OLD (predecessor) config_id. The transport binds `from` to the
  // laggard's CURRENT slot in the DONOR's active membership; the old claimed slot and `from` DIFFER, so the
  // STRICT self-id binding would DROP the request before `on_request_sync` and the laggard could NEVER
  // receive the crossing checkpoint. The relaxed binding admits it on `from`'s member identity (the claimed
  // slot carries no authority — a RequestSync is a pure solicitation answered only by a committed-vouched
  // checkpoint), and the donor serves the reply ADDRESSED TO `from`'s CURRENT slot so it routes back.
  let (mut donor, mut wal, mut sb, predecessor_config_id, checkpoint_op) =
    donor_at_e1_with_shifted_member();
  let now = Instant::ZERO;
  assert_ne!(
    predecessor_config_id,
    donor.membership.config_id(),
    "E and E+1 config_ids genuinely differ (a real hash-chained swap)"
  );

  // The slot-shifted laggard is MemberId 2: OLD slot 2 (what it stamps), CURRENT slot 1 (what `from` binds
  // to in the donor's E+1 membership [0,2,3]).
  let old_claimed_slot = ReplicaId::new(2);
  let current_slot = ReplicaId::new(1);
  let from = Peer::Replica(current_slot);
  let request_sync = |slot: ReplicaId, config_id: u128| {
    Message::RequestSync(crate::RequestSync::new(
      View::new(),
      OpNumber::new(), // the laggard is far behind (checkpoint 0), so the donor's checkpoint is in-reach
      slot,
      0xBEEF,
      false,
      config_id,
    ))
  };

  // Deliver the cross-epoch RequestSync: claimed slot = OLD slot 2, config_id = the PREDECESSOR (E) id,
  // authenticated `from` = the laggard's CURRENT slot 1.
  donor.handle_message(
    now,
    &mut wal,
    &mut sb,
    from,
    request_sync(old_claimed_slot, predecessor_config_id),
  );
  donor.handle_storage(now, &mut wal, &mut sb); // drive the serve-read completion → ship the SyncCheckpoint

  // The donor SERVED it: a SyncCheckpoint (or its over-frame announce) addressed to the laggard's CURRENT
  // slot, carrying the donor's E+1 membership (the cross-epoch crossing payload). It was NOT dropped at the
  // sender binding.
  let mut served_to_current_slot = false;
  while let Some(out) = donor.poll_message() {
    match out.msg_ref() {
      Message::SyncCheckpoint(scp) => {
        assert_eq!(
          out.to(),
          Recipient::To(from),
          "the SyncCheckpoint routes to the laggard's CURRENT slot (not the stale claimed slot)"
        );
        assert_eq!(
          scp.checkpoint_op().get(),
          checkpoint_op,
          "serves the donor's durable checkpoint"
        );
        assert!(
          !scp.membership().is_empty(),
          "the cross-epoch serve attaches the E+1 successor membership (XI-b gate satisfied by the forced \
           checkpoint)"
        );
        served_to_current_slot = true;
      }
      Message::SyncCheckpointMeta(meta) => {
        assert_eq!(
          out.to(),
          Recipient::To(from),
          "the over-frame announce also routes to the current slot"
        );
        assert_eq!(meta.checkpoint_op().get(), checkpoint_op);
        served_to_current_slot = true;
      }
      _ => {}
    }
  }
  assert!(
    served_to_current_slot,
    "the slot-shifted cross-epoch RequestSync was admitted to on_request_sync and SERVED — not dropped"
  );

  // GUARD: the strict binding still bites for the no-shift forge surface. A RequestSync whose claimed slot
  // DISAGREES with `from` AND whose config_id is the donor's CURRENT (E+1) config — i.e. NOT a cross-epoch
  // ancestor solicitation, just a mismatched self-id — is DROPPED (no relaxation).
  let (mut d2, mut w2, mut s2, _pred, _ck) = donor_at_e1_with_shifted_member();
  let current_config = d2.membership.config_id();
  d2.handle_message(
    now,
    &mut w2,
    &mut s2,
    Peer::Replica(ReplicaId::new(2)),                // from = slot 2
    request_sync(ReplicaId::new(0), current_config), // claims slot 0, CURRENT config (not an ancestor)
  );
  d2.handle_storage(now, &mut w2, &mut s2);
  assert!(
    !d2.poll_message().is_some_and(|o| matches!(
      o.msg_ref(),
      Message::SyncCheckpoint(_) | Message::SyncCheckpointMeta(_)
    )),
    "a same-config mismatched-self-id RequestSync is still DROPPED by the strict binding (no relaxation)"
  );
}

/// Re-plant `donor`'s durable checkpoint (built by [`donor_at_e1_with_shifted_member`]) with an
/// OVER-FRAME snapshot at the SAME `checkpoint_op`, PRESERVING its E+1 epoch / membership / lineage /
/// `config_install_op` — so the donor answers a state-sync solicitation with a `SyncCheckpointMeta`
/// announce (the chunked path) instead of a single-frame `SyncCheckpoint`, while still attaching the
/// E+1 successor membership (the XI-b serve gate `checkpoint_op >= config_install_op` holds). Returns
/// the planted `(env, id)` for the test to feed back as chunks.
fn replant_over_frame(
  donor: &mut Endpoint<CountSm, SingleChange>,
  sb: &mut TestSb,
) -> (Bytes, u128) {
  let root = sb.state();
  let big = crate::message::max_unchunked_snapshot_len() + 4096;
  let env = Endpoint::<CountSm>::encode_checkpoint(
    root.checkpoint_op(),
    &std::collections::BTreeMap::new(),
    &std::vec![0x5Au8; big],
  );
  assert!(
    env.len() > crate::message::max_unchunked_snapshot_len(),
    "the re-planted envelope exceeds the one-frame budget (forces the chunked serve)"
  );
  let id = crate::checkpoint_id(&env);
  // Rebuild the durable root with the SAME E+1 scalars, only swapping the checkpoint id to the
  // over-frame envelope's. `config_install_op` (the reconfigure op) is preserved, so the serve still
  // attaches the successor membership. The in-memory `checkpoint_op` is unchanged (we re-plant at the
  // SAME op), so the donor's serve gates (`cr.op() == self.checkpoint_op`, the durable-id match) hold.
  sb.state = crate::VsrState::try_new_v4(
    root.view(),
    root.log_view(),
    root.commit(),
    root.checkpoint_op(),
    id,
    root.committed_headers_slice().to_vec(),
    root.epoch(),
    root.prev_epoch(),
    root.membership().clone(),
    root.prior_config_ids().to_vec(),
    root.config_install_op(),
  )
  .expect("the re-planted E+1 root is valid");
  sb.checkpoint = Some((root.checkpoint_op(), env.clone()));
  let _ = donor; // the in-memory checkpoint_op is already aligned (re-plant is at the same op).
  (env, id)
}

#[test]
fn a_slot_shifted_cross_epoch_chunk_pull_is_served_and_the_chunk_routes_to_the_current_slot() {
  // CLASS 1, the CHUNKED leg. When the donor's crossing checkpoint is OVER-FRAME it answers a state-sync
  // solicitation with a `SyncCheckpointMeta` announce, and the slot-shifted laggard then PULLS the
  // envelope with `RequestSyncChunk`s — which stamp the SAME stale OLD slot as the initial `RequestSync`.
  // The strict self-id binding would DROP those chunk pulls before `on_request_sync_chunk` (stranding the
  // over-frame crossing even though the OFFER pull was admitted), and even if admitted the served chunk
  // would route to the stale slot. The shared relaxation admits the chunk pull on `from`'s member
  // identity, and the serve addresses the `SyncChunk` to `from`'s CURRENT slot — so a slot-shifted
  // laggard can pull, reassemble, and cross over the chunked path. (The reassembly+install half is pinned
  // by `the_chunked_reassembly_carries_the_same_epoch_and_membership_as_the_single_frame_form`; this pins
  // the donor-side admit+route that feeds it for a slot-shifted requester.)
  let (mut donor, mut wal, mut sb, predecessor_config_id, checkpoint_op) =
    donor_at_e1_with_shifted_member();
  let now = Instant::ZERO;
  let (env, id) = replant_over_frame(&mut donor, &mut sb);

  // The slot-shifted laggard is MemberId 2: OLD slot 2 (what it stamps), CURRENT slot 1 (what `from`
  // binds to in the donor's E+1 membership [0,2,3]).
  let old_claimed_slot = ReplicaId::new(2);
  let current_slot = ReplicaId::new(1);
  let from = Peer::Replica(current_slot);

  // 1) The OFFER pull (RequestSync) with the STALE slot + the predecessor config_id — admitted via the
  //    shared binding, answered with the over-frame ANNOUNCE routed to the CURRENT slot.
  donor.handle_message(
    now,
    &mut wal,
    &mut sb,
    from,
    Message::RequestSync(crate::RequestSync::new(
      View::new(),
      OpNumber::new(),
      old_claimed_slot,
      0xBEEF,
      false,
      predecessor_config_id,
    )),
  );
  donor.handle_storage(now, &mut wal, &mut sb); // serve-read completes → announce + warm the cache
  let mut announced = None;
  while let Some(out) = donor.poll_message() {
    if let Message::SyncCheckpointMeta(meta) = out.msg_ref() {
      assert_eq!(
        out.to(),
        Recipient::To(from),
        "the over-frame announce routes to the laggard's CURRENT slot"
      );
      assert_eq!(meta.checkpoint_op().get(), checkpoint_op);
      assert!(
        !meta.membership().is_empty(),
        "the announce carries the E+1 successor membership (XI-b gate satisfied)"
      );
      announced = Some(meta.clone());
    }
  }
  let announce =
    announced.expect("the over-frame donor announces (never ships one oversized frame)");
  assert!(
    donor.sync_donating.is_some(),
    "the verified serve-read warmed the donor cache (chunk pulls are cache slices)"
  );

  // 2) The CHUNK pulls (RequestSyncChunk) with the SAME stale slot — admitted via the shared relaxation,
  //    and the SyncChunk serve routes to the CURRENT slot. Collect the whole envelope + confirm it
  //    reassembles to the announced content (so a slot-shifted laggard genuinely receives a crossable
  //    envelope).
  let pull_chunk = |donor: &mut Endpoint<CountSm, SingleChange>,
                    wal: &mut TestWal,
                    sb: &mut TestSb,
                    offset: u64|
   -> crate::SyncChunk {
    donor.handle_message(
      now,
      wal,
      sb,
      from, // authenticated current slot 1
      Message::RequestSyncChunk(crate::RequestSyncChunk::new(
        View::new(),
        announce.checkpoint_op(),
        id,
        predecessor_config_id, // the laggard stamps its OLD (ancestor) config_id
        offset,
        old_claimed_slot, // and its OLD (stale) slot — the relaxation must admit it
        0xBEEF,
      )),
    );
    let mut chunk = None;
    while let Some(out) = donor.poll_message() {
      if let Message::SyncChunk(c) = out.msg_ref() {
        assert_eq!(
          out.to(),
          Recipient::To(from),
          "the SyncChunk routes to the laggard's CURRENT slot, NOT the stale claimed slot"
        );
        chunk = Some(c.clone());
      }
    }
    chunk.expect("the slot-shifted chunk pull was ADMITTED and served (not dropped at the binding)")
  };
  let first = pull_chunk(&mut donor, &mut wal, &mut sb, 0);
  assert_eq!(first.offset(), 0);
  let tail_offset = first.bytes().len() as u64;
  let tail = pull_chunk(&mut donor, &mut wal, &mut sb, tail_offset);
  assert_eq!(
    tail_offset + tail.bytes().len() as u64,
    env.len() as u64,
    "the two chunks span the whole envelope"
  );
  let mut staged = std::vec::Vec::with_capacity(env.len());
  staged.extend_from_slice(first.bytes());
  staged.extend_from_slice(tail.bytes());
  assert_eq!(
    crate::checkpoint_id(&staged),
    id,
    "the slot-shifted-pulled chunks reassemble the exact announced (crossable) envelope"
  );

  // GUARD: the chunk-pull binding still bites the same-config forge surface. A RequestSyncChunk whose
  // claimed slot DISAGREES with `from` but whose config_id is the donor's CURRENT (E+1) config — NOT an
  // ancestor solicitation — is DROPPED (no relaxation), exactly like the same-config RequestSync guard.
  let current_config = donor.membership.config_id();
  donor.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)), // from = slot 2
    Message::RequestSyncChunk(crate::RequestSyncChunk::new(
      View::new(),
      announce.checkpoint_op(),
      id,
      current_config, // CURRENT config, not an ancestor
      0,
      ReplicaId::new(0), // claims slot 0 (disagrees with from)
      0xBEEF,
    )),
  );
  assert!(
    !donor
      .poll_message()
      .is_some_and(|o| matches!(o.msg_ref(), Message::SyncChunk(_))),
    "a same-config mismatched-self-id RequestSyncChunk is still DROPPED by the strict binding"
  );
}

#[test]
fn a_slot_shifted_cross_epoch_request_prepare_is_served_and_routes_to_the_current_slot() {
  // CLASS 1, the REPAIR-body leg. A slot-shifted retained laggard pulls a committed log body with
  // `RequestPrepare` stamped with its OLD slot. The strict self-id binding would DROP it before
  // `on_request_prepare`, and even if admitted the served `Prepare` would route to the stale slot. The
  // shared solicitation relaxation admits the pull on `from`'s member identity, and the serve addresses
  // the `Prepare` to `from`'s CURRENT slot — so a slot-shifted laggard repairs predecessor-log bodies from
  // current-epoch donors. (The chunked SYNC leg is pinned by
  // `a_slot_shifted_cross_epoch_chunk_pull_is_served_and_the_chunk_routes_to_the_current_slot`.)
  let (mut donor, mut wal, mut sb, predecessor_config_id, _checkpoint_op) =
    donor_at_e1_with_shifted_member();
  let now = Instant::ZERO;
  // MemberId 2: OLD slot 2 (what it stamps), CURRENT slot 1 (what `from` binds to in the E+1 [0,2,3]).
  let old_claimed_slot = ReplicaId::new(2);
  let current_slot = ReplicaId::new(1);
  let from = Peer::Replica(current_slot);

  // A `RequestPrepare` for the committed reconfigure op (op 1) with the STALE slot + the predecessor
  // (ancestor) config_id — admitted via the shared binding, answered with the body routed to CURRENT slot.
  donor.handle_message(
    now,
    &mut wal,
    &mut sb,
    from,
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(1),
      old_claimed_slot,
      predecessor_config_id,
    )),
  );
  let mut served = false;
  while let Some(out) = donor.poll_message() {
    if let Message::Prepare(_) = out.msg_ref() {
      assert_eq!(
        out.to(),
        Recipient::To(from),
        "the repair Prepare routes to the laggard's CURRENT slot, not the stale claimed slot"
      );
      served = true;
    }
  }
  assert!(
    served,
    "the slot-shifted RequestPrepare was admitted (shared solicitation binding) + served to the current slot"
  );

  // GUARD: a SAME-config (E+1) RequestPrepare whose claimed self-id MISMATCHES `from` is still DROPPED by
  // the strict binding — the relaxation is scoped to STRICT-ANCESTOR config solicitations only.
  let e1_config = donor.membership.config_id();
  donor.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(current_slot),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(2), // mismatched self-id, but SAME config (E+1) → strict binding applies
      e1_config,
    )),
  );
  assert!(
    !donor
      .poll_message()
      .is_some_and(|o| matches!(o.msg_ref(), Message::Prepare(_))),
    "a same-config mismatched-self-id RequestPrepare is still DROPPED by the strict binding"
  );
}

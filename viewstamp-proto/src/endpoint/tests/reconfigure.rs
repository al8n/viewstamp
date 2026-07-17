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
  Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  )
}

/// A 3-voter `SingleChange` endpoint whose local member is slot 1 — a BACKUP under view 0.
fn single_change_backup() -> Endpoint<CountSm, SingleChange> {
  let cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  )
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
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner is a valid delta on a 3-voter cluster");
  let expected_payload = ReconfigurePayload::from_membership(&successor, 0);

  let before_op = e.op();
  let op = e
    .propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(3)),
    )
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
    .propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(3)),
    )
    .expect("the first proposal mints an op");

  // A second proposal while the first is uncommitted is refused — single change at a time.
  assert_eq!(
    e.propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(4))
    ),
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

/// Propose `AddLearner(3)` on a fresh 3-voter SingleChange primary and drive it to COMMIT — but stop
/// the instant it commits, BEFORE the staged `SwapEpoch` root is made durable. Returns the endpoint,
/// its storage, the minted op, and the successor membership / payload. `AddLearner` is the accepted
/// membership-changing delta used to exercise the reconfigure MACHINERY (mint → commit → swap → carry)
/// independently of any voter-set change; direct `AddVoter` is refused at propose time.
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner is a valid delta on a 3-voter cluster");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  let op = e
    .propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(3)),
    )
    .expect("the primary mints the reconfiguration op");
  while e.poll_message().is_some() {} // drop the broadcast Prepare
  // The primary's own WAL append lands → its own vote is recorded (1 of 3).
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  // One backup ack reaches the 2-of-3 commit quorum → the op commits and stages SwapEpoch.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  // The SwapEpoch root MUST carry the WAL-geometry witness — a swap changes only the configuration,
  // not the geometry. A crash in the window between this root landing and the forced-checkpoint root
  // is reachable, so recovery off THIS root must see a FORMATTED store: without the geometry it would
  // read as unformatted, skip the geometry fence, AND fail-stop this legitimately-reconfigured voter.
  assert_ne!(
    sb.state().checkpoint_ops(),
    0,
    "the SwapEpoch root pins the WAL-geometry witness (a crash in the swap window stays recoverable)"
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let recovered = Endpoint::<CountSm, SingleChange>::recover_with_reconfig(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    &mut rwal,
    &mut rsb,
    &mut blocks,
  )
  .expect("recover accepts this store");
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // land the SwapEpoch root → install
  assert!(
    e.sm_for_test().applied().is_empty(),
    "the Reconfigure op was never applied to the state machine"
  );
}

#[test]
fn e_epoch_ops_sit_at_or_below_commit_max_after_a_swap_so_are_never_nack_candidates() {
  // No E+1 participant can nack-truncate a predecessor-epoch committed op after an epoch swap. The reason
  // is structural, not a nack-side check: committing the `Reconfigure` op N lifts `commit_max >= N` (in
  // `commit_reconfigure`, before the SwapEpoch even stages), and the mint fence makes N the LAST op of its
  // epoch — so every E-epoch op sits at/below `commit_max` once the swap installs. A repair-or-truncate
  // candidate is STRICTLY above `commit_max`, so no E-epoch op is ever a candidate in E+1, and `on_nack`'s
  // candidate re-check drops any nack for it regardless of the successor voter set / quorum. This pins the
  // invariant that keeps the counting-proof truncation safe across any epoch swap.
  let (mut e, mut wal, mut sb, op, _successor, _payload) = proposed_and_committed_swap();
  let mut blocks = crate::block_store::MemBlockStore::new();
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // land the SwapEpoch root → install E+1
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the epoch swapped to E+1"
  );
  assert!(
    e.commit_max() >= op,
    "committing the reconfigure op N (op {}) lifted commit_max ({}) to >= N before the E+1 config installed",
    op.get(),
    e.commit_max().get(),
  );
  // Every E-epoch op (1..=N) is at/below commit_max — the committed band — never strictly above it (the
  // region a repair-or-truncate candidate must occupy). So a new E+1 voter's nack can never truncate one.
  for x in 1..=op.get() {
    assert!(
      x <= e.commit_max().get(),
      "E-epoch op {x} is <= commit_max {} — subsumed in the committed band, never a nack candidate",
      e.commit_max().get(),
    );
  }
}

#[test]
fn on_the_durable_root_the_epoch_swaps_and_membership_changed_is_emitted() {
  // Once the SwapEpoch root lands, `install_membership` runs: epoch == old+1, prev_epoch == old, the
  // successor membership is active, and a `MembershipChanged` event is emitted.
  let (mut e, mut wal, mut sb, op, successor, _payload) = proposed_and_committed_swap();
  let mut blocks = crate::block_store::MemBlockStore::new();
  // Drain any pre-swap events (the committed-op band, etc.) so the swap event is observable cleanly.
  while e.poll_event().is_some() {}

  e.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // land the SwapEpoch root

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
    "the successor membership (3 voters + 1 learner, chained config_id) is now active"
  );
  assert_eq!(
    e.membership.learner_count(),
    1,
    "the new learner is in the set"
  );
  assert_eq!(
    e.membership.replica_count(),
    3,
    "the voting set is unchanged by an AddLearner"
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
  let mut blocks = crate::block_store::MemBlockStore::new();
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.config_install_op, op,
    "the install recorded the reconfigure op as config_install_op = N"
  );
  // Drain the two-write forced checkpoint (snapshot → durable root) to completion.
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
fn a_swap_forced_checkpoint_flush_fault_is_self_retried_by_the_primary_heartbeat_with_no_client_commits()
 {
  // The SwapEpoch arm forces a post-swap checkpoint at M >= N; if its block-store flush faults TRANSIENTLY
  // the checkpoint is NOT submitted, leaving `config_install_op (N) > checkpoint_op` — the debt that makes
  // a donor WITHHOLD the successor membership from a cross-epoch laggard. A QUIESCENT new-epoch primary
  // (no client traffic) has no commit-advance tail to re-force it, so it must SELF-HEAL off its heartbeat:
  // the debt-pay path is armed from the primary timer, and once the flush recovers it re-forces the owed
  // checkpoint, opening the cross-epoch serve gate — with NO subsequent client commit or restart.
  let (mut e, mut wal, mut sb, op, _successor, _payload) = proposed_and_committed_swap();
  let mut blocks = crate::block_store::MemBlockStore::new();
  // The SwapEpoch arm's forced checkpoint hits a flush fault (1 fault, then durable).
  blocks.script_flush_fault(1);
  let now = Instant::ZERO;

  // Land the SwapEpoch root: `install_membership` sets `config_install_op = N`, then `force_checkpoint`
  // FAILS the flush → no checkpoint is submitted and the debt is owed.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.config_install_op, op,
    "the install recorded the reconfigure op as config_install_op = N"
  );
  // Drain any in-flight storage. The forced checkpoint never staged (the flush faulted), so the durable
  // checkpoint stays at 0 and the debt (`config_install_op N > checkpoint_op 0`) is owed + WITHHELD.
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::new(),
    "the flush fault held the SwapEpoch forced checkpoint back — no durable checkpoint"
  );
  assert!(
    e.config_install_op > e.checkpoint_op(),
    "the SwapEpoch debt is owed (config_install_op {} > checkpoint_op {}) → the successor membership is \
     withheld from a cross-epoch laggard",
    e.config_install_op.get(),
    e.checkpoint_op().get(),
  );

  // QUIESCENT: deliver NO client message ever again. Drive ONLY the primary heartbeat timer (and the
  // synchronous storage it stages) forward. The flush has recovered, so the heartbeat-armed debt-pay
  // re-forces the owed checkpoint and its two-write root drains to durability.
  let mut later = now;
  for _ in 0..8 {
    later = later + core::time::Duration::from_millis(60);
    e.handle_timeout(later, &mut wal, &mut sb, &mut blocks);
    e.handle_storage(later, &mut wal, &mut sb, &mut blocks);
  }

  // The debt is paid with no client commit: the checkpoint now embeds N and the serve gate holds.
  assert!(
    e.checkpoint_op() >= e.config_install_op,
    "the primary self-healed the SwapEpoch debt off its heartbeat: checkpoint_op {} >= config_install_op \
     {} (cross-epoch serve gate now open)",
    e.checkpoint_op().get(),
    e.config_install_op.get(),
  );
  assert_eq!(
    e.checkpoint_op(),
    op,
    "the self-retried forced checkpoint landed at M == N"
  );
  assert_eq!(
    sb.state().checkpoint_op(),
    op,
    "the self-retried forced checkpoint is durable"
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
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid (E+1)");
  let successor_e2 = successor_e1
    .apply_delta(&SingleVoterDelta::PromoteLearner(MemberId::new(3)))
    .expect("promoting the E+1 learner off the E+1 successor is valid (E+2)");

  // A Normal BACKUP (slot 1) that committed its OWN reconfigure op N1 (op == commit_min == N1), checkpoint 0.
  let cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  let mut e = Endpoint::<CountSm>::genesis_unchecked(
    cfg,
    genesis_mem.clone(),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
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
  let cross_snap = CountSm::default().snapshot();
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(m2),
    crate::block_address(&cross_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  // Seed the crossing checkpoint's single leaf so the install frontier drains with no RequestBlock round
  // trip (the small envelope now names the SM root by address, not inline bytes).
  blocks.write_verified(cross_snap.clone());
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
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // SwapEpoch root → install_membership(N1) + force_checkpoint
  assert_eq!(
    e.membership.epoch(),
    successor_e1.epoch(),
    "the node's own swap installed E+1"
  );
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drain the forced checkpoint (snapshot -> root)
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
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    cross_msg(nonce2),
  );
  assert!(
    e.pending_install.is_some(),
    "with the root cleared, the re-solicited reply STAGED the crossing install (no longer deferred)"
  );
  for _ in 0..3 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the two-write re-persist -> durable root -> install
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
  let mut e = Endpoint::<CountSm>::genesis_unchecked(
    cfg,
    genesis_mem.clone(),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
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
  let cross_snap = CountSm::default().snapshot();
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(n1),
    crate::block_address(&cross_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  // Seed the crossing checkpoint's single leaf so the install frontier drains with no RequestBlock round
  // trip (the small envelope names the SM root by address, not inline bytes).
  blocks.write_verified(cross_snap.clone());
  let cross_id = crate::checkpoint_id(&cross_env);
  let membership_body =
    ReconfigurePayload::from_membership(&successor_e1, genesis_config_id).encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
fn a_recovery_peer_fetch_install_error_re_fetches_and_completes_without_stranding() {
  // The RECOVERY peer-fetch restore-error retry must stay SERVICEABLE while Recovering. A laggard on the
  // recovery peer-fetch path (`enter_cross_epoch_peer_fetch` → Recovering, `awaiting_peer_checkpoint`)
  // stages the synced re-persist via `apply_sync`, which CLEARS `recover` + `recover_retry` and stays
  // Recovering. If a local checkpoint block CORRUPTS between the frontier draining and the destructive
  // `install_sync` (run when the durable root lands), the restore returns an error WITH NOTHING MUTATED.
  // The retry must NOT lean on `sync_solicit` — that timer is serviced ONLY while Normal, so a recovery
  // install error would strand the node Recovering with no serviced re-fetch path. It must re-create the
  // peer-fetch (`awaiting_peer_checkpoint`) and re-arm the recovery cadence (`recover_retry`, serviced by
  // `recover_timeouts`), and it must NOT hold `pending_install` while `pending_checkpoint` is clear (the
  // `pending_install ⟹ in-flight SyncRepersist` sub-state invariant). Once the clean block is re-fetched,
  // the install retries and recovery completes to Normal — the `assert_invariants` at every handler exit
  // would PANIC if the sub-state invariant were violated, so reaching the end proves it held throughout.
  let n1: u64 = 2; // the node's OWN reconfigure op N (E0 -> E1); committed band is ops (0 .. N].
  let genesis_mem = genesis(3);
  let successor_e1 = genesis_mem
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid (E+1)");
  let genesis_config_id = genesis_mem.config_id();

  // A BACKUP (slot 1) at E0, Normal, that committed its own reconfigure op N (op == commit_min == N),
  // checkpoint 0 — the commit-first window before the SwapEpoch root installs.
  let cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  let mut e = Endpoint::<CountSm>::genesis_unchecked(
    cfg,
    genesis_mem.clone(),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.force_state_for_test(0, n1, n1, 0, &[]);
  e.stage_epoch_swap(OpNumber::with(n1), successor_e1.clone(), &mut sb);

  // A higher-epoch heartbeat routes the non-Normal laggard into the recovery peer-fetch.
  e.enter_cross_epoch_peer_fetch(now, OpNumber::with(n1));
  assert!(
    e.status() == Status::Recovering
      && e.awaiting_peer_checkpoint_for_test()
      && e.sync_requires_cross_epoch_for_test(),
    "setup: a Recovering peer-fetch with a forced crossing-required sync"
  );

  // The crossing checkpoint: the E1 successor chained off genesis at op N. The SM root IS seeded (valid),
  // so the frontier drains in one shot when the SyncCheckpoint arrives → `apply_sync` STAGES the re-persist.
  let nonce = e.sync_nonce_for_test();
  let cross_snap = CountSm::default().snapshot();
  let sm_root_addr = crate::block_address(&cross_snap);
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(n1),
    sm_root_addr,
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  blocks.write_verified(cross_snap.clone());
  let cross_id = crate::checkpoint_id(&cross_env);
  let membership_body =
    ReconfigurePayload::from_membership(&successor_e1, genesis_config_id).encode_body();
  let cross_msg = |nonce: u64| {
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
    ))
  };
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    cross_msg(nonce),
  );
  assert!(
    e.pending_install.is_some(),
    "the crossing reply STAGED the re-persist install (frontier drained, root not yet durable)"
  );

  // --- CORRUPT the SM-root block in the window AFTER the drain, BEFORE the destructive install. ---
  // Write garbage under the root address: it no longer hashes to `sm_root_addr`, so the verify-on-read
  // restore view reports it ABSENT and `install_sync`'s restore returns an error (nothing mutated).
  blocks.write_block(sm_root_addr, Bytes::copy_from_slice(b"corrupt-root-bytes"));

  // Drive the two-write re-persist → durable root → `install_sync` (which fails on the corrupt block).
  // `handle_storage` runs `assert_invariants` at exit — a `pending_install` held without an in-flight
  // SyncRepersist would PANIC here.
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }

  // The install FAILED, but the node did NOT strand and the sub-state invariant holds:
  assert_eq!(
    e.state_syncs_applied(),
    0,
    "the install error did NOT complete the sync (the corrupt block blocked the restore)"
  );
  assert_eq!(
    e.status(),
    Status::Recovering,
    "the node stays Recovering after the install error (no false flip to Normal)"
  );
  // The frontier ADVANCED to M (the crossing installed, in lockstep with the durable root) and the SM-
  // reconstruct obligation is owed — there is no `pending_install` to keep (it was consumed at the root
  // completion). The invariant holds because the obligation re-arms `block_fetch` but starts no new
  // `SyncRepersist` write.
  assert!(
    e.sm_reconstruct_owed(),
    "the SM-reconstruct obligation is owed after the restore fault — the SM is not yet M"
  );
  assert!(
    e.pending_install.is_none(),
    "the PRE-ROOT staging was consumed at the root completion (it is now the obligation)"
  );
  assert!(
    e.awaiting_peer_checkpoint_for_test() && e.sync_requires_cross_epoch_for_test(),
    "the recovery peer-fetch was RE-CREATED — a SERVICED re-fetch path (not an orphaned sync_solicit)"
  );

  // --- The recovery cadence re-solicits; the donor re-pulls the CLEAN block (overwriting the corrupt
  // bytes), and the re-served SyncCheckpoint re-stages + completes the install. ---
  blocks.write_verified(cross_snap.clone()); // the re-fetched clean block overwrites the corrupt bytes
  // The recovery cadence (`recover_timeouts`, driven by `recover_retry`) is the SERVICED ARQ while
  // Recovering — fire it to confirm it re-broadcasts the solicitation (it would be a no-op / spin if the
  // retry had stranded on `sync_solicit`).
  e.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
  let nonce2 = e.sync_nonce_for_test(); // the still-armed sync's (unchanged) nonce
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    cross_msg(nonce2),
  );
  // The re-solicited reply (at M) re-pulled M's DAG via the obligation (donor failover), NOT a re-stage.
  // The clean block was already re-fetched into the store, so the retry reconstructs the SM SYNCHRONOUSLY
  // here and the obligation clears — no second `SyncRepersist` write was started.
  assert!(
    !e.sm_reconstruct_owed(),
    "the obligation reconstructed the SM from the repaired DAG (donor failover, no re-stage)"
  );
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }

  // Recovery COMPLETED — the clean block was re-fetched, the install succeeded, the node is Normal at E1.
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the install retried against the repaired store and completed exactly once"
  );
  assert_eq!(
    e.status(),
    Status::Normal,
    "recovery completed to Normal (complete_recovery ran after the install landed)"
  );
  assert!(
    e.pending_install.is_none(),
    "no orphaned pending_install survives the completed install"
  );
  assert_eq!(
    e.membership, successor_e1,
    "the laggard CROSSED to E1 via the re-fetched crossing checkpoint"
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
  .expect("a SwapEpoch root carrying config_install_op above its checkpoint is valid")
  // A running node stamps geometry on every durable root; match the recover config's default interval
  // and the ring-less test WAL's `u64::MAX` capacity so recovery's geometry fence accepts it.
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);

  // Recover replica 1 — a BACKUP of view 0 in the successor (slot 0 leads), so `complete_recovery`
  // resumes Normal (NOT the abdicate-to-view-change primary branch) and pays the debt immediately.
  let cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  let mut wal = ScriptedWal::with_entries(n); // ops 1..=N held, clean reads
  let mut sb = TestSb {
    state: swap_root,
    done: std::collections::VecDeque::new(),
    checkpoint: None, // checkpoint_op == 0 → no snapshot; recover restores the genesis SM
  };
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let mut e = Endpoint::<CountSm>::recover(
    cfg,
    genesis_mem,
    9,
    CountSm::default(),
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect("recover accepts this store")
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
  drive_recovery(&mut e, &mut wal, &mut sb, &mut blocks, now);
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
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
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
    e.propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(4))
    ),
    Err(ProposeMembershipError::AlreadyInFlight),
    "a second reconfiguration is refused while the first's swap is committed-but-not-installed",
  );

  // Once the swap INSTALLS (the SwapEpoch root lands), the window closes and a new proposal succeeds.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land the SwapEpoch root → install
  assert!(
    !e.pending_swap_for_test(),
    "the swap installed — the window is closed"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the first change installed (E+1)"
  );
  // A fresh single change is now proposable. (Member 4 is a fresh learner id on the E+1 config.)
  let next = e.propose_membership(
    now,
    &mut wal,
    SingleVoterDelta::AddLearner(MemberId::new(4)),
  );
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
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
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
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // op-2 AdoptVote append completes; the view write stays inflight
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let head_before = e.op();

  assert_eq!(
    e.propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(3))
    ),
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    client_ack(2, 2),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  let admitted = e.propose_membership(
    now,
    &mut wal,
    SingleVoterDelta::AddLearner(MemberId::new(3)),
  );
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
  let mut blocks = crate::block_store::MemBlockStore::new();
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
    &mut blocks,
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
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
    &mut blocks,
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
  fn truncate(&mut self, above: OpNumber) -> std::vec::Vec<OpId> {
    self.inner.truncate(above)
  }
  fn prune(&mut self, below: OpNumber) -> std::vec::Vec<OpId> {
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
    e.propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(3))
    ),
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
      SingleVoterDelta::AddLearner(MemberId::new(3))
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .unwrap();
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let op = 1u64;

  // The primary's Prepare for the Reconfigure op (flat wire body = the encoded successor), commit 0.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the backup's append lands (deferred PrepareOk)
  while e.poll_message().is_some() {}

  // The primary's Commit advances the backup's commit to the Reconfigure op → it commits + stages
  // SwapEpoch. The epoch is still old here (the fence holds on the backup too).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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

  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land the backup's SwapEpoch root → install
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
  let mut pblocks = crate::block_store::MemBlockStore::new();
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
  primary.handle_timeout(now + COMMIT_HEARTBEAT, &mut pwal, &mut psb, &mut pblocks);
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
  let mut bblocks = crate::block_store::MemBlockStore::new();
  backup.handle_message(
    now,
    &mut bwal,
    &mut bsb,
    &mut bblocks,
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
  backup.handle_storage(now, &mut bwal, &mut bsb, &mut bblocks); // the backup's append lands
  while backup.poll_message().is_some() {}

  // Deliver the PRIMARY'S OWN heartbeat Commit (not a hand-rolled one) — the convergence signal.
  backup.handle_message(
    now,
    &mut bwal,
    &mut bsb,
    &mut bblocks,
    primary_peer(),
    commit_msg,
  );
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
  backup.handle_storage(now, &mut bwal, &mut bsb, &mut bblocks);
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
// invariant on `self.membership`). So every E+1 voter durably committed the Reconfigure op, hence
// holds the FULL E-committed prefix `<=` that op (commit-first puts the whole prefix on a node before
// its E+1 vote can count). A RETAINED voter committed it in place; a NEWLY-ADDED voter can only be a
// PROMOTED LEARNER — `propose_membership` refuses a direct `AddVoter`, so the sole path into the voting
// set is a promote whose gate demands a fresh durable-prefix proof AND whose Reconfigure op the learner
// must itself durably commit (commit-first) to install the swap. Either way the E+1 voter holds the
// full prefix; there is NO path by which one joins the voting set without committing the Reconfigure op.
// Any E+1 DVC-quorum member therefore holds any E-committed op `o`, so `o` rides
// `select_canonical_log`'s union and is never nack-truncated.
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
// view change for both the shrink (`cp_overlap_3_to_2_remove_voter_in_the_old_write_quorum` — the
// removed voter sat in the old write quorum) and the grow
// (`cp_overlap_3_to_4_promoted_learner_grow_keeps_a_committed_op_across_the_dvc` — a promoted learner
// enlarges the voting set 3→4).

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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let o = 1u64;

  // (1) Commit the client op `o` under E=0: mint + own append (own vote) + one backup ack (2-of-3).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(o),
      Bytes::from(std::vec![o as u8]),
    )),
  );
  while e.poll_message().is_some() {} // drop the broadcast Prepare
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // primary's own append durable → own vote
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(ack_backup)),
    client_ack(o, ack_backup),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(o),
    "the client op committed under E=0"
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drain any commit-tail superblock work
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // primary's own append durable → own vote
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(ack_backup)),
    reconfigure_ack(r.get(), &payload, ack_backup),
  );
  assert_eq!(e.commit(), r, "the Reconfigure op committed under E=0");
  // Make the SwapEpoch root durable → install the successor. `self.membership` is now E+1.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.membership, successor, "the E+1 successor is installed");
  assert!(!e.pending_swap_for_test(), "the staged swap was consumed");
  while e.poll_event().is_some() {}
  while e.poll_message().is_some() {}

  (e, wal, sb, o)
}

#[test]
fn cp_overlap_3_to_2_remove_voter_in_the_old_write_quorum() {
  // 3→2 RemoveVoter where the old WRITE quorum INCLUDES the removed voter. This is the case the naive
  // count bound FAILS: `quorum(3) + quorum_view_change(2) = 2 + 1 = 3`, NOT `> 3`. Commit `o` with the
  // primary (slot 0) and the voter that will be REMOVED (slot 2), so `o`'s old write quorum is
  // {slot 0, slot 2} — the removed voter is one of the two nodes that acked `o`. The swap removes
  // member 2 (the highest slot), so the retained voters keep their slots (`{member0→slot0,
  // member1→slot1}`); the lone retained non-primary voter slot 1 forms a full E+1 view-change quorum
  // (`quorum_view_change(2) == 1`) and is DISJOINT from `o`'s write quorum {slot 0, slot 2}. Only the
  // exact-durable-catch-up structure preserves `o` here: slot 1 never acked `o`, yet it reached E+1 by
  // durably committing the Reconfigure op (op 2), so it holds the full prefix `<= 2` — including the
  // client op `o == 1` — and must vouch for `o` at the view change.
  let ack_backup = 2u16; // slot 2 (the voter being removed) acks both `o` and the Reconfigure op
  let (mut e, _wal, _sb, o) =
    committed_op_then_swapped(SingleVoterDelta::RemoveVoter(MemberId::new(2)), ack_backup);

  // The post-swap config is the 2-voter E+1 membership; the removed voter (slot 2, one of `o`'s
  // write-quorum acks) is gone, and slot 1 (the DVC donor) is a RETAINED voter — so the E+1 view-change
  // quorum {slot 1} is DISJOINT from `o`'s write quorum {slot 0, slot 2}.
  assert_eq!(e.membership.replica_count(), 2, "E+1 is a 2-voter config");
  assert_eq!(e.membership.epoch(), crate::Epoch::new(1), "swapped to E+1");
  assert_eq!(
    e.membership.quorum_view_change(),
    1,
    "quorum_view_change(2) == 1 — a single DVC is a full E+1 view-change quorum",
  );
  assert!(
    !e.membership.is_voter(ReplicaId::new(2)),
    "the removed voter (slot 2), one of o's write-quorum acks, is NOT in the retained E+1 membership",
  );
  assert!(
    e.membership.is_voter(ReplicaId::new(1)),
    "slot 1 (the DVC donor) is a RETAINED E+1 voter",
  );

  // The E+1 DVC quorum is the single retained voter slot 1 — the worst case: DISJOINT from `o`'s write
  // quorum {slot 0, slot 2} (slot 1 is neither the primary nor the removed voter that acked `o`). Make
  // that disjointness explicit against the write-quorum members {slot 0, slot ack_backup}:
  let dvc_donor = 1u16;
  assert_ne!(dvc_donor, 0, "the DVC donor is not the primary (slot 0)");
  assert_ne!(
    dvc_donor, ack_backup,
    "the DVC donor is DISJOINT from o's write-quorum backup (slot {ack_backup}, the removed voter)",
  );
  // By exact catch-up slot 1 durably committed the Reconfigure op (op 2), so its DVC carries the full
  // prefix `[1..=2]` — including the client op `o`. (A real DVC's epoch/config_id stamping is irrelevant
  // to `select_canonical_log`, which reads only the carried log + frontier + the LOCAL membership's
  // quorum sizes.)
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(dvc_donor), dvc(dvc_donor, 0, 2, 2));
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
    .insert(ReplicaId::new(dvc_donor), dvc_offset(dvc_donor, 0, 0, 0, 0)); // the survivor holds NOTHING (head 0)
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

/// A synthetic E=0-generation DVC from `replica` carrying the dense prefix `[1..=op]` (`commit` is the
/// vouched commit), where the op-`o` slot carries the REAL identity the committed client op `o` was
/// minted with — client 7, request `o`, body `[o]` (checksum `fnv1a_128([o])`) — so a survival check
/// can assert `o`'s FULL committed identity rode `select_canonical_log`'s union, not merely that its
/// op-number slot stayed occupied. The other ops carry generic filler content, immaterial to a
/// selection that keys only on op numbers, floors, commits, and nacks.
fn dvc_carrying_committed_o(
  replica: u16,
  log_view: u64,
  op: u64,
  commit: u64,
  o: u64,
) -> DoViewChange {
  let log = (1..=op)
    .map(|i| {
      if i == o {
        PreparedEntry::new(
          OpNumber::with(i),
          ClientId::new(7),
          RequestNumber::with(i),
          Bytes::from(std::vec![o as u8]),
        )
      } else {
        PreparedEntry::new(
          OpNumber::with(i),
          ClientId::new(1),
          RequestNumber::with(i),
          Bytes::copy_from_slice(&i.to_be_bytes()),
        )
      }
    })
    .collect();
  DoViewChange::new(
    View::with(log_view + 10),
    View::with(log_view),
    OpNumber::with(op),
    OpNumber::with(commit),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(replica),
    log,
  )
}

#[test]
fn cp_overlap_3_to_4_promoted_learner_grow_keeps_a_committed_op_across_the_dvc() {
  // 3→4 GROW via the LEGITIMATE promote path (direct `AddVoter` is refused at propose time). Commit a
  // client op `o` under the OLD 3-voter E=0 quorum, promote the learner into the voting set (the
  // fresh-proof challenge + commit-first install), then prove `o` rides an E+1 DVC quorum through
  // `select_canonical_log`. This is the odd→even 3→4 case the naive count bound does NOT cover
  // (`quorum(3) + quorum_view_change(4) = 2 + 2 = 4`, not `> 4`): safety rests on exact-durable-catch-up
  // — every E+1 voter (retained OR promoted) durably committed the Reconfigure op, so it holds the full
  // prefix `<= o`.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let learner = MemberId::new(3);
  assert_eq!(
    e.membership.replica_count(),
    3,
    "genesis: 3 voters (slots 0-2) + learner slot 3"
  );
  assert!(
    !e.membership.is_voter(ReplicaId::new(3)),
    "slot 3 starts as a NON-voting learner",
  );

  // (1) Commit the client op `o == 1` under the OLD 3-voter E=0 quorum: mint + own append (own vote) +
  // one voter ack (2-of-3). This is the pre-grow committed op the transition must preserve.
  let o = 1u64;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(o),
      Bytes::from(std::vec![o as u8]),
    )),
  );
  while e.poll_message().is_some() {} // drop the broadcast Prepare
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // primary's own append durable → own vote
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    client_ack(o, 1),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(o),
    "the client op committed under the 3-voter E=0 config",
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drain the commit-tail superblock work
  while e.poll_message().is_some() {}

  // (2) Promote the learner through the REAL gate. The first propose has no fresh proof → it emits a
  // challenge and returns `ProofPending`; the learner answers with a frontier covering the head (`o`),
  // so the proof validates; the retry MINTS the promote op. The challenge frontier + commit-first are
  // exactly what make a promoted learner genuinely hold `o`.
  assert_eq!(
    e.propose_membership(now, &mut wal, SingleVoterDelta::PromoteLearner(learner)),
    Err(ProposeMembershipError::ProofPending),
    "the first propose with no fresh proof solicits one",
  );
  let challenge = take_proof_challenge(&mut e, 3);
  assert_eq!(
    challenge.at_op(),
    OpNumber::with(o),
    "the challenge pins the committed head `o`",
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    answer_proof(&challenge, 3, o), // the learner's fresh proof covers the head → it validates
  );
  let promote_op = e
    .propose_membership(now, &mut wal, SingleVoterDelta::PromoteLearner(learner))
    .expect("a caught-up learner with a fresh proof is promotable — the op mints");
  let promote_payload = e
    .log
    .get(&promote_op.get())
    .expect("the promote op is in the log")
    .body
    .as_reconfigure()
    .expect("a Body::Reconfigure op")
    .clone();
  assert_eq!(
    promote_payload.replica_count(),
    4,
    "the promote enlarges the voting set to 4",
  );

  // Commit the promote op (own vote + one voter ack, 2-of-3 under E=0) and make its `SwapEpoch` root
  // durable → INSTALL the 4-voter E=1 config. By commit-first, every replica that votes to install it —
  // the promoted learner included — durably holds the whole prefix `[1..=promote_op]` ⊇ `o`.
  while e.poll_message().is_some() {} // drop the broadcast Prepare
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // primary's own append durable → own vote
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    reconfigure_ack(promote_op.get(), &promote_payload, 1),
  );
  assert_eq!(
    e.commit(),
    promote_op,
    "the promote op committed under the 3-voter E=0 config",
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land the SwapEpoch root → install E=1
  assert_eq!(
    e.membership.replica_count(),
    4,
    "the promote installed a 4-voter E=1 config",
  );
  assert_eq!(e.membership.epoch(), crate::Epoch::new(1), "swapped to E=1");
  assert!(
    e.membership.is_voter(ReplicaId::new(3)),
    "the former learner (slot 3) is now a VOTER",
  );
  assert!(!e.pending_swap_for_test(), "the staged swap was consumed");
  while e.poll_event().is_some() {}
  while e.poll_message().is_some() {}

  // (3) The E+1 view change: for n=4, `quorum_view_change == 2`, so a DVC quorum is any 2 of 4. In both
  // cases the quorum members durably committed the promote op (`op == 2`), so their DVCs carry the dense
  // prefix `[1..=2]` ⊇ `o`. `select_canonical_log` must keep `o` in the committed band and in the log.

  // The full committed identity of `o` — client 7, request `o`, body `[o]` (checksum `fnv1a_128([o])`),
  // exactly what the commit quorum content-addressed — must ride the union INTACT, not merely leave its
  // op-number slot occupied. Assert that identity on the surviving entry in each quorum case.
  let o_body = [o as u8];
  let assert_o_identity = |log: &[crate::PreparedEntry], case: &str| {
    let entry = log
      .iter()
      .find(|entry| entry.op().get() == o)
      .unwrap_or_else(|| panic!("o == {o} is absent from the canonical log ({case})"));
    assert_eq!(
      entry.client(),
      ClientId::new(7),
      "o's client id survives ({case})"
    );
    assert_eq!(
      entry.request(),
      RequestNumber::with(o),
      "o's request number survives ({case})",
    );
    assert_eq!(
      entry.body(),
      Some(o_body.as_slice()),
      "o's body bytes survive ({case})",
    );
    assert_eq!(
      entry.body_checksum(),
      crate::storage::fnv1a_128(&[o as u8]),
      "o's body checksum survives ({case})",
    );
  };

  // EXCLUDES the promoted voter: an E+1 DVC quorum of the two RETAINED voters {slot 0, slot 1}, with the
  // promoted slot 3 absent. Each committed the promote op, so each carries `[1..=2]` with `o`'s real
  // identity at op 1 — `o` survives even though the newly-promoted voter contributes nothing here.
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc_carrying_committed_o(0, 0, 2, 2, o));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc_carrying_committed_o(1, 0, 2, 2, o));
  let (log, op_head, commit_star, _) = e.select_canonical_log();
  assert!(
    commit_star >= o,
    "commit* >= o: the retained-voter DVC quorum vouches o committed, got {commit_star}",
  );
  assert!(
    op_head >= o,
    "op_head >= o: o is at/below the canonical head, got {op_head}"
  );
  assert_o_identity(&log, "an E+1 DVC quorum that EXCLUDES the promoted voter");

  // INCLUDES the promoted voter: an E+1 DVC quorum {slot 0, slot 3} that DOES contain the promoted
  // learner. This is LEGITIMATELY backed — slot 3 answered the promote challenge with a frontier
  // covering `o` AND, by commit-first, durably committed the promote op — so its DVC genuinely carries
  // `[1..=2]` ⊇ `o` (unlike a brand-new voter, which the crate refuses to admit). A maximally
  // adversarial "the promoted learner is the SOLE holder of o" case is NOT constructible here: every
  // legitimate E+1 voter committed the promote op and by commit-first holds `o`, so none can nack `o`;
  // the non-holding-donor hazard control below (not a fabricated illegitimate voter) is the correct
  // non-vacuity witness. `o` survives here too, with its full identity intact.
  e.dvc_from_mut_for_test().clear();
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc_carrying_committed_o(0, 0, 2, 2, o));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(3), dvc_carrying_committed_o(3, 0, 2, 2, o));
  let (log, op_head, commit_star, _) = e.select_canonical_log();
  assert!(
    commit_star >= o && op_head >= o,
    "the promoted learner's DVC vouches o committed (commit* {commit_star}, op_head {op_head})",
  );
  assert_o_identity(&log, "an E+1 DVC quorum that INCLUDES the promoted learner");

  // NON-VACUITY (the hazard exact-catch-up forecloses): had an E+1 DVC quorum reached E+1 WITHOUT the
  // reconfigure-op prefix — a lag-bound shortcut holding only the prefix BELOW `o` — its donors would
  // carry empty/low logs and vouch a sub-`o` commit. `select_canonical_log` on THAT quorum truncates
  // `o`: with a 2-of-4 quorum at head 0 / commit 0, `op_head` clamps to 0, so `o` is gone. This
  // witnesses that the survival above is BECAUSE every E+1 voter durably committed the promote op (hence
  // holds `o`), not because `select_canonical_log` always keeps `o`.
  let mut hazard = single_change_primary();
  hazard.membership = e.membership.clone(); // the same 4-voter E=1 config (same quorum sizes)
  hazard
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc_offset(0, 0, 0, 0, 0)); // a donor that holds NOTHING (head 0)
  hazard
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc_offset(1, 0, 0, 0, 0)); // the second quorum donor, also empty
  let (hazard_log, hazard_head, hazard_commit, _) = hazard.select_canonical_log();
  assert_eq!(
    hazard_commit, 0,
    "the lag-shortcut quorum vouches nothing committed"
  );
  assert!(
    hazard_head < o,
    "without the reconfigure-op prefix, o is above the canonical head"
  );
  assert!(
    !hazard_log.iter().any(|entry| entry.op().get() == o),
    "the hazard control confirms o is DROPPED when the E+1 quorum lacks the reconfigure-op prefix — \
     so the survival above is load-bearing on exact catch-up",
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
  let e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  assert_eq!(e.replica(), ReplicaId::new(0), "slot 0 is the local member");
}

// === catch-up-then-promote (the non-voting LearnerStatus gate) ===

/// A 3-voter + 1-learner `SingleChange` endpoint whose local member is slot 0 — the primary of view 0.
/// The learner is member 3 at slot 3 (`replica_count == 3`, so id 3 is the first non-voting member).
fn single_change_primary_with_learner() -> Endpoint<CountSm, SingleChange> {
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis_with_learners(3, 1),
    0,
    CountSm::default(),
    u64::MAX,
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
fn mint_one_client_op(
  e: &mut Endpoint<CountSm, SingleChange>,
  wal: &mut TestWal,
  sb: &mut TestSb,
  blocks: &mut dyn BlockStore,
) {
  e.handle_message(
    Instant::ZERO,
    wal,
    sb,
    blocks,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from(std::vec![1u8]),
    )),
  );
  while e.poll_message().is_some() {}
}

/// Drains the primary's outgoing queue and returns the single `RequestLearnerProof` it emitted (the
/// promote-proof challenge), asserting exactly one was produced and that it is addressed to `slot`.
/// Panics if none / more than one is found — the gate emits exactly one challenge per `ProofPending`.
fn take_proof_challenge(
  e: &mut Endpoint<CountSm, SingleChange>,
  slot: u16,
) -> crate::RequestLearnerProof {
  let mut found = None;
  while let Some(out) = e.poll_message() {
    if let Message::RequestLearnerProof(rq) = out.msg_ref() {
      assert_eq!(
        out.to(),
        crate::Recipient::To(Peer::Replica(ReplicaId::new(slot))),
        "the challenge is addressed to the target learner's slot",
      );
      assert!(
        found.is_none(),
        "exactly one challenge is emitted per ProofPending"
      );
      found = Some(*rq);
    }
  }
  found.expect("the gate emitted a RequestLearnerProof challenge")
}

/// Builds the target learner's `LearnerProof` reply to `challenge`, reporting a contiguous applied
/// `frontier` (the value a real learner's `commit()` would return at reply time), self-identifying by
/// the learner's slot and echoing the challenge nonce + the live (epoch, config_id) so it validates.
fn answer_proof(challenge: &crate::RequestLearnerProof, slot: u16, frontier: u64) -> Message {
  Message::LearnerProof(crate::LearnerProof::new(
    ReplicaId::new(slot),
    challenge.nonce(),
    OpNumber::with(frontier),
    challenge.epoch(),
    challenge.config_id(),
  ))
}

#[test]
fn on_learner_status_records_peer_progress_monotone_and_touches_no_vote_state() {
  // A `LearnerStatus` is a NON-VOTING progress report: `on_learner_status` records the durable frontier
  // into `peer_progress` (keyed by the stable MemberId) and touches NOTHING else — no inflight vote
  // tracker, no DVC/SVC map, no quorum bitset. And the update is MONOTONE: a reordered LOWER report
  // never lowers a recorded value. `peer_progress` is now a pure LIVENESS HINT (when a learner is worth
  // challenging), NOT the safety input — the promote gate consumes a FRESH proof round-trip instead — so
  // this test pins the accumulation + the no-vote-state property, not any gating decision.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
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
    &mut blocks,
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
    &mut blocks,
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
    &mut blocks,
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
fn promote_learner_happy_path_challenge_then_fresh_proof_mints_the_op() {
  // The two-phase catch-up-then-promote gate, happy path: the first `propose_membership(PromoteLearner)`
  // has NO fresh proof, so it EMITS a `RequestLearnerProof` challenge and returns the retryable
  // `ProofPending`; delivering a fresh `LearnerProof` whose frontier covers the head fills the proof; and
  // the retry MINTS the Reconfigure op. By commit-first, the learner that durably commits it then holds
  // the entire E-committed prefix.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let learner = MemberId::new(3);

  // Advance the head to op 1 so the gate's threshold (`>= self.op`) is a non-trivial 1.
  mint_one_client_op(&mut e, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.op(), OpNumber::with(1), "the head advanced to op 1");

  // Phase 2: no fresh proof → ProofPending + a challenge emitted; nothing minted.
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "the first propose with no fresh proof solicits one and returns ProofPending",
  );
  assert_eq!(e.reconfigure_inflight, None, "no op was minted");
  assert_eq!(e.op(), OpNumber::with(1), "the head did not advance");
  let challenge = take_proof_challenge(&mut e, 3);
  assert_eq!(
    challenge.at_op(),
    OpNumber::with(1),
    "the challenge pins the head"
  );
  assert_eq!(
    challenge.from(),
    ReplicaId::new(0),
    "the challenge carries the soliciting primary's slot",
  );

  // Deliver a FRESH proof covering the head (frontier 1 == head). The proof now validates.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    answer_proof(&challenge, 3, 1),
  );

  // The retry mints the op (Phase 1 consumes the fresh proof).
  let op = e
    .propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner),
    )
    .expect("a caught-up learner with a fresh proof is promotable — the op mints");
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
  let entry = e.log.get(&op.get()).expect("the promote op is in the log");
  let payload = entry.body.as_reconfigure().expect("a Body::Reconfigure op");
  assert_eq!(
    payload.replica_count(),
    4,
    "the learner was promoted into the voting set"
  );
}

#[test]
fn promote_learner_an_unpaced_re_propose_reuses_the_in_flight_challenge_and_converges() {
  // The challenge is IDEMPOTENT in its head: a re-propose issued while a reply is still in flight
  // REUSES the outstanding challenge's nonce (retransmit) rather than superseding it. Without this, a
  // caller retrying faster than the round-trip re-draws the nonce on every call, so the in-flight
  // `LearnerProof` always arrives stale-nonce and is dropped — the promote never converges. Here a
  // SECOND propose precedes the reply; it must reuse the first nonce, and a reply answering that
  // (reused) nonce then mints.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let learner = MemberId::new(3);
  mint_one_client_op(&mut e, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.op(), OpNumber::with(1), "the head advanced to op 1");

  // First propose: a challenge is emitted (nonce N1), ProofPending.
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
  );
  let first = take_proof_challenge(&mut e, 3);

  // Re-propose BEFORE the reply lands (unpaced) — it must REUSE the same nonce (retransmit), not
  // supersede its own outstanding challenge.
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
  );
  let second = take_proof_challenge(&mut e, 3);
  assert_eq!(
    second.nonce(),
    first.nonce(),
    "an in-flight re-propose reuses the outstanding challenge's nonce — it does not supersede",
  );

  // The learner's reply answers the (reused) first challenge → validates against the still-outstanding
  // nonce. Had the second propose re-drawn, this reply would arrive stale-nonce and be dropped.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    answer_proof(&first, 3, 1),
  );

  // The retry mints — the reply was not dropped, because the unpaced re-propose did not re-draw.
  let op = e
    .propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner),
    )
    .expect("the in-flight reply validated against the reused nonce — the promote mints");
  assert_eq!(
    op,
    OpNumber::with(2),
    "the Reconfigure op minted at head + 1"
  );
}

#[test]
fn promote_learner_crash_regress_falsifier_a_regressed_fresh_proof_does_not_mint() {
  // THE R24 FALSIFIER, now closed by the fresh-proof challenge. A learner reports covering the head
  // (banking a stale-high `peer_progress`), then its contiguous applied frontier honestly REGRESSES
  // below the head (a crash + recover reconstructs it lower). With the OLD monotone-`peer_progress`
  // gate the banked stale-high value would mint the promotion — and the learner, now a voter below a
  // repair hole, could not install the promote op (successor quorum wedge). With the fresh-proof gate
  // the primary re-solicits at propose time and the learner answers with its REGRESSED frontier, so the
  // gate refuses to mint.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let learner = MemberId::new(3);

  // Advance the head to op 2 so the regressed frontier (1) is strictly below it.
  mint_one_client_op(&mut e, &mut wal, &mut sb, &mut blocks);
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(2),
      Bytes::from(std::vec![2u8]),
    )),
  );
  while e.poll_message().is_some() {}
  assert_eq!(e.op(), OpNumber::with(2), "the head advanced to op 2");

  // The learner once reported covering the head — the stale-high accumulator the OLD gate trusted.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    learner_status(3, 2),
  );
  assert_eq!(
    e.peer_progress.get(&learner),
    Some(&OpNumber::with(2)),
    "peer_progress banks the stale-high pre-crash frontier (now only a hint)",
  );

  // Propose: the gate IGNORES the stale-high peer_progress and solicits a fresh proof instead.
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "the gate solicits a fresh proof rather than minting off the banked stale-high peer_progress",
  );
  assert_eq!(
    e.reconfigure_inflight, None,
    "no op minted off the stale-high hint"
  );
  let challenge = take_proof_challenge(&mut e, 3);

  // The learner crashed and recovered BELOW the head: its fresh contiguous applied frontier is now 1.
  // It answers the challenge with that REGRESSED frontier (what a real learner's `commit()` returns).
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    answer_proof(&challenge, 3, 1),
  );

  // The retry STILL does not mint: the fresh frontier (1) is below the head (2) — fail-closed.
  // MUTATION CHECK: a gate that read the stale-high peer_progress (2 >= head 2) would mint here.
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "a fresh proof carrying the REGRESSED frontier does not mint — the stale-high accumulator is moot",
  );
  assert_eq!(
    e.reconfigure_inflight, None,
    "no promote op was minted for a regressed learner (no successor wedge)",
  );
}

#[test]
fn promote_learner_regressed_after_an_honest_high_proof_cannot_install_the_swap_until_repaired() {
  // THE COMMIT-FIRST GATE — the decisive defense over the finding's EXACT window (the falsifier above
  // covers only a learner that REPORTS a low frontier; this covers an HONEST HIGH proof followed by a
  // regression in the proof->commit/install gap). The primary already minted the `PromoteLearner`
  // Reconfigure op `N` off a fresh proof covering the head, and that op reaches this learner. But the
  // learner then crashed/storage-faulted and recovered REGRESSED: a committed op BELOW `N` read back
  // body-faulty, so it is held header-only as a `Body::Repairing` hole (the durable-header carry). The
  // load-bearing claim: a learner becomes a successor VOTER only by INSTALLING the swap, and the swap
  // installs only after committing op `N` IN SEQUENCE — the commit loop HOLDS at the hole below `N`
  // (`advance_commit` / `commit_op` peer-repair the hole and `break`, never skipping to `N`). So a
  // regressed learner NEVER stages the SwapEpoch, NEVER stamps E+1, and `is_voter()` stays false: it
  // cannot acquire successor view-change-quorum authority below the proven prefix. The hole's repair is
  // the SOLE unblock — only then does commit reach `N`, stage the swap, and install the voter.
  //
  // Shape (the promoted-learner slot): self is the learner member 3 at slot 3 of a 3-voter + 1-learner
  // cluster (`replica_count == 3`, so slot 3 is NON-voting). `PromoteLearner(member 3)` yields a 4-voter
  // successor in which slot 3 IS a voter — so `is_voter()` flips false->true EXACTLY at the install, and
  // observing it stay false witnesses the gate. The log holds op 1 as a committed `Body::Repairing` hole
  // (the regression) and op 2 as the typed `Body::Reconfigure` promote op `N`. (Log shape mirrors
  // `commit_holds_at_a_body_repairing_entry_and_solicits_the_body`; the commit+install path mirrors
  // `a_backup_committing_the_same_reconfigure_installs_the_identical_successor`.)
  let cfg =
    Config::try_new(0, MemberId::new(3)).expect("learner member 3 of a 3-voter + 1-learner set");
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis_with_learners(3, 1),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // The promote op `N == 2` promotes member 3 (this learner). Build its successor membership exactly as
  // the proposer did (chained off the genesis predecessor, `prev_config_id == 0`), so a commit that
  // REACHED op 2 would stage+install THIS successor — the only thing standing in the way is the hole.
  let promote = MemberId::new(3);
  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::PromoteLearner(promote))
    .expect("promoting the learner member 3 yields a 4-voter successor");
  assert_eq!(
    successor.replica_count(),
    4,
    "the successor promotes the learner into a 4-voter set",
  );
  assert!(
    successor.is_voter(ReplicaId::new(3)),
    "in the successor, this node's slot 3 is a VOTER (so is_voter flips only at install)",
  );
  let payload = ReconfigurePayload::from_membership(&successor, e.membership.config_id());

  // Precondition: as a learner under the predecessor configuration, this node is NOT a voter.
  assert!(
    !e.is_voter(),
    "precondition: a learner (slot 3 >= replica_count 3) is not a voter",
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "precondition: at the predecessor epoch E",
  );

  // The regressed log: op 1 is a COMMITTED op whose body read back faulty on recover — kept header-only
  // as a `Body::Repairing` hole (existence + durable body_checksum preserved). Op 2 is the typed
  // `Body::Reconfigure` promote op `N`. Head is op 2; nothing applied yet (commit_min 0).
  e.op = OpNumber::with(2);
  e.log.insert(
    1,
    super::super::LogEntry {
      client: ClientId::new(7),
      request: RequestNumber::with(1),
      body: Body::Repairing(crate::storage::fnv1a_128(&[1u8])),
    },
  );
  e.log.insert(
    2,
    super::super::LogEntry {
      client: ClientId::RECONFIGURATION,
      request: RequestNumber::with(2),
      body: Body::Reconfigure(payload.clone()),
    },
  );

  // The primary announces commit == 2 (op N committed cluster-wide). `on_commit` -> `advance_commit(2)`
  // walks ops in order from commit_min: it reaches op 1 FIRST, finds its body absent, and must HOLD —
  // peer-repair the hole and stop — so it NEVER reaches op 2 to commit+stage the swap.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );

  // THE LOAD-BEARING ASSERTIONS. The commit is held at the hole, so the promote op never installed:
  assert_eq!(
    e.commit(),
    OpNumber::with(0),
    "the commit is HELD at the body-Repairing hole (op 1) — it never reached the promote op (op 2)",
  );
  assert!(
    e.has_repair_hole_for_test(1),
    "op 1 is registered for peer fault-repair (the hole below N is solicited, not skipped)",
  );
  assert!(
    !e.pending_swap_for_test(),
    "no SwapEpoch is staged — a held commit never reached the Reconfigure op to stage the swap",
  );
  // ...and so this node has NOT acquired successor voter authority:
  assert!(
    !e.is_voter(),
    "the regressed learner stays NON-voting — it cannot install the swap below the repair hole",
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "the epoch stays E — no E+1 stamp without the install (durable-epoch-before-participate)",
  );
  assert_eq!(
    e.membership.replica_count(),
    3,
    "the membership is still the predecessor (3 voters); slot 3 is still >= replica_count (non-voting)",
  );
  assert!(
    !e.membership.is_voter(ReplicaId::new(3)),
    "this node's own slot is still a learner slot — not a successor voter",
  );

  // THE UNBLOCK: repair op 1's body (the canonical Prepare a peer serves). Now the commit can advance
  // PAST op 1, reach op 2, commit the Reconfigure, stage the SwapEpoch root, and (landing it) install —
  // so `is_voter()` flips to true ONLY here, proving the gate was the hole, not some unrelated block.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::with(2), // commit >= op: a committed-vouching fill for the hole
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::copy_from_slice(&[1u8]),
    )),
  );
  // Drive storage to settle the repair append + the commit advance + the staged SwapEpoch root install.
  for _ in 0..8 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    while e.poll_message().is_some() {}
  }
  assert!(
    !e.has_repair_hole_for_test(1),
    "op 1's body was repaired — the hole cleared",
  );
  assert_eq!(
    e.membership, successor,
    "with the hole repaired, the commit reached op N, staged + installed the IDENTICAL successor",
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the install stamped E+1 (the swap landed)",
  );
  assert!(
    e.is_voter(),
    "ONLY after repairing the hole and installing the swap does the promoted node become a voter",
  );
}

#[test]
fn a_promoted_learner_voters_committed_repairing_op_rides_the_dvc_and_is_not_truncated() {
  // THE DURABLE-HEADER NO-TRUNCATION BACKSTOP (the SECOND-line defense behind the commit-first gate
  // above). Suppose the learner DID install (it applied through the Reconfigure op `N` cleanly and is
  // now an ordinary voter), and THEN a fault drops a committed op's body (the durable-header window). The
  // op is kept header-only as `Body::Repairing` (its existence + durable identity survive), so it rides the
  // promoted voter's `DoViewChange` as a header-only entry. The property the promoted voter relies on:
  // `select_canonical_log` keeps that committed op in the band (`commit* >= it`, `op_head >= it`) and the
  // body-aware nack scan NEVER truncates it — even when collected alongside a laggard nack quorum that
  // does not hold it — because the committed-frontier DVC vouches it committed. So no committed op is
  // lost and its number is never re-minted; it is REPAIRED, not cut.
  //
  // This pins the invariant in the POST-PROMOTION voting band (4 voters; slot 3 is the FORMER learner,
  // now a voter — the membership the gate test above installs). The canonical-log selection is
  // provenance-agnostic: once installed, a promoted learner is an ordinary voter, so this exercises the
  // SAME `select_canonical_log` path the existing voter durable-header tests cover
  // (`view_change::committed_repairing_op_survives_a_second_view_change_before_repair`,
  // `view_change::c_committed_repairing_op_kept_across_view_changes_and_repaired_within_the_grace`, and
  // the reconfigure-band `header_only_adoption_preserves_the_new_primarys_local_reconfigure_body`),
  // asserted here for the promoted-learner band the finding cares about.
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);

  // The committed donor is the PROMOTED EX-LEARNER (slot 3 of the 4-voter post-promotion set): head op 2,
  // commit 2 — op 1 a real body, op 2 COMMITTED but carried HEADER-ONLY (`Body::Repairing`, the body it
  // acked before the fault). This is the DVC a promoted learner emits after a recover-time body loss.
  let promoted_voter_dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(2),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(3),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        op2_checksum,
      ),
    ],
  );

  // The selector is voter slot 0 (new primary of view 1) of the 4-voter post-promotion cluster.
  let mut selector = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(0)).expect("voter 0 of the 4-voter post-promotion set"),
    genesis(4),
    0,
    NoopSm,
    u64::MAX,
  );
  // For n=4, quorum_view_change == quorum_nack_prepare == 2. Collect the committed donor (slot 3) plus
  // TWO laggards (head op 1) that would form a nack quorum on op 2 — the real truncation threat the
  // committed frontier must defeat.
  selector
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(3), promoted_voter_dvc);
  selector
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc(1, 0, 1, 1)); // laggard, head op 1, nacks op 2
  selector
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(2), dvc(2, 0, 1, 1)); // laggard, head op 1, nacks op 2

  let (log, op_head, commit_star, _) = selector.select_canonical_log();

  // THE BACKSTOP ASSERTIONS: the committed op stays in the band and in the canonical log — never cut by
  // the laggard nack quorum, because the promoted voter's DVC vouches it committed (commit* >= 2).
  assert!(
    commit_star >= 2 && op_head >= 2,
    "the promoted voter's committed op 2 stays in the band (commit* {commit_star}, op_head {op_head}) — \
     the laggard nack quorum cannot truncate a committed-frontier-vouched op",
  );
  assert!(
    log.iter().any(|e| e.op() == OpNumber::with(2)),
    "the committed header-only op 2 is in the canonical log (TAKEN for repair, NOT truncated/re-minted)",
  );
  // It rides as the durable HEADER (the body is peer-repaired after adoption), not fabricated — existence
  // preserved, exactly the durable-header carry the promoted learner depends on.
  let carried = log
    .iter()
    .find(|e| e.op() == OpNumber::with(2))
    .expect("op 2 is carried in the canonical log");
  assert!(
    carried.is_repairing(),
    "op 2 rides header-only (Body::Repairing) — its existence is preserved and the body is repaired, not lost",
  );
}

#[test]
fn promote_learner_crash_mid_challenge_no_proof_arrives_keeps_proof_pending() {
  // A crash BETWEEN challenge and reply: the learner never answers, so the proof stays `None`,
  // `ProofPending` persists, and no promotion ever mints (fail-closed). Re-proposing just re-challenges
  // (a fresh nonce); it never silently promotes.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let learner = MemberId::new(3);
  mint_one_client_op(&mut e, &mut wal, &mut sb, &mut blocks);

  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "the first propose solicits a proof",
  );
  let _ = take_proof_challenge(&mut e, 3);

  // No LearnerProof arrives (the learner is mid-crash). Re-propose: still ProofPending, still no mint.
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "with no reply the proof stays None — ProofPending persists",
  );
  assert_eq!(e.reconfigure_inflight, None, "no op was minted");
}

#[test]
fn promote_learner_drops_stale_nonce_wrong_target_and_foreign_config_proofs() {
  // The STALE-PROOF GUARDS on the primary's `on_learner_proof`: a `LearnerProof` with a wrong NONCE, a
  // wrong TARGET slot, or a foreign `(epoch, config_id)` is DROPPED — `proof` stays `None`, so the retry
  // still returns `ProofPending` and never mints. Only the exactly-matching fresh proof validates.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let learner = MemberId::new(3);
  mint_one_client_op(&mut e, &mut wal, &mut sb, &mut blocks);

  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "the first propose solicits a proof",
  );
  let challenge = take_proof_challenge(&mut e, 3);

  // (a) WRONG NONCE: a reply for a different/replayed challenge (covering the head) is dropped.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    Message::LearnerProof(crate::LearnerProof::new(
      ReplicaId::new(3),
      challenge.nonce().wrapping_add(1), // a non-matching nonce
      OpNumber::with(1),                 // would cover the head if it validated
      challenge.epoch(),
      challenge.config_id(),
    )),
  );
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "a wrong-nonce proof is dropped — proof stays None",
  );
  // The previous propose re-challenged (a fresh nonce); take it and continue against the live nonce.
  let challenge = take_proof_challenge(&mut e, 3);

  // (b) WRONG TARGET SLOT: a proof self-identifying a DIFFERENT member's slot is dropped. Slot 1 is a
  // voter (a current member, so `sender_matches` admits the binding) but is NOT the challenge target.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::LearnerProof(crate::LearnerProof::new(
      ReplicaId::new(1), // a member, but not the target (slot 3)
      challenge.nonce(),
      OpNumber::with(1),
      challenge.epoch(),
      challenge.config_id(),
    )),
  );
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "a wrong-target proof is dropped — proof stays None",
  );
  let challenge = take_proof_challenge(&mut e, 3);

  // (c) FOREIGN CONFIG: a proof carrying a different `config_id` is dropped (the freshness backstop). A
  // foreign-config proof is dropped at ingress (`epoch_authority_admits`) before it can fill the proof.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    Message::LearnerProof(crate::LearnerProof::new(
      ReplicaId::new(3),
      challenge.nonce(),
      OpNumber::with(1),
      challenge.epoch(),
      0xDEAD_BEEF, // a foreign config_id (not in this primary's lineage)
    )),
  );
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "a foreign-config proof is dropped — proof stays None",
  );
  assert_eq!(
    e.reconfigure_inflight, None,
    "no stale/wrong proof ever minted the op"
  );

  // Positive control: the exactly-matching fresh proof (live nonce, right slot, live config, frontier
  // covering the head) validates and the retry mints.
  let challenge = take_proof_challenge(&mut e, 3);
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    answer_proof(&challenge, 3, 1),
  );
  assert!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    )
    .is_ok(),
    "the exactly-matching fresh proof mints the op",
  );
}

#[test]
fn promote_learner_re_challenges_when_the_head_advanced_past_a_validated_proof() {
  // A proof for an OLDER `at_op` after the head advanced must NOT mint: the proof proved an old head, so
  // it is stale for the new head. The gate re-validates `at_op >= self.op` at mint and falls through to
  // re-challenge against the new head — a fresh proof covering the NEW head then mints.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let learner = MemberId::new(3);
  mint_one_client_op(&mut e, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.op(), OpNumber::with(1), "head at op 1");

  // Challenge at head 1; the learner answers covering head 1 (frontier 1).
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "challenge at head 1",
  );
  let challenge = take_proof_challenge(&mut e, 3);
  assert_eq!(
    challenge.at_op(),
    OpNumber::with(1),
    "the challenge pinned head 1"
  );
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    answer_proof(&challenge, 3, 1),
  );

  // The head ADVANCES to op 2 before the promote retry — the validated proof (for head 1) is now stale.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(2),
      Bytes::from(std::vec![2u8]),
    )),
  );
  while e.poll_message().is_some() {}
  assert_eq!(e.op(), OpNumber::with(2), "the head advanced to op 2");

  // The retry does NOT mint off the head-1 proof: it re-challenges against head 2.
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "a proof for an older head does not mint — the gate re-challenges against the advanced head",
  );
  assert_eq!(
    e.reconfigure_inflight, None,
    "no op minted off the stale (head-1) proof"
  );
  let challenge = take_proof_challenge(&mut e, 3);
  assert_eq!(
    challenge.at_op(),
    OpNumber::with(2),
    "the re-challenge pins the NEW head (op 2)"
  );

  // A fresh proof covering the NEW head (frontier 2) mints.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    answer_proof(&challenge, 3, 2),
  );
  assert!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    )
    .is_ok(),
    "a fresh proof covering the advanced head mints the op",
  );
}

#[test]
fn promote_learner_clears_a_pending_challenge_on_a_view_transition() {
  // VIEW-TRANSITION MID-CHALLENGE: `learner_proof` is transient promote state cleared by
  // `reset_for_view_transition`, so a pre-transition reply never validates a post-transition mint. After
  // a forced reset the challenge is gone, and re-proposing starts a fresh challenge (a fresh nonce), so a
  // reply minted against the OLD challenge cannot satisfy the new one.
  let mut e = single_change_primary_with_learner();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let learner = MemberId::new(3);
  mint_one_client_op(&mut e, &mut wal, &mut sb, &mut blocks);

  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "the first propose solicits a proof",
  );
  let stale_challenge = take_proof_challenge(&mut e, 3);
  assert!(e.learner_proof.is_some(), "a challenge is outstanding");

  // A view transition clears the outstanding challenge.
  e.reset_for_view_transition(Instant::ZERO);
  assert!(
    e.learner_proof.is_none(),
    "reset_for_view_transition clears the outstanding learner-promote challenge",
  );

  // A reply carrying the PRE-transition challenge's nonce no longer validates anything (the challenge is
  // gone). Re-establish the proposing state and re-propose to issue a FRESH challenge.
  e.force_state_for_test(0, 1, 1, 0, &[]);
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    answer_proof(&stale_challenge, 3, 1), // the OLD nonce
  );
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(learner)
    ),
    Err(ProposeMembershipError::ProofPending),
    "a pre-transition reply never validates the fresh challenge — ProofPending, no mint",
  );
  assert_eq!(
    e.reconfigure_inflight, None,
    "no op minted off a pre-transition reply"
  );
}

#[test]
fn an_epoch_swap_clears_an_outstanding_promote_challenge() {
  // EPOCH-SWAP MID-CHALLENGE: a learner-promote challenge minted under the OLD configuration is CLEARED
  // when a `SwapEpoch` root installs the successor (`install_membership`), so a pre-swap reply never
  // validates a post-swap mint. Arm a challenge directly, then drive an AddLearner reconfiguration on a
  // sole-voter cluster through commit + the durable SwapEpoch install, and assert the swap cleared it.
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis(1),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();

  // Arm an outstanding promote challenge under the CURRENT configuration (any target/nonce — the swap
  // clears it regardless; the `(epoch, config_id)` reply binding is the structural backstop).
  e.learner_proof = Some(super::super::LearnerProofState {
    target: MemberId::new(9),
    at_op: OpNumber::new(),
    nonce: 0xABCD,
    proof: None,
  });
  assert!(
    e.learner_proof.is_some(),
    "a challenge is outstanding pre-swap"
  );

  // Drive an AddLearner reconfiguration to commit + install (the sole voter is the whole quorum, so its
  // own durable append commits the op; landing the SwapEpoch root installs the successor epoch).
  e.propose_membership(
    Instant::ZERO,
    &mut wal,
    SingleVoterDelta::AddLearner(MemberId::new(1)),
  )
  .expect("AddLearner on a single-voter cluster is admitted");
  e.handle_timeout(Instant::ZERO, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // own append durable → own vote → commit
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // land the SwapEpoch root → install_membership
  assert_eq!(
    e.membership.learner_count(),
    1,
    "the successor epoch is installed (the AddLearner swap landed)",
  );
  assert!(
    e.learner_proof.is_none(),
    "the epoch swap (install_membership) cleared the outstanding promote challenge",
  );
}

#[test]
fn a_non_promote_delta_is_unaffected_by_the_catch_up_gate() {
  // The gate is `PromoteLearner`-specific: a NON-promote delta (here `AddLearner`, adding a brand-new
  // learner) mints WITHOUT any `peer_progress` entry — the catch-up-then-promote gate never engages for
  // it, since there is no promotion to prove a durable prefix for.
  let mut e = single_change_primary_with_learner();
  let mut wal = TestWal::default();
  assert!(e.peer_progress.is_empty(), "no progress recorded");
  let op = e
    .propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(4)),
    )
    .expect("a non-promote delta is unaffected by the promote gate");
  assert_eq!(e.reconfigure_inflight, Some(op), "the AddLearner op minted");
}

// === the direct AddVoter rejection (the sibling of the catch-up-then-promote gate) ===

/// A 1-voter `SingleChange` endpoint whose sole member is slot 0 — the primary of view 0. The only
/// voter is the whole write quorum AND the whole view-change quorum, so a direct `AddVoter` here would
/// produce a 2-voter successor with `quorum_view_change == 1`.
fn single_change_primary_solo() -> Endpoint<CountSm, SingleChange> {
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis(1),
    0,
    CountSm::default(),
    u64::MAX,
  )
}

/// An `n`-voter `SingleChange` endpoint whose local member is slot 0 — the primary of view 0.
fn single_change_primary_n(n: u8) -> Endpoint<CountSm, SingleChange> {
  let cfg = Config::try_new(0, MemberId::new(0)).expect("valid cluster config");
  Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis(n),
    0,
    CountSm::default(),
    u64::MAX,
  )
}

#[test]
fn add_voter_from_a_single_voter_cluster_is_rejected_breaks_quorum_intersection() {
  // A DIRECT 1->2 `AddVoter` from a single-voter cluster is REFUSED. The new voter holds NO committed
  // prefix, and the 2-voter successor's view-change quorum is 1, so the new voter could form an E+1
  // view-change quorum ALONE (electing itself leader with an empty log) and drop the old committed
  // prefix — committed-op loss. This is the extreme of the uniform direct-`AddVoter` rejection; the safe
  // path is `AddLearner` then `PromoteLearner` (contrast `PromoteLearner`, whose target durably caught
  // up before promotion).
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
    Err(ProposeMembershipError::DirectAddVoterUnsupported),
    "a direct AddVoter is refused; the brand-new voter holds no committed prefix",
  );
  assert_eq!(e.reconfigure_inflight, None, "no op was minted");
  assert_eq!(e.op(), OpNumber::new(), "the head did not advance");
}

#[test]
fn add_voter_from_two_or_more_voters_is_also_rejected() {
  // A direct `AddVoter` is rejected at EVERY size, not only the single-voter extreme. The old admission
  // for 2+ voters rested on a flawed premise — that the brand-new voter would hold the committed prefix.
  // It cannot: it was never a predecessor member, so it never appended or committed the predecessor's
  // Reconfigure op (nor any prior op). A successor view-change quorum that includes the empty-log new
  // voter but omits a prefix-holding retained voter can still drop a committed op, so the safe grow is
  // ALWAYS `AddLearner` then `PromoteLearner` (the caught-up voter holds the prefix before it votes).
  // Confirm 2->3 and 3->4 are both refused with no op minted.
  for n in [2u8, 3] {
    let mut e = single_change_primary_n(n);
    let mut wal = TestWal::default();
    assert_eq!(
      e.propose_membership(
        Instant::ZERO,
        &mut wal,
        SingleVoterDelta::AddVoter(MemberId::new(u128::from(n))),
      ),
      Err(ProposeMembershipError::DirectAddVoterUnsupported),
      "a direct AddVoter from {n} voters is refused (add as a learner, then promote)",
    );
    assert_eq!(
      e.reconfigure_inflight, None,
      "no op was minted for {n} voters"
    );
    assert_eq!(
      e.op(),
      OpNumber::new(),
      "the head did not advance for {n} voters"
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
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis(1),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
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
  e.handle_timeout(Instant::ZERO, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // own append durable → own vote → commit
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // land the SwapEpoch root → install
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
  mint_one_client_op(&mut e, &mut wal, &mut sb, &mut blocks);
  let head = e.op();
  assert!(head.get() >= 1, "the head advanced");

  // (2) PromoteLearner solicits a fresh proof and returns ProofPending until the learner answers with a
  // frontier covering the head. The challenge carries the endpoint's CURRENT (post-AddLearner-swap)
  // epoch/config_id, so the reply must echo them to validate.
  assert_eq!(
    e.propose_membership(
      Instant::ZERO,
      &mut wal,
      SingleVoterDelta::PromoteLearner(newcomer)
    ),
    Err(ProposeMembershipError::ProofPending),
    "the learner has not yet proven a fresh durable catch-up",
  );
  let challenge = take_proof_challenge(&mut e, learner_slot.get());
  assert_eq!(
    challenge.epoch(),
    e.membership.epoch(),
    "the challenge carries the post-AddLearner-swap epoch",
  );

  // (3) The learner answers with a fresh frontier covering the head → PromoteLearner SUCCEEDS. By
  // commit-first, the learner that durably commits the promote op then holds the entire prefix.
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(learner_slot),
    answer_proof(&challenge, learner_slot.get(), head.get()),
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
  let mut blocks = crate::block_store::MemBlockStore::new();
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
  e.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // own append durable → own vote
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land the SwapEpoch root → install the successor
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
  let mut survivor = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    survivor_cfg,
    successor,
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();

  // It starts Normal as a backup; its idle timer has not yet fired.
  assert_eq!(survivor.status(), Status::Normal);
  assert!(
    !survivor.is_primary(),
    "member 2 (slot 1) is a backup under view 0"
  );
  survivor.handle_timeout(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // bootstrap primary_idle (not yet due)
  let later = Instant::ZERO + core::time::Duration::from_millis(300);
  survivor.handle_timeout(later, &mut wal, &mut sb, &mut blocks); // idle due → propose view 1, broadcast SVC

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
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
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
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the backup's append lands (deferred PrepareOk)
  while e.poll_message().is_some() {}

  // The primary's Commit advances the backup's commit to the Reconfigure op → it commits + stages its
  // own SwapEpoch root (still at the OLD epoch — the fence holds on the backup).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land the backup's SwapEpoch root → install the successor
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
  let mut blocks = crate::block_store::MemBlockStore::new();

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
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks); // far past PRIMARY_IDLE — must not arm/fire a VC, must not panic
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let genesis_config_id = 0u128; // the fixture genesis carries config_id 0 (see the `genesis` helper)
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // land swap #1 → E=1 install
  let config_1 = e.membership.config_id();
  assert_ne!(
    config_1, genesis_config_id,
    "the first swap chained a new config_id"
  );
  // The installed E=1 config is 3 voters {0,1,2} + 1 learner (slot 3); a learner does not raise
  // `replica_count`, so the voting quorum stays 2.
  assert_eq!(
    e.membership.replica_count(),
    3,
    "the E=1 config is 3 voters (slots 0-2) + 1 learner (slot 3), quorum 2",
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

  // A SECOND swap: propose+commit+install RemoveVoter on the current (E=1, 3-voter + 1-learner) config.
  let now = Instant::ZERO;
  let succ2 = e
    .membership
    .apply_delta(&SingleVoterDelta::RemoveVoter(MemberId::new(1)))
    .expect("removing a voter from the 3-voter E=1 config is valid");
  let payload2 = ReconfigurePayload::from_membership(&succ2, e.membership.config_id());
  let op2 = e
    .propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::RemoveVoter(MemberId::new(1)),
    )
    .expect("the primary mints the second Reconfigure op");
  while e.poll_message().is_some() {}
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // own append → own vote
  // Commit under the E=1 3-voter quorum (2 of {0,1,2}): the primary (slot 0, via its own durable vote)
  // + one retained-voter ack (slot 2). Slot 1 is the voter being removed; slot 3 is the learner, whose
  // ack would not count toward the voting quorum. The ack must be stamped E=1 / config_1 — the primary's
  // CURRENT configuration — or the strict ingress gate drops it.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    reconfigure_ack_at(op2.get(), &payload2, 2, crate::Epoch::new(1), config_1),
  );
  assert_eq!(
    e.commit(),
    op2,
    "the second Reconfigure op committed under E=1"
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land swap #2 → E=2 install
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  e.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // land the swap → the survivor is now at E=1
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the survivor is at E+1"
  );
  let now = Instant::ZERO;
  // This node is slot 0 of the E=1 config (3 voters {0,1,2} + 1 learner at slot 3; the primary of view
  // 0), so feed the SVC to a BACKUP survivor to observe a view-change transition cleanly. Re-home onto
  // slot 1.
  let backup_cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  let mut backup = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    backup_cfg,
    e.membership.clone(),
    0,
    CountSm::default(),
    u64::MAX,
  );
  // Pin the config the gate runs against: 3 voters, so the view-change quorum is 2 (not 3).
  assert_eq!(
    backup.membership.replica_count(),
    3,
    "the survivor runs a 3-voter config (quorum_view_change 2)",
  );
  assert_eq!(
    backup.membership.quorum_view_change(),
    2,
    "quorum_view_change(3) == 2",
  );

  // A stale OLD-epoch (E=0) SVC for view 1 from a removed/forked server: dropped at the strict gate.
  backup.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(1), // current epoch — admitted
      backup.membership.config_id(),
    )),
  );
  // The E=1 SVC is ADMITTED: the backup adopts view 1 as its SVC target and casts its own join bit, so
  // together with replica 2's admitted SVC the 2-of-3 view-change quorum is MET and the backup enters a
  // view change for view 1 (status → ViewChange). The contrast is the whole point — the OLD-epoch SVC
  // above left the survivor Normal, whereas the matching-epoch SVC drives the transition.
  assert_eq!(
    backup.svc_target_for_test(),
    View::with(1),
    "the same SVC at the matching epoch IS admitted (the drop above was the epoch gate)",
  );
  assert_eq!(
    backup.status(),
    Status::ViewChange,
    "the admitted E=1 SVC reached the 2-of-3 quorum and drove the survivor into a view change",
  );
}

// (c) AVAILABILITY (single change in flight). The single-writer `reconfigure_inflight` latch
// serializes: it is SET at propose and CLEARED at the commit's `stage_epoch_swap`, and a second
// proposal mid-flight is refused `AlreadyInFlight`.

#[test]
fn the_in_flight_latch_cycles_set_at_propose_then_cleared_at_commit_stage() {
  let mut e = single_change_primary();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  assert_eq!(e.reconfigure_inflight, None, "no change in flight at rest");

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .unwrap();
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let op = e
    .propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(3)),
    )
    .expect("the primary mints the Reconfigure op");
  // SET at propose.
  assert_eq!(
    e.reconfigure_inflight,
    Some(op),
    "the latch is set at propose"
  );

  // A second proposal mid-flight is refused, and the latch still holds the FIRST op.
  assert_eq!(
    e.propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(4))
    ),
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // own append → own vote
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
    .propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(4)),
    )
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // Propose on the view-0 primary → the latch is set on the uncommitted op (it is NOT driven to commit).
  let op = e
    .propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(3)),
    )
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
    &mut blocks,
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
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).expect("valid cluster config"),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // Seed an uncommitted Reconfigure op at op 1 (a RECONFIGURATION-client Prepare from the view-0
  // primary), held but never committed.
  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .unwrap();
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the append lands
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
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks); // primary_idle → propose view 1, own SVC bit
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).expect("valid cluster config"),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = genesis(3)
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .unwrap();
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let reconfig_checksum = Body::Reconfigure(payload.clone()).body_checksum();

  // Drive slot 1 into ViewChange as primary of view 1 via the real SVC path (its own DVC carries op 0
  // — it holds nothing yet). The canonical donor (replica 2) carries the Reconfigure op at op 1
  // HEADER-ONLY (a `Repairing` entry with the canonical RECONFIGURATION checksum) at log_view 0,
  // vouching commit 0 (uncommitted tail — it re-commits under the new view). With the new primary's
  // own DVC, the 2-of-3 quorum forms and the canonical generation (log_view 0) unions in op 1.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks); // primary_idle → propose view 1, own SVC bit
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    &mut blocks,
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
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land the durable-view write → start_view_participate
  while e.poll_message().is_some() {}

  // Answer the new primary's RequestPrepare for op 1 with the canonical RECONFIGURATION body (a holder
  // serves it; commit >= op vouches it). The fill must rebuild a typed Body::Reconfigure.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the RepairFill append lands → the body is in the log
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
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land the SwapEpoch root → install
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
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).expect("valid cluster config"),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = genesis(3)
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .unwrap();
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let op = 1u64;

  // (1) The view-0 primary's Prepare for the Reconfigure op (flat wire body = encoded successor).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the backup's append lands
  sb.flush(); // the append is durable
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}

  // (2) The primary's Commit advances the backup's commit to the Reconfigure op → it commits (commit_min
  // moves PAST it) + stages the swap. The `SwapEpoch` root is submitted but NOT yet flushed — it is in
  // flight across the view change to come.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks); // primary_idle → propose view 1, own SVC bit
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    &mut blocks,
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
    &mut blocks,
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
    e.handle_storage(later, &mut wal, &mut sb, &mut blocks);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner is a valid delta on a 3-voter cluster");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  let op = e
    .propose_membership(
      now,
      &mut wal,
      SingleVoterDelta::AddLearner(MemberId::new(3)),
    )
    .expect("the primary mints the reconfiguration op");
  // DROP the one-shot broadcast Prepare: no backup ever hears the initial transmission.
  while e.poll_message().is_some() {}
  // The primary's own append lands (its own vote), but with the Prepare dropped no quorum forms — the
  // Reconfigure op is stuck uncommitted in the un-acked window.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    e.commit() < op,
    "the Reconfigure op is uncommitted (its only Prepare was dropped, so no quorum acked it)"
  );

  // Fire the prepare-retransmit tick: it MUST re-ship the Reconfigure op (TODAY it skips the op because
  // its body is `Body::Reconfigure`, not `Body::Present` — the op is never resent and the change stalls).
  e.handle_timeout(
    now + super::super::PREPARE_RETRANSMIT,
    &mut wal,
    &mut sb,
    &mut blocks,
  );
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
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land the SwapEpoch root → install
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
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).expect("valid cluster config"),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner is a valid delta on a 3-voter cluster");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  // (1) Replica 1 (a view-0 backup) receives the view-0 primary's Prepares: a client op at op 1, then the
  // reconfiguration op at op 2. It now holds op 2 LOCALLY as a typed `Body::Reconfigure`.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
    &mut blocks,
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
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    while e.poll_message().is_some() {}
    if e.commit() >= OpNumber::with(2) {
      break;
    }
    // The new primary re-commits op 2 once a quorum re-acks it under view 1.
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
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
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis(4),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the primary's own append lands (own vote)
  for acker in [1u16, 2u16] {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(acker)),
      reconfigure_ack(op.get(), &payload, acker),
    );
  }
  // Drain the SwapEpoch root + its forced checkpoint (snapshot -> durable root) to completion.
  for _ in 0..8 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
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
  let mut blocks = crate::block_store::MemBlockStore::new();
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
    &mut blocks,
    from,
    request_sync(old_claimed_slot, predecessor_config_id),
  );
  donor.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drive the serve-read completion → ship the SyncCheckpoint

  // The donor SERVED it: a SyncCheckpoint (or its over-frame announce) addressed to the laggard's CURRENT
  // slot, carrying the donor's E+1 membership (the cross-epoch crossing payload). It was NOT dropped at the
  // sender binding.
  let mut served_to_current_slot = false;
  while let Some(out) = donor.poll_message() {
    if let Message::SyncCheckpoint(scp) = out.msg_ref() {
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
  }
  assert!(
    served_to_current_slot,
    "the slot-shifted cross-epoch RequestSync was admitted to on_request_sync and SERVED — not dropped"
  );

  // GUARD: the strict binding still bites for the no-shift forge surface. A RequestSync whose claimed slot
  // DISAGREES with `from` AND whose config_id is the donor's CURRENT (E+1) config — i.e. NOT a cross-epoch
  // ancestor solicitation, just a mismatched self-id — is DROPPED (no relaxation).
  let (mut d2, mut w2, mut s2, _pred, _ck) = donor_at_e1_with_shifted_member();
  let mut s2blocks = crate::block_store::MemBlockStore::new();
  let current_config = d2.membership.config_id();
  d2.handle_message(
    now,
    &mut w2,
    &mut s2,
    &mut s2blocks,
    Peer::Replica(ReplicaId::new(2)),                // from = slot 2
    request_sync(ReplicaId::new(0), current_config), // claims slot 0, CURRENT config (not an ancestor)
  );
  d2.handle_storage(now, &mut w2, &mut s2, &mut s2blocks);
  assert!(
    !d2
      .poll_message()
      .is_some_and(|o| matches!(o.msg_ref(), Message::SyncCheckpoint(_))),
    "a same-config mismatched-self-id RequestSync is still DROPPED by the strict binding (no relaxation)"
  );
}

#[test]
fn a_slot_shifted_cross_epoch_sync_checkpoint_fetches_blocks_from_the_authenticated_from_slot() {
  // The cross-epoch BLOCK-FETCH donor pin (the laggard side). A retained OLD-epoch laggard armed a
  // cross-epoch crossing sync; a donor whose slot SHIFTED across the reconfiguration answers with a
  // `SyncCheckpoint` stamping its SUCCESSOR-epoch (shifted) slot in `replica()`, while the authenticated
  // `from` is the slot the laggard ACTUALLY routes to in its own (old) membership — the slot the
  // relaxed sender-binding admitted the reply on. The crossing checkpoint's SM DAG is NOT local, so the
  // laggard must FETCH it. The follow-up `RequestBlock` MUST be addressed to `from`'s routeable slot (the
  // real donor), NOT `replica()`'s shifted slot — which routes to a DIFFERENT member (or nobody) in the
  // laggard's old-epoch routing, never fetching the blocks → wedge.
  let m2: u64 = 2; // the E+1 crossing checkpoint op the laggard is crossing to
  let genesis_mem = genesis(3);
  let successor_e1 = genesis_mem
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid (E+1)");

  // A Normal BACKUP (slot 1) at the OLD epoch (E0, the genesis lineage), op == commit_min == 0, checkpoint 0.
  let cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  let mut e = Endpoint::<CountSm>::genesis_unchecked(
    cfg,
    genesis_mem.clone(),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.force_state_for_test(0, 0, 0, 0, &[]);

  // Arm a forced cross-epoch crossing sync toward the E+1 crossing checkpoint M2 (the laggard heard a
  // higher-epoch hint and armed the crossing while staying Normal).
  e.arm_cross_epoch_sync_for_test(m2);
  let nonce = e.sync_nonce_for_test();

  // The crossing checkpoint's SM root — DELIBERATELY NOT seeded into the laggard's store, so the install
  // frontier does NOT drain locally and the laggard must emit a `RequestBlock` to the donor.
  let cross_snap = CountSm::default().snapshot();
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(m2),
    crate::block_address(&cross_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  let membership_body =
    ReconfigurePayload::from_membership(&successor_e1, genesis_mem.config_id()).encode_body();

  // The donor self-claims the SHIFTED slot 2 (its successor-epoch slot), but the authenticated `from` is
  // slot 1 — a CURRENT member of the laggard's (genesis) membership, the slot the laggard routes to. The
  // two DIFFER, exactly the slot-shifted cross-epoch donor.
  let shifted_claimed_slot = ReplicaId::new(2);
  let routeable_from_slot = ReplicaId::new(1);
  assert_ne!(
    shifted_claimed_slot, routeable_from_slot,
    "the donor's self-claimed (shifted) slot DIFFERS from the slot the laggard routes to"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(routeable_from_slot),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(m2),
      cross_id,
      successor_e1.epoch(),
      successor_e1.config_id(), // a DESCENDANT of the laggard's genesis config — the crossing reply
      shifted_claimed_slot,     // the donor's self-claimed SUCCESSOR-epoch (shifted) slot
      nonce,
      cross_env.clone(),
      membership_body.clone(),
    )),
  );

  // The block-fetch is pinned to the AUTHENTICATED `from` slot (the routeable donor), NOT the shifted
  // self-claimed slot.
  assert_eq!(
    e.block_fetch_donor(),
    Some(routeable_from_slot.get()),
    "the block-fetch donor is pinned to the authenticated `from` slot, not the shifted `replica()`"
  );

  // The emitted `RequestBlock` routes to `from`'s slot (the real donor) — never the shifted slot.
  let mut requested_from_routeable = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::RequestBlock(_)) {
      assert_eq!(
        out.to(),
        Recipient::To(Peer::Replica(routeable_from_slot)),
        "the RequestBlock is addressed to the authenticated `from` slot (the real donor)"
      );
      assert_ne!(
        out.to(),
        Recipient::To(Peer::Replica(shifted_claimed_slot)),
        "the RequestBlock is NOT addressed to the donor's shifted self-claimed slot"
      );
      requested_from_routeable = true;
    }
  }
  assert!(
    requested_from_routeable,
    "the laggard emitted a RequestBlock for the non-local crossing DAG, addressed to the real donor"
  );

  // Drive the fetch+crossing to completion: the donor (at `from`'s slot) answers the RequestBlock with the
  // crossing block; the frontier drains and the crossing install completes.
  blocks.write_verified(cross_snap.clone()); // the donor's BlockResponse lands the block
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(routeable_from_slot),
    Message::BlockResponse(crate::BlockResponse::new(
      crate::block_address(&cross_snap),
      Some(cross_snap.clone()),
    )),
  );
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // two-write re-persist -> durable root -> install
  }
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the fetch+crossing completed (the blocks were fetched from the real donor and installed)"
  );
  assert_eq!(
    e.membership, successor_e1,
    "the laggard CROSSED to E+1 via the fetched crossing checkpoint"
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
  let mut blocks = crate::block_store::MemBlockStore::new();
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
    &mut blocks,
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
    &mut blocks,
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

// ---------------------------------------------------------------------------------------------
// The install-time voter-admission fence: a committed `Reconfigure` op may not seat a brand-new
// voter (one that was never a member of its exact predecessor). One falsifier per reachable path —
// the prepare-append screen, the primary commit lane, the backup/adoption re-commit lane, and the
// recovery WAL-replay re-commit — plus the legitimate-delta positive controls. The cross-epoch
// STATE-SYNC install has no constructible falsifier BY DESIGN: a laggard installs a wholesale,
// hash-verified successor possibly many epochs ahead, where "voter not in my stale configuration"
// is a LEGITIMATE shape (added-then-promoted across the skipped epochs), so no local single-change
// diff exists to trip; that path's safety is the induction — every compliant committer runs this
// fence, so no committed state (hence no donor checkpoint) ever contains a direct-add successor.
//
// The VOTE-MINT screens close the remaining ack/vote lanes for an entry that reaches a log WITHOUT
// crossing the screened prepare append (a recovered WAL, a view-change adoption): `send_prepare_ok`
// refuses the ack — covering the canonical re-ack and the adoption re-ack — and `record_own_vote`
// refuses the own bit — covering the adopted-tail re-append and the peer-repair fill. Each lane has
// a falsifier below, plus legitimate-delta positive controls proving the screens admit every legal
// shape (and the checkpoint-report re-ack, whose GC-pruned op the ack screen must let through).
// ---------------------------------------------------------------------------------------------

#[test]
fn a_direct_voter_add_prepare_is_dropped_before_append_and_ack() {
  // The append-seam screen: a RECONFIGURATION `Prepare` whose successor seats a brand-new voter,
  // pinned to THIS backup's current configuration, is dropped whole — no log entry, no head advance,
  // no WAL append, and (append-before-ack) no PrepareOk. The op can therefore never assemble a
  // quorum of compliant acks, which is what keeps the commit-time fence unreachable in a compliant
  // cluster.
  let mut e = single_change_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the delta arithmetic still derives a direct-add successor");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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

  assert!(
    !e.log.contains_key(&1),
    "the direct-add prepare was not appended to the log"
  );
  assert_eq!(e.op().get(), 0, "the head did not advance");
  assert!(
    wal.entries.is_empty(),
    "no WAL append was submitted for the dropped prepare"
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while let Some(out) = e.poll_message() {
    assert!(
      !matches!(out.msg_ref(), Message::PrepareOk(_)),
      "the dropped prepare must never be acked"
    );
  }
}

#[test]
#[should_panic(expected = "refusing to install the committed Reconfigure op")]
fn committing_a_direct_voter_add_panics_on_the_primary_commit_lane() {
  // The authoritative fence, primary lane: `propose_membership` refuses to mint a direct AddVoter,
  // so this seeds the minted-op shape directly (head at the op, a typed log entry, the op durable in
  // the WAL, the primary's own vote recorded) — modeling an op minted without the propose guard. The
  // one backup ack completes the 2-of-3 quorum, `try_commit` recognizes the Reconfigure op, and the
  // commit-time fence refuses BEFORE any swap is staged or made durable.
  let mut e = single_change_primary();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the delta arithmetic still derives a direct-add successor");
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let body = payload.encode_body();
  let header = Header::new(
    OpNumber::with(1),
    View::new(),
    ClientId::RECONFIGURATION,
    RequestNumber::with(1),
    &body,
  );

  e.op = OpNumber::with(1);
  e.log.insert(
    1,
    LogEntry::reconfigure(
      ClientId::RECONFIGURATION,
      RequestNumber::with(1),
      payload.clone(),
    ),
  );
  wal.entries.insert(1, (header, body));
  wal.head = 1;
  e.inflight.insert(
    1,
    Inflight {
      oks: 1, // the primary's own slot-0 vote (its append landed)
      committed: false,
      prepare_checksum: crate::storage::prepare_identity(
        ClientId::RECONFIGURATION,
        RequestNumber::with(1),
        Body::Reconfigure(payload.clone()).body_checksum(),
      ),
    },
  );

  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    reconfigure_ack(1, &payload, 1),
  );
}

#[test]
#[should_panic(expected = "refusing to install the committed Reconfigure op")]
fn committing_a_direct_voter_add_panics_on_the_backup_recommit_lane() {
  // The backup/adoption re-commit lane: an entry that reaches a log WITHOUT crossing the screened
  // prepare append — a view-change adoption inserts canonical entries straight into `self.log`
  // (typed, so `commit_reconfigure` recognizes them at re-commit), and this seeds that same shape
  // directly — still cannot install: the shared commit recognition (`advance_commit` →
  // `commit_reconfigure`) hits the fence the moment a Commit advances past the op.
  let mut e = single_change_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the delta arithmetic still derives a direct-add successor");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  e.op = OpNumber::with(1);
  e.log.insert(
    1,
    LogEntry::reconfigure(ClientId::RECONFIGURATION, RequestNumber::with(1), payload),
  );

  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
}

#[test]
#[should_panic(expected = "refusing to install the committed Reconfigure op")]
fn recovery_recommitting_a_direct_voter_add_panics_at_the_fence() {
  // The recovery WAL-replay lane, modeling a store written WITHOUT this fence: the WAL holds a
  // COMMITTED direct-voter-add Reconfigure op (the durable root's commit covers it and its
  // committed-band header names it) while the durable membership is still the predecessor — the
  // committed-but-uninstalled window. Recovery rebuilds the typed `Body::Reconfigure` entry from the
  // WAL through the shared reconstruction and re-commits the band above the checkpoint through the
  // SAME commit recognition as live traffic, where the fence refuses the direct admission. (The one
  // pre-fence shape no runtime check can catch — a direct-add successor ALREADY INSTALLED into the
  // durable root — is excluded by not running this build over pre-fence stores at all; see the fence
  // comment in `commit_reconfigure`.)
  let successor = genesis(3)
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the delta arithmetic still derives a direct-add successor");
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let body = payload.encode_body();
  let header = Header::new(
    OpNumber::with(1),
    View::new(),
    ClientId::RECONFIGURATION,
    RequestNumber::with(1),
    &body,
  );

  let mut wal = TestWal::default();
  wal.entries.insert(1, (header, body));
  wal.head = 1;
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(1),
    OpNumber::new(),
    0,
    std::vec![header],
  )
  .expect("a root recording the committed reconfigure op is valid")
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut blocks = crate::block_store::MemBlockStore::new();

  let cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  let recovered = Endpoint::<CountSm, SingleChange>::recover_with_reconfig(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect("recover accepts this store");
  let mut e = match recovered {
    Recovered::Active(e) => e,
    Recovered::Retired(_) => panic!("a current member recovers Active"),
  };

  // Re-commit the recovered band above the checkpoint through the ordinary commit path.
  let now = Instant::ZERO;
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
}

#[test]
#[should_panic(expected = "a commit-first swap must never install")]
fn installing_a_direct_voter_add_swap_panics_at_the_backstop() {
  // The single-membership-writer backstop. `install_membership` is the ONE place a successor becomes
  // the live configuration; for a commit-first swap (a `Some` reconfigure op) its `debug_assert`
  // re-affirms that the successor seats no brand-new voter. On every live path this is unreachable —
  // `commit_reconfigure`'s panic refuses a direct voter admission before any swap is staged, so no
  // such successor ever reaches the writer — so this drives the writer DIRECTLY to pin the
  // defense-in-depth check: build a direct-add successor (a voter absent from the predecessor) and
  // hand it to `install_membership(Some(N), ..)`. The backstop fails-stop rather than install a
  // configuration whose new voter holds no committed prefix. (The cross-epoch state-sync install —
  // the `None` arm — is exempt by design and is not exercised here.)
  let mut e = single_change_primary();
  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the delta arithmetic still derives a direct-add successor");
  e.install_membership(Some(OpNumber::with(1)), successor);
}

#[test]
fn every_legitimate_delta_commits_and_installs_through_the_backup_lane() {
  // Positive controls: each accepted delta kind — AddLearner, PromoteLearner, RemoveVoter,
  // RemoveLearner — still passes the fence end to end on the backup lane: the prepare appends
  // (screened), the op commits (fenced), the SwapEpoch root lands, the successor installs, and a
  // `MembershipChanged` names the op. The promote-time challenge is a PROPOSE-side gate (covered by
  // the propose tests); the commit lane installs whatever legitimately committed. RemoveVoter removes
  // a NON-local voter (removing the local node retires it — a separate concern with its own tests).
  let cases: [(Membership, SingleVoterDelta); 4] = [
    (genesis(3), SingleVoterDelta::AddLearner(MemberId::new(3))),
    (
      genesis_with_learners(3, 1),
      SingleVoterDelta::PromoteLearner(MemberId::new(3)),
    ),
    (genesis(3), SingleVoterDelta::RemoveVoter(MemberId::new(2))),
    (
      genesis_with_learners(3, 1),
      SingleVoterDelta::RemoveLearner(MemberId::new(3)),
    ),
  ];
  for (pred, delta) in cases {
    let cfg = Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
    let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
      cfg,
      pred.clone(),
      0,
      CountSm::default(),
      u64::MAX,
    );
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let mut blocks = crate::block_store::MemBlockStore::new();
    let now = Instant::ZERO;

    let successor = pred
      .apply_delta(&delta)
      .expect("a legitimate delta derives its successor");
    let payload = ReconfigurePayload::from_membership(&successor, 0);

    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
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
    assert!(
      e.log.contains_key(&1),
      "the {} prepare passed the append screen",
      delta.as_str(),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land the append (deferred PrepareOk)
    while e.poll_message().is_some() {}

    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(1),
        OpNumber::new(),
        crate::Epoch::new(0),
        0,
      )),
    );
    assert!(
      e.pending_swap_for_test(),
      "the {} op committed and staged its swap",
      delta.as_str(),
    );
    while e.poll_event().is_some() {} // drain pre-swap events so the install event is observable

    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land the SwapEpoch root → install
    assert_eq!(
      e.membership,
      successor,
      "the {} successor installed at the durable root",
      delta.as_str(),
    );
    let mut changed = false;
    while let Some(ev) = e.poll_event() {
      if let Event::MembershipChanged(c) = ev {
        assert_eq!(
          c.op().get(),
          1,
          "the MembershipChanged names the {} op",
          delta.as_str(),
        );
        changed = true;
      }
    }
    assert!(
      changed,
      "a MembershipChanged was emitted for {}",
      delta.as_str(),
    );
  }
}

#[test]
fn a_matching_durable_direct_voter_add_prepare_is_never_re_acked() {
  // The canonical re-ack lane: the backup already holds the direct-add Reconfigure op DURABLY (the
  // typed entry in `self.log`, its WAL slot Clean — the shape a recovered store or a completed
  // append leaves), and the primary retransmits the identical Prepare. `on_prepare` takes the
  // canonical-held branch (identity match + durable), which acks WITHOUT crossing the append-seam
  // screen — the `send_prepare_ok` mint screen is what refuses the vouch.
  let mut e = single_change_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the delta arithmetic still derives a direct-add successor");
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let body = payload.encode_body();
  let header = Header::new(
    OpNumber::with(1),
    View::new(),
    ClientId::RECONFIGURATION,
    RequestNumber::with(1),
    &body,
  );
  e.op = OpNumber::with(1);
  e.log.insert(
    1,
    LogEntry::reconfigure(
      ClientId::RECONFIGURATION,
      RequestNumber::with(1),
      payload.clone(),
    ),
  );
  wal.entries.insert(1, (header, body));
  wal.head = 1;

  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while let Some(out) = e.poll_message() {
    assert!(
      !matches!(out.msg_ref(), Message::PrepareOk(_)),
      "a held direct-add op is never re-acked"
    );
  }
}

#[test]
fn a_matching_durable_legitimate_reconfigure_prepare_is_re_acked() {
  // The positive control on the canonical re-ack lane: an AddLearner successor (a legal delta) in
  // the identical held-durable shape IS re-acked — the mint screen refuses only a brand-new voter
  // admission, never a legitimate reconfiguration.
  let mut e = single_change_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner is a valid delta on a 3-voter cluster");
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let body = payload.encode_body();
  let header = Header::new(
    OpNumber::with(1),
    View::new(),
    ClientId::RECONFIGURATION,
    RequestNumber::with(1),
    &body,
  );
  e.op = OpNumber::with(1);
  e.log.insert(
    1,
    LogEntry::reconfigure(
      ClientId::RECONFIGURATION,
      RequestNumber::with(1),
      payload.clone(),
    ),
  );
  wal.entries.insert(1, (header, body));
  wal.head = 1;

  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  let mut acked = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.msg_ref() {
      assert_eq!(ok.op().get(), 1, "the re-ack names the held op");
      acked = true;
    }
  }
  assert!(acked, "the held legitimate reconfigure op is re-acked");
}

#[test]
fn a_direct_voter_add_interior_overwrite_is_refused_before_the_log_and_wal() {
  // The interior-overwrite lane: the backup's head is PAST the op but it holds NO entry at it (the
  // dropped-stale interior shape), so a current-view Prepare would durably (re-)append into the
  // interior slot. The `reappend_canonical_prepare` screen refuses the direct-add BEFORE the log
  // insert and the WAL write — no entry, no slot, and (append-before-ack) no deferred ack. Asserted
  // on the log + WAL state, which only this seam guards: the ack mint would independently refuse
  // the vouch, so an ack assertion alone could not witness this screen.
  let mut e = single_change_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the delta arithmetic still derives a direct-add successor");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  e.op = OpNumber::with(2);
  e.log.insert(
    2,
    LogEntry::present(
      ClientId::new(7),
      RequestNumber::with(2),
      Bytes::copy_from_slice(&[2u8]),
    ),
  );

  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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

  assert!(
    !e.log.contains_key(&1),
    "the direct-add interior op takes no log entry"
  );
  assert!(
    wal.entries.is_empty(),
    "no interior WAL overwrite was submitted for the dropped prepare"
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while let Some(out) = e.poll_message() {
    assert!(
      !matches!(out.msg_ref(), Message::PrepareOk(_)),
      "the refused interior overwrite owes no ack"
    );
  }
}

#[test]
fn an_adopted_direct_voter_add_tail_op_is_never_adopt_acked() {
  // The view-change adoption re-ack lane: a backup adopts a StartView whose canonical tail carries
  // an uncommitted direct-add Reconfigure op alongside a legitimate client op. After the durable
  // view lands, `start_view_acks` re-appends each held tail op and defers its PrepareOk to the
  // append completion — a lane that never crosses the append-seam screen. The `send_prepare_ok`
  // mint screen refuses the direct-add op's vouch; the neighboring legitimate op IS acked (the
  // in-test positive control), so the refusal is the screen, not a stalled adoption.
  let cfg = Config::try_new(2, MemberId::new(2)).expect("valid cluster config");
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the delta arithmetic still derives a direct-add successor");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(crate::StartView::new(
      View::with(1),
      OpNumber::with(2),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(1),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          Bytes::copy_from_slice(b"a"),
        ),
        PreparedEntry::reconfigure(
          OpNumber::with(2),
          ClientId::RECONFIGURATION,
          RequestNumber::with(2),
          payload.clone(),
        ),
      ],
    )),
  );
  // Land the durable-view root, then the AdoptAck re-appends it schedules.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  let (mut acked_1, mut acked_2) = (false, false);
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.msg_ref() {
      match ok.op().get() {
        1 => acked_1 = true,
        2 => acked_2 = true,
        _ => {}
      }
    }
  }
  assert!(
    acked_1,
    "the legitimate adopted tail op is adopt-acked once durable"
  );
  assert!(!acked_2, "the adopted direct-add op is never adopt-acked");
}

#[test]
fn an_adopted_legitimate_reconfigure_tail_op_is_adopt_acked() {
  // The positive control on the adoption re-ack lane: a LEGAL reconfiguration op (AddLearner)
  // adopted as the uncommitted tail is re-appended and acked once durable — the mint screen admits
  // every legitimate delta on this lane too.
  let cfg = Config::try_new(2, MemberId::new(2)).expect("valid cluster config");
  let mut e = Endpoint::<CountSm, SingleChange>::genesis_unchecked(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner is a valid delta on a 3-voter cluster");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(crate::StartView::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(1),
      std::vec![PreparedEntry::reconfigure(
        OpNumber::with(1),
        ClientId::RECONFIGURATION,
        RequestNumber::with(1),
        payload.clone(),
      )],
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  let mut acked = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.msg_ref() {
      assert_eq!(ok.op().get(), 1, "the adopt-ack names the adopted op");
      acked = true;
    }
  }
  assert!(acked, "the adopted legitimate reconfigure op is adopt-acked");
}

#[test]
fn a_forged_ack_cannot_commit_an_adopted_direct_voter_add_tail_op() {
  // The adopted-tail own-vote lane, plus the single-corruption bound: replica 1 becomes the view-1
  // primary adopting a canonical tail whose op 1 is the direct-add Reconfigure (uncommitted). The
  // adopted-tail re-append completes and `record_own_vote` REFUSES the own bit; one forged
  // content-matched PrepareOk (a single corrupted message) then contributes the ONLY vote the op
  // ever gets — 1 of the required 2 — so the op never commits: no swap is staged, the commit-time
  // fence panic is unreachable, and the cluster survives the poison op un-committed rather than
  // fail-stopping.
  let mut e = single_change_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the delta arithmetic still derives a direct-add successor");
  let payload = ReconfigurePayload::from_membership(&successor, 0);

  // Idle-timeout into the view change, then a second StartViewChange completes the view-change
  // quorum for view 1 (this replica leads it).
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  // A DoViewChange from replica 2 carries the direct-add op as the canonical uncommitted tail; the
  // new primary adopts it (`oks: 0`) and re-appends it tagged for its own vote.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![PreparedEntry::reconfigure(
        OpNumber::with(1),
        ClientId::RECONFIGURATION,
        RequestNumber::with(1),
        payload.clone(),
      )],
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  assert!(
    e.log.contains_key(&1),
    "precondition: the adopted direct-add op is held in the new view's log"
  );

  // The forged, content-matched ack — the single in-model corrupted message.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(crate::PrepareOk::new(
      View::with(1),
      OpNumber::with(1),
      ReplicaId::new(2),
      OpNumber::new(),
      crate::storage::prepare_identity(
        ClientId::RECONFIGURATION,
        RequestNumber::with(1),
        Body::Reconfigure(payload.clone()).body_checksum(),
      ),
      crate::Epoch::new(0),
      0,
    )),
  );

  assert_eq!(
    e.commit_min.get(),
    0,
    "the direct-add op never commits: its only vote is the forged ack"
  );
  assert!(!e.pending_swap_for_test(), "no epoch swap is staged");
  assert_eq!(e.membership, genesis(3), "the configuration is unchanged");
}

#[test]
fn a_repair_filled_direct_voter_add_tail_op_earns_no_own_vote() {
  // The peer-repair own-vote lane: the new primary adopted the direct-add op HEADER-ONLY (a
  // `Repairing` carrier), so the adoption re-append skipped it and the repair channel fetches its
  // body. When the fill lands durably, the uncommitted-tail completion casts the primary's own
  // vote — `record_own_vote` refuses it there (the fill inserted the TYPED body first, so the
  // screen classifies it). A forged content-matched PrepareOk then leaves the op at 1 of the
  // required 2 votes: never committed, no swap, no fail-stop.
  let mut e = single_change_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  let successor = e
    .membership
    .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("the delta arithmetic still derives a direct-add successor");
  let payload = ReconfigurePayload::from_membership(&successor, 0);
  let body_checksum = Body::Reconfigure(payload.clone()).body_checksum();

  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  // The canonical log: op 1 committed (a client op), op 2 the direct-add Reconfigure carried
  // HEADER-ONLY — its durable canonical identity (client, request, body checksum) without bytes.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::new(),
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
          Bytes::copy_from_slice(b"a"),
        ),
        PreparedEntry::repairing(
          OpNumber::with(2),
          ClientId::RECONFIGURATION,
          RequestNumber::with(2),
          body_checksum,
        ),
      ],
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  assert!(
    e.log.get(&2).is_some_and(|entry| entry.body.is_repairing()),
    "precondition: the adopted direct-add op is held header-only"
  );
  assert!(
    e.has_repair_hole_for_test(2),
    "precondition: the header-only tail op is a registered repair hole"
  );

  // A peer's Prepare carrying the canonical body answers the hole; `fill_repair` verifies the FULL
  // kept identity (client, request, body checksum) and stages the durable fill.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::Prepare(Prepare::new(
      View::with(1),
      OpNumber::with(2),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ClientId::RECONFIGURATION,
      RequestNumber::with(2),
      payload.encode_body(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  assert!(
    e.log
      .get(&2)
      .is_some_and(|entry| entry.body.as_reconfigure().is_some()),
    "the fill landed the TYPED reconfigure body (what the vote-mint screen classifies)"
  );

  // The forged, content-matched ack — the single in-model corrupted message.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(crate::PrepareOk::new(
      View::with(1),
      OpNumber::with(2),
      ReplicaId::new(2),
      OpNumber::new(),
      crate::storage::prepare_identity(
        ClientId::RECONFIGURATION,
        RequestNumber::with(2),
        body_checksum,
      ),
      crate::Epoch::new(0),
      0,
    )),
  );

  assert_eq!(
    e.commit_min.get(),
    1,
    "only the legitimate committed prefix applies; the direct-add op never commits"
  );
  assert!(!e.pending_swap_for_test(), "no epoch swap is staged");
  assert_eq!(e.membership, genesis(3), "the configuration is unchanged");
}

#[test]
fn the_checkpoint_report_re_ack_still_fires_with_a_pruned_log() {
  // The heartbeat checkpoint report re-acks the backup's own `checkpoint_op` — an op folded into
  // the durable snapshot and GC-pruned from the log cache, so the ack mint's admission screen reads
  // NO entry and must let the report through: the op is committed (the commit-time fence already
  // ruled on it) and the report's identity stamp matches no live inflight entry.
  let mut e = single_change_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  e.handle_message(now, &mut wal, &mut sb, &mut blocks, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    e.force_checkpoint(&mut sb, &mut blocks),
    "the committed+applied boundary is checkpointable"
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  assert_eq!(e.checkpoint_op.get(), 1, "precondition: the checkpoint advanced");
  assert!(
    !e.log.contains_key(&1),
    "precondition: the checkpointed op is GC-pruned from the log cache"
  );

  // The next Commit heartbeat re-reports: a PrepareOk for `checkpoint_op` fires despite the pruned
  // entry (its identity stamp is the absent-entry zero — inert at the primary's vote ingress).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  let mut reported = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.msg_ref() {
      assert_eq!(ok.op().get(), 1, "the report re-acks the checkpoint op");
      reported = true;
    }
  }
  assert!(
    reported,
    "the checkpoint report re-ack still fires with a pruned log entry"
  );
}

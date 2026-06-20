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
  let expected_payload = ReconfigurePayload::from_membership(&successor);

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
  let payload = ReconfigurePayload::from_membership(&successor);

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
  let payload = ReconfigurePayload::from_membership(&successor);
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
  let payload = ReconfigurePayload::from_membership(&successor);
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
  let payload = ReconfigurePayload::from_membership(&successor);
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
  let payload = ReconfigurePayload::from_membership(&successor);
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
  let payload2 = ReconfigurePayload::from_membership(&succ2);
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
  let payload = ReconfigurePayload::from_membership(&successor);
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
  let payload = ReconfigurePayload::from_membership(&successor);
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
  let payload = ReconfigurePayload::from_membership(&successor);
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

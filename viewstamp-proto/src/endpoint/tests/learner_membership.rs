//! The voter-vs-member sender split and the voter-only GC order statistic, exercised in a cluster
//! configured WITH learners (so `node_count > replica_count` and a learner id exists). With
//! `learner_count == 0` every check below is byte-identical to the voting-only behavior; these tests
//! pin the BEHAVIOR ONCE a learner id is present: a learner is a valid SENDER of serves/solicitations
//! of committed content (and a valid serve-handler REQUESTER), but is never counted in any quorum/vote,
//! and never pollutes the GC quorum order statistic.

use super::*;
use crate::{
  ClientId, Commit, Config, DoViewChange, OpNumber, ReplicaId, Request, RequestNumber,
  StartViewChange, View,
};

/// A 3-voter cluster (ids 0,1,2) with 2 learners (ids 3,4 — `node_count == 5`), self = voter 0.
fn voter_with_learners() -> Endpoint<NoopSm> {
  Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(0)).expect("valid 3-voter + 2-learner config"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
    u64::MAX,
  )
}

/// The first learner id (`replica_count == 3`, so id 3 is the first non-voting member).
const LEARNER: u16 = 3;

#[test]
fn sender_matches_accepts_serve_and_solicit_messages_from_a_learner() {
  // A non-voting member legitimately SOLICITS committed state and can SERVE committed content to
  // others — so the serve/solicit family binds to the FULL membership (`sender_is_member`), not the
  // voting set. Each of these, self-claiming the learner id 3 from the matching `Peer::Replica(3)`,
  // must be ACCEPTED. (These carry no quorum authority; the content is verified independently.)
  let e = voter_with_learners();
  let from = Peer::Replica(ReplicaId::new(LEARNER));
  let learner = ReplicaId::new(LEARNER);
  let v = View::new();
  let op = OpNumber::with(1);

  let serves = [
    Message::GetView(crate::GetView::new(v, learner, 7, crate::Epoch::new(0), 0)),
    Message::RequestPrepare(crate::RequestPrepare::new(v, op, learner, 0)),
    Message::RequestPrepareRange(crate::RequestPrepareRange::new(v, op, op, learner, 0)),
    Message::Recovery(crate::Recovery::new(learner, 7, crate::Epoch::new(0), 0)),
    Message::RequestSync(crate::RequestSync::new(
      v,
      OpNumber::new(),
      learner,
      7,
      false,
      0,
    )),
  ];
  for msg in serves {
    assert!(
      e.sender_matches(from, &msg),
      "a serve/solicit message from a learner id is a valid member sender: {msg:?}",
    );
  }
}

#[test]
fn sender_matches_accepts_a_repair_serve_prepare_and_repair_batch_from_a_learner() {
  // The `Prepare` repair-serve escape and `RepairBatch` bind to the full membership (`< node_count`):
  // a non-voting member holding a committed op can serve a repair. The escape additionally requires
  // the op to be a registered repair hole — so register an op-2 hole first, then a repair `Prepare`
  // for op 2 from the learner passes the escape. `RepairBatch` carries no self id, so any member
  // `from` (incl. the learner) is accepted; `fill_repair`/`fill_repair_batch` verify the bodies.
  let mut e = voter_with_learners();
  e.force_state_for_test(0, 3, 1, 0, &[2]); // hold a repair hole at op 2
  assert!(e.has_repair_hole_for_test(2), "op-2 hole registered");
  let from = Peer::Replica(ReplicaId::new(LEARNER));

  let repair_serve = Message::Prepare(Prepare::new(
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    OpNumber::new(),
    crate::Epoch::new(0),
    0,
    ClientId::new(7),
    RequestNumber::with(2),
    Bytes::copy_from_slice(&[2u8]),
  ));
  assert!(
    e.sender_matches(from, &repair_serve),
    "a repair-serve Prepare for a registered hole from a learner (a member) is accepted",
  );

  let batch = Message::RepairBatch(crate::RepairBatch::new(
    View::new(),
    OpNumber::with(2),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
  ));
  assert!(
    e.sender_matches(from, &batch),
    "a RepairBatch from a learner (a member) is accepted — fill_repair_batch verifies each entry",
  );
}

#[test]
fn sender_matches_rejects_votes_from_a_learner() {
  // VOTES bind to the VOTING set (`sender_is_voter`): a vote from a non-voting member must NEVER reach
  // a quorum bitset / vote map. Each of `PrepareOk`/`StartViewChange`/`DoViewChange`, self-claiming
  // the learner id 3 from the matching `Peer::Replica(3)`, must be REJECTED at ingress.
  let e = voter_with_learners();
  let from = Peer::Replica(ReplicaId::new(LEARNER));
  let learner = ReplicaId::new(LEARNER);
  let v = View::new();
  let op = OpNumber::with(1);

  let prepare_ok = Message::PrepareOk(PrepareOk::new(
    v,
    op,
    learner,
    OpNumber::new(),
    0,
    crate::Epoch::new(0),
    0,
  ));
  assert!(
    !e.sender_matches(from, &prepare_ok),
    "a PrepareOk from a learner id is a non-voter vote — rejected",
  );

  let svc = Message::StartViewChange(crate::StartViewChange::new(
    View::with(1),
    learner,
    crate::Epoch::new(0),
    0,
  ));
  assert!(
    !e.sender_matches(from, &svc),
    "a StartViewChange from a learner id is a non-voter vote — rejected",
  );

  let dvc = Message::DoViewChange(DoViewChange::new(
    View::with(1),
    View::new(),
    op,
    OpNumber::new(),
    crate::Epoch::new(0),
    0,
    learner,
    std::vec::Vec::new(),
  ));
  assert!(
    !e.sender_matches(from, &dvc),
    "a DoViewChange from a learner id is a non-voter vote — rejected",
  );
}

#[test]
fn sender_matches_rejects_a_relayed_request_from_a_learner() {
  // A relayed client `Request` is accepted only from a VOTING replica: a non-voting member has no
  // client-ingress role, so it does NOT relay client writes. A Request whose authenticated `from` is
  // the learner id 3 (and not the issuing client) must be REJECTED.
  let e = voter_with_learners();
  let req = Message::Request(Request::new(
    ClientId::new(7),
    RequestNumber::with(1),
    Bytes::from_static(b"a"),
  ));
  assert!(
    !e.sender_matches(Peer::Replica(ReplicaId::new(LEARNER)), &req),
    "a client Request relayed by a learner id is rejected — a non-voting member does not relay writes",
  );
  // Positive control: the same relay from a VOTING replica (id 1) is accepted.
  assert!(
    e.sender_matches(Peer::Replica(ReplicaId::new(1)), &req),
    "the same Request relayed by a voting replica is accepted",
  );
}

#[test]
fn on_request_prepare_serves_a_learner_requester() {
  // A serve handler must answer a learner REQUESTER: the `>= node_count` range check admits a learner
  // id (in `[replica_count, node_count)`). Drive a voter backup to hold a committed op, then a learner
  // (id 3) RequestPrepare for it — the holder answers with the Prepare addressed back to the learner.
  // Goes end-to-end through `handle_message`, so it also exercises `sender_is_member` for RequestPrepare.
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).expect("voter 1 of 3 + 2 learners"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
    u64::MAX,
  );
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  // Hold ops 1 + 2 (apply 1 via the piggybacked commit), discard the resulting acks.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(now, &mut storage, primary_peer(), prepare(1, 0));
  e.storage_step(now, &mut storage, &mut blocks);
  e.handle_message(now, &mut storage, primary_peer(), prepare(2, 1));
  e.storage_step(now, &mut storage, &mut blocks);
  while e.poll_message().is_some() {}

  let learner = ReplicaId::new(LEARNER);
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(learner),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(1),
      learner,
      0,
    )),
  );
  let out = e
    .poll_message()
    .expect("the holder answers a learner's RequestPrepare");
  assert_eq!(
    out.to(),
    Recipient::To(Peer::Replica(learner)),
    "the Prepare is addressed back to the learner requester",
  );
  match out.into_msg() {
    Message::Prepare(p) => assert_eq!(p.op(), OpNumber::with(1), "carries the requested op"),
    other => panic!("expected a Prepare reply, got {other:?}"),
  }
}

#[test]
fn on_recovery_serves_a_learner_requester() {
  // The Recovery → RecoveryResponse serve must answer a learner requester too (the requester range is
  // `0..node_count`). A primary (voter 0) answers a learner (id 3) Recovery with a RecoveryResponse
  // addressed back to the learner. (A learner adopts a head only from the primary; the SERVE side is
  // membership-wide.)
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(0)).expect("voter 0 (primary of view 0) + 2 learners"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
    u64::MAX,
  );
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  assert!(e.is_primary(), "voter 0 is the primary of view 0");
  let learner = ReplicaId::new(LEARNER);
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(learner),
    Message::Recovery(crate::Recovery::new(
      learner,
      0x1234,
      crate::Epoch::new(0),
      0,
    )),
  );
  let out = e
    .poll_message()
    .expect("the primary answers a learner's Recovery");
  assert_eq!(
    out.to(),
    Recipient::To(Peer::Replica(learner)),
    "the RecoveryResponse is addressed back to the learner requester",
  );
  assert!(
    matches!(out.into_msg(), Message::RecoveryResponse(_)),
    "the serve is a RecoveryResponse",
  );
}

#[test]
fn compute_quorum_checkpoint_op_on_a_learner_excludes_its_own_checkpoint() {
  // The GC quorum order statistic is voter-only BY CONSTRUCTION. On a LEARNER self (id 3 of a 3-voter
  // set), its own (possibly high) durable checkpoint must NOT seed the statistic — populating no voter
  // `peer_checkpoint`, the learner computes the conservative floor 0, so a high learner checkpoint
  // cannot lift the GC floor and free an op a voter quorum still needs.
  let mut learner = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(LEARNER as u128)).expect("learner id 3 of a 3-voter set"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
    u64::MAX,
  );
  // Force a HIGH own durable checkpoint (op 9) on the learner.
  learner.force_state_for_test(0, 9, 9, 9, &[]);
  assert_eq!(
    learner.compute_quorum_checkpoint_op(),
    OpNumber::new(),
    "a learner's own checkpoint is excluded from the voter-only quorum statistic — the floor stays 0",
  );
  // The cached value matches the fresh compute (the staleness assert in `quorum_checkpoint_op` holds
  // for a learner — the seed mirror in `recover`/the recompute agree).
  assert_eq!(
    learner.quorum_checkpoint_op(),
    OpNumber::new(),
    "the cached quorum_checkpoint is coherent with the voter-only compute on a learner",
  );

  // Contrast: the SAME high own checkpoint on a VOTER (id 0) in a solo (1-voter) cluster IS the
  // quorum, so it seeds the statistic — proving the exclusion is voter-gated, not unconditional.
  let mut solo_voter = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(0)).expect("solo voter 0 + 2 learners"),
    genesis_with_learners(1, 2),
    0,
    NoopSm,
    u64::MAX,
  );
  solo_voter.force_state_for_test(0, 9, 9, 9, &[]);
  assert_eq!(
    solo_voter.compute_quorum_checkpoint_op(),
    OpNumber::with(9),
    "a voter in a 1-voter set counts its own checkpoint (it IS the quorum)",
  );
}

/// A LEARNER endpoint (self = learner id 3) in a 3-voter (0,1,2) + 2-learner (3,4) cluster. Voter 0 is
/// the primary of view 0; voter 1 is the primary of view 1.
fn learner_self() -> Endpoint<NoopSm> {
  Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(LEARNER as u128)).expect("learner id 3 of a 3-voter set"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
    u64::MAX,
  )
}

#[test]
fn a_learner_never_acks_a_prepare_or_proposes_a_view_change_on_idle() {
  // A learner applies the committed feed but emits NO PrepareOk, and never arms/fires `primary_idle` —
  // so when the primary goes quiet it proposes NO view change. Drive it with a Prepare (which on a voter
  // backup acks) and a Commit (which on a voter backup defers the idle timeout), then advance far past
  // PRIMARY_IDLE and fire timers: nothing is acked, nothing is proposed, and it stays Normal.
  let mut e = learner_self();
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  e.handle_message(now, &mut storage, primary_peer(), prepare(1, 0));
  e.storage_step(now, &mut storage, &mut blocks);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  while let Some(out) = e.poll_message() {
    assert!(
      !matches!(out.into_msg(), Message::PrepareOk(_)),
      "a learner never emits a PrepareOk",
    );
  }
  // `primary_idle` is never armed for a learner, so firing timers far past it (the no-orphan-due assert
  // inside `handle_timeout` must hold) proposes nothing and leaves it Normal.
  let later = now + core::time::Duration::from_millis(10_000);
  e.handle_timeout(later, &mut storage);
  assert_eq!(
    e.status(),
    Status::Normal,
    "a learner stays Normal — it never proposes a view change on idle",
  );
  while let Some(out) = e.poll_message() {
    assert!(
      !matches!(
        out.into_msg(),
        Message::StartViewChange(_) | Message::DoViewChange(_) | Message::PrepareOk(_)
      ),
      "a learner emits no vote/SVC/DVC on idle",
    );
  }
}

#[test]
fn a_quorum_of_voter_svcs_does_not_activate_a_learner() {
  // A learner is not a view-change participant: a full voter StartViewChange quorum delivered to it does
  // NOT transition it to an active view change (`on_start_view_change` early-returns), so `join_svc` —
  // whose `1 << id` would overflow for a high learner id — is never reached and no panic occurs.
  let mut e = learner_self();
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // quorum_view_change for 3 voters is 2: deliver StartViewChange(view 1) from voters 0 and 1.
  let mut storage = Storage::new(wal, sb);
  for v in [0u16, 1] {
    e.handle_message(
      now,
      &mut storage,
      Peer::Replica(ReplicaId::new(v)),
      Message::StartViewChange(StartViewChange::new(
        View::with(1),
        ReplicaId::new(v),
        crate::Epoch::new(0),
        0,
      )),
    );
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "a learner does not enter ViewChange from a voter SVC quorum",
  );
  let later = now + core::time::Duration::from_millis(10_000);
  e.handle_timeout(later, &mut storage);
  assert_eq!(
    e.status(),
    Status::Normal,
    "...and still does not after time advances"
  );
  while let Some(out) = e.poll_message() {
    assert!(
      !matches!(
        out.into_msg(),
        Message::StartViewChange(_) | Message::DoViewChange(_)
      ),
      "a learner emits no SVC/DVC",
    );
  }
}

#[test]
fn a_learner_catch_up_does_not_escalate_to_active_view_change() {
  // A learner that sees a higher view enters catch-up (ViewChange + catching_up, soliciting GetView). It
  // must NEVER escalate to active: `view_change_status` is voter-only, so the catch-up keeps re-soliciting
  // GetView (never flips catching_up to false, never emits SVC/DVC) until it adopts a StartView.
  let mut e = learner_self();
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // A higher-view Commit from view 1's primary (`primary(1) == Replica(1)`) triggers catch_up_to_view(1).
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    e.status().is_view_change() && e.catching_up(),
    "a higher view puts the learner into catch-up",
  );
  let mut saw_get_view = false;
  while let Some(out) = e.poll_message() {
    match out.into_msg() {
      Message::GetView(_) => saw_get_view = true,
      Message::StartViewChange(_) | Message::DoViewChange(_) => {
        panic!("a catching-up learner emits no SVC/DVC")
      }
      _ => {}
    }
  }
  assert!(saw_get_view, "catch-up solicits GetView");
  // Advance well past VIEW_CHANGE_STATUS and fire timers repeatedly — a VOTER would escalate to active here.
  let mut t = now;
  for _ in 0..5 {
    t = t + core::time::Duration::from_millis(600);
    e.handle_timeout(t, &mut storage);
  }
  assert!(
    e.status().is_view_change() && e.catching_up(),
    "the learner is STILL catching up — it never escalated to an active view change",
  );
  let mut still_soliciting = false;
  while let Some(out) = e.poll_message() {
    match out.into_msg() {
      Message::GetView(_) => still_soliciting = true,
      Message::StartViewChange(_) | Message::DoViewChange(_) => {
        panic!("a catching-up learner never escalates to SVC/DVC")
      }
      _ => {}
    }
  }
  assert!(
    still_soliciting,
    "the learner keeps re-soliciting GetView while catching up",
  );
}

#[test]
fn a_learner_recovered_mid_view_change_catches_up_and_never_emits_a_dvc() {
  // A learner can persist a view-ahead-of-log_view durable root (`log_view < view`) exactly like a
  // voter — it adopts a higher view before installing that view's log. A VOTER recovering from this
  // shape RE-DRIVES the view change (casts a DoViewChange). A LEARNER must NOT: it is never a
  // view-change voter or candidate primary, so `complete_recovery` routes it into the CATCH-UP posture
  // (ViewChange + `catching_up`, soliciting GetView) instead, which re-fetches the canonical head and
  // restores `log_view == view` WITHOUT ever emitting a counted message. (Regression: a missing voter
  // gate on the mid-view-change recovery re-drive let a learner enter `enter_view_change_from_recovery`
  // and emit a DoViewChange — a non-voter taking part in consensus.)
  let wal = wal_in_view(2, 0); // ops 1..=2 stamped view 0 (the not-yet-installed log)
  let sb = sb_with_view(1, 0); // durable root: view 1, log_view 0 → log_view < view
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  // self = learner id 3 (slot 3 of a 3-voter set with 2 learners) — a NON-VOTER.
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(LEARNER as u128)).expect("learner id 3 of a 3-voter set"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  for _ in 0..16 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert!(
    r.status().is_view_change() && r.catching_up(),
    "a learner that crashed mid-view-change CATCHES UP (ViewChange + catching_up), it does NOT re-drive",
  );
  assert_eq!(
    r.view(),
    View::with(1),
    "it stays at the durable view and re-fetches THAT view's canonical head (not view+1)",
  );
  // It solicits GetView and emits NO counted message — the load-bearing learner invariant.
  let mut solicited = false;
  while let Some(out) = r.poll_message() {
    match out.into_msg() {
      Message::GetView(_) => solicited = true,
      Message::DoViewChange(_) | Message::StartViewChange(_) | Message::PrepareOk(_) => {
        panic!("a recovering learner must never emit a counted message (DVC/SVC/PrepareOk)")
      }
      _ => {}
    }
  }
  assert!(
    solicited,
    "the learner solicits GetView to re-fetch the canonical head"
  );
}

#[test]
fn a_voter_backup_still_acks_and_proposes_unlike_a_learner() {
  // Positive control: the SAME drive on a VOTER backup (id 1) DOES ack the prepare and DOES propose a
  // view change when the primary goes idle — so the learner exclusions are learner-specific, not a
  // blanket disable of the backup machinery.
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).expect("voter 1 backup + 2 learners"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
    u64::MAX,
  );
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  e.handle_message(now, &mut storage, primary_peer(), prepare(1, 0));
  e.storage_step(now, &mut storage, &mut blocks);
  let mut acked = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.into_msg(), Message::PrepareOk(_)) {
      acked = true;
    }
  }
  assert!(acked, "a voter backup acks a prepare");
  let later = now + core::time::Duration::from_millis(10_000);
  e.handle_timeout(later, &mut storage);
  let mut proposed = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.into_msg(), Message::StartViewChange(_)) {
      proposed = true;
    }
  }
  assert!(
    proposed,
    "a voter backup proposes a view change when the primary goes idle",
  );
}

#[test]
fn a_learner_emits_learner_status_carrying_its_contiguous_applied_frontier_not_commit_max() {
  // A non-voting learner reports its progress on a cadence: drive its timers past LEARNER_STATUS_CADENCE
  // and it emits a single `LearnerStatus` to the primary. `durable_commit_min` carries the learner's
  // CONTIGUOUS APPLIED FRONTIER (`commit_min`) — NOT its durable known-committed frontier (`commit_max`,
  // == `sb.state().commit()`). The two DIFFER for a SPARSE-band recovered learner: it can KNOW a high
  // commit point while a missing / `Repairing` committed op BELOW the head still blocks apply, leaving
  // the applied frontier short of `commit_max`. Reporting `commit_max` would let such a repair-holed
  // learner pass the catch-up-then-promote gate without durably holding the prefix it would vote on; the
  // honest metric is the hole-free applied frontier.
  let mut e = learner_self();
  // Model the sparse band on the learner: head op 6, `commit_max == 6` (it KNOWS ops 1..=6 committed),
  // but a repair hole at op 4 holds the contiguous applied frontier at `commit_min == 3`. `repair=[4,6]`
  // makes `force_state_for_test` lift `commit_max` to 6 (= the head it knows committed) while the holes
  // 4,6 are exactly the committed ops it does NOT durably hold.
  e.force_state_for_test(0, 6, 3, 0, &[4, 6]);
  // The durable root ALSO vouches `commit_max == 6` (a recovered sparse-band learner persists the
  // known-committed frontier) — so a reverted emitter reading `sb.state().commit()` would report 6.
  let durable_root = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(6),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
  )
  .expect("a valid durable root");
  let sb = TestSb {
    state: durable_root,
    ..Default::default()
  };
  let wal = TestWal {
    head: 6,
    ..Default::default()
  };

  let now = Instant::ZERO;
  // Bootstrap the cadence (the first `handle_timeout` arms it), then advance past it and fire.
  let mut storage = Storage::new(wal, sb);
  e.handle_timeout(now, &mut storage);
  let later = now + core::time::Duration::from_millis(10_000);
  e.handle_timeout(later, &mut storage);

  let mut reports = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::LearnerStatus(ls) = out.msg_ref() {
      // It is addressed to the primary of the current view (voter 0 leads view 0).
      assert_eq!(
        out.to(),
        crate::Recipient::To(Peer::Replica(ReplicaId::new(0))),
        "the learner reports to the current primary",
      );
      reports.push(*ls);
    }
  }
  assert_eq!(
    reports.len(),
    1,
    "exactly one LearnerStatus per cadence tick"
  );
  let ls = reports[0];
  assert_eq!(
    ls.replica(),
    ReplicaId::new(LEARNER),
    "self-identified by the learner's slot"
  );
  // The load-bearing assertion: the report carries the CONTIGUOUS APPLIED FRONTIER (`commit_min` == 3),
  // NOT `commit_max` (6). Reverting the emitter to `storage.sb_mut().state().commit()` reports 6 and fails here.
  assert_eq!(
    ls.durable_commit_min(),
    OpNumber::with(3),
    "reports the contiguous applied frontier (commit_min == 3), NOT commit_max (6) past the hole at 4",
  );
  assert_eq!(
    ls.durable_op(),
    OpNumber::with(6),
    "reports the DURABLE WAL head (6)",
  );
  assert_eq!(ls.epoch(), crate::Epoch::new(0), "the current epoch");
  assert_eq!(ls.config_id(), 0, "the current config_id");
}

#[test]
fn a_voter_never_emits_learner_status() {
  // The progress report is learner-specific: a VOTING backup participates directly (its votes carry its
  // frontier), so it never arms or fires the learner-status cadence. The same drive on a voter emits NO
  // `LearnerStatus`.
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).expect("voter 1 backup + 2 learners"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
    u64::MAX,
  );
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  e.handle_timeout(now, &mut storage);
  let later = now + core::time::Duration::from_millis(10_000);
  e.handle_timeout(later, &mut storage);
  while let Some(out) = e.poll_message() {
    assert!(
      !matches!(out.into_msg(), Message::LearnerStatus(_)),
      "a voter never emits a learner progress report",
    );
  }
}

#[test]
fn learner_status_is_admitted_only_from_a_member_under_strict_epoch_config() {
  // Ingress: a `LearnerStatus` is admitted (`sender_matches` + `epoch_authority_admits`) ONLY from a
  // current configuration MEMBER under an exact `(epoch, config_id)`. A non-member sender, or a
  // foreign epoch/config, is rejected — it carries config-scoped progress this primary must not record.
  let e = voter_with_learners(); // self = voter 0 (the primary), 3 voters + 2 learners
  let learner = ReplicaId::new(LEARNER);

  // From the learner member (slot 3), matching `from`, under the genesis epoch/config: ADMITTED.
  let ok = Message::LearnerStatus(crate::LearnerStatus::new(
    learner,
    OpNumber::with(2),
    OpNumber::with(2),
    crate::Epoch::new(0),
    0,
  ));
  assert!(
    e.sender_matches(Peer::Replica(learner), &ok),
    "a member sender at the claimed slot is bound",
  );
  assert!(
    e.epoch_authority_admits(&ok),
    "an exact (epoch, config_id) match is admitted",
  );

  // A self-consistent report from a NON-MEMBER id (slot 9, out of a 5-node cluster) is rejected by the
  // sender binding (it is not a configured member).
  let non_member = ReplicaId::new(9);
  let forged = Message::LearnerStatus(crate::LearnerStatus::new(
    non_member,
    OpNumber::with(2),
    OpNumber::with(2),
    crate::Epoch::new(0),
    0,
  ));
  assert!(
    !e.sender_matches(Peer::Replica(non_member), &forged),
    "a non-member sender is rejected — its progress is never recorded",
  );

  // A FOREIGN-epoch report (epoch 1 ≠ this config's epoch 0) is rejected by the strict authority gate.
  let foreign = Message::LearnerStatus(crate::LearnerStatus::new(
    learner,
    OpNumber::with(2),
    OpNumber::with(2),
    crate::Epoch::new(1),
    0,
  ));
  assert!(
    !e.epoch_authority_admits(&foreign),
    "a foreign-epoch progress report is not this configuration's to act on",
  );
}

#[test]
fn a_learner_answers_a_proof_challenge_with_its_fresh_contiguous_applied_frontier() {
  // The learner side of the promote-proof round-trip: a `RequestLearnerProof` from the primary (a
  // current member) is answered with a `LearnerProof` carrying this node's CONTIGUOUS APPLIED FRONTIER
  // (`commit()` == `commit_min`) RECOMPUTED FROM DURABLE STATE NOW — NOT a remembered high-water. The
  // reply self-identifies by the learner's slot, echoes the challenge nonce, and carries the live
  // (epoch, config_id). The frontier is read fresh: a just-regressed learner answers with its lower
  // frontier.
  let mut e = learner_self(); // self = learner slot 3, 3 voters + 2 learners, voter 0 = primary
  let (wal, sb) = (TestWal::default(), TestSb::default());
  // Model a learner whose head/commit_max cover op 5 but whose contiguous applied frontier is 2 (a
  // repair hole at op 3 holds apply) — `commit()` returns the hole-free frontier (2), not the head.
  e.force_state_for_test(0, 5, 2, 0, &[3, 5]);
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "the fresh contiguous applied frontier is 2"
  );

  // The primary (voter 0) challenges the learner to prove it holds the prefix through op 5.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    Instant::ZERO,
    &mut storage,
    primary_peer(),
    Message::RequestLearnerProof(crate::RequestLearnerProof::new(
      ReplicaId::new(0), // the soliciting primary's slot
      OpNumber::with(5), // prove the prefix through op 5
      0xBEEF,
      crate::Epoch::new(0),
      0,
    )),
  );

  // Exactly one LearnerProof is emitted, addressed to the soliciting primary, carrying the FRESH
  // frontier (2 — below the challenged head 5, the honest answer), the learner's slot, and the echoed
  // nonce + live config.
  let mut replies = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::LearnerProof(p) = out.msg_ref() {
      assert_eq!(
        out.to(),
        crate::Recipient::To(Peer::Replica(ReplicaId::new(0))),
        "the proof is addressed to the soliciting primary",
      );
      replies.push(*p);
    }
  }
  assert_eq!(replies.len(), 1, "exactly one LearnerProof per challenge");
  let proof = replies[0];
  assert_eq!(
    proof.replica(),
    ReplicaId::new(LEARNER),
    "the proof self-identifies by the learner's slot",
  );
  assert_eq!(proof.nonce(), 0xBEEF, "the challenge nonce is echoed");
  assert_eq!(
    proof.frontier(),
    OpNumber::with(2),
    "the proof carries the FRESH contiguous applied frontier (commit_min == 2), NOT the challenged head",
  );
  assert_eq!(proof.epoch(), crate::Epoch::new(0), "the live epoch");
  assert_eq!(proof.config_id(), 0, "the live config_id");
}

#[test]
fn a_learner_drops_a_cross_epoch_proof_challenge() {
  // The learner answers ONLY for its live configuration: a `RequestLearnerProof` carrying a foreign
  // epoch is dropped (no reply). The ingress `epoch_authority_admits` STRICT gate already rejects it,
  // and the handler re-checks — so a stale-config challenge can never elicit a proof that a later mint
  // under that stale config could consume.
  let mut e = learner_self();
  let (wal, sb) = (TestWal::default(), TestSb::default());
  e.force_state_for_test(0, 5, 5, 0, &[]);

  // A foreign-epoch challenge (epoch 1 ≠ this config's epoch 0).
  let foreign = Message::RequestLearnerProof(crate::RequestLearnerProof::new(
    ReplicaId::new(0),
    OpNumber::with(5),
    0xBEEF,
    crate::Epoch::new(1),
    0,
  ));
  assert!(
    !e.epoch_authority_admits(&foreign),
    "a cross-epoch challenge is inadmissible at ingress",
  );
  let mut storage = Storage::new(wal, sb);
  e.handle_message(Instant::ZERO, &mut storage, primary_peer(), foreign);
  assert!(
    !core::iter::from_fn(|| e.poll_message())
      .any(|out| matches!(out.into_msg(), Message::LearnerProof(_))),
    "a cross-epoch challenge elicits no proof reply",
  );
}

#[test]
fn proof_challenge_and_reply_bind_to_a_member_under_strict_epoch_config() {
  // Ingress binding for both new messages: a `RequestLearnerProof` (the primary's solicitation) and a
  // `LearnerProof` (the learner's reply) are each admitted (`sender_matches` + `epoch_authority_admits`)
  // ONLY from a current configuration MEMBER under an exact `(epoch, config_id)`. A non-member sender or
  // a foreign epoch/config is rejected — both gate a reconfiguration and so are STRICT, config-scoped.
  let e = voter_with_learners(); // self = voter 0 (the primary)
  let primary = ReplicaId::new(0);
  let learner = ReplicaId::new(LEARNER);

  // A challenge self-claiming the primary's slot, from the matching peer, under the genesis config.
  let challenge = Message::RequestLearnerProof(crate::RequestLearnerProof::new(
    primary,
    OpNumber::with(2),
    7,
    crate::Epoch::new(0),
    0,
  ));
  assert!(
    e.sender_matches(Peer::Replica(primary), &challenge),
    "a member sender is bound"
  );
  assert!(
    e.epoch_authority_admits(&challenge),
    "an exact (epoch, config_id) match is admitted"
  );

  // A reply self-claiming the learner's slot, from the matching peer, under the genesis config.
  let reply = Message::LearnerProof(crate::LearnerProof::new(
    learner,
    7,
    OpNumber::with(2),
    crate::Epoch::new(0),
    0,
  ));
  assert!(
    e.sender_matches(Peer::Replica(learner), &reply),
    "a member sender is bound"
  );
  assert!(
    e.epoch_authority_admits(&reply),
    "an exact (epoch, config_id) match is admitted"
  );

  // A reply from a NON-MEMBER id (slot 9 of a 5-node cluster) is rejected by the sender binding.
  let non_member = ReplicaId::new(9);
  let forged = Message::LearnerProof(crate::LearnerProof::new(
    non_member,
    7,
    OpNumber::with(2),
    crate::Epoch::new(0),
    0,
  ));
  assert!(
    !e.sender_matches(Peer::Replica(non_member), &forged),
    "a non-member proof sender is rejected",
  );

  // A FOREIGN-epoch challenge + reply are rejected by the strict authority gate.
  let foreign_challenge = Message::RequestLearnerProof(crate::RequestLearnerProof::new(
    primary,
    OpNumber::with(2),
    7,
    crate::Epoch::new(1),
    0,
  ));
  let foreign_reply = Message::LearnerProof(crate::LearnerProof::new(
    learner,
    7,
    OpNumber::with(2),
    crate::Epoch::new(1),
    0,
  ));
  assert!(
    !e.epoch_authority_admits(&foreign_challenge),
    "a foreign-epoch challenge is not admitted"
  );
  assert!(
    !e.epoch_authority_admits(&foreign_reply),
    "a foreign-epoch reply is not admitted"
  );

  // Neither advertises an authoritative/participatory view — both are config-scoped, no-vote messages.
  assert!(
    !challenge.advertises_authoritative_view(),
    "the challenge claims no participatory view"
  );
  assert!(
    !reply.advertises_authoritative_view(),
    "the reply claims no participatory view"
  );
}

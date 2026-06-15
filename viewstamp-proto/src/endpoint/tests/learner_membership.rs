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
  Endpoint::new(
    Config::try_new(1, MemberId::new(0)).expect("valid 3-voter + 2-learner config"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
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
    Message::RequestSyncChunk(crate::RequestSyncChunk::new(
      v,
      OpNumber::with(4),
      0xab,
      0,
      0,
      learner,
      7,
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
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).expect("voter 1 of 3 + 2 learners"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Hold ops 1 + 2 (apply 1 via the piggybacked commit), discard the resulting acks.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}

  let learner = ReplicaId::new(LEARNER);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).expect("voter 0 (primary of view 0) + 2 learners"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  assert!(e.is_primary(), "voter 0 is the primary of view 0");
  let learner = ReplicaId::new(LEARNER);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
  let mut learner = Endpoint::new(
    Config::try_new(1, MemberId::new(LEARNER as u128)).expect("learner id 3 of a 3-voter set"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
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
  let mut solo_voter = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).expect("solo voter 0 + 2 learners"),
    genesis_with_learners(1, 2),
    0,
    NoopSm,
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
  Endpoint::new(
    Config::try_new(1, MemberId::new(LEARNER as u128)).expect("learner id 3 of a 3-voter set"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
  )
}

#[test]
fn a_learner_never_acks_a_prepare_or_proposes_a_view_change_on_idle() {
  // A learner applies the committed feed but emits NO PrepareOk, and never arms/fires `primary_idle` —
  // so when the primary goes quiet it proposes NO view change. Drive it with a Prepare (which on a voter
  // backup acks) and a Commit (which on a voter backup defers the idle timeout), then advance far past
  // PRIMARY_IDLE and fire timers: nothing is acked, nothing is proposed, and it stays Normal.
  let mut e = learner_self();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
  e.handle_timeout(later, &mut wal, &mut sb);
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
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // quorum_view_change for 3 voters is 2: deliver StartViewChange(view 1) from voters 0 and 1.
  for v in [0u16, 1] {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
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
  e.handle_timeout(later, &mut wal, &mut sb);
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
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // A higher-view Commit from view 1's primary (`primary(1) == Replica(1)`) triggers catch_up_to_view(1).
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
    e.handle_timeout(t, &mut wal, &mut sb);
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
fn a_voter_backup_still_acks_and_proposes_unlike_a_learner() {
  // Positive control: the SAME drive on a VOTER backup (id 1) DOES ack the prepare and DOES propose a
  // view change when the primary goes idle — so the learner exclusions are learner-specific, not a
  // blanket disable of the backup machinery.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).expect("voter 1 backup + 2 learners"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  let mut acked = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.into_msg(), Message::PrepareOk(_)) {
      acked = true;
    }
  }
  assert!(acked, "a voter backup acks a prepare");
  let later = now + core::time::Duration::from_millis(10_000);
  e.handle_timeout(later, &mut wal, &mut sb);
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

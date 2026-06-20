use super::*;
use crate::{
  ClientId, Config, DoViewChange, OpNumber, ReplicaId, Request, RequestNumber, StartViewChange,
  View,
};

#[test]
fn forged_prepare_ok_from_a_different_sender_is_dropped() {
  // A primary (replica 0 of 3, quorum 2) is collecting votes on op 1. Its own append is the first
  // vote; a SECOND vote from a DISTINCT replica would reach quorum and commit. Deliver a PrepareOk
  // whose BODY claims replica 2 but whose authenticated `from` is replica 1 — a forged/misrouted
  // vote. It must NOT count toward the quorum: commit stays at 0 (only the primary's own vote stands).
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    EchoSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // The primary assigns op 1 to a client request and durably appends it (its OWN vote: bit 0).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"a"),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // own append durable → own vote recorded
  assert_eq!(e.op(), OpNumber::with(1));
  assert_eq!(
    e.commit(),
    OpNumber::new(),
    "own vote alone is below quorum"
  );

  // The FORGED vote: body claims replica 2, but the authenticated sender is replica 1.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)), // authenticated sender
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(2),
      OpNumber::new(),
      crate::storage::fnv1a_128(b"a"),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.commit(),
    OpNumber::new(),
    "a PrepareOk whose claimed replica != authenticated `from` must not be counted: commit stays 0",
  );

  // Positive control: an HONEST PrepareOk (claimed replica == `from`) DOES count → quorum → commit.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::new(),
      crate::storage::prepare_identity(
        ClientId::new(7),
        RequestNumber::with(1),
        crate::storage::fnv1a_128(b"a"),
      ),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "an honest PrepareOk (claim matches `from`) is processed → quorum → op 1 commits",
  );
}

#[test]
fn forged_do_view_change_from_a_different_sender_is_dropped() {
  // Replica 1 is the primary of view 1 (1 % 3). Drive it into ViewChange(1) via an SVC quorum, then
  // deliver a DoViewChange whose BODY claims replica 2 but whose authenticated `from` is replica 0.
  // With its own DVC, ONE more genuine DVC reaches the view-change quorum (2) and it becomes primary;
  // the forged DVC must NOT contribute, so it stays in ViewChange (does not become a serving primary).
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Idle → propose SVC(view 1); a peer SVC completes the SVC quorum → enter ViewChange(1).
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
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  assert!(!e.is_primary() || e.pending_sb_for_test()); // not yet a serving primary
  while e.poll_message().is_some() {}

  // The FORGED DVC: body claims replica 2, but the authenticated sender is replica 0.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)), // authenticated sender
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(2),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![],
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "a forged DVC (claim != `from`) must not contribute to the view-change quorum: still ViewChange",
  );

  // Positive control: an HONEST DVC (claim == `from`) DOES count → quorum → it forms the new view.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(2),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![],
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // durable-view write lands → it serves as primary
  assert_eq!(e.view(), View::with(1));
  assert!(
    e.is_primary() && e.status().is_normal() && !e.pending_sb_for_test(),
    "an honest DVC completes the quorum → replica 1 becomes the serving primary of view 1",
  );
}

#[test]
fn forged_start_view_change_from_a_different_sender_is_dropped() {
  // A backup (replica 0 of 3) is collecting StartViewChanges for view 1 (view-change quorum 2). Once
  // it adopts the target it counts its OWN bit, so ONE genuine peer SVC reaches quorum and it
  // transitions to ViewChange. A SVC whose BODY claims replica 1 but whose authenticated `from` is
  // replica 2 is forged: it must NOT contribute, so the backup does not reach the SVC quorum.
  let mut e = backup(); // replica 1 of 3 — a backup of view 0
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  assert_eq!(e.status(), Status::Normal);

  // The FORGED SVC: body claims replica 0, but the authenticated sender is replica 2.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)), // authenticated sender
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )), // claims R0
  );
  assert_eq!(
    e.status(),
    Status::Normal,
    "a forged SVC (claim != `from`) must not be counted; the backup does not enter a view change",
  );

  // Positive control: an HONEST SVC (claim == `from`) IS counted; with this backup's own bit that is
  // the view-change quorum (2 of 3) → it transitions to ViewChange.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0,
    )), // matches `from`
  );
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "an honest SVC completes the view-change quorum (own bit + R2) → the backup enters ViewChange",
  );
}

#[test]
fn forged_commit_from_a_non_primary_is_dropped_by_the_sender_binding() {
  // A bonus primary-authority binding: a `Commit` heartbeat legitimately comes ONLY from the primary
  // of its advertised view (it carries no self id, so it binds to `config.primary(view)`). First seed
  // the backup with op 1 (a genuine Prepare from the real primary), so a forged Commit advancing the
  // commit would have an op to apply. A `Commit(view 0, commit 1)` whose authenticated `from` is a
  // NON-primary (replica 2; the view-0 primary is replica 0) is forged/misrouted and must be dropped
  // — the backup's commit does not advance. The honest Commit path (from the real primary) is
  // unaffected. (`Prepare` binds to `config.primary(view)` OR a registered repair hole —
  // so the normal head-advancing path is primary-bound while the non-primary repair-serve still
  // works; see `sender_matches` and the `forged_prepare_from_a_non_primary_replica_is_dropped` test.)
  let mut e = backup(); // replica 1 of 3
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // The real primary (replica 0) prepares op 1; the backup appends + acks it.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.op(), OpNumber::with(1));
  assert_eq!(e.commit(), OpNumber::new());
  while e.poll_message().is_some() {}

  // Forged: a Commit for view 0 advancing commit to 1, but `from` is replica 2 (NOT the primary).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)), // not the primary of view 0
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::new(),
    "a Commit from a non-primary `from` is dropped: the backup's commit does not advance",
  );
  // Positive control: the SAME Commit from the REAL primary (replica 0) advances the commit.
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
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the identical Commit from the genuine primary advances the backup's commit to 1",
  );
}

#[test]
fn forged_prepare_from_a_client_is_dropped_by_the_sender_binding() {
  // `Prepare` binds to `config.primary(view)` OR a registered repair hole. A client
  // `from` is neither the primary nor a replica serving a hole, so a `Prepare` whose authenticated
  // `from` is a `Peer::Client` is forged/misrouted and must be dropped — the backup does not append it.
  // The honest primary-originated `Prepare` is unaffected.
  let mut e = backup(); // replica 1 of 3
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Forged: a Prepare for op 1, but `from` is a client (not a replica).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    prepare(1, 0),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.op(),
    OpNumber::new(),
    "a Prepare from a client `from` is dropped: the backup does not append it",
  );
  // Positive control: the identical Prepare from the genuine primary IS appended.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the identical Prepare from the genuine primary is appended",
  );
}

#[test]
fn forged_prepare_from_a_non_primary_replica_is_dropped() {
  // the head-advancing / normal `Prepare` path must accept a Prepare ONLY from the
  // primary of its advertised view. A current-view `Prepare` from a NON-primary replica (replica 2;
  // the view-0 primary is replica 0) whose op is NOT one of our registered repair holes is
  // forged/misrouted — `sender_matches` drops it, so the backup does NOT append it and emits NO
  // PrepareOk (which the primary would otherwise count toward a commit quorum). The legitimate
  // non-primary repair-serve path (a Prepare for a registered hole) is unaffected (it is gated on
  // `self.repair.contains(op)`, exercised by the peer-repair tests).
  let mut e = backup(); // replica 1 of 3
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Forged: a current-view (view 0) Prepare for op 1 from replica 2 (NOT the view-0 primary), op 1
  // is not a repair hole.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    prepare(1, 0),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.op(),
    OpNumber::new(),
    "a normal Prepare from a non-primary `from` is dropped: the backup does not append it",
  );
  assert!(
    e.poll_message().is_none(),
    "the dropped Prepare emits no PrepareOk (no forged vote reaches the primary's quorum)",
  );
  // Positive control: the identical Prepare from the genuine primary (replica 0) IS appended + acked.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the identical Prepare from the genuine primary is appended",
  );
}

#[test]
fn forged_prepare_batch_from_a_non_primary_is_dropped_by_the_sender_binding() {
  // `PrepareBatch` is the primary's batched retransmit of its un-acked window — it carries no self
  // `replica()` and (unlike `Prepare`) has NO repair-serve role, so it binds STRICTLY to
  // `config.primary(view)` like `Commit`/`StartView`. A batch from a non-primary replica (replica 2;
  // the view-0 primary is replica 0) — or from a client — is forged/misrouted and must be dropped
  // WHOLE: no entry reaches `on_prepare`, so the backup appends nothing and emits no PrepareOk
  // (which the primary would otherwise count toward a commit quorum).
  let mut e = backup(); // replica 1 of 3
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let batch = || {
    Message::PrepareBatch(crate::PrepareBatch::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        Bytes::copy_from_slice(&[1u8]),
      )],
    ))
  };
  // Forged: the batch from replica 2 (NOT the view-0 primary), then from a client.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    batch(),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    batch(),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.op(),
    OpNumber::new(),
    "a PrepareBatch from a non-primary `from` is dropped whole: nothing appended",
  );
  assert!(
    e.poll_message().is_none(),
    "the dropped batch emits no PrepareOk (no forged vote reaches the primary's quorum)",
  );
  // Positive control: the identical batch from the genuine primary (replica 0) is appended + acked.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), batch());
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the identical PrepareBatch from the genuine primary is appended",
  );
}

#[test]
fn out_of_range_prepare_ok_is_not_counted_toward_quorum() {
  // MEMBERSHIP RANGE CHECK (vote surface): a PrepareOk whose self-claimed replica is NOT
  // a configured cluster member (replica 5 in a 3-replica cluster) — delivered from a matching
  // out-of-range `from` by a buggy/misrouting driver — must NOT count toward the commit quorum. The
  // centralized `sender_is_member_replica` check drops it at ingress.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    EchoSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // The primary assigns op 1 and durably appends it (its own vote: bit 0).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"a"),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.commit(),
    OpNumber::new(),
    "own vote alone is below quorum"
  );
  // Out-of-range vote: body claims replica 5 (>= replica_count 3), from is the matching Replica(5).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(5)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(5),
      OpNumber::new(),
      crate::storage::fnv1a_128(b"a"),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.commit(),
    OpNumber::new(),
    "an out-of-range (non-member) PrepareOk does not count toward the quorum",
  );
  // Positive control: a genuine in-member vote from replica 1 reaches quorum 2 and commits op 1.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::new(),
      crate::storage::prepare_identity(
        ClientId::new(7),
        RequestNumber::with(1),
        crate::storage::fnv1a_128(b"a"),
      ),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "a genuine in-member second vote reaches quorum and commits",
  );
}

#[test]
fn out_of_range_sync_checkpoint_is_dropped_by_the_membership_check() {
  // MEMBERSHIP RANGE CHECK (apply surface): a SyncCheckpoint whose self-claimed replica
  // is NOT a configured member (replica 5 in a 3-replica cluster), even with a matching nonce and a
  // self-consistent checkpoint hash, must NOT reach apply_sync — that would restore SM/session state
  // from a non-member. The centralized membership check drops it at ingress; the sync stays outstanding.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  // Trigger sync (Commit advertising checkpoint_op=4); capture the nonce.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // Out-of-range SyncCheckpoint: claims replica 5, from the matching Replica(5), valid nonce/id/env.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(5)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(5), // non-member self-claim
      nonce,
      env.clone(),
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::new(),
    "an out-of-range (non-member) SyncCheckpoint is dropped: the sync is not applied",
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    0,
    "the non-member snapshot was NOT restored into the SM",
  );
  // Positive control: the identical SyncCheckpoint from the genuine member (replica 0) applies.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env.clone(),
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the identical SyncCheckpoint from a genuine member applies",
  );
}

#[test]
fn repair_hole_prepare_from_a_client_is_dropped() {
  // REPAIR-HOLE INGRESS GUARD (Part A): the `Prepare` ingress escape for a registered repair hole must require a
  // CONFIGURED replica `from` — the committed-op repair-serve legitimately comes ONLY from a peer
  // replica that holds the op, never a client. Without that guard, an authenticated `Peer::Client`
  // whose (forged/misrouted) `Prepare`'s op happens to be one of our holes passed `sender_matches`
  // (the bare `self.repair.contains(op)` escape) and reached `fill_repair`, which only checks
  // `commit >= op` + `Header::verify` self-consistency before any role check — so a buggy/misrouting
  // driver could fill a committed hole from a NON-replica peer. The hole must stay open.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  while r.poll_message().is_some() {} // discard the recovery solicitation
  let now = Instant::ZERO;
  // Learn commit up to 3 → applies op 1, registers + holds at the op-2 hole.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(r.has_repair_hole_for_test(2), "the op-2 hole is registered");
  assert_eq!(r.commit(), OpNumber::with(1), "held at the hole");
  while r.poll_message().is_some() {} // discard the repair solicitation

  // A committed-vouching repair Prepare for op 2 (`commit = 2` >= op 2) whose `from` is a CLIENT.
  // The body/placement/commit-vouch all PASS — only the new replica-peer escape drops it.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    repair_prepare(0, 2, 2),
  );
  r.handle_storage(now, &mut wal, &mut sb); // pump: no RepairFill should have been staged
  assert!(
    r.has_repair_hole_for_test(2),
    "a repair Prepare from a client `from` is dropped: the committed hole stays OPEN",
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "the client `from` repair Prepare did NOT fill the hole: the held commit does not advance",
  );

  // Positive control: the identical repair Prepare from a VALID replica holder (replica 0) fills it.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );
  r.handle_storage(now, &mut wal, &mut sb); // the repaired append completes → clear hole + resume
  assert!(
    !r.has_repair_hole_for_test(2),
    "the same repair Prepare from a valid replica holder DOES fill the hole",
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "the committed value filled the hole → the held commit resumes (ops 2 then 3 apply)",
  );
}

#[test]
fn repair_hole_prepare_from_an_out_of_range_replica_is_dropped() {
  // REPAIR-HOLE INGRESS GUARD (Part A): the `Prepare` repair-hole escape must require an IN-RANGE configured
  // replica `from` (`r < config.replica_count()`). An out-of-range replica id is not a member of the
  // cluster, so a `Prepare` it sends for one of our holes is misrouted/forged and must be dropped at
  // ingress, never reaching `fill_repair`. The hole stays open until a valid holder answers.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  while r.poll_message().is_some() {} // discard the recovery solicitation
  let now = Instant::ZERO;
  // Learn commit up to 3 → applies op 1, registers + holds at the op-2 hole.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(r.has_repair_hole_for_test(2), "the op-2 hole is registered");
  assert_eq!(r.commit(), OpNumber::with(1), "held at the hole");
  while r.poll_message().is_some() {} // discard the repair solicitation

  // A committed-vouching repair Prepare for op 2 from an OUT-OF-RANGE replica (id 5; the cluster has
  // replicas 0..3). Body/placement/commit-vouch all PASS — only the in-range replica escape drops it.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(5)),
    repair_prepare(0, 2, 2),
  );
  r.handle_storage(now, &mut wal, &mut sb); // pump: no RepairFill should have been staged
  assert!(
    r.has_repair_hole_for_test(2),
    "a repair Prepare from an out-of-range replica `from` is dropped: the hole stays OPEN",
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "the out-of-range `from` repair Prepare did NOT fill the hole: the held commit does not advance",
  );

  // Positive control: the identical repair Prepare from an IN-RANGE replica holder (replica 0) fills it.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );
  r.handle_storage(now, &mut wal, &mut sb);
  assert!(
    !r.has_repair_hole_for_test(2),
    "the same repair Prepare from an in-range replica holder DOES fill the hole",
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "the held commit resumes once a valid holder fills it"
  );
}

#[test]
fn higher_view_non_canonical_hole_prepare_does_not_trigger_catch_up() {
  // REPAIR-HOLE INGRESS GUARD (Part B): a registered repair hole is owned EXCLUSIVELY by the repair path. A
  // hole-targeted `Prepare` that `fill_repair` DECLINES (here `commit < op`, an uncommitted old-view
  // body) is NOT the canonical fill — it must be dropped IMMEDIATELY, before the higher-view
  // `catch_up_to_view`. Otherwise a higher-view non-canonical hole Prepare (which still passes the
  // repair-hole ingress escape) would yank the replica into a spurious view change off a body it
  // explicitly rejected. The replica must stay in its current view/status and keep the hole open.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  while r.poll_message().is_some() {} // discard the recovery solicitation
  let now = Instant::ZERO;
  // Learn commit up to 3 → applies op 1, registers + holds at the op-2 hole. (View stays 0.)
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(r.has_repair_hole_for_test(2), "the op-2 hole is registered");
  assert_eq!(r.status(), Status::Normal, "starts Normal");
  assert_eq!(r.view(), View::new(), "starts at view 0");
  while r.poll_message().is_some() {} // discard the repair solicitation

  // A HIGHER-view (view 1) Prepare for the hole op 2 carrying `commit = 1` (< op 2): `fill_repair`
  // DECLINES it (the commit-vouch guard). Its op IS a registered hole, so it passes the ingress
  // escape (from a configured replica). Pre-fix this fell through to `p.view() > self.view` →
  // `catch_up_to_view(1)`.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(1, 2, 1),
  );
  assert_eq!(
    r.status(),
    Status::Normal,
    "a declined hole Prepare must NOT trigger a view catch-up: status stays Normal",
  );
  assert_eq!(
    r.view(),
    View::new(),
    "a declined hole Prepare must NOT change the view: still view 0 (no spurious catch-up)",
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "the hole stays registered — a rejected non-canonical Prepare does not consume it",
  );
  assert!(
    r.poll_message().is_none(),
    "no GetView (catch-up probe) is emitted for the dropped hole Prepare",
  );
}

// --- Item 1: `advance_checkpoint_op` is a MONOTONE chokepoint (non-vacuity). ---

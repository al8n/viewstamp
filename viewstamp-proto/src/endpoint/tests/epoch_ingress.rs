//! The (epoch, config_id) AUTHORITY ingress gate (`epoch_authority_admits` + the `on_prepare`
//! normal-arm epoch branch). A STRICT message (a vote/lead driver) contributes to append/vote/
//! view-adoption ONLY on an exact `(epoch, config_id)` match; an AGNOSTIC serve/solicitation is
//! admitted iff its `config_id` is in lineage (same config in PR1). The fixtures carry `config_id = 0`
//! (see the `genesis` helper), so a same-config message uses `(Epoch::new(0), 0)`.

use super::*;
use crate::{
  ClientId, Commit, Config, Epoch, EpochAhead, OpNumber, Prepare, PrepareOk, ReplicaId, Request,
  RequestNumber, StartViewChange, View,
};

/// A `config_id` that is NOT in the fixture lineage (the fixtures carry `config_id = 0`).
const FOREIGN_CONFIG_ID: u128 = 0xDEAD_BEEF;
/// An epoch that is NOT the fixture epoch (the fixtures carry `Epoch::new(0)`).
const FOREIGN_EPOCH: u64 = 7;

#[test]
fn foreign_epoch_prepare_ok_does_not_count_toward_the_vote_quorum() {
  // (a) A primary (replica 0 of 3, quorum 2) is accumulating votes on op 1; its own append is the
  // first vote. A SECOND, otherwise-honest vote whose `epoch` is 7 (not the primary's epoch 0) must
  // contribute NOTHING — it is a vote from a different configuration, so it cannot reach the quorum
  // bitset: commit stays at 0.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    EchoSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"a"),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // own append durable → own vote (bit 0)
  assert_eq!(e.op(), OpNumber::with(1));
  assert_eq!(
    e.commit(),
    OpNumber::new(),
    "own vote alone is below quorum"
  );

  // The foreign-EPOCH vote: claimed replica 1 from the authenticated replica 1 (sender-binding OK),
  // but `epoch = 7`. The strict gate drops it for authority — it never reaches the vote map.
  let honest_checksum = crate::storage::prepare_identity(
    ClientId::new(7),
    RequestNumber::with(1),
    crate::storage::fnv1a_128(b"a"),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::new(),
      honest_checksum,
      Epoch::new(FOREIGN_EPOCH),
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.commit(),
    OpNumber::new(),
    "a foreign-epoch PrepareOk must not count toward the quorum: commit stays 0",
  );

  // Positive control: the SAME vote at the primary's epoch 0 DOES count → quorum (2) → op 1 commits.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::new(),
      honest_checksum,
      Epoch::new(0),
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the same PrepareOk at the matching epoch reaches quorum → op 1 commits",
  );
}

#[test]
fn foreign_config_id_commit_is_not_adopted() {
  // (b) A backup at op 1 / commit 0. A `Commit(view 0, commit 1)` whose `config_id` is foreign must
  // NOT advance the commit — it is authority from a configuration not in our lineage. A same-config
  // Commit then DOES advance it, proving the drop is the config gate and not some other guard.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Hold op 1 (so a commit=1 is appliable).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(1, 0),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.op(), OpNumber::with(1));
  assert_eq!(e.commit(), OpNumber::new());

  // Foreign-config Commit: dropped for authority.
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
      Epoch::new(0),
      FOREIGN_CONFIG_ID,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.commit(),
    OpNumber::new(),
    "a foreign-config_id Commit must not be adopted: commit stays 0",
  );

  // Positive control: the SAME Commit at our config_id 0 advances the commit to 1.
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
      Epoch::new(0),
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the same Commit at the matching config_id is adopted → commit advances to 1",
  );
}

#[test]
fn agnostic_request_prepare_is_admitted_only_in_lineage() {
  // (c, solicitation side) A holder of committed ops answers a peer's `RequestPrepare` (an AGNOSTIC
  // solicitation) with the carrying `Prepare` — but only when the request's `config_id` is in our
  // lineage. A foreign-config_id request draws NO reply; the same request at our config_id 0 does.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(1, 0),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(2, 1),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {} // discard acks

  // Foreign-config_id RequestPrepare for op 1: rejected at the lineage gate — no serve.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(2),
      FOREIGN_CONFIG_ID,
      0,
    )),
  );
  assert!(
    e.poll_message().is_none(),
    "a RequestPrepare with a foreign config_id is rejected — the holder serves nothing",
  );

  // Positive control: the same request at our config_id 0 is admitted → the holder serves the Prepare.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(2),
      0,
      0,
    )),
  );
  match e
    .poll_message()
    .expect("an in-lineage RequestPrepare is served")
    .into_msg()
  {
    Message::Prepare(p) => {
      assert_eq!(p.op(), OpNumber::with(1));
      assert_eq!(p.body(), &[1u8], "carries op 1's real body");
    }
    other => panic!("expected a Prepare serve, got {other:?}"),
  }
}

#[test]
fn agnostic_repair_batch_fills_a_hole_only_in_lineage() {
  // (c, batch side) The windowed repair serve `RepairBatch` is AGNOSTIC. A replica holding a
  // committed-op hole at op 2 must ignore a foreign-config_id batch (the hole stays open) and adopt an
  // in-lineage one (the hole is filled). `RepairBatch` carries `config_id` but no `epoch`, so only the
  // lineage gate applies.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  let mut blocks = crate::block_store::MemBlockStore::new();
  while r.poll_message().is_some() {} // discard the repair solicitation
  // Learn commit up to 3 → applies op 1, then registers the op-2 hole as it tries to cross it. The
  // commit is in-lineage (config_id 0), so the new gate admits it.
  r.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      Epoch::new(0),
      0,
    )),
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "op-2 hole is open before any serve"
  );

  let entry = PreparedEntry::new(
    OpNumber::with(2),
    ClientId::new(7),
    RequestNumber::with(2),
    Bytes::copy_from_slice(&[2u8]),
  );

  // Foreign-config_id batch from a member peer (sender-binding OK): rejected at the lineage gate, so
  // `on_repair_batch` never runs and the hole stays open.
  r.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::RepairBatch(crate::RepairBatch::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::new(),
      FOREIGN_CONFIG_ID,
      std::vec![entry.clone()],
    )),
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "a foreign-config_id RepairBatch is rejected — the op-2 hole stays open",
  );

  // Positive control: an in-lineage batch (config_id 0) is admitted → `fill_repair` stages the fill,
  // and the hole is closed.
  r.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::RepairBatch(crate::RepairBatch::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::new(),
      0,
      std::vec![entry],
    )),
  );
  r.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks);
  assert!(
    !r.has_repair_hole_for_test(2),
    "an in-lineage RepairBatch is admitted → the op-2 hole is filled",
  );
}

#[test]
fn same_config_prepare_happy_path_still_appends_and_acks() {
  // (d) The same-config (epoch 0, config_id 0) happy path must still work end-to-end through the gate:
  // a backup admits the primary's `Prepare`, appends it, and emits a `PrepareOk` — the STRICT
  // normal-arm path under a matching `(epoch, config_id)`.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // `prepare(1, 0)` carries `Epoch::new(0)` + config_id 0 (the fixture lineage).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(1, 0),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the same-config Prepare is appended"
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // pump WAL → PrepareOk
  match e
    .poll_message()
    .expect("a PrepareOk is emitted for the admitted Prepare")
    .into_msg()
  {
    Message::PrepareOk(ok) => {
      assert_eq!(ok.op(), OpNumber::with(1));
      assert_eq!(ok.replica(), ReplicaId::new(1));
      assert_eq!(ok.epoch(), Epoch::new(0), "the ack carries our own epoch");
    }
    other => panic!("expected a PrepareOk, got {other:?}"),
  }
}

/// A recovering replica (replica 1 of 3) AT EPOCH `epoch` with a permanently-faulty op-`faulty_op`
/// read, so it completes recovery to `Normal` holding op-`faulty_op` as a repair hole. Mirrors
/// [`recovering_with_hole`] but seeds the membership at a chosen epoch (so a LOWER foreign epoch can
/// exercise the `on_prepare` arms without tripping the strictly-higher-epoch cross-epoch trigger that
/// runs at the central ingress). `config_id` stays 0 (the fixture lineage), so hand-built messages at
/// config_id 0 are in-lineage.
fn recovering_with_hole_at_epoch(
  head: u64,
  faulty_op: u64,
  epoch: u64,
) -> (Endpoint<CountSm>, ScriptedWal, TestSb) {
  let membership = Membership::from_durable_parts(
    Epoch::new(epoch),
    3,
    0,
    (0..3u128).map(MemberId::new).collect(),
    0,
  )
  .expect("valid genesis membership at the chosen epoch");
  let mut wal = ScriptedWal::with_entries(head);
  wal.script_read_fault(OpNumber::with(faulty_op), u8::MAX);
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    membership,
    0,
    CountSm::default(),
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect_active();
  drive_recovery(&mut r, &mut wal, &mut sb, &mut blocks, now);
  (r, wal, sb)
}

#[test]
fn foreign_epoch_prepare_normal_arm_is_dropped_but_repair_arm_is_agnostic() {
  // The PATH-SENSITIVE split in `on_prepare`: a `Prepare` whose op is one of our registered repair
  // holes is served by the AGNOSTIC repair arm regardless of `epoch` (committed, view-independent
  // content), while a NORMAL head-advancing `Prepare` at a foreign epoch is dropped by the strict
  // normal-arm gate. Both arms are exercised with a LOWER foreign epoch: a STRICTLY-HIGHER epoch would
  // instead trip the cross-epoch catch-up trigger at the central ingress (which routes the replica into
  // the forced peer-fetch BEFORE `on_prepare` runs), so the replica sits at epoch 1 and the foreign
  // serve/head Prepares carry epoch 0.
  //
  // Repair arm (agnostic): a foreign-EPOCH (lower) Prepare for the op-2 hole still fills it — the
  // repair path runs before the normal-arm epoch check.
  let (mut r, mut wal, mut sb) = recovering_with_hole_at_epoch(3, 2, 1);
  let mut blocks = crate::block_store::MemBlockStore::new();
  assert_eq!(
    r.membership.epoch(),
    Epoch::new(1),
    "the recovering replica is at epoch 1"
  );
  while r.poll_message().is_some() {}
  // Register the op-2 hole: an in-lineage Commit(commit=3) at OUR epoch holds at the hole as it tries to
  // cross it (a same-epoch Commit, admitted by the strict arm, drives the commit frontier).
  r.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      Epoch::new(1),
      0,
    )),
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "op-2 hole open before the serve"
  );
  r.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2), // commit >= op: vouches the served op committed
      OpNumber::new(),
      Epoch::new(0), // foreign (lower) epoch — irrelevant to the AGNOSTIC repair arm
      0,             // config_id in lineage (required for both arms)
      ClientId::new(7),
      RequestNumber::with(2),
      Bytes::copy_from_slice(&[2u8]),
    )),
  );
  r.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks);
  assert!(
    !r.has_repair_hole_for_test(2),
    "a foreign-epoch repair-serve Prepare fills the hole — the repair arm is epoch-agnostic",
  );

  // Normal arm (strict): a backup at the head must NOT append a foreign-epoch head-advancing Prepare.
  let (mut e, mut wal2, mut sb2) = recovering_with_hole_at_epoch(3, 2, 1);
  let mut blocks2 = crate::block_store::MemBlockStore::new();
  while e.poll_message().is_some() {}
  let head_before = e.op();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal2,
    &mut sb2,
    &mut blocks2,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::new(),
      OpNumber::new(),
      Epoch::new(0), // foreign (lower) epoch — the strict normal arm drops it
      0,
      ClientId::new(7),
      RequestNumber::with(4),
      Bytes::copy_from_slice(&[4u8]),
    )),
  );
  assert_eq!(
    e.op(),
    head_before,
    "a foreign-epoch head-advancing Prepare is dropped by the strict normal arm: head unchanged",
  );
  // No PrepareOk — the strict normal arm cast no vote. The lower-epoch Prepare DOES elicit a single
  // pre-binding `EpochAhead` hint (the Change #3 egress: this replica is ahead of the sender), so the
  // assertion is precisely "no vote", not "no message".
  let mut saw_prepare_ok = false;
  while let Some(out) = e.poll_message() {
    match out.msg_ref() {
      Message::PrepareOk(_) => saw_prepare_ok = true,
      Message::EpochAhead(h) => {
        assert_eq!(
          h.epoch(),
          Epoch::new(1),
          "the hint carries our higher epoch"
        );
      }
      other => panic!("unexpected message {}", other.kind_str()),
    }
  }
  assert!(
    !saw_prepare_ok,
    "no PrepareOk is emitted for a dropped foreign-epoch Prepare",
  );
}

#[test]
fn a_non_normal_laggard_routes_a_higher_epoch_heartbeat_into_the_recovery_peer_fetch() {
  // A backup stranded in a futile OLD-epoch view-change (it entered an election just as the cluster
  // swapped epochs) cannot state-sync directly (the sync trigger is Normal-gated) and its old-epoch
  // view-change is epoch-inadmissible from the swapped cluster — so a STRICTLY-higher-epoch
  // `Commit`/`Prepare`, dropped at the authority ingress, must route it into the RECOVERY peer-fetch
  // (`awaiting_peer_checkpoint`): it solicits a cross-epoch `SyncCheckpoint` and ends Normal at E+1.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Drive the backup into a ViewChange at the OLD epoch via a higher-view (same-epoch) catch-up.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::with(3),
      OpNumber::new(),
      OpNumber::new(),
      Epoch::new(0),
      0,
    )),
  );
  assert!(
    e.status().is_view_change(),
    "a higher-view Commit catches the backup up into ViewChange"
  );
  assert!(
    !e.awaiting_peer_checkpoint_for_test(),
    "not yet awaiting a peer checkpoint"
  );
  while e.poll_message().is_some() {} // drain the catch-up GetView

  // A strictly-higher-EPOCH Commit (epoch 1 > our 0) is dropped at the authority ingress, but it is the
  // cross-epoch catch-up signal: the non-Normal laggard abandons the futile view-change and enters the
  // recovery peer-fetch, broadcasting a `RequestSync` flagged `recovery` carrying our OLD config_id. The
  // Commit claims view 3, whose primary (3 % 3 = 0) is `primary_peer`, so `sender_matches` passes and the
  // epoch gate is what drops it into the cross-epoch catch-up.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::with(3),
      OpNumber::with(9),
      OpNumber::with(9),
      Epoch::new(1),
      FOREIGN_CONFIG_ID,
    )),
  );
  assert!(
    e.status().is_recovering(),
    "the higher-epoch heartbeat routes the non-Normal laggard into Recovering"
  );
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "it is now awaiting a PEER checkpoint (the cross-epoch SyncCheckpoint)"
  );
  let mut saw_recovery_request = false;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSync(r) = out.msg_ref() {
      assert!(
        r.recovery(),
        "the peer-fetch solicitation is flagged recovery"
      );
      assert_eq!(
        r.config_id(),
        0,
        "it carries our OLD (predecessor) config_id so the E+1 server admits it in-lineage"
      );
      saw_recovery_request = true;
    }
  }
  assert!(
    saw_recovery_request,
    "the laggard broadcasts a recovery RequestSync to solicit the cross-epoch checkpoint"
  );
}

#[test]
fn a_pending_durable_view_write_defers_the_cross_epoch_peer_fetch() {
  // SAFETY: a non-Normal laggard with an in-flight DURABLE-VIEW write (a self-driven view change's
  // SendDoViewChange root, not yet landed) must NOT be torn into the peer-fetch mid-write — that could
  // regress a view it is vouching for. The transition DEFERS until the write settles; a later
  // higher-epoch heartbeat re-triggers it.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Self-driven view change via SVC quorum (own idle-timeout SVC + one peer SVC), which issues a
  // SendDoViewChange durable-view write. We do NOT pump `handle_storage`, so the write stays in flight
  // (the initial DoViewChange is deferred until the view is durable) and `pending_durable_view` holds.
  e.handle_timeout(now, &mut wal, &mut sb, &mut blocks); // bootstrap primary_idle
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks); // primary_idle due → own SVC(view 1)
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      Epoch::new(0),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  assert!(
    e.status().is_view_change() && e.pending_durable_view_for_test(),
    "a self-driven view change has an in-flight durable-view write"
  );
  // The higher-epoch heartbeat arrives WHILE the durable-view write is pending. It claims view 3
  // (primary 0 = `primary_peer`), so `sender_matches` passes and it reaches the cross-epoch catch-up,
  // which then DEFERS on the pending durable-view write rather than tearing it down.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::with(3),
      OpNumber::with(9),
      OpNumber::with(9),
      Epoch::new(1),
      FOREIGN_CONFIG_ID,
    )),
  );
  assert!(
    e.status().is_view_change() && !e.awaiting_peer_checkpoint_for_test(),
    "the peer-fetch is DEFERRED while the durable-view write is in flight (no mid-write teardown)"
  );
}

/// A settled Normal voter (replica 1 of 3) at the given `epoch` — used to drive the epoch-mismatch
/// RESPONSE: a node already AHEAD of a stranded laggard. `Endpoint::new` lands it Normal at view 0 for
/// the passed membership.
fn settled_voter_at(epoch: u64) -> Endpoint<NoopSm> {
  let membership = Membership::from_durable_parts(
    Epoch::new(epoch),
    3,
    0,
    (0..3u128).map(MemberId::new).collect(),
    0,
  )
  .expect("valid membership at the chosen epoch");
  Endpoint::new(
    Config::try_new(1, MemberId::new(1)).expect("valid cluster config"),
    membership,
    0,
    NoopSm,
  )
}

#[test]
fn a_settled_voter_answers_a_lower_epoch_message_with_a_single_epoch_ahead_hint() {
  // Change #3 — the egress half. A settled Normal voter at E+1 receives a strictly-LOWER-epoch
  // StartViewChange (a stranded laggard's old-epoch view-change traffic) from an ACTIVE member. It
  // answers — BEFORE the sender binding — with EXACTLY ONE minimal `EpochAhead{epoch: E+1,
  // checkpoint_op}` back to that `from`, acting on NONE of the stale message's content (the SVC is then
  // dropped at the authority ingress, casting no vote / driving no view change).
  let mut e = settled_voter_at(1);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  assert!(e.status().is_normal() && e.membership.epoch() == Epoch::new(1));
  let from = Peer::Replica(ReplicaId::new(2)); // an active member of our 3-voter config

  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    from,
    // A stranded laggard's OLD-epoch (epoch 0) StartViewChange at some view, self-identifying replica 2.
    Message::StartViewChange(StartViewChange::new(
      View::with(4),
      ReplicaId::new(2),
      Epoch::new(0),
      0,
    )),
  );

  // EXACTLY ONE EpochAhead, addressed back to the laggard, carrying our epoch + checkpoint_op and nothing
  // else.
  let out = e.poll_message().expect("a hint is emitted");
  assert_eq!(
    out.to(),
    Recipient::To(from),
    "addressed back to the laggard"
  );
  let Message::EpochAhead(hint) = out.msg_ref() else {
    panic!(
      "the response is an EpochAhead hint, got {}",
      out.msg_ref().kind_str()
    );
  };
  assert_eq!(hint.epoch(), Epoch::new(1), "carries OUR (higher) epoch");
  assert_eq!(
    hint.checkpoint_op(),
    e.checkpoint_op(),
    "carries OUR cluster checkpoint_op (the crossing target)"
  );
  assert!(
    e.poll_message().is_none(),
    "exactly one hint per inbound stale message"
  );

  // It acted on NONE of the stale content: it neither adopted the laggard's view nor changed status.
  assert!(e.status().is_normal(), "no state change from the stale SVC");
  assert_eq!(
    e.view(),
    View::new(),
    "did not adopt the laggard's advertised view"
  );

  // A Retired / Recovering node must NOT answer: a stale message elicits nothing when we are not a
  // settled member. (A Commit is the lead-traffic shape — also in the trigger set.)
  let mut backup_at_e0 = backup(); // Normal at epoch 0 — a LOWER-epoch message is not below it, no hint
  backup_at_e0.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      Epoch::new(0),
      0,
    )),
  );
  assert!(
    !backup_at_e0
      .poll_message()
      .is_some_and(|o| matches!(o.msg_ref(), Message::EpochAhead(_))),
    "a same-epoch message is not below us → no hint",
  );
}

#[test]
fn a_stranded_laggard_triggers_the_cross_epoch_peer_fetch_on_an_epoch_ahead_hint() {
  // Change #3 — the ingress half. A stranded laggard at epoch 0 (Normal) receives a minimal
  // `EpochAhead{epoch: 1, checkpoint_op: 9}` pulled back from a bindable retained voter. It must arm the
  // SAME forced, crossing-required cross-epoch sync a higher-epoch Commit would — needing NO new-primary
  // binding (`from` is a retained voter in our own config). A NORMAL laggard STAYS Normal (it is
  // behind-but-operational): the speculative arm leaves status/op/commit/view untouched and the replica
  // crosses only when the verified crossing checkpoint installs.
  let mut e = backup(); // Normal at epoch 0
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  assert!(e.status().is_normal() && e.membership.epoch() == Epoch::new(0));

  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(), // a retained voter (slot 0) the laggard already binds
    Message::EpochAhead(EpochAhead::new(Epoch::new(1), OpNumber::with(9))),
  );

  assert!(
    e.status().is_normal() && e.membership.epoch() == Epoch::new(0),
    "the NORMAL laggard STAYS Normal at the old epoch (the speculative arm does not transition)"
  );
  assert!(
    !e.awaiting_peer_checkpoint_for_test(),
    "it did NOT enter the recovery peer-fetch (it stays operational, not Recovering)"
  );
  assert!(
    e.sync_is_forced_for_test() && e.sync_requires_cross_epoch_for_test(),
    "but it ARMED a FORCED, crossing-required cross-epoch sync (the unified crossing requirement)"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(9),
    "the forced sync targets the hint's checkpoint_op"
  );
}

#[test]
fn a_higher_epoch_hint_from_a_non_member_slot_does_not_trigger_catch_up() {
  // The pre-binding cross-epoch trigger authenticates the SENDER as a CURRENT MEMBER of our config
  // (`member_at`), mirroring `maybe_answer_lower_epoch`. A higher-epoch Commit from a slot BEYOND our
  // config (slot 5 >= node_count 3 — a NON-member: a misrouted or forged hint) must NOT arm a crossing.
  // Otherwise, on an IDLE checkpoint-0 primary it would arm a forced crossing sync no donor can answer
  // (every checkpoint_op is 0) with no same-epoch authority ingress to clear the stale intent — wedging
  // writes (`sync.is_some()`) at the old epoch forever. The reliable catch-up signal is the `EpochAhead`
  // from a RETAINED voter (a member of our config — a single-voter change always retains at least one),
  // pinned by the sibling tests above; a non-member hint is dropped here BEFORE it can poison.
  let mut e = backup(); // Normal at epoch 0, node_count 3
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  assert_eq!(
    e.membership.node_count(),
    3,
    "slot 5 is beyond our config (a non-member)"
  );

  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(5)), // a NON-member slot beyond our config — misrouted/forged
    Message::Commit(Commit::new(
      View::with(2),
      OpNumber::with(9),
      OpNumber::with(9),
      Epoch::new(1),
      FOREIGN_CONFIG_ID,
    )),
  );

  assert!(
    e.status().is_normal() && !e.awaiting_peer_checkpoint_for_test(),
    "the NORMAL primary stays Normal — a non-member hint does not drive it Recovering"
  );
  assert!(
    e.sync_target_for_test().is_none() && e.cross_epoch_intent_for_test().is_none(),
    "a higher-epoch hint from a NON-member slot arms NO crossing sync and pins NO intent — no idle-primary poison"
  );
}

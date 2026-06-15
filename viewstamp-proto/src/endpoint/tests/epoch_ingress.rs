//! The (epoch, config_id) AUTHORITY ingress gate (`epoch_authority_admits` + the `on_prepare`
//! normal-arm epoch branch). A STRICT message (a vote/lead driver) contributes to append/vote/
//! view-adoption ONLY on an exact `(epoch, config_id)` match; an AGNOSTIC serve/solicitation is
//! admitted iff its `config_id` is in lineage (same config in PR1). The fixtures carry `config_id = 0`
//! (see the `genesis` helper), so a same-config message uses `(Epoch::new(0), 0)`.

use super::*;
use crate::{
  ClientId, Commit, Config, Epoch, OpNumber, Prepare, PrepareOk, ReplicaId, Request, RequestNumber,
  View,
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
  let now = Instant::ZERO;
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
  e.handle_storage(now, &mut wal, &mut sb); // own append durable → own vote (bit 0)
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
  e.handle_storage(now, &mut wal, &mut sb);
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
  e.handle_storage(now, &mut wal, &mut sb);
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
  let now = Instant::ZERO;
  // Hold op 1 (so a commit=1 is appliable).
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.op(), OpNumber::with(1));
  assert_eq!(e.commit(), OpNumber::new());

  // Foreign-config Commit: dropped for authority.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      Epoch::new(0),
      FOREIGN_CONFIG_ID,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
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
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      Epoch::new(0),
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
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
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {} // discard acks

  // Foreign-config_id RequestPrepare for op 1: rejected at the lineage gate — no serve.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(2),
      FOREIGN_CONFIG_ID,
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
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(2),
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
  while r.poll_message().is_some() {} // discard the repair solicitation
  // Learn commit up to 3 → applies op 1, then registers the op-2 hole as it tries to cross it. The
  // commit is in-lineage (config_id 0), so the new gate admits it.
  r.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
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
    Peer::Replica(ReplicaId::new(0)),
    Message::RepairBatch(crate::RepairBatch::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::new(),
      0,
      std::vec![entry],
    )),
  );
  r.handle_storage(Instant::ZERO, &mut wal, &mut sb);
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
  let now = Instant::ZERO;
  // `prepare(1, 0)` carries `Epoch::new(0)` + config_id 0 (the fixture lineage).
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the same-config Prepare is appended"
  );
  e.handle_storage(now, &mut wal, &mut sb); // pump WAL → PrepareOk
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

#[test]
fn foreign_epoch_prepare_normal_arm_is_dropped_but_repair_arm_is_agnostic() {
  // The PATH-SENSITIVE split: a `Prepare` whose op is one of our registered repair holes is served by
  // the AGNOSTIC repair arm regardless of `epoch` (committed, view-independent content), while a
  // NORMAL head-advancing `Prepare` at a foreign epoch is dropped by the strict normal-arm gate.
  //
  // Repair arm (agnostic): a foreign-EPOCH Prepare for the op-2 hole still fills it — the repair path
  // runs before the normal-arm epoch check.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  while r.poll_message().is_some() {}
  // Register the op-2 hole: an in-lineage Commit(commit=3) holds at the hole as it tries to cross it.
  r.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
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
    "op-2 hole open before the serve"
  );
  r.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2), // commit >= op: vouches the served op committed
      OpNumber::new(),
      Epoch::new(FOREIGN_EPOCH), // foreign epoch — irrelevant to the AGNOSTIC repair arm
      0,                         // config_id in lineage (required for both arms)
      ClientId::new(7),
      RequestNumber::with(2),
      Bytes::copy_from_slice(&[2u8]),
    )),
  );
  r.handle_storage(Instant::ZERO, &mut wal, &mut sb);
  assert!(
    !r.has_repair_hole_for_test(2),
    "a foreign-epoch repair-serve Prepare fills the hole — the repair arm is epoch-agnostic",
  );

  // Normal arm (strict): a backup at the head must NOT append a foreign-epoch head-advancing Prepare.
  let mut e = backup();
  let (mut wal2, mut sb2) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal2,
    &mut sb2,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      OpNumber::new(),
      Epoch::new(FOREIGN_EPOCH), // foreign epoch — the strict normal arm drops it
      0,
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::copy_from_slice(&[1u8]),
    )),
  );
  assert_eq!(
    e.op(),
    OpNumber::new(),
    "a foreign-epoch head-advancing Prepare is dropped by the strict normal arm: head stays 0",
  );
  assert!(
    e.poll_message().is_none(),
    "no PrepareOk is emitted for a dropped foreign-epoch Prepare",
  );
}

use super::*;
use crate::{ClientId, Config, Header, OpNumber, ReplicaId, RequestNumber, View, VsrState, Wal};
use std::collections::VecDeque;

#[test]
fn on_request_prepare_holder_replies_with_the_prepare() {
  // A Normal replica that holds a committed op answers a peer's RequestPrepare with the Prepare
  // carrying that op's body — the peer-fault-repair *server* side.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Hold ops 1 + 2 (apply 1 via the piggybacked commit).
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

  // Replica 2 asks us for op 1.
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
    )),
  );
  let out = e.poll_message().expect("holder answers RequestPrepare");
  assert_eq!(
    out.to(),
    Recipient::To(Peer::Replica(ReplicaId::new(2))),
    "the Prepare is addressed back to the requester"
  );
  match out.into_msg() {
    Message::Prepare(p) => {
      assert_eq!(p.op(), OpNumber::with(1));
      assert_eq!(p.body(), &[1u8], "carries op 1's real body");
    }
    other => panic!("expected a Prepare reply, got {other:?}"),
  }
}

#[test]
fn on_request_prepare_is_serve_silent_or_nack_by_local_holding() {
  // The THREE-WAY answer a Normal replica gives a peer's RequestPrepare, by what it durably holds:
  //   * `Present` at/below head       → SERVE the Prepare (the body it holds);
  //   * header-only `Repairing`       → SILENT (it holds the identity, not the body — a body holder answers);
  //   * durably LACKS it, op > checkpoint_op  → NACK (its log is the authoritative durable record for the slot);
  //   * durably LACKS it, op <= checkpoint_op → SILENT (subsumed by its snapshot — it HOLDS the op).
  // A new primary holding op 1 `Present`, op 2 header-only `Repairing`, checkpoint 0, head 2 covers the
  // first three; a separate replica with a non-zero checkpoint covers the fourth.
  let (mut e, mut wal, mut sb, mut blocks) = new_primary_with_op2_candidate(genesis(3));
  let now = Instant::ZERO;
  let request_prepare = |op: u64| {
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::with(1),
      OpNumber::with(op),
      ReplicaId::new(2),
      0,
    ))
  };

  // `Present` op 1 (at/below head) → serve the Prepare carrying its body.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    request_prepare(1),
  );
  match e.poll_message().expect("a Present op is served").into_msg() {
    Message::Prepare(p) => {
      assert_eq!(p.op(), OpNumber::with(1), "serves the held op 1");
      assert_eq!(p.body(), &b"a"[..], "carries op 1's real body");
    }
    other => panic!("expected a Prepare serve, got {other:?}"),
  }

  // Header-only `Repairing` op 2 → SILENT (we hold the identity, not the body).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    request_prepare(2),
  );
  assert!(
    e.poll_message().is_none(),
    "a header-only Repairing op is never served NOR nacked — a body holder answers"
  );

  // Durably LACKED op 5, above our checkpoint (0) → NACK, addressed back to the requester.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    request_prepare(5),
  );
  let out = e
    .poll_message()
    .expect("a durably-lacked op above the checkpoint is nacked");
  assert_eq!(
    out.to(),
    Recipient::To(Peer::Replica(ReplicaId::new(2))),
    "the nack routes back to the requester"
  );
  match out.into_msg() {
    Message::Nack(n) => {
      assert_eq!(n.op(), OpNumber::with(5), "the nack names the lacked op");
      assert_eq!(n.replica(), ReplicaId::new(1), "stamped with our own slot");
      assert_eq!(n.view(), View::with(1), "carries our current view");
    }
    other => panic!("expected a Nack, got {other:?}"),
  }
  assert!(e.poll_message().is_none(), "exactly one nack");

  // A durably-LACKED op AT/BELOW the checkpoint is subsumed by the snapshot → SILENT (state-sync, not nack).
  let mut b = backup();
  b.force_state_for_test(0, 5, 5, 5, &[]); // op/commit/checkpoint all 5 (a self-consistent snapshot)
  let (mut wal2, mut sb2) = (TestWal::default(), TestSb::default());
  let mut blocks2 = crate::block_store::MemBlockStore::new();
  b.handle_message(
    now,
    &mut wal2,
    &mut sb2,
    &mut blocks2,
    Peer::Replica(ReplicaId::new(2)),
    request_prepare(3), // 3 <= checkpoint 5: subsumed
  );
  assert!(
    b.poll_message().is_none(),
    "an op at/below the checkpoint is subsumed by the snapshot — silent, never nacked"
  );
}

#[test]
fn on_request_prepare_serves_a_held_op_with_a_truthful_commit_field() {
  // A replica serves a RequestPrepare for any op it HOLDS (`Present`) at or below its head
  // (`op <= self.op`), with a TRUTHFUL `commit` field (= its `commit_min`). Safety rests on the
  // REQUESTER's `fill_repair`, not on a restrictive serve gate:
  //   * a COMMITTED op (`op <= commit_min`) is served with `commit >= op` — a committed vouch the
  //     requester's ordinary committed-hole repair accepts;
  //   * an UNCOMMITTED held op (`commit_min < op <= self.op`) is served with `commit < op` — NOT a
  //     committed vouch; the requester adopts such a body ONLY against a locally-known canonical
  //     `body_checksum` (a view-change-carried `Repairing` hole), so a peer-held uncommitted body is
  //     never trusted blindly. This is what lets a new primary fetch a carried-through uncommitted-tail
  //     op's body from a peer that holds it.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Hold ops 1 + 2 but COMMIT only op 1 (prepare(2,1) piggybacks commit=1 → commit_min == 1, op == 2).
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
  assert_eq!(e.commit(), OpNumber::with(1), "committed through op 1 only");
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "but holds op 2 (uncommitted) in its log"
  );

  // Asking for op 2 (held-but-uncommitted, op <= head) → served, but with a TRUTHFUL `commit` (= 1)
  // that does NOT vouch op 2 committed (`commit < op`). The requester's `fill_repair` is the safety gate.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(2),
      ReplicaId::new(2),
      0,
    )),
  );
  match e
    .poll_message()
    .expect("a held op at/below head IS served")
    .into_msg()
  {
    Message::Prepare(p) => {
      assert_eq!(p.op(), OpNumber::with(2), "serves the held op 2");
      assert!(
        p.commit().get() < p.op().get(),
        "but the commit field is truthful (= commit_min = 1 < op 2) — NOT a committed vouch"
      );
    }
    other => panic!("expected a Prepare for the held op, got {other:?}"),
  }

  // Asking for op 1 (<= commit_min, committed) → answered with a committed vouch (commit >= op).
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
    )),
  );
  match e
    .poll_message()
    .expect("a committed op IS served")
    .into_msg()
  {
    Message::Prepare(p) => {
      assert_eq!(p.op(), OpNumber::with(1), "serves the committed op 1");
      assert!(
        p.commit().get() >= p.op().get(),
        "the answer vouches op 1 is committed (commit = commit_min >= op)"
      );
    }
    other => panic!("expected a Prepare for the committed op, got {other:?}"),
  }

  // Asking for op 3 (ABOVE our head — we durably LACK it, above our checkpoint 0) → NACK, not a serve:
  // we never fabricate a Prepare for an op we do not hold, and our log is the authoritative durable record
  // for that slot, so we answer the negative "I lack op 3".
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::new(),
      OpNumber::with(3),
      ReplicaId::new(2),
      0,
    )),
  );
  match e
    .poll_message()
    .expect("a durably-lacked op above the checkpoint is nacked, not served")
    .into_msg()
  {
    Message::Nack(n) => assert_eq!(n.op(), OpNumber::with(3), "the nack names the lacked op 3"),
    other => panic!("expected a Nack for the lacked op above our head, got {other:?}"),
  }
  assert!(
    e.poll_message().is_none(),
    "no Prepare for an op we do not hold"
  );
}

#[test]
fn repaired_prepare_fills_the_hole_and_resumes_the_held_commit() {
  // End to end: a held-commit replica receives the peer-supplied Prepare for its hole, verifies it
  // (checksum + placement), fills the cache, and resumes applying the committed prefix in order —
  // the committed op is restored, NOT lost.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  let mut blocks = crate::block_store::MemBlockStore::new();
  while r.poll_message().is_some() {} // discard the solicitation
  let now = Instant::ZERO;
  // Learn commit up to 3 → applies op 1, holds at the op-2 hole.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(r.commit(), OpNumber::with(1), "held at the hole");

  // A peer answers our RequestPrepare with op 2's Prepare → stage the durable fill (the apply +
  // hole-clear + commit-resume DEFER to the append's completion), then complete it.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    repair_prepare(0, 2, 3),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "commit still held until the repaired append is durable"
  );
  r.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the repaired append completes → apply + resume
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "the hole filled (durably) → the held commit resumes and applies ops 2 then 3 in order"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[
      (1, std::vec![1u8]),
      (2, std::vec![2u8]),
      (3, std::vec![3u8])
    ],
    "every committed op applied in order — the rotted op 2 was repaired from a peer, not lost"
  );
  // The repaired op was persisted durably (a later read serves it), so the hole cannot reopen.
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "the repaired op 2 is re-appended to the WAL (durable for future reads / DVCs)"
  );
}

#[test]
fn a_misplaced_repaired_prepare_is_rejected_not_adopted() {
  // Placement guard (the misdirected-IO defense the recovery read path makes, applied to a peer
  // reply): a Prepare for an op that is NOT our hole must NOT fill it. The hole stays open, the
  // commit stays HELD, and no wrong op's body is applied to the held slot.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  let mut blocks = crate::block_store::MemBlockStore::new();
  while r.poll_message().is_some() {}
  let now = Instant::ZERO;
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(r.commit(), OpNumber::with(1));
  // A Prepare for op 5 (not our hole, op 2) is rejected by the placement check (`repair.contains`).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    repair_prepare(0, 5, 3),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "a Prepare whose op is not the hole does not fill it (placement mismatch)"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[(1, std::vec![1u8])],
    "no wrong body applied; the commit stays held until the CORRECT op 2 arrives"
  );
  // The correct op 2 still repairs it (liveness: a wrong reply did not poison the hole). Its fill is a
  // durability barrier, so complete the append before the commit resumes.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    repair_prepare(0, 2, 3),
  );
  r.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the repaired append completes → apply + resume
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "the correct op 2 fills the hole"
  );
}

#[test]
fn fill_repair_rejects_a_stale_uncommitted_prepare_for_a_committed_hole() {
  // SAFETY (committed-op survival): a committed repair hole may ONLY be filled with the committed
  // value for the op. A STALE/reordered Prepare from an old view, broadcast while its body was still
  // UNCOMMITTED (`commit < op`), must be REJECTED — it does not vouch the op is committed, and the
  // committed value at that op could be a DIFFERENT body. Accepting it would diverge the replica from
  // the quorum that committed the real body. The hole stays open + the commit stays HELD until a
  // Prepare that vouches commit >= op arrives.
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  let mut blocks = crate::block_store::MemBlockStore::new();
  while r.poll_message().is_some() {} // discard the solicitation
  let now = Instant::ZERO;
  // Learn commit up to 3 → applies op 1, holds at the op-2 hole.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(r.commit(), OpNumber::with(1), "held at the hole");

  // A STALE Prepare for op 2 carrying `commit = 1` (< op 2): an old-view primary broadcast it while
  // op 2 was still uncommitted. Placement (op 2 IS our hole) + body checksum both PASS — only the new
  // commit-vouch guard rejects it.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    repair_prepare(0, 2, 1),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "a stale Prepare (commit < op) does NOT fill a committed hole — commit stays HELD"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "the hole stays OPEN (re-solicited) — the uncommitted old-view body is never adopted"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[(1, std::vec![1u8])],
    "no uncommitted body applied to the held slot"
  );

  // A Prepare that VOUCHES op 2 is committed (`commit = 2` >= op 2, from a peer that holds it
  // committed) fills the hole and resumes the held commit — liveness preserved. The fill is a
  // durability barrier: complete the append before the hole clears + the commit resumes.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );
  r.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the repaired append completes → clear hole + resume
  assert!(
    !r.has_repair_hole_for_test(2),
    "a committed-vouching Prepare (commit >= op) clears the hole"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "the committed value fills the hole → the held commit resumes (ops 2 then 3 apply in order)"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[
      (1, std::vec![1u8]),
      (2, std::vec![2u8]),
      (3, std::vec![3u8])
    ],
    "every committed op applied in order — only the committed value filled the hole"
  );
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "the committed op 2 is durably (re)appended once the vouching Prepare fills it"
  );
}

#[test]
fn repair_holds_the_commit_across_a_long_unrepaired_window() {
  // Liveness/safety under delay: while the hole is unrepaired the commit stays HELD no matter how
  // much further commit the primary announces — a committed op above the hole is NEVER applied
  // before the hole is filled (strict in-order apply). Then a single repair fills it and the whole
  // suffix applies at once.
  let (mut r, mut wal, mut sb) = recovering_with_hole(4, 2);
  let mut blocks = crate::block_store::MemBlockStore::new();
  while r.poll_message().is_some() {}
  while r.poll_event().is_some() {}
  let now = Instant::ZERO;
  // Repeatedly learn commit up to the head; the hole at op 2 pins the applied frontier at op 1.
  for _ in 0..5 {
    r.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      primary_peer(),
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(4),
        OpNumber::new(),
        crate::Epoch::new(0),
        0,
      )),
    );
    assert_eq!(
      r.commit(),
      OpNumber::with(1),
      "commit pinned at the hole regardless of how far the primary's commit advances"
    );
  }
  // The windowed solicit surfaced as an observability event: the hole band starts (and here ends —
  // ops 3,4 are held Present, terminating the run) at op 2.
  assert!(
    core::iter::from_fn(|| r.poll_event()).any(|e| e
      == Event::RepairStarted(crate::RepairStarted::new(
        OpNumber::with(2),
        OpNumber::with(2)
      ))),
    "the held commit's windowed repair solicit emits RepairStarted for the hole band"
  );
  // One repair → the entire held suffix (2,3,4) applies in order (once the repaired append is durable —
  // the durability barrier).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    repair_prepare(0, 2, 4),
  );
  r.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the repaired append completes → apply the held suffix
  assert_eq!(r.commit(), OpNumber::with(4));
  assert_eq!(
    r.state_machine_ref().applied(),
    &[
      (1, std::vec![1u8]),
      (2, std::vec![2u8]),
      (3, std::vec![3u8]),
      (4, std::vec![4u8])
    ],
    "every committed op applied in order once the single hole was repaired"
  );
}

#[test]
fn fill_repair_defers_apply_until_the_repaired_append_is_durable() {
  // CONSENSUS-CRITICAL regression. `fill_repair` inserted the repaired body into
  // `self.log`, `submit_append`ed it, REMOVED the repair hole, and immediately `advance_commit`ed — but
  // the async `Wal`'s `submit_append` only STAGES the write. So with the async WAL the repaired op was
  // APPLIED (and exposable in a DVC/StartView/checkpoint) BEFORE `WalDone::Appended`: a crash in that
  // window LOSES the only durable copy of an op this replica had already participated on — breaking
  // append-before-participate (durable-source) for peer repair.
  //
  // The fix makes the repaired append a DURABILITY BARRIER: `fill_repair` stages the body in a
  // `Pending::RepairFill` (NOT in `self.log`) + `submit_append`s + marks `op` `appending`, but keeps the
  // hole OPEN and does NOT advance the commit; `on_wal_done` inserts the body, clears the hole, and
  // resumes the held commit ONLY once the append completes.
  //
  // Setup (the held-committed-hole shape): replica 1 of 3, durable commit 2 (op 2 KNOWN
  // committed), checkpoint_op 0, canonical headers for ops 1 + 2. WAL head 3, slot 2 reads back
  // PERMANENTLY FAULTY → recover keeps it header-only as a `Body::Repairing` COMMITTED hole (op 1 held
  // canonical, op 3 the uncommitted tail). commit_max == 2, commit_min == 0.
  let mk_header = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::new(),
    0,
    std::vec![mk_header(1), mk_header(2)],
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(3);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // op 2's slot read permanently faults → Repairing
  let mut blocks = crate::block_store::MemBlockStore::new();
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
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
  drive_recovery(&mut r, &mut wal, &mut sb, &mut blocks, now);
  assert_eq!(r.status(), Status::Normal, "recovers to Normal");
  assert_eq!(r.commit_max(), OpNumber::with(2), "op 2 is KNOWN committed");
  while r.poll_message().is_some() {} // discard recovery chatter
  while r.poll_event().is_some() {}

  // The primary announces commit == 2. `advance_commit` applies the held op 1 (commit → 1), then HOLDS
  // at the missing op 2 and registers it as a committed repair hole (`request_repair`). op 1 applied,
  // commit held at 1, op 2 a hole below commit_max == 2.
  r.handle_message(
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
  assert!(
    r.has_repair_hole_for_test(2),
    "op 2 is a committed repair hole (held + peer-repaired)"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "commit held below the op-2 hole (op 1 applied)"
  );
  while r.poll_message().is_some() {} // discard the RequestPrepare for op 2
  while r.poll_event().is_some() {}
  // Drain any pre-existing WAL completions so the only outstanding append below is the repair fill's.
  while wal.poll().is_some() {}

  // A committed-vouching peer answers our RequestPrepare for op 2 (canonical body [2], commit 2 >= op 2).
  // This calls `fill_repair`, which STAGES the body + `submit_append`s it — but the append is NOT yet
  // delivered (no `handle_storage` / `on_wal_done` yet).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );

  // BEFORE the append completes: the barrier holds. (FAIL-BEFORE: each of these is already violated — the
  // hole is gone, op 2 applied, commit == 2 — on the staged, non-durable append.)
  assert!(
    r.has_repair_hole_for_test(2),
    "the repair hole stays OPEN until the repaired append is durable \
     (FAIL-BEFORE: fill_repair cleared the hole on the staged append)"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "commit is NOT advanced past the op-2 hole before durability \
     (FAIL-BEFORE: commit advanced to 2 on the staged append)"
  );
  assert!(
    r.state_machine_ref()
      .applied()
      .iter()
      .all(|(op, _)| *op != 2),
    "op 2 is NOT applied to the SM before its append is durable \
     (FAIL-BEFORE: op 2 applied immediately on the staged append)"
  );
  // op 2's HEADER stays exposed in the log_slice as a `Repairing` hole — seed-774 keeps a committed op's
  // existence in the DVC (header-only) so a new primary peer-repairs it; that header has been durable in
  // the committed band since recovery, independent of this staged fill. The consensus-critical barrier is
  // that the STAGED RepairFill body is NOT folded into a `Present` entry before it is durable: op 2 stays
  // `Repairing` (the body rides in `Pending::RepairFill`, not `self.log`), so this replica never sources
  // the non-durable repaired body.
  assert_eq!(
    r.log.get(&2).expect("op 2 is a held Repairing hole").body,
    Body::Repairing(mk_header(2).body_checksum()),
    "op 2 stays Repairing (header-only) while its RepairFill is pending — the staged body is NOT folded \
     in (FAIL-BEFORE: fill_repair inserted the repaired body into self.log on the staged append)"
  );

  // Now the repaired append completes (on_wal_done's RepairFill arm): the body lands in self.log, the
  // hole clears, and the held commit resumes through ops 1 + 2.
  r.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    !r.has_repair_hole_for_test(2),
    "the durable repair fill clears the hole"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the held commit resumes to op 2 ONLY after the repaired append is durable"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[(1, std::vec![1u8]), (2, std::vec![2u8])],
    "ops 1 + 2 apply once op 2 is durable — the repaired body is never applied before its WAL append lands"
  );
  // And op 2 is now exposed (the hole is gone, the body is in self.log).
  assert!(
    r.log_entries().iter().any(|e| e.op() == OpNumber::with(2)),
    "op 2 is exposed once its RepairFill is durable"
  );
}

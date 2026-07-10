use super::{super::*, *};
use crate::{
  ClientId, Config, Header, OpId, OpNumber, ReplicaId, Request, RequestNumber, SlotStatus, View,
  encode_message,
};

#[test]
fn fresh_endpoint_state() {
  let cfg = Config::try_new(1, MemberId::new(0)).expect("valid cluster config");
  let e = Endpoint::new(cfg, genesis(3), 99, NoopSm);
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(e.view(), View::new());
  assert_eq!(e.op(), OpNumber::new());
  assert_eq!(e.commit(), OpNumber::new());
  assert!(e.is_primary()); // replica 0 is primary of view 0
}

#[test]
fn backup_appends_and_acks_then_commits_via_piggyback() {
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  assert!(!e.is_primary());
  let now = Instant::ZERO;

  // Prepare op=1, commit=0: submit append, pump storage so it completes, ack, commit stays 0.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(1, 0),
  );
  assert_eq!(e.op(), OpNumber::with(1));
  assert_eq!(e.commit(), OpNumber::with(0));
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // pump WAL → on_wal_done → PrepareOk
  match e.poll_message().expect("prepare_ok emitted").into_msg() {
    Message::PrepareOk(ok) => {
      assert_eq!(ok.op(), OpNumber::with(1));
      assert_eq!(ok.replica(), ReplicaId::new(1));
    }
    _ => panic!("expected PrepareOk"),
  }

  // Prepare op=2, commit=1: piggybacked commit applies op 1 (synchronously), then append op 2.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(2, 1),
  );
  assert_eq!(e.op(), OpNumber::with(2));
  assert_eq!(e.commit(), OpNumber::with(1));
}

#[test]
fn backup_buffers_out_of_order_prepares() {
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // op=2 arrives before op=1: buffered, head op stays 0.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(2, 0),
  );
  assert_eq!(e.op(), OpNumber::with(0));

  // op=1 arrives: append 1, then drain buffered op 2.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(1, 0),
  );
  assert_eq!(e.op(), OpNumber::with(2));
}

#[test]
fn a_stale_view_buffered_prepare_is_not_drained_into_the_adopted_view() {
  // A backup carries its reorder `buffer` across a `StartView` adoption (by design), so a `Prepare`
  // buffered under an OLD view must NOT be spliced into the new view when the head later reaches it — the
  // new view may have re-minted a different op at that number, and a spliced stale body would apply off a
  // Commit heartbeat / poison a future DVC (`LogEntry` records no per-entry view to catch it later).
  let mut e = backup(); // replica 1 of 3, view 0, head 0
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // Buffer a view-0 Prepare at op 2 (op 1 missing) — head stays 0.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(2, 0),
  );
  assert_eq!(e.op(), OpNumber::with(0));

  // Adopt view 2 (primary = 2 % 3 = 2, not this backup) at canonical head 0 via StartView; drain the
  // durable-view write so the backup is Normal at view 2. The buffered view-0 op-2 entry survives.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartView(crate::StartView::new(
      View::with(2),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec::Vec::new(),
    )),
  );
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(e.view(), View::with(2));
  assert!(e.status().is_normal());

  // A view-2 Prepare at op 1 extends the head to 1, then the drain reaches the buffered op 2 — which is
  // stamped view 0. It must be DROPPED, not appended: the head stays at 1, op 2 is absent from the log.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::Prepare(Prepare::new(
      View::with(2),
      OpNumber::with(1),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::copy_from_slice(&[1u8]),
    )),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the stale view-0 buffered op 2 was dropped, not spliced into view 2",
  );
  assert!(
    !e.has_log_entry_for_test(2),
    "no stale op sits in the log at 2",
  );
}

#[test]
fn backup_caches_the_reply_so_a_backup_turned_primary_can_resend_it() {
  // REGRESSION (the lost-reply-across-failover hang): the primary caches each
  // committed reply (`commit_op`), but a BACKUP used to discard it. So if a client's reply was LOST
  // in flight and the primary then failed over, the new primary (a former backup) saw the client's
  // resend as a duplicate (`request == session.request`) yet had NO cached reply to resend — staying
  // SILENT and hanging the client forever, even with a healthy quorum. The fix caches the reply on
  // the backup's apply path too (it is the SM's deterministic output). Here: a backup applies op 1
  // (client 7, request 1) and must hold its cached reply.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Prepare op 1 (client 7, request 1), make it durable, then Commit to apply it.
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
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.commit(), OpNumber::with(1), "the backup applied op 1");
  // The backup cached the reply for client 7's request 1 — so once it becomes primary it can resend
  // it on a duplicate request (NoopSm's reply body is empty, but the cache ENTRY must be present and
  // keyed to request 1, which is what the duplicate-resend path checks).
  let cached = e.session_reply_for_test(7);
  assert!(
    cached.is_some(),
    "a backup must cache the committed reply (so a backup-turned-primary can resend a lost reply)"
  );
  assert_eq!(
    cached.unwrap().0,
    1,
    "the cached reply is keyed to the applied request number"
  );
}

#[test]
fn apply_caches_the_reply_even_when_the_watermark_was_pre_seeded_without_it() {
  // REGRESSION (the seeded-watermark reply black hole): the session watermark can legitimately sit AT
  // an op's request BEFORE that op is applied, with NO cached reply — a primary's `on_request` seeds it
  // at ACCEPT time and a checkpoint snapshot captures that row (restored by recovery / state-sync), and
  // `start_view_as_new_primary` backfills it from a held-but-unapplied adopted entry. When the op's
  // apply is DEFERRED past such a seeding (a floored view-change union holds the commit at a sub-floor
  // hole until repair / state-sync), gating the reply cache on the watermark ADVANCING would skip it
  // permanently: the client's retry of exactly that request would dedup against the seeded watermark
  // with no cached reply and be dropped forever (a liveness freeze — the op committed, so the request
  // can never be re-minted). The apply must cache the reply for the applied request regardless of
  // whether the watermark moved.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Pre-seed client 7's watermark at request 1 with NO reply — the snapshot-restored / backfilled row.
  e.clients.insert(
    7,
    Session {
      request: RequestNumber::with(1),
      reply: None,
      last_op: OpNumber::new(),
    },
  );
  // Apply op 1 (client 7, request 1) via the normal Prepare + Commit flow.
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
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.commit(), OpNumber::with(1), "the backup applied op 1");
  let cached = e.session_reply_for_test(7);
  assert_eq!(
    cached.map(|(rn, _)| rn),
    Some(1),
    "the apply caches request 1's reply even though the watermark already sat at 1 (seeded without a \
     reply) — otherwise the client's retry dedups to a silent drop forever"
  );
}

#[test]
fn backup_below_primary_commit_solicits_the_committed_tail_gap() {
  // REGRESSION (the backup tail-gap liveness bug): a backup whose head fell BELOW the primary's
  // commit_min is missing committed ops that are ABOVE the cluster checkpoint (so the `> self.op`
  // state-sync trigger is FALSE) yet ABOVE its head (so advance_commit can't reach them). The
  // primary's prepare-retransmit only covers `commit_min+1..=op`, so it never re-sends them. Without
  // a backup-side solicitation the backup stalls at its head forever (and can wedge the whole cluster
  // if it is in the only surviving quorum). The fix: on hearing a Commit whose commit is above our
  // head, solicit the band `(head .. commit]` via RequestPrepare so it arrives as ordinary Prepares.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // Bring the backup to head op 2 (append 1, 2 via in-order Prepares; commit stays 0).
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
    prepare(2, 0),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.op(), OpNumber::with(2));
  while e.poll_message().is_some() {} // drain the acks

  // A Commit learns the primary committed up to op 5 (checkpoint still 2, so 3,4,5 are above the
  // checkpoint — NOT snapshot-only). The backup holds only up to op 2 → it must solicit 3,4,5.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(5),
      OpNumber::with(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  // It does NOT advance commit past its head (it lacks 3,4,5) and does NOT state-sync (head >= ckpt).
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "commit is held at the head until the gap fills"
  );
  // It solicits exactly the committed tail-gap (3,4,5) via RequestPrepare — NOT a state-sync.
  let mut requested = std::collections::BTreeSet::new();
  let mut saw_request_sync = false;
  while let Some(out) = e.poll_message() {
    match out.into_msg() {
      Message::RequestPrepare(rp) => {
        requested.insert(rp.op().get());
      }
      Message::RequestSync(_) => saw_request_sync = true,
      _ => {}
    }
  }
  assert_eq!(
    requested,
    [3, 4, 5].into_iter().collect(),
    "the backup solicits exactly the committed tail-gap (3,4,5) above its head"
  );
  assert!(
    !saw_request_sync,
    "the gap is above the cluster checkpoint → ordinary tail-gap repair, not a state-sync"
  );
}

#[test]
fn tail_gap_repair_is_bounded_per_call() {
  // REGRESSION (the unbounded tail-gap DoS): a backup that learns a `commit_max` FAR above its head
  // (a large legitimate gap, or a malformed/bogus Commit) must NOT push the whole `(head .. commit_max]`
  // band into `outgoing` in a single `request_tail_gap` call — that is unbounded CPU/memory in the
  // Sans-I/O core. It must emit at most `TAIL_GAP_WINDOW` RequestPrepares per call (the rest follow on
  // later heartbeats as the head advances). Before the fix this enqueued ~1,000,000 RequestPrepares.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // The backup is at head 0, checkpoint 0. A single Commit advertises a colossal commit_max — above
  // the checkpoint (so this is tail-gap territory, not state-sync) and far above the head.
  let bogus = 1_000_000u64;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(bogus),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  // It records the learned commit_max but solicits only a bounded window above its head.
  assert_eq!(
    e.commit_max(),
    OpNumber::with(bogus),
    "the learned commit_max is recorded (it just is not all solicited at once)"
  );
  let mut requested: std::vec::Vec<u64> = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::RequestPrepare(rp) = out.msg_ref() {
      requested.push(rp.op().get());
    }
  }
  assert_eq!(
    requested.len() as u64,
    TAIL_GAP_WINDOW,
    "at most TAIL_GAP_WINDOW RequestPrepares are emitted per call, not the whole range"
  );
  // The window starts at the first op above the head (1) and is contiguous up to the cap — so the gap
  // is closed incrementally from the bottom across heartbeats, never all at once.
  assert_eq!(
    requested,
    (1..=TAIL_GAP_WINDOW).collect::<std::vec::Vec<u64>>(),
    "the bounded window is the contiguous band (head+1 ..= head+TAIL_GAP_WINDOW)"
  );
}

#[test]
fn tail_gap_repair_within_the_window_requests_the_whole_gap() {
  // The cap must not under-serve a SMALL gap: a backup whose gap fits inside one window still solicits
  // exactly the gap (no truncation, no over-request past commit_max).
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Head 0, checkpoint 0, commit_max 3 (< TAIL_GAP_WINDOW) → solicit exactly {1,2,3}.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  let mut requested: std::vec::Vec<u64> = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::RequestPrepare(rp) = out.msg_ref() {
      requested.push(rp.op().get());
    }
  }
  assert_eq!(
    requested,
    std::vec![1, 2, 3],
    "a gap smaller than the window is requested in full (no truncation, no over-request)"
  );
}

#[test]
fn fresh_endpoint_log_view_is_zero() {
  let e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    99,
    NoopSm,
  );
  assert_eq!(e.log_view(), View::new());
  assert_eq!(e.status(), Status::Normal);
}

#[test]
fn commit_max_tracks_learned_commit_above_applied() {
  // A backup that hears commit=5 but only holds op 2 records commit_max=5, commit_min=2.
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
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(2, 5),
  ); // primary says commit=5, we have op 2
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "commit_min only advances over ops we hold"
  );
  assert_eq!(
    e.commit_max(),
    OpNumber::with(5),
    "commit_max records the learned commit"
  );
}

#[test]
fn backup_acks_only_after_append_is_durable() {
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
  assert!(
    e.poll_message().is_none(),
    "no PrepareOk before the append is durable"
  );
  assert_eq!(
    wal.op_head(),
    OpNumber::with(1),
    "the prepare was submitted to the WAL"
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  match e
    .poll_message()
    .expect("PrepareOk after durable")
    .into_msg()
  {
    Message::PrepareOk(ok) => assert_eq!(ok.op(), OpNumber::with(1)),
    _ => panic!("expected PrepareOk"),
  }
}

#[test]
fn reack_suppressed_for_committed_op_not_durably_appended_locally() {
  // REGRESSION (append-before-ack): the `pop <= self.op` re-ack branch must consult the WAL
  // for durability, NOT just the `appending` set. A view change / catch-up clears `appending` (to
  // keep it in lockstep with `pending`); with an ASYNC WAL an append abandoned in the old generation
  // is still in flight, and once that op is COMMITTED (commit_min advances past it) the view-change
  // re-append range `(commit_min+1 ..= op]` never re-marks it. So `appending` is empty for an op the
  // replica has NOT durably appended — and a retransmitted current-view Prepare(pop) would re-ack it,
  // claiming a durability this replica does not have (it could lose the op on crash). We reproduce
  // that exact divergent state directly: op 5 committed + at the head, but ABSENT from the WAL (a
  // not-yet-durable slot, exactly like an in-flight async append) and not in `appending`.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // view 0 (primary is replica 0, so replica 2 is a backup), op 5 = commit_min (committed + at head),
  // checkpoint_op 0, no repair holes. `appending` is empty (fresh) and the WAL holds nothing — the
  // post-async-view-change divergence where op 5's local append never became durable.
  e.force_state_for_test(
    /*view*/ 0,
    /*op*/ 5,
    /*commit_min*/ 5,
    /*checkpoint_op*/ 0,
    &[],
  );
  // Seed op 5 in the dense `log` cache with its CANONICAL identity (client 7, request 5, body [5]) —
  // matching the `prepare(5, 5)` retransmit below. In real operation a committed op AT the head is
  // ALWAYS in the dense cache (`append_prepare` inserts it; `enter_view_change` clears `pending`/
  // `appending`/the WAL-in-flight mark but NOT `self.log`), even when its async WAL append was abandoned
  // — `force_state_for_test` just omits it. The re-ack identity gate reads this entry to prove the
  // replica holds the canonical body; the WAL-durability gate (this test's subject) then decides whether
  // to ack. (Without the entry the re-ack would mis-classify a durable committed op as a dropped hole.)
  e.log.insert(
    5,
    LogEntry::present(
      ClientId::new(7),
      RequestNumber::with(5),
      Bytes::copy_from_slice(&[5u8]),
    ),
  );
  assert_eq!(
    wal.status(OpNumber::with(5)),
    SlotStatus::Empty,
    "precondition: op 5 not durable"
  );

  // The primary RETRANSMITS the current-view Prepare(5) (its PREPARE_RETRANSMIT). pop=5 <= self.op=5
  // → the re-ack branch. It must NOT ack: op 5 is not durably appended on THIS replica.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(5, 5),
  );
  let mut premature = 0;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.into_msg()
      && ok.op() == OpNumber::with(5)
    {
      premature += 1;
    }
  }
  assert_eq!(
    premature, 0,
    "append-before-ack: must not re-ack op 5 while it is not durably appended locally (pre-fix the \
     `appending`-only guard let this through → premature PrepareOk(5))"
  );

  // Legitimacy check: once op 5 IS durably appended locally, the same retransmitted Prepare(5) DOES
  // re-ack it — the fix suppresses only the non-durable case, preserving lost-PrepareOk recovery.
  let h = Header::new(
    OpNumber::with(5),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(5),
    &[5u8],
  );
  wal.submit_append(
    OpId::new(5),
    OpNumber::with(5),
    h,
    Bytes::copy_from_slice(&[5u8]),
  );
  let _ = wal.poll(); // TestWal is synchronous: op 5 is now durable (Clean).
  assert_eq!(wal.status(OpNumber::with(5)), SlotStatus::Clean);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(5, 5),
  );
  let mut reacked = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.into_msg()
      && ok.op() == OpNumber::with(5)
    {
      reacked = true;
    }
  }
  assert!(
    reacked,
    "a durable committed op is still re-acked on retransmit (legitimate lost-PrepareOk recovery)"
  );
}

#[test]
fn on_request_is_dropped_while_a_sync_or_checkpoint_persist_is_in_flight() {
  // DEFENSE: a primary must NOT serve a client while a state-sync OR a checkpoint-persist is
  // in flight — either can reset `self.op` (a sync via `apply_sync`; a checkpoint completion advances
  // checkpoint_op + GCs), so assigning a new request an op now risks op-number reuse. Both an
  // outstanding `sync` and an outstanding `pending_checkpoint` must short-circuit `on_request`.
  let serve = |arm: fn(&mut Endpoint<NoopSm>)| -> bool {
    let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
    let mut ep = Endpoint::new(cfg, genesis(3), 7, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    let mut blocks = crate::block_store::MemBlockStore::new();
    assert!(ep.is_primary());
    let head_before = ep.op();
    arm(&mut ep);
    ep.handle_message(
      Instant::ZERO,
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
    ep.op() != head_before // true ⇒ the request was served (op advanced)
  };
  // With a sync outstanding → dropped (op does not advance).
  assert!(
    !serve(|ep| ep.arm_forced_sync_for_test(0)),
    "a request is dropped while a state-sync is outstanding (op-reset risk)"
  );
  // With a checkpoint-persist staged → dropped.
  assert!(
    !serve(|ep| ep.stage_pending_checkpoint_for_test()),
    "a request is dropped while a checkpoint-persist is in flight (op-reset risk)"
  );
  // Control: a clean primary (nothing in flight) DOES serve the request (op advances) — proving the
  // guard is specific to the in-flight-reset states, not a blanket block.
  assert!(
    serve(|_| {}),
    "a clean primary serves the request (the guard does not over-block)"
  );
}

#[test]
fn on_request_waits_for_the_committed_prefix_to_apply_before_serving_clients() {
  // SAFETY (at-most-once / sessions-caught-up): a primary must NOT assign a fresh op to a client while
  // its committed prefix is unapplied (`commit_max > commit_min` — a committed op is KNOWN but held by
  // a repair hole). The session/dedup table (`self.clients`) is only updated as ops APPLY, so during
  // the gap a just-committed client request is ABSENT from the table → a retry would be mis-seen as NEW
  // and assigned an op ABOVE the gap → when the hole fills, the apply loop (which has no dedup) would
  // execute BOTH the original AND the duplicate → divergence. The primary must catch up first; the
  // client retries.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 8).unwrap();
  let mut ep = Endpoint::new(cfg, genesis(3), 7, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  // Primary holding a committed-op GAP: head op 4, commit HELD at 1 by a hole at op 2, but commit_max
  // = 4 (ops 2..=4 are known committed cluster-wide, merely unapplied here). Ops 3 + 4 are present in
  // the log; only op 2 is the unreadable hole. (`force_state_for_test` raises commit_max to cover the
  // op-2 hole; raise it further to 4 to model the full known-but-unapplied committed suffix.)
  ep.force_state_for_test(0, 4, 1, 0, &[2]);
  ep.commit_max = OpNumber::with(4);
  for op in [3u64, 4u64] {
    ep.log.insert(
      op,
      LogEntry::present(
        ClientId::new(7),
        RequestNumber::with(op),
        Bytes::copy_from_slice(&[op as u8]),
      ),
    );
  }
  assert!(ep.is_primary());
  assert!(
    ep.commit_max().get() > ep.commit().get(),
    "precondition: a committed op is known but not yet applied (commit_max > commit_min)"
  );
  let head_before = ep.op();

  // A FRESH client request (client 9, request 1) arrives DURING the gap → must be DROPPED: no Prepare,
  // no Reply, and the head op does NOT advance (no fresh op assigned that could later double-execute).
  ep.handle_message(
    Instant::ZERO,
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
  assert_eq!(
    ep.op(),
    head_before,
    "no fresh op is assigned while the committed prefix is unapplied (sessions stale)"
  );
  assert!(
    ep.poll_message().is_none(),
    "no Prepare and no Reply is emitted during the committed gap"
  );

  // Close the gap: the hole at op 2 is filled (a vouching repair Prepare, commit >= op), so once the
  // repaired append is DURABLE (the durability barrier) `advance_commit` applies ops 2,3,4 in order →
  // commit_min catches up to commit_max == 4, and the repair set empties.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    repair_prepare(0, 2, 4),
  );
  ep.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // the repaired append completes → apply the suffix
  assert_eq!(
    ep.commit(),
    OpNumber::with(4),
    "the gap closed: the committed prefix is fully applied (commit_min == commit_max)"
  );
  assert!(
    !ep.has_repair_hole_for_test(2),
    "the repair hole is cleared once the committed value fills it"
  );
  while ep.poll_message().is_some() {} // discard catch-up output (Committed/etc.)

  // Now the SAME fresh request IS served — the primary assigns it a fresh op and broadcasts a Prepare.
  ep.handle_message(
    Instant::ZERO,
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
  assert!(
    ep.op().get() > head_before.get(),
    "once the committed prefix is applied, the primary serves the request (op advances)"
  );
  let mut saw_prepare = false;
  while let Some(out) = ep.poll_message() {
    if let Message::Prepare(p) = out.msg_ref() {
      assert!(
        p.op().get() > 4,
        "the served request lands at a fresh op above the (now-applied) committed prefix"
      );
      saw_prepare = true;
    }
  }
  assert!(
    saw_prepare,
    "the primary broadcasts a Prepare for the request once it has caught up"
  );
}

#[test]
fn op_admission_stalls_when_the_header_only_carrier_band_would_exceed_the_frame_fit_depth() {
  // Release-build frame-fit floor for the header-only view-change carriers. The carriers
  // (`DoViewChange`/`StartView`/`RecoveryResponse`) emit `log_entries()` — EVERY retained `self.log`
  // op, header-only, with NO range filter — as one HEADER-ONLY band. A band past
  // `MAX_HEADER_ONLY_BAND_DEPTH` encodes a carrier OVER the transport frame cap, which the transport
  // drops on the send path, wedging the view change. `MAX_CHECKPOINT_OPS` + the `log_entries()`
  // `debug_assert` already bound this for a ring-sized WAL, but a backend whose OWN ring exceeds the
  // band depth (its wal-wrap stall sits above it) with a deep uncommitted tail could grow the band past
  // the bound in a release build. So op-admission must REFUSE to mint a new op the instant its carrier
  // band would exceed the depth — the same backpressure as the wal-wrap stall, gating the carrier
  // instead of the ring.
  //
  // The gate bounds the ACTUAL carrier (`self.log.len()`), NOT a `next_op - prune_floor` proxy: the
  // carrier is the retained log, and `prune_floor` can advance ahead of an actual `self.log` trim (a
  // quorum checkpoint REPORT raises it without a local `run_gc`), so the proxy can under-count. Here we
  // SEED `self.log` to the band depth so the realized carrier is exactly what the gate reads.
  //
  // The WAL is a backend with its OWN ring larger than the band depth (`capacity = depth + 8`), so the
  // wal-wrap stall is OUT of the picture and any refusal is the band bound alone. (A RING-LESS backend
  // cannot reach this edge any more: the proto-imposed ring — a few checkpoint intervals + the pipeline,
  // far below the ~342k band depth — stalls admission first. The band gate remains the only guard for a
  // backend whose genuine ring exceeds the band depth, which is what this pins.)
  let depth = crate::message::MAX_HEADER_ONLY_BAND_DEPTH as u64;
  let body = bytes::Bytes::from(std::vec![1u8]);

  // (a) JUST BELOW the bound: head at `depth - 1` with `self.log` holding `[1..=depth-1]` (so the
  // carrier is `depth - 1` entries). Minting `next_op == depth` grows the retained band to exactly
  // `depth` entries — at/below `MAX_HEADER_ONLY_BAND_DEPTH`, so admission SUCCEEDS. Proves the bound
  // does not perturb normal admission right up to the edge (the band is huge — ~342k — so a real
  // in-flight band never reaches it; this is a release-build floor, not a normal-path limit).
  {
    let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 8).unwrap();
    let mut ep = Endpoint::new(cfg, genesis(3), 7, NoopSm);
    let mut wal = ScriptedWal::with_entries(0);
    wal.capacity = depth + 8; // the backend's own ring, above the band depth
    let mut sb = TestSb::default();
    let mut blocks = crate::block_store::MemBlockStore::new();
    let head = depth - 1;
    ep.force_state_for_test(0, head, head, 0, &[]); // commit_min == op (caught up), no holes
    for op in 1..=head {
      ep.log.insert(
        op,
        LogEntry::present(ClientId::new(7), RequestNumber::with(op), body.clone()),
      );
    }
    assert_eq!(
      ep.log.len() as u64,
      head,
      "the retained carrier is `depth - 1` entries"
    );
    assert!(ep.is_primary());
    // A fresh client (no prior session) — `on_request`'s `entry(key).or_default()` seeds request 0, so
    // request 1 is the canonical next request and is admitted (subject only to the band bound).
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(9)),
      Message::Request(Request::new(
        ClientId::new(9),
        RequestNumber::with(1),
        body.clone(),
      )),
    );
    assert_eq!(
      ep.op().get(),
      depth,
      "a band of exactly MAX_HEADER_ONLY_BAND_DEPTH entries is admitted (the bound is the ceiling, \
       not below it) — op advances to {depth}"
    );
    assert_eq!(
      ep.log.len() as u64,
      depth,
      "the realized carrier is now exactly at the frame-fit ceiling"
    );
    assert_eq!(ep.wal_stalls(), 0, "no admission stall at the bound");
    assert!(
      ep.poll_message()
        .map(|o| matches!(o.into_msg(), Message::Prepare(_)))
        .unwrap_or(false),
      "the admitted op is broadcast as a Prepare"
    );
  }

  // (b) AT the bound: head at `depth` with `self.log` holding `[1..=depth]` (the carrier is exactly
  // `depth` entries). Minting `next_op == depth + 1` would grow the retained band to `depth + 1`
  // entries — OVER `MAX_HEADER_ONLY_BAND_DEPTH`, whose carrier would exceed the frame cap. Admission
  // must STALL: the op does NOT advance, no Prepare is emitted, and the stall counter ticks —
  // backpressure before an oversized header-only carrier could ever be minted.
  {
    let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 8).unwrap();
    let mut ep = Endpoint::new(cfg, genesis(3), 7, NoopSm);
    let mut wal = ScriptedWal::with_entries(0);
    wal.capacity = depth + 8; // the backend's own ring, above the band depth
    let mut sb = TestSb::default();
    let mut blocks = crate::block_store::MemBlockStore::new();
    ep.force_state_for_test(0, depth, depth, 0, &[]); // head exactly at the bound, caught up, no holes
    for op in 1..=depth {
      ep.log.insert(
        op,
        LogEntry::present(ClientId::new(7), RequestNumber::with(op), body.clone()),
      );
    }
    assert_eq!(
      ep.log.len() as u64,
      depth,
      "the retained carrier sits exactly at the frame-fit ceiling"
    );
    assert!(ep.is_primary());
    let head_before = ep.op();
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(9)),
      Message::Request(Request::new(
        ClientId::new(9),
        RequestNumber::with(1),
        body.clone(),
      )),
    );
    assert_eq!(
      ep.op(),
      head_before,
      "no op is minted when its header-only carrier band would exceed the frame-fit depth"
    );
    assert_eq!(
      ep.wal_stalls(),
      1,
      "the admission stall engaged (the carrier-band backpressure, not a wal wrap — capacity is u64::MAX)"
    );
    assert!(
      ep.poll_message().is_none(),
      "no Prepare is emitted for the refused op (the band would overflow the frame)"
    );
  }
}

#[test]
fn a_quorum_checkpoint_report_advances_prune_floor_without_a_gc_trim_yet_the_carrier_fits_the_frame()
 {
  // The RELEASE gap the actual-carrier gate closes. The view-change carriers
  // (`DoViewChange`/`StartView`/`RecoveryResponse`) encode `log_entries()` — EVERY retained `self.log`
  // op, header-only, with NO range filter — so the real carrier-entry count is `self.log.len()`. A
  // release gate on the `next_op - prune_floor()` PROXY would miss it: `prune_floor()` advances the
  // instant a quorum checkpoint REPORT raises `quorum_checkpoint_op()`, while `self.log` is trimmed
  // only by a LOCAL checkpoint's `run_gc`. So a peer report can shrink the proxy BELOW the true
  // retained span (GC lag) — leaving the proxy within bound while the ACTUAL carrier exceeds
  // `MAX_FRAME_LEN`, which the transport then drops on the send path → a wedged view change in a
  // release build.
  use crate::message::{MAX_FRAME_LEN, MAX_HEADER_ONLY_BAND_DEPTH};
  let cap = MAX_FRAME_LEN as usize;
  let depth = MAX_HEADER_ONLY_BAND_DEPTH;

  // A Normal primary (replica 0 of 3, view 0 — replica 0 leads it) whose in-memory log holds the FULL
  // band `[1..=depth]` — exactly at the frame-fit ceiling. This is the state a primary reaches by
  // appending a deep tail before any local checkpoint lands.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  e.op = OpNumber::with(depth as u64);
  e.commit_min = OpNumber::with(depth as u64);
  e.sm_at = e.commit_min; // hand-built state: the SM is modelled as applied through commit_min
  e.commit_max = OpNumber::with(depth as u64);
  let body = bytes::Bytes::from(std::vec![0x5Au8; 8]);
  for op in 1..=depth as u64 {
    e.log.insert(
      op,
      LogEntry::present(ClientId::new(7), RequestNumber::with(op), body.clone()),
    );
  }
  assert_eq!(
    e.log.len(),
    depth,
    "the band sits exactly at the frame-fit ceiling"
  );

  // A QUORUM checkpoint REPORT advances the prune floor WITHOUT trimming `self.log` (no local
  // checkpoint ran, so no `run_gc`). Model the report via the exact mechanism a `Commit`/`PrepareOk`
  // uses — `record_peer_checkpoint` — for a quorum (self + one peer) at a HIGH checkpoint op.
  let high = depth as u64 - 1;
  e.record_peer_checkpoint(ReplicaId::new(1), OpNumber::with(high));
  // self's own report (quorum of 2-of-3 now at `high`); the helper keeps the log_floor coupling AND
  // the cached quorum statistic coherent, as a real checkpoint advance would.
  e.set_own_checkpoint_for_test(high);
  // The `next_op - prune_floor()` PROXY is now WAY below the bound …
  let proxy = e
    .op()
    .get()
    .saturating_add(1)
    .saturating_sub(e.prune_floor().get());
  assert!(
    proxy < depth as u64,
    "the quorum report shrank the next_op - prune_floor proxy below the bound (proxy={proxy}), \
     yet `self.log` is untrimmed — the GC-lag gap the proxy missed"
  );
  // … while the ACTUAL retained carrier is still the whole `depth`-entry band.
  assert_eq!(
    e.log.len(),
    depth,
    "self.log is NOT trimmed by a mere peer report (GC lag)"
  );

  // The real DVC carrier the primary would build encodes UNDER the frame cap — the actual-carrier
  // gate held the band at the ceiling, so even with the proxy fooled the carrier fits.
  let dvc = Message::DoViewChange(crate::DoViewChange::new(
    e.view,
    e.log_view,
    e.op,
    e.commit_max,
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    e.log_entries(),
  ));
  let n = encode_message(&dvc).len();
  assert!(
    n <= cap,
    "the header-only DoViewChange carrier must fit the frame cap: {n} > {cap}"
  );

  // And the gate FIRES on the actual count: a fresh client request is REFUSED (no op minted, the stall
  // counter ticks), because admitting it would push the carrier to `depth + 1` entries — over the
  // frame. The unbounded `TestWal` (`capacity() == u64::MAX`) rules out the WAL-wrap stall, so this is
  // the carrier-band backpressure alone.
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let head_before = e.op();
  let stalls_before = e.wal_stalls();
  e.handle_message(
    Instant::ZERO,
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
  assert_eq!(
    e.op(),
    head_before,
    "op-admission stalls on the ACTUAL carrier count even though the prune-floor proxy is within bound"
  );
  assert_eq!(
    e.wal_stalls(),
    stalls_before + 1,
    "the carrier-band backpressure engaged (not a WAL wrap — capacity is u64::MAX)"
  );
}

#[test]
fn a_backup_whose_checkpoint_lags_while_it_accepts_prepares_keeps_its_carrier_under_the_frame() {
  // The BACKUP side of the band gate: a backup extends its head via `on_prepare`, so it needs the
  // same carrier bound as the primary's `on_request`. Without one, a backup on an UNBOUNDED WAL (so
  // the ring-window stall never fires) that keeps accepting head-extending prepares while its
  // checkpoint/GC lags grows `self.log` without bound, and its DVC / RecoveryResponse carrier
  // (`log_entries()`) with it — past `MAX_FRAME_LEN`, then dropped on the send path → a wedge if a
  // view change collects this backup.
  use crate::message::{MAX_FRAME_LEN, MAX_HEADER_ONLY_BAND_DEPTH};
  let cap = MAX_FRAME_LEN as usize;
  let depth = MAX_HEADER_ONLY_BAND_DEPTH;

  // A Normal backup (replica 1 of 3, view 0, primary is replica 0) sitting exactly at the frame-fit
  // ceiling: head at `depth`, checkpoint lagging at 0 (no local checkpoint yet), the whole band held.
  // This is the state reached by accepting a deep prepare tail before any checkpoint lands.
  let mut e = backup();
  e.op = OpNumber::with(depth as u64);
  e.commit_min = OpNumber::with(depth as u64);
  e.sm_at = e.commit_min; // hand-built state: the SM is modelled as applied through commit_min
  e.commit_max = OpNumber::with(depth as u64);
  let body = bytes::Bytes::from(std::vec![0x5Au8; 8]);
  for op in 1..=depth as u64 {
    e.log.insert(
      op,
      LogEntry::present(ClientId::new(7), RequestNumber::with(op), body.clone()),
    );
  }
  assert_eq!(e.log.len(), depth);
  assert!(!e.is_primary());

  // The next head-extending Prepare (`pop == self.op + 1`) is REFUSED by the carrier-band gate: the
  // head does NOT advance and nothing is appended, because growing to `depth + 1` retained entries
  // would push the DVC carrier over the frame. `TestWal` is unbounded, so the ring-window stall is out
  // of the picture — this is the band backpressure alone.
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let head_before = e.op();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(depth as u64 + 1, 0),
  );
  assert_eq!(
    e.op(),
    head_before,
    "the backup refuses to extend its head past the carrier-band frame-fit depth"
  );
  assert!(
    !e.log.contains_key(&(depth as u64 + 1)),
    "no over-cap op was appended to the backup's log"
  );

  // The DVC carrier this lagging backup would answer a view change with still fits the frame.
  let dvc = Message::DoViewChange(crate::DoViewChange::new(
    e.view,
    e.log_view,
    e.op,
    e.commit_max,
    crate::Epoch::new(0),
    0,
    ReplicaId::new(1),
    e.log_entries(),
  ));
  let n = encode_message(&dvc).len();
  assert!(
    n <= cap,
    "the lagging backup's header-only DoViewChange carrier must fit the frame cap: {n} > {cap}"
  );
  // The recovery-answer carrier is the same `log_entries()` band — also frame-bounded.
  let rr = Message::RecoveryResponse(crate::RecoveryResponse::new(
    e.view,
    e.op,
    e.commit_max,
    crate::Epoch::new(0),
    0,
    ReplicaId::new(1),
    0xC0FFEE,
    e.log_entries(),
  ));
  let nr = encode_message(&rr).len();
  assert!(
    nr <= cap,
    "the lagging backup's RecoveryResponse carrier must fit the frame cap: {nr} > {cap}"
  );
}

#[test]
fn commit_holds_at_a_body_repairing_entry_and_solicits_the_body() {
  // A body-`Repairing` log entry — the op EXISTS (its identity + durable body_checksum survived a
  // torn-body fault) but its bytes are absent — must be treated by the commit path EXACTLY like a
  // wholly-missing slot: HOLD the commit at it (never apply over an absent body) and solicit the body
  // from a peer (`RequestPrepare`). This is the safety the otherwise-untested `Body::Repairing` apply
  // arm rests on. (`recover` now produces such entries for body-faulty committed ops; this seeds one
  // directly to isolate the commit-path apply arm.)
  let mut e = backup(); // replica 1 of 3, view 0 (primary is replica 0)
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Head op 1, nothing applied yet, op 1 present in the log as a body-ABSENT `Repairing` slot carrying
  // only op 1's canonical body_checksum (the bytes did not survive).
  e.op = OpNumber::with(1);
  e.log.insert(
    1,
    LogEntry {
      client: ClientId::new(7),
      request: RequestNumber::with(1),
      body: Body::Repairing(crate::storage::fnv1a_128(&[1u8])),
    },
  );
  assert!(
    !e.has_repair_hole_for_test(1),
    "precondition: op 1 is not yet a tracked repair hole"
  );

  // The primary announces commit=1. `on_commit` → `advance_commit(target=1)` reaches op 1, finds its
  // body absent, and must HOLD: commit_min stays 0, op 1 is registered for peer fault-repair, and a
  // RequestPrepare(op 1) is solicited.
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
  assert_eq!(
    e.commit(),
    OpNumber::with(0),
    "the commit is HELD at the body-Repairing entry (op 1 not applied over an absent body)"
  );
  assert!(
    e.has_repair_hole_for_test(1),
    "op 1 is registered for peer fault-repair (the absent body is solicited, not skipped)"
  );
  let mut solicited = false;
  while let Some(out) = e.poll_message() {
    // The hole arm solicits the contiguous run via the windowed `RequestPrepareRange` (here a
    // single-op range `[1,1]`, since `commit_max == 1` caps the band) rather than a per-op `RequestPrepare`.
    if let Message::RequestPrepareRange(rp) = out.msg_ref()
      && rp.lo() <= OpNumber::with(1)
      && rp.hi() >= OpNumber::with(1)
    {
      solicited = true;
    }
  }
  assert!(
    solicited,
    "a RequestPrepareRange covering op 1 is emitted to fetch the missing body — the windowed missing-slot behavior"
  );

  // The repair Prepare answers with op 1's real body: once its append is durable, the held commit
  // resumes and op 1 applies (commit_min reaches 1), proving the hold was a genuine pause, not a loss.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    repair_prepare(0, 1, 1),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the repaired append completes → apply op 1
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "once the body is repaired + durable, the held commit applies op 1"
  );
  assert!(
    !e.has_repair_hole_for_test(1),
    "the repair hole clears once the canonical body fills it"
  );
}

#[test]
fn on_prepare_ok_counts_a_vote_only_when_the_full_operation_identity_matches() {
  // CONSENSUS-CRITICAL: votes are content-addressed by the FULL operation identity (op, client, request,
  // body_checksum), NOT the body alone. A PrepareOk for op N counts toward op N's quorum ONLY if it
  // carries the identity of the operation the primary is driving at op N. This closes the SAME-BODY
  // op-reuse hole that body_checksum alone left open: two DISTINCT operations can share body bytes (same
  // body_checksum) yet differ in (client, request), so a stale ack for an op number that was truncated
  // and re-minted for a DIFFERENT request — even one with identical body bytes — must NOT be counted.
  let cfg = Config::try_new(1, MemberId::new(0)).expect("valid cluster config");
  let mut e = Endpoint::new(cfg, genesis(3), 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  assert!(e.is_primary(), "replica 0 is primary of view 0");
  let now = Instant::ZERO;

  // The primary serves client 9's request 1 (body [1]) → mints op 1, seeding inflight[1] with that
  // OPERATION's identity. Pump storage so the durable own append records the primary's own vote.
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
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the clean primary serves the request — op 1 is minted"
  );
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the own append lands → the primary's own vote
  }
  let own_bit = 1u64 << 0; // replica 0
  assert_eq!(
    e.inflight.get(&1).map(|i| i.oks),
    Some(own_bit),
    "after the durable append op 1 carries only the primary's own vote"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(0),
    "the own vote alone is below quorum (2)"
  );

  // The identity the primary is driving at op 1 (client 9, request 1, body [1]). A DIFFERENT operation —
  // client 7's request 1 — that happens to carry the SAME body bytes [1] has the SAME body_checksum but
  // a DIFFERENT identity: exactly the collision body_checksum-only voting could not tell apart.
  let body = crate::storage::fnv1a_128(&[1u8]);
  let driven = crate::storage::prepare_identity(ClientId::new(9), RequestNumber::with(1), body);
  let same_body_other_op =
    crate::storage::prepare_identity(ClientId::new(7), RequestNumber::with(1), body);
  assert_ne!(
    driven, same_body_other_op,
    "same body bytes, different client → DIFFERENT operation identity (the hole body_checksum left open)"
  );

  // A backup ack for op 1 carrying a DIFFERENT operation's identity — even with the SAME body bytes — is
  // REJECTED. (With body_checksum-only voting its checksum would have MATCHED and forged a quorum.)
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
      same_body_other_op,
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.inflight.get(&1).map(|i| i.oks),
    Some(own_bit),
    "the same-body different-operation ack left the vote bitset unchanged — dropped, not counted"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(0),
    "a same-body ack for a DIFFERENT operation does not commit op 1 (full-identity votes reject it)"
  );

  // The SAME backup acking op 1 with the MATCHING operation identity counts → own + backup = quorum.
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
      driven,
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the matching-identity ack counts — op 1 commits on the content-addressed quorum"
  );
}

// ── Forfeit — a lagging primary steps down via a view change ────────────────────────────────────

#[test]
fn backup_reorder_buffer_is_bounded_to_the_tail_gap_window() {
  // The reorder buffer holds frame-sized bodies, so it must not grow on arbitrary far-future
  // Prepares: only an op within TAIL_GAP_WINDOW of the head is buffered; anything further is
  // DROPPED (the primary's retransmit redelivers it once the head closes the gap — the same
  // backpressure shape as the ring stall), so a buggy primary emitting sparse high-op Prepares
  // cannot grow the buffer without bound.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Head is 0. An op just past the window is NOT retained...
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(TAIL_GAP_WINDOW + 1, 0),
  );
  assert_eq!(
    e.buffer_len_for_test(),
    0,
    "a beyond-window Prepare is dropped, not buffered"
  );
  // ...while one at the window edge (and an interior one) is.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(TAIL_GAP_WINDOW, 0),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(2, 0),
  );
  assert_eq!(
    e.buffer_len_for_test(),
    2,
    "within-window Prepares are buffered"
  );
  assert_eq!(e.op(), OpNumber::with(0), "the head has not moved");
}

#[test]
fn a_faulted_append_completion_retries_and_the_op_still_acks() {
  // The `Wal` contract requires an append to complete as `Appended` — but a backend that surfaces
  // a `Fault` for one anyway must not LEAK the op's in-flight bookkeeping (the `Pending` entry +
  // `appending` mark would otherwise linger until the next view transition: the op could never be
  // re-acked and `has_inflight_storage()` would read true forever). The endpoint degrades the
  // violation to a RETRY: the fault re-submits the same append from the held entry, and the
  // deferred ack follows the retried append's completion.
  let mut wal = ScriptedWal::with_entries(0);
  wal.script_append_fault(OpNumber::with(1), 1); // the first append of op 1 faults; the retry lands
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut e = backup();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare(1, 0),
  );
  assert_eq!(
    wal.append_submits(OpNumber::with(1)),
    1,
    "the prepare submitted its append"
  );
  // Drain: the Fault completion re-submits the append; its Appended completion then acks.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    wal.append_submits(OpNumber::with(1)),
    2,
    "the faulted append was re-submitted"
  );
  let mut acked = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.msg_ref() {
      assert_eq!(ok.op(), OpNumber::with(1));
      acked = true;
    }
  }
  assert!(acked, "the op still acks once the retried append lands");
  assert!(
    !e.has_inflight_storage(),
    "no in-flight bookkeeping leaks after the retry resolves"
  );
}

/// Drive `n` distinct clients (ids `1..=n`, each submitting its request 1 with body `[id]`) through
/// COMMIT on a SOLO PRIMARY (quorum 1: each op commits via `commit_op` the moment its append lands) —
/// the primary-path half of the session-eviction determinism proof. Returns the endpoint with every
/// op applied.
fn solo_primary_with_clients(cap: u32, n: u64) -> (Endpoint<EchoSm>, TestWal, TestSb) {
  let cfg = Config::try_new(1, MemberId::new(0))
    .unwrap()
    .with_max_client_sessions(cap)
    .unwrap();
  let mut e = Endpoint::new(cfg, genesis(1), 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  for c in 1..=n {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(c as u128)),
      Message::Request(Request::new(
        ClientId::new(c as u128),
        RequestNumber::with(1),
        Bytes::from(std::vec![c as u8]),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // append lands → own vote → commit_op applies op c
    assert_eq!(e.commit().get(), c, "the solo primary committed op {c}");
  }
  (e, wal, sb)
}

/// Drive the SAME op stream (op `c` = client `c`, request 1, body `[c]`) through a BACKUP's
/// `on_prepare` + `advance_commit` apply path — the backup-path half of the determinism proof.
fn backup_with_clients(cap: u32, n: u64) -> (Endpoint<EchoSm>, TestWal, TestSb) {
  let cfg = Config::try_new(1, MemberId::new(1))
    .unwrap()
    .with_max_client_sessions(cap)
    .unwrap();
  let mut e = Endpoint::new(cfg, genesis(2), 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let from = Peer::Replica(ReplicaId::new(0)); // the view-0 primary of the 2-replica cluster
  for c in 1..=n {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      from,
      Message::Prepare(Prepare::new(
        View::new(),
        OpNumber::with(c),
        OpNumber::with(c - 1),
        OpNumber::new(),
        crate::Epoch::new(0),
        0,
        ClientId::new(c as u128),
        RequestNumber::with(1),
        Bytes::from(std::vec![c as u8]),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // append lands → PrepareOk
  }
  // The final commit advance applies op n.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    from,
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(n),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.commit().get(), n, "the backup applied through op {n}");
  (e, wal, sb)
}

#[test]
fn session_eviction_is_replica_deterministic_across_primary_and_backup_paths() {
  // THE determinism proof for the apply-time session-cap eviction: the SAME applied op stream — 7
  // distinct clients through a cap of 4 — driven through the PRIMARY apply path (`commit_op`, on a
  // solo primary) and the BACKUP apply path (`advance_commit`) must yield IDENTICAL session tables,
  // IDENTICAL eviction counts, and byte-IDENTICAL checkpoint envelopes (the table rides every
  // envelope, so divergent eviction would diverge checkpoint ids — state-sync chaos).
  let (cap, n) = (4u32, 7u64);
  let (p, _, _) = solo_primary_with_clients(cap, n);
  let (b, _, _) = backup_with_clients(cap, n);

  // Both evicted the same number of sessions (7 clients into 4 slots → 3 evictions)…
  assert_eq!(p.sessions_evicted(), 3, "primary path evicted 7 - 4 = 3");
  assert_eq!(b.sessions_evicted(), 3, "backup path evicted 7 - 4 = 3");
  // …the surviving tables are identical, with the OLDEST-activity sessions (clients 1..=3, applied
  // at ops 1..=3) evicted and the 4 freshest retained, each stamped with its applied op…
  let expect: std::vec::Vec<(u128, u64, u64)> =
    (4..=7).map(|c| (c as u128, 1u64, c as u64)).collect();
  assert_eq!(p.sessions_snapshot_for_test(), expect);
  assert_eq!(b.sessions_snapshot_for_test(), expect);
  // …and the checkpoint envelopes both replicas would encode are byte-identical (identical
  // checkpoint ids for the same checkpoint op): identical session tables produce the same
  // content-addressed `sessions_root`, hence the same envelope and id.
  let mut pstore = crate::block_store::MemBlockStore::new();
  let mut bstore = crate::block_store::MemBlockStore::new();
  let pe = p.encode_sessions_envelope_for_test(n, &mut pstore);
  let be = b.encode_sessions_envelope_for_test(n, &mut bstore);
  assert_eq!(pe, be, "identical tables encode byte-identical envelopes");
  assert_eq!(crate::checkpoint_id(&pe), crate::checkpoint_id(&be));
}

#[test]
fn session_table_never_exceeds_the_cap_and_victims_are_oldest_first() {
  // Drive 3× the cap through the backup apply path, asserting after EVERY apply that the APPLIED
  // session count never exceeds the cap (the eviction is immediate, not amortized).
  let cap = 4u32;
  let cfg = Config::try_new(1, MemberId::new(1))
    .unwrap()
    .with_max_client_sessions(cap)
    .unwrap();
  let mut e = Endpoint::new(cfg, genesis(2), 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let from = Peer::Replica(ReplicaId::new(0));
  for c in 1..=(3 * cap as u64) {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      from,
      Message::Prepare(Prepare::new(
        View::new(),
        OpNumber::with(c),
        OpNumber::with(c.saturating_sub(1)),
        OpNumber::new(),
        crate::Epoch::new(0),
        0,
        ClientId::new(c as u128),
        RequestNumber::with(1),
        Bytes::from_static(b"x"),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    let applied = e
      .sessions_snapshot_for_test()
      .iter()
      .filter(|(_, _, last_op)| *last_op > 0)
      .count();
    assert!(
      applied <= cap as usize,
      "applied sessions ({applied}) exceeded the cap ({cap}) after op {c}"
    );
  }
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    from,
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3 * cap as u64),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  // The survivors are exactly the `cap` most-recently-applied clients.
  let survivors: std::vec::Vec<u128> = e
    .sessions_snapshot_for_test()
    .iter()
    .map(|(c, _, _)| *c)
    .collect();
  let expect: std::vec::Vec<u128> = ((2 * cap as u128 + 1)..=(3 * cap as u128)).collect();
  assert_eq!(
    survivors, expect,
    "the oldest-activity sessions were evicted first"
  );
  assert_eq!(e.sessions_evicted(), 2 * cap as u64);
}

#[test]
fn an_evicted_client_returns_as_a_fresh_session_only_from_request_one() {
  // The evicted-client contract on MAX_CLIENT_SESSIONS: an evicted client's dedup history is gone —
  // a resume of its old numbering is silently dropped (no session, request != 1), while a
  // RE-REGISTRATION from request 1 opens a fresh session (which is also what un-wedges a client
  // that restarted with a lost request counter once its stale row ages out).
  let (mut e, mut wal, mut sb) = solo_primary_with_clients(2, 3); // cap 2: client 1 was evicted
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  assert_eq!(e.session_request_for_test(1), None, "client 1 was evicted");

  // Client 1 resumes its OLD numbering (request 2) → unknown client + request != 1 → silent drop.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(1)),
    Message::Request(Request::new(
      ClientId::new(1),
      RequestNumber::with(2),
      Bytes::from_static(b"resume"),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.op().get(), 3, "a resumed evicted numbering mints no op");
  assert_eq!(
    e.session_request_for_test(1),
    None,
    "and mints no session row"
  );

  // Client 1 re-registers from request 1 → a FRESH session is opened and the op commits.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(1)),
    Message::Request(Request::new(
      ClientId::new(1),
      RequestNumber::with(1),
      Bytes::from_static(b"fresh"),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.commit().get(), 4, "the re-registered request commits");
  assert_eq!(
    e.session_request_for_test(1),
    Some(1),
    "client 1 holds a fresh session at watermark 1"
  );
}

#[test]
fn pipeline_admission_stalls_at_the_cap_and_releases_as_commits_advance() {
  // A 2-replica primary (quorum 2) accepts client requests WITHOUT committing (no backup acks), so
  // the pipeline `(commit_min, op]` grows to MAX_PIPELINE — at which point admission STALLS (no op
  // minted, no watermark advanced, so the client's retransmit is still canonical). Acking the first
  // op then advances the commit and admission RELEASES.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap();
  let mut e = Endpoint::new(cfg, genesis(2), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let submit = |e: &mut Endpoint<NoopSm>,
                wal: &mut TestWal,
                sb: &mut TestSb,
                blocks: &mut dyn BlockStore,
                rn: u64| {
    e.handle_message(
      now,
      wal,
      sb,
      blocks,
      Peer::Client(ClientId::new(7)),
      client_request(rn),
    );
    e.handle_storage(now, wal, sb, blocks); // land the append (own vote only — quorum 2 never commits)
  };
  for rn in 1..=MAX_PIPELINE {
    submit(&mut e, &mut wal, &mut sb, &mut blocks, rn);
  }
  assert_eq!(e.op().get(), MAX_PIPELINE, "the pipeline filled to the cap");
  assert_eq!(e.commit().get(), 0, "nothing committed (no backup acks)");

  // The next request is REFUSED at admission: no op minted, watermark unchanged.
  submit(&mut e, &mut wal, &mut sb, &mut blocks, MAX_PIPELINE + 1);
  assert_eq!(
    e.op().get(),
    MAX_PIPELINE,
    "admission stalled at MAX_PIPELINE"
  );
  assert_eq!(
    e.session_request_for_test(7),
    Some(MAX_PIPELINE),
    "the stalled request did not advance the watermark"
  );

  // The backup acks op 1 (content-addressed vote) → commit advances → admission releases.
  let identity = crate::storage::prepare_identity(
    ClientId::new(7),
    RequestNumber::with(1),
    crate::storage::fnv1a_128(&[1u8]),
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
      identity,
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.commit().get(), 1, "op 1 committed off the backup ack");
  submit(&mut e, &mut wal, &mut sb, &mut blocks, MAX_PIPELINE + 1);
  assert_eq!(
    e.op().get(),
    MAX_PIPELINE + 1,
    "admission released once the commit advanced"
  );
}

#[test]
fn prepare_retransmit_is_windowed_to_the_first_unacked_ops() {
  // A primary with a deep un-acked pipeline re-broadcasts at most PREPARE_RETRANSMIT_WINDOW prepares
  // per retransmit tick — the LOWEST ops (the ones the commit is waiting on) — not the whole window.
  // The window ships as a byte-bounded `PrepareBatch` (small bodies: ONE batch carrying the whole
  // window), never as per-op `Prepare` frames.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap();
  let mut e = Endpoint::new(cfg, genesis(2), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let deep = PREPARE_RETRANSMIT_WINDOW + 16;
  for rn in 1..=deep {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      client_request(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  while e.poll_message().is_some() {} // drop the initial broadcasts
  // Fire the prepare-retransmit timer.
  let later = now + PREPARE_RETRANSMIT;
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks);
  let mut retransmitted = std::vec::Vec::new();
  let mut batches = 0u64;
  while let Some(out) = e.poll_message() {
    match out.msg_ref() {
      Message::PrepareBatch(b) => {
        batches += 1;
        assert_eq!(
          b.view(),
          View::new(),
          "the batch carries the primary's view"
        );
        assert_eq!(
          b.commit(),
          OpNumber::new(),
          "the batch carries the primary's commit (nothing committed — quorum 2, no backup acks)"
        );
        for entry in b.log_slice() {
          assert!(
            entry.body().is_some(),
            "a retransmitted entry always carries its body (the primary skips its own holes)"
          );
          retransmitted.push(entry.op().get());
        }
      }
      Message::Prepare(_) => panic!("the retransmit path is batched: no per-op Prepare frames"),
      _ => {}
    }
  }
  let expect: std::vec::Vec<u64> = (1..=PREPARE_RETRANSMIT_WINDOW).collect();
  assert_eq!(
    retransmitted, expect,
    "exactly the first PREPARE_RETRANSMIT_WINDOW un-acked ops are re-broadcast"
  );
  assert_eq!(
    batches, 1,
    "small bodies fit the frame budget: the whole window ships as ONE batch"
  );
  assert_eq!(
    e.prepare_batches_sent(),
    1,
    "the observability counter witnesses the batched retransmit"
  );
}

#[test]
fn prepare_retransmit_splits_batches_at_the_frame_budget() {
  // The retransmit accumulator is byte-bounded: ops whose bodies cannot share one frame split into
  // multiple batches, each under MAX_FRAME_LEN, together still covering the whole window. Three
  // 6 MiB ops: two fit one frame (12 MiB + framing < 16 MiB), the third would exceed the budget —
  // so the tick emits [1,2] then [3].
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap();
  let mut e = Endpoint::new(cfg, genesis(2), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let big = 6 * 1024 * 1024usize;
  for rn in 1..=3u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8; big]),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.op(),
    OpNumber::with(3),
    "three large ops minted, un-acked"
  );
  while e.poll_message().is_some() {} // drop the initial per-op broadcasts
  e.handle_timeout(now + PREPARE_RETRANSMIT, &mut wal, &mut sb, &mut blocks);
  let mut batches: std::vec::Vec<std::vec::Vec<u64>> = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::PrepareBatch(b) = out.msg_ref() {
      assert!(
        Message::PrepareBatch(b.clone()).encoded_len() <= crate::message::MAX_FRAME_LEN as usize,
        "every emitted batch fits the frame cap"
      );
      batches.push(b.log_slice().iter().map(|e| e.op().get()).collect());
    }
  }
  assert_eq!(
    batches,
    std::vec![std::vec![1, 2], std::vec![3]],
    "the window splits at the byte budget into successive sub-cap batches, in op order"
  );
  assert_eq!(
    e.prepare_batches_sent(),
    2,
    "the counter advances once per emitted batch"
  );
}

#[test]
fn prepare_retransmit_skips_a_repairing_hole_in_the_window() {
  // A post-adoption primary can hold a header-only (`Repairing`) entry inside its un-acked window —
  // it has the op's identity but not its bytes (the windowed repair channel is fetching them). The
  // retransmit must SKIP it (there is no body to ship) while still batching the `Present` ops on
  // either side.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap();
  let mut e = Endpoint::new(cfg, genesis(2), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  for rn in 1..=3u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      client_request(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  // Replace op 2's body with a `Repairing` hole (the in-memory shape a view-change adoption leaves
  // for an op whose body no donor shipped).
  e.log.insert(
    2,
    LogEntry {
      client: ClientId::new(7),
      request: RequestNumber::with(2),
      body: Body::Repairing(0xABCD),
    },
  );
  while e.poll_message().is_some() {}
  e.handle_timeout(now + PREPARE_RETRANSMIT, &mut wal, &mut sb, &mut blocks);
  let mut retransmitted = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::PrepareBatch(b) = out.msg_ref() {
      for entry in b.log_slice() {
        retransmitted.push(entry.op().get());
      }
    }
  }
  assert_eq!(
    retransmitted,
    std::vec![1, 3],
    "the Repairing hole is skipped; its Present neighbours still ship in one batch"
  );
}

#[test]
fn prepare_batch_delivery_is_equivalent_to_the_separate_prepares() {
  // The semantics-identical-by-construction proof: a backup fed ONE `PrepareBatch` ends in EXACTLY
  // the state of a backup fed the equivalent per-op `Prepare`s (same envelope
  // view/commit/checkpoint_op, same entries, same order) — `on_prepare_batch` reconstructs each
  // per-op `Prepare` and routes it through `on_prepare`, so every gate re-evaluates per entry. The
  // entry set deliberately exercises DIFFERENT `on_prepare` branches: ops 1-2 head-extend (with the
  // piggybacked commit applying op 1), op 4 is a future op (op 3 missing) that lands in the
  // tail-gap buffer and solicits the gap.
  let now = Instant::ZERO;
  let body_of = |op: u64| Bytes::copy_from_slice(&[op as u8]);
  let (commit, ck) = (OpNumber::with(1), OpNumber::new());
  let ops = [1u64, 2, 4];

  // Path A: the separate per-op Prepares, delivered back-to-back.
  let mut a = backup();
  let (mut wal_a, mut sb_a) = (TestWal::default(), TestSb::default());
  let mut blocks_a = crate::block_store::MemBlockStore::new();
  for op in ops {
    a.handle_message(
      now,
      &mut wal_a,
      &mut sb_a,
      &mut blocks_a,
      primary_peer(),
      Message::Prepare(Prepare::new(
        View::new(),
        OpNumber::with(op),
        commit,
        ck,
        crate::Epoch::new(0),
        0,
        ClientId::new(7),
        RequestNumber::with(op),
        body_of(op),
      )),
    );
  }

  // Path B: ONE PrepareBatch carrying the same envelope + entries.
  let mut b = backup();
  let (mut wal_b, mut sb_b) = (TestWal::default(), TestSb::default());
  let mut blocks_b = crate::block_store::MemBlockStore::new();
  let entries = ops
    .iter()
    .map(|&op| {
      PreparedEntry::new(
        OpNumber::with(op),
        ClientId::new(7),
        RequestNumber::with(op),
        body_of(op),
      )
    })
    .collect();
  b.handle_message(
    now,
    &mut wal_b,
    &mut sb_b,
    &mut blocks_b,
    primary_peer(),
    Message::PrepareBatch(crate::PrepareBatch::new(
      View::new(),
      commit,
      ck,
      crate::Epoch::new(0),
      0,
      entries,
    )),
  );

  // Land the in-flight appends on both, so the deferred acks are emitted too.
  a.handle_storage(now, &mut wal_a, &mut sb_a, &mut blocks_a);
  b.handle_storage(now, &mut wal_b, &mut sb_b, &mut blocks_b);

  // The full observable state converges — position, retained log, buffer, repair set, sessions…
  assert_eq!(a.op(), b.op());
  assert_eq!(
    a.op(),
    OpNumber::with(2),
    "ops 1-2 extended the head; op 4 is buffered (op 3 missing)"
  );
  assert_eq!(a.commit(), b.commit());
  assert_eq!(
    a.commit(),
    OpNumber::with(1),
    "the piggybacked commit applied op 1"
  );
  assert_eq!(a.commit_max, b.commit_max);
  assert_eq!(a.log, b.log, "identical retained logs");
  assert_eq!(a.buffer, b.buffer, "identical tail-gap buffers");
  assert!(a.buffer.contains_key(&4), "the future op buffered on both");
  assert_eq!(a.repair, b.repair);
  assert_eq!(
    a.sessions_snapshot_for_test(),
    b.sessions_snapshot_for_test()
  );
  // …the emitted message sequences (acks + the tail-gap solicitation, in order)…
  let drain_msgs = |e: &mut Endpoint<NoopSm>| {
    let mut out = std::vec::Vec::new();
    while let Some(m) = e.poll_message() {
      out.push(m);
    }
    out
  };
  let (out_a, out_b) = (drain_msgs(&mut a), drain_msgs(&mut b));
  assert_eq!(out_a, out_b, "identical emitted message sequences");
  assert!(
    out_a
      .iter()
      .any(|o| matches!(o.msg_ref(), Message::PrepareOk(ok) if ok.op() == OpNumber::with(2))),
    "non-vacuous: the durable appends acked on both paths"
  );
  // …and the application events.
  let drain_events = |e: &mut Endpoint<NoopSm>| {
    let mut out = std::vec::Vec::new();
    while let Some(ev) = e.poll_event() {
      out.push(ev);
    }
    out
  };
  assert_eq!(
    drain_events(&mut a),
    drain_events(&mut b),
    "identical event sequences"
  );
}

#[test]
fn prepare_batch_skips_a_repairing_entry_and_processes_the_rest() {
  // A header-only (`Repairing`) entry carries no bytes to prepare, so the receive side SKIPS it and
  // processes the remaining entries. The sender never emits one (its retransmit loop skips its own
  // holes), so this is the defensive posture against a buggy-but-authenticated primary: op 1
  // (Present) appends + acks, the Repairing op 2 neither extends the head nor buffers, and op 3 —
  // now a future op relative to head 1 — still flows through `on_prepare` into the tail-gap buffer
  // (hole-filling stays owned by the windowed repair channel, never the retransmit).
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let entry = |op: u64| {
    PreparedEntry::new(
      OpNumber::with(op),
      ClientId::new(7),
      RequestNumber::with(op),
      Bytes::copy_from_slice(&[op as u8]),
    )
  };
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::PrepareBatch(crate::PrepareBatch::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      std::vec![
        entry(1),
        PreparedEntry::repairing(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          0xABCD,
        ),
        entry(3),
      ],
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the Present op extended the head; the Repairing entry did not"
  );
  assert!(
    e.buffer.contains_key(&3) && !e.buffer.contains_key(&2),
    "the entry after the skipped one still processed (buffered as a future op); nothing buffered \
     for the skipped op"
  );
  let mut acked = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.msg_ref() {
      acked.push(ok.op().get());
    }
  }
  assert_eq!(acked, std::vec![1], "exactly the Present head-extend acked");
}

#[test]
fn recently_acked_voters_reads_only_the_uncommitted_inflight_tail() {
  // 3-voter cluster, primary at slot 0.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap();
  let mut e = Endpoint::new(cfg, genesis(3), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // Idle: no uncommitted in-flight entries → empty oracle.
  assert!(
    e.recently_acked_voters(64).is_empty(),
    "an idle cluster yields no oracle evidence"
  );

  // Submit op 1 (client 7, request 1): primary appends, sends Prepare to backups, oks=0.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    client_request(1),
  );
  // Pump WAL: the primary's own append is now durable → record_own_vote sets bit 0 → oks = 0b001.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {} // drain the Prepare broadcast

  // Op 1 is in-flight and uncommitted; slot 0 (primary) has acked.
  let member_slot0 = MemberId::new(0); // genesis: MemberId::new(i) == slot i
  let member_slot1 = MemberId::new(1);
  let acked_before_backup = e.recently_acked_voters(64);
  assert!(
    acked_before_backup.contains(&member_slot0),
    "slot 0 (primary, own vote) must appear in the uncommitted tail"
  );
  assert!(
    !acked_before_backup.contains(&member_slot1),
    "slot 1 has not acked yet"
  );

  // Deliver PrepareOk from slot 1 for op 1 (content-addressed, so checksum must match).
  let checksum = crate::storage::prepare_identity(
    ClientId::new(7),
    RequestNumber::with(1),
    crate::storage::fnv1a_128(&[1u8]),
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
      checksum,
      crate::Epoch::new(0),
      0,
    )),
  );
  // Op 1 is still uncommitted (quorum for a 3-voter cluster is 2; we now have 2 acks but
  // try_commit fires and COMMITS here — so we need to verify the oracle BEFORE commit triggers,
  // OR test that the committed entry is excluded. Let's verify by checking the post-commit state.
  // After delivering slot-1's PrepareOk, try_commit fires: oks has bits 0+1 = 2 ≥ quorum(2),
  // so op 1 is committed (inflight[1].committed = true). The oracle must return empty.
  assert!(
    e.recently_acked_voters(64).is_empty(),
    "after op 1 commits (inflight entry stays but committed=true) the oracle returns empty — \
     only uncommitted entries are fresh"
  );
}

#[test]
fn recently_acked_voters_uncommitted_op_visible_before_quorum() {
  // A 3-voter cluster where one backup has NOT acked yet: only the primary's own ack is in the
  // bitset, so the oracle sees exactly the primary's member (slot 0). This proves the oracle reads
  // partial progress on uncommitted entries, not only fully-acked ops.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap();
  let mut e = Endpoint::new(cfg, genesis(3), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    client_request(1),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // primary's own WAL append → own oks bit set
  while e.poll_message().is_some() {}
  // Only the primary's own ack: op 1 uncommitted, one ack, oracle returns {MemberId(0)}.
  let acked = e.recently_acked_voters(64);
  assert_eq!(
    acked.len(),
    1,
    "exactly one voter acked so far (the primary)"
  );
  assert!(
    acked.contains(&MemberId::new(0)),
    "the primary (slot 0, MemberId 0) is the sole acked voter"
  );
}

#[test]
fn membership_accessor_returns_live_snapshot() {
  // The membership() accessor returns the live Membership: its replica_count and member_at match
  // the values from the individual accessor methods (replica_count, member_at) — proving it is the
  // SAME struct, not a copy with diverging state.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap();
  let e = Endpoint::new(cfg, genesis(3), 0, NoopSm);
  let m = e.membership();
  assert_eq!(
    m.replica_count(),
    e.replica_count(),
    "membership().replica_count() matches the direct accessor"
  );
  assert_eq!(
    m.member_at(ReplicaId::new(0)),
    e.member_at(ReplicaId::new(0)),
    "membership().member_at(slot) matches the direct accessor"
  );
  assert_eq!(
    m.member_at(ReplicaId::new(1)),
    Some(MemberId::new(1)),
    "genesis slot 1 holds MemberId 1"
  );
}

use super::super::*;
use super::*;
use crate::{
  ClientId, Config, Header, OpId, OpNumber, ReplicaId, Request, RequestNumber, SlotStatus, View,
};

#[test]
fn fresh_endpoint_state() {
  let cfg = Config::try_new(1, ReplicaId::new(0), 3).expect("valid cluster config");
  let e = Endpoint::new(cfg, 99, NoopSm);
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
  assert!(!e.is_primary());
  let now = Instant::ZERO;

  // Prepare op=1, commit=0: submit append, pump storage so it completes, ack, commit stays 0.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  assert_eq!(e.op(), OpNumber::with(1));
  assert_eq!(e.commit(), OpNumber::with(0));
  e.handle_storage(now, &mut wal, &mut sb); // pump WAL → on_wal_done → PrepareOk
  match e.poll_message().expect("prepare_ok emitted").into_msg() {
    Message::PrepareOk(ok) => {
      assert_eq!(ok.op(), OpNumber::with(1));
      assert_eq!(ok.replica(), ReplicaId::new(1));
    }
    _ => panic!("expected PrepareOk"),
  }

  // Prepare op=2, commit=1: piggybacked commit applies op 1 (synchronously), then append op 2.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  assert_eq!(e.op(), OpNumber::with(2));
  assert_eq!(e.commit(), OpNumber::with(1));
}

#[test]
fn backup_buffers_out_of_order_prepares() {
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  // op=2 arrives before op=1: buffered, head op stays 0.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 0));
  assert_eq!(e.op(), OpNumber::with(0));

  // op=1 arrives: append 1, then drain buffered op 2.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  assert_eq!(e.op(), OpNumber::with(2));
}

#[test]
fn backup_caches_the_reply_so_a_backup_turned_primary_can_resend_it() {
  // REGRESSION (the lost-reply-across-failover hang the M3 sweep exposed): the primary caches each
  // committed reply (`commit_op`), but a BACKUP used to discard it. So if a client's reply was LOST
  // in flight and the primary then failed over, the new primary (a former backup) saw the client's
  // resend as a duplicate (`request == session.request`) yet had NO cached reply to resend — staying
  // SILENT and hanging the client forever, even with a healthy quorum. The fix caches the reply on
  // the backup's apply path too (it is the SM's deterministic output). Here: a backup applies op 1
  // (client 7, request 1) and must hold its cached reply.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Prepare op 1 (client 7, request 1), make it durable, then Commit to apply it.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(1), OpNumber::new())),
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
  let now = Instant::ZERO;

  // Bring the backup to head op 2 (append 1, 2 via in-order Prepares; commit stays 0).
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 0));
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.op(), OpNumber::with(2));
  while e.poll_message().is_some() {} // drain the acks

  // A Commit learns the primary committed up to op 5 (checkpoint still 2, so 3,4,5 are above the
  // checkpoint — NOT snapshot-only). The backup holds only up to op 2 → it must solicit 3,4,5.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(5),
      OpNumber::with(2),
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
  let now = Instant::ZERO;
  // The backup is at head 0, checkpoint 0. A single Commit advertises a colossal commit_max — above
  // the checkpoint (so this is tail-gap territory, not state-sync) and far above the head.
  let bogus = 1_000_000u64;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(bogus),
      OpNumber::with(0),
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
  let now = Instant::ZERO;
  // Head 0, checkpoint 0, commit_max 3 (< TAIL_GAP_WINDOW) → solicit exactly {1,2,3}.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::with(0),
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
    Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
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
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 5)); // primary says commit=5, we have op 2
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
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  assert!(
    e.poll_message().is_none(),
    "no PrepareOk before the append is durable"
  );
  assert_eq!(
    wal.op_head(),
    OpNumber::with(1),
    "the prepare was submitted to the WAL"
  );
  e.handle_storage(now, &mut wal, &mut sb);
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
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
    LogEntry {
      client: ClientId::new(7),
      request: RequestNumber::with(5),
      body: Bytes::copy_from_slice(&[5u8]),
    },
  );
  assert_eq!(
    wal.status(OpNumber::with(5)),
    SlotStatus::Empty,
    "precondition: op 5 not durable"
  );

  // The primary RETRANSMITS the current-view Prepare(5) (its PREPARE_RETRANSMIT). pop=5 <= self.op=5
  // → the re-ack branch. It must NOT ack: op 5 is not durably appended on THIS replica.
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(5, 5));
  let mut premature = 0;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.into_msg() {
      if ok.op() == OpNumber::with(5) {
        premature += 1;
      }
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
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(5, 5));
  let mut reacked = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.into_msg() {
      if ok.op() == OpNumber::with(5) {
        reacked = true;
      }
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
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
    let mut ep = Endpoint::new(cfg, 7, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(ep.is_primary());
    let head_before = ep.op();
    arm(&mut ep);
    ep.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
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
  // a B4 repair hole). The session/dedup table (`self.clients`) is only updated as ops APPLY, so during
  // the gap a just-committed client request is ABSENT from the table → a retry would be mis-seen as NEW
  // and assigned an op ABOVE the gap → when the hole fills, the apply loop (which has no dedup) would
  // execute BOTH the original AND the duplicate → divergence. The primary must catch up first; the
  // client retries.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 8).unwrap();
  let mut ep = Endpoint::new(cfg, 7, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  // Primary holding a committed-op GAP: head op 4, commit HELD at 1 by a hole at op 2, but commit_max
  // = 4 (ops 2..=4 are known committed cluster-wide, merely unapplied here). Ops 3 + 4 are present in
  // the log; only op 2 is the unreadable hole. (`force_state_for_test` keeps commit_max == commit_min,
  // so raise it directly to model the known-but-unapplied committed suffix.)
  ep.force_state_for_test(0, 4, 1, 0, &[2]);
  ep.commit_max = OpNumber::with(4);
  for op in [3u64, 4u64] {
    ep.log.insert(
      op,
      LogEntry {
        client: ClientId::new(7),
        request: RequestNumber::with(op),
        body: Bytes::copy_from_slice(&[op as u8]),
      },
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
    primary_peer(),
    repair_prepare(0, 2, 4),
  );
  ep.handle_storage(Instant::ZERO, &mut wal, &mut sb); // the repaired append completes → apply the suffix
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

// ── Forfeit — a lagging primary steps down via a view change ────────────────────────────────────

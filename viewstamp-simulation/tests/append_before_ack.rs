//! Append-before-ack reproduction: a backup must never `PrepareOk` an op whose WAL append is still in
//! flight, even when the primary RETRANSMITS the current-view `Prepare` during the in-flight window.
//!
//! The bug lives in `Endpoint::on_prepare`'s `pop <= self.op` re-ack branch, which re-acks INLINE on
//! the assumption the op is "already durable". But `append_prepare` advances `self.op` while the WAL
//! append is still ASYNCHRONOUS (durable only on a later `WalDone::Appended`). So a retransmitted
//! `Prepare(N)` arriving before that completion makes the backup ack op `N` it has NOT durably
//! appended — an append-before-ack violation. With the synchronous default WAL the window never
//! opens; [`InMemoryWal::with_async_appends`] reopens it deterministically so this test can drive it.
//!
//! This test FAILS on the pre-fix proto (a premature `PrepareOk(N)` appears while the append is
//! staged) and PASSES once the choke point suppresses any ack of an in-flight op.

use bytes::Bytes;
use viewstamp_proto::{
  ClientId, Config, Endpoint, Instant, Message, OpNumber, Peer, Prepare, ReplicaId, RequestNumber,
  StateMachine, View, Wal,
};
use viewstamp_simulation::sm::LogSm;
use viewstamp_simulation::{InMemorySuperblock, InMemoryWal};

/// Drains the backup's outgoing queue, returning how many `PrepareOk(op)` it emitted for `want_op`.
fn drain_prepare_oks<S: StateMachine>(e: &mut Endpoint<S>, want_op: OpNumber) -> usize {
  let mut n = 0;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.into_msg() {
      if ok.op() == want_op {
        n += 1;
      }
    }
  }
  n
}

#[test]
fn backup_does_not_ack_an_op_whose_append_is_still_in_flight_on_retransmit() {
  // Replica 2 of a 3-cluster: a BACKUP in view 0 (primary is replica 0), status Normal, head op 0.
  let cfg = Config::try_new(1, ReplicaId::new(2), 3).unwrap();
  let mut backup = Endpoint::new(cfg, 0, LogSm::default());
  // ASYNC WAL: an append stays in flight for a few polls (the append-before-ack window). The superblock
  // is the ordinary synchronous sim superblock — only the WAL append timing matters here.
  let mut wal = InMemoryWal::with_async_appends(4);
  let mut sb = InMemorySuperblock::new();
  let now = Instant::ZERO;

  let primary = Peer::Replica(ReplicaId::new(0));
  let op1 = OpNumber::with(1);
  let prepare = || {
    Prepare::new(
      View::new(),       // view 0 (current view — the re-ack branch only fires same-view)
      op1,               // op 1
      OpNumber::with(0), // primary commit
      OpNumber::with(0), // checkpoint_op
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"v1"),
    )
  };

  // (1) First delivery: the backup appends op 1 — but the append is ASYNC, so op 1 is NOT yet durable.
  backup.handle_message(now, &mut wal, &mut sb, primary, Message::Prepare(prepare()));
  assert_eq!(backup.op(), op1, "the head advanced to op 1 on the append");
  assert_eq!(
    wal.staged_len(),
    1,
    "precondition: op 1's append is genuinely in flight (staged, not durable)"
  );
  assert_eq!(
    wal.status(op1),
    viewstamp_proto::SlotStatus::Dirty,
    "precondition: op 1's WAL slot is Dirty (not durably appended)"
  );
  assert_eq!(
    drain_prepare_oks(&mut backup, op1),
    0,
    "no PrepareOk yet — the normal-path ack is deferred to the append completion"
  );

  // (2) The primary RETRANSMITS the same current-view Prepare(1) BEFORE the append completes — this
  // is what `primary_timeouts` does every PREPARE_RETRANSMIT. The append is STILL in flight here.
  assert_eq!(
    wal.staged_len(),
    1,
    "the append is still in flight at retransmit time"
  );
  backup.handle_message(now, &mut wal, &mut sb, primary, Message::Prepare(prepare()));

  // (3) THE LOAD-BEARING ASSERT (append-before-ack): while op 1's append is in flight, the backup
  // must emit NO PrepareOk(1). On the pre-fix proto the re-ack branch fires INLINE here → FAIL.
  let acks_while_in_flight = drain_prepare_oks(&mut backup, op1);
  assert!(
    wal.staged_len() >= 1,
    "sanity: op 1 is still in flight when we check for a premature ack"
  );
  assert_eq!(
    acks_while_in_flight, 0,
    "append-before-ack VIOLATED: the backup acked op 1 while its WAL append was still in flight \
     (the retransmit re-ack branch must not ack a non-durable op)"
  );

  // (4) Now let the append complete (becomes durable) and drive the deferred ack.
  let mut total_acks = 0;
  for _ in 0..16 {
    backup.handle_storage(now, &mut wal, &mut sb);
    total_acks += drain_prepare_oks(&mut backup, op1);
    if wal.staged_len() == 0 {
      break;
    }
  }
  assert_eq!(
    wal.status(op1),
    viewstamp_proto::SlotStatus::Clean,
    "op 1 is durable after the append completes"
  );
  // (5) EXACTLY ONE PrepareOk(1) overall — emitted only AFTER durability. The in-flight retransmit
  // owed no ack (the in-flight append's own completion already owes exactly one).
  assert_eq!(
    total_acks, 1,
    "exactly one PrepareOk(1), emitted only after the append became durable"
  );
}

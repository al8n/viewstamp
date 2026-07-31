use super::{super::*, *};
use crate::{ClientId, Config, OpNumber, Prepare, ReplicaId, Request, RequestNumber, View};

#[test]
fn checkpoint_envelope_binds_the_op_and_both_dag_roots() {
  // The envelope is now FRAME-BOUNDED: just the bound op + the two content-addressed DAG roots (the SM
  // state AND the client-session table live in the block store, not inline). The session-table DAG
  // round-trip is covered in `session_blocks::tests`; here we assert the envelope binds all three fields
  // into the content hash and decodes them back exactly.
  let sm_root = crate::block_address(b"SM-SNAPSHOT");
  let sessions_root = crate::block_address(b"SESSIONS-DAG-ROOT");
  let env = Endpoint::<NoopSm>::encode_checkpoint(OpNumber::with(42), sm_root, sessions_root);
  assert_eq!(env.len(), 8 + 16 + 16, "the envelope is a fixed 40 bytes");
  let (decoded_op, decoded_sm, decoded_sessions) =
    Endpoint::<NoopSm>::decode_checkpoint(&env).expect("a well-formed envelope decodes");
  assert_eq!(decoded_op, OpNumber::with(42), "the bound op round-trips");
  assert_eq!(decoded_sm, sm_root, "the SM root round-trips");
  assert_eq!(
    decoded_sessions, sessions_root,
    "the session-table root round-trips"
  );
  // The bound op is part of the content hash: encoding the SAME roots under a DIFFERENT op yields a
  // DIFFERENT checkpoint_id (so an overstated advertised op cannot reuse stale bytes' id).
  let env_other_op =
    Endpoint::<NoopSm>::encode_checkpoint(OpNumber::with(43), sm_root, sessions_root);
  assert_ne!(
    crate::checkpoint_id(&env),
    crate::checkpoint_id(&env_other_op),
    "the checkpoint op is bound into the content hash"
  );
  // The sessions_root is bound too: a DIFFERENT session table (different root) under the SAME op + SM
  // root yields a DIFFERENT id (so the session table is part of the checkpoint identity).
  let env_other_sessions = Endpoint::<NoopSm>::encode_checkpoint(
    OpNumber::with(42),
    sm_root,
    crate::block_address(b"OTHER"),
  );
  assert_ne!(
    crate::checkpoint_id(&env),
    crate::checkpoint_id(&env_other_sessions),
    "the session-table root is bound into the content hash"
  );
  // The empty/sentinel roots make a valid envelope (op 0).
  let empty_sm = crate::block_address(&Bytes::new());
  let empty_sessions = crate::block_address(&Bytes::new());
  let empty = Endpoint::<NoopSm>::encode_checkpoint(OpNumber::new(), empty_sm, empty_sessions);
  let (eop, esm, esessions) =
    Endpoint::<NoopSm>::decode_checkpoint(&empty).expect("the empty envelope decodes");
  assert_eq!(eop, OpNumber::new());
  assert_eq!(esm, empty_sm);
  assert_eq!(esessions, empty_sessions);

  // A truncated / malformed envelope decodes to None (fault-not-panic), never an out-of-range panic.
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&[]).is_none(),
    "an empty buffer (missing the leading op) is malformed → None"
  );
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&[0, 0, 0, 0, 0, 0, 0]).is_none(),
    "a buffer too short for the 8-byte leading op is malformed → None"
  );
  // The op is present but the buffer is too short for the SM root (and the session root).
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&[0u8; 8]).is_none(),
    "only the op present (no SM root) is malformed → None"
  );
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&[0u8; 24]).is_none(),
    "op + SM root present but no session root is malformed → None"
  );
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&[0u8; 39]).is_none(),
    "one byte short of the full 40-byte envelope is malformed → None"
  );
}

#[test]
fn primary_checkpoints_after_interval_ops_via_two_superblock_writes() {
  // Single-replica cluster (quorum 1): the primary commits each op as soon as its append is
  // durable. With checkpoint_ops=2, committing op 2 makes commit_min=2 >= checkpoint_op(0)+2 →
  // the checkpoint sequence runs (TWO superblock writes), and checkpoint_op advances to 2 ONLY
  // after BOTH writes are durable. `StepSb` completes writes lazily (`flush` between rounds) so
  // each of the three steps is observed in isolation.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(1), 0, EchoSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };

  // Commit op 1: not yet at the interval; no checkpoint, nothing inflight on the superblock.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    req(1),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // append durable → commit op 1
  assert_eq!(e.commit(), OpNumber::with(1));
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "no checkpoint before the interval"
  );
  assert!(
    !sb.has_inflight(),
    "no superblock write before the interval"
  );

  // Commit op 2: commit_min reaches checkpoint_op(0)+checkpoint_ops(2)=2 → step 1: the snapshot
  // write is submitted (inflight) but NOT yet durable.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    req(2),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // append durable → commit op 2 → submit_write_checkpoint
  assert_eq!(e.commit(), OpNumber::with(2));
  assert!(sb.has_inflight(), "step 1: the snapshot write is inflight");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "checkpoint not durable until BOTH sb writes complete"
  );
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(0),
    "the durable root still names the OLD checkpoint after only step 1's submit"
  );

  // Flush step 1 (snapshot durable) → step 2: the VsrState root write is submitted (inflight).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(sb.has_inflight(), "step 2: the root write is inflight");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "still not durable after only the snapshot write completed"
  );

  // Flush step 2 (root durable) → step 3: the checkpoint officially advances in-memory.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(!sb.has_inflight(), "the sequence is complete");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint durable after both writes"
  );
  // The durable root now names the new checkpoint, with a non-zero content id (hash of envelope).
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(2));
  assert_ne!(sb.state().checkpoint_id(), 0);
  // The root-durable arm surfaced as an observability event for exactly the checkpointed op.
  assert!(
    core::iter::from_fn(|| e.poll_event())
      .any(|ev| ev == Event::CheckpointDurable(OpNumber::with(2))),
    "the durable checkpoint root emits CheckpointDurable"
  );
}

#[test]
fn a_block_store_flush_fault_holds_the_checkpoint_pointer_back_then_recovers() {
  // DURABLE-CHECKPOINT-TRANSACTION GUARD: the blocks a checkpoint names must be flushed durable BEFORE
  // its superblock pointer advances. If the block-store flush barrier FAILS, the checkpoint must NOT be
  // submitted at all (no torn checkpoint pointing at un-flushed blocks) — `checkpoint_op` stays put and
  // the durable root still names the OLD checkpoint. Mirrors the storage-fault discipline: a flush fault
  // is treated as data, and the sticky cadence re-forces the checkpoint once the flush succeeds.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(1), 0, EchoSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  // Arm exactly ONE flush fault: the first checkpoint's durability barrier fails.
  blocks.script_flush_fault(1);

  // Commit ops 1,2 → commit_min reaches the boundary and `force_checkpoint` runs — it writes the DAG
  // blocks, flushes (which FAULTS), and returns false WITHOUT submitting the checkpoint envelope.
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(e.commit(), OpNumber::with(2), "the ops still commit");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "a failed block-store flush does NOT advance the checkpoint pointer"
  );
  assert!(
    sb.checkpoint.is_none(),
    "no superblock checkpoint write was submitted when the flush faulted (no torn checkpoint)"
  );
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(0),
    "the durable root still names the OLD checkpoint after the flush fault"
  );
  assert!(
    !core::iter::from_fn(|| e.poll_event()).any(|ev| matches!(ev, Event::CheckpointDurable(_))),
    "no checkpoint became durable on the flush fault"
  );

  // The fault was a single shot; the next checkpoint attempt flushes cleanly. Commit op 3 — the cadence
  // still sees `commit_min(3) >= checkpoint_op(0)+2`, so the sticky re-force fires immediately and THIS
  // time the flush succeeds, so the checkpoint completes durably (advancing the pointer to 3). This is
  // the storage-fault-discipline payoff: the failed barrier only DELAYED the checkpoint, never lost it.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    req(3),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.commit(), OpNumber::with(3));
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(3),
    "once the flush succeeds the re-forced checkpoint advances the pointer"
  );
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(3));
  assert_ne!(sb.state().checkpoint_id(), 0);
}

#[test]
fn checkpoint_does_not_double_trigger_while_in_flight() {
  // While a checkpoint's superblock writes are pending, commit_min may keep advancing; a second
  // overlapping checkpoint must NOT start. checkpoint_ops=2: after op 2 triggers a checkpoint,
  // committing ops 3,4 (which also cross a 2-op boundary) must not arm a second checkpoint while
  // the first is in flight — only ONE checkpoint completes, landing at the op it staged (2).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(1), 0, EchoSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };

  // Commit ops 1,2 → checkpoint triggers (step 1: snapshot write inflight, NOT durable).
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(e.commit(), OpNumber::with(2));
  assert_eq!(e.checkpoint_op(), OpNumber::with(0));
  assert!(
    sb.has_inflight(),
    "the first checkpoint's snapshot write is inflight"
  );

  // Send requests 3,4 WHILE the first checkpoint's snapshot write is still in flight. The
  // op-reset DEFENSE (`on_request` short-circuits while `pending_checkpoint.is_some()`) DROPS them —
  // a primary must not assign new ops while a checkpoint-persist is in flight (an op-reuse hazard).
  // So commit stays at 2, and (a fortiori) no second checkpoint is armed.
  for rn in 3..=4 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "requests are dropped while a checkpoint-persist is in flight (the op-reset defense) — commit held at 2"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "the first checkpoint is still in flight"
  );

  // Drive the first (and only) in-flight checkpoint — staged at target_op=2 — to completion by
  // flushing its two writes. It advances checkpoint_op to 2 exactly (no second checkpoint started).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // step 1 done → step 2 (root write) inflight
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // step 2 done → checkpoint advances to 2
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "exactly one checkpoint completed at its staged op (2), no double-trigger"
  );
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(2));

  // Now the checkpoint is durable (no persist in flight), so the primary serves again. Resending
  // 3,4 commits them; commit_min reaches 4 → the boundary re-evaluates (4 >= checkpoint_op(2)+2) and
  // a SECOND checkpoint triggers at op 4 and completes. This proves the gate only suppressed the
  // OVERLAP, and that the serve-defense releases the moment the persist finishes.
  for rn in 3..=4 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "the primary serves again once the persist is durable (3,4 now commit)"
  );
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // snapshot done → root write
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // root done → checkpoint advances
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "a fresh checkpoint runs once the prior one is durable (boundary re-evaluated at commit_min=4)"
  );
}

#[test]
fn checkpoint_completes_in_one_drain_with_synchronous_superblock() {
  // The sim's real `InMemorySuperblock` completes ALL queued writes (including ones submitted
  // mid-drain) in a single `handle_storage`. `TestSb` models that. Confirm the whole 3-step
  // sequence completes in the single drain that commits the boundary op — this is the path the
  // sim `Cluster` exercises each tick, so a long-enough sim run checkpoints.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(1), 0, EchoSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(e.commit(), OpNumber::with(2));
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "synchronous superblock completes both checkpoint writes in the boundary-commit drain"
  );
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(2));
  assert_ne!(sb.state().checkpoint_id(), 0);
}

#[test]
fn checkpoint_gcs_wal_and_maps_below_the_quorum_checkpoint() {
  // GC: once a checkpoint is durable, the WAL slots + in-memory caches below the prune floor
  // are freed. Single replica (quorum 1) → quorum_checkpoint_op == self.checkpoint_op, so the floor
  // is the checkpoint op (2): ops <= 2 are pruned from the WAL and the log/inflight caches, while a
  // NEW request still commits (apply reads from commit_min, not from a pruned op).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(1), 0, EchoSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // append durable → commit; on op 2, checkpoint completes
  }
  assert_eq!(e.checkpoint_op(), OpNumber::with(2));
  // Quorum=1 → prune floor = checkpoint_op = 2 → ops <= 2 are freed from the WAL.
  assert!(
    wal.header(OpNumber::with(1)).is_none(),
    "op 1 pruned from the WAL"
  );
  assert!(
    wal.header(OpNumber::with(2)).is_none(),
    "op 2 pruned from the WAL"
  );
  // The in-memory log + inflight caches are trimmed to (floor .. head] = empty here (head == 2).
  assert_eq!(
    e.min_log_op(),
    None,
    "log cache trimmed entirely below the checkpoint (nothing above op 2 yet)"
  );
  assert_eq!(e.log_len(), 0, "log cache empty after the prune");
  assert_eq!(
    e.inflight_len(),
    0,
    "inflight cache trimmed below the checkpoint"
  );
  // A NEW request still commits (op 3) — the SM applies from commit_min, not from a pruned op.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    req(3),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.commit(),
    OpNumber::with(3),
    "commit continues past the pruned checkpoint"
  );
  assert_eq!(
    e.min_log_op(),
    Some(3),
    "op 3 is cached above the floor; the pruned prefix stays gone"
  );
}

#[test]
fn backup_gcs_below_its_own_checkpoint_even_without_quorum_reports() {
  // A backup never collects PrepareOks, so its `quorum_checkpoint_op` would be 0 (peers default 0)
  // — if GC used the quorum floor on a backup, the backup would never prune and its WAL/log would
  // grow unbounded. The asymmetric floor lets a BACKUP prune below its OWN durable checkpoint
  // (those ops are in its snapshot; a laggard below it state-syncs). This test drives a backup
  // (replica 1 of 3) to a durable checkpoint via Prepares + Commits and asserts it pruned.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, EchoSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  // The backup has heard from no peers → its quorum_checkpoint_op is 0 (conservative).
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::with(0));
  // Append ops 1,2 via Prepares from the primary (replica 0, view 0), pumping the durable append.
  for op in 1..=2u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(0)),
      Message::Prepare(Prepare::new(
        View::new(),
        OpNumber::with(op),
        OpNumber::with(op - 1),
        OpNumber::new(),
        crate::Epoch::new(0),
        0,
        ClientId::new(7),
        RequestNumber::with(op),
        Bytes::from(std::vec![op as u8]),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  // Commit op 2 so the backup's commit_min reaches the boundary and it checkpoints.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.commit(), OpNumber::with(2), "backup committed op 2");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "backup took a durable checkpoint at op 2"
  );
  // The backup's quorum floor is STILL 0: N=3 needs 2 replicas to report a checkpoint, but only
  // self reports 2 (peers default 0) → the quorum-th-highest is 0. This is exactly why a backup
  // cannot use the quorum floor (it would never prune). It pruned below its OWN checkpoint instead.
  assert_eq!(
    e.quorum_checkpoint_op(),
    OpNumber::with(0),
    "the backup's quorum floor is 0 (only self reports a checkpoint) — yet it still pruned"
  );
  assert!(
    wal.header(OpNumber::with(1)).is_none() && wal.header(OpNumber::with(2)).is_none(),
    "a backup prunes its WAL below its own checkpoint (boundedness), no quorum reports needed"
  );
  assert_eq!(
    e.log_len(),
    0,
    "backup log cache trimmed below its own checkpoint"
  );
}

#[test]
fn view_change_preserves_the_durable_checkpoint_pointer() {
  // SAFETY REGRESSION GUARD: a view-change durable-view write must NOT regress the durable
  // checkpoint_op to 0 (that would, once the WAL below it is GC'd in Task 5, lose committed ops on
  // recovery). Drive a single-replica primary to a durable checkpoint at op 2, then force a view
  // change (escalate to view 1) and let its durable-view write land; the durable root must still
  // name checkpoint_op=2 with its original id.
  use crate::StartViewChange;
  // N=3 so a view change is reachable, but checkpoint_ops=2 and we commit 2 ops as primary first.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, EchoSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  // Commit 2 ops with a 2-of-3 quorum (replica 1 acks), so commit_min reaches 2 and a checkpoint
  // is taken. The primary's own append + replica 1's PrepareOk = quorum 2.
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // primary's own append durable (own vote)
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(1)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(rn),
        ReplicaId::new(1),
        OpNumber::new(),
        crate::storage::prepare_identity(
          ClientId::new(7),
          RequestNumber::with(rn),
          crate::storage::fnv1a_128(&[rn as u8]),
        ),
        crate::Epoch::new(0),
        0,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drain any checkpoint writes
  }
  assert_eq!(e.commit(), OpNumber::with(2));
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint is durable at op 2"
  );
  let id_before = sb.state().checkpoint_id();
  assert_ne!(id_before, 0);

  // Force a view change: two peers send StartViewChange(view 1) → SVC quorum → ViewChange(1),
  // which submits a durable-view write. Pump it.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(1),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the durable-view write completes
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(2),
    "the view-change durable-view write must PRESERVE the checkpoint_op (not regress to 0)"
  );
  assert_eq!(
    sb.state().checkpoint_id(),
    id_before,
    "and preserve the matching checkpoint id"
  );
  // The in-memory checkpoint_op is likewise unchanged by the view change.
  assert_eq!(e.checkpoint_op(), OpNumber::with(2));
}

#[test]
fn primary_tracks_quorum_checkpoint_op() {
  // N=3, quorum=2. Primary self.checkpoint_op=0. Backups report checkpoints 5 and 3 via PrepareOk.
  // self(0)=0, r1=5, r2=3 → sorted desc [5,3,0]; the quorum(2)-th highest (index 1) is 3 — the
  // highest op a quorum (2 of 3) has reported checkpointing.
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  // A fresh primary in Normal view 0 with no peers heard from has quorum_checkpoint_op == 0.
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::new());
  // Quorum-checkpoint tracking is independent of inflight: the ok is recorded for its replica even
  // without a matching inflight op (the replica-id range check is the only guard).
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
      OpNumber::with(5),
      0,
      crate::Epoch::new(0),
      0,
    )),
  );
  // Only one backup heard from: self(0)=0, r1=5, r2=unheard(0) → desc [5,0,0] → index 1 = 0.
  assert_eq!(
    e.quorum_checkpoint_op(),
    OpNumber::new(),
    "one backup is not yet a quorum-checkpoint above 0"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(2),
      OpNumber::with(3),
      0,
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::with(3));
}

#[test]
fn quorum_checkpoint_op_single_replica_is_self() {
  // N=1, quorum=1 → the quorum checkpoint is exactly self's checkpoint (no peers to wait for).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(1), 0, EchoSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::new());
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(e.checkpoint_op(), OpNumber::with(2));
  assert_eq!(
    e.quorum_checkpoint_op(),
    OpNumber::with(2),
    "single-replica quorum checkpoint follows self's checkpoint"
  );
}

// ── Monotone peer_checkpoint ──

#[test]
fn peer_checkpoint_is_monotone_under_reordering() {
  // A primary records a peer's checkpoint_op, then a REORDERED older report arrives. The recorded
  // value must NOT regress — the GC floor + the force-sync trigger that read `quorum_checkpoint_op`
  // all rely on monotone per-peer checkpoints (a regressing floor could un-fire the escalation).
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 1, NoopSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  assert!(ep.is_primary(), "replica 0 is the view-0 primary");
  // A PrepareOk from replica 1 reporting checkpoint_op = 8.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::with(8),
      0,
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(ep.peer_checkpoint_for_test(1), 8);
  // A REORDERED older PrepareOk from replica 1 reporting checkpoint_op = 4 — must NOT regress.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::with(4),
      0,
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    ep.peer_checkpoint_for_test(1),
    8,
    "a reordered older report must not regress the recorded peer checkpoint"
  );
}

#[test]
fn on_commit_records_the_primary_checkpoint_monotonically() {
  // The backup-side record path (`on_commit`) is likewise monotone: a reordered older Commit from
  // the primary must not lower the recorded primary checkpoint.
  let mut e = sync_backup(); // replica 1 of 3, primary is replica 0
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(0),
      OpNumber::with(6),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.peer_checkpoint_for_test(0), 6);
  // A reordered older Commit (checkpoint 2) must not regress the recorded value.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(0),
      OpNumber::with(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.peer_checkpoint_for_test(0),
    6,
    "a reordered older Commit must not regress the recorded primary checkpoint"
  );
}

#[test]
fn committed_session_projection_drops_provisionals_and_lowers_accept_ahead_watermarks() {
  // A checkpoint persists only COMMITTED dedup state. The live table can carry two rows a checkpoint must
  // NOT capture, because a view change can later truncate the op they name and the restored watermark
  // would then hang the client's retry as a replyless in-flight duplicate (see
  // `committed_session_projection`): a PROVISIONAL row (no committed reply) is dropped, and an ACCEPT-AHEAD
  // watermark (`request` above the applied `reply.0`) is lowered to the applied request.
  let mut e = backup();
  // C1 (client 1): provisional — accepted request 1, never committed (no reply, last_op 0).
  e.clients.insert(
    1,
    Session {
      request: RequestNumber::with(1),
      reply: None,
      last_op: OpNumber::new(),
    },
  );
  // C2 (client 2): known — applied request 3 (reply cached), then accepted request 4 (watermark ahead,
  // its op not yet committed). This is the row a bare `last_op == 0` filter would WRONGLY keep.
  e.clients.insert(
    2,
    Session {
      request: RequestNumber::with(4),
      reply: Some((RequestNumber::with(3), Bytes::copy_from_slice(&[3u8]))),
      last_op: OpNumber::with(5),
    },
  );
  let projected = e.committed_session_projection();
  assert!(
    !projected.contains_key(&1),
    "the provisional row is dropped — recovery must not restore a replyless watermark"
  );
  let c2 = projected
    .get(&2)
    .expect("the known client survives the projection");
  assert_eq!(
    c2.request,
    RequestNumber::with(3),
    "the accept-ahead watermark is lowered to the applied request reply.0, not the uncommitted 4"
  );
  assert_eq!(
    c2.reply.as_ref().map(|(r, _)| *r),
    Some(RequestNumber::with(3)),
    "the cached reply is preserved"
  );
  assert_eq!(
    c2.last_op,
    OpNumber::with(5),
    "the applied-op stamp is preserved"
  );
}

#[test]
fn adoption_rolls_back_an_orphaned_accept_ahead_watermark() {
  // A deposed primary's ACCEPT-AHEAD watermark must roll back when adoption truncates the op it named —
  // else a retransmit of that truncated request dedups as a replyless duplicate and hangs the client (the
  // wedge `reconcile_session_watermarks` closes). Model a replica that accepted client 1's request 2 as
  // op 2 (watermark 2, reply cached at request 1) but never committed it, then adopt a higher view whose
  // canonical head is op 1 — op 2 is dropped, and the watermark must roll back to the reply-backed 1.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  e.force_state_for_test(0, 2, 1, 0, &[]);
  e.log.insert(
    1,
    LogEntry::present(
      ClientId::new(1),
      RequestNumber::with(1),
      Bytes::copy_from_slice(&[1u8]),
    ),
  );
  e.log.insert(
    2,
    LogEntry::present(
      ClientId::new(1),
      RequestNumber::with(2),
      Bytes::copy_from_slice(&[2u8]),
    ),
  );
  e.clients.insert(
    1,
    Session {
      request: RequestNumber::with(2), // accept-ahead: op 2 minted, not yet committed
      reply: Some((RequestNumber::with(1), Bytes::copy_from_slice(&[1u8]))),
      last_op: OpNumber::with(1),
    },
  );
  assert_eq!(
    e.session_request_for_test(1),
    Some(2),
    "precondition: the accept-ahead watermark is at the uncommitted request 2"
  );

  // Adopt view 1 whose canonical head is op 1 (commit 1): the uncommitted op 2 is truncated.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(crate::StartView::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(1),
      Epoch::new(0),
      0,
      ReplicaId::new(1),
      std::vec::Vec::new(),
    )),
  );

  assert!(
    !e.has_log_entry_for_test(2),
    "the uncommitted accept-ahead op 2 was truncated by the adoption"
  );
  assert_eq!(
    e.session_request_for_test(1),
    Some(1),
    "the orphaned accept-ahead watermark rolled back to the reply-backed request 1 — not left at 2, \
     where a retransmit of request 2 would dedup to a replyless hang"
  );
  assert_eq!(
    e.session_reply_for_test(1).map(|(r, _)| r),
    Some(1),
    "the cached reply is preserved — at-most-once holds (a committed request stays deduped)"
  );
}

// ── State-sync ──

// ── The WAL slot-quiescence fence (checkpoint/GC lane) ──

/// A client `Request` from client 7: request `rn`, body `[rn]`.
fn chaos_req(rn: u64) -> Message {
  Message::Request(Request::new(
    ClientId::new(7),
    RequestNumber::with(rn),
    Bytes::from(std::vec![rn as u8]),
  ))
}

/// A backup's `PrepareOk` for op `op` (view 0) from `replica`, carrying its `checkpoint_op` report and
/// the content-addressed identity of the client-7 op minted by [`chaos_req`].
fn chaos_ok(op: u64, replica: u16, checkpoint_op: u64) -> Message {
  Message::PrepareOk(PrepareOk::new(
    View::new(),
    OpNumber::with(op),
    ReplicaId::new(replica),
    OpNumber::with(checkpoint_op),
    crate::storage::prepare_identity(
      ClientId::new(7),
      RequestNumber::with(op),
      crate::storage::fnv1a_128(&[op as u8]),
    ),
    crate::Epoch::new(0),
    0,
  ))
}

/// Drive a view-0 primary (replica 0 of 3, `checkpoint_ops = 2`) over a BOUNDED [`ReorderWal`] ring of
/// 4 slots into the released-op-with-an-unquiesced-write state:
/// - op 1's append (body `[1]`) is STILL IN FLIGHT (staged, completion held) while op 1 itself
///   committed long ago — BOTH backups voted, so the quorum formed without the primary's own
///   (never-cast) vote — and is now checkpoint-subsumed;
/// - ops 2..=4 committed normally (their appends released + acked; the backups' acks carry their
///   `checkpoint_op = 2` reports), so the checkpoint at op 4 runs GC with a quorum prune floor of 2:
///   `wal.prune(3)` frees the durable slots through op 2, and op 1 becomes a RELEASED op whose
///   physical write never quiesced — the exact state a late landing (or a late async cancellation)
///   resolves.
///
/// Returns the endpoint + storage with the outgoing queue drained.
fn primary_with_op1_write_held_across_checkpoint_gc() -> (
  Endpoint<NoopSm>,
  ReorderWal,
  TestSb,
  crate::block_store::InMemoryBlockStore,
) {
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, NoopSm, 4);
  let (mut wal, mut sb) = (ReorderWal::bounded(4), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  // Op 1 = body `[1]` staged (completion HELD). Both backups vote → op 1 commits WITHOUT the
  // primary's own vote (2-of-3 quorum from the backups alone) while its own append is still in
  // flight — the client is replied to on the strength of the BACKUPS' durable copies.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    chaos_req(1),
  );
  assert_eq!(
    wal.staged_ops(),
    std::vec![1],
    "op 1's append is staged, its completion withheld"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    chaos_ok(1, 1, 0),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    chaos_ok(1, 2, 0),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "op 1 committed on the two backup votes alone (its own append still in flight)"
  );

  // Op 2: mint, release its append (own vote), one backup ack → commit 2 → the checkpoint at op 2
  // fires and lands durably (synchronous superblock). Its GC prunes nothing yet: the quorum floor is
  // still 0 (no peer has REPORTED a checkpoint).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    chaos_req(2),
  );
  assert!(wal.release_latest_for(2), "op 2's append lands normally");
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // own vote for op 2
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    chaos_ok(2, 1, 0),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drain the checkpoint writes
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "the checkpoint at op 2 is durable"
  );

  // Ops 3 and 4: mint + release + both backups ack CARRYING `checkpoint_op = 2`, so the quorum
  // checkpoint rises to 2 and the checkpoint at op 4 runs GC with prune floor 2 → `wal.prune(3)`.
  for op in 3..=4 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      chaos_req(op),
    );
    assert!(
      wal.release_latest_for(op),
      "op {op}'s append lands normally"
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // own vote
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(1)),
      chaos_ok(op, 1, 2),
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(2)),
      chaos_ok(op, 2, 2),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drain (op 4's commit fires the checkpoint + GC)
  }
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the checkpoint at op 4 is durable"
  );
  assert_eq!(
    wal.durable_body(2),
    None,
    "the GC prune freed the durable WAL slots through op 2"
  );
  assert!(
    wal.durable_body(3).is_some() && wal.durable_body(4).is_some(),
    "the un-pruned tail (ops 3, 4) is durably held"
  );
  assert_eq!(
    wal.staged_ops(),
    std::vec![1],
    "op 1's write is STILL staged — the prune could not cancel the device write"
  );
  while e.poll_message().is_some() {}
  (e, wal, sb, blocks)
}

#[test]
fn gc_retires_a_checkpoint_subsumed_deferred_appends_bookkeeping() {
  // Liveness (a deferred append overtaken by the checkpoint). A fence-deferred append's op can
  // COMMIT on the other replicas' quorum votes while the waiter still sits behind an un-quiesced
  // blocker, and the next checkpoint then subsumes it. GC must retire the waiter's WHOLE footprint —
  // the deferred entry AND the `appending` mark it owns — because a dropped waiter never mints a
  // completion: an orphaned mark would hold `has_inflight_storage()` true until the next generation
  // reset, wedging the graceful-shutdown, restart-drain, and seal paths on a healthy replica.
  let (mut e, mut wal, mut sb, mut blocks) = primary_with_op1_write_held_across_checkpoint_gc();
  let now = Instant::ZERO;

  // Op 5 (the ring alias of op 1 under capacity 4) mints and DEFERS behind op 1's un-quiesced
  // write, then commits on the two backup votes alone — the waiter is now covered by the cluster
  // without ever having been submitted locally.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    chaos_req(5),
  );
  assert_eq!(
    wal.staged_ops(),
    std::vec![1],
    "op 5's append is deferred (only op 1's old write is physically staged)"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    chaos_ok(5, 1, 4),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    chaos_ok(5, 2, 4),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(5),
    "op 5 commits on the backups' votes alone, its own append still deferred"
  );

  // Op 6 carries the cluster to the next checkpoint boundary; its acks report `checkpoint_op = 6`,
  // so the boundary's GC runs with a prune floor covering the deferred op 5.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    chaos_req(6),
  );
  assert!(wal.release_latest_for(6), "op 6's append lands normally");
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // own vote for op 6
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    chaos_ok(6, 1, 6),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    chaos_ok(6, 2, 6),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // checkpoint at 6 → root durable → GC
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(6),
    "the checkpoint at op 6 is durable and its GC subsumed the deferred op 5"
  );

  // Quiesce the one remaining physical write — op 1's blocker — and drain. With the waiter's whole
  // footprint retired, NOTHING is left in flight: the drain signal settles instead of reading true
  // forever off an `appending` mark no completion can ever clear.
  assert!(wal.release_latest_for(1), "op 1's old write finally lands");
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    !e.has_inflight_storage(),
    "the checkpoint-subsumed waiter left no orphaned bookkeeping — storage fully quiesces"
  );
  while e.poll_message().is_some() {}
}

#[test]
fn ring_wrap_reappend_defers_until_the_pruned_slots_old_write_quiesces() {
  // Safety (ring-slot reuse across a checkpoint prune). On a bounded ring of 4, op 5 physically
  // reuses op 1's slot (5 mod 4 == 1 mod 4). Op 1 committed and was checkpoint-pruned while its own
  // append never quiesced (the device still holds the write) — so when the primary mints op 5, the
  // admission window allows it (5 − prune_floor(2) = 3 ≤ 4) but the PHYSICAL slot still has op 1's
  // un-quiesced write in flight. WITHOUT the fence op 5's append is submitted immediately; append
  // completions may reorder, so a newest-first device lands op 5's bytes FIRST and op 1's stale
  // bytes LAST — evicting the COMMITTED op 5's durable value from the shared slot while its commit
  // (and client reply) stand: committed-value loss. The fence DEFERS op 5's append until op 1's
  // write quiesces, so op 5's bytes are the last write to the slot.
  let (mut e, mut wal, mut sb, mut blocks) = primary_with_op1_write_held_across_checkpoint_gc();
  let now = Instant::ZERO;

  // Mint op 5 (body `[5]`) — the ring alias of op 1's slot. The Prepare broadcasts (consensus
  // proceeds), but the physical append is DEFERRED behind op 1's un-quiesced write.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    chaos_req(5),
  );
  assert_eq!(
    wal.staged_ops(),
    std::vec![1],
    "op 5's append was DEFERRED by the fence (only op 1's old write is staged) despite the \
     admission window allowing the mint"
  );
  let mut saw_prepare_5 = false;
  while let Some(out) = e.poll_message() {
    if let Message::Prepare(p) = out.msg_ref()
      && p.op() == OpNumber::with(5)
    {
      saw_prepare_5 = true;
    }
  }
  assert!(
    saw_prepare_5,
    "the op-5 Prepare WAS broadcast — only the physical write waits on the fence"
  );
  // One backup votes for op 5. It cannot commit yet: the primary's own vote follows its own durable
  // append (append-before-ack), which is deferred.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    chaos_ok(5, 1, 2),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "op 5 must not commit before the primary's own durable vote"
  );

  // The device completes newest-first: repeatedly land the NEWEST staged write, draining after each.
  // Fenced: only op 1's old write is staged — it lands late into the pruned region (an INERT
  // resurrection: its stale completion finds op 1 released and casts nothing) and the quiesced slot
  // releases op 5's deferred append; the next round lands op 5's bytes — physically evicting the
  // resurrected op 1 from the shared slot — and the completion casts the primary's own vote,
  // committing op 5 with the backup's ack. Reverted (no fence): op 5's append was submitted at mint
  // ALONGSIDE op 1's, so newest-first lands op 5 FIRST and op 1's stale bytes LAST — evicting the
  // committed op 5's durable value, which the final durable_body assert catches.
  while let Some(&newest) = wal.staged_ops().last() {
    assert!(wal.release_latest_for(newest));
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(5),
    "op 5 commits once its deferred append lands (own vote + the backup ack)"
  );
  // THE property: the durable ring slot holds the COMMITTED op 5's bytes — the last write to the
  // slot — and op 1's stale resurrection was evicted by the wrap, not the other way around.
  assert_eq!(
    wal.durable_body(5),
    Some(Bytes::from(std::vec![5u8])),
    "the shared ring slot durably holds the committed op 5's bytes, not op 1's late stale write"
  );
  assert_eq!(
    wal.durable_body(1),
    None,
    "op 1's resurrected entry was evicted by op 5's wrap (the checkpoint owns its content)"
  );
  assert!(
    !e.has_inflight_storage(),
    "every physical write quiesced — nothing lingers after the choreography"
  );
}

#[test]
fn async_cancellation_of_a_released_ops_write_retires_it_silently() {
  // The `WalDone::Cancelled` RELEASED-op arm. Op 1 is checkpoint-subsumed and GC-pruned (at/below
  // the actually-pruned floor) while its append never quiesced, and its `Pending::Ack` action is
  // still live (GC deliberately leaves `pending` intact — the write is still with the device). The
  // backend then reports the write ASYNC-CANCELLED: its bytes never landed and never will. The
  // endpoint must retire the bookkeeping ON THE SPOT — no vote cast, no resubmit staged (the op is
  // released; nothing is owed) — so the storage-drain signal settles and a driver's graceful
  // teardown completes.
  let (mut e, mut wal, mut sb, mut blocks) = primary_with_op1_write_held_across_checkpoint_gc();
  let now = Instant::ZERO;

  assert!(
    e.has_inflight_storage(),
    "op 1's un-quiesced write still holds the storage-drain signal true"
  );
  assert!(
    wal.cancel_latest_for(1),
    "the backend async-cancels op 1's staged write"
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    wal.staged_ops(),
    std::vec![] as std::vec::Vec<u64>,
    "nothing was re-submitted for the released op (the cancellation is not a fault to retry)"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "no vote/commit moved — the released op's cancellation owes nothing"
  );
  assert_eq!(
    wal.durable_body(1),
    None,
    "the cancelled write never landed (no resurrection)"
  );
  assert!(
    !e.has_inflight_storage(),
    "the released-op cancellation retired ALL bookkeeping — the endpoint settles"
  );
}

#[test]
fn async_cancellation_of_a_live_ops_write_degrades_to_a_resubmit() {
  // The `WalDone::Cancelled` LIVE-op arm (a backend contract violation, degraded like `Fault`).
  // A primary mints op 1 and the backend spuriously cancels the LIVE append — an op the endpoint
  // still owes its own vote for. Silently retiring it would leak the op's in-flight bookkeeping and
  // wedge the commit; treating it as `Appended` would cast a vote for bytes that never landed. The
  // endpoint instead RE-SUBMITS the append from its still-held data, so the spurious cancel costs
  // one retry and the op still commits.
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    u64::MAX,
  );
  let (mut wal, mut sb) = (ReorderWal::new(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    chaos_req(1),
  );
  assert_eq!(wal.staged_ops(), std::vec![1], "op 1's append is staged");
  assert!(
    wal.cancel_latest_for(1),
    "the backend spuriously cancels the LIVE append"
  );
  assert_eq!(
    wal.staged_len(),
    0,
    "the cancel popped the old write before the endpoint reacts"
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    wal.staged_ops(),
    std::vec![1],
    "a FRESH re-submit was staged for the live op (degraded to a retry, not a leak)"
  );

  // The retried append lands → the primary's own vote; one backup ack completes the quorum.
  assert!(wal.release_latest_for(1), "the re-submitted append lands");
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    chaos_ok(1, 1, 0),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "liveness preserved: the op still commits despite the spurious cancellation"
  );
  assert_eq!(
    wal.durable_body(1),
    Some(Bytes::from(std::vec![1u8])),
    "the durable slot holds the retried append's bytes"
  );
  assert!(
    !e.has_inflight_storage(),
    "nothing lingers once the retried append quiesced"
  );
}

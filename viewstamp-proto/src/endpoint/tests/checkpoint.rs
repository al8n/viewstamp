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
  let (wal, sb) = (TestWal::default(), StepSb::default());
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
  let mut storage = Storage::new(wal, sb);
  e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(1));
  e.storage_step(now, &mut storage, &mut blocks); // append durable → commit op 1
  assert_eq!(e.commit(), OpNumber::with(1));
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "no checkpoint before the interval"
  );
  assert!(
    !storage.sb_mut().has_inflight(),
    "no superblock write before the interval"
  );

  // Commit op 2: commit_min reaches checkpoint_op(0)+checkpoint_ops(2)=2 → step 1: the snapshot
  // write is submitted (inflight) but NOT yet durable.
  e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(2));
  e.storage_step(now, &mut storage, &mut blocks); // append durable → commit op 2 → submit_write_checkpoint
  assert_eq!(e.commit(), OpNumber::with(2));
  assert!(
    storage.sb_mut().has_inflight(),
    "step 1: the snapshot write is inflight"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "checkpoint not durable until BOTH sb writes complete"
  );
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
    OpNumber::with(0),
    "the durable root still names the OLD checkpoint after only step 1's submit"
  );

  // Flush step 1 (snapshot durable) → step 2: the VsrState root write is submitted (inflight).
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(
    storage.sb_mut().has_inflight(),
    "step 2: the root write is inflight"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "still not durable after only the snapshot write completed"
  );

  // Flush step 2 (root durable) → step 3: the checkpoint officially advances in-memory.
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(!storage.sb_mut().has_inflight(), "the sequence is complete");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint durable after both writes"
  );
  // The durable root now names the new checkpoint, with a non-zero content id (hash of envelope).
  assert_eq!(storage.sb_mut().state().checkpoint_op(), OpNumber::with(2));
  assert_ne!(storage.sb_mut().state().checkpoint_id(), 0);
  // The root-durable arm surfaced as an observability event for exactly the checkpointed op.
  assert!(
    core::iter::from_fn(|| e.poll_event())
      .any(|ev| ev == Event::CheckpointDurable(OpNumber::with(2))),
    "the durable checkpoint root emits CheckpointDurable"
  );
}

#[test]
fn an_ordinary_root_landing_after_a_missed_abandon_is_absorbed_not_dropped() {
  // An ordinary checkpoint root whose correlation ended WITHOUT its abandon — the session's
  // parked-cell contract tolerates exactly this (a mismatched abandon clears nothing and the
  // submitted front lands regardless), and the tolerance has two halves at two layers: the
  // SESSION half is that the landing rewinds nothing on the timeline; the ENDPOINT half —
  // asserted here — is that the uncorrelated landing's facts are ABSORBED rather than dropped
  // as stale. Same incarnation, no live correlation: the durable root advances to the
  // checkpoint the write carried, and the endpoint must follow it (the frontier catch-up
  // adopts immediately, since an ordinary checkpoint's target never outruns the commit floor
  // that produced it) — otherwise the durable pointer leads the in-memory one with no owed
  // catch-up recorded, which the settled-lockstep assertion in `handle_storage` trips on.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(1), 0, EchoSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), StepSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  let mut storage = Storage::new(wal, sb);
  // Commit through the interval: the checkpoint sequence starts (snapshot write in flight).
  for rn in 1..=2u64 {
    e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(rn));
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(e.commit(), OpNumber::with(2));
  // Snapshot durable → the ROOT write is submitted and stays in flight (StepSb withholds it).
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(
    matches!(
      e.pending_checkpoint,
      Some(PendingCheckpoint {
        step: CheckpointStep::AwaitRoot(..),
        ..
      })
    ),
    "the checkpoint root write is staged and in flight"
  );

  // The missed/mismatched abandonment: the correlation ends, but its abandon names the wrong id
  // (clearing nothing — the session's id guard) and the root itself is the submitted front (an
  // abandon never touches it). The endpoint is left holding no correlation for a root write the
  // medium still owes.
  storage.abandon_root(RootRole::Checkpoint, WriteId::new(0, 999));
  e.pending_checkpoint = None;

  // The root lands: same incarnation, no live correlation. The absorb must follow the durable
  // pointer — `handle_storage`'s settled-lockstep assertion runs inside this step, so reaching
  // the assertions below at all proves the landing left no untracked divergence.
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
    OpNumber::with(2),
    "the durable root advanced to the checkpoint the disowned write carried"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "the uncorrelated landing's frontier was absorbed and adopted (commit_min already covers it)"
  );
  assert!(
    e.inherited_frontier.is_none(),
    "the owed catch-up settled at the landing — nothing left owed"
  );
  assert!(
    e.repersist_orphan.is_none(),
    "an ordinary root never classifies as an orphaned re-persist: its target sits at/below the \
     commit floor that produced it"
  );
  assert_eq!(
    e.status(),
    Status::Normal,
    "an immediately-adoptable landing needs no reconciliation posture"
  );
  assert_eq!(e.commit(), OpNumber::with(2), "commit did not move");
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
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
  let mut storage = Storage::new(wal, sb);
  for rn in 1..=2 {
    e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(rn));
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(e.commit(), OpNumber::with(2), "the ops still commit");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "a failed block-store flush does NOT advance the checkpoint pointer"
  );
  assert!(
    storage.sb_mut().checkpoint.is_none(),
    "no superblock checkpoint write was submitted when the flush faulted (no torn checkpoint)"
  );
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
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
  e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(3));
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(e.commit(), OpNumber::with(3));
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(3),
    "once the flush succeeds the re-forced checkpoint advances the pointer"
  );
  assert_eq!(storage.sb_mut().state().checkpoint_op(), OpNumber::with(3));
  assert_ne!(storage.sb_mut().state().checkpoint_id(), 0);
}

#[test]
fn checkpoint_does_not_double_trigger_while_in_flight() {
  // While a checkpoint's superblock writes are pending, commit_min may keep advancing; a second
  // overlapping checkpoint must NOT start. checkpoint_ops=2: after op 2 triggers a checkpoint,
  // committing ops 3,4 (which also cross a 2-op boundary) must not arm a second checkpoint while
  // the first is in flight — only ONE checkpoint completes, landing at the op it staged (2).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(1), 0, EchoSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), StepSb::default());
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
  let mut storage = Storage::new(wal, sb);
  for rn in 1..=2 {
    e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(rn));
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(e.commit(), OpNumber::with(2));
  assert_eq!(e.checkpoint_op(), OpNumber::with(0));
  assert!(
    storage.sb_mut().has_inflight(),
    "the first checkpoint's snapshot write is inflight"
  );

  // Send requests 3,4 WHILE the first checkpoint's snapshot write is still in flight. The
  // op-reset DEFENSE (`on_request` short-circuits while `pending_checkpoint.is_some()`) DROPS them —
  // a primary must not assign new ops while a checkpoint-persist is in flight (an op-reuse hazard).
  // So commit stays at 2, and (a fortiori) no second checkpoint is armed.
  for rn in 3..=4 {
    e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(rn));
    e.storage_step(now, &mut storage, &mut blocks);
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
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks); // step 1 done → step 2 (root write) inflight
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks); // step 2 done → checkpoint advances to 2
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "exactly one checkpoint completed at its staged op (2), no double-trigger"
  );
  assert_eq!(storage.sb_mut().state().checkpoint_op(), OpNumber::with(2));

  // Now the checkpoint is durable (no persist in flight), so the primary serves again. Resending
  // 3,4 commits them; commit_min reaches 4 → the boundary re-evaluates (4 >= checkpoint_op(2)+2) and
  // a SECOND checkpoint triggers at op 4 and completes. This proves the gate only suppressed the
  // OVERLAP, and that the serve-defense releases the moment the persist finishes.
  for rn in 3..=4 {
    e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(rn));
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "the primary serves again once the persist is durable (3,4 now commit)"
  );
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks); // snapshot done → root write
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks); // root done → checkpoint advances
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  let mut storage = Storage::new(wal, sb);
  for rn in 1..=2 {
    e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(rn));
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(e.commit(), OpNumber::with(2));
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "synchronous superblock completes both checkpoint writes in the boundary-commit drain"
  );
  assert_eq!(storage.sb_mut().state().checkpoint_op(), OpNumber::with(2));
  assert_ne!(storage.sb_mut().state().checkpoint_id(), 0);
}

#[test]
fn checkpoint_gcs_wal_and_maps_below_the_quorum_checkpoint() {
  // GC: once a checkpoint is durable, the WAL slots + in-memory caches below the prune floor
  // are freed. Single replica (quorum 1) → quorum_checkpoint_op == self.checkpoint_op, so the floor
  // is the checkpoint op (2): ops <= 2 are pruned from the WAL and the log/inflight caches, while a
  // NEW request still commits (apply reads from commit_min, not from a pruned op).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(1), 0, EchoSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  let mut storage = Storage::new(wal, sb);
  for rn in 1..=2 {
    e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(rn));
    e.storage_step(now, &mut storage, &mut blocks); // append durable → commit; on op 2, checkpoint completes
  }
  assert_eq!(e.checkpoint_op(), OpNumber::with(2));
  // Quorum=1 → prune floor = checkpoint_op = 2 → ops <= 2 are freed from the WAL.
  assert!(
    storage.wal_mut().header(OpNumber::with(1)).is_none(),
    "op 1 pruned from the WAL"
  );
  assert!(
    storage.wal_mut().header(OpNumber::with(2)).is_none(),
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
  e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(3));
  e.storage_step(now, &mut storage, &mut blocks);
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  // The backup has heard from no peers → its quorum_checkpoint_op is 0 (conservative).
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::with(0));
  // Append ops 1,2 via Prepares from the primary (replica 0, view 0), pumping the durable append.
  let mut storage = Storage::new(wal, sb);
  for op in 1..=2u64 {
    e.handle_message(
      now,
      &mut storage,
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
    e.storage_step(now, &mut storage, &mut blocks);
  }
  // Commit op 2 so the backup's commit_min reaches the boundary and it checkpoints.
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.storage_step(now, &mut storage, &mut blocks);
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
    storage.wal_mut().header(OpNumber::with(1)).is_none()
      && storage.wal_mut().header(OpNumber::with(2)).is_none(),
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
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
  let mut storage = Storage::new(wal, sb);
  for rn in 1..=2 {
    e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(rn));
    e.storage_step(now, &mut storage, &mut blocks); // primary's own append durable (own vote)
    e.handle_message(
      now,
      &mut storage,
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
    e.storage_step(now, &mut storage, &mut blocks); // drain any checkpoint writes
  }
  assert_eq!(e.commit(), OpNumber::with(2));
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint is durable at op 2"
  );
  let id_before = storage.sb_mut().state().checkpoint_id();
  assert_ne!(id_before, 0);

  // Force a view change: two peers send StartViewChange(view 1) → SVC quorum → ViewChange(1),
  // which submits a durable-view write. Pump it.
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  e.storage_step(now, &mut storage, &mut blocks); // the durable-view write completes
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
    OpNumber::with(2),
    "the view-change durable-view write must PRESERVE the checkpoint_op (not regress to 0)"
  );
  assert_eq!(
    storage.sb_mut().state().checkpoint_id(),
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // A fresh primary in Normal view 0 with no peers heard from has quorum_checkpoint_op == 0.
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::new());
  // Quorum-checkpoint tracking is independent of inflight: the ok is recorded for its replica even
  // without a matching inflight op (the replica-id range check is the only guard).
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
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
  let mut storage = Storage::new(wal, sb);
  for rn in 1..=2 {
    e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(rn));
    e.storage_step(now, &mut storage, &mut blocks);
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary(), "replica 0 is the view-0 primary");
  // A PrepareOk from replica 1 reporting checkpoint_op = 8.
  let mut storage = Storage::new(wal, sb);
  ep.handle_message(
    Instant::ZERO,
    &mut storage,
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
    &mut storage,
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
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
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
  Storage<ReorderWal, TestSb, NoopSm>,
  crate::block_store::InMemoryBlockStore,
) {
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, NoopSm, 4);
  let (wal, sb) = (ReorderWal::bounded(4), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  // Op 1 = body `[1]` staged (completion HELD). Both backups vote → op 1 commits WITHOUT the
  // primary's own vote (2-of-3 quorum from the backups alone) while its own append is still in
  // flight — the client is replied to on the strength of the BACKUPS' durable copies.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    Peer::Client(ClientId::new(7)),
    chaos_req(1),
  );
  assert_eq!(
    storage.wal_mut().staged_ops(),
    std::vec![1],
    "op 1's append is staged, its completion withheld"
  );
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)),
    chaos_ok(1, 1, 0),
  );
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
    Peer::Client(ClientId::new(7)),
    chaos_req(2),
  );
  assert!(
    storage.wal_mut().release_latest_for(2),
    "op 2's append lands normally"
  );
  e.storage_step(now, &mut storage, &mut blocks); // own vote for op 2
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)),
    chaos_ok(2, 1, 0),
  );
  e.storage_step(now, &mut storage, &mut blocks); // drain the checkpoint writes
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "the checkpoint at op 2 is durable"
  );

  // Ops 3 and 4: mint + release + both backups ack CARRYING `checkpoint_op = 2`, so the quorum
  // checkpoint rises to 2 and the checkpoint at op 4 runs GC with prune floor 2 → `storage.wal_mut().prune(3)`.
  for op in 3..=4 {
    e.handle_message(
      now,
      &mut storage,
      Peer::Client(ClientId::new(7)),
      chaos_req(op),
    );
    assert!(
      storage.wal_mut().release_latest_for(op),
      "op {op}'s append lands normally"
    );
    e.storage_step(now, &mut storage, &mut blocks); // own vote
    e.handle_message(
      now,
      &mut storage,
      Peer::Replica(ReplicaId::new(1)),
      chaos_ok(op, 1, 2),
    );
    e.handle_message(
      now,
      &mut storage,
      Peer::Replica(ReplicaId::new(2)),
      chaos_ok(op, 2, 2),
    );
    e.storage_step(now, &mut storage, &mut blocks); // drain (op 4's commit fires the checkpoint + GC)
  }
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the checkpoint at op 4 is durable"
  );
  assert_eq!(
    storage.wal_mut().durable_body(2),
    None,
    "the GC prune freed the durable WAL slots through op 2"
  );
  assert!(
    storage.wal_mut().durable_body(3).is_some() && storage.wal_mut().durable_body(4).is_some(),
    "the un-pruned tail (ops 3, 4) is durably held"
  );
  assert_eq!(
    storage.wal_mut().staged_ops(),
    std::vec![1],
    "op 1's write is STILL staged — the prune could not cancel the device write"
  );
  while e.poll_message().is_some() {}
  (e, storage, blocks)
}

#[test]
fn gc_retires_a_checkpoint_subsumed_deferred_appends_bookkeeping() {
  // Liveness (a deferred append overtaken by the checkpoint). A fence-deferred append's op can
  // COMMIT on the other replicas' quorum votes while the waiter still sits behind an un-quiesced
  // blocker, and the next checkpoint then subsumes it. GC must retire the waiter's WHOLE footprint —
  // the deferred entry AND the `appending` mark it owns — because a dropped waiter never mints a
  // completion: an orphaned mark would hold `has_inflight_storage()` true until the next generation
  // reset, wedging the graceful-shutdown, restart-drain, and seal paths on a healthy replica.
  let (mut e, mut storage, mut blocks) = primary_with_op1_write_held_across_checkpoint_gc();
  let now = Instant::ZERO;

  // Op 5 (the ring alias of op 1 under capacity 4) mints and DEFERS behind op 1's un-quiesced
  // write, then commits on the two backup votes alone — the waiter is now covered by the cluster
  // without ever having been submitted locally.
  e.handle_message(
    now,
    &mut storage,
    Peer::Client(ClientId::new(7)),
    chaos_req(5),
  );
  assert_eq!(
    storage.wal_mut().staged_ops(),
    std::vec![1],
    "op 5's append is deferred (only op 1's old write is physically staged)"
  );
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)),
    chaos_ok(5, 1, 4),
  );
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
    Peer::Client(ClientId::new(7)),
    chaos_req(6),
  );
  assert!(
    storage.wal_mut().release_latest_for(6),
    "op 6's append lands normally"
  );
  e.storage_step(now, &mut storage, &mut blocks); // own vote for op 6
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)),
    chaos_ok(6, 1, 6),
  );
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    chaos_ok(6, 2, 6),
  );
  e.storage_step(now, &mut storage, &mut blocks); // checkpoint at 6 → root durable → GC
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(6),
    "the checkpoint at op 6 is durable and its GC subsumed the deferred op 5"
  );

  // Quiesce the one remaining physical write — op 1's blocker — and drain. With the waiter's whole
  // footprint retired, NOTHING is left in flight: the drain signal settles instead of reading true
  // forever off an `appending` mark no completion can ever clear.
  assert!(
    storage.wal_mut().release_latest_for(1),
    "op 1's old write finally lands"
  );
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(
    !e.has_inflight_storage(&storage),
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
  let (mut e, mut storage, mut blocks) = primary_with_op1_write_held_across_checkpoint_gc();
  let now = Instant::ZERO;

  // Mint op 5 (body `[5]`) — the ring alias of op 1's slot. The Prepare broadcasts (consensus
  // proceeds), but the physical append is DEFERRED behind op 1's un-quiesced write.
  e.handle_message(
    now,
    &mut storage,
    Peer::Client(ClientId::new(7)),
    chaos_req(5),
  );
  assert_eq!(
    storage.wal_mut().staged_ops(),
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
    &mut storage,
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
  while let Some(&newest) = storage.wal_mut().staged_ops().last() {
    assert!(storage.wal_mut().release_latest_for(newest));
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(5),
    "op 5 commits once its deferred append lands (own vote + the backup ack)"
  );
  // THE property: the durable ring slot holds the COMMITTED op 5's bytes — the last write to the
  // slot — and op 1's stale resurrection was evicted by the wrap, not the other way around.
  assert_eq!(
    storage.wal_mut().durable_body(5),
    Some(Bytes::from(std::vec![5u8])),
    "the shared ring slot durably holds the committed op 5's bytes, not op 1's late stale write"
  );
  assert_eq!(
    storage.wal_mut().durable_body(1),
    None,
    "op 1's resurrected entry was evicted by op 5's wrap (the checkpoint owns its content)"
  );
  assert!(
    !e.has_inflight_storage(&storage),
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
  let (mut e, mut storage, mut blocks) = primary_with_op1_write_held_across_checkpoint_gc();
  let now = Instant::ZERO;

  assert!(
    e.has_inflight_storage(&storage),
    "op 1's un-quiesced write still holds the storage-drain signal true"
  );
  assert!(
    storage.wal_mut().cancel_latest_for(1),
    "the backend async-cancels op 1's staged write"
  );
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    storage.wal_mut().staged_ops(),
    std::vec![] as std::vec::Vec<u64>,
    "nothing was re-submitted for the released op (the cancellation is not a fault to retry)"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "no vote/commit moved — the released op's cancellation owes nothing"
  );
  assert_eq!(
    storage.wal_mut().durable_body(1),
    None,
    "the cancelled write never landed (no resurrection)"
  );
  assert!(
    !e.has_inflight_storage(&storage),
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
  let (wal, sb) = (ReorderWal::new(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    Peer::Client(ClientId::new(7)),
    chaos_req(1),
  );
  assert_eq!(
    storage.wal_mut().staged_ops(),
    std::vec![1],
    "op 1's append is staged"
  );
  assert!(
    storage.wal_mut().cancel_latest_for(1),
    "the backend spuriously cancels the LIVE append"
  );
  assert_eq!(
    storage.wal_mut().staged_len(),
    0,
    "the cancel popped the old write before the endpoint reacts"
  );
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    storage.wal_mut().staged_ops(),
    std::vec![1],
    "a FRESH re-submit was staged for the live op (degraded to a retry, not a leak)"
  );

  // The retried append lands → the primary's own vote; one backup ack completes the quorum.
  assert!(
    storage.wal_mut().release_latest_for(1),
    "the re-submitted append lands"
  );
  e.storage_step(now, &mut storage, &mut blocks);
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)),
    chaos_ok(1, 1, 0),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "liveness preserved: the op still commits despite the spurious cancellation"
  );
  assert_eq!(
    storage.wal_mut().durable_body(1),
    Some(Bytes::from(std::vec![1u8])),
    "the durable slot holds the retried append's bytes"
  );
  assert!(
    !e.has_inflight_storage(&storage),
    "nothing lingers once the retried append quiesced"
  );
}

/// A `Normal` backup of a 3-voter cluster with a two-op checkpoint interval — the fixture the
/// block-job falsifiers below drive. A BACKUP is used deliberately: it applies its committed prefix
/// from an incoming `Commit`, so the checkpoint it triggers is issued on the INGRESS path, where the
/// endpoint runs no block work of its own. That is what lets a test hold the materialize.
fn backup_checkpointing_every(ops: u64) -> Endpoint<EchoSm> {
  Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::with_checkpoint_ops(1, MemberId::new(1), ops).expect("valid cluster config"),
    genesis(3),
    0,
    EchoSm,
    u64::MAX,
  )
}

/// Accept `[1..=op]` and commit through `commit`, driving the WAL to durability in between so the
/// backup's appends quiesce.
fn accept_and_commit(
  e: &mut Endpoint<EchoSm>,
  storage: &mut Storage<TestWal, StepSb, EchoSm>,
  blocks: &mut crate::block_store::InMemoryBlockStore,
  ops: core::ops::RangeInclusive<u64>,
  commit: u64,
) {
  let now = Instant::ZERO;
  for op in ops {
    e.handle_message(now, storage, primary_peer(), prepare(op, 0));
  }
  e.storage_step(now, storage, blocks);
  e.handle_message(
    now,
    storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(commit),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
}

#[test]
fn commits_advance_while_a_checkpoint_materialize_is_still_being_written() {
  // ANTI-STALL. The whole point of the job seam: writing a checkpoint's block DAG is storage work,
  // not consensus work, so the pump must keep committing while it runs. Before the seam this test
  // could not even be expressed — `force_checkpoint` materialized both DAGs, flushed, and submitted
  // the superblock write in ONE synchronous call inside the commit, so there was no interval during
  // which a materialize was outstanding and no job to hold.
  //
  // Here the driver's storage lane TAKES the job and does not execute it (a slow disk), and the
  // backup keeps accepting and applying ops the whole time.
  let mut e = backup_checkpointing_every(2);
  let (wal, sb) = (TestWal::default(), StepSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  let mut storage = Storage::new(wal, sb);
  accept_and_commit(&mut e, &mut storage, &mut blocks, 1..=2, 2);
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "the interval boundary is applied"
  );

  // The lane takes the job. ANTI-VACUITY: a materialize really is outstanding — this is the
  // precondition the rest of the test is meaningless without.
  let job = storage
    .poll_block_job()
    .expect("crossing the checkpoint boundary issues the materialize");
  assert_eq!(
    job.tag(),
    crate::BlockJobTag::Materialize,
    "the queued job is the checkpoint's DAG write"
  );
  assert!(
    e.has_inflight_storage(&storage),
    "the held materialize counts as outstanding durability work"
  );
  assert!(
    !storage.sb_mut().has_inflight(),
    "no superblock write exists yet — the pointer may not name blocks that are not flushed"
  );

  // CONSENSUS PROGRESS WHILE IT IS HELD: accept + commit two more ops purely through the ingress
  // path, and observe the endpoint still answering.
  accept_and_commit(&mut e, &mut storage, &mut blocks, 3..=4, 4);
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "commits advanced past the boundary while the materialize was still being written"
  );
  assert!(
    core::iter::from_fn(|| e.poll_message()).count() > 0,
    "the replica kept answering its primary while the materialize was outstanding"
  );
  // ANTI-VACUITY (the second half): the job was STILL unexecuted across all of that — the progress
  // above genuinely overlapped the write rather than following it.
  assert!(
    e.has_inflight_storage(&storage),
    "the materialize is still outstanding after the commits advanced"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "and no checkpoint was published while its blocks were unwritten"
  );

  // Now the lane finishes. Only THEN does the checkpoint's superblock write appear.
  let mut cursor = crate::BlockJobCursor::new();
  let done = crate::execute_block_job(&mut cursor, job, &mut blocks);
  e.on_block_done(now, &mut storage, done);
  assert!(
    storage.sb_mut().has_inflight(),
    "the completed+flushed DAG releases the snapshot write"
  );
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "the checkpoint publishes once its blocks are durable"
  );
}

#[test]
fn a_materialize_that_crosses_a_view_change_is_superseded_and_never_published() {
  // SUPERSESSION. A checkpoint abandoned by a view transition while its DAG was being written must
  // publish NOTHING when the write finally lands: its completion carries roots for a checkpoint the
  // endpoint no longer owns, and naming them would advance the durable pointer off a generation the
  // replica abandoned.
  let mut e = backup_checkpointing_every(2);
  let (wal, sb) = (TestWal::default(), StepSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  let mut storage = Storage::new(wal, sb);
  accept_and_commit(&mut e, &mut storage, &mut blocks, 1..=2, 2);
  let job = storage
    .poll_block_job()
    .expect("crossing the checkpoint boundary issues the materialize");
  let durable_before = storage.sb_mut().state().checkpoint_op();

  // A VIEW CHANGE fires while the DAG is being written: this backup's own idle timeout proposes
  // view 1 and a peer's StartViewChange completes the quorum.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut storage);
  e.handle_message(
    later,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "ANTI-VACUITY: the transition really happened while the materialize was in flight"
  );
  assert_eq!(
    e.block_jobs_superseded(),
    0,
    "nothing has been dropped yet — the job has not completed"
  );

  // The lane finishes AFTER the transition. Its result must be refused.
  let mut cursor = crate::BlockJobCursor::new();
  let done = crate::execute_block_job(&mut cursor, job, &mut blocks);
  e.on_block_done(later, &mut storage, done);
  assert_eq!(
    e.block_jobs_superseded(),
    1,
    "ANTI-VACUITY: the superseded completion really was refused here, not merely absent"
  );
  assert!(
    e.pending_checkpoint.is_none(),
    "no checkpoint write was submitted for the abandoned checkpoint (the only write in flight is \
     the transition's own durable-view root)"
  );
  assert!(
    e.pending_sb.is_some(),
    "ANTI-VACUITY: the transition's durable-view write IS in flight, so the superblock was reachable \
     — the checkpoint's absence is a refusal, not an unreachable superblock"
  );
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
    durable_before,
    "the durable checkpoint pointer never moved"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "and the in-memory pointer never regressed or advanced"
  );
}

#[test]
fn repeated_view_changes_over_a_paused_lane_keep_one_materialize_outstanding() {
  // THE ACCUMULATION BOUND. A view transition clears the LOGICAL `pending_checkpoint` at
  // `FlushingBlocks`, but the `Materialize` it named cannot be retracted — the lane executes serially
  // in issue order, so the job stays queued carrying a full state-machine image plus a session
  // projection. With the logical guard cleared the cadence is free to capture ANOTHER image the moment
  // Normal resumes, so churn against a lane draining slower than the churn rate would queue one large
  // superseded image per round without bound. The PHYSICAL half is tracked independently, so at most
  // one image capture is ever owed to the lane however many times the logical half is dropped.
  //
  // NEUTER CHECK: drop the `materializing` guard in `force_checkpoint` and the queue grows by one
  // `Materialize` per round below (5 instead of 1).
  let mut e = backup_checkpointing_every(2);
  let (wal, sb) = (TestWal::default(), StepSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  // Cross the checkpoint boundary once: the first capture is issued and the lane is PAUSED from here
  // on (no `poll_block_job`, so nothing the endpoint issues ever executes).
  let mut storage = Storage::new(wal, sb);
  accept_and_commit(&mut e, &mut storage, &mut blocks, 1..=2, 2);
  assert!(
    matches!(
      e.pending_checkpoint.map(|pc| pc.step),
      Some(CheckpointStep::FlushingBlocks(_))
    ),
    "precondition: the first capture is queued on the lane and logically tracked"
  );

  // Four view transitions, each adopting a strictly higher view from that view's primary (slots 2 and
  // 0 alternate; slot 1 is this replica). Each one runs the shared transition reset and lands back in
  // Normal with the cadence still due — `checkpoint_op` never advances, because nothing publishes.
  for (round, (view, primary)) in [(2u64, 2u16), (3, 0), (5, 2), (6, 0)]
    .into_iter()
    .enumerate()
  {
    let t = now + core::time::Duration::from_millis(1000 * (round as u64 + 1));
    e.handle_message(
      t,
      &mut storage,
      Peer::Replica(ReplicaId::new(primary)),
      Message::StartView(crate::StartView::new(
        View::with(view),
        OpNumber::with(2),
        OpNumber::with(2),
        crate::Epoch::new(0),
        0,
        ReplicaId::new(primary),
        std::vec::Vec::new(),
      )),
    );
    assert!(
      e.pending_checkpoint.is_none(),
      "round {round}: ANTI-VACUITY — the transition really DID clear the logical guard, leaving the \
       queued image superseded"
    );
    // Settle the adoption's durable-view write WITHOUT touching the block lane, then re-drive the
    // commit tail so the (still due) cadence genuinely attempts a fresh capture.
    for _ in 0..4 {
      storage.sb_mut().flush();
      e.handle_storage(t, &mut storage);
    }
    e.handle_message(
      t,
      &mut storage,
      Peer::Replica(ReplicaId::new(primary)),
      Message::Commit(Commit::new(
        View::with(view),
        OpNumber::with(2),
        OpNumber::new(),
        crate::Epoch::new(0),
        0,
      )),
    );
    assert_eq!(
      e.status(),
      Status::Normal,
      "round {round}: back in Normal, where the cadence runs"
    );
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(0),
      "round {round}: ANTI-VACUITY — nothing published, so the cadence is still due at every round"
    );
    assert!(
      e.commit().get() >= e.checkpoint_op().get() + 2,
      "round {round}: ANTI-VACUITY — the checkpoint boundary really is crossed, so a capture was due"
    );
  }

  // THE BOUND: the paused lane holds exactly ONE image, whatever the churn.
  let mut jobs = std::vec::Vec::new();
  while let Some(job) = storage.poll_block_job() {
    jobs.push(job);
  }
  let materializes = jobs
    .iter()
    .filter(|j| j.tag() == crate::BlockJobTag::Materialize)
    .count();
  assert_eq!(
    materializes, 1,
    "the lane holds ONE image capture across every transition, not one per round"
  );

  // ANTI-VACUITY (the closing half): run the held job and observe the endpoint REFUSE it — the image
  // the rounds above accumulated behind really was superseded, not merely idle.
  let mut cursor = crate::BlockJobCursor::new();
  let superseded_before = e.block_jobs_superseded();
  let last = now + core::time::Duration::from_millis(9000);
  for job in jobs {
    let done = crate::execute_block_job(&mut cursor, job, &mut blocks);
    e.on_block_done(last, &mut storage, done);
  }
  assert!(
    e.block_jobs_superseded() > superseded_before,
    "ANTI-VACUITY: the queued image completed into a state that no longer owns it — a genuine \
     supersession, which is exactly what the rounds above kept producing"
  );
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
    OpNumber::with(0),
    "and no superseded image ever advanced the durable checkpoint pointer"
  );
}

/// A view-0 `Commit` carrying `commit` — the heartbeat that re-drives a backup's committed
/// frontier (and, with it, the checkpoint cadence) after a restart.
fn commit_msg(commit: u64) -> Message {
  Message::Commit(Commit::new(
    View::new(),
    OpNumber::with(commit),
    OpNumber::new(),
    crate::Epoch::new(0),
    0,
  ))
}

#[test]
fn a_restart_in_place_inherits_the_lanes_outstanding_materialize() {
  // THE ACCUMULATION BOUND, ACROSS ENDPOINT REBUILDS. The test above pins the bound across view
  // churn WITHIN one endpoint; this pins it across the other reset the guard must survive — a
  // restart in place, where the storage lane (queue, delivery) outlives the endpoint and `recover`
  // builds a successor over the same session. The image occupies the LANE, and so does the quota it
  // claimed: the successor's capture site starts CLOSED over the still-executing image, opens only
  // when the lane delivers that image's completion (refused at the incarnation choke — a dead
  // incarnation's job can complete no other way), and only then captures fresh.
  //
  // NEUTER CHECK: release the capture quota in `LaneFront::settle` only for own-incarnation
  // completions, or claim it anywhere but the queue, and the re-driven boundary below either queues
  // a SECOND full image behind the first or never opens again.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(2), 2).unwrap(); // a backup of view 0
  let (wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  crate::format(&cfg, &genesis(3), &wal, &mut sb).expect("format the genesis store");

  // The predecessor crosses the checkpoint boundary and captures — but the lane never executes the
  // job, so the image stays queued when the endpoint is replaced.
  let mut storage = Storage::new(wal, sb);
  let mut dead = Endpoint::recover(cfg, genesis(3), 0, EchoSm, &mut storage)
    .expect("recover the formatted store")
    .expect_active();
  assert_eq!(dead.status(), Status::Normal, "resumes Normal as a backup");
  for op in 1..=2 {
    dead.handle_message(now, &mut storage, primary_peer(), prepare(op, 0));
  }
  for _ in 0..4 {
    dead.handle_storage(now, &mut storage);
  }
  dead.handle_message(now, &mut storage, primary_peer(), commit_msg(2));
  let held = storage
    .poll_block_job()
    .expect("the crossed boundary owes an image capture");
  assert!(held.tag().is_materialize());
  assert!(
    storage.materialize_owed(),
    "ANTI-VACUITY: the lane still owes the capture it was handed"
  );
  drop(dead);

  // The successor recovers over the same session, which IS the same lane front. It re-learns the
  // committed frontier and finds the cadence due again — every condition for a capture except the
  // one that matters: the lane already holds an image.
  let mut live = Endpoint::recover(cfg, genesis(3), 1, EchoSm, &mut storage)
    .expect("recover in place over the live storage")
    .expect_active();
  for _ in 0..4 {
    live.handle_storage(now, &mut storage);
  }
  live.handle_message(now, &mut storage, primary_peer(), commit_msg(2));
  assert_eq!(
    live.status(),
    Status::Normal,
    "ANTI-VACUITY: back in Normal"
  );
  assert_eq!(
    live.commit(),
    OpNumber::with(2),
    "ANTI-VACUITY: the committed frontier was re-learned past the boundary"
  );
  assert_eq!(
    live.checkpoint_op(),
    OpNumber::with(0),
    "ANTI-VACUITY: nothing published, so a capture is genuinely due"
  );
  assert!(
    storage.poll_block_job().is_none(),
    "the successor captured a second image behind the lane's un-drained one"
  );

  // The lane finally executes the predecessor's job. Its completion names a dead incarnation —
  // refused, publishing nothing — and that refusal is what re-opens the capture site.
  let mut cursor = crate::BlockJobCursor::new();
  let done = crate::execute_block_job(&mut cursor, held, &mut blocks);
  live.on_block_done(now, &mut storage, done);
  assert_eq!(
    live.foreign_completions_rejected(),
    1,
    "the dead incarnation's materialize was refused at the choke"
  );
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
    OpNumber::with(0),
    "the refused completion advanced no durable pointer"
  );

  // Re-drive the still-due cadence (the next heartbeat): the freed capture site takes the boundary
  // it refused above, and this capture publishes.
  live.handle_message(now, &mut storage, primary_peer(), commit_msg(2));
  let fresh = storage
    .poll_block_job()
    .expect("the released capture site takes the still-due boundary");
  assert!(fresh.tag().is_materialize());
  let done = crate::execute_block_job(&mut cursor, fresh, &mut blocks);
  live.on_block_done(now, &mut storage, done);
  live.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
    OpNumber::with(2),
    "the successor's own capture published once the inherited one released"
  );
}

#[test]
fn a_restart_in_place_inherits_the_lanes_outstanding_serves() {
  // The serve cap is the OTHER lane-depth quota, and it crosses the rebuild the same way: `Serve`
  // jobs a dead endpoint left on the lane still occupy it, so the successor's cap counts them — and
  // each one frees its slot when the lane delivers its completion, refused at the incarnation choke.
  //
  // NEUTER CHECK: count serves on the endpoint instead of on the lane front and the admission loop
  // below accepts a full fresh cap (the refusal assertions fail).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(2), 2).unwrap();
  let (wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  crate::format(&cfg, &genesis(3), &wal, &mut sb).expect("format the genesis store");

  let mut storage = Storage::new(wal, sb);
  let mut dead = Endpoint::recover(cfg, genesis(3), 0, EchoSm, &mut storage)
    .expect("recover the formatted store")
    .expect_active();
  let requester = Peer::Replica(ReplicaId::new(0));
  let addr = crate::block_address(b"a block some laggard wants");
  dead.on_request_block(&mut storage, requester, addr);
  dead.on_request_block(&mut storage, requester, addr);
  let first = storage.poll_block_job().expect("the first serve is queued");
  let second = storage
    .poll_block_job()
    .expect("the second serve is queued");
  assert!(first.tag().is_serve() && second.tag().is_serve());
  assert_eq!(
    storage.serves_outstanding(),
    2,
    "ANTI-VACUITY: the lane still owes both serves"
  );
  drop(dead);

  let mut live = Endpoint::recover(cfg, genesis(3), 1, EchoSm, &mut storage)
    .expect("recover in place over the live storage")
    .expect_active();
  while live.poll_message().is_some() {} // discard the recover chatter; watch for serve replies
  // The successor's cap starts two slots down: it admits exactly `MAX - 2` before refusing.
  for _ in 0..MAX_OUTSTANDING_BLOCK_SERVES - 2 {
    live.on_request_block(&mut storage, requester, addr);
  }
  assert_eq!(
    live.block_serves_refused(),
    0,
    "ANTI-VACUITY: every admission below the inherited-adjusted cap was accepted"
  );
  live.on_request_block(&mut storage, requester, addr);
  assert_eq!(
    live.block_serves_refused(),
    1,
    "the cap counts the dead endpoint's serves still on the lane"
  );

  // The lane delivers one dead serve: refused at the choke — no reply is emitted for it — and its
  // cap slot frees, so the next request is admitted again.
  let mut cursor = crate::BlockJobCursor::new();
  let done = crate::execute_block_job(&mut cursor, first, &mut blocks);
  live.on_block_done(now, &mut storage, done);
  assert_eq!(
    live.foreign_completions_rejected(),
    1,
    "the dead incarnation's serve was refused at the choke"
  );
  assert!(
    live.poll_message().is_none(),
    "a refused serve answers no requester"
  );
  live.on_request_block(&mut storage, requester, addr);
  assert_eq!(
    live.block_serves_refused(),
    1,
    "the freed slot admits the next request — the inherited count releases as the lane drains"
  );
  drop(second);
}

/// A capture that was QUEUED but never POLLED must not wedge the successor's capture site forever.
///
/// The two tests above cover the rebuild landing AFTER the driver polled the job. This one lands it
/// in the window BEFORE the poll — the window in which a queue owned by the endpoint and a quota
/// relayed across the rebuild come apart: the claim is inherited, the job it describes is not, and
/// nothing can ever deliver a completion for a job that no longer exists, so the site never re-opens
/// (no checkpoint, a frozen prune floor, a filling WAL ring, a wedged replica).
///
/// The queue and the quota are ONE object with the lane's lifetime, so there is no such window: the
/// un-polled job is still queued after the rebuild, the successor polls it, and its completion —
/// refused at the incarnation choke — releases the quota that admitted it.
///
/// The drive below is behaviour-only: it re-learns the committed frontier, executes every job the
/// lane yields, and re-drives the still-due cadence across several heartbeats. However the rebuild
/// treats the lane, a checkpoint must eventually publish.
///
/// NEUTER CHECK: give the endpoint back its own `block_jobs` queue (or reset the lane front in
/// `recover`) and the drive below publishes nothing.
#[test]
fn a_capture_queued_but_never_polled_does_not_wedge_the_successors_capture_site() {
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(2), 2).unwrap(); // a backup of view 0
  let (wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  crate::format(&cfg, &genesis(3), &wal, &mut sb).expect("format the genesis store");

  // The predecessor crosses the checkpoint boundary and queues the image capture — and is replaced
  // BEFORE the driver polls it off the endpoint.
  let mut storage = Storage::new(wal, sb);
  let mut dead = Endpoint::recover(cfg, genesis(3), 0, EchoSm, &mut storage)
    .expect("recover the formatted store")
    .expect_active();
  for op in 1..=2 {
    dead.handle_message(now, &mut storage, primary_peer(), prepare(op, 0));
  }
  for _ in 0..4 {
    dead.handle_storage(now, &mut storage);
  }
  dead.handle_message(now, &mut storage, primary_peer(), commit_msg(2));
  assert!(
    storage.materialize_owed(),
    "ANTI-VACUITY: the capture quota is claimed while the job is still QUEUED, un-polled"
  );
  // The endpoint is replaced without the job ever being handed to a lane.
  drop(dead);

  // The successor recovers over the same session — the queue and the quota come with it.
  let mut live = Endpoint::recover(cfg, genesis(3), 1, EchoSm, &mut storage)
    .expect("recover in place over the live storage")
    .expect_active();
  let mut cursor = crate::BlockJobCursor::new();
  for _ in 0..4 {
    for _ in 0..4 {
      live.handle_storage(now, &mut storage);
    }
    // The heartbeat re-drives the committed frontier and, with it, the still-due capture cadence.
    live.handle_message(now, &mut storage, primary_peer(), commit_msg(2));
    // Execute EVERYTHING the successor's lane yields, to completion — if the queued job survived
    // the rebuild, this runs it (its completion refused or published, either releases the site);
    // if the site re-opens, this runs the fresh capture.
    while let Some(job) = storage.poll_block_job() {
      let done = crate::execute_block_job(&mut cursor, job, &mut blocks);
      live.on_block_done(now, &mut storage, done);
    }
    live.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    live.status(),
    Status::Normal,
    "ANTI-VACUITY: back in Normal"
  );
  assert_eq!(
    live.commit(),
    OpNumber::with(2),
    "ANTI-VACUITY: the committed frontier was re-learned past the boundary"
  );

  // THE INVARIANT: the boundary is crossed and the cadence has been re-driven repeatedly with the
  // lane fully drained each round — a checkpoint must have published. A capture site that never
  // opens again is the permanent wedge: no checkpoint, no prune, a frozen floor.
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
    OpNumber::with(2),
    "no checkpoint ever published after the rebuild: a claim survived that the job it describes did \
     not, so nothing could ever re-open the capture site"
  );
}

/// Drive a backup to a DURABLE checkpoint, then hand back two freshly issued block jobs — a GC
/// sweep over the live roots, then a serve for a peer's block — plus the parts. Two OUTSTANDING
/// jobs is the precondition every issue-order falsifier needs, and it is asserted at every use.
///
/// The sweep is deliberately the EARLIER of the pair: the hazard the order contract exists for is a
/// stale sweep running after a later materialize, so the falsifiers below need the damaging job
/// first. The second is a serve rather than a second sweep because the lane admits one sweep at a
/// time — a second offered while the first is still queued is coalesced into it — and a serve is
/// the kind whose cap admits many, so the pair is genuinely two jobs.
#[allow(clippy::type_complexity)]
fn two_outstanding_block_jobs() -> (
  Endpoint<EchoSm>,
  Storage<TestWal, StepSb, EchoSm>,
  crate::block_store::InMemoryBlockStore,
  crate::BlockJob<EchoSm>,
  crate::BlockJob<EchoSm>,
) {
  let mut e = backup_checkpointing_every(2);
  let (wal, sb) = (TestWal::default(), StepSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  accept_and_commit(&mut e, &mut storage, &mut blocks, 1..=2, 2);
  for _ in 0..3 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "precondition: a durable checkpoint establishes the live GC roots"
  );
  assert!(
    storage.poll_block_job().is_none(),
    "precondition: the durable-checkpoint drive left no job outstanding, so the only jobs below are \
     the two this helper issues"
  );
  e.gc_blocks_for_test(&mut storage);
  e.on_request_block(
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    crate::block_address(b"a block a laggard peer asked this backup for"),
  );
  let first = storage.poll_block_job().expect("the sweep is queued");
  let second = storage
    .poll_block_job()
    .expect("the serve is queued behind it");
  assert_ne!(
    first.id(),
    second.id(),
    "precondition: two DISTINCT jobs are outstanding"
  );
  (e, storage, blocks, first, second)
}

#[test]
fn the_storage_lane_executes_block_jobs_in_issue_order() {
  // CONTROL ARM for the two falsifiers below: in issue order, both the lane's cursor and the
  // endpoint's completion gate accept the pair. Without this the `should_panic` arms could pass for
  // the wrong reason (any panic, from any cause).
  let (mut e, mut storage, mut blocks, first, second) = two_outstanding_block_jobs();
  let mut cursor = crate::BlockJobCursor::new();
  let d1 = crate::execute_block_job(&mut cursor, first, &mut blocks);
  let d2 = crate::execute_block_job(&mut cursor, second, &mut blocks);
  e.on_block_done(Instant::ZERO, &mut storage, d1);
  e.on_block_done(Instant::ZERO, &mut storage, d2);
  assert!(
    !e.has_inflight_storage(&storage),
    "both jobs retired, so the endpoint owes no storage work"
  );
}

#[test]
#[should_panic(expected = "block job executed out of issue order")]
fn a_storage_lane_that_executes_out_of_issue_order_fails_stop() {
  // THE DRIVER-CONTRACT FALSIFIER. Serial execution in issue order is a storage-SAFETY obligation,
  // not a convenience: a sweep carrying one generation's live roots, run after the next generation's
  // materialize, frees the very blocks the next durable root is about to name. Admission is strictly
  // greater, so the later-issued job (delivered first here) executes and the EARLIER one is stopped
  // before it touches the store — which is the direction that matters, since the damaging job (the
  // stale sweep) is always the earlier of the pair.
  let (_e, _storage, mut blocks, first, second) = two_outstanding_block_jobs();
  let mut cursor = crate::BlockJobCursor::new();
  let _ = crate::execute_block_job(&mut cursor, second, &mut blocks);
  let _ = crate::execute_block_job(&mut cursor, first, &mut blocks);
}

#[test]
#[should_panic(expected = "block job completion out of issue order")]
fn a_storage_lane_that_delivers_completions_out_of_order_fails_stop() {
  // The endpoint's half of the same contract: even a lane that EXECUTES in order must deliver the
  // completions in order, because the endpoint's correlation decisions (publish this checkpoint,
  // retire that obligation) are sequenced against the issue order it minted.
  let (mut e, mut storage, mut blocks, first, second) = two_outstanding_block_jobs();
  let mut cursor = crate::BlockJobCursor::new();
  let d1 = crate::execute_block_job(&mut cursor, first, &mut blocks);
  let d2 = crate::execute_block_job(&mut cursor, second, &mut blocks);
  e.on_block_done(Instant::ZERO, &mut storage, d2);
  let _ = d1;
}

#[test]
fn a_block_job_completion_from_a_dead_incarnation_is_refused_and_counted() {
  // THE INCARNATION CHOKE, on the block-job lane. Two endpoints over the same store mint their
  // correlation sequences INDEPENDENTLY from 1, so a dead instance's completion can carry the exact
  // sequence number the live instance has outstanding — and both jobs sit in ONE lane, so the
  // completion really is delivered into the successor. Without the incarnation check the dead
  // endpoint's serve would answer the live endpoint's requester off state it no longer owns.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(2), 2).unwrap();
  let (wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  crate::format(&cfg, &genesis(3), &wal, &mut sb).expect("format the genesis store");
  let mut storage = Storage::new(wal, sb);
  let requester = Peer::Replica(ReplicaId::new(0));
  let addr = crate::block_address(b"a block some laggard wants");

  let mut dead = Endpoint::recover(cfg, genesis(3), 0, EchoSm, &mut storage)
    .expect("recover the formatted store")
    .expect_active();
  dead.on_request_block(&mut storage, requester, addr);
  let dead_job = storage
    .poll_block_job()
    .expect("the dead instance's serve is queued on the lane");
  drop(dead);

  // A restart in place: the successor recovers over the same session, so the dead job is still the
  // lane's and its completion is still owed HERE.
  let mut live = Endpoint::recover(cfg, genesis(3), 1, EchoSm, &mut storage)
    .expect("recover in place over the live storage")
    .expect_active();
  while live.poll_message().is_some() {} // discard the recover chatter; watch for serve replies
  live.on_request_block(&mut storage, requester, addr);
  let live_job = storage
    .poll_block_job()
    .expect("the live instance's serve is queued behind it");
  // ANTI-VACUITY: the ids genuinely ALIAS on the sequence and differ only in the incarnation, which
  // is exactly the case the choke exists for.
  assert_eq!(
    dead_job.id().seq(),
    live_job.id().seq(),
    "the two instances minted the same correlation sequence"
  );
  assert_ne!(
    dead_job.id().incarnation(),
    live_job.id().incarnation(),
    "but different incarnations"
  );

  // The lane executes in issue order, so the dead job's completion arrives first.
  let mut cursor = crate::BlockJobCursor::new();
  let foreign = crate::execute_block_job(&mut cursor, dead_job, &mut blocks);
  assert_eq!(live.foreign_completions_rejected(), 0);
  live.on_block_done(now, &mut storage, foreign);
  assert_eq!(
    live.foreign_completions_rejected(),
    1,
    "the foreign completion was refused at the choke and counted"
  );
  assert!(
    live.poll_message().is_none(),
    "and it answered nobody: the refusal consumed no output"
  );
  assert!(
    live.has_inflight_storage(&storage),
    "the live endpoint's own serve is still owed — the refusal did not retire it"
  );

  // The live endpoint's OWN completion still lands, proving the refusal was surgical.
  let own = crate::execute_block_job(&mut cursor, live_job, &mut blocks);
  live.on_block_done(now, &mut storage, own);
  assert!(
    live
      .poll_message()
      .is_some_and(|out| matches!(out.into_msg(), Message::BlockResponse(_))),
    "its own serve answers the requester"
  );
  assert!(
    !live.has_inflight_storage(&storage),
    "and the lane owes nothing further"
  );
}

use super::super::*;
use super::*;
use crate::{ClientId, Config, OpNumber, Prepare, ReplicaId, Request, RequestNumber, View};

#[test]
fn checkpoint_envelope_round_trips_sessions_and_snapshot() {
  let mut sessions = BTreeMap::new();
  sessions.insert(
    7u128,
    Session {
      request: RequestNumber::with(3),
      reply: Some((RequestNumber::with(3), Bytes::from_static(b"r3"))),
    },
  );
  sessions.insert(
    9u128,
    Session {
      request: RequestNumber::with(1),
      reply: None,
    },
  );
  let snap = Bytes::from_static(b"SM-SNAPSHOT");
  let env = Endpoint::<NoopSm>::encode_checkpoint(OpNumber::with(42), &sessions, &snap);
  let (decoded_op, decoded_sessions, decoded_snap) =
    Endpoint::<NoopSm>::decode_checkpoint(&env).expect("a well-formed envelope decodes");
  assert_eq!(
    decoded_op,
    OpNumber::with(42),
    "the bound checkpoint op round-trips (F3)"
  );
  assert_eq!(decoded_snap, &b"SM-SNAPSHOT"[..]);
  assert_eq!(decoded_sessions.len(), 2);
  assert_eq!(decoded_sessions[&7].request, RequestNumber::with(3));
  assert_eq!(
    decoded_sessions[&7].reply.as_ref().unwrap().1,
    Bytes::from_static(b"r3")
  );
  assert_eq!(decoded_sessions[&9].reply, None);
  // The bound op is part of the content hash: encoding the SAME sessions+snapshot under a DIFFERENT
  // op yields a DIFFERENT checkpoint_id (so an overstated advertised op cannot reuse stale bytes' id).
  let env_other_op = Endpoint::<NoopSm>::encode_checkpoint(OpNumber::with(43), &sessions, &snap);
  assert_ne!(
    crate::checkpoint_id(&env),
    crate::checkpoint_id(&env_other_op),
    "the checkpoint op is bound into the content hash"
  );
  // empty sessions + empty snapshot is a valid envelope (op 0)
  let empty =
    Endpoint::<NoopSm>::encode_checkpoint(OpNumber::new(), &BTreeMap::new(), &Bytes::new());
  let (eop, es, esnap) =
    Endpoint::<NoopSm>::decode_checkpoint(&empty).expect("the empty envelope decodes");
  assert_eq!(eop, OpNumber::new());
  assert!(es.is_empty());
  assert!(esnap.is_empty());

  // A truncated / malformed envelope decodes to None (fault-not-panic), never an out-of-range panic.
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&[]).is_none(),
    "an empty buffer (missing the leading op) is malformed → None"
  );
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&[0, 0, 0, 0, 0, 0, 0]).is_none(),
    "a buffer too short for the 8-byte leading op is malformed → None"
  );
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none(),
    "the op is present but the buffer is too short for the 4-byte session count → None"
  );
  // The op + a count of 1 session but with no session bytes following → None (not a panic).
  let mut count1 = std::vec::Vec::new();
  count1.extend_from_slice(&7u64.to_be_bytes()); // bound op
  count1.extend_from_slice(&1u32.to_be_bytes()); // 1 session, no payload follows
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&count1).is_none(),
    "a count of 1 with no session payload is truncated → None"
  );
  // A reply-length field that overruns the remaining bytes → None (the bounds check on the body).
  let mut overrun = std::vec::Vec::new();
  overrun.extend_from_slice(&7u64.to_be_bytes()); // bound op
  overrun.extend_from_slice(&1u32.to_be_bytes()); // 1 session
  overrun.extend_from_slice(&7u128.to_be_bytes()); // client
  overrun.extend_from_slice(&3u64.to_be_bytes()); // request
  overrun.push(1); // has_reply
  overrun.extend_from_slice(&3u64.to_be_bytes()); // reply request number
  overrun.extend_from_slice(&999u32.to_be_bytes()); // reply len 999 (but no body follows)
  assert!(
    Endpoint::<NoopSm>::decode_checkpoint(&overrun).is_none(),
    "a reply length that overruns the buffer is malformed → None (no panic)"
  );
}

#[test]
fn primary_checkpoints_after_interval_ops_via_two_superblock_writes() {
  // Single-replica cluster (quorum 1): the primary commits each op as soon as its append is
  // durable. With checkpoint_ops=2, committing op 2 makes commit_min=2 >= checkpoint_op(0)+2 →
  // the checkpoint sequence runs (TWO superblock writes), and checkpoint_op advances to 2 ONLY
  // after BOTH writes are durable. `StepSb` completes writes lazily (`flush` between rounds) so
  // each of the three steps is observed in isolation.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
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
    Peer::Client(ClientId::new(7)),
    req(1),
  );
  e.handle_storage(now, &mut wal, &mut sb); // append durable → commit op 1
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
    Peer::Client(ClientId::new(7)),
    req(2),
  );
  e.handle_storage(now, &mut wal, &mut sb); // append durable → commit op 2 → submit_write_checkpoint
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
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(sb.has_inflight(), "step 2: the root write is inflight");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "still not durable after only the snapshot write completed"
  );

  // Flush step 2 (root durable) → step 3: the checkpoint officially advances in-memory.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(!sb.has_inflight(), "the sequence is complete");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint durable after both writes"
  );
  // The durable root now names the new checkpoint, with a non-zero content id (hash of envelope).
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(2));
  assert_ne!(sb.state().checkpoint_id(), 0);
}

#[test]
fn checkpoint_does_not_double_trigger_while_in_flight() {
  // While a checkpoint's superblock writes are pending, commit_min may keep advancing; a second
  // overlapping checkpoint must NOT start. checkpoint_ops=2: after op 2 triggers a checkpoint,
  // committing ops 3,4 (which also cross a 2-op boundary) must not arm a second checkpoint while
  // the first is in flight — only ONE checkpoint completes, landing at the op it staged (2).
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
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
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(e.commit(), OpNumber::with(2));
  assert_eq!(e.checkpoint_op(), OpNumber::with(0));
  assert!(
    sb.has_inflight(),
    "the first checkpoint's snapshot write is inflight"
  );

  // Send requests 3,4 WHILE the first checkpoint's snapshot write is still in flight. The M3.5
  // op-reset DEFENSE (`on_request` short-circuits while `pending_checkpoint.is_some()`) DROPS them —
  // a primary must not assign new ops while a checkpoint-persist is in flight (an op-reuse hazard).
  // So commit stays at 2, and (a fortiori) no second checkpoint is armed.
  for rn in 3..=4 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb);
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
  e.handle_storage(now, &mut wal, &mut sb); // step 1 done → step 2 (root write) inflight
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb); // step 2 done → checkpoint advances to 2
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
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "the primary serves again once the persist is durable (3,4 now commit)"
  );
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb); // snapshot done → root write
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb); // root done → checkpoint advances
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
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb);
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
  // M3.4b GC: once a checkpoint is durable, the WAL slots + in-memory caches below the prune floor
  // are freed. Single replica (quorum 1) → quorum_checkpoint_op == self.checkpoint_op, so the floor
  // is the checkpoint op (2): ops <= 2 are pruned from the WAL and the log/inflight caches, while a
  // NEW request still commits (apply reads from commit_min, not from a pruned op).
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb); // append durable → commit; on op 2, checkpoint completes
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
    Peer::Client(ClientId::new(7)),
    req(3),
  );
  e.handle_storage(now, &mut wal, &mut sb);
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
  // grow unbounded. M3.4b's asymmetric floor lets a BACKUP prune below its OWN durable checkpoint
  // (those ops are in its snapshot; a laggard below it state-syncs). This test drives a backup
  // (replica 1 of 3) to a durable checkpoint via Prepares + Commits and asserts it pruned.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // The backup has heard from no peers → its quorum_checkpoint_op is 0 (conservative).
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::with(0));
  // Append ops 1,2 via Prepares from the primary (replica 0, view 0), pumping the durable append.
  for op in 1..=2u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::Prepare(Prepare::new(
        View::new(),
        OpNumber::with(op),
        OpNumber::with(op - 1), // commit lags by one so each Prepare also commits the prior op
        OpNumber::new(),        // primary's checkpoint_op (0; irrelevant here)
        ClientId::new(7),
        RequestNumber::with(op),
        Bytes::from(std::vec![op as u8]),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb);
  }
  // Commit op 2 so the backup's commit_min reaches the boundary and it checkpoints.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
  );
  e.handle_storage(now, &mut wal, &mut sb);
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
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb); // primary's own append durable (own vote)
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(rn),
        ReplicaId::new(1),
        OpNumber::new(),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb); // drain any checkpoint writes
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
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(1))),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
  );
  assert_eq!(e.status(), Status::ViewChange);
  e.handle_storage(now, &mut wal, &mut sb); // the durable-view write completes
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
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // A fresh primary in Normal view 0 with no peers heard from has quorum_checkpoint_op == 0.
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::new());
  // Quorum-checkpoint tracking is independent of inflight: the ok is recorded for its replica even
  // without a matching inflight op (the replica-id range check is the only guard).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::with(5),
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
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(2),
      OpNumber::with(3),
    )),
  );
  assert_eq!(e.quorum_checkpoint_op(), OpNumber::with(3));
}

#[test]
fn quorum_checkpoint_op_single_replica_is_self() {
  // N=1, quorum=1 → the quorum checkpoint is exactly self's checkpoint (no peers to wait for).
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let mut e = Endpoint::new(cfg, 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(e.checkpoint_op(), OpNumber::with(2));
  assert_eq!(
    e.quorum_checkpoint_op(),
    OpNumber::with(2),
    "single-replica quorum checkpoint follows self's checkpoint"
  );
}

// ── M3.5 T1: monotone peer_checkpoint ──

#[test]
fn peer_checkpoint_is_monotone_under_reordering() {
  // A primary records a peer's checkpoint_op, then a REORDERED older report arrives. The recorded
  // value must NOT regress — the GC floor + the force-sync trigger that read `quorum_checkpoint_op`
  // all rely on monotone per-peer checkpoints (a regressing floor could un-fire the escalation).
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 1, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary(), "replica 0 is the view-0 primary");
  // A PrepareOk from replica 1 reporting checkpoint_op = 8.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::with(8),
    )),
  );
  assert_eq!(ep.peer_checkpoint_for_test(1), 8);
  // A REORDERED older PrepareOk from replica 1 reporting checkpoint_op = 4 — must NOT regress.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::with(4),
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
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(0),
      OpNumber::with(6),
    )),
  );
  assert_eq!(e.peer_checkpoint_for_test(0), 6);
  // A reordered older Commit (checkpoint 2) must not regress the recorded value.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(0),
      OpNumber::with(2),
    )),
  );
  assert_eq!(
    e.peer_checkpoint_for_test(0),
    6,
    "a reordered older Commit must not regress the recorded primary checkpoint"
  );
}

// ── State-sync (M3.4a) ──

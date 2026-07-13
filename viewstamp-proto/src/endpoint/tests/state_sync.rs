// NOTE: the over-frame CHUNKED state-sync transfer (`SyncCheckpointMeta` / `RequestSyncChunk` /
// `SyncChunk`, the `sync_donating`/`sync_transfer` donor+receiver state, the announce→pull→reassemble
// loop, the donor serve-cache + cold/warm reread, the slot-shifted meta/chunk admission legs, and the
// chunk-level cross-epoch transfer/cancel tests) has been REPLACED by a content-addressed block fetch
// (`RequestBlock`/`BlockResponse` over the SM checkpoint DAG). Those tests are dropped here; the
// block-fetch transfer is covered by the simulation's DAG state machine + a follow-up oracle. The
// single-frame `SyncCheckpoint` whole-envelope path (and every guard/freshness/cross-epoch-membership
// test that runs on the message metadata) is RETAINED below. A `SyncCheckpoint` now carries a SMALL
// envelope (`op | sessions | sm_root(16B)`) whose tail is the SM checkpoint DAG ROOT, not inline SM
// bytes; a laggard FETCHES the DAG from the block store before installing. In these unit tests the
// donor's checkpoint leaf is seeded into the laggard's block store up front (see `seed_donor_blocks`),
// so a delivered `SyncCheckpoint` installs immediately (its block-fetch frontier drains locally without
// a `RequestBlock` round trip) — the install assertions are unchanged.
use super::{super::*, *};
use crate::{
  ClientId, Config, Header, OpId, OpNumber, Prepare, ReadOk, ReplicaId, Request, RequestNumber,
  SlotStatus, StartViewChange, View, VsrState, Wal, WalDone, block_store::MemBlockStore,
};
use std::collections::VecDeque;

/// A FIXED-RING WAL of `capacity` slots (the bounded-WAL backend, modelled for the proto unit
/// tests). Op `K` occupies ring slot `K mod capacity`; appending `K` EVICTS whatever op last held that
/// slot (op `K - capacity`), so the resident set never exceeds `capacity` and a read of the
/// wrapped-over op returns `Absent` — exactly the sim's `set_capacity` semantics
/// (`viewstamp_simulation::storage`). Used to drive the proto's `maybe_sync_below_ring_window` /
/// `append_prepare`-overflow paths deterministically at the unit level (`TestWal` is unbounded).
struct RingWal {
  entries: BTreeMap<u64, (Header, Bytes)>,
  head: u64,
  capacity: u64,
  done: VecDeque<WalDone>,
}
impl RingWal {
  fn new(capacity: u64) -> Self {
    Self {
      entries: BTreeMap::new(),
      head: 0,
      capacity,
      done: VecDeque::new(),
    }
  }
}
impl Wal for RingWal {
  fn op_head(&self) -> OpNumber {
    OpNumber::with(self.head)
  }
  fn capacity(&self) -> u64 {
    self.capacity
  }
  fn header(&self, op: OpNumber) -> Option<Header> {
    self.entries.get(&op.get()).map(|(h, _)| *h)
  }
  fn status(&self, op: OpNumber) -> SlotStatus {
    if self.entries.contains_key(&op.get()) {
      SlotStatus::Clean
    } else {
      SlotStatus::Empty
    }
  }
  fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes) {
    // Evict the op that last held this ring slot (op `K - capacity`), modelling the physical wrap.
    if op.get() > self.capacity {
      self.entries.remove(&(op.get() - self.capacity));
    }
    self.entries.insert(op.get(), (header, body));
    self.head = self.head.max(op.get());
    self.done.push_back(WalDone::Appended(id));
  }
  fn submit_read(&mut self, id: OpId, op: OpNumber) {
    self.done.push_back(match self.entries.get(&op.get()) {
      Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    });
  }
  fn truncate(&mut self, above: OpNumber) {
    self.entries.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
  }
  fn prune(&mut self, below: OpNumber) {
    self.entries.retain(|&op, _| op >= below.get());
  }
  fn poll(&mut self) -> Option<WalDone> {
    self.done.pop_front()
  }
}

#[test]
fn a_bound_breach_abort_increments_the_dag_walk_counter() {
  // `dag_walks_capped` is the observability witness for a block-DAG sync read/transfer ABORTED at
  // MAX_REACHABLE_BLOCKS (a malformed / foreign / oversized DAG). Every abort increments it once: a teardown
  // that frees a live `block_fetch` routes through the shared `abort_oversized_block_fetch` helper (this
  // test's target), while the two NO-fetch local walks — the recovery checkpoint read and the
  // fresh-checkpoint re-pin, where the aborted fetch is a local not yet installed — count inline. This test
  // pins the shared helper moving the witness 0 → 1; the 2^20-block TooManyBlocks trigger itself is covered
  // by the block_sync unit tests.
  let mut e = sync_backup();
  assert_eq!(e.dag_walks_capped(), 0, "no aborts yet");
  e.abort_oversized_block_fetch();
  assert_eq!(
    e.dag_walks_capped(),
    1,
    "a reachable-block-bound abort increments the observability counter"
  );
}

#[test]
fn stale_checkpoint_commit_triggers_request_sync() {
  // replica 1 of 3, Normal, head op 0, checkpoint 0. A Commit advertising checkpoint_op=8 (> our
  // head) means the cluster checkpointed past our entire WAL → we must state-sync.
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(10),
      OpNumber::with(8),
      crate::Epoch::new(0),
      0,
    )),
  );
  let mut saw = None;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSync(r) = out.msg_ref() {
      saw = Some(*r);
    }
  }
  let r = saw.expect("a stale-checkpoint replica broadcasts RequestSync");
  assert_eq!(
    r.checkpoint_op(),
    OpNumber::with(0),
    "advertises our stale checkpoint"
  );
  assert_eq!(r.replica(), ReplicaId::new(1));
  assert_eq!(
    e.status(),
    Status::Normal,
    "still Normal (sync is in-band, not a status)"
  );
  // The fresh arm surfaced as an observability event carrying the solicited target.
  assert!(
    core::iter::from_fn(|| e.poll_event())
      .any(|ev| ev == Event::StateSyncStarted(OpNumber::with(8))),
    "arming a state-sync emits StateSyncStarted with the target checkpoint op"
  );
}

#[test]
fn stale_checkpoint_prepare_triggers_request_sync() {
  // A `Prepare` (not just a Commit) carrying checkpoint_op > our head also triggers the sync — the
  // this commit signal closes the last trigger gap for a backup that only ever hears Prepares.
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare_ck(9, 8, 8),
  );
  let mut saw_sync = false;
  while let Some(out) = e.poll_message() {
    saw_sync |= out.msg_ref().is_request_sync();
  }
  assert!(
    saw_sync,
    "a Prepare advertising a far-ahead checkpoint triggers state-sync"
  );
}

#[test]
fn in_reach_checkpoint_does_not_trigger_sync() {
  // checkpoint_op == our head (8) and we hold the tail → ordinary catch-up suffices, NO sync.
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  for op in 1..=8 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      primary_peer(),
      prepare(op, 0),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(8),
      OpNumber::with(8),
      crate::Epoch::new(0),
      0,
    )),
  );
  let mut saw_sync = false;
  while let Some(out) = e.poll_message() {
    saw_sync |= out.msg_ref().is_request_sync();
  }
  assert!(!saw_sync, "checkpoint within our held log → no state-sync");
}

#[test]
fn already_syncing_does_not_emit_a_second_handshake_per_heartbeat() {
  // Once a sync is outstanding, a second Commit only RAISES the target — it does not emit a fresh
  // RequestSync per heartbeat (only the timer re-solicits).
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(10),
      OpNumber::with(8),
      crate::Epoch::new(0),
      0,
    )),
  );
  let first: usize = {
    let mut n = 0;
    while let Some(out) = e.poll_message() {
      n += usize::from(out.msg_ref().is_request_sync());
    }
    n
  };
  assert_eq!(first, 1, "the trigger emits exactly one RequestSync");
  // A second heartbeat (even a higher checkpoint) must NOT emit another handshake immediately.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(12),
      OpNumber::with(10),
      crate::Epoch::new(0),
      0,
    )),
  );
  let second: usize = {
    let mut n = 0;
    while let Some(out) = e.poll_message() {
      n += usize::from(out.msg_ref().is_request_sync());
    }
    n
  };
  assert_eq!(
    second, 0,
    "a second heartbeat raises the target but emits no fresh handshake"
  );
}

#[test]
fn primary_answers_request_sync_with_sync_checkpoint() {
  // A donor primary with a durable checkpoint at op 2 answers a lagging replica's RequestSync by
  // shipping a SyncCheckpoint with the right op/id/snapshot/nonce, addressed back to the requester.
  let (mut e, mut wal, mut sb) = donor_primary_at_checkpoint(2);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  while e.poll_message().is_some() {} // drain prepares/replies from the warm-up
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      e.view(),
      OpNumber::with(0),
      ReplicaId::new(2),
      0xCAFE,
      false,
      0, // ordinary state-sync (not a recovery peer-fetch)
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the checkpoint read completes → ship SyncCheckpoint
  let mut shipped = None;
  while let Some(out) = e.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      shipped = Some((out.to(), s.clone()));
    }
  }
  let (to, s) = shipped.expect("primary ships a SyncCheckpoint");
  assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(2))));
  assert_eq!(s.checkpoint_op(), OpNumber::with(2));
  assert_eq!(s.checkpoint_id(), sb.state().checkpoint_id());
  assert_eq!(s.nonce(), 0xCAFE);
  assert_eq!(
    crate::checkpoint_id(s.snapshot()),
    s.checkpoint_id(),
    "shipped snapshot provably matches its advertised id"
  );
}

#[test]
fn repeat_request_sync_from_one_requester_yields_one_serve_and_one_ship() {
  // `sync_serving` is keyed by REQUESTER: a solicit burst from one replica (here two back-to-back
  // RequestSyncs, e.g. a buggy/impatient peer re-soliciting before the first serve-read completes)
  // must NOT stack a second checkpoint read — the repeat only REFRESHES the echoed nonce, and the
  // single completion ships ONE SyncCheckpoint answering the LATEST solicitation. (A map keyed per
  // minted read id would stack N reads for N solicits, each completion shipping a full snapshot.)
  let (mut e, mut wal, mut sb) = donor_primary_at_checkpoint(2);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  while e.poll_message().is_some() {} // drain the warm-up
  let solicit = |nonce: u64| {
    Message::RequestSync(crate::RequestSync::new(
      View::with(0),
      OpNumber::with(0),
      ReplicaId::new(2),
      nonce,
      false,
      0,
    ))
  };
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    solicit(0xAAAA),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    solicit(0xBBBB),
  );
  assert_eq!(
    e.sync_serving.len(),
    1,
    "one outstanding serve per requester — the repeat solicit must not stack a second read"
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the single serve-read completes
  let mut ships = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      ships.push((out.to(), s.clone()));
    }
  }
  assert_eq!(
    ships.len(),
    1,
    "the burst is answered by exactly ONE shipped snapshot"
  );
  let (to, s) = &ships[0];
  assert_eq!(*to, Recipient::To(Peer::Replica(ReplicaId::new(2))));
  assert_eq!(
    s.nonce(),
    0xBBBB,
    "the completion answers the LATEST solicitation's nonce"
  );
  assert_eq!(s.checkpoint_op(), OpNumber::with(2));
  assert!(
    e.sync_serving.is_empty(),
    "the serve entry is retired on completion"
  );
  // A fresh solicit AFTER completion is served anew (the dedupe holds only while a serve is
  // outstanding — it never starves a requester).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    solicit(0xCCCC),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  let mut again = None;
  while let Some(out) = e.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      again = Some(s.clone());
    }
  }
  assert_eq!(
    again.expect("a post-completion solicit is served").nonce(),
    0xCCCC
  );
}

#[test]
fn serve_sync_checkpoint_drops_a_corrupt_checkpoint_read() {
  // REGRESSION (serve path must be as strict as recover): a Normal donor at a durable
  // checkpoint (op 2) answers a peer's RequestSync by reading its own checkpoint snapshot. A DISK FAULT
  // (in-model: bit-rot in the snapshot region that STILL DECODES) makes that read return CORRUPT bytes
  // bound to the right op — so the existing `cr.op() == checkpoint_op` gate passes — but whose hash no
  // longer matches the donor's DURABLE checkpoint id (`sb.state().checkpoint_id()`). Serving them would
  // ship a self-consistent (corrupt_id, corrupt_snapshot) pair the receiver cannot distinguish from a
  // good one (`on_sync_checkpoint` only re-checks `checkpoint_id(snapshot) == advertised id`, which the
  // donor computed FROM the corrupt bytes), so it would restore CORRUPT SM/session state. With the fix
  // the donor verifies the read bytes against its own durable id (mirroring `recover`'s `id_ok` gate)
  // and DROPS the corrupt read — nothing is served, and the requester re-solicits (another peer, or our
  // next clean read, answers).
  let now = Instant::ZERO;

  // Positive control: a GENUINE checkpoint read IS served (with the correct durable id).
  {
    let (mut e, mut wal, mut sb) = donor_primary_at_checkpoint(2);
    let mut blocks = crate::block_store::MemBlockStore::new();
    while e.poll_message().is_some() {} // drain the warm-up
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestSync(crate::RequestSync::new(
        e.view(),
        OpNumber::with(0),
        ReplicaId::new(2),
        0xABCD,
        false,
        0,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // clean read completes → ship SyncCheckpoint
    let mut shipped = None;
    while let Some(out) = e.poll_message() {
      if let Message::SyncCheckpoint(s) = out.msg_ref() {
        shipped = Some(s.clone());
      }
    }
    let s = shipped.expect("a genuine checkpoint read IS served");
    assert_eq!(s.checkpoint_op(), OpNumber::with(2));
    assert_eq!(
      s.checkpoint_id(),
      sb.state().checkpoint_id(),
      "the served id is the donor's durable checkpoint id"
    );
  }

  // Corrupt case: the read returns bytes that PARSE (same op bound) but hash to a DIFFERENT id than the
  // durable root — the serve path must DROP it (no SyncCheckpoint).
  {
    let (mut e, mut wal, mut sb) = donor_primary_at_checkpoint(2);
    let mut blocks = crate::block_store::MemBlockStore::new();
    while e.poll_message().is_some() {} // drain the warm-up
    // Sanity: the genuine snapshot hashes to the durable id (so the corruption is the only difference).
    let (_genuine, durable_id) = donor_envelope(&sb);
    // Craft a corrupt-but-parseable snapshot bound to the SAME op (2) so `cr.op() == checkpoint_op`
    // still holds — only the SM-tail content differs, so it decodes cleanly yet hashes to a NEW id.
    let mut tampered_sm = CountSm::default();
    tampered_sm.apply(OpNumber::with(1), &[0xDE]);
    tampered_sm.apply(OpNumber::with(2), &[0xAD]);
    let corrupt_env = Endpoint::<CountSm>::encode_checkpoint(
      OpNumber::with(2),
      crate::block_address(&tampered_sm.snapshot()),
      super::super::session_blocks::encode_sessions(
        &std::collections::BTreeMap::new(),
        &mut blocks,
      ),
    );
    assert_ne!(
      crate::checkpoint_id(&corrupt_env),
      durable_id,
      "the corrupt bytes hash to a DIFFERENT id than the durable checkpoint"
    );
    assert!(
      Endpoint::<CountSm>::decode_checkpoint(&corrupt_env).is_some(),
      "the corrupt bytes still PARSE (a decode-but-wrong-content disk fault)"
    );
    // Inject the disk fault: the checkpoint REGION reads back corrupt, but the durable ROOT (and its id)
    // is untouched — exactly bit-rot in the snapshot that the backend cannot detect.
    sb.checkpoint = Some((OpNumber::with(2), corrupt_env));
    assert_eq!(
      sb.state().checkpoint_id(),
      durable_id,
      "the durable root id is unchanged by the snapshot-region corruption"
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestSync(crate::RequestSync::new(
        e.view(),
        OpNumber::with(0),
        ReplicaId::new(2),
        0xCAFE,
        false,
        0,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the corrupt read completes → must be DROPPED
    let served_any = {
      let mut found = false;
      while let Some(out) = e.poll_message() {
        found |= out.msg_ref().is_sync_checkpoint();
      }
      found
    };
    assert!(
      !served_any,
      "a corrupt-but-parseable checkpoint read is NOT served (the serve path is as strict as recover)"
    );
  }
}

#[test]
fn peer_without_newer_checkpoint_does_not_answer_request_sync() {
  // A replica whose checkpoint == requester's (or 0) ships nothing (no megabyte for a no-op).
  let mut e = sync_backup(); // checkpoint 0
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::RequestSync(crate::RequestSync::new(
      e.view(),
      OpNumber::with(0),
      ReplicaId::new(0),
      1,
      false,
      0, // ordinary state-sync (not a recovery peer-fetch)
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(e.poll_message().is_none(), "nothing newer → silent");
}

#[test]
fn recovery_request_sync_is_served_by_a_peer_at_the_same_checkpoint() {
  // REGRESSION (recovery peer-fetch livelock): a recovering replica whose OWN checkpoint snapshot
  // is permanently corrupt solicits a RECOVERY RequestSync advertising its (known) checkpoint_op. The
  // escalation only got served by a STRICTLY-newer peer (`>`), so on an idle cluster where every
  // healthy peer holds EXACTLY the same checkpoint_op, the request was ignored forever → the recovery
  // livelocked (the cluster could stay unavailable if that replica is needed for quorum). With the
  // fix, a `recovery` request is served by a peer at an EQUAL checkpoint_op; an ordinary one is not.
  let now = Instant::ZERO;
  // A donor that is Normal at checkpoint op 2.
  let (mut donor, mut wal, mut sb) = donor_primary_at_checkpoint(2);
  let mut blocks = crate::block_store::MemBlockStore::new();
  while donor.poll_message().is_some() {} // drain warm-up

  // (a) A RECOVERY request at the SAME checkpoint (op 2) IS served.
  donor.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      donor.view(),
      OpNumber::with(2), // EQUAL to the donor's checkpoint
      ReplicaId::new(2),
      0xF00D,
      true,
      0, // recovery peer-fetch
    )),
  );
  donor.handle_storage(now, &mut wal, &mut sb, &mut blocks); // checkpoint read completes → ship SyncCheckpoint
  let mut served = None;
  while let Some(out) = donor.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      served = Some((out.to(), s.clone()));
    }
  }
  let (to, s) = served.expect("a recovery request at an EQUAL checkpoint IS served");
  assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(2))));
  assert_eq!(s.checkpoint_op(), OpNumber::with(2));
  assert_eq!(s.nonce(), 0xF00D);

  // (b) An ORDINARY (non-recovery) request at the SAME checkpoint is NOT served (strict `>`).
  donor.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      donor.view(),
      OpNumber::with(2), // EQUAL to the donor's checkpoint
      ReplicaId::new(2),
      0xBEEF,
      false,
      0, // ordinary state-sync
    )),
  );
  donor.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  let mut ordinary_served = false;
  while let Some(out) = donor.poll_message() {
    if matches!(out.msg_ref(), Message::SyncCheckpoint(_)) {
      ordinary_served = true;
    }
  }
  assert!(
    !ordinary_served,
    "an ordinary RequestSync at an equal checkpoint is NOT served (no megabyte for a no-op)",
  );
}

#[test]
fn recovery_peer_fetch_converges_against_an_equal_checkpoint_peer() {
  // REGRESSION (end-to-end convergence): a replica whose OWN durable checkpoint snapshot is
  // permanently unreadable escalates to a recovery peer-fetch; a Normal peer at the SAME checkpoint
  // op serves it; delivering that SyncCheckpoint converges the recovering replica to Normal. (Before
  // the fix the equal-checkpoint peer ignored the request and the replica never left Recovering.)
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let now = Instant::ZERO;
  // Durable root names a checkpoint at op 2; the scripted SB has an EMPTY read script → every
  // checkpoint read FAULTS (permanently-unreadable own snapshot).
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    0xDEAD_BEEF,
    std::vec::Vec::new(),
  )
  .unwrap()
  .with_wal_geometry(2, u64::MAX);
  let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2, // head == checkpoint_op → empty tail; isolates the checkpoint path
    done: VecDeque::new(),
  };
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 2);
  let mut e = Endpoint::recover(
    cfg,
    genesis(3),
    5,
    CountSm::default(),
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect("recover accepts this store")
  .expect_active();
  // Drive past the per-op retry budget so it escalates to a peer fetch (pumping the recover-retry
  // timer each round — the timer owns the read-retry budget).
  drive_recovery_scripted_sb(&mut e, &mut wal, &mut sb, &mut blocks, now);
  assert_eq!(e.status(), Status::Recovering);
  assert!(e.awaiting_peer_checkpoint_for_test());
  // The escalation emits a RequestSync flagged `recovery` and advertising our own checkpoint op (2).
  let mut req = None;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSync(r) = out.msg_ref() {
      req = Some(*r);
    }
  }
  let req = req.expect("a RequestSync was solicited");
  assert!(req.recovery(), "the recovery escalation flags the request");
  assert_eq!(
    req.checkpoint_op(),
    OpNumber::with(2),
    "advertises its own checkpoint op"
  );

  // A peer that is Normal at the SAME checkpoint op (2) serves this exact request.
  let (mut peer, mut pwal, mut psb) = donor_primary_at_checkpoint(2);
  let mut pblocks = crate::block_store::MemBlockStore::new();
  while peer.poll_message().is_some() {}
  peer.handle_message(
    now,
    &mut pwal,
    &mut psb,
    &mut pblocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::RequestSync(req),
  );
  peer.handle_storage(now, &mut pwal, &mut psb, &mut pblocks);
  let mut answer = None;
  while let Some(out) = peer.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      answer = Some(s.clone());
    }
  }
  let answer = answer.expect("the equal-checkpoint peer SERVES the recovery request");

  // Deliver the peer's SyncCheckpoint back to the recovering replica → it STAGES the re-persist (staying
  // Recovering); once the SyncRepersist root is durable it installs + flips to Normal at the synced point.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(answer),
  );
  // Drive the durable re-persist to completion: flush the scripted superblock each round so the two staged
  // writes (snapshot, then the root) surface and `on_sb_done` lands the root, completing recovery. (The
  // node stays Recovering until the root is durable — the install + flip-to-Normal defer to `on_sb_done`.)
  for _ in 0..16 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    if !e.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "the recovering replica converged via the equal-checkpoint peer fetch",
  );
  assert_eq!(e.checkpoint_op(), OpNumber::with(2));
  assert!(
    !e.awaiting_peer_checkpoint_for_test(),
    "no longer awaiting a peer checkpoint"
  );
}

#[test]
fn sync_checkpoint_restores_and_resumes_at_the_synced_point() {
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  // Trigger sync (Commit advertising checkpoint_op=4), capture the nonce it used.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  // Deliver the SyncCheckpoint.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drive the durable re-persist (TestSb synchronous)
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.commit_max(), OpNumber::with(4));
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(
    e.state_machine_ref().applied().len(),
    4,
    "SM restored from the snapshot, not replayed"
  );
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "synced checkpoint is now durable"
  );
  assert_eq!(sb.state().checkpoint_id(), id);
  // The sync's full arc surfaced as observability events: armed at the learned target, completed
  // once the synced checkpoint went durable.
  let events: std::vec::Vec<Event> = core::iter::from_fn(|| e.poll_event()).collect();
  assert!(
    events.contains(&Event::StateSyncStarted(OpNumber::with(4))),
    "the sync arm emitted StateSyncStarted"
  );
  assert!(
    events.contains(&Event::StateSyncCompleted(OpNumber::with(4))),
    "the durable install emitted StateSyncCompleted"
  );
}

#[test]
fn a_state_sync_flush_fault_retains_the_checkpoint_and_self_retries_the_local_install() {
  // A TRANSIENT block-store flush fault during a state-sync install must NOT drop the verified checkpoint.
  // The laggard has already fetched + verified the COMPLETE DAG (both frontiers drained locally), so the
  // only thing missing is durability; a later flush would succeed. The install is RETAINED as a local
  // retry obligation, and the sync solicit cadence re-flushes + re-stages LOCALLY — no fresh donor reply
  // is needed, so even if the donor crashed after serving the blocks, the sync still completes.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4); // the laggard already holds M's complete DAG (immediate drain)
  blocks.script_flush_fault(1); // the FIRST durability barrier faults; the next succeeds
  let now = Instant::ZERO;
  // Trigger the sync (a Commit advertising checkpoint_op=4) and capture its nonce.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  // Deliver the SyncCheckpoint. The DAG is fully local, so `apply_sync` runs immediately — and hits the
  // scripted flush fault: it must stage NOTHING durable, retain the install, and keep the sync armed.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  // The flush faulted → NOTHING advanced: no durable checkpoint, the in-memory frontier untouched, but
  // the verified install is RETAINED as a local-retry obligation (NOT dropped).
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(0),
    "the flush fault held the durable checkpoint pointer back"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "the in-memory frontier did not advance on the flush fault"
  );
  assert!(
    e.install_flush_retry_owed(),
    "the verified install is RETAINED for a local flush retry, not dropped"
  );

  // The donor is now SILENT — deliver NO further message. Fire ONLY the sync solicit timer past its
  // deadline: the local retry re-flushes (now succeeding) and stages the re-persist with no donor reply.
  let later = now + core::time::Duration::from_millis(150);
  e.sync_timeouts(later, &mut sb, &mut blocks);
  e.handle_storage(later, &mut wal, &mut sb, &mut blocks); // drive the now-staged durable re-persist
  // The retry's flush succeeded → the checkpoint installs and the sync completes, with no fresh donor.
  assert!(
    !e.install_flush_retry_owed(),
    "the local retry consumed the obligation once the flush succeeded"
  );
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "the synced checkpoint is now durable after the retry"
  );
  assert_eq!(sb.state().checkpoint_id(), id);
  assert_eq!(
    e.state_machine_ref().applied().len(),
    4,
    "SM restored from the snapshot after the retry"
  );
  let events: std::vec::Vec<Event> = core::iter::from_fn(|| e.poll_event()).collect();
  assert!(
    events.contains(&Event::StateSyncCompleted(OpNumber::with(4))),
    "the install completed via the LOCAL retry (no fresh donor reply)"
  );
}

#[test]
fn a_retained_install_survives_a_block_gc_before_the_flush_retry() {
  // The GC-isolation guarantee: a state-sync install RETAINED across a flush fault is a LIVE GC ROOT, so a
  // block-store GC sweep that fires WHILE the install is owed (an ordinary checkpoint GC could run before
  // the local flush retry) must NOT free the install's drained DAG — otherwise the later retry would advance
  // the durable checkpoint to name blocks GC already freed, losing the just-synced committed state.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4); // the laggard already holds M's complete DAG (immediate drain)
  // A block reachable from NOTHING — neither a durable checkpoint (the laggard has none yet) nor the
  // retained install's DAG. The GC sweep below must free it, proving the sweep actually ran (not a no-op).
  blocks.write_verified(Bytes::from_static(b"unreferenced-garbage-block"));
  blocks.script_flush_fault(1); // the FIRST durability barrier faults; the next succeeds
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    e.install_flush_retry_owed(),
    "the verified install is RETAINED (flush faulted) — owed, not yet staged"
  );
  let held_before = blocks.len();

  // GC fires BEFORE the local flush retry. The retained install's DAG must SURVIVE (it is a live root); the
  // unreferenced garbage block must be FREED (the sweep ran). Were the install not a GC root, its blocks
  // would be swept here and the retry would re-persist a checkpoint naming freed blocks.
  e.gc_blocks_for_test(&mut blocks);
  assert_eq!(
    blocks.len(),
    held_before - 1,
    "GC swept exactly the unreferenced garbage block — the retained install's DAG survived"
  );

  // The donor is SILENT — fire ONLY the local retry. Its flush now succeeds and stages the re-persist; the
  // SAME verified checkpoint installs (its DAG was never swept) and no committed state is lost.
  let later = now + core::time::Duration::from_millis(150);
  e.sync_timeouts(later, &mut sb, &mut blocks);
  e.handle_storage(later, &mut wal, &mut sb, &mut blocks);
  assert!(
    !e.install_flush_retry_owed(),
    "the retry consumed the retained install once the flush succeeded"
  );
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "the synced checkpoint is durable after the post-GC retry"
  );
  assert_eq!(sb.state().checkpoint_id(), id);
  assert_eq!(
    e.state_machine_ref().applied().len(),
    4,
    "SM restored from the synced snapshot — its DAG survived the intervening GC"
  );
  let events: std::vec::Vec<Event> = core::iter::from_fn(|| e.poll_event()).collect();
  assert!(
    events.contains(&Event::StateSyncCompleted(OpNumber::with(4))),
    "the install completed after a GC swept around it (no committed state lost)"
  );
}

#[test]
fn the_block_fetch_arq_retransmits_a_missing_session_block_after_the_sm_dag_drains() {
  // The block-fetch ARQ (the `sync_solicit` timer's pull re-drive) must re-request the outstanding block
  // across the COMBINED frontier — the SM DAG AND the session-table DAG. A laggard whose SM DAG has
  // FULLY drained locally but whose session DAG is still missing one block must keep retransmitting the
  // SESSION `RequestBlock` on the ARQ timer. Pumping only the SM frontier here would emit NOTHING once
  // the SM DAG drained, so a dropped session `RequestBlock`/`BlockResponse` would strand the whole
  // install until a fresh `SyncCheckpoint` re-pinned the fetch.
  //
  // Setup: a donor at checkpoint 4 over `CountSm` — its checkpoint records client 7's session, so the
  // `sessions_root` DAG has a real (non-empty) leaf to fetch. The laggard is seeded with ONLY the SM DAG
  // (so the SM frontier drains locally), the session leaf withheld. The donor answers session
  // `RequestBlock`s from its own store.
  let (_donor_e, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("the donor envelope decodes");

  // The donor's full block store (BOTH DAGs) — the source the donor serves `RequestBlock`s from.
  let mut donor_blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);
  assert!(
    donor_blocks.has_block(sessions_root),
    "the donor holds the session-table DAG root"
  );

  // The laggard's store: seed ONLY the SM DAG (walk it from `sm_root` in the donor store), so the SM
  // frontier drains locally; the session DAG is deliberately ABSENT.
  let mut blocks = crate::block_store::MemBlockStore::new();
  {
    let mut stack = std::vec![sm_root];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(addr) = stack.pop() {
      if !seen.insert(addr) {
        continue;
      }
      let block = donor_blocks
        .read_block(addr)
        .expect("SM block present in donor store");
      for child in CountSm::block_references(&block) {
        stack.push(child);
      }
      blocks.write_block(addr, block);
    }
  }
  assert!(
    blocks.has_block(sm_root),
    "the laggard holds the SM DAG locally"
  );
  assert!(
    !blocks.has_block(sessions_root),
    "the laggard does NOT hold the session-table DAG (it must fetch it)"
  );

  let mut e = sync_backup();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut now = Instant::ZERO;

  // Trigger the sync (a Commit advertising checkpoint 4 > head 0), capture the nonce.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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

  // Deliver the donor's `SyncCheckpoint`. The install pumps the combined frontier: the SM DAG drains
  // locally, so the first emitted `RequestBlock` is for the MISSING session block (addressed to the
  // donor, slot 0).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  let first_session_request = {
    let mut req = None;
    while let Some(out) = e.poll_message() {
      if let Message::RequestBlock(addr) = out.msg_ref() {
        assert_eq!(
          out.to(),
          Recipient::To(Peer::Replica(ReplicaId::new(0))),
          "the session `RequestBlock` is pinned to the donor"
        );
        req = Some(*addr);
      }
    }
    req.expect("a session `RequestBlock` was emitted once the SM DAG drained")
  };
  assert!(
    !blocks.has_block(sessions_root) && first_session_request == sessions_root,
    "the first outstanding block is the missing session-table root"
  );
  assert!(
    e.block_fetch_donor() == Some(0),
    "the block-fetch is still in progress, pinned to the donor"
  );

  // DROP that first `BlockResponse` (never deliver it). Advance past the solicit deadline and fire the
  // ARQ via `handle_timeout`: it must RE-REQUEST the session block — WITHOUT any fresh `SyncCheckpoint`
  // (which the laggard cannot synthesize on its own).
  now = now + core::time::Duration::from_millis(101);
  e.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
  let mut retransmitted_session_block = false;
  let mut saw_sync_checkpoint = false;
  while let Some(out) = e.poll_message() {
    match out.msg_ref() {
      Message::RequestBlock(addr) => {
        if *addr == sessions_root {
          assert_eq!(
            out.to(),
            Recipient::To(Peer::Replica(ReplicaId::new(0))),
            "the retransmitted session `RequestBlock` is still pinned to the donor"
          );
          retransmitted_session_block = true;
        }
      }
      Message::SyncCheckpoint(_) => saw_sync_checkpoint = true,
      _ => {}
    }
  }
  assert!(
    retransmitted_session_block,
    "the ARQ retransmitted the MISSING session block after the SM DAG drained (combined-frontier pull)"
  );
  assert!(
    !saw_sync_checkpoint,
    "the retransmit rode the existing block-fetch — no fresh `SyncCheckpoint` was needed"
  );

  // The donor finally answers: deliver the session blocks (the root index + its leaf) and drive the
  // re-persist. The install then completes — proving the ARQ recovered the dropped fetch.
  loop {
    let want = match e.block_fetch_donor() {
      Some(_) => {
        // Find the laggard's current outstanding session request and answer it from the donor store.
        let mut req = None;
        e.handle_timeout(
          now + core::time::Duration::from_millis(101),
          &mut wal,
          &mut sb,
          &mut blocks,
        );
        now = now + core::time::Duration::from_millis(101);
        while let Some(out) = e.poll_message() {
          if let Message::RequestBlock(addr) = out.msg_ref() {
            req = Some(*addr);
          }
        }
        req
      }
      None => None,
    };
    let Some(addr) = want else { break };
    let block = donor_blocks
      .read_block(addr)
      .expect("the donor serves every requested session block");
    blocks.write_block(addr, block.clone());
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      primary_peer(),
      Message::BlockResponse(crate::BlockResponse::new(addr, Some(block))),
    );
    for _ in 0..4 {
      e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    }
    if e.state_syncs_applied() == 1 {
      break;
    }
  }
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the install completed once the dropped session fetch was recovered by the ARQ"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the laggard installed the synced checkpoint"
  );
}

#[test]
fn state_sync_installs_atomically_only_after_the_root_is_durable() {
  // DURABLE-BEFORE-INSTALL: a verified SyncCheckpoint STAGES the durable re-persist
  // (the two superblock writes) but must NOT install the synced state — restore the SM, advance
  // commit_min/op/commit_max/checkpoint_op, or prune the WAL — until the SYNC ROOT (step 2) is
  // durable. The install is ATOMIC at the root completion: everything advances together, only then.
  // FAIL-BEFORE: the old `apply_sync` mutated EAGERLY (it restored + advanced + pruned at STAGE time,
  // before the snapshot write even completed), so the SM/commit/op/checkpoint advanced and the WAL was
  // pruned the moment the SyncCheckpoint arrived — with `checkpoint_op` still old until the root.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  // The laggard: replica 1 of 3 over CountSm with a HUGE checkpoint interval (so committing its own
  // little band does NOT auto-checkpoint and race the sync's persist — it stays at checkpoint 0).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  // Give the laggard a small live WAL band (ops 1,2) below the synced point so the prune is OBSERVABLE.
  let mut wal = TestWal::default();
  let mut sb = StepSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  for op in 1..=2u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      primary_peer(),
      prepare(op, 0),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  while e.poll_message().is_some() {}
  assert!(
    wal.entries.contains_key(&1) && wal.entries.contains_key(&2),
    "the laggard holds a live WAL band {{1,2}} before syncing"
  );
  // Trigger a sync to checkpoint 4 (> head 2), then deliver the SyncCheckpoint → STAGE.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  // Baseline the OLD (pre-STAGE, post-trigger) frontier — the install must not move it before the root.
  let (base_commit, base_op, base_ckpt) = (e.commit(), e.op(), e.checkpoint_op());
  let base_applied = e.state_machine_ref().applied().len();
  assert_eq!(
    base_ckpt,
    OpNumber::with(0),
    "the laggard is at its old checkpoint 0 before STAGE"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  // STAGE only: the snapshot write is in flight (not yet flushed). NOTHING may have installed.
  assert_eq!(
    e.checkpoint_op(),
    base_ckpt,
    "checkpoint_op UNCHANGED at STAGE"
  );
  assert_eq!(
    e.commit(),
    base_commit,
    "commit_min UNCHANGED at STAGE (NOT advanced to the synced 4)"
  );
  assert_eq!(
    e.op(),
    base_op,
    "op UNCHANGED at STAGE (still the old head)"
  );
  assert!(
    e.commit().get() < 4,
    "commit_min did NOT jump to the synced point at STAGE"
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    base_applied,
    "SM NOT restored at STAGE (still its old applied state, no snapshot installed yet)"
  );
  assert!(
    wal.entries.contains_key(&1) && wal.entries.contains_key(&2),
    "the WAL is NOT pruned at STAGE (the destructive prune is deferred to the install)"
  );
  // Complete step 1 (snapshot durable → root submitted), still NO install (the root is now in flight).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    base_ckpt,
    "checkpoint_op still UNCHANGED after step 1"
  );
  assert_eq!(
    e.commit(),
    base_commit,
    "commit_min still UNCHANGED after step 1"
  );
  assert_eq!(e.op(), base_op, "op still UNCHANGED after step 1");
  assert!(
    wal.entries.contains_key(&1) && wal.entries.contains_key(&2),
    "the WAL is still NOT pruned after step 1 (the root is not yet durable)"
  );
  // Complete step 2 (the SYNC ROOT durable) → INSTALL fires ATOMICALLY: everything advances together.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "checkpoint_op advances on the durable root"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "commit_min advances on the durable root"
  );
  assert_eq!(e.commit_max(), OpNumber::with(4));
  assert_eq!(e.op(), OpNumber::with(4), "op advances on the durable root");
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(
    e.state_machine_ref().applied().len(),
    4,
    "SM restored from the snapshot ONLY after the root is durable"
  );
  assert!(
    !wal.entries.contains_key(&1) && !wal.entries.contains_key(&2),
    "the WAL is pruned at the synced point only AFTER the install (durable-before-install)"
  );
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "synced checkpoint is durable"
  );
  assert_eq!(e.state_syncs_applied(), 1, "the sync fully applied");
}

#[test]
fn state_sync_view_change_defers_while_a_re_persist_root_is_staged() {
  // REGRESSION (the durable-checkpoint rewind). A laggard STAGES a SyncCheckpoint and its re-persist ROOT
  // write reaches the superblock queue (AwaitRoot) — that root will advance the durable checkpoint to the
  // synced point. A VIEW CHANGE (SVC quorum) fires in this window. It must NOT proceed: the staged root
  // cannot be cancelled, so a view-change root submitted now would land BEHIND it and REWIND the durable
  // checkpoint back to the stale pre-sync pointer (and the destructive install cannot run interleaved with
  // a transition's adopted log). So the transition is DEFERRED until the sync installs to the synced point
  // (durable advances 0→4 MONOTONICALLY); the sticky SVC then re-drives the view change from the
  // cleanly-synced state. FAIL-BEFORE: the view change proceeds, the sync root lands at 4, and a trailing
  // view root rewinds the durable checkpoint back to 0.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  // The laggard: replica 1 of 3 over CountSm with a HUGE checkpoint interval (so its own band does not
  // auto-checkpoint and race the sync persist — it stays at its old durable checkpoint 0).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let mut wal = TestWal::default();
  let mut sb = StepSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  // The laggard (replica 1 of 3) holds a live WAL band {1,2} below the synced point.
  for op in 1..=2u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      primary_peer(),
      prepare(op, 0),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  while e.poll_message().is_some() {}
  // Trigger + STAGE a sync to checkpoint 4 (> head 2). The trigger Commit carries commit=0, so the
  // laggard does NOT learn a commit above its head (a known-commit above op would, correctly, fail-stop
  // canonical-log selection — that hazard is orthogonal to this test).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(0),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
    )),
  );
  // Advance step 1 (snapshot durable → root submitted) but withhold the ROOT (it stays in flight).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    e.sync_target_for_test().is_some(),
    "the sync is still armed (the root has NOT completed → the install is pending)"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "checkpoint_op is still old at this point"
  );
  // A VIEW CHANGE fires in this window: the laggard's own primary-idle timeout plus an SVC from replica 2
  // form an SVC quorum (2 of 3) for view 1 — which would normally drive it into ViewChange(1). But the
  // sync re-persist ROOT is staged (AwaitRoot), so the transition is DEFERRED.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks); // primary_idle → SVC(view 1), own bit
  e.handle_message(
    later,
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
  assert_eq!(
    e.status(),
    Status::Normal,
    "the SVC quorum is DEFERRED while the sync re-persist root is staged — no view change proceeds"
  );
  assert!(
    e.sync_target_for_test().is_some(),
    "the staged sync is NOT cancelled by the deferred view change"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "checkpoint_op is still old — the sync has not installed yet"
  );
  // Land the staged sync root → the sync INSTALLS to the synced point. The durable checkpoint advances
  // 0 → 4 MONOTONICALLY; no trailing view root rewinds it (the bug this guards).
  sb.flush();
  e.handle_storage(later, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the sync installed: in-memory checkpoint_op advanced to the synced point"
  );
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "the durable checkpoint advanced 0→4 monotonically — never rewound by a stale view root"
  );
  assert_eq!(
    e.sync_target_for_test(),
    None,
    "the sync completed (its install ran on the root's completion)"
  );
  // The deferred trigger is STICKY: the next primary-idle timeout re-emits the SVC and re-evaluates the
  // persisted quorum, now re-driving the view change from the cleanly-synced state (the laggard is at
  // checkpoint 4, so becoming primary strands no lower laggard).
  let later2 = later + core::time::Duration::from_millis(300);
  e.handle_timeout(later2, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "the deferred view change re-drives once the sync installed"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the re-driven view change carries the synced checkpoint — monotone, no rewind"
  );
}

#[test]
fn an_ordinary_checkpoint_completing_during_a_solicited_sync_advances_without_clearing_it() {
  // REGRESSION. The `on_sb_done` root-completion arm must route by whether THIS
  // root is the sync's re-persist (`pc.sync`), NOT by `self.sync.is_some()`. A sync can be merely
  // SOLICITED (armed, awaiting a SyncCheckpoint — no staged install) while an ORDINARY checkpoint
  // completes. If that ordinary completion were misrouted to the sync-install branch it would (a) NOT
  // advance `checkpoint_op` and (b) CLEAR the solicited sync — so the laggard's checkpoint never moves
  // and it re-solicits forever (the long-down-replica state-sync livelock). With the `pc.sync`
  // discriminator the ordinary checkpoint advances `checkpoint_op` and LEAVES the solicited sync armed.
  let mut e = sync_backup(); // replica 1 of 3, CountSm, checkpoint_ops = 2
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Hold a live band {1,2} (durable).
  for op in 1..=2u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      primary_peer(),
      prepare(op, 0),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  while e.poll_message().is_some() {}
  // A Commit carries commit=2 (applies the band → crosses the checkpoint boundary at op 2 → an ORDINARY
  // checkpoint fires) AND checkpoint_op=99 (far above the head → SOLICITS a state-sync). Both happen in
  // this one handler: `maybe_request_sync` arms the sync, then `advance_commit` applies + `maybe_
  // checkpoint` stages the ordinary checkpoint.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(99),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(99),
    "a state-sync is SOLICITED (armed) — but no SyncCheckpoint has been received, so nothing is staged"
  );
  // The in-flight checkpoint is TYPED `Ordinary`, even though a sync is concurrently solicited — the
  // discriminator the routing uses lives in the completion token (`pc.kind`), NOT in `self.sync`. This
  // is the structural property that types the footgun away: there is no ambient bool to confuse.
  assert_eq!(
    e.pending_checkpoint_is_sync_for_test(),
    Some(false),
    "the staged checkpoint is an ORDINARY one (CheckpointKind::Ordinary), not a sync re-persist, \
     despite the concurrently-solicited sync"
  );
  let synced_before = e.state_syncs_applied();
  // Complete the ordinary checkpoint's two superblock writes.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "the ORDINARY checkpoint advanced checkpoint_op (it was NOT misrouted to the sync-install branch)"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(99),
    "the SOLICITED sync is still armed — an ordinary checkpoint completion must NOT clear it"
  );
  assert_eq!(
    e.state_syncs_applied(),
    synced_before,
    "no state-sync was counted as applied (the ordinary checkpoint is not a sync re-persist)"
  );
}

#[test]
fn a_primary_does_not_apply_a_state_sync_it_steps_down_instead() {
  // REGRESSION (an adversarial schedule). A `Normal` PRIMARY that receives a valid `SyncCheckpoint` for an
  // outstanding sync must NOT apply it in place (that would reset commit_min to the checkpoint and
  // clear the commit pipeline while it stays primary → a wedge: `try_commit` can never advance past
  // the checkpoint, and a recovered/op-reset primary can REUSE committed op numbers — divergence).
  // Instead it STEPS DOWN: flags the deferred forfeit and drops the sync, unchanged. A
  // caught-up replica then leads.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 1_000).unwrap(); // huge interval: no checkpoint
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Drive the primary to op 4, commit 4 (no checkpoint — interval is huge).
  for rn in 1..=4u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Client(ClientId::new(7)),
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // own append durable → own vote
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
  }
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.checkpoint_op(), OpNumber::with(0));
  while e.poll_message().is_some() {}
  // A valid checkpoint envelope at op 6 (from a donor), and an outstanding FORCED sync to it.
  let (_d, _dw, dsb) = donor_primary_at_checkpoint(6);
  let (env, id) = donor_envelope(&dsb);
  e.arm_forced_sync_for_test(6);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(6),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  // It must NOT have applied the sync: op/commit/checkpoint unchanged, SM not restored.
  assert_eq!(e.op(), OpNumber::with(4), "op unchanged (no apply)");
  assert_eq!(e.commit(), OpNumber::with(4), "commit unchanged (no apply)");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "checkpoint unchanged (no apply)"
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    4,
    "SM still reflects its own 4 applied ops — the peer snapshot was NOT restored"
  );
  // It stepped down instead: the deferred forfeit is flagged and the sync was dropped.
  assert!(
    e.pending_forfeit_for_test(),
    "the primary flagged the deferred forfeit (it abdicates rather than apply a sync)"
  );
  assert_eq!(
    e.sync_target_for_test(),
    None,
    "the sync was dropped (the primary is stepping down, not syncing)"
  );
}

#[test]
fn a_recovery_peer_fetch_stays_recovering_until_the_sync_root_is_durable() {
  // REGRESSION (the dissolved recovery eager-install window). A replica whose OWN durable checkpoint
  // snapshot is permanently unreadable escalates to a recovery peer-fetch. When the answering
  // SyncCheckpoint arrives it STAGES the durable re-persist but STAYS `Recovering` — both the destructive
  // install (restore SM, advance the frontier, prune the WAL) AND the flip to Normal DEFER to `on_sb_done`
  // (the durable root). So there is NO window where a Normal node holds an advanced commit frontier + a
  // pruned WAL over a durable root still naming the OLD checkpoint: a `Recovering` replica is excluded
  // from all Normal-path participation by the central ingress (it accepts only SyncCheckpoint/Meta/Chunk
  // while awaiting a peer checkpoint, and once the sync is staged it accepts nothing). The CRUX is that
  // delivering the SyncCheckpoint does NOT eagerly flip the node to Normal or advance `checkpoint_op`.
  let now = Instant::ZERO;
  // The recovering replica is MemberId 0 — the PRIMARY of view 0 in genesis(3). Durable root at view 0,
  // checkpoint op 2, with an EMPTY checkpoint read script → its own snapshot is permanently unreadable, so
  // recovery escalates to a peer fetch.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    0xDEAD_BEEF,
    std::vec::Vec::new(),
  )
  .unwrap()
  .with_wal_geometry(2, u64::MAX);
  let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 6);
  let mut e = Endpoint::recover(
    cfg,
    genesis(3),
    5,
    CountSm::default(),
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery_scripted_sb(&mut e, &mut wal, &mut sb, &mut blocks, now);
  assert_eq!(e.status(), Status::Recovering);
  assert!(e.awaiting_peer_checkpoint_for_test());
  while e.poll_message().is_some() {} // drain the solicited RequestSync
  let nonce = e.sync_nonce_for_test();
  // A donor at a HIGHER checkpoint (op 6 > our 2): delivering its SyncCheckpoint stages the re-persist to
  // the synced point and prunes the band (2..6] — but only once the SyncRepersist root lands in
  // `on_sb_done`.
  let (_d, _dw, dsb) = donor_primary_at_checkpoint(6);
  let (env, id) = donor_envelope(&dsb);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(6),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(1),
      nonce,
      env,
      Bytes::new(),
    )),
  );
  // THE CRUX: AFTER delivery but BEFORE driving storage, the node has NOT eagerly flipped/installed. It
  // STAYS Recovering and its durable checkpoint is STILL the OLD one (the SyncRepersist root has not yet
  // landed). The old eager path flipped to Normal here and advanced the in-memory frontier over a stale
  // durable root — exactly the window this refactor dissolves.
  assert_eq!(
    e.status(),
    Status::Recovering,
    "the peer-fetch STAGES the re-persist and STAYS Recovering — no eager flip to Normal"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "durable checkpoint still the OLD one — the SyncRepersist root has not landed (no eager install)"
  );
  // Now drive storage to completion: flush the scripted superblock each round so the two staged writes
  // (snapshot, then the root naming it) surface and `on_sb_done` lands the root. The SyncRepersist arm then
  // installs ATOMICALLY (restore + advance `checkpoint_op` to 6) and `complete_recovery` finishes recovery.
  for _ in 0..16 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    if !e.status().is_recovering() {
      break;
    }
  }
  // The install + durable-root advance landed ATOMICALLY: `checkpoint_op` is now the synced point 6 (never
  // advanced before the root was durable), and recovery is complete (the node has LEFT Recovering).
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(6),
    "the SyncRepersist root landed → install + `checkpoint_op` advance are atomic at the synced point 6"
  );
  assert!(
    !e.status().is_recovering(),
    "recovery completed once the synced root was durable"
  );
  // MemberId 0 is the PRIMARY of view 0, so `complete_recovery` ABDICATES (a restarted primary forces a
  // clean view change rather than resuming as the established primary) → ViewChange, not Normal. The
  // BACKUP case (which resumes Normal at the synced point) is covered end-to-end by
  // `recovery_peer_fetch_converges_against_an_equal_checkpoint_peer`.
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "a recovered PRIMARY abdicates on completion (a backup would resume Normal instead)"
  );
}

#[test]
fn sync_checkpoint_with_mismatched_id_is_rejected_not_restored() {
  // A corrupt/forged snapshot whose bytes don't hash to the advertised id MUST NOT be restored.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  let bad_env = Bytes::from_static(b"not the real envelope");
  let advertised = 0xDEAD_BEEF_u128; // != checkpoint_id(bad_env)
  assert_ne!(advertised, crate::checkpoint_id(&bad_env));
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      advertised,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      bad_env,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "rejected: checkpoint not advanced"
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    0,
    "rejected: SM untouched"
  );
  // sync stays armed → it re-solicits on the timer.
  assert!(
    e.poll_timeout().is_some(),
    "sync remains armed to re-solicit"
  );
}

#[test]
fn sync_checkpoint_with_op_not_bound_to_the_snapshot_is_rejected_not_restored() {
  // REGRESSION (overstated checkpoint op over stale-but-consistent bytes): a faulty peer ships a
  // snapshot whose REAL frontier is op A=2 but advertises `checkpoint_op = B=4`. The snapshot's bytes
  // hash to the advertised `checkpoint_id` (so the existing integrity gate PASSES — the id is
  // consistent with the OLD bytes), yet B > A. Before binding the op into the hash, the receiver
  // restored the op-2 SM but advanced `commit_min`/`commit_max`/`op` to 4 — SILENTLY DROPPING the
  // committed ops in (A, B] = (2, 4]. With the fix, the op bound INSIDE the envelope (2) is compared
  // to the advertised op (4) and the mismatch REJECTS the snapshot: no restore, no commit advance.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Trigger a sync targeting op 4 (the overstated op).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  // Build a STALE-BUT-CONSISTENT envelope: a genuine snapshot bound to op A=2, with the matching id.
  let mut stale_sm = CountSm::default();
  stale_sm.apply(OpNumber::with(1), &[1]);
  stale_sm.apply(OpNumber::with(2), &[2]);
  let stale_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    crate::block_address(&stale_sm.snapshot()),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let real_id = crate::checkpoint_id(&stale_env); // the id IS consistent with these (op-2) bytes
  // Seed the named SM leaf so the reply reaches `apply_sync`'s op-bind check (the load-bearing rejection)
  // rather than deferring into a block-fetch.
  blocks.write_verified(stale_sm.snapshot());
  // Deliver it advertising the OVERSTATED op B=4 but the bytes' REAL id → the hash gate passes, the
  // op-binding gate must reject (bound op 2 != advertised op 4).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4), // OVERSTATED — does not match the op bound (2) inside the snapshot
      real_id,
      crate::Epoch::new(0),
      0, // matches checkpoint_id(stale_env), so the integrity gate PASSES
      ReplicaId::new(0),
      nonce,
      stale_env,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // (no re-persist should have been staged)
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "rejected: checkpoint op not advanced to the overstated value",
  );
  // The APPLIED frontier (`commit_min`) is the safety-critical one: it must NOT advance past the
  // snapshot's real frontier — that is precisely the committed-op drop the binding prevents. (The
  // cluster-wide `commit_max` legitimately becomes 4 from the learned Commit; that is just a watermark
  // we have NOT caught up to, not an applied/durable advance — the replica still lacks ops (2, 4].)
  assert_eq!(
    e.commit(),
    OpNumber::with(0),
    "rejected: applied frontier (commit_min) NOT advanced past the snapshot's real content",
  );
  assert_eq!(
    e.op(),
    OpNumber::with(0),
    "rejected: head not advanced to the overstated op"
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    0,
    "rejected: SM untouched (the op-2 snapshot was NOT restored under op 4)",
  );
  assert_eq!(e.state_syncs_applied(), 0, "no state-sync was applied",);
  // sync stays armed → it re-solicits on the timer (another peer answers).
  assert!(
    e.poll_timeout().is_some(),
    "sync remains armed to re-solicit"
  );
}

#[test]
fn stale_nonce_sync_checkpoint_is_ignored() {
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  // Deliver a SyncCheckpoint with the WRONG nonce — must be ignored.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce.wrapping_add(1),
      env,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "wrong nonce → ignored"
  );
  assert_eq!(e.state_machine_ref().applied().len(), 0);
}

#[test]
fn sync_checkpoint_below_target_is_ignored() {
  // A SyncCheckpoint whose checkpoint_op does not even reach the target we learned the cluster has
  // committed (an out-of-date peer answering with an OLDER checkpoint) → ignored: it would not
  // advance us past the committed frontier. (Target 6; a reply at op 4 is dropped.)
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let (_d, _dw, dsb) = donor_primary_at_checkpoint(4);
  let (env4, id4) = donor_envelope(&dsb);
  let now = Instant::ZERO;
  // Trigger a sync targeting 6 (the cluster's known checkpoint).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(6),
      OpNumber::with(6),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // A stale peer answers with checkpoint 4 (< target 6): must be ignored.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id4,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env4,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "a SyncCheckpoint below the learned target is ignored (would not reach the committed frontier)"
  );
  assert!(
    e.poll_timeout().is_some(),
    "sync stays armed to await a checkpoint >= target"
  );
}

#[test]
fn sync_checkpoint_without_an_outstanding_sync_is_ignored() {
  // A SyncCheckpoint arriving with NO sync outstanding (never triggered, or already applied) is
  // dropped — never an unsolicited restore. This also covers the "duplicate after apply" case (the
  // first apply clears `sync`, so a re-delivery finds no outstanding sync).
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let (_d, _dw, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let now = Instant::ZERO;
  // No trigger fired → sync is None. Deliver a (valid) SyncCheckpoint anyway.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      0xABCD,
      env,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "an unsolicited SyncCheckpoint (no outstanding sync) is ignored"
  );
  assert_eq!(e.state_machine_ref().applied().len(), 0);
}

#[test]
fn lower_sync_checkpoint_is_ignored_after_a_higher_one() {
  // Monotonicity: after syncing to checkpoint 4, a later SyncCheckpoint advertising a LOWER
  // checkpoint must never regress us. (We forge a stale reply at the same nonce/below our point.)
  let (mut e, mut wal, mut sb, env4, id4) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let (_d2, _dw2, dsb2) = donor_primary_at_checkpoint(2);
  let (env2, id2) = donor_envelope(&dsb2);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id4,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env4,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  // A stale lower SyncCheckpoint (op 2) arriving now: sync is already cleared, and even if it
  // weren't, `> self.checkpoint_op` fails. It must be ignored — no regression.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      id2,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env2,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "a lower SyncCheckpoint never regresses us"
  );
  assert_eq!(e.commit(), OpNumber::with(4));
}

#[test]
fn sync_checkpoint_clears_a_pending_repair_hole_below_the_synced_point() {
  // A replica with a `repair` hole at op 2 that then syncs a checkpoint at op 5 drops the hole
  // (subsumed by the snapshot) and stops the repair timer.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(6);
  // Use a checkpoint at 6 so it is strictly above the hole at 2 and the head.
  let (env, id) = donor_envelope(&dsb);
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 6);
  let now = Instant::ZERO;
  // Manufacture a pending-repair hole at op 2 (as the recover loop would).
  e.request_repair(now, 2);
  assert!(e.repair.contains(&2), "hole registered");
  assert!(e.timers.repair_retry.is_some(), "repair timer armed");
  // Trigger + apply a sync to checkpoint 6 (above the hole).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(6),
      OpNumber::with(6),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(6),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.checkpoint_op(), OpNumber::with(6));
  assert!(
    e.repair.is_empty(),
    "the hole below the synced point is subsumed + cleared"
  );
  assert!(e.timers.repair_retry.is_none(), "repair timer stopped");
}

// ── Force-state-sync escalation ────────────────────────────────────────────────────────────────

#[test]
fn a_pruned_committed_hole_forces_a_state_sync() {
  // A Normal BACKUP (replica 1 of 3) holds a repair hole at op N=2 with a head ABOVE it (op=4),
  // where a QUORUM has checkpointed past N (so RequestPrepare is futile — the op is pruned on the
  // quorum). It must (a) clear the doomed hole, (b) emit a RequestSync (not just RequestPrepare),
  // (c) record a FORCED sync targeting the quorum checkpoint.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(1), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, NoopSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  // Normal-backup state: head op 4, commit held at 1, own checkpoint 0, a committed hole at op 2.
  ep.force_state_for_test(0, 4, 1, 0, &[2]);
  assert!(!ep.is_primary());
  assert!(ep.has_repair_hole_for_test(2), "the hole is registered");
  // Teach it a QUORUM (2 of 3) has checkpointed past N=2: peers 0 and 2 report checkpoint_op = 4.
  // (self reports 0; the 2nd-highest of {0,4,4} = 4 >= N=2 → the hole is snapshot-only.)
  ep.inject_peer_checkpoint_for_test(0, 4);
  ep.inject_peer_checkpoint_for_test(2, 4);
  assert_eq!(
    ep.quorum_checkpoint_op(),
    OpNumber::with(4),
    "the quorum-checkpoint floor is 4 (>= the hole at 2)"
  );
  // Drive a real checkpoint report (a Commit from the primary, replica 0) so the production
  // `on_commit` → `maybe_force_sync` path runs the escalation.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  // (a) the doomed hole is cleared, and its retry timer stopped.
  assert!(
    !ep.has_repair_hole_for_test(2),
    "the snapshot-only hole at N=2 is cleared"
  );
  assert!(
    ep.timers.repair_retry.is_none(),
    "the futile repair retransmit is stopped"
  );
  // (c) a FORCED sync to the quorum checkpoint (4) is recorded.
  assert_eq!(
    ep.sync_target_for_test(),
    Some(4),
    "the forced sync targets the quorum checkpoint"
  );
  assert!(
    ep.sync_is_forced_for_test(),
    "the sync is marked forced (the assert-relaxation path)"
  );
  // (b) a RequestSync was emitted (not merely a RequestPrepare).
  let mut saw_request_sync = false;
  let mut saw_request_prepare = false;
  while let Some(out) = ep.poll_message() {
    match out.msg_ref() {
      Message::RequestSync(_) => saw_request_sync = true,
      Message::RequestPrepare(_) => saw_request_prepare = true,
      _ => {}
    }
  }
  assert!(
    saw_request_sync,
    "a RequestSync is solicited instead of looping RequestPrepare"
  );
  let _ = saw_request_prepare; // an earlier futile RequestPrepare may have been emitted before the escalation
  // SAFETY: the commit frontier did NOT advance past the hole — it stays at N-1 until the snapshot
  // (>= N) is applied. No committed op is abandoned; it is recovered from the synced snapshot.
  assert_eq!(
    ep.commit(),
    OpNumber::with(1),
    "no commit advances past the hole until the forced snapshot lands"
  );
}

#[test]
fn force_sync_does_not_fire_when_the_op_is_still_peer_repairable() {
  // The escalation must NOT pre-empt the cheap single-op repair when the hole is still IN-REACH —
  // i.e. NO peer has checkpointed past it, so every reporter may still hold it as a servable prepare.
  // Here the only peer report (replica 0) is a checkpoint BELOW the hole (N=4, primary checkpoint=3),
  // so the max-peer floor stays below N → no force-sync.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(1), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, NoopSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  // Head op 6, commit held at 3, own checkpoint 0, a committed hole at op 4.
  ep.force_state_for_test(0, 6, 3, 0, &[4]);
  // The primary (replica 0) reports a checkpoint of 3 — BELOW the hole at 4. The max-peer floor is
  // max{self=0, r0=3} = 3 < N=4 → the hole is still in-reach (the primary has NOT pruned op 4, so a
  // RequestPrepare can still be answered) → no force-sync.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::with(3),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    ep.max_peer_checkpoint_op(),
    OpNumber::with(3),
    "the max-peer floor (3) stays below the hole (4)"
  );
  // The hole is RETAINED (still peer-repairable) and NO sync is armed.
  assert!(
    ep.has_repair_hole_for_test(4),
    "an in-reach hole keeps using ordinary RequestPrepare repair"
  );
  assert_eq!(
    ep.sync_target_for_test(),
    None,
    "no forced sync is armed while no peer has pruned the op (it may still be served)"
  );
  assert!(
    ep.timers.repair_retry.is_some(),
    "the repair retransmit timer stays armed"
  );
}

#[test]
fn force_sync_fires_on_a_backup_that_only_hears_the_primary() {
  // REGRESSION (the backup-visibility bug): a Normal BACKUP only ever records the PRIMARY's
  // checkpoint (PrepareOks flow to the primary, never between backups), so `quorum_checkpoint_op`
  // is structurally pinned at ~0 on a backup. The escalation MUST key on the max single-peer
  // checkpoint instead — otherwise a backup stuck on a pruned committed hole below the cluster
  // checkpoint (head above it) hangs at `commit_min == N-1` forever. Here a SINGLE peer report (the
  // primary's Commit, checkpoint=8) past the hole (N=2) is enough to force the sync.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(1), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, NoopSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  // Head op 10 (ABOVE the cluster checkpoint, so the ORDINARY `> self.op` sync stays FALSE — this is
  // the precise force-sync regime), commit held at 1, own checkpoint 0, a committed hole at op 2.
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
  assert!(!ep.is_primary());
  // Only the primary (replica 0) reports — exactly a backup's real visibility. quorum_checkpoint_op
  // is still 0 here (only self + one peer report), proving the OLD quorum-gated trigger could never
  // have fired; the max-peer floor (8) is what rescues it. The primary's checkpoint (8) is BELOW the
  // head (10), so `maybe_request_sync` (`8 > 10`?) does NOT fire — ONLY the forced path can.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::with(8),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    ep.quorum_checkpoint_op(),
    OpNumber::with(0),
    "the quorum-th floor is 0 on a backup (only the primary reports) — the OLD trigger was dead here"
  );
  assert!(
    !ep.has_repair_hole_for_test(2),
    "the snapshot-only hole is cleared via the max-peer floor (the backup no longer hangs)"
  );
  assert_eq!(
    ep.sync_target_for_test(),
    Some(8),
    "the forced sync targets the primary's reported checkpoint"
  );
  assert!(ep.sync_is_forced_for_test(), "the sync is marked forced");
}

#[test]
fn force_sync_stays_dormant_until_a_quorum_floor_is_known() {
  // Empty repair set, or no quorum-checkpoint floor → the escalation is a no-op (it must never fire
  // spuriously). With a hole but a zero floor (partitioned: no peers heard), it stays dormant.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(1), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, NoopSm, u64::MAX);
  // No holes at all → maybe_force_sync is a no-op.
  ep.maybe_force_sync(Instant::ZERO);
  assert_eq!(ep.sync_target_for_test(), None);
  // A hole but no quorum floor (no peer reports) → still dormant.
  ep.force_state_for_test(0, 4, 1, 0, &[2]);
  ep.maybe_force_sync(Instant::ZERO);
  assert!(
    ep.has_repair_hole_for_test(2),
    "the hole survives — no floor means no escalation"
  );
  assert_eq!(
    ep.sync_target_for_test(),
    None,
    "no sync armed without a quorum floor"
  );
}

#[test]
fn forced_sync_preserves_a_held_tail_above_the_checkpoint_without_panic() {
  // SAFETY (an adversarial schedule): a forced sync where checkpoint_op (3) <= self.op (5). The held tail
  // (3..5] is ops this replica already durably appended + ACKED, so the cluster may have COMMITTED
  // them off its vote. The OLD code discarded the tail (rewound the head to 3 + truncated the WAL),
  // destroying its only durable copy while keeping `log_view` — a later view change then took its
  // (log_view, op) as the canonical head and dropped those committed ops, the loss `adopt_canonical_
  // head`'s `op >= commit_min` assert trips on. The forced path must instead apply WITHOUT panic,
  // PRESERVE the above-floor tail (keep op 5 + its log entries), restore the SM at the snapshot, and
  // subsume the doomed hole at 2.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(3);
  let (env, id) = donor_envelope(&dsb);
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 4).unwrap();
  let mut ep =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 1, CountSm::default(), u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 3);
  // A backup holding a tail at op 5, commit at 1, a committed hole at 2, own checkpoint 0. Seed the
  // in-memory tail entries (4, 5) it holds above the synced checkpoint (force_state_for_test leaves
  // the cache empty); these must survive the forced sync.
  ep.force_state_for_test(0, 5, 1, 0, &[2]);
  ep.seed_log_entry_for_test(4);
  ep.seed_log_entry_for_test(5);
  ep.arm_forced_sync_for_test(3); // self.sync = Some { target: 3, forced: true }
  let nonce = ep.sync_nonce_for_test();
  // A valid SyncCheckpoint at op 3 (id matches its bytes) — must apply, not panic.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(3),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
    )),
  );
  ep.handle_storage(Instant::ZERO, &mut wal, &mut sb, &mut blocks); // drive the durable re-persist
  assert_eq!(
    ep.op(),
    OpNumber::with(5),
    "the held tail above the synced checkpoint is PRESERVED — the head is NOT rewound to 3"
  );
  assert!(
    ep.has_log_entry_for_test(4) && ep.has_log_entry_for_test(5),
    "the above-floor tail entries (4, 5) survive the forced sync"
  );
  assert_eq!(
    ep.commit(),
    OpNumber::with(3),
    "the applied frontier advanced to the synced point (past the old hole at 2)"
  );
  assert_eq!(
    ep.checkpoint_op(),
    OpNumber::with(3),
    "synced checkpoint adopted"
  );
  assert!(
    !ep.has_repair_hole_for_test(2),
    "the pruned committed hole at/below the floor is subsumed by the snapshot"
  );
  assert_eq!(
    ep.state_syncs_applied(),
    1,
    "the forced sync routed through apply_sync → the durable re-persist completed"
  );
}

#[test]
fn a_stale_forced_sync_checkpoint_is_dropped_after_repair_advances_past_its_target() {
  // REGRESSION (a stale forced SyncCheckpoint reaches apply_sync). A forced sync is armed
  // for a doomed hole at target T=2, but the ORDINARY repair path completes FIRST: a peer's `Prepare`
  // fills the hole via `fill_repair`, its WAL append lands, and `advance_commit` moves `commit_min` PAST
  // T (to 4) while the forced `sync` is armed. Then a DELAYED `SyncCheckpoint(checkpoint_op = T = 2)` for
  // the now-stale target arrives. The ordinary stale-response guard (`checkpoint_op <= self.op → drop`)
  // is SKIPPED for the forced path (the forced-tail relaxation), so the stale response would reach
  // `apply_sync` — where the forced-branch `assert!(checkpoint_op >= commit_min)` PANICKED (commit_min 4
  // > checkpoint_op 2). FAIL-BEFORE: that panic. PASS-AFTER: Part A CANCELS the satisfied forced sync the
  // moment `advance_commit` carries `commit_min` past T, so the stale response is dropped upstream (no
  // outstanding sync), the applied frontier is unchanged, and nothing is installed — no panic, no rewind.
  //
  // A real BACKUP (replica 1 of 3) over CountSm with a HUGE checkpoint interval, so applying its band
  // does NOT auto-checkpoint (which would otherwise set `pending_checkpoint` and short-circuit the path).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut ep =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, CountSm::default(), u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Head op 4, commit HELD at 1, own checkpoint 0, a committed hole at op 2. The above-hole committed
  // band (ops 3, 4) is held in the log cache so that — once the hole at 2 fills — `advance_commit` can
  // apply 2, 3, 4 in order and move `commit_min` to 4.
  ep.force_state_for_test(0, 4, 1, 0, &[2]);
  ep.seed_log_entry_for_test(3);
  ep.seed_log_entry_for_test(4);
  // Learn the cluster has committed through op 4 (so `commit_max == 4`), with the commit HELD at the
  // hole (op 2). The Commit carries checkpoint_op 0, so it triggers neither the ordinary sync nor the
  // forced escalation (no peer-checkpoint floor crosses the hole yet) — it only raises `commit_max`.
  ep.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    ep.commit(),
    OpNumber::with(1),
    "the commit is still held at the hole (op 2)"
  );
  assert_eq!(
    ep.commit_max(),
    OpNumber::with(4),
    "but commit_max learned the cluster reached op 4"
  );
  assert!(
    ep.has_repair_hole_for_test(2),
    "the hole at op 2 is still registered"
  );
  // Arm a FORCED sync to target T=2 (as `maybe_force_sync` would for a hole pruned on the quorum).
  ep.arm_forced_sync_for_test(2);
  assert_eq!(ep.sync_target_for_test(), Some(2));
  assert!(ep.sync_is_forced_for_test());
  // The ORDINARY repair path completes: a peer `Prepare` for op 2 (commit >= op, verifiable body) fills
  // the hole via `fill_repair` (staged as a durability-barrier RepairFill); its WAL append then lands.
  ep.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    repair_prepare(0, 2, 4),
  );
  assert!(
    ep.has_repair_hole_for_test(2),
    "the hole stays OPEN until the repair-fill append is durable"
  );
  ep.handle_storage(now, &mut wal, &mut sb, &mut blocks); // on_wal_done: insert op 2, clear the hole, advance_commit
  assert!(
    !ep.has_repair_hole_for_test(2),
    "the hole filled via ordinary repair"
  );
  assert_eq!(
    ep.commit(),
    OpNumber::with(4),
    "advance_commit moved the applied frontier PAST the forced-sync target (commit_min 4 > T 2)"
  );
  // Part A (the root cause): the forced sync the commit just satisfied is CANCELLED — its target (2) is
  // now `<= commit_min` (4), so the hole it was working around is recovered the cheap way. (Without
  // this, the stale SyncCheckpoint below would reach `apply_sync` and panic at the forced assert.)
  assert_eq!(
    ep.sync_target_for_test(),
    None,
    "the satisfied forced sync is cancelled (Part A) — no longer awaiting a response we don't need",
  );
  assert!(
    ep.poll_timeout().is_none() || ep.timers.sync_solicit.is_none(),
    "the sync_solicit timer is cleared with the cancelled forced sync"
  );
  while ep.poll_message().is_some() {}
  // A DELAYED SyncCheckpoint for the original (now-stale) target T=2 arrives. With the forced sync
  // already cancelled it is dropped upstream (the `sync.is_none` guard in `on_sync_checkpoint`) and never
  // reaches `apply_sync`. Build a valid envelope at op 2 (id matches its bytes); the OLD code (no Part A)
  // would have carried it into `apply_sync` and panicked at `assert!(checkpoint_op >= commit_min)`.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(2);
  let (env, _id) = donor_envelope(&dsb);
  ep.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      crate::checkpoint_id(&env),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      // a nonce that would have matched the cancelled forced sync (it is gone, so this is moot)
      7,
      env,
      Bytes::new(),
    )),
  );
  ep.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  // The stale response was DROPPED: nothing rewound, no snapshot installed, no re-persist staged.
  assert_eq!(
    ep.commit(),
    OpNumber::with(4),
    "the applied frontier is UNCHANGED — the stale forced SyncCheckpoint did not rewind it"
  );
  assert_eq!(
    ep.checkpoint_op(),
    OpNumber::with(0),
    "no stale checkpoint was installed (checkpoint_op unchanged)"
  );
  assert_eq!(ep.op(), OpNumber::with(4), "the head is unchanged");
  assert_eq!(
    ep.state_syncs_applied(),
    0,
    "no state-sync was applied from the stale response"
  );
}

#[test]
fn apply_sync_drops_a_stale_forced_sync_checkpoint_below_the_applied_frontier() {
  // SAFETY NET (Part B — reaching `apply_sync` directly). Models the reordering where a
  // forced `SyncCheckpoint` for a target the applied frontier has ALREADY passed reaches `apply_sync`
  // (i.e. Part A's apply-loop cancel did not run between the arm and this delivery). The forced sync's
  // target (2) is `<= self.op` (so the upstream `<= self.op → drop` guard is relaxed for the forced
  // path) and `< commit_min` (4) — applying it would rewind the applied frontier. Part B DROPS it
  // gracefully (no panic, no rewind) instead of asserting; the LEGITIMATE forced sync is unaffected.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut ep =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, CountSm::default(), u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 2);
  let now = Instant::ZERO;
  // Head op 4, applied frontier already at 4, own checkpoint 0 (no hole — the band is fully applied).
  ep.force_state_for_test(0, 4, 4, 0, &[]);
  ep.seed_log_entry_for_test(4);
  // Arm a forced sync to a target (2) the applied frontier (4) is already past — exactly the reordered
  // state where Part A's chokepoint never fired between the arm and the delivery below.
  ep.arm_forced_sync_for_test(2);
  let nonce = ep.sync_nonce_for_test();
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(2);
  let (env, id) = donor_envelope(&dsb);
  // Deliver the stale forced SyncCheckpoint at op 2. It passes the upstream guards (target 2 reached,
  // forced relaxes `<= self.op`, 2 > own checkpoint 0, integrity ok, not primary) and reaches
  // `apply_sync` with `checkpoint_op 2 < commit_min 4`. FAIL-BEFORE: panic. PASS-AFTER: dropped.
  ep.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
    )),
  );
  ep.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    ep.commit(),
    OpNumber::with(4),
    "Part B: the stale forced SyncCheckpoint below the applied frontier was DROPPED — no rewind"
  );
  assert_eq!(
    ep.checkpoint_op(),
    OpNumber::with(0),
    "no stale checkpoint installed"
  );
  assert_eq!(ep.op(), OpNumber::with(4), "head unchanged");
  assert_eq!(
    ep.state_syncs_applied(),
    0,
    "no sync applied from the stale response"
  );
  assert_eq!(
    ep.sync_target_for_test(),
    None,
    "the stale forced sync was cancelled on the drop (its target is already satisfied)"
  );
}

#[test]
fn a_primary_in_the_force_sync_strand_forfeits_instead_of_resetting_op() {
  // SAFETY REGRESSION (op-number reuse → divergence): a PRIMARY that reaches the force-sync strand (a
  // committed-op repair hole at/below `max_peer_checkpoint_op`) must NOT force-sync. Force-sync resets
  // `self.op` to the checkpoint (BELOW the primary's head) and clears the log/inflight; the primary
  // would then assign NEW client requests at REUSED op numbers in the same view, which backups re-ack
  // from their old entries WITHOUT comparing bodies → the primary commits body B while backups applied
  // body A for the same op (committed-state divergence). The fix: the primary flags a deferred forfeit
  // and steps down on its next tick — `self.op` is NEVER rewound, and no forced sync is armed.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, NoopSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  assert!(ep.is_primary(), "replica 0 at view 0 is the primary");
  // The primary holds a head at op 10 with a committed-op hole at op 2 (commit held at 1 below it).
  // (A recovered primary with a rotted committed slot the cluster long since checkpointed+pruned.)
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
  assert_eq!(ep.op(), OpNumber::with(10));
  // A backup's PrepareOk reports checkpoint_op = 8 — ABOVE the hole at 2, so the hole is snapshot-only
  // on that peer (pruned: RequestPrepare is futile). This drives the production `on_prepare_ok` →
  // `maybe_force_sync` path on the PRIMARY (the exact strand the finding flagged as reachable).
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(2),
      ReplicaId::new(1),
      OpNumber::with(8),
      0,
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    ep.max_peer_checkpoint_op(),
    OpNumber::with(8),
    "the peer-checkpoint floor (8) is above the hole (2) → the force-sync strand is entered"
  );
  // The CORE assertion: the primary flagged a deferred forfeit and did NOT touch its op or arm a sync.
  assert!(
    ep.pending_forfeit_for_test(),
    "the primary flags a deferred forfeit instead of force-syncing"
  );
  assert_eq!(
    ep.op(),
    OpNumber::with(10),
    "the primary's op is NOT rewound to the checkpoint (no op-number reuse)"
  );
  assert_eq!(
    ep.sync_target_for_test(),
    None,
    "no forced sync is armed on the primary (it steps down, it does not reset its state)"
  );
  assert!(
    ep.has_repair_hole_for_test(2),
    "the hole is NOT cleared by a force-sync — the primary abdicates rather than subsume it locally"
  );
  // No RequestSync was emitted (a primary never force-syncs).
  let mut saw_request_sync = false;
  while let Some(out) = ep.poll_message() {
    if let Message::RequestSync(_) = out.msg_ref() {
      saw_request_sync = true;
    }
  }
  assert!(
    !saw_request_sync,
    "a primary in the force-sync strand emits NO RequestSync (no self-reset)"
  );
  // The next primary tick ACTS on the flag: it forfeits by proposing the next view (StartViewChange).
  // The flag PERSISTS — the lone SVC has not yet formed a quorum, so the view has not changed;
  // the latch keeps the primary re-proposing + not heartbeating until it does. The op is unchanged.
  // (The step-down bootstraps `svc_message` at the retransmit cadence, so the re-propose
  // is serviced on the next svc_message window; tick at that 100ms boundary.)
  ep.handle_timeout(
    Instant::ZERO + core::time::Duration::from_millis(100),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  assert!(
    ep.pending_forfeit_for_test(),
    "the forfeit PERSISTS until the view actually changes (not one-shot — a dropped SVC must not let \
     the primary resume heartbeating and wedge the cluster)"
  );
  assert_eq!(
    ep.op(),
    OpNumber::with(10),
    "op remains unchanged across the forfeit (never reset)"
  );
  let mut saw_svc_view1 = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(svc) = out.into_msg()
      && svc.view().get() == 1
    {
      saw_svc_view1 = true;
    }
  }
  assert!(
    saw_svc_view1,
    "the flagged primary forfeits on its next tick (proposes view 1 via StartViewChange)"
  );
}

#[test]
fn a_primary_in_the_force_sync_strand_never_reuses_an_op_number() {
  // SAFETY (the heart of the finding): the op-reuse divergence happens ONLY if the primary's `op` is
  // REWOUND below its head (force-sync resets it to the checkpoint, then new requests land at the
  // vacated op numbers that backups still hold under old bodies). The forfeit fix guarantees `op` is
  // NEVER rewound. We drive the full strand→forfeit→serve sequence and assert `op` is monotone
  // non-decreasing throughout: a request the (still-Normal, lone-SVC) primary serves lands at a FRESH
  // op ABOVE the old head (11), never at a reused number. Under the OLD force-sync behaviour `op`
  // would have collapsed to the checkpoint floor, and the next request would have reused op 9/10.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, NoopSm, u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
  let head_at_strand = ep.op().get();
  assert_eq!(head_at_strand, 10);
  // Enter the force-sync strand (flag the deferred forfeit) via a peer PrepareOk above the hole.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(2),
      ReplicaId::new(1),
      OpNumber::with(8),
      0,
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(ep.pending_forfeit_for_test());
  assert!(
    ep.op().get() >= head_at_strand,
    "entering the strand did NOT rewind op (no force-sync reset)"
  );
  while ep.poll_message().is_some() {}
  // The forfeit fires on the next tick → the primary proposes view 1 (a lone SVC; view stays 0 until a
  // real SVC quorum forms, so it may still be primary-of-view-0 and serve).
  ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb, &mut blocks);
  assert!(
    ep.op().get() >= head_at_strand,
    "the forfeit did NOT rewind op (it steps down, it does not reset state)"
  );
  while ep.poll_message().is_some() {}
  // A fresh client request: whatever the primary does with it, it must NOT assign it an op number
  // at/below the head it held at the strand (that would be a reuse). If it serves at all, it serves
  // STRICTLY ABOVE the old head.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from(std::vec![42u8]),
    )),
  );
  assert!(
    ep.op().get() >= head_at_strand,
    "op is never rewound across the whole sequence → no op number is ever reused"
  );
  // Any Prepare the primary broadcast for the new request carries an op STRICTLY above the old head —
  // never a reused op number that a backup still holds under a different body.
  while let Some(out) = ep.poll_message() {
    if let Message::Prepare(p) = out.msg_ref() {
      assert!(
        p.op().get() > head_at_strand,
        "a served request lands at a FRESH op (> old head {head_at_strand}), never a reused number"
      );
    }
  }
}

#[test]
fn recover_after_state_sync_restores_the_synced_checkpoint() {
  // Durability-before-resume: after a sync goes durable, a crash + recover() must come back at the
  // synced checkpoint (the durable root names it), not the stale one.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
  drop(e); // crash
  // Recover from the same wal/sb: the synced checkpoint is the durable root.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let mut recovered = Endpoint::recover(
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
  assert_eq!(
    recovered.checkpoint_op(),
    OpNumber::with(4),
    "recovered at the synced checkpoint"
  );
  assert_eq!(recovered.commit(), OpNumber::with(4));
  assert_eq!(
    recovered.op(),
    OpNumber::with(4),
    "op >= commit_min must hold after recover (the synced head, not a sub-checkpoint WAL head)"
  );
  recovered.handle_storage(now, &mut wal, &mut sb, &mut blocks); // restore SM from the synced snapshot → Normal
  assert_eq!(recovered.status(), Status::Normal);
  assert_eq!(
    recovered.state_machine_ref().applied().len(),
    4,
    "recovered SM reflects the synced checkpoint prefix"
  );
}

// ── State-sync — view-change / canonical-log-interaction safety (regression guards) ──

#[test]
fn synced_replica_reports_its_checkpoint_in_view_change() {
  // After syncing to checkpoint 4, force the replica into a view change and inspect its DVC: it must
  // report commit == 4 (the synced point) with log_view <= view and a tail that does NOT start at
  // op 1 — exactly the recover-from-checkpoint shape (this is the canonical-log interaction; no canonical-log-selection code here).
  // Use replica 2 of 3 as the laggard: in view 1 the primary is replica 1 (not itself), so it sends
  // a DoViewChange we can capture (a replica that is itself the next primary would form the
  // canonical log directly instead of sending a DVC).
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::with_checkpoint_ops(1, MemberId::new(2), 2).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = {
    let mut nonce = None;
    while let Some(out) = e.poll_message() {
      if let Message::RequestSync(r) = out.msg_ref() {
        nonce = Some(r.nonce());
      }
    }
    nonce.expect("a RequestSync was emitted")
  };
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.status(), Status::Normal);
  while e.poll_message().is_some() {}

  // Force a view change to view 1 (primary = replica 1): replica 2 proposes view 1 on idle, a peer
  // SVC completes the quorum → ViewChange(1) → it sends a DoViewChange to replica 1.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks); // primary_idle → propose view 1 (own bit)
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  assert_eq!(e.view(), View::with(1));
  e.handle_storage(later, &mut wal, &mut sb, &mut blocks); // durable-view write completes → DVC is sent
  let mut dvc = None;
  while let Some(out) = e.poll_message() {
    if let Message::DoViewChange(d) = out.msg_ref() {
      dvc = Some(d.clone());
    }
  }
  let dvc = dvc.expect("a synced backup sends a DoViewChange");
  assert_eq!(
    dvc.commit(),
    OpNumber::with(4),
    "reports the synced checkpoint as commit, not a sparse log"
  );
  assert_eq!(
    dvc.op(),
    OpNumber::with(4),
    "head is the synced point (tail-empty)"
  );
  assert!(dvc.log_view().get() <= dvc.view().get(), "log_view <= view");
  // The carried log is the (empty) tail above the checkpoint — it does NOT fabricate ops [1..=4].
  assert!(
    dvc.log_slice().iter().all(|e| e.op().get() > 4),
    "the DVC log is the tail above the synced checkpoint (no fabricated sub-checkpoint ops)"
  );
}

#[test]
fn bounded_wal_below_ring_sync_does_not_wedge_after_a_local_checkpoint_satisfies_it() {
  // REGRESSION (the un-completable-sync WEDGE). The bounded-WAL backup-overflow path
  // `maybe_sync_below_ring_window` armed a forced sync whenever the cluster checkpoint `C` the
  // overflowing Prepare advertises satisfied `C >= self.commit_min`. The `==` case (`C == commit_min`)
  // is the bug: a sub-quorum backup that has ALREADY APPLIED through `C` (commit_min == C) but whose own
  // `checkpoint_op` still LAGS (an ordinary checkpoint for `C` merely IN FLIGHT) would arm a forced sync
  // at `target = C`. Then the LOCAL ordinary checkpoint root LANDS, advancing `checkpoint_op` to `C` —
  // but `cancel_forced_sync_if_satisfied` fires only on a COMMIT advance, never a CHECKPOINT advance, so
  // the forced sync stays armed at `target == C == checkpoint_op`. An equal `SyncCheckpoint(C)` is then
  // REJECTED by `on_sync_checkpoint`'s `checkpoint_op <= self.checkpoint_op` guard (a sync to a
  // checkpoint we already hold is a no-op) → the forced sync can NEVER complete. And while
  // `sync.is_some()`, `on_prepare` DROPS every retransmitted Prepare → the backup WEDGES: it already
  // holds the checkpoint it needed, yet is stuck "syncing" forever, dropping the very prepares that
  // would extend its head.
  //
  // FAIL-BEFORE: with the `>= commit_min` arm, the forced sync stays armed (target C == checkpoint_op),
  // the equal SyncCheckpoint is rejected, and the retransmitted Prepare is dropped — `op` never extends,
  // no PrepareOk, the cluster cannot converge through this replica. PASS-AFTER (Part A): the arm uses the
  // STRICT `target > commit_min`, so the `C == commit_min` case arms NO sync — it just back-pressures
  // (drops the overflowing Prepare). The in-flight local checkpoint then advances `checkpoint_op` to `C`,
  // freeing the ring, and the retransmitted Prepare FITS + appends + acks. No wedge.
  //
  // Numbers: capacity N = 4; old checkpoint_op = 0; commit_min = C = 5; head = 5. The next op (6)
  // overflows the ring (`6 - 0 = 6 > 4`), and the Prepare advertises checkpoint_op = C = 5 == commit_min
  // (the `==` case) while `5 <= head` (so the ORDINARY `> self.op` sync trigger correctly does NOT fire —
  // only the below-ring path can).
  const N: u64 = 4;
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 5).unwrap(); // checkpoint_ops == C
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, CountSm::default(), u64::MAX);
  let mut wal = RingWal::new(N);
  let mut sb = StepSb::default(); // async: the ordinary checkpoint root lands on a later flush
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // Pre-overflow state: a sub-quorum laggard with head 5, applied frontier (commit_min) 5, own
  // checkpoint still 0. Its head ran ahead of its checkpoint (the canonical-head-over-a-held-hole shape),
  // so its ring is FULL relative to its stale checkpoint. Seed the live tail (1..=5) into the ring so the
  // resident-tail invariant is realistic (the checkpoint snapshot content itself is irrelevant — the
  // wedge is about the sync arming, and the sync is never applied).
  e.force_state_for_test(0, 5, 5, 0, &[]);
  for op in 1..=5u64 {
    let body = Bytes::copy_from_slice(&[op as u8]);
    let h = Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &body,
    );
    wal.entries.insert(op, (h, body));
  }
  wal.head = 5;

  // Stage a REAL ordinary checkpoint for C = 5 (as `advance_commit` → `maybe_checkpoint` would once the
  // backup applied through the checkpoint boundary): commit_min (5) >= checkpoint_op (0) + checkpoint_ops
  // (5), so this snapshots at commit_min and submits the snapshot write to the async superblock. It is
  // now IN FLIGHT (checkpoint_op is still 0 until the root lands).
  e.maybe_checkpoint(&mut sb, &mut blocks);
  assert_eq!(
    e.pending_checkpoint_is_sync_for_test(),
    Some(false),
    "an ORDINARY checkpoint for C is staged (in flight) — checkpoint_op is still old"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "the local checkpoint has NOT landed yet (checkpoint_op still 0)"
  );

  // A head-extending Prepare(op = 6, commit = 5, checkpoint_op = 5) arrives. It OVERFLOWS the ring
  // (`6 - 0 > N`). checkpoint_op = 5 <= head 5, so the ordinary `> self.op` sync trigger does NOT fire;
  // the below-ring-window guard handles it. The Prepare is dropped either way (back-pressure); the
  // question is whether a forced sync is (wrongly) armed at C = commit_min.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare_ck(6, 5, 5),
  );
  while e.poll_message().is_some() {}
  assert_eq!(
    e.op(),
    OpNumber::with(5),
    "the overflowing Prepare was dropped (back-pressure) — head not extended past the ring"
  );
  // PART A — the discriminator. With `C == commit_min`, NO forced sync may be armed: the backup has
  // ALREADY applied through the cluster checkpoint, so the ring is full only because its OWN checkpoint
  // lags — a local checkpoint (in flight) will free it. (FAIL-BEFORE: a forced sync to target 5 is armed
  // here, which the local checkpoint then makes un-completable.)
  assert_eq!(
    e.sync_target_for_test(),
    None,
    "Part A: a below-ring forced sync is NOT armed when applied through the cluster checkpoint \
     (target C == commit_min) — it back-pressures instead, so the local checkpoint can release it"
  );
  assert_eq!(
    e.below_ring_window_syncs(),
    0,
    "no below-ring-window sync was armed in the C == commit_min case"
  );

  // The in-flight LOCAL ordinary checkpoint root now lands → checkpoint_op advances to C = 5, freeing the
  // ring (`head - checkpoint_op = 0`). (With the old code this is the exact moment a forced sync armed at
  // C becomes un-completable — sync.target == checkpoint_op == 5.)
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // AwaitSnapshot → submit root
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // AwaitRoot → advance_checkpoint_op(5) + run_gc
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(5),
    "the local ordinary checkpoint landed → checkpoint_op advanced to C"
  );
  assert_eq!(
    e.sync_target_for_test(),
    None,
    "still no outstanding sync after the local checkpoint (nothing left un-completable)"
  );

  // THE WEDGE TEST. The donor crashes / a prior ack was lost, so the primary RETRANSMITS the
  // head-extending Prepare(op = 6). The ring now has room (`6 - checkpoint_op(5) = 1 <= N`), so a healthy
  // backup APPENDS it and acks. FAIL-BEFORE: `sync.is_some()` (the un-completable forced sync) makes
  // `on_prepare` DROP this retransmit → op stays 5, no PrepareOk, the cluster wedges through this replica.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    prepare_ck(6, 5, 5),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drive the append → its PrepareOk
  let mut acked_op6 = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.msg_ref() {
      acked_op6 |= ok.op() == OpNumber::with(6);
    }
  }
  assert_eq!(
    e.op(),
    OpNumber::with(6),
    "NO WEDGE: the retransmitted Prepare(6) was APPENDED (the ring freed; no un-completable sync \
     dropped it) — the backup's head extended"
  );
  assert!(
    acked_op6,
    "NO WEDGE: the backup ACKED the retransmitted op 6 — it can make progress (it is not stuck \
     dropping prepares behind a sync it can never complete)"
  );
  assert!(
    wal.entries.contains_key(&6),
    "op 6 is durably resident in the ring after the append"
  );

  // And the cluster converges through this replica: a Commit advancing the frontier to 6 applies cleanly
  // (the backup is no longer wedged behind a phantom sync).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(6),
      OpNumber::with(5),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.commit(),
    OpNumber::with(6),
    "the backup applied op 6 — it converged (no wedge)"
  );
  assert_eq!(
    e.sync_target_for_test(),
    None,
    "no phantom sync was ever left armed across the whole sequence"
  );
  // Part B (defense-in-depth) is SUBSUMED by Part A — no checkpoint-advance cancellation is added. Every
  // forced/ordinary sync is armed with `target > commit_min` (below-ring: the strict discriminator;
  // `maybe_force_sync`: `target = floor` over a hole held at `commit_min < floor`; ordinary: `target >
  // self.op >= commit_min`). A LOCAL checkpoint advances `checkpoint_op` to at most `commit_min` (it
  // checkpoints at `target_op = commit_min`), so `checkpoint_op <= commit_min < sync.target` always holds
  // — a local checkpoint can NEVER make `sync.target <= checkpoint_op`. So a checkpoint-advance
  // satisfied-sync cancel would be dead code; Part A closes the wedge at the root (the arm site).
}

/// Capture the `SyncCheckpoint` a donor ships in answer to a `RequestSync` from replica 2 (draining
/// the rest of the outbound queue).
fn serve_request_sync(
  e: &mut Endpoint<CountSm>,
  wal: &mut TestWal,
  sb: &mut TestSb,
  blocks: &mut MemBlockStore,
) -> crate::SyncCheckpoint {
  let now = Instant::ZERO;
  while e.poll_message().is_some() {} // drain warm-up / membership-change emissions
  e.handle_message(
    now,
    wal,
    sb,
    blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      e.view(),
      OpNumber::with(0),
      ReplicaId::new(2),
      0xCAFE,
      false,
      0,
    )),
  );
  e.handle_storage(now, wal, sb, blocks); // the checkpoint read completes → ship SyncCheckpoint
  let mut shipped = None;
  while let Some(out) = e.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      shipped = Some(s.clone());
    }
  }
  shipped.expect("the donor ships a SyncCheckpoint")
}

#[test]
fn a_swapped_donor_below_its_reconfigure_op_withholds_the_cross_epoch_membership() {
  // XI-b SERVE GATE (the CP-safety fix): a donor that has committed-first SWAPPED to E+1 at reconfigure
  // op N, but whose durable checkpoint is still BELOW N, must NOT attach its E+1 membership to a sync
  // answer — else a laggard would install E+1 at the served frontier `M < N`, i.e. at E+1 WITHOUT the
  // committed prefix through the reconfigure op, and could vote in E+1 unsafely. The donor instead serves
  // an EMPTY membership; once its checkpoint advances PAST N it serves the real E+1 membership.
  let (mut e, mut wal, mut sb) = donor_primary_at_checkpoint(2);
  let mut blocks = crate::block_store::MemBlockStore::new();
  // SWAP to E+1 exactly as a commit-first swap does (AddVoter keeps replica 0 a voter, so it stays the
  // primary), naming reconfigure op N = 5 — ABOVE the donor's durable checkpoint (op 2). This is the
  // commit-first window: the swap is in memory (epoch = E+1) but the checkpoint does not yet reflect it.
  let successor = e
    .membership
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid");
  let predecessor_config_id = e.membership.config_id();
  e.install_membership(Some(OpNumber::with(5)), successor.clone());
  assert_eq!(
    e.config_install_op,
    OpNumber::with(5),
    "install_membership(Some(N)) records the reconfigure op as config_install_op"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the donor is at E+1"
  );
  assert!(
    e.checkpoint_op().get() < e.config_install_op.get(),
    "the donor's checkpoint (2) is BELOW its reconfigure op (5) — the commit-first window"
  );

  // SERVE while below N: the header advertises E+1 (the donor's epoch/config_id), but the membership BODY
  // is WITHHELD (empty) — so a cross-epoch laggard cannot install E+1 from this below-N checkpoint.
  let shipped = serve_request_sync(&mut e, &mut wal, &mut sb, &mut blocks);
  assert_eq!(shipped.checkpoint_op(), OpNumber::with(2));
  assert_eq!(
    shipped.epoch(),
    crate::Epoch::new(1),
    "the answer still advertises the donor's E+1 epoch in its header"
  );
  assert_ne!(
    shipped.config_id(),
    predecessor_config_id,
    "the header carries the E+1 config_id"
  );
  assert!(
    shipped.membership().is_empty(),
    "BELOW the reconfigure op the donor WITHHOLDS the cross-epoch membership (empty body)"
  );

  // The donor now CHECKPOINTS PAST N: model it by lowering config_install_op to at/below the checkpoint
  // (equivalently, the checkpoint advanced to/over N). The gate flips to SERVE the real E+1 membership.
  e.config_install_op = OpNumber::with(2);
  let shipped = serve_request_sync(&mut e, &mut wal, &mut sb, &mut blocks);
  assert!(
    !shipped.membership().is_empty(),
    "once the checkpoint reflects the reconfigure op the donor SERVES the E+1 membership"
  );
  // The served body is the canonical E+1 membership, chained off its predecessor — it reconstructs +
  // verifies to exactly the successor a laggard would install.
  let served = crate::message::ReconfigurePayload::decode_body(shipped.membership())
    .expect("the served membership body decodes")
    .to_membership_verified(shipped.epoch(), shipped.config_id())
    .expect("the served membership verifies against its carried (epoch, config_id)");
  assert_eq!(
    served, successor,
    "the served membership is the exact E+1 successor"
  );
}

#[test]
fn a_laggard_keeps_its_membership_when_a_below_n_donor_withholds_then_swaps_once_served() {
  // End to end: a laggard at the PREDECESSOR config receives a cross-epoch answer with an EMPTY membership
  // (a donor below its reconfigure op). It must NOT install E+1 — it installs the SM frontier but KEEPS
  // its current membership. Then, given a cross-epoch answer that DOES carry the membership (the donor has
  // since checkpointed past N), it installs the successor.
  let predecessor = genesis(3);
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid");

  // --- Phase 1: the WITHHELD (empty) cross-epoch answer keeps the laggard's membership. ---
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let laggard_config_id = e.membership.config_id();
  assert_eq!(
    laggard_config_id,
    predecessor.config_id(),
    "the laggard starts at the predecessor config"
  );
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  // A cross-epoch SyncCheckpoint: the header advertises E+1, but the membership body is EMPTY (the donor
  // withheld it — its checkpoint is below the reconfigure op).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      successor.epoch(),
      successor.config_id(),
      ReplicaId::new(0),
      nonce,
      env.clone(),
      Bytes::new(), // WITHHELD cross-epoch membership
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the two-write persist → durable root → install
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the laggard still installs the SM frontier off the below-N checkpoint"
  );
  assert_eq!(
    e.membership.config_id(),
    laggard_config_id,
    "the laggard KEEPS its membership — it did NOT install E+1 from the withheld (empty) answer"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "the laggard is still at its old epoch (E), to catch the band up to N via the commit-first path"
  );

  // --- Phase 2: a cross-epoch answer that CARRIES the membership installs the successor. ---
  let (mut e2, mut wal2, mut sb2, env2, id2) = sync_apply_harness(4);
  let mut blocks2 = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks2, 4);
  e2.handle_message(
    now,
    &mut wal2,
    &mut sb2,
    &mut blocks2,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce2 = captured_sync_nonce(&mut e2);
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor, predecessor.config_id())
      .encode_body();
  e2.handle_message(
    now,
    &mut wal2,
    &mut sb2,
    &mut blocks2,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id2,
      successor.epoch(),
      successor.config_id(),
      ReplicaId::new(0),
      nonce2,
      env2.clone(),
      membership_body,
    )),
  );
  e2.handle_storage(now, &mut wal2, &mut sb2, &mut blocks2);
  assert_eq!(
    e2.state_syncs_applied(),
    1,
    "the carried-membership sync applies"
  );
  assert_eq!(
    e2.membership, successor,
    "a cross-epoch answer that CARRIES the membership installs the E+1 successor"
  );
}

#[test]
fn a_direct_e0_to_e2_crossing_stamps_the_verified_chain_so_a_reserve_verifies() {
  // XI-b LINEAGE HASH-CHAIN (the multi-epoch-skip fix). A retained E0 laggard state-syncs an E2
  // successor DIRECTLY from an E2 donor (a multi-epoch skip inside the two-prior window): E2's config_id
  // chains from E1 (`hash(E2_membership, E1) == E2_config_id`), so it VERIFIES. The crossing install must
  // stamp the lineage from the VERIFIED chain — `[E1, E0]` most-recent-first (the verified immediate
  // predecessor E1, then the laggard's own prior E0) — NOT `[E0, ..]` re-derived from the laggard's stale
  // current config. Otherwise a later RE-SERVE of the E2 membership would chain it from E0, recomputing a
  // config_id NO fresh laggard expects, and that laggard would reject the crossing forever. This drives
  // the direct E0→E2 install, asserts the `[E1, E0]` ring, then RE-SERVES E2 to a fresh laggard and
  // asserts its crossing VERIFIES (recomputes E2's config_id) — proving the re-served bytes carry E1.
  let e0 = genesis(3); // [0,1,2]
  let e1 = e0
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter(3) on the 3-voter genesis is valid"); // [0,1,2,3], chains from E0
  let e2 = e1
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(4)))
    .expect("AddVoter(4) on the 4-voter E1 is valid"); // [0,1,2,3,4], chains from E1
  assert_eq!(e1.epoch(), crate::Epoch::new(1));
  assert_eq!(
    e2.epoch(),
    crate::Epoch::new(2),
    "E2 is two epochs above genesis"
  );
  assert_ne!(e1.config_id(), e0.config_id());
  assert_ne!(e2.config_id(), e1.config_id());
  // The donor serves the E2 membership chained from its VERIFIED predecessor E1.
  assert_eq!(
    crate::Membership::recompute_config_id(
      e2.epoch(),
      e2.replica_count(),
      e2.learner_count(),
      e2.members_slice(),
      e1.config_id(),
    ),
    e2.config_id(),
    "E2's config_id chains from E1 — so `to_membership_verified` against E1 succeeds"
  );

  // The laggard starts at E0 (MemberId 1, slot 1 — retained in E2, so it can later re-serve).
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  assert_eq!(
    e.membership.config_id(),
    e0.config_id(),
    "laggard starts at E0"
  );
  let now = Instant::ZERO;
  // A higher-epoch heartbeat arms the (forced, crossing-required) cross-epoch sync.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  // The E2 donor's SyncCheckpoint: header advertises E2, body is the E2 membership chained from E1.
  let e2_body =
    crate::message::ReconfigurePayload::from_membership(&e2, e1.config_id()).encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      e2.epoch(),
      e2.config_id(),
      ReplicaId::new(0),
      nonce,
      env.clone(),
      e2_body,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // two-write persist → durable root → install

  // The crossing installed E2 directly.
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the direct E0→E2 crossing applied"
  );
  assert_eq!(
    e.membership, e2,
    "the laggard installed the E2 successor directly"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(2),
    "the laggard crossed to E2"
  );
  // THE FIX: the in-memory lineage is the VERIFIED chain `[E1, E0]`, NOT `[E0, ..]`.
  assert_eq!(
    e.lineage_ring_for_test(),
    [e1.config_id(), e0.config_id()],
    "the crossing stamped the VERIFIED chain (E1 the immediate predecessor, then the laggard's own prior E0)"
  );
  assert!(e.in_lineage_for_test(e1.config_id()), "E1 admitted");
  assert!(
    e.in_lineage_for_test(e0.config_id()),
    "E0 admitted (the laggard's own prior, within the two-prior window)"
  );
  // THE SCALAR FIX: the LIVE `prev_epoch` is the VERIFIED predecessor E1 (= successor.epoch() - 1), NOT
  // the laggard's stale own epoch E0. Stamping E0 would record "E2 chains from epoch 0" while the ring
  // above says `[E1, E0]` — a contradiction the lineage checker reads as a fork.
  assert_eq!(
    e.prev_epoch,
    crate::Epoch::new(1),
    "the LIVE prev_epoch is the verified predecessor E1 (successor.epoch() - 1), not the stale E0"
  );
  // The DURABLE root the crossing staged records the SAME scalar (recovery restores it). `sb.state()` is
  // the v6 root `durable_root_with_successor` wrote naming the synced checkpoint.
  assert_eq!(
    sb.state().prev_epoch(),
    crate::Epoch::new(1),
    "the DURABLE sync-successor root stamps prev_epoch = E1 (matches the live scalar by construction)"
  );
  assert_eq!(
    sb.state().epoch(),
    crate::Epoch::new(2),
    "the durable root names the crossed-to epoch E2"
  );

  // RE-SERVE: a fresh E0/E1 laggard (slot 2) solicits; the installed node serves its E2 checkpoint with
  // the E2 membership chained from `lineage[0]`. A recovery-flagged RequestSync is served at/above our op.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      e.view(),
      OpNumber::with(0),
      ReplicaId::new(2),
      0xBEEF,
      true, // recovery peer-fetch — served at/above our checkpoint
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the serve-read completes → ship SyncCheckpoint
  let mut reserved = None;
  while let Some(out) = e.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      reserved = Some(s.clone());
    }
  }
  let reserved = reserved.expect("the installed node re-serves a SyncCheckpoint");
  assert_eq!(reserved.epoch(), e2.epoch(), "the re-serve advertises E2");
  assert_eq!(
    reserved.config_id(),
    e2.config_id(),
    "the re-serve advertises E2's config_id"
  );
  assert!(
    !reserved.membership().is_empty(),
    "the re-serve carries the E2 membership (the node's checkpoint reflects it: config_install_op == 4 == checkpoint_op)"
  );
  // THE LOAD-BEARING ASSERTION: a FRESH laggard's crossing VERIFIES the re-served bytes — it recomputes
  // E2's config_id from the carried `(epoch, config_id, membership)`. This succeeds ONLY because the
  // re-served body chains from E1 (`lineage[0]`), the verified predecessor. Were the install to have
  // stamped `lineage[0] = E0`, the body would chain from E0 and this verification would FAIL forever.
  let verified = crate::message::ReconfigurePayload::decode_body(reserved.membership())
    .expect("the re-served membership body decodes")
    .to_membership_verified(reserved.epoch(), reserved.config_id())
    .expect("a fresh laggard's crossing VERIFIES the re-served E2 (recomputes E2's config_id)");
  assert_eq!(
    verified, e2,
    "the re-served bytes reconstruct EXACTLY E2 — the crossing propagates to another laggard"
  );

  // RECOVER off the durable root the crossing staged: a node restarting after the crossing restores the
  // IDENTICAL prev_epoch E1 (the in-memory and durable scalars are the same value by construction, so no
  // contradiction survives a crash). The re-serve above was a read-only serve, so the root's
  // epoch/prev_epoch/membership are unchanged. The laggard's stable id is MemberId 1 (slot 1), retained in
  // E2, so it recovers Active.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let recovered = match Endpoint::recover(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect("recover accepts this store")
  {
    Recovered::Active(r) => r,
    Recovered::Retired(_) => panic!("MemberId 1 is retained in E2 → recover Active"),
  };
  assert_eq!(
    recovered.membership.epoch(),
    crate::Epoch::new(2),
    "the recovered node comes up at E2 (the durable root's epoch)"
  );
  assert_eq!(
    recovered.prev_epoch,
    crate::Epoch::new(1),
    "the RECOVERED prev_epoch is E1 — the durable root's scalar restored unchanged (matches the live + \
     durable scalars asserted above)"
  );
}

#[test]
fn a_direct_e0_to_e3_crossing_too_deep_for_the_ring_is_rejected_not_mis_installed() {
  // XI-b LINEAGE DISTANCE BOUND (the deep-skip guard). A retained E0 laggard is offered an E3 successor
  // DIRECTLY from an E3 donor — an epoch DISTANCE of 3, beyond the two-prior `LINEAGE_RING` window. The
  // carried payload VERIFIES (E3's config_id chains from E2, `hash(E3_membership, E2) == E3_config_id`),
  // but a single carried predecessor (E2) cannot prove the missing E2<-E1<-E0 chain, and the ring (two
  // slots) cannot hold both the verified immediate predecessor E2 AND the laggard's own prior E0 with E2's
  // real predecessor E1 in between. So `apply_sync`'s distance guard REJECTS it: stage NOTHING, no install,
  // `sync` stays armed (forced + crossing-required) so the solicit timer re-fetches / a closer-skip donor
  // is tried — the laggard stays at E0 rather than mis-installing a lineage it cannot represent. (Contrast
  // the distance-2 E0→E2 crossing above, which the SAME guard ACCEPTS and stamps `[E1, E0]`.)
  let e0 = genesis(3); // [0,1,2]
  let e1 = e0
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter(3) on the 3-voter genesis is valid"); // E1, chains from E0
  let e2 = e1
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(4)))
    .expect("AddVoter(4) on the 4-voter E1 is valid"); // E2, chains from E1
  let e3 = e2
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(5)))
    .expect("AddVoter(5) on the 5-voter E2 is valid"); // E3, chains from E2
  assert_eq!(
    e3.epoch(),
    crate::Epoch::new(3),
    "E3 is three epochs above genesis"
  );
  // The donor serves the E3 membership chained from its VERIFIED predecessor E2 — so the payload would
  // PASS `to_membership_verified`; ONLY the distance bound rejects it.
  assert_eq!(
    crate::Membership::recompute_config_id(
      e3.epoch(),
      e3.replica_count(),
      e3.learner_count(),
      e3.members_slice(),
      e2.config_id(),
    ),
    e3.config_id(),
    "E3's config_id chains from E2 — the payload verifies; only the distance-3 bound rejects it"
  );

  // The laggard starts at E0 (MemberId 1, slot 1).
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  assert_eq!(
    e.membership.config_id(),
    e0.config_id(),
    "laggard starts at E0"
  );
  let now = Instant::ZERO;
  // Arm the sync exactly as the E0→E2 crossing test does: a same-epoch `Commit` advertising the higher
  // checkpoint op 4 arms an ordinary sync; the CROSSING is driven purely by the reply's higher epoch +
  // successor membership. The distance guard lives in `apply_sync`'s successor-reconstruction block, which
  // runs on ANY successor-carrying reply (gated on a differing config_id + non-empty membership), so it
  // applies here independent of `require_cross_epoch`.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  assert!(e.sync_target_for_test().is_some(), "a sync is armed");
  // The E3 donor's SyncCheckpoint: header advertises E3, body is the E3 membership chained from E2. The
  // freshness/monotone gates pass (checkpoint_op 4 > self.checkpoint_op 0), so it REACHES `apply_sync` —
  // where the distance guard is the load-bearing rejection.
  let e3_body =
    crate::message::ReconfigurePayload::from_membership(&e3, e2.config_id()).encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      e3.epoch(),
      e3.config_id(),
      ReplicaId::new(0),
      nonce,
      env.clone(),
      e3_body,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // nothing was staged → no install drives here

  // REJECTED: no crossing installed, the laggard is STILL at E0, and the sync stays armed for a re-fetch.
  assert_eq!(
    e.state_syncs_applied(),
    0,
    "the too-deep E0→E3 skip was REJECTED — no sync installed"
  );
  assert_eq!(
    e.membership.config_id(),
    e0.config_id(),
    "the laggard did NOT cross — still at E0"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "still at epoch E0"
  );
  assert_eq!(
    e.prev_epoch,
    crate::Epoch::new(0),
    "prev_epoch unchanged (genesis) — no mis-installed scalar"
  );
  assert!(
    !e.pending_sb_for_test(),
    "nothing was staged — no pending durable root"
  );
  assert!(
    e.pending_checkpoint_is_sync_for_test().is_none(),
    "nothing was staged — no pending checkpoint (the reject returned BEFORE submit_write_checkpoint)"
  );
  assert!(
    e.sync_target_for_test().is_some(),
    "the sync STAYS armed (the solicit timer re-fetches a closer donor) — not mis-installed"
  );
}

#[test]
fn an_op_equals_n_normal_laggard_forced_syncs_across_the_epoch() {
  // Change #2 — the `op == N` crossing. A Normal laggard APPENDED the reconfigure op N but missed its
  // commit (`op == N`, `commit_min < N`), so the ordinary `maybe_request_sync` trigger (gated
  // `incoming_checkpoint > self.op`) would do NOTHING for a checkpoint at `M == N == op` and the laggard
  // would strand at the OLD epoch. The unified forced peer-fetch is NOT `> op`-gated: a higher-epoch
  // heartbeat routes the laggard into Recovering + a FORCED, crossing-required sync, and a donor
  // checkpoint at `M >= N` carrying the successor membership crosses it to E+1 (committing N).
  let n: u64 = 2;
  // A backup over CountSm (replica 1 of 3) with a high checkpoint cadence — so driving it to head op N
  // does NOT auto-checkpoint (its `checkpoint_op` stays 0, leaving `op == N`, `commit_min < N`).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 100).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Append ops 1..=N with commit 0 (the laggard appended the reconfigure op N but never saw its commit).
  for op in 1..=n {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      primary_peer(),
      prepare_ck(op, 0, 0),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  while e.poll_message().is_some() {}
  assert_eq!(
    e.op(),
    OpNumber::with(n),
    "the laggard head is at the reconfigure op N"
  );
  assert!(
    e.commit().get() < n,
    "but its commit frontier is below N (it missed N's commit)"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::new(),
    "and it has not checkpointed — a checkpoint at M == N == op is NOT > op, so the ordinary sync would no-op"
  );
  assert!(e.sync_target_for_test().is_none(), "no sync is armed yet");

  // The successor a real swap derives off genesis (AddVoter keeps the lineage valid; epoch is E+1).
  let predecessor = genesis(3);
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid");
  let laggard_config_id = e.membership.config_id();

  // A STRICTLY-higher-epoch Commit (E+1) advertising the cluster checkpoint at N. Dropped at the
  // authority ingress, but it is the cross-epoch catch-up signal: the laggard enters the FORCED
  // peer-fetch (NOT the no-op `maybe_request_sync` path) targeting the crossing checkpoint.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(n),
      OpNumber::with(n),
      crate::Epoch::new(1),
      successor.config_id(),
    )),
  );
  assert!(
    e.status().is_normal() && !e.awaiting_peer_checkpoint_for_test(),
    "the NORMAL op == N laggard STAYS Normal (it does not strand at the old epoch, NOR go Recovering — \
     the speculative arm keeps it operational)"
  );
  assert_eq!(
    e.op(),
    OpNumber::with(n),
    "the speculative arm did NOT rewind op — it is untouched until the crossing checkpoint installs"
  );
  assert!(
    e.commit().get() < n,
    "and commit is still below N (the arm moves no accumulator)"
  );
  assert!(
    e.sync_is_forced_for_test() && e.sync_requires_cross_epoch_for_test(),
    "but it ARMED a FORCED, crossing-required cross-epoch sync"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(n),
    "the forced sync targets the advertised cluster crossing checkpoint (N) — NOT `> op`-gated, so \
     `op == N` still arms"
  );
  let nonce = e.sync_nonce_for_test();

  // A donor at checkpoint M == N answers with a cross-epoch SyncCheckpoint CARRYING the successor
  // membership. (A default-SM snapshot encoded at op N binds op N — the bind check passes.)
  let snap = CountSm::default().snapshot();
  let env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(n),
    crate::block_address(&snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let id = crate::checkpoint_id(&env);
  // The envelope names the SM leaf by content address; seed the leaf so the crossing install's block-fetch
  // frontier drains locally and applies without a RequestBlock round trip.
  blocks.write_verified(snap.clone());
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor, predecessor.config_id())
      .encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(n),
      id,
      successor.epoch(),
      successor.config_id(),
      ReplicaId::new(0),
      nonce,
      env.clone(),
      membership_body,
    )),
  );
  // apply_sync staged the durable re-persist (two superblock writes) + STAYED Normal; drive them.
  for _ in 0..3 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "the crossing SyncCheckpoint install lands the laggard Normal at E+1 (it was Normal throughout)"
  );
  assert_eq!(
    e.membership, successor,
    "the laggard CROSSED to the E+1 successor membership"
  );
  assert_ne!(
    e.membership.config_id(),
    laggard_config_id,
    "the config_id advanced off the predecessor"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(n),
    "the crossing committed the reconfigure op N (commit_min advanced to M >= N)"
  );
  assert_eq!(
    e.forced_syncs_applied(),
    1,
    "the crossing routed through apply_sync as a FORCED sync"
  );
}

/// The reconfigure op the slot-shifting `RemoveVoter(1)` swap names (the donor's checkpoint embeds it).
const SLOT_SHIFT_N: u64 = 4;

/// Build a FAR-BEHIND laggard (checkpoint 0) at the PREDECESSOR config `genesis(4) = [m0,m1,m2,m3]` that
/// has ARMED a FORCED, crossing-required cross-epoch sync toward the E+1 successor produced by a LOW-INDEX
/// `RemoveVoter(MemberId 1)` (the slot-shifting delta). The successor is `[m0,m2,m3]`, so the surviving
/// `MemberId 2` SHIFTS from OLD slot 2 (the laggard's E membership) to NEW slot 1 (the donor's E+1
/// membership) — the slot-shifted DONOR. The laggard itself is `MemberId 3` (retained; it shifts 3->2 in
/// E+1, but during the crossing it is still at E and resolves peers under its E membership). Returns
/// `(laggard, wal, sb, successor, predecessor_config_id, nonce)`.
fn slot_shifted_crossing_laggard() -> (Endpoint<CountSm>, TestWal, TestSb, Membership, u128, u64) {
  // The laggard is MemberId 3 (slot 3) — retained across the removal, far behind, high checkpoint cadence
  // so nothing auto-checkpoints it off the bookkeeping below.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(3), 100).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(4), 0, CountSm::default(), u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let predecessor = genesis(4);
  let predecessor_config_id = e.membership.config_id();
  // The E+1 successor a LOW-INDEX RemoveVoter derives: removing MemberId 1 from [m0,m1,m2,m3] leaves
  // [m0,m2,m3], shifting m2 (slot 2 -> 1) and m3 (slot 3 -> 2).
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::RemoveVoter(MemberId::new(1)))
    .expect("RemoveVoter(1) on a 4-voter cluster is valid (leaves 3 voters)");
  assert_eq!(
    predecessor.member_at(ReplicaId::new(2)),
    Some(MemberId::new(2)),
    "the donor MemberId 2 sits at OLD slot 2 in the laggard's E membership"
  );
  assert_eq!(
    successor.member_at(ReplicaId::new(1)),
    Some(MemberId::new(2)),
    "the donor MemberId 2 SHIFTED to NEW slot 1 in the E+1 successor"
  );

  // ARM the forced cross-epoch sync: a strictly-higher-epoch Commit (E+1) advertising the cluster
  // checkpoint at N. It is dropped at the authority ingress, but the pre-binding catch-up trigger arms a
  // FORCED, crossing-required sync. `from` is a RETAINED, BINDABLE voter (MemberId 0 == slot 0 in both
  // configs) — the laggard need not bind the shifted donor to be triggered.
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(SLOT_SHIFT_N),
      OpNumber::with(SLOT_SHIFT_N),
      crate::Epoch::new(1),
      successor.config_id(),
    )),
  );
  assert!(
    e.sync_is_forced_for_test() && e.sync_requires_cross_epoch_for_test(),
    "the laggard armed a FORCED, crossing-required cross-epoch sync"
  );
  let nonce = e.sync_nonce_for_test();
  (e, wal, sb, successor, predecessor_config_id, nonce)
}

/// The donor's cross-epoch crossing envelope at `SLOT_SHIFT_N`, carrying the E+1 successor membership
/// chained from `predecessor_config_id`. Returns `(env, id, membership_body)`.
fn slot_shift_crossing_envelope(
  successor: &Membership,
  predecessor_config_id: u128,
) -> (Bytes, u128, Bytes) {
  let snap = CountSm::default().snapshot();
  let env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(SLOT_SHIFT_N),
    crate::block_address(&snap),
    super::super::session_blocks::encode_sessions(
      &std::collections::BTreeMap::new(),
      &mut crate::block_store::MemBlockStore::new(),
    ),
  );
  let id = crate::checkpoint_id(&env);
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(successor, predecessor_config_id)
      .encode_body();
  (env, id, membership_body)
}

#[test]
fn a_slot_shifted_donor_whole_sync_checkpoint_reply_is_admitted_and_crosses() {
  // FINDING (high) — the cross-epoch SERVE-REPLY binding. After a LOW-INDEX RemoveVoter shifts a retained
  // DONOR's slot, the donor stamps its WHOLE SyncCheckpoint reply with its CURRENT (E+1) slot while the
  // mid-crossing OLD-epoch laggard resolves `from` under its OLD (E) membership slot — so `from` (E-slot)
  // != claimed (E+1-slot). The STRICT `sender_is_member` binding would DROP the reply at ingress before
  // `apply_sync`. The path-sensitive reply binding admits a nonce-bound reply from an authenticated member
  // while a sync is outstanding; `apply_sync` is the real authenticator (nonce + integrity + the carried
  // successor membership), so the crossing installs.
  let (mut e, mut wal, mut sb, successor, predecessor_config_id, nonce) =
    slot_shifted_crossing_laggard();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let (env, id, membership_body) = slot_shift_crossing_envelope(&successor, predecessor_config_id);
  // `slot_shift_crossing_envelope` names the SM leaf (a default-SM snapshot) by content address; seed it
  // so the crossing install's block-fetch frontier drains locally and applies without a round trip. Seed
  // the (empty) session-table DAG too so the session frontier likewise drains locally.
  blocks.write_verified(CountSm::default().snapshot());
  super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks);

  // The slot-shifted donor MemberId 2: `from` = its OLD slot 2 (what the laggard's E transport resolves),
  // self-stamped `replica()` = its CURRENT slot 1 (the donor's E+1 slot). They DIFFER — the strict binding
  // would drop this.
  let donor_old_slot = ReplicaId::new(2); // resolved `from` (laggard's E membership)
  let donor_current_slot = ReplicaId::new(1); // the donor's self-stamp (its E+1 slot)
  assert_ne!(
    donor_old_slot, donor_current_slot,
    "the donor's E and E+1 slots genuinely differ — a real slot shift"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(donor_old_slot), // bound under the laggard's OLD membership
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(SLOT_SHIFT_N),
      id,
      successor.epoch(),
      successor.config_id(),
      donor_current_slot, // the donor self-stamps its CURRENT (E+1) slot
      nonce,
      env.clone(),
      membership_body,
    )),
  );
  // apply_sync staged the durable re-persist (two superblock writes); drive them to install.
  for _ in 0..3 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the slot-shifted-donor whole SyncCheckpoint reply was ADMITTED — it reached apply_sync and installed"
  );
  assert_eq!(
    e.membership, successor,
    "the laggard CROSSED to the E+1 successor membership off the slot-shifted reply"
  );
  assert_ne!(
    e.membership.config_id(),
    predecessor_config_id,
    "the config_id advanced off the predecessor"
  );

  // MUTATION GUARD: with the reply binding reverted to strict (`sender_is_member`), `from` (slot 2) !=
  // claimed (slot 1) DROPS this reply at ingress and the assertion above FAILS. Confirm the strict path
  // STILL bites the same-config forge surface: a reply whose claimed slot disagrees with `from` AND whose
  // config_id is the laggard's CURRENT (predecessor) config — i.e. NOT a cross-epoch answer, just a
  // mismatched self-id forge — is DROPPED even with a sync outstanding.
  let (mut e2, mut w2, mut s2, succ2, pred2, nonce2) = slot_shifted_crossing_laggard();
  let mut blocks2 = crate::block_store::MemBlockStore::new();
  let (env2, id2, body2) = slot_shift_crossing_envelope(&succ2, pred2);
  e2.handle_message(
    now,
    &mut w2,
    &mut s2,
    &mut blocks2,
    Peer::Replica(ReplicaId::new(2)), // from = slot 2
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(SLOT_SHIFT_N),
      id2,
      e2.membership.epoch(),     // SAME-config header (the laggard's current E)
      e2.membership.config_id(), // CURRENT (predecessor) config_id — NOT a cross-epoch answer
      ReplicaId::new(0),         // claims slot 0 (disagrees with from = slot 2)
      nonce2,
      env2,
      body2,
    )),
  );
  for _ in 0..3 {
    e2.handle_storage(now, &mut w2, &mut s2, &mut blocks2);
  }
  assert_eq!(
    e2.state_syncs_applied(),
    0,
    "a SAME-config mismatched-self-id reply is still DROPPED by the strict binding (no relaxation)"
  );
}

#[test]
fn a_cross_epoch_fetch_rejects_a_below_n_empty_membership_reply_and_re_solicits() {
  // Change #2 — the CROSSING REQUIREMENT. A forced cross-epoch fetch (`require_cross_epoch`) must NOT
  // settle for a below-target / empty-membership reply (a donor in the transient force-checkpoint window
  // serving its `M < N` checkpoint): installing it with `successor = None` would EXIT Recovering STILL at
  // the old epoch — a fetch that does not cross. The fetch REJECTS such a reply (sync stays armed, no
  // install, still old epoch) and re-solicits, completing ONLY on the `M >= N` successor-membership reply.
  let n: u64 = 5;
  let target: u64 = n; // the advertised cluster crossing checkpoint
  // A backup laggard far behind (op 0, checkpoint 0), high checkpoint cadence.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 100).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let predecessor = genesis(3);
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid");
  let laggard_config_id = e.membership.config_id();
  // A higher-epoch Commit advertising the cluster checkpoint at N → the forced crossing fetch.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(target),
      OpNumber::with(target),
      crate::Epoch::new(1),
      successor.config_id(),
    )),
  );
  assert!(
    e.status().is_normal() && !e.awaiting_peer_checkpoint_for_test(),
    "the NORMAL laggard stays Normal (it armed the speculative sync, did not go Recovering)"
  );
  assert!(
    e.sync_is_forced_for_test() && e.sync_requires_cross_epoch_for_test(),
    "the laggard armed a crossing-required forced sync"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(target),
    "targeting the cluster crossing checkpoint N"
  );
  let nonce = e.sync_nonce_for_test();

  // --- A BELOW-N, EMPTY-membership reply (a donor whose checkpoint is still `< N`) — REJECTED. ---
  let below: u64 = 2; // < target (N)
  let below_snap = CountSm::default().snapshot();
  let below_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(below),
    crate::block_address(&below_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let below_id = crate::checkpoint_id(&below_env);
  // Both replies name the same default-SM leaf by content address; seed it so each reaches `apply_sync`
  // (where the crossing-membership check rejects the below-N empty reply and accepts the M >= N one)
  // rather than deferring into a futile block-fetch.
  blocks.write_verified(below_snap.clone());
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(below),
      below_id,
      crate::Epoch::new(1),
      successor.config_id(),
      ReplicaId::new(0),
      nonce,
      below_env.clone(),
      Bytes::new(), // WITHHELD (empty) membership — the donor is below N
    )),
  );
  for _ in 0..3 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.state_syncs_applied(),
    0,
    "the below-N empty-membership reply was REJECTED — nothing installed"
  );
  assert!(
    e.status().is_normal() && e.sync_target_for_test() == Some(target),
    "the sync stays armed (still Normal, still targeting N) — it did not exit / install at the old epoch"
  );
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "the crossing requirement is still pinned so the solicit timer re-fetches"
  );
  assert_eq!(
    e.membership.config_id(),
    laggard_config_id,
    "still at the OLD epoch (no crossing off the withheld reply)"
  );

  // --- A later `M >= N` reply CARRYING the successor membership — crosses. ---
  let cross_snap = CountSm::default().snapshot();
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(n),
    crate::block_address(&cross_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor, predecessor.config_id())
      .encode_body();
  let nonce2 = e.sync_nonce_for_test(); // the still-armed sync's nonce
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(n),
      cross_id,
      successor.epoch(),
      successor.config_id(),
      ReplicaId::new(0),
      nonce2,
      cross_env.clone(),
      membership_body,
    )),
  );
  for _ in 0..3 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "the M >= N crossing reply completes recovery to Normal"
  );
  assert_eq!(
    e.membership, successor,
    "and CROSSES to the E+1 successor membership"
  );
  assert_eq!(
    e.forced_syncs_applied(),
    1,
    "exactly one crossing applied (the below-N reply did not)"
  );
}

#[test]
fn a_cross_epoch_fetch_crosses_below_an_unreachable_hinted_target_on_a_verified_successor() {
  // Change #2 — the VERIFICATION IS THE AUTHORITY, not the unverified hint. The cross-epoch trigger
  // treats the hint's `checkpoint_op` only as a STICKY SOLICIT FLOOR (`target` raises). A buggy/misrouted
  // higher-epoch message (an `EpochAhead` hint here) carrying an UNREACHABLE-HIGH `checkpoint_op` must NOT
  // become a hard crossing bound: the real crossing requirement is installing a VERIFIED successor
  // membership (the bytes hash-chain to the carried `config_id`), which comes only from a donor whose
  // checkpoint is at/above the reconfigure op N. So a later VALID successor-membership reply at a LOWER
  // `checkpoint_op` than the bogus target STILL crosses the laggard. (Were `checkpoint_op >= target` still a
  // crossing conjunct, the bogus hint would pin the target unreachably high and reject every honest reply
  // forever — the laggard would never cross.)
  let n: u64 = 4; // the REAL cluster crossing checkpoint (a donor serves the successor membership at >= N)
  let bogus_target: u64 = 9_999; // an UNREACHABLE hinted checkpoint_op no honest donor can satisfy
  // A backup laggard far behind (op 0, checkpoint 0), high checkpoint cadence.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 100).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let predecessor = genesis(3);
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid");
  let laggard_config_id = e.membership.config_id();

  // A higher-epoch `EpochAhead` hint carrying the BOGUS unreachable checkpoint_op → the speculative
  // crossing fetch arms with that bogus value as its (sticky) target.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::EpochAhead(crate::EpochAhead::new(
      crate::Epoch::new(1),
      OpNumber::with(bogus_target),
    )),
  );
  assert!(
    e.status().is_normal() && !e.awaiting_peer_checkpoint_for_test(),
    "the NORMAL laggard stays Normal (it armed the speculative sync off the hint, did not go Recovering)"
  );
  assert!(
    e.sync_is_forced_for_test() && e.sync_requires_cross_epoch_for_test(),
    "the laggard armed a crossing-required forced sync"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(bogus_target),
    "the (sticky) solicit target latched the BOGUS hinted checkpoint_op — but it is NOT a hard crossing bound"
  );
  let nonce = e.sync_nonce_for_test();

  // --- A below-N, EMPTY-membership reply is STILL rejected (the verification, not the target, gates). ---
  let below: u64 = 1; // below N — a donor in the transient force-checkpoint window, membership withheld
  let below_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(below),
    crate::block_address(&CountSm::default().snapshot()),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let below_id = crate::checkpoint_id(&below_env);
  // Both replies name the same default-SM leaf by content address; seed it so each reaches `apply_sync`
  // (the successor-verification gate) instead of deferring into a futile block-fetch.
  blocks.write_verified(CountSm::default().snapshot());
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(below),
      below_id,
      crate::Epoch::new(1),
      successor.config_id(),
      ReplicaId::new(0),
      nonce,
      below_env.clone(),
      Bytes::new(), // WITHHELD (empty) membership — NOT a verified successor
    )),
  );
  for _ in 0..3 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.state_syncs_applied(),
    0,
    "the empty-membership reply is REJECTED — the crossing requires a VERIFIED successor, not just a checkpoint"
  );
  assert_eq!(
    e.membership.config_id(),
    laggard_config_id,
    "still at the OLD epoch (no crossing off the unverified reply)"
  );

  // --- A VALID successor-membership reply at checkpoint_op N, FAR BELOW the bogus target — CROSSES. ---
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(n),
    crate::block_address(&CountSm::default().snapshot()),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor, predecessor.config_id())
      .encode_body();
  let nonce2 = e.sync_nonce_for_test(); // the still-armed sync's nonce
  assert!(
    n < bogus_target,
    "setup: the VALID crossing reply's checkpoint_op (N) is strictly BELOW the bogus hinted target"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(n),
      cross_id,
      successor.epoch(),
      successor.config_id(),
      ReplicaId::new(0),
      nonce2,
      cross_env.clone(),
      membership_body,
    )),
  );
  for _ in 0..3 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "the verified successor reply (below the bogus target) completes the crossing to Normal"
  );
  assert_eq!(
    e.membership, successor,
    "the laggard CROSSED to the E+1 successor membership — the unreachable hint did not poison the target"
  );
  assert_ne!(
    e.membership.config_id(),
    laggard_config_id,
    "the config_id advanced off the predecessor"
  );
  assert_eq!(
    e.forced_syncs_applied(),
    1,
    "exactly one crossing applied (the empty-membership reply did not)"
  );
}

#[test]
fn a_recovered_swapped_donor_restores_config_install_op_so_the_gate_still_holds() {
  // DURABILITY of the gate: a donor that has swapped to E+1 with its checkpoint still BELOW the reconfigure
  // op N must, after a CRASH + recover, RESTORE config_install_op = N — so it keeps withholding the E+1
  // membership until its checkpoint crosses N. The SwapEpoch durable root carries N (config_install_op),
  // and recover reads it back.
  let genesis_mem = genesis(3);
  let successor = genesis_mem
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter is valid");
  // A REAL checkpoint envelope at op 2 (so recover's decode + bind + id checks all pass).
  let (_d, _dw, dsb) = donor_primary_at_checkpoint(2);
  let (env, env_id) = donor_envelope(&dsb);
  // The durable SwapEpoch root the donor wrote at swap time: the SUCCESSOR membership at checkpoint_op = 2,
  // carrying config_install_op = N = 5 (ABOVE the checkpoint — the commit-first window made durable).
  let swap_root = VsrState::try_new_v4(
    View::new(),
    View::new(),
    OpNumber::with(2), // commit
    OpNumber::with(2), // checkpoint_op — BELOW N
    env_id,
    std::vec::Vec::new(),
    successor.epoch(),
    genesis_mem.epoch(),
    successor.clone(),
    std::vec![genesis_mem.config_id()],
    OpNumber::with(5), // config_install_op = N, ABOVE the checkpoint
  )
  .expect("a SwapEpoch root carrying config_install_op above its checkpoint is valid")
  // A running node stamps geometry on every durable root; match the recover config's interval (1_000)
  // and the ring-less test WAL's `u64::MAX` capacity so recovery's geometry fence accepts it.
  .with_wal_geometry(1_000, u64::MAX);
  assert_eq!(
    swap_root.config_install_op(),
    OpNumber::with(5),
    "the durable root carries config_install_op = N"
  );

  // Recover replica 0 (a voter in the successor) off that root. A state-synced shape: the snapshot owns
  // the prefix [1..=checkpoint_op] and the WAL tail above the checkpoint is EMPTY (head 0 < checkpoint 2),
  // so no WAL entries are needed — recover restores the SM from the snapshot and the metadata from the root.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 1_000).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb {
    state: swap_root,
    done: VecDeque::new(),
    checkpoint: Some((OpNumber::with(2), env)),
  };
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut e = Endpoint::recover(
    cfg,
    genesis_mem,
    9,
    CountSm::default(),
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect("recover accepts this store")
  .expect_active();
  // Drive the recovery storage to completion (the checkpoint read restores the SM + sessions).
  let now = Instant::ZERO;
  for _ in 0..8 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.config_install_op,
    OpNumber::with(5),
    "recover RESTORES config_install_op = N from the durable root"
  );
  assert!(
    e.checkpoint_op().get() < e.config_install_op.get(),
    "the recovered donor is still in the swapped-but-below-N window, so the gate must withhold"
  );
}

#[test]
fn a_stale_cross_epoch_hint_does_not_poison_ordinary_same_epoch_state_sync() {
  // FINDING 2 — the require_cross_epoch DOWNGRADE on the ordinary same-epoch trigger. A speculative
  // `require_cross_epoch` sync can be armed in Normal by the pre-binding higher-epoch / `EpochAhead` hook
  // BEFORE any successor checkpoint is verified — gated only on the hint sender being a replica. If that
  // hint was STALE/misrouted and NO successor checkpoint actually exists, the crossing requirement must NOT
  // persist into a later LEGITIMATE same-epoch state-sync: `apply_sync` would otherwise REJECT every
  // same-config reply forever (it demands a successor that never comes), poisoning ordinary catch-up.
  // The fix: a same-epoch admissible message CANCELS the stale crossing at the ingress, and the node
  // re-arms a fresh ordinary same-config sync (new nonce) that installs.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // Arm a STALE cross-epoch sync at a LOW target (a higher-epoch hint that armed before any successor was
  // verified — and none exists). It is forced + crossing-required.
  e.arm_cross_epoch_sync_for_test(2);
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "setup: the stale hint armed a crossing-required sync"
  );

  // An ORDINARY same-epoch Commit advertising a HIGHER cluster checkpoint (op 4 > head 0). The ingress
  // CANCELS the stale crossing, then `maybe_request_sync` re-arms a fresh ordinary same-config sync at 4.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "the same-epoch ingress evidence CANCELLED the stale crossing requirement"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(4),
    "the cancelled crossing re-armed a fresh ordinary same-config sync at the reachable cluster checkpoint"
  );
  // Cancelled + re-armed at the ingress, so the nonce advanced — capture the CURRENT one for the reply.
  let nonce = e.sync_nonce_for_test();

  // Now a LEGITIMATE same-config (epoch 0, empty membership) SyncCheckpoint at op 4 arrives. With the bit
  // cleared it must PROCEED + INSTALL — not be rejected for lacking a successor membership.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0, // same config_id as the laggard — no successor membership (an ordinary same-epoch sync)
      ReplicaId::new(0),
      nonce,
      env.clone(),
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drive the durable re-persist → install

  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the ordinary same-epoch sync INSTALLED (was not poisoned by the stale crossing requirement)"
  );
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.status(), Status::Normal);
  assert!(
    e.sync_target_for_test().is_none(),
    "the sync completed and cleared (no outstanding, indefinitely-armed sync)"
  );
}

#[test]
fn a_stale_high_target_cross_epoch_hint_does_not_poison_ordinary_same_epoch_state_sync() {
  // CLASS 2, the WHOLE-CLASS downgrade. The prior per-instance fix cleared `require_cross_epoch` ONLY
  // when a same-epoch checkpoint RAISED the sync target (`incoming > s.target`). But a STALE/misrouted
  // higher-epoch hint can pin the speculative cross-epoch sync at an UNREACHABLY-HIGH target. A later
  // LEGITIMATE same-epoch checkpoint that is ABOVE this replica's head yet BELOW the bogus target then
  // takes the NON-raise path — so the bit PERSISTED, and `apply_sync` rejected every same-config reply
  // FOREVER (demanding a successor that never comes). The golden fix CANCELS the stale crossing at the
  // ingress on ANY same-epoch admissible message (target-independent); the node then re-arms a fresh
  // ordinary same-config sync at the reachable checkpoint — so the bogus-high target is gone and the
  // below-bogus reply is no longer dropped at the freshness gate.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // Arm a STALE cross-epoch sync at an UNREACHABLY-HIGH target (op 1000 — no donor will ever serve it;
  // no successor exists). It is forced + crossing-required.
  e.arm_cross_epoch_sync_for_test(1000);
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "setup: the stale hint armed a crossing-required sync"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(1000),
    "setup: pinned at the bogus unreachable-high target"
  );
  // An ORDINARY same-epoch Commit advertising a cluster checkpoint op 4 — ABOVE our head (0) but BELOW
  // the bogus target (1000). The ingress CANCELS the stale crossing regardless of the bogus target, then
  // `maybe_request_sync` re-arms a fresh ordinary same-config sync at the reachable op 4.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "the ingress CANCELLED the stale crossing even though the same-epoch checkpoint was below the bogus target"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(4),
    "the cancelled crossing re-armed a fresh ordinary same-config sync at the reachable op 4 (bogus 1000 gone)"
  );
  // Cancelled + re-armed at the ingress, so the nonce advanced — capture the CURRENT one for the reply.
  let nonce = e.sync_nonce_for_test();

  // A LEGITIMATE same-config (epoch 0, empty membership) SyncCheckpoint at op 4 arrives. With the bit
  // cleared AND the target reachable it must PROCEED + INSTALL — not be rejected for lacking a successor
  // (the require_cross_epoch carve-out) NOR dropped as below-target (the freshness gate).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0, // same config_id — no successor membership (an ordinary same-epoch sync)
      ReplicaId::new(0),
      nonce,
      env.clone(),
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drive the durable re-persist → install

  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the ordinary same-epoch sync INSTALLED (the high-target stale hint no longer poisons it)"
  );
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.status(), Status::Normal);
  assert!(
    e.sync_target_for_test().is_none(),
    "the sync completed and cleared (no indefinitely-armed cross-epoch sync left behind)"
  );

  // GUARD: a GENUINE crossing is NOT stranded — the cross-epoch trigger RE-ARMS afresh. After the
  // downgrade+install above, a real higher-epoch heartbeat re-establishes the crossing requirement.
  let (mut e2, mut wal2, mut sb2, _env2, _id2) = sync_apply_harness(4);
  let mut blocks2 = crate::block_store::MemBlockStore::new();
  e2.arm_cross_epoch_sync_for_test(1000);
  e2.handle_message(
    now,
    &mut wal2,
    &mut sb2,
    &mut blocks2,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    !e2.sync_requires_cross_epoch_for_test(),
    "the stale hint is downgraded by the same-epoch trigger"
  );
  // A STRICTLY-HIGHER-epoch heartbeat (the genuine crossing signal) re-arms the crossing requirement.
  e2.handle_message(
    now,
    &mut wal2,
    &mut sb2,
    &mut blocks2,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(7),
      OpNumber::with(7),
      crate::Epoch::new(1), // a real higher epoch
      0,
    )),
  );
  assert!(
    e2.sync_requires_cross_epoch_for_test(),
    "a genuine higher-epoch heartbeat RE-ARMS require_cross_epoch — a real crossing is never stranded by the downgrade"
  );
}

#[test]
fn a_stale_cross_epoch_hint_is_cancelled_by_same_epoch_evidence_at_or_below_the_head() {
  // CLASS 2, the `<= op` GAP. A same-epoch checkpoint AT/BELOW the head takes `maybe_request_sync`'s EARLY
  // return (`incoming <= self.op`), so the per-trigger downgrade never ran — a stale `require_cross_epoch`
  // sync PERSISTED, blocking primary op-mint + backup checkpoint reports and rejecting every same-config
  // reply forever. The ingress cancel fires on ANY same-epoch admissible message regardless of op, so a
  // same-epoch Commit at/below the head CANCELS the stale crossing outright (we are already caught up
  // in-epoch — no re-arm, since `maybe_request_sync` early-returns).
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.arm_cross_epoch_sync_for_test(1000);
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "setup: the stale hint armed a crossing-required sync"
  );

  // A same-epoch Commit advertising a checkpoint AT the head (op 0 == our head) — the `<= op` early-return
  // path the per-trigger downgrade skipped. The ingress cancel still fires on this same-epoch message.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    e.sync_target_for_test().is_none(),
    "the ingress CANCELLED the stale crossing on same-epoch evidence at/below the head (no longer poisoned)"
  );
}

#[test]
fn a_higher_epoch_trigger_upgrades_an_ordinary_sync_to_crossing_even_when_the_target_does_not_increase()
 {
  // RE-ARM completeness — the inverse of the cancel: a genuine higher-epoch trigger must PIN the
  // crossing requirement on an outstanding sync EVEN WHEN the hinted checkpoint does not exceed the current
  // target. An ordinary same-epoch sync already at/above the hint would otherwise stay ordinary, and a
  // legitimate below-target successor checkpoint would be rejected by the ordinary `< target` freshness
  // gate (or an ordinary reply would complete WITHOUT crossing) — stranding the node at the old epoch until
  // another higher-epoch trigger happens to arrive. `maybe_request_cross_epoch_catchup` now upgrades any
  // outstanding sync to forced + require_cross_epoch regardless of target monotonicity.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // An ORDINARY same-epoch sync already armed at a HIGH target (10), ABOVE the real crossing checkpoint.
  e.maybe_request_sync(now, OpNumber::with(10));
  assert!(
    !e.sync_requires_cross_epoch_for_test() && e.sync_target_for_test() == Some(10),
    "setup: an ordinary (non-crossing) sync at target 10"
  );
  let nonce_before = e.sync_nonce_for_test();

  // A genuine higher-epoch hint whose checkpoint (4) is BELOW the ordinary target (10).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::EpochAhead(crate::EpochAhead::new(
      crate::Epoch::new(1),
      OpNumber::with(4),
    )),
  );

  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "the higher-epoch trigger UPGRADED the ordinary sync to crossing-required (even though hint 4 < target 10)"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(10),
    "the target kept the HIGHER of the two (no regression to the below-target hint)"
  );
  assert_eq!(
    e.sync_nonce_for_test(),
    nonce_before,
    "the upgrade preserved the nonce (the in-flight handshake is kept, not re-armed)"
  );
}

#[test]
fn a_staged_same_epoch_install_re_arms_the_crossing_from_the_intent_after_it_completes() {
  // The PERSISTENT-INTENT lifecycle. The crossing requirement on the in-flight `SyncState` does NOT
  // survive the sync's install step: if an ORDINARY same-epoch sync has already STAGED its install
  // (`pending_install` set, `successor` None) and a higher-epoch trigger then arrives before the
  // `SyncRepersist` root completes, the trigger rewrites the `SyncState` (upgrading it to crossing) but
  // the staged SAME-epoch install still completes — `on_sb_done` clears `self.sync` — so the node would
  // settle at the OLD epoch with NO crossing armed, pinning the crossing only if ANOTHER higher-epoch
  // trigger later happened to arrive. The persistent `cross_epoch_intent` closes this: the trigger SETS
  // it, and `on_sb_done` RE-ARMS a crossing sync from it the instant a non-crossing install completes.
  //
  // MUTATION CHECK: remove the `on_sb_done` re-arm (step 3) and the final assertion FAILS — the node
  // settles old-epoch with `sync == None`, exactly the defect this intent closes.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // (1) An ORDINARY same-epoch FORCED sync to the donor checkpoint (op 4), and the matching same-epoch
  // (epoch 0, empty-membership) reply → `apply_sync` STAGES the install with `successor` None.
  e.arm_forced_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(), // empty membership — a SAME-config (non-crossing) install
    )),
  );
  assert!(
    e.pending_install.is_some(),
    "setup: the ordinary same-epoch sync STAGED its install (pending_install set)"
  );
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "setup: the staged sync is ordinary (no crossing requirement yet)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    None,
    "setup: no crossing is owed before any higher-epoch trigger"
  );

  // (2) A BELOW-target higher-epoch `EpochAhead` (epoch 1, checkpoint 1 < the ordinary target 4) arrives
  // from an active member WHILE the install is staged and the `SyncRepersist` root is still in flight. It
  // PINS the persistent intent (and incidentally upgrades the soon-to-be-cleared `SyncState`).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::EpochAhead(crate::EpochAhead::new(
      crate::Epoch::new(1),
      OpNumber::with(1),
    )),
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(1),
    "the higher-epoch trigger pinned the persistent crossing intent to the hinted checkpoint (1)"
  );

  // (3) Drive the staged `SyncRepersist` to durability → `install_sync` runs the SAME-epoch (successor
  // None) install, `on_sb_done` clears `self.sync`. WITHOUT the intent the node would settle old-epoch
  // with no crossing armed; the `on_sb_done` re-arm fires from the still-owed intent instead.
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the staged same-epoch sync completed (its re-persist root landed)"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "the completed install did NOT cross — the node is still at the OLD epoch (same-config install)"
  );

  // THE GOAL: the node did NOT settle old-epoch with no crossing armed. The non-crossing install that
  // completed while a crossing was owed immediately RE-PINNED the crossing from the intent.
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "after the non-crossing install, a CROSSING sync (require_cross_epoch) is re-armed from the intent"
  );
  assert!(
    e.sync_is_forced_for_test(),
    "the re-armed crossing sync is forced (the relaxed apply_sync invariant the crossing needs)"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(1),
    "the re-armed crossing sync targets the intent's checkpoint (1)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(1),
    "the intent is STILL owed (no real cross yet) — it is cleared only when a successor actually installs"
  );
}

#[test]
fn a_successful_cross_clears_the_intent_so_on_sb_done_never_re_arms_forever() {
  // The CLEAR-ON-CROSS half (step 4) of the persistent-intent lifecycle. A crossing install MUST clear
  // `cross_epoch_intent`, else `on_sb_done`'s re-arm would re-pin a crossing sync FOREVER after the node
  // has already crossed. Here a Normal speculative crossing armed from a hint installs a genuine E+1
  // successor; afterwards the intent is None and no crossing sync is left armed.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let m = 4u64; // the E+1 crossing checkpoint
  let successor_e1 = genesis(3)
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid (E+1)");

  // Arm the speculative crossing AND pin the persistent intent, as the higher-epoch trigger does.
  e.arm_cross_epoch_sync_for_test(m);
  e.set_cross_epoch_intent_for_test(m);
  let nonce = e.sync_nonce_for_test();

  // A verified E+1 successor-membership SyncCheckpoint at op M → `apply_sync` stages a CROSSING install.
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(m),
    crate::block_address(&CountSm::default().snapshot()),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  // The envelope names the SM leaf by content address; seed it so the crossing reaches `apply_sync` and
  // STAGES the install locally (the `pending_install` assertion below) instead of arming a block-fetch.
  blocks.write_verified(CountSm::default().snapshot());
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor_e1, genesis(3).config_id())
      .encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(m),
      cross_id,
      successor_e1.epoch(),
      successor_e1.config_id(),
      ReplicaId::new(0),
      nonce,
      cross_env,
      membership_body,
    )),
  );
  assert!(e.pending_install.is_some(), "the crossing install staged");
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.membership, successor_e1,
    "the node CROSSED into E+1 (the successor membership installed)"
  );
  // THE GOAL of the clear: the intent is dropped on a real cross, so the `on_sb_done` re-arm sees None
  // and does NOT re-arm a crossing sync — no forever-re-arm after the node has already crossed.
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    None,
    "a successful cross CLEARED the persistent intent (otherwise on_sb_done would re-arm forever)"
  );
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "no crossing sync is re-armed after the node crossed (the intent was cleared, so on_sb_done saw None)"
  );
}

#[test]
fn the_trigger_level_downgrade_clears_the_persistent_intent_so_on_sb_done_never_re_poisons() {
  // The trigger-level stale downgrade (`downgrade_stale_cross_epoch_sync`) is a SAME-EPOCH evidence
  // path DISTINCT from the ingress cancel. The REAL production trigger sets BOTH the transient
  // `require_cross_epoch` bit AND the persistent `cross_epoch_intent`; this downgrade must clear the intent
  // too, else after the downgraded now-ordinary sync installs, `on_sb_done` would re-arm a crossing from
  // the still-set intent — re-introducing the stale-hint poison the intent refactor exists to remove.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // A REAL higher-epoch trigger sets the intent AND arms a crossing sync (NOT the `_for_test` helper).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::EpochAhead(crate::EpochAhead::new(
      crate::Epoch::new(1),
      OpNumber::with(10),
    )),
  );
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "setup: the higher-epoch trigger armed a crossing-required sync"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(10),
    "setup: the trigger also SET the persistent intent (the production path, not the test helper)"
  );

  // Exercise the TRIGGER-LEVEL downgrade (a same-epoch sync trigger learns a reachable same-epoch
  // checkpoint at 4 > head 0) — NOT the ingress cancel.
  e.maybe_request_sync(now, OpNumber::with(4));
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "the downgrade cleared the crossing bit (the sync is now ordinary, re-targeted to the reachable 4)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    None,
    "the downgrade ALSO cleared the persistent intent — no leak for on_sb_done to re-poison from"
  );
}

#[test]
fn a_same_epoch_message_clears_an_orphaned_cross_epoch_intent() {
  // The persistent intent is DECOUPLED from the sync, so it can be ORPHANED — a path like
  // `reset_for_view_transition` clears `sync` (and `block_fetch`/`pending_install`) without clearing the
  // intent. If the stale-evidence clear paths keyed only off `self.sync.is_some()`, no later same-epoch
  // traffic could clear the orphan, and a subsequent ordinary sync's `on_sb_done` would re-pin a bogus
  // crossing from it — re-introducing the stale-hint poison. The ingress cancel now clears an orphaned
  // intent on same-epoch evidence even when NO sync remains.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // An ORPHANED intent: the persistent crossing goal survives with NO outstanding sync (the post-reset
  // state a view transition leaves behind for a bare stale hint).
  e.set_cross_epoch_intent_for_test(10);
  assert!(
    e.cross_epoch_intent_for_test() == Some(10) && e.sync_target_for_test().is_none(),
    "setup: an orphaned intent — the crossing goal survives with the sync cleared"
  );

  // A same-epoch admissible Commit: the node is operating at its current epoch, so the higher-epoch hint
  // that set the intent was stale.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );

  assert_eq!(
    e.cross_epoch_intent_for_test(),
    None,
    "the orphaned intent is CLEARED by same-epoch evidence with NO sync required — on_sb_done can no longer re-poison from it"
  );
}

#[test]
fn an_ordinary_staged_install_does_not_shield_a_stale_intent_from_a_same_epoch_clear() {
  // The intent clear is DECOUPLED from the sync teardown. A STAGED install (`pending_install`, here a
  // same-config one with `successor: None`) is COMMITTED, so its sync is NOT torn down on same-epoch
  // evidence — but the stale `cross_epoch_intent` for a FUTURE crossing MUST still be cleared, else the
  // staged install completes with it intact and `on_sb_done` re-arms a bogus crossing from it (the poison
  // the intent lifecycle exists to prevent). The intent-clear scope (`stale_crossing_intent_clearable`)
  // therefore admits a staged install, while the narrower sync-teardown gate
  // (`crossing_is_pre_answer_speculative`) excludes it.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // (1) Stage an ORDINARY same-config install (successor None): a forced same-epoch sync + the matching
  // same-epoch (epoch 0, empty-membership) SyncCheckpoint → `apply_sync` stages `pending_install` with its
  // paired SyncRepersist `pending_checkpoint`, root NOT yet durable. (Drive it as the staged-install tests
  // do, so the `pending_install => SyncRepersist-checkpoint` coupling `assert_invariants` enforces holds.)
  e.arm_forced_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(), // empty membership — an ORDINARY same-config install (successor None)
    )),
  );
  assert!(
    e.pending_install.is_some(),
    "setup: the ordinary same-config sync STAGED its install (root not yet durable, in flight)"
  );

  // (2) A STALE persistent crossing intent — a higher-epoch hint pinned it while the ordinary install is
  // mid-flight (the orphaned-intent shape the lifecycle must keep clearable).
  e.set_cross_epoch_intent_for_test(7);
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(7),
    "setup: a stale crossing intent is pinned WHILE an ordinary (successor None) install is staged"
  );

  // (3) Same-epoch operating evidence (a Commit at OUR epoch, AT the head so it never re-arms a sync)
  // arrives BEFORE the root lands. The ingress cancel runs; the ordinary (successor None) staged install
  // must NOT shield the stale intent — `crossing_is_pre_answer_speculative` is true, so it is cleared.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );

  assert_eq!(
    e.cross_epoch_intent_for_test(),
    None,
    "the ORDINARY (successor None) staged install did NOT shield the stale intent — same-epoch evidence cleared it"
  );
}

#[test]
fn a_same_config_live_fetch_does_not_shield_a_stale_cross_epoch_intent_from_same_epoch_authority() {
  // A `BlockFetch` is armed BEFORE `apply_sync` verifies the carried membership, and the cross-epoch solicit
  // admits BELOW-target replies onto the fetch path — so a SAME-CONFIG / EMPTY-membership reply (a donor in
  // the force-checkpoint window serving its `M < N` checkpoint) arms a LIVE fetch that is NOT a crossing.
  // The bare `block_fetch.is_some()` would wrongly read that as "a donor has begun answering a crossing" and
  // refuse to clear a stale `cross_epoch_intent` — a misrouted higher-epoch hint then stays shielded by
  // non-crossing replies forever (and on a primary `sync.is_some()` also wedges new-op admission). The
  // crossing-answer predicates read the fetch's recorded `crossing_answered` bit instead: a same-config
  // fetch is NOT a crossing answer, so same-epoch authority STILL clears the stale intent.
  let (_donor_e, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");

  // Laggard store: SM DAG present (drains locally), session DAG absent — so the same-config checkpoint arms
  // a LIVE block-fetch (active address = `sessions_root`) rather than installing or staging.
  let mut donor_blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  {
    let mut stack = std::vec![sm_root];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(addr) = stack.pop() {
      if !seen.insert(addr) {
        continue;
      }
      let block = donor_blocks
        .read_block(addr)
        .expect("SM block present in donor store");
      for child in CountSm::block_references(&block) {
        stack.push(child);
      }
      blocks.write_block(addr, block);
    }
  }
  assert!(
    !blocks.has_block(sessions_root),
    "session DAG absent → a live fetch arms"
  );

  let mut e = sync_backup();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let now = Instant::ZERO;

  // Arm a CROSSING sync, then deliver a SAME-CONFIG (epoch 0, empty-membership) checkpoint at op 4: the
  // cross-epoch solicit admits it onto the fetch path, arming a live fetch that does NOT present a crossing.
  e.arm_cross_epoch_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
      Bytes::new(), // SAME-CONFIG / empty membership — NOT a crossing presentation
    )),
  );
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "setup: a live block-fetch is pinned (the same-config reply armed it, did not stage/install)"
  );
  assert_eq!(
    e.block_fetch_crossing_answered_for_test(),
    Some(false),
    "the live fetch is draining a SAME-CONFIG reply — it does NOT present a crossing"
  );

  // A STALE persistent crossing intent (a misrouted higher-epoch hint pinned it) — and NO staged install,
  // so only the live non-crossing fetch could (wrongly) shield it.
  e.set_cross_epoch_intent_for_test(7);
  assert!(
    e.cross_epoch_intent_for_test() == Some(7) && e.pending_install.is_none(),
    "setup: a stale crossing intent is pinned with a live NON-crossing fetch and no staged install"
  );

  // Same-epoch operating evidence (a Commit at OUR epoch, AT the head so it never re-arms a sync): the
  // same-config live fetch must NOT shield the stale intent, and the bare speculative crossing sync is
  // dropped (it would install with successor None and exit still at the old epoch).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );

  assert_eq!(
    e.cross_epoch_intent_for_test(),
    None,
    "the same-config live fetch did NOT shield the stale intent — same-epoch authority cleared it"
  );
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "the bare speculative crossing sync (a non-crossing fetch) was dropped on the same-epoch evidence"
  );
}

#[test]
fn after_an_ordinary_install_completes_on_sb_done_does_not_re_arm_a_crossing() {
  // The completion half of the successor-awareness: once the stale intent is cleared (the predicate let the
  // ordinary install NOT shield it), the ordinary install completing must NOT re-arm a crossing —
  // `on_sb_done` sees `cross_epoch_intent == None` and re-pins nothing. (Contrast
  // `a_staged_same_epoch_install_re_arms_the_crossing_from_the_intent_after_it_completes`, where the intent
  // SURVIVES and `on_sb_done` legitimately re-arms.) This closes the loop: a stale intent shielded by a
  // mis-scoped predicate would re-poison HERE; a correctly-cleared one cannot.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // Reach Test 1's cleared-intent state: stage an ordinary (successor None) install, pin a stale intent,
  // then clear it with a same-epoch head Commit.
  e.arm_forced_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
    )),
  );
  e.set_cross_epoch_intent_for_test(7);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    None,
    "precondition: the stale intent was cleared by the same-epoch evidence (Test 1's end-state)"
  );

  // Drive the staged SyncRepersist root to durability → `install_sync` runs the same-config install and
  // `on_sb_done` clears `self.sync`. With the intent already None, the re-arm sees None and pins NOTHING.
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the ordinary same-config install COMPLETED (its re-persist root landed)"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the install advanced the durable checkpoint (the same-config sync truly installed)"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "the install did NOT cross — still the OLD epoch (a same-config install)"
  );

  // THE GOAL: completion re-armed NO crossing. `on_sb_done` saw a None intent, so it did not re-pin a
  // bogus crossing — neither a crossing-required sync nor a re-set intent.
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "no crossing sync is re-armed after the ordinary install completes (on_sb_done saw a cleared intent)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    None,
    "the intent stays None after completion (on_sb_done did not re-pin a bogus crossing)"
  );
}

#[test]
fn a_staged_install_upgraded_to_crossing_is_not_orphaned_by_same_epoch_authority() {
  // A STAGED install is COMMITTED to installing — same-epoch authority must NOT tear down its sync. The
  // lifecycle split: an ORDINARY same-config sync drains its block-fetch and STAGES `pending_install`
  // (`successor: None`, `transfer` now None); a higher-epoch hint upgrades the SAME live sync to
  // `require_cross_epoch` IN PLACE; then a same-epoch authority message (a Commit at OUR epoch) arrives
  // BEFORE the `SyncRepersist` root lands. The ingress cancel reads the crossing as outstanding
  // (`crossing_sync`), but the staged install means the sync is committed: it must keep `sync` +
  // `pending_install` + `pending_checkpoint` paired and only clear the (stale) `cross_epoch_intent`. If the
  // cancel instead cleared `sync`/`transfer` (gating only on `transfer.is_none()` for "answered"), the
  // staged `pending_install`/`pending_checkpoint` would be ORPHANED — the debug `pending_install => sync`
  // invariant trips, and the staged root completion runs a state-sync install whose handshake was torn down.
  //
  // MUTATION CHECK: gate the cancel teardown on `transfer.is_none()` alone (drop the
  // `crossing_is_pre_answer_speculative` staged-install exclusion) and `handle_message` panics on the
  // orphaned `pending_install` at its exit-time `assert_invariants`.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // (1) An ORDINARY same-config FORCED sync to op 4, and its matching same-epoch (empty-membership) reply →
  // `apply_sync` STAGES the install (`successor: None`) and clears the transfer; the root is NOT yet durable.
  e.arm_forced_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(), // empty membership — an ORDINARY same-config install (successor None)
    )),
  );
  assert!(
    e.pending_install.is_some(),
    "setup: the ordinary same-config sync STAGED its install (root not yet durable)"
  );
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "setup: the staged sync is ordinary (no crossing requirement yet)"
  );

  // (2) A higher-epoch `EpochAhead` UPGRADES that same live sync to `require_cross_epoch` IN PLACE (and pins
  // the persistent intent). The staged `pending_install` is left intact — it is committed.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::EpochAhead(crate::EpochAhead::new(
      crate::Epoch::new(1),
      OpNumber::with(1),
    )),
  );
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "setup: the higher-epoch hint upgraded the live sync to a crossing IN PLACE"
  );
  assert!(
    e.pending_install.is_some(),
    "setup: the upgrade kept the committed staged install (it does not drop pending_install)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(1),
    "setup: the higher-epoch hint pinned the persistent crossing intent"
  );

  // (3) Same-epoch authority (a Commit at OUR epoch, AT the head so it re-arms nothing) arrives BEFORE the
  // root lands. The ingress cancel runs. The staged install must NOT be orphaned: `handle_message`'s
  // exit-time `assert_invariants` would panic on `pending_install` without `sync` — this is the RED.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    e.pending_install.is_some(),
    "the staged install is NOT orphaned — pending_install survived the same-epoch cancel"
  );
  assert!(
    e.sync_target_for_test().is_some(),
    "the committed staged install keeps its sync paired (the pending_install => sync invariant holds)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    None,
    "the stale crossing intent WAS cleared (same-epoch evidence proved the hint stale) — only the intent, \
     not the committed install"
  );

  // (4) The staged root lands → the same-config install completes and installs; no panic, no orphan.
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the staged install COMPLETED (its re-persist root landed and installed)"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the install advanced the durable checkpoint (the staged install truly installed)"
  );
  assert!(
    e.pending_install.is_none() && e.sync_target_for_test().is_none(),
    "the lifecycle completed cleanly — the staged install consumed, the sync torn down together"
  );
  // The intent was cleared by same-epoch evidence in (3), so the completing install re-arms NO crossing.
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "no crossing is re-armed: the stale intent was cleared, so on_sb_done re-pinned nothing"
  );
}

#[test]
fn a_bare_speculative_crossing_with_no_staged_install_is_still_downgradable() {
  // The complement: a genuinely PRE-ANSWER crossing (no transfer, no staged install) MUST still be torn
  // down by stale same-epoch authority — the fix must not OVER-suppress. The ingress cancel drops the bare
  // crossing sync AND clears the intent, exactly as before the staged-install carve-out.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // A REAL higher-epoch trigger arms a bare crossing-required sync + the persistent intent (no SyncCheckpoint
  // answered it yet → no transfer, no staged install).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::EpochAhead(crate::EpochAhead::new(
      crate::Epoch::new(1),
      OpNumber::with(10),
    )),
  );
  assert!(
    e.sync_requires_cross_epoch_for_test()
      && e.pending_install.is_none()
      && e.cross_epoch_intent_for_test() == Some(10),
    "setup: a BARE pre-answer crossing — a crossing sync + intent, NO transfer, NO staged install"
  );

  // Same-epoch authority (a Commit at OUR epoch) proves the hint stale → the bare speculative crossing is
  // torn down: the sync is cancelled AND the intent cleared.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    e.sync_target_for_test().is_none(),
    "the bare speculative crossing sync WAS cancelled by same-epoch evidence (no over-suppression)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    None,
    "the bare speculative crossing's intent WAS cleared by same-epoch evidence"
  );
}

#[test]
fn a_verified_staged_crossing_keeps_its_intent_against_stale_same_epoch_authority() {
  // A VERIFIED, COMMITTED crossing must NOT be stranded at the old epoch by delayed same-epoch traffic. The
  // shape: `apply_sync` of a CROSS-EPOCH `SyncCheckpoint` reconstructs + verifies the successor membership,
  // stages a CROSSING install (`pending_install.successor.is_some()`, `transfer` drained), and keeps `sync`
  // armed until the re-persist root lands. Same-epoch traffic is NOT evidence such a crossing is stale, so it
  // must clear NEITHER the sync (already covered) NOR the PERSISTENT `cross_epoch_intent` — because a
  // subsequent view transition (`reset_for_view_transition`) cancels the pre-root install (drops
  // `pending_install`/`sync`), and if the intent were already cleared the laggard would have NO record it
  // intends to cross: stranded at the OLD epoch until some unrelated higher-epoch hint happens to re-arm it.
  //
  // The successor-shield in `stale_crossing_intent_clearable` keeps the intent against a verified staged
  // crossing, while a SAME-CONFIG staged install's (irrelevant) intent stays clearable — so the intent-clear
  // scope must admit the ordinary staged install yet shield the verified crossing one, not blanket every
  // staged install.
  //
  // The laggard is replica 1 of 3 with a HUGE checkpoint interval (so its own band never auto-checkpoints
  // and races the sync persist), and `StepSb` so the re-persist ROOT is withheld across (3) and (4).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let mut wal = TestWal::default();
  let mut sb = StepSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let m = 4u64; // the E+1 crossing checkpoint op
  let successor_e1 = genesis(3)
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid (E+1)");

  // (1) Arm a speculative crossing sync AND pin the persistent intent, as the higher-epoch trigger does.
  e.arm_cross_epoch_sync_for_test(m);
  e.set_cross_epoch_intent_for_test(m);
  let nonce = e.sync_nonce_for_test();

  // A verified E+1 successor-membership `SyncCheckpoint` at op M → `apply_sync` STAGES a CROSSING install.
  // Seed the SM leaf so the crossing's block-fetch frontier drains locally (no `RequestBlock` round trip)
  // and reaches `apply_sync`'s staging instead of arming a fetch.
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(m),
    crate::block_address(&CountSm::default().snapshot()),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  blocks.write_verified(CountSm::default().snapshot());
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor_e1, genesis(3).config_id())
      .encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(m),
      cross_id,
      successor_e1.epoch(),
      successor_e1.config_id(),
      ReplicaId::new(0),
      nonce,
      cross_env,
      membership_body,
    )),
  );
  assert!(
    e.pending_install.is_some(),
    "setup: the cross-epoch reply STAGED a crossing install (root not yet durable, transfer drained)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(m),
    "setup: the persistent crossing intent is pinned WHILE the verified crossing install is staged"
  );
  // Do NOT drive storage to completion — the install stays staged (the re-persist root is withheld), and
  // `membership` is still the OLD epoch (the crossing has not installed yet).
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "setup: the staged crossing has NOT installed — still the OLD epoch"
  );

  // (2)+(3) Delayed SAME-EPOCH authority (a Commit at OUR old epoch, AT the head so it never re-arms a sync)
  // arrives BEFORE the root lands. The ingress cancel runs, but the staged install IS a verified crossing —
  // same-epoch traffic is not evidence it is stale, so the persistent intent must SURVIVE.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(m),
    "the verified staged crossing SHIELDED its intent — same-epoch authority did NOT clear it (RED before the fix)"
  );
  assert!(
    e.pending_install.is_some() && e.sync_target_for_test().is_some(),
    "the committed crossing install + its paired sync survive the same-epoch cancel"
  );

  // (4) A VIEW CHANGE fires in this window and CANCELS the pre-root install: an SVC quorum drives the laggard
  // into ViewChange(1), and `reset_for_view_transition` drops `pending_install`/`sync` together. The
  // PERSISTENT intent (deliberately NOT cleared by that reset) is the ONLY surviving record of the crossing.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks); // primary_idle → SVC(view 1), own bit
  e.handle_message(
    later,
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
  assert_eq!(e.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  assert!(
    e.pending_install.is_none() && e.sync_target_for_test().is_none(),
    "the view transition CANCELLED the pre-root install (pending_install + sync dropped together)"
  );

  // THE GOAL: the laggard is NOT stranded at the old epoch. With the install cancelled, the persistent
  // intent is the sole surviving record that a crossing is owed — it must SURVIVE so the next higher-epoch
  // trigger / `on_sb_done` re-arms the crossing rather than the laggard idling at E forever.
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(m),
    "the crossing intent SURVIVED the cancel — the laggard still intends to cross (NOT stranded at the old epoch)"
  );
}

#[test]
fn a_verified_crossing_retained_across_a_flush_fault_keeps_its_intent_against_stale_same_epoch_authority()
 {
  // The flush-fault analogue of the staged-crossing intent shield: a VERIFIED crossing whose install hits a
  // block-store FLUSH FAULT is RETAINED-but-not-staged (held in `pending_install` with `successor.is_some()`,
  // `block_fetch` already drained), NOT yet durable. That retained crossing must shield `cross_epoch_intent`
  // exactly like a fully-staged one: same-epoch authority is not evidence it is stale, and a subsequent view
  // transition drops `pending_install`, leaving the persistent intent as the SOLE record the laggard intends
  // to cross. Were the retained crossing not shielded, delayed same-epoch authority would clear the intent
  // and the view transition would strand the laggard at the OLD epoch.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let m = 4u64; // the E+1 crossing checkpoint op
  let successor_e1 = genesis(3)
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid (E+1)");

  // (1) Arm a speculative crossing sync AND pin the persistent intent, as the higher-epoch trigger does.
  e.arm_cross_epoch_sync_for_test(m);
  e.set_cross_epoch_intent_for_test(m);
  let nonce = e.sync_nonce_for_test();

  // A verified E+1 successor-membership `SyncCheckpoint` at op M, with the SM leaf seeded so the crossing's
  // block-fetch frontier drains LOCALLY and reaches `apply_sync`. A SCRIPTED FLUSH FAULT makes `apply_sync`
  // RETAIN the crossing as an owed-but-not-staged `pending_install` instead of staging it durably.
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(m),
    crate::block_address(&CountSm::default().snapshot()),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  blocks.write_verified(CountSm::default().snapshot());
  blocks.script_flush_fault(1); // the install's durability barrier faults — the crossing is RETAINED
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor_e1, genesis(3).config_id())
      .encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(m),
      cross_id,
      successor_e1.epoch(),
      successor_e1.config_id(),
      ReplicaId::new(0),
      nonce,
      cross_env,
      membership_body,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    e.install_flush_retry_owed(),
    "setup: the flush fault RETAINED the verified crossing (owed pending_install, not yet staged)"
  );
  assert!(
    e.pending_install
      .as_ref()
      .is_some_and(|pi| pi.successor.is_some()),
    "setup: the retained install carries the verified successor membership (it IS a crossing)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(m),
    "setup: the persistent crossing intent is pinned WHILE the retained crossing is owed"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "setup: the retained crossing has NOT installed — still the OLD epoch"
  );

  // (2) Delayed SAME-EPOCH authority (a Commit at OUR old epoch, AT the head so it never re-arms a sync)
  // arrives while the crossing is owed. The retained crossing shields the intent — same-epoch traffic is not
  // evidence it is stale — so `cross_epoch_intent` must SURVIVE.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(m),
    "the RETAINED crossing shielded its intent — same-epoch authority did NOT clear it"
  );
  assert!(
    e.install_flush_retry_owed() && e.sync_target_for_test().is_some(),
    "the owed crossing install + its paired sync survive the same-epoch cancel"
  );

  // (3) A VIEW CHANGE fires and CANCELS the owed install: an SVC quorum drives the laggard into ViewChange(1),
  // and `reset_for_view_transition` drops `pending_install`/`sync` together. The PERSISTENT intent (NOT cleared
  // by that reset) is the ONLY surviving record of the crossing.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks); // primary_idle → SVC(view 1), own bit
  e.handle_message(
    later,
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
  assert_eq!(e.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  assert!(
    e.pending_install.is_none() && e.sync_target_for_test().is_none(),
    "the view transition CANCELLED the owed crossing install (pending_install + sync dropped together)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(m),
    "the crossing intent SURVIVED the cancel — the laggard still intends to cross (NOT stranded at the old epoch)"
  );
}

#[test]
fn a_retained_crossing_install_survives_a_stale_reply_rejected_by_apply_sync() {
  // ORDERING: a verified crossing install RETAINED across a flush fault is the local retry source, a LIVE GC
  // root, AND the shield that holds `cross_epoch_intent` against same-epoch authority. It must survive a fresh
  // reply that ENTERS `begin_block_sync` but is then REJECTED by `apply_sync`. Under `require_cross_epoch`,
  // `begin_block_sync` admits a stale SAME-CONFIG / EMPTY-membership reply (the crossing requirement is only
  // checked later in `apply_sync`), so `begin_block_sync` must NOT clear the owed `pending_install` on entry:
  // were it cleared there, a stale reply that `apply_sync` rejects would erase the verified crossing BEFORE any
  // replacement was staged — `retry_install_flush` would have nothing to re-flush, the old DAG would lose its
  // GC mark, and delayed same-epoch authority could clear the intent, reopening the crossing strand. The owed
  // install is dropped ONLY when `apply_sync` STAGES a replacement (atomic) or a teardown cancels it.
  //
  // MUTATION CHECK: re-add `self.pending_install = None;` on `begin_block_sync` entry and the stale reply
  // erases the crossing — the post-stale assertions (owed install present, GC roots survive) fail.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let m = 4u64; // the E+1 crossing checkpoint op
  let successor_e1 = genesis(3)
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid (E+1)");

  // (1) Arm a speculative crossing sync + pin the persistent intent, then deliver a VERIFIED E+1
  // successor-membership reply whose SM leaf is seeded so its block-fetch drains LOCALLY and reaches
  // `apply_sync`. A SCRIPTED FLUSH FAULT makes `apply_sync` RETAIN the crossing as an owed (not staged)
  // `pending_install` (no in-flight `pending_checkpoint`).
  e.arm_cross_epoch_sync_for_test(m);
  e.set_cross_epoch_intent_for_test(m);
  let nonce = e.sync_nonce_for_test();
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(m),
    crate::block_address(&CountSm::default().snapshot()),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  blocks.write_verified(CountSm::default().snapshot());
  blocks.script_flush_fault(1); // the crossing's durability barrier faults — it is RETAINED
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor_e1, genesis(3).config_id())
      .encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(m),
      cross_id,
      successor_e1.epoch(),
      successor_e1.config_id(),
      ReplicaId::new(0),
      nonce,
      cross_env,
      membership_body,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    e.install_flush_retry_owed()
      && e
        .pending_install
        .as_ref()
        .is_some_and(|pi| pi.successor.is_some()),
    "setup: the flush fault RETAINED the VERIFIED crossing (owed pending_install carrying a successor)"
  );
  let (crossing_sm_root, crossing_sessions_root) = e
    .pending_install
    .as_ref()
    .map(|pi| (pi.sm_root, pi.sessions_root))
    .expect("the owed crossing install names its two DAG roots");

  // (2) A STALE SAME-CONFIG reply (a donor in the force-checkpoint window serving its `M' < N` checkpoint:
  // empty membership, OUR config_id) at a higher op so it clears the monotone gate and ENTERS
  // `begin_block_sync`. Its SM leaf is already local, so its fetch DRAINS IMMEDIATELY and reaches
  // `apply_sync`, where the `require_cross_epoch && successor.is_none()` gate REJECTS it. `begin_block_sync`
  // must have LEFT the owed crossing install intact while admitting this stale reply.
  let stale_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(m + 1),
    crate::block_address(&CountSm::default().snapshot()),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let stale_id = crate::checkpoint_id(&stale_env);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(m + 1),
      stale_id,
      crate::Epoch::new(0), // OUR epoch — a same-config reply
      genesis(3).config_id(),
      ReplicaId::new(0),
      nonce,
      stale_env,
      Bytes::new(), // empty membership — NOT a crossing; apply_sync rejects it
    )),
  );

  // The stale reply was REJECTED by `apply_sync`: the ORIGINAL verified crossing install SURVIVES untouched
  // (still owed, still carrying its successor and its original DAG roots), and its persistent intent SURVIVES.
  assert!(
    e.install_flush_retry_owed()
      && e
        .pending_install
        .as_ref()
        .is_some_and(|pi| pi.successor.is_some()),
    "the ORIGINAL crossing install survived the stale reply (begin_block_sync did NOT clear it on entry)"
  );
  assert_eq!(
    e.pending_install
      .as_ref()
      .map(|pi| (pi.sm_root, pi.sessions_root)),
    Some((crossing_sm_root, crossing_sessions_root)),
    "the surviving install is the SAME crossing (its DAG roots are unchanged — not a stale replacement)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(m),
    "the retained crossing still shields its intent — the rejected stale reply did NOT erase it"
  );

  // The crossing's GC roots SURVIVE a sweep: the owed crossing install is still a LIVE GC ROOT.
  assert!(
    blocks.has_block(crossing_sm_root) && blocks.has_block(crossing_sessions_root),
    "the crossing's DAG roots are present before the GC sweep"
  );
  e.gc_blocks_for_test(&mut blocks);
  assert!(
    blocks.has_block(crossing_sm_root) && blocks.has_block(crossing_sessions_root),
    "the crossing's DAG roots SURVIVED GC — the retained crossing is a live root despite the stale reply"
  );

  // The original crossing still COMPLETES on the local retry (no fresh donor reply): its flush now succeeds,
  // stages the re-persist, and the SAME verified successor membership installs — the laggard crosses to E+1.
  let later = now + core::time::Duration::from_millis(150);
  e.sync_timeouts(later, &mut sb, &mut blocks);
  for _ in 0..6 {
    e.handle_storage(later, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.membership.epoch(),
    successor_e1.epoch(),
    "the RETAINED crossing completed on retry — the laggard crossed into E+1 (NOT stranded at the old epoch)"
  );
  assert_eq!(
    e.membership.config_id(),
    successor_e1.config_id(),
    "the successor membership installed (the same verified crossing, never erased by the stale reply)"
  );
  assert!(
    e.pending_install.is_none(),
    "the crossing install was consumed once its re-persist root landed"
  );
}

#[test]
fn a_recovery_retained_crossing_survives_a_stale_reply_rejected_by_apply_sync() {
  // The recovery peer-fetch mirror of the ordering fix: `begin_recover_block_sync` had the same early-clear of
  // a retained `pending_install`. A Recovering laggard fetching to cross into E+1 (`require_cross_epoch`) whose
  // crossing install hits a flush fault holds it as an owed `pending_install`; a STALE same-config reply that
  // ENTERS `begin_recover_block_sync` and is then REJECTED by `apply_sync` must NOT erase it — the owed install
  // stays a live GC root + the local `recover_timeouts` retry source, so the crossing still completes.
  //
  // MUTATION CHECK: re-add `self.pending_install = None;` on `begin_recover_block_sync` entry and the stale
  // reply erases the crossing; the post-stale install/GC-root assertions fail.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let m = 4u64;
  let successor_e1 = genesis(3)
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid (E+1)");

  // (1) Drive the laggard into a Recovering, cross-epoch (`require_cross_epoch`) peer-fetch directly, then
  // deliver a VERIFIED crossing reply with a SCRIPTED FLUSH FAULT so the recovery `apply_sync` RETAINS the
  // crossing as an owed `pending_install` while STAYING Recovering.
  e.enter_cross_epoch_peer_fetch(now, OpNumber::with(m));
  assert_eq!(
    e.status(),
    Status::Recovering,
    "setup: recovering peer-fetch"
  );
  assert!(e.awaiting_peer_checkpoint_for_test());
  while e.poll_message().is_some() {} // drain the solicited recovery RequestSync
  let nonce = e.sync_nonce_for_test();
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(m),
    crate::block_address(&CountSm::default().snapshot()),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  blocks.write_verified(CountSm::default().snapshot());
  blocks.script_flush_fault(1);
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor_e1, genesis(3).config_id())
      .encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(m),
      cross_id,
      successor_e1.epoch(),
      successor_e1.config_id(),
      ReplicaId::new(0),
      nonce,
      cross_env,
      membership_body,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    e.install_flush_retry_owed()
      && e
        .pending_install
        .as_ref()
        .is_some_and(|pi| pi.successor.is_some()),
    "setup: the recovery flush fault RETAINED the VERIFIED crossing (owed pending_install with a successor)"
  );
  assert!(
    e.status().is_recovering(),
    "setup: still Recovering (root not yet durable)"
  );
  let (crossing_sm_root, crossing_sessions_root) = e
    .pending_install
    .as_ref()
    .map(|pi| (pi.sm_root, pi.sessions_root))
    .expect("the owed crossing install names its two DAG roots");

  // (2) A STALE SAME-CONFIG recovery reply (empty membership, OUR config_id) at a higher op enters
  // `begin_recover_block_sync`, drains immediately (SM leaf local), and is REJECTED by `apply_sync`'s crossing
  // requirement. `begin_recover_block_sync` must have LEFT the owed crossing install intact.
  let stale_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(m + 1),
    crate::block_address(&CountSm::default().snapshot()),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let stale_id = crate::checkpoint_id(&stale_env);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(m + 1),
      stale_id,
      crate::Epoch::new(0),
      genesis(3).config_id(),
      ReplicaId::new(0),
      nonce,
      stale_env,
      Bytes::new(),
    )),
  );
  assert!(
    e.install_flush_retry_owed()
      && e
        .pending_install
        .as_ref()
        .is_some_and(|pi| pi.successor.is_some()),
    "the ORIGINAL crossing survived the stale recovery reply (begin_recover_block_sync did NOT clear it)"
  );
  assert_eq!(
    e.pending_install
      .as_ref()
      .map(|pi| (pi.sm_root, pi.sessions_root)),
    Some((crossing_sm_root, crossing_sessions_root)),
    "the surviving install is the SAME crossing (DAG roots unchanged)"
  );
  e.gc_blocks_for_test(&mut blocks);
  assert!(
    blocks.has_block(crossing_sm_root) && blocks.has_block(crossing_sessions_root),
    "the crossing's DAG roots SURVIVED GC despite the rejected stale recovery reply (a live GC root)"
  );

  // The crossing completes on the LOCAL recovery retry (no fresh donor reply): the flush succeeds, stages the
  // re-persist, and `on_sb_done` installs the successor — the laggard crosses into E+1 and leaves Recovering.
  let later = now + core::time::Duration::from_millis(300);
  for _ in 0..16 {
    e.recover_timeouts(later, &mut wal, &mut sb, &mut blocks);
    e.handle_storage(later, &mut wal, &mut sb, &mut blocks);
    if !e.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    e.membership.epoch(),
    successor_e1.epoch(),
    "the RETAINED recovery crossing completed on the local retry — crossed into E+1"
  );
  assert!(
    !e.status().is_recovering(),
    "recovery completed once the synced crossing root was durable"
  );
}

#[test]
fn a_stale_below_commit_min_reply_does_not_tear_down_a_cross_epoch_forced_sync() {
  // A FORCED `require_cross_epoch` crossing sync must survive a stale same-config `SyncCheckpoint`
  // whose `checkpoint_op` is already below `commit_min` — the "below-commit-min forced-drop" guard
  // in `apply_sync` must NOT clear `sync`+`block_fetch` for a crossing.
  //
  // Setup: a NORMAL backup (replica 1) that has committed ops 1..4 without checkpointing
  // (`commit_min = 4`, `checkpoint_op = 0`). A crossing sync is armed at a HIGH target (9). A
  // donor's checkpoint at op 2 is seeded into the local block store. Delivering the matching
  // SyncCheckpoint (op=2, below commit_min=4) reaches `apply_sync`'s FORCED path where the stale
  // drop fires. WITHOUT the fix (`require_cross_epoch` carve-out), `sync` is cleared, permanently
  // wedging the crossing. WITH the fix, `sync` stays Some, `require_cross_epoch` remains set, and
  // `commit_min` is not rewound — the crossing is alive and the solicit timer will re-fetch.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap(); // huge interval: no checkpoint
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // Drive the backup to commit_min = 4, checkpoint_op = 0 (no checkpoint — interval is huge).
  // The backup has slot 1; primary (slot 0) drives Prepares and commits via PrepareOks.
  for rn in 1..=4u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(0)), // primary's Prepare
      Message::Prepare(Prepare::new(
        View::new(),
        OpNumber::with(rn),
        OpNumber::with(rn - 1),
        OpNumber::new(), // checkpoint_op (no checkpoint taken)
        crate::Epoch::new(0),
        0,
        ClientId::new(7),
        RequestNumber::with(rn),
        bytes::Bytes::from(std::vec![rn as u8]),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // own append → own vote
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(0)), // primary's Commit
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(rn),
        OpNumber::with(rn),
        crate::Epoch::new(0),
        0,
      )),
    );
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "setup: backup commit_min = 4"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "setup: no checkpoint taken (huge interval)"
  );

  // Arm a FORCED, cross-epoch-crossing sync at a high target (9) — what `enter_cross_epoch_peer_fetch`
  // or `maybe_request_cross_epoch_catchup` builds for a laggard that received a higher-epoch hint.
  e.arm_cross_epoch_sync_for_test(9);
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "setup: crossing-required forced sync armed"
  );
  let nonce = e.sync_nonce_for_test();

  // A donor checkpoint at op 2 — BELOW commit_min (4) but ABOVE checkpoint_op (0). Seed its SM
  // leaf so the block-fetch drains immediately and `apply_sync` is reached without a RequestBlock
  // round-trip (same technique as `seed_donor_blocks`).
  let (_, _, dsb) = donor_primary_at_checkpoint(2);
  let (env2, id2) = donor_envelope(&dsb);
  seed_donor_blocks(&mut blocks, 2);

  // Deliver the stale same-config reply at op 2 (below commit_min = 4). The freshness gates admit
  // it (op=2 > checkpoint_op=0; `require_cross_epoch` bypasses the `< target` gate). `apply_sync`
  // sees a forced sync with `checkpoint_op (2) < commit_min (4)` — without the crossing carve-out
  // it would teardown `sync`; WITH the fix it exempts a crossing and returns without clearing.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      id2,
      crate::Epoch::new(0),
      0, // same config_id — a stale same-config donor reply
      ReplicaId::new(0),
      nonce,
      env2,
      Bytes::new(),
    )),
  );

  // THE CRITICAL ASSERTIONS: the crossing survives the stale below-commit-min reply.
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "the crossing is still armed — `apply_sync` did NOT tear it down on the stale below-commit-min reply"
  );
  assert!(
    e.sync_target_for_test().is_some(),
    "sync is Some — not cleared by the stale reply"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "commit_min was NOT rewound (no committed ops lost)"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "checkpoint_op was NOT advanced to the stale below-frontier point"
  );
}

#[test]
fn a_post_root_restore_fault_advances_to_m_owes_reconstruct_and_rejects_an_older_checkpoint() {
  // REDESIGN: the instant M's re-persist root is durable it is the COMMIT POINT — `checkpoint_op`
  // advances to M=4 UNCONDITIONALLY (in lockstep with the durable root), and the SM-content restore
  // follows. When that restore FAULTS on a bit-rotted block, the pointer is ALREADY at M (so nothing
  // is rewound — in-memory `checkpoint_op` equals the durable root), and the node owes an SM-RECONSTRUCT
  // obligation. A stale-but-valid SyncCheckpoint `C` with `checkpoint_op < M` is then rejected by the
  // ORDINARY `< self.checkpoint_op == M` reject — no special floor needed, because in-memory == durable.
  //
  // To isolate that reject (not the `< s.target` guard), the sync is triggered at a LOW target `T = 2`,
  // then the donor serves the HIGHER `M = 4` (which also passes `>= T`); the older `C = 2` satisfies
  // `C >= T` but `C < M = 4 == checkpoint_op`, so the ordinary monotone-checkpoint reject drops it.
  //
  // Two donors: M=4 (the checkpoint that staged) and C=2 (the adversarial older reply).
  let (_donor_m, _dwal_m, dsb_m) = donor_primary_at_checkpoint(4);
  let (env_m, id_m) = donor_envelope(&dsb_m);
  let (_donor_c, _dwal_c, dsb_c) = donor_primary_at_checkpoint(2);
  let (env_c, id_c) = donor_envelope(&dsb_c);
  let sm_root_m = {
    let mut donor_sm = CountSm::default();
    for rn in 1..=4u64 {
      donor_sm.apply(OpNumber::with(rn), &[rn as u8]);
    }
    crate::block_address(&donor_sm.snapshot())
  };
  // The laggard: huge checkpoint interval so no auto-checkpoint races the sync persist.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let mut wal = TestWal::default();
  let mut sb = StepSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  // Seed C's block so a C reply (if not rejected) would drain its block-fetch immediately —
  // this is the adversarial block that would rewind M's durable root without the monotone reject.
  let snap_c = {
    let mut donor_sm = CountSm::default();
    for rn in 1..=2u64 {
      donor_sm.apply(OpNumber::with(rn), &[rn as u8]);
    }
    donor_sm.snapshot()
  };
  blocks.write_verified(snap_c.clone());
  // Seed M's block so the SyncCheckpoint can drain and reach apply_sync.
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // Trigger a sync at the LOW target T=2 (Commit with checkpoint_op=2, commit_min=2).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);

  // Deliver M's SyncCheckpoint (checkpoint_op=4 >= T=2): `apply_sync` stages the durable re-persist.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id_m,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env_m.clone(),
      Bytes::new(),
    )),
  );
  assert!(
    e.pending_install.is_some(),
    "M staged: pending_install is Some while the re-persist is in flight (PRE-ROOT)"
  );

  // CORRUPT M's block AFTER staging. The corrupt bytes do not hash to sm_root_m, so the
  // verify-on-read in install_sync returns an error.
  blocks.write_block(sm_root_m, Bytes::copy_from_slice(b"post-stage-corruption"));

  // Drive the two-write re-persist to completion (step 1: snapshot; step 2: root).
  // `install_sync` advances the frontier to M, then FAILS the SM restore on the corrupt block.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);

  assert_eq!(
    e.state_syncs_applied(),
    0,
    "the restore faulted: the corrupt block blocked it, so the sync is NOT yet complete"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "checkpoint_op ADVANCED to M=4 in lockstep with the durable root (NOT left at 0)"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "commit_min ADVANCED to M=4 (the frontier advance is unconditional)"
  );
  assert!(
    e.sm_reconstruct_owed(),
    "the SM-content reconstruction is owed (the restore faulted, the SM is not yet M)"
  );
  assert!(
    e.pending_install.is_none(),
    "the PRE-ROOT staging was consumed by the root completion — it is now the sm_reconstruct obligation"
  );
  // In-memory == durable: the no-rewind property is now structural, not a floor.
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "M's durable root names checkpoint_op=4 — equal to the in-memory checkpoint_op"
  );

  // THE KEY ASSERTION: deliver older C (checkpoint_op=2). It passes `>= sync.target=2` but is
  // `< checkpoint_op=4` — the ordinary monotone-checkpoint reject drops it. Without the redesign's
  // pointer advance, C would re-stage and overwrite M's durable root (a committed-state REWIND).
  let nonce_after = e.sync_nonce_for_test();
  while e.poll_message().is_some() {} // drain pending messages so none interfere
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      id_c,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce_after,
      env_c.clone(),
      Bytes::new(),
    )),
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "C was REJECTED: checkpoint_op stays 4 — no rewind of M's durable root"
  );
  assert_eq!(
    e.state_syncs_applied(),
    0,
    "C was REJECTED: sync count still 0 — no spurious install from C"
  );
  assert!(
    e.sm_reconstruct_owed(),
    "the obligation still holds M (the rejected C never disturbed it)"
  );

  // Fix M's block and re-deliver M (an `== M` reply): donor-failover re-pulls M's DAG, the retry
  // reconstructs the SM, and the sync completes — with NO pointer regression.
  seed_donor_blocks(&mut blocks, 4);
  let nonce_m2 = e.sync_nonce_for_test();
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id_m,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce_m2,
      env_m.clone(),
      Bytes::new(),
    )),
  );
  for _ in 0..4 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the SM reconstructed + the sync completed exactly once after the block was repaired"
  );
  assert!(
    !e.sm_reconstruct_owed(),
    "the obligation cleared once the SM held M"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "checkpoint_op stayed at M=4 throughout — no regression"
  );
  assert_eq!(e.commit(), OpNumber::with(4), "commit_min stayed at M=4");
  assert_eq!(e.status(), Status::Normal, "node stays Normal throughout");
}

/// Drive a laggard backup to a POST-ROOT SM-RESTORE FAULT for `M = 4`: trigger a sync at the LOW target
/// `T = 2`, stage M's re-persist, corrupt M's block, then drain the two-write re-persist so the frontier
/// advances to M (in lockstep with M's durable root) but `install_sync(M)`'s SM restore FAILS on the
/// corrupt block. Returns the endpoint + its storage with the frontier at M (`checkpoint_op == 4`),
/// `sm_reconstruct` OWED, `pending_install` consumed, and `M`'s leaf left CORRUPT (a caller that wants to
/// complete the reconstruction re-seeds it). The block-store's `sm_root_m` is also returned so a caller
/// can re-corrupt or repair it.
fn laggard_owing_sm_reconstruct_at_m() -> (
  Endpoint<CountSm>,
  TestWal,
  StepSb,
  MemBlockStore,
  BlockAddress,
  u128,
) {
  let (_donor_m, _dwal_m, dsb_m) = donor_primary_at_checkpoint(4);
  let (env_m, id_m) = donor_envelope(&dsb_m);
  let sm_root_m = {
    let mut donor_sm = CountSm::default();
    for rn in 1..=4u64 {
      donor_sm.apply(OpNumber::with(rn), &[rn as u8]);
    }
    crate::block_address(&donor_sm.snapshot())
  };
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let mut wal = TestWal::default();
  let mut sb = StepSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // Trigger a sync at the LOW target T=2.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);

  // Deliver M's SyncCheckpoint (op=4 >= T=2): `apply_sync` stages the re-persist → pending_install=M.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id_m,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env_m.clone(),
      Bytes::new(),
    )),
  );
  assert!(e.pending_install.is_some(), "M staged");

  // CORRUPT M's block, then drive the two-write re-persist: install_sync fails on the root completion.
  blocks.write_block(sm_root_m, Bytes::copy_from_slice(b"post-stage-corruption"));
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);

  assert_eq!(
    e.state_syncs_applied(),
    0,
    "the restore faulted on the corrupt block: the sync is not yet complete"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "checkpoint_op ADVANCED to M=4 in lockstep with the durable root (the redesign advances first)"
  );
  assert!(
    e.sm_reconstruct_owed(),
    "the SM-content reconstruction is owed (the restore faulted)"
  );
  assert!(
    e.pending_install.is_none(),
    "the PRE-ROOT staging was consumed at the root completion"
  );
  // In-memory == durable: the no-rewind property is structural (not a floor).
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "M's durable root names checkpoint_op=4 — equal to the in-memory checkpoint_op"
  );
  let m_checkpoint_id = sb.state().checkpoint_id();
  (e, wal, sb, blocks, sm_root_m, m_checkpoint_id)
}

/// The MULTI-block checkpoint DAG a `TwoLeafSm` at checkpoint `M = ckpt` produces: the root (over two
/// leaves) plus `leaf-x` (the first half of the applied ops) and `leaf-y` (the second half). Returns the
/// envelope + its id, the three block addresses, and a store holding all three CLEAN blocks. The envelope
/// carries an EMPTY session set (the laggard restores no sessions), so it is byte-reproducible from the
/// root alone — exactly what a real donor's serve path would ship for this DAG.
fn two_leaf_dag(
  ckpt: u64,
) -> (
  Bytes,
  u128,
  BlockAddress,
  BlockAddress,
  BlockAddress,
  MemBlockStore,
) {
  let mut donor_sm = TwoLeafSm::default();
  for rn in 1..=ckpt {
    donor_sm.apply(OpNumber::with(rn), &[rn as u8]);
  }
  let (leaf_x, leaf_y) = donor_sm.leaves();
  let xa = block_address(&leaf_x);
  let ya = block_address(&leaf_y);
  let mut store = MemBlockStore::new();
  let sm_root = {
    let mut sm = TwoLeafSm::default();
    for rn in 1..=ckpt {
      sm.apply(OpNumber::with(rn), &[rn as u8]);
    }
    sm.checkpoint(&mut store) // writes root + both leaves CLEAN into `store`, returns the root addr
  };
  // Encode the (empty) session table into the SAME donor store so its DAG block is part of the returned
  // store the laggard seeds from — both DAGs must be present for the install frontier to drain.
  let sessions_root =
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut store);
  let env = Endpoint::<TwoLeafSm>::encode_checkpoint(OpNumber::with(ckpt), sm_root, sessions_root);
  let id = crate::checkpoint_id(&env);
  (env, id, sm_root, xa, ya, store)
}

/// Drive a `TwoLeafSm` laggard backup to a POST-ROOT SM-RESTORE FAULT for `M = 4`, with EXACTLY ONE leaf
/// (`corrupt`) left bit-rotted while the rest of the DAG (root + the other leaf) is held CLEAN. Mirrors
/// [`laggard_owing_sm_reconstruct_at_m`] but over the multi-block DAG so two such laggards can fault
/// COMPLEMENTARY leaves. Returns the endpoint + storage with `checkpoint_op == 4`, `sm_reconstruct` OWED,
/// the SM still pre-M, and the named leaf corrupt in its local block store.
fn laggard_owing_two_leaf_at_m(
  local: u16,
  corrupt: BlockAddress,
) -> (
  Endpoint<TwoLeafSm>,
  TestWal,
  StepSb,
  MemBlockStore,
  BlockAddress,
  u128,
) {
  let (env_m, id_m, sm_root_m, _xa, _ya, _donor_store) = two_leaf_dag(4);
  // The local slot is derived from the config's `MemberId` matched in `genesis(3)` (member `i` → slot
  // `i`), so `MemberId::new(local)` makes this a slot-`local` endpoint; the seed stays 0.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(local as u128), 1_000).unwrap();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    cfg,
    genesis(3),
    0,
    TwoLeafSm::default(),
    u64::MAX,
  );
  let mut wal = TestWal::default();
  let mut sb = StepSb::default();
  // Seed the laggard's store with the WHOLE clean DAG so the block-fetch drains locally at stage; the
  // targeted leaf is corrupted AFTER staging (mirroring the single-block helper).
  let mut blocks = MemBlockStore::new();
  {
    let (_e2, _id2, _root2, _x2, _y2, donor_store) = two_leaf_dag(4);
    for addr in [sm_root_m, _x2, _y2] {
      if let Some(b) = donor_store.read_block(addr) {
        blocks.write_block(addr, b);
      }
    }
    // Also seed the (empty) session-table DAG so the install frontier drains both DAGs locally.
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks);
  }
  let now = Instant::ZERO;

  // Trigger a sync at the LOW target T=2.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = {
    let mut n = None;
    while let Some(out) = e.poll_message() {
      if let Message::RequestSync(r) = out.msg_ref() {
        n = Some(r.nonce());
      }
    }
    n.expect("a sync was solicited")
  };

  // Deliver M's SyncCheckpoint (op=4 >= T=2): stage the re-persist (DAG already present → drains at stage).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id_m,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env_m,
      Bytes::new(),
    )),
  );
  assert!(e.pending_install.is_some(), "M staged");

  // Corrupt the TARGETED leaf, then drive the two-write re-persist: install_sync's restore faults on it.
  blocks.write_block(corrupt, Bytes::copy_from_slice(b"post-stage-corruption"));
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);

  assert_eq!(
    e.state_syncs_applied(),
    0,
    "the restore faulted on the corrupt leaf: the sync is not yet complete"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "checkpoint_op ADVANCED to M=4"
  );
  assert!(
    e.sm_reconstruct_owed(),
    "the SM-content reconstruction is owed"
  );
  assert!(
    e.pending_install.is_none(),
    "the PRE-ROOT staging was consumed"
  );
  let m_checkpoint_id = sb.state().checkpoint_id();
  (e, wal, sb, blocks, sm_root_m, m_checkpoint_id)
}

#[test]
fn two_complementary_debtors_donate_each_others_blocks_and_both_reconstruct() {
  // THE QUORUM-WEDGE the SERVE-side decouple fixes. A 3-node cluster: the original full donor (replica 0)
  // is GONE, and the two live replicas BOTH owe an SM-reconstruct at the SAME checkpoint M=4 because of
  // DIFFERENT (complementary) local block faults — replica A faulted `leaf-x` (holds clean `leaf-y`),
  // replica B faulted `leaf-y` (holds clean `leaf-x`). Together they hold every clean block of M's DAG.
  //
  // Both emit an equal-checkpoint `RequestSync` (their owed-state solicit sets `recovery`). Before the
  // fix, `on_request_sync` DROPPED every request while `sm_reconstruct_owed()`, so BOTH stayed silent:
  // neither re-pinned its block-fetch to the other (a block fetch only re-pins after a fresh
  // `SyncCheckpoint`), neither pulled the clean block the OTHER still held, both stayed owed forever, the
  // SM stayed withheld, apply/serve stayed gated — the live quorum WEDGED even though together they hold
  // every clean block. With the fix an owed replica still HIDES its own un-reconstructed SM (gated) but
  // SERVES, for an equal-checkpoint repair, its verified durable ENVELOPE (re-pinning the peer's fetch)
  // and each CLEAN block via `on_request_block`'s verified read (ABSENT for its own faulted leaf). So each
  // debtor donates the other's missing block, both reconstruct, both `state_machine()` become `Some`.
  let (_env, _id, _sm_root, leaf_x, leaf_y, _donor_store) = two_leaf_dag(4);
  let a_id = ReplicaId::new(1);
  let b_id = ReplicaId::new(2);

  // Replica A (slot 1): faulted `leaf-x`, holds clean root + `leaf-y`. Replica B (slot 2): faulted
  // `leaf-y`, holds clean root + `leaf-x`. Distinct slots so each, serving the other, stamps its own
  // slot as the `SyncCheckpoint.replica()` the receiver's same-config sender binding admits.
  let (mut a, mut awal, mut asb, mut ablocks, _a_root, m_id) =
    laggard_owing_two_leaf_at_m(1, leaf_x);
  let (mut b, mut bwal, mut bsb, mut bblocks, _b_root, _b_mid) =
    laggard_owing_two_leaf_at_m(2, leaf_y);

  // Strand precondition: both Normal, owed at M=4, SM withheld, the original donor (replica 0) is gone.
  for (e, who) in [(&a, "A"), (&b, "B")] {
    assert_eq!(
      e.status(),
      Status::Normal,
      "{who} is Normal after the faulted restore"
    );
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(4),
      "{who} frontier is M=4"
    );
    assert!(e.sm_reconstruct_owed(), "{who} owes an SM-reconstruct");
    assert!(
      e.state_machine().is_none(),
      "{who}'s production SM is withheld while owed"
    );
  }

  // Each debtor's owed-state ARQ broadcasts an equal-checkpoint `RequestSync`. Fire the solicit timer.
  let later = Instant::ZERO + core::time::Duration::from_millis(300);
  let solicit = |e: &mut Endpoint<TwoLeafSm>,
                 sb: &mut StepSb,
                 blocks: &mut MemBlockStore|
   -> crate::RequestSync {
    while e.poll_message().is_some() {}
    e.sync_timeouts(later, sb, blocks);
    core::iter::from_fn(|| e.poll_message())
      .find_map(|out| match out.msg_ref() {
        Message::RequestSync(r) => Some(*r),
        _ => None,
      })
      .expect("the owed-reconstruct ARQ broadcasts a RequestSync")
  };
  let a_sol = solicit(&mut a, &mut asb, &mut ablocks);
  let b_sol = solicit(&mut b, &mut bsb, &mut bblocks);
  assert!(
    a_sol.recovery() && b_sol.recovery(),
    "each owed debtor solicits an EQUAL-CHECKPOINT repair (recovery flag set)"
  );
  assert_eq!(
    a_sol.checkpoint_op(),
    OpNumber::with(4),
    "A advertises its checkpoint M=4"
  );
  assert_eq!(
    b_sol.checkpoint_op(),
    OpNumber::with(4),
    "B advertises its checkpoint M=4"
  );

  // THE LOAD-BEARING SERVE-SIDE ASSERTION: an owed replica, asked an equal-checkpoint repair, SUBMITS a
  // serve-read and SHIPS a byte-correct envelope — the `sm_reconstruct_owed()` gate must NOT short-circuit
  // the serve before the read, or `sync_serving` stays empty and no SyncCheckpoint is shipped (the wedge
  // two complementary-corruption debtors recover from by serving each other).
  let serve_envelope = |donor: &mut Endpoint<TwoLeafSm>,
                        dwal: &mut TestWal,
                        dsb: &mut StepSb,
                        dblocks: &mut MemBlockStore,
                        to: ReplicaId,
                        sol: &crate::RequestSync|
   -> Option<crate::SyncCheckpoint> {
    while donor.poll_message().is_some() {}
    donor.on_request_sync(
      later,
      dsb,
      Peer::Replica(to),
      crate::RequestSync::new(
        sol.view(),
        OpNumber::with(4),
        to,
        sol.nonce(),
        true, // an equal-checkpoint repair
        sol.config_id(),
      ),
    );
    dsb.flush();
    donor.handle_storage(later, dwal, dsb, dblocks);
    core::iter::from_fn(|| donor.poll_message()).find_map(|out| match out.into_msg() {
      Message::SyncCheckpoint(m) => Some(m),
      _ => None,
    })
  };

  // B serves A's solicitation (A's failover donor), and A serves B's. Each ships a verified M envelope.
  let b_to_a = serve_envelope(&mut b, &mut bwal, &mut bsb, &mut bblocks, a_id, &a_sol)
    .expect("an owed B SERVES A's equal-checkpoint repair (envelope) — the decouple");
  let a_to_b = serve_envelope(&mut a, &mut awal, &mut asb, &mut ablocks, b_id, &b_sol)
    .expect("an owed A SERVES B's equal-checkpoint repair (envelope) — the decouple");
  assert_eq!(
    b_to_a.checkpoint_op(),
    OpNumber::with(4),
    "B serves the M=4 envelope to A"
  );
  assert_eq!(
    b_to_a.checkpoint_id(),
    m_id,
    "B's served envelope id is M's durable id"
  );
  assert_eq!(
    a_to_b.checkpoint_id(),
    m_id,
    "A's served envelope id is M's durable id"
  );

  // Re-pin: deliver each donor's envelope to the OTHER debtor. `refetch_sm_reconstruct` re-points the
  // obligation's block-fetch to the live donor and emits a `RequestBlock` for the locally-faulted leaf.
  let repin = |e: &mut Endpoint<TwoLeafSm>,
               wal: &mut TestWal,
               sb: &mut StepSb,
               blocks: &mut MemBlockStore,
               donor: ReplicaId,
               env: crate::SyncCheckpoint|
   -> crate::BlockAddress {
    while e.poll_message().is_some() {}
    e.handle_message(
      later,
      wal,
      sb,
      blocks,
      Peer::Replica(donor),
      Message::SyncCheckpoint(env),
    );
    core::iter::from_fn(|| e.poll_message())
      .find_map(|out| match (out.to(), out.msg_ref()) {
        (Recipient::To(Peer::Replica(d)), Message::RequestBlock(addr)) if d == donor => Some(*addr),
        _ => None,
      })
      .expect("the re-pinned fetch requests the locally-faulted leaf from the FRESH donor")
  };
  let a_wants = repin(&mut a, &mut awal, &mut asb, &mut ablocks, b_id, b_to_a);
  let b_wants = repin(&mut b, &mut bwal, &mut bsb, &mut bblocks, a_id, a_to_b);
  assert_eq!(a_wants, leaf_x, "A re-pulls its faulted leaf-x (from B)");
  assert_eq!(b_wants, leaf_y, "B re-pulls its faulted leaf-y (from A)");

  // THE SECOND LOAD-BEARING ASSERTION: each owed donor's `on_request_block` SERVES the CLEAN block it
  // holds (its own un-faulted leaf) via the verified read — and would return ABSENT for the leaf IT
  // faulted on (proven by `a_wants`/`b_wants` being exactly the complementary leaves).
  let serve_block = |donor: &mut Endpoint<TwoLeafSm>,
                     dblocks: &MemBlockStore,
                     to: ReplicaId,
                     addr: crate::BlockAddress|
   -> crate::BlockResponse {
    while donor.poll_message().is_some() {}
    donor.on_request_block(Peer::Replica(to), addr, dblocks);
    core::iter::from_fn(|| donor.poll_message())
      .find_map(|out| match out.into_msg() {
        Message::BlockResponse(m) => Some(m),
        _ => None,
      })
      .expect("the owed donor answers the block request")
  };
  // B serves A its clean leaf-x; A serves B its clean leaf-y.
  let x_from_b = serve_block(&mut b, &bblocks, a_id, a_wants);
  let y_from_a = serve_block(&mut a, &ablocks, b_id, b_wants);
  assert!(
    x_from_b.block().is_some(),
    "an owed B DONATES its CLEAN leaf-x (verified read) even though B itself owes a reconstruct"
  );
  assert!(
    y_from_a.block().is_some(),
    "an owed A DONATES its CLEAN leaf-y (verified read) even though A itself owes a reconstruct"
  );

  // Feed each clean block back: the corrupt leaf is overwritten, the DAG drains, the SM reconstructs.
  let complete = |e: &mut Endpoint<TwoLeafSm>,
                  wal: &mut TestWal,
                  sb: &mut StepSb,
                  blocks: &mut MemBlockStore,
                  donor: ReplicaId,
                  resp: crate::BlockResponse| {
    while e.poll_message().is_some() {}
    e.handle_message(
      later,
      wal,
      sb,
      blocks,
      Peer::Replica(donor),
      Message::BlockResponse(resp),
    );
    for _ in 0..4 {
      sb.flush();
      e.handle_storage(later, wal, sb, blocks);
    }
  };
  complete(&mut a, &mut awal, &mut asb, &mut ablocks, b_id, x_from_b);
  complete(&mut b, &mut bwal, &mut bsb, &mut bblocks, a_id, y_from_a);

  // End state: BOTH obligations cleared, BOTH SMs hold M, the production read resumes on both, and serving
  // is no longer gated — the quorum did NOT wedge.
  for (e, who) in [(&a, "A"), (&b, "B")] {
    assert!(
      !e.sm_reconstruct_owed(),
      "{who}'s obligation cleared — the failover reconstructed it"
    );
    assert_eq!(
      e.checkpoint_op(),
      OpNumber::with(4),
      "{who} stayed at M=4 (no rewind)"
    );
    let sm = e
      .state_machine()
      .expect("state_machine() returns Some once reconstruction completes");
    assert_eq!(
      sm.applied().len(),
      4,
      "{who}'s SM now holds M's 4 applied ops"
    );
  }

  // Apply/serve resume: a fresh RequestSync now submits a serve-read on both.
  let resumes = |e: &mut Endpoint<TwoLeafSm>,
                 wal: &mut TestWal,
                 sb: &mut StepSb,
                 blocks: &mut MemBlockStore,
                 peer: ReplicaId| {
    while e.poll_message().is_some() {}
    e.handle_message(
      later,
      wal,
      sb,
      blocks,
      Peer::Replica(peer),
      Message::RequestSync(crate::RequestSync::new(
        e.view(),
        OpNumber::with(0),
        peer,
        0xF00D,
        false,
        0,
      )),
    );
    assert_eq!(
      e.sync_serving.len(),
      1,
      "serving resumes — a RequestSync now submits a serve-read"
    );
  };
  resumes(&mut a, &mut awal, &mut asb, &mut ablocks, b_id);
  resumes(&mut b, &mut bwal, &mut bsb, &mut bblocks, a_id);

  // The genuinely-unrecoverable case stays correctly FENCED, NOT weakened. Prove the boundary: a debtor
  // re-faults BOTH the locally-held leaf AND re-pins to a donor that ALSO faulted that same leaf — the
  // block is lost on every reachable donor. The envelope re-pin still succeeds, but every `RequestBlock`
  // for that leaf is answered ABSENT (verified read → None), so the fetch never drains, the obligation
  // stays owed, the frontier stays at M, and the SM stays withheld — no rewind, no weakened verification.
  // C is a slot-1 debtor that faulted leaf-x; its only reachable donor (slot 2) ALSO faulted leaf-x — so
  // leaf-x is lost on every reachable donor.
  let (mut c, mut cwal, mut csb, mut cblocks, _c_root, c_mid) =
    laggard_owing_two_leaf_at_m(1, leaf_x);
  let (mut bad_donor, mut bwal2, mut bsb2, mut bdblocks, _bd_root, _bd_mid) =
    laggard_owing_two_leaf_at_m(2, leaf_x);
  let c_sol = solicit(&mut c, &mut csb, &mut cblocks);
  let donor_env = serve_envelope(
    &mut bad_donor,
    &mut bwal2,
    &mut bsb2,
    &mut bdblocks,
    a_id,
    &c_sol,
  )
  .expect("even an owed bad-donor serves the equal-checkpoint envelope (the re-pin succeeds)");
  assert_eq!(
    donor_env.checkpoint_id(),
    c_mid,
    "the re-pin envelope names M"
  );
  let c_wants = repin(&mut c, &mut cwal, &mut csb, &mut cblocks, b_id, donor_env);
  assert_eq!(c_wants, leaf_x, "C still needs leaf-x");
  // The bad donor cannot serve leaf-x (it faulted it too): `on_request_block` returns an ABSENT response.
  while bad_donor.poll_message().is_some() {}
  bad_donor.on_request_block(Peer::Replica(a_id), c_wants, &bdblocks);
  let absent = core::iter::from_fn(|| bad_donor.poll_message())
    .find_map(|out| match out.into_msg() {
      Message::BlockResponse(m) => Some(m),
      _ => None,
    })
    .expect("the bad donor answers");
  assert!(
    absent.block().is_none(),
    "the universally-lost leaf is served ABSENT (verified read → None) — verification is NOT weakened"
  );
  complete(&mut c, &mut cwal, &mut csb, &mut cblocks, b_id, absent);
  assert!(
    c.sm_reconstruct_owed(),
    "with the block lost on every donor the obligation STAYS owed — correctly fenced, no rewind"
  );
  assert_eq!(
    c.checkpoint_op(),
    OpNumber::with(4),
    "the frontier stays at M=4 (no rewind)"
  );
  assert!(
    c.state_machine().is_none(),
    "the SM stays withheld until the block returns"
  );
}

#[test]
fn an_owed_sm_reconstruct_survives_a_view_change_and_no_durable_view_write_rewinds_m() {
  // An SM-RECONSTRUCT obligation for M=4 is owed: M's `SyncRepersist` root is durable AND the in-memory
  // `checkpoint_op` is ALREADY 4 (the redesign advances the pointer in lockstep with the root, before the
  // restore). A view change entered in this window must NOT rewind the durable checkpoint, and the view
  // change's own durable-VIEW write reads `self.checkpoint_op == 4 == durable` — so it CANNOT name a
  // checkpoint below M. The obligation survives the transition (for liveness — to keep the retry alive).
  // The hazard this guards: were `checkpoint_op` left stale (0) on a restore fault while the durable root
  // named M, `submit_durable_view` would persist the stale 0 paired with M's checkpoint_id and REWIND the
  // durable checkpoint. In-memory advancing to M in lockstep makes that rewind impossible.
  let (mut e, mut wal, mut sb, mut blocks, _sm_root_m, m_checkpoint_id) =
    laggard_owing_sm_reconstruct_at_m();
  let now = Instant::ZERO;

  // Enter a view change: two peers send StartViewChange(view 1) → SVC quorum → ViewChange(1), which
  // submits a durable-VIEW write. This is the teardown + durable-root write that must not rewind M.
  for r in [1u16, 2] {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(r)),
      Message::StartViewChange(StartViewChange::new(
        View::with(1),
        ReplicaId::new(r),
        crate::Epoch::new(0),
        0,
      )),
    );
  }
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "the SVC quorum entered ViewChange"
  );
  // THE OBLIGATION SURVIVED THE TEARDOWN: `reset_for_view_transition` kept it (for liveness).
  assert!(
    e.sm_reconstruct_owed(),
    "the SM-reconstruct obligation is KEPT across the view-change entry (not cancelled)"
  );

  // Drive the view-change durable-VIEW write to durability and inspect the root it persisted. It read
  // `self.checkpoint_op == 4` (== durable), so it CANNOT name a checkpoint below M.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "the durable-view write named checkpoint_op=4 (== in-memory) — no rewind of M's durable root"
  );
  assert_eq!(
    sb.state().checkpoint_id(),
    m_checkpoint_id,
    "and the durable root still names M's checkpoint id (no id/op contradiction)"
  );

  // FORWARD PROGRESS: settle the view as a backup (adopt a StartView at view 1 with a head AT M), repair
  // M's block, and let the retry complete. In-memory == durable never rewound anything, and M's SM
  // reconstructs once its block is clean.
  seed_donor_blocks(&mut blocks, 4);
  // Adopt the new view's canonical head so the node returns to Normal (a backup exit that runs the shared
  // reset AGAIN — the obligation must survive this exit too, and re-arm its serviced solicit timer).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(crate::StartView::new(
      View::with(1),
      OpNumber::with(4),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(1),
      std::vec::Vec::new(),
    )),
  );
  // Drain any pending superblock writes the adoption queued (its AdoptedStartView durable-view write must
  // ALSO read checkpoint_op=4).
  for _ in 0..6 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "the adoption durable-view write also named checkpoint_op=4 — no rewind"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "checkpoint_op stayed at M=4 throughout — never a rewind below M"
  );
}

#[test]
fn a_cancelled_superseding_sync_keeps_the_sm_reconstruct_obligation_gated() {
  // REGRESSION: an SM-reconstruct obligation for M=4 is owed (M's restore faulted; the SM still holds pre-M
  // content while `checkpoint_op == 4`). A strictly-NEWER checkpoint M'=8 supersedes it and stages a
  // PRE-ROOT `pending_install`. That install is CANCELLABLE — a view transition drops it before its root
  // lands. The obligation for M MUST survive the whole handoff: if it were cleared at M''s stage time,
  // cancelling `pending_install` would leave the SM behind `checkpoint_op` with NEITHER gate set, and a
  // Commit heartbeat could `advance_commit` over stale pre-M content (committed-state divergence).
  let (mut e, mut wal, mut sb, mut blocks, _sm_root_m, _id_m) = laggard_owing_sm_reconstruct_at_m();
  let now = Instant::ZERO;
  let later = now + core::time::Duration::from_secs(1);
  assert!(
    e.sm_reconstruct_owed(),
    "precondition: M's reconstruct is owed"
  );
  assert!(
    e.pending_install.is_none(),
    "precondition: the M install already faulted, none staged"
  );

  // A strictly-newer checkpoint M'=8, its DAG already present locally so `apply_sync` stages immediately.
  let (_d8, _w8, s8) = donor_primary_at_checkpoint(8);
  let (env8, id8) = donor_envelope(&s8);
  seed_donor_blocks(&mut blocks, 8);
  // Fire the sync-solicit timer so a fresh RequestSync (carrying the current nonce) is emitted to capture.
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks);
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(8),
      id8,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env8,
      Bytes::new(),
    )),
  );
  assert!(
    e.pending_install.is_some(),
    "M'=8 staged a pre-root install"
  );
  assert!(
    e.sm_reconstruct_owed(),
    "the M obligation is KEPT through the M' staging (not cleared) — the SM is still pre-M",
  );

  // A view change cancels the pre-root M' install (SVC quorum → ViewChange).
  for r in [1u16, 2] {
    e.handle_message(
      later,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(r)),
      Message::StartViewChange(StartViewChange::new(
        View::with(1),
        ReplicaId::new(r),
        crate::Epoch::new(0),
        0,
      )),
    );
  }
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "the SVC quorum entered ViewChange"
  );
  assert!(
    e.pending_install.is_none(),
    "the view transition cancelled the pre-root M' install",
  );
  assert!(
    e.sm_reconstruct_owed(),
    "the SM-reconstruct obligation SURVIVES the cancel — the SM stays gated (no ungated pre-M apply window)",
  );
}

#[test]
fn a_retained_newer_install_is_not_orphaned_by_an_equal_checkpoint_reply() {
  // REGRESSION: while an SM-reconstruct obligation for M=4 is owed AND a strictly-newer M'=8 install is
  // RETAINED (staged, then its block-store flush faulted — `pending_checkpoint` is None), a fresh EQUAL-M
  // (=4) reply must NOT run the same-M reconstruct: doing so would, on success, clear `sm_reconstruct` +
  // `sync` and orphan the retained `pending_install(8)` (tripping `pending_install => sync` in debug /
  // wedging the apply gate in release). The newer install subsumes M and is retried locally.
  let (mut e, mut wal, mut sb, mut blocks, _sm_root_m, _id_m) = laggard_owing_sm_reconstruct_at_m();
  let now = Instant::ZERO;
  let t1 = now + core::time::Duration::from_secs(1);
  let t2 = now + core::time::Duration::from_secs(2);

  // Stage a strictly-newer M'=8 whose flush FAULTS, leaving `pending_install(8)` retained.
  let (_d8, _w8, s8) = donor_primary_at_checkpoint(8);
  let (env8, id8) = donor_envelope(&s8);
  seed_donor_blocks(&mut blocks, 8);
  blocks.script_flush_fault(1);
  e.handle_timeout(t1, &mut wal, &mut sb, &mut blocks);
  let nonce1 = captured_sync_nonce(&mut e);
  e.handle_message(
    t1,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(8),
      id8,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce1,
      env8,
      Bytes::new(),
    )),
  );
  assert!(
    e.pending_install.is_some(),
    "M'=8 install retained after the flush fault"
  );
  assert!(
    e.sm_reconstruct_owed(),
    "M's obligation still owed alongside the retained newer install"
  );

  // No block-fetch is armed while the newer install is retained (it was consumed at stage time).
  assert!(
    e.block_fetch.is_none(),
    "no block-fetch while the newer install is retained"
  );

  // An EQUAL-M (=4) reply now. The guard DROPS it (falls through to the monotone reject); without the
  // guard it would route to `refetch_sm_reconstruct`, which arms a block-fetch pinned to M=4 and, on
  // success, clears `sync` and orphans the retained install.
  let (_d4, _w4, s4) = donor_primary_at_checkpoint(4);
  let (env4, id4) = donor_envelope(&s4);
  e.handle_timeout(t2, &mut wal, &mut sb, &mut blocks);
  let nonce2 = captured_sync_nonce(&mut e);
  e.handle_message(
    t2,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id4,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce2,
      env4,
      Bytes::new(),
    )),
  );
  assert!(
    e.pending_install.is_some(),
    "the equal-M reply did NOT orphan the retained newer install",
  );
  assert!(
    e.sm_reconstruct_owed(),
    "the obligation is still owed (the equal-M reply was dropped, not routed to a same-M reconstruct)",
  );
  assert!(
    e.block_fetch.is_none(),
    "the equal-M reply was DROPPED, not routed to refetch_sm_reconstruct (which would arm a block-fetch)",
  );
}

#[test]
fn an_owed_sm_reconstruct_blocks_a_competing_lower_checkpoint_write() {
  // An SM-RECONSTRUCT obligation for M=4 is owed (M's durable root is written, in-memory checkpoint_op=4).
  // A competing LOWER durable-root write must NOT produce a root naming a checkpoint < M:
  //   (a) an ordinary `maybe_checkpoint` is WITHHELD while the obligation holds (force_checkpoint would
  //       snapshot the stale SM under the forward op M); and
  //   (b) a durable-VIEW write (the most direct competing root) reads `self.checkpoint_op == 4 == durable`,
  //       so it names checkpoint_op=4 and cannot rewind.
  // Were `checkpoint_op` left stale on a fault, the durable-view write would persist the stale value below M
  // — a rewind; the lockstep advance + the obligation gate on `maybe_checkpoint` close both routes.
  let (mut e, mut wal, mut sb, mut blocks, _sm_root_m, _m_checkpoint_id) =
    laggard_owing_sm_reconstruct_at_m();
  let now = Instant::ZERO;

  // (a) The obligation withholds any ordinary checkpoint: a checkpoint attempt while it is owed must start
  //     NO checkpoint write (no superblock submission). The node is Normal here (the faulted restore left
  //     it Normal), so without the obligation gate `maybe_checkpoint` could snapshot the stale SM.
  assert!(
    !sb.has_inflight(),
    "no superblock write is in flight after the faulted restore"
  );
  e.maybe_checkpoint(&mut sb, &mut blocks);
  assert!(
    !sb.has_inflight(),
    "maybe_checkpoint started NO new checkpoint write while the SM-reconstruct obligation is owed"
  );

  // (b) A durable-VIEW write submitted while the obligation holds reads `self.checkpoint_op == 4` and so
  //     names checkpoint_op=4. Trigger it via a view change (the production path that issues one).
  for r in [1u16, 2] {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(r)),
      Message::StartViewChange(StartViewChange::new(
        View::with(1),
        ReplicaId::new(r),
        crate::Epoch::new(0),
        0,
      )),
    );
  }
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "the competing durable-view write named checkpoint_op=4 (== in-memory) — no rewind"
  );
  assert!(
    sb.state().commit().get() >= 4,
    "and its commit is >= M=4 so the commit >= checkpoint_op root invariant holds (it is {})",
    sb.state().commit().get()
  );
}

#[test]
fn an_owed_sm_reconstruct_does_not_serve_m_until_the_sm_is_restored() {
  // While the SM-reconstruct obligation is owed, `self.checkpoint_op == M` but the SM does not yet hold M:
  // the node MUST NOT serve a `SyncCheckpoint` for M (it cannot — it is missing the very block its own
  // restore faulted on, and its SM is not M). A peer's `RequestSync` must start NO serve-read while owed;
  // once the retry reconstructs the SM, serving resumes normally.
  let (mut e, mut wal, mut sb, mut blocks, _sm_root_m, _id) = laggard_owing_sm_reconstruct_at_m();
  let now = Instant::ZERO;
  while e.poll_message().is_some() {} // drain anything queued by the install path

  // A peer solicits a sync. The node is Normal with `checkpoint_op == 4`, so absent the gate it would
  // submit a serve-read and ship M — but the obligation is owed, so it must stay silent.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      e.view(),
      OpNumber::with(0),
      ReplicaId::new(2),
      0xBEEF,
      false,
      0,
    )),
  );
  assert!(
    e.sync_serving.is_empty(),
    "no serve-read was submitted while the SM-reconstruct obligation is owed"
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  let shipped_while_owed = core::iter::from_fn(|| e.poll_message())
    .any(|out| matches!(out.msg_ref(), Message::SyncCheckpoint(_)));
  assert!(
    !shipped_while_owed,
    "the node shipped NO SyncCheckpoint for M while it does not yet hold M"
  );

  // Repair M's block + re-deliver M: the retry reconstructs the SM and the obligation clears.
  seed_donor_blocks(&mut blocks, 4);
  let nonce = e.sync_nonce_for_test();
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      _id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      donor_envelope(&donor_primary_at_checkpoint(4).2).0,
      Bytes::new(),
    )),
  );
  for _ in 0..4 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }
  assert!(
    !e.sm_reconstruct_owed(),
    "the obligation cleared once the SM reconstructed"
  );

  // Serving now resumes: a fresh RequestSync submits a serve-read.
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      e.view(),
      OpNumber::with(0),
      ReplicaId::new(2),
      0xFEED,
      false,
      0,
    )),
  );
  assert_eq!(
    e.sync_serving.len(),
    1,
    "serving resumes once the SM holds M — a RequestSync now submits a serve-read"
  );
}

#[test]
fn state_machine_is_withheld_while_sm_reconstruct_is_owed_and_resumes_once_cleared() {
  // The SM-readiness gate: `state_machine()` returns `None` while `sm_reconstruct_owed()` is true (the SM
  // still holds pre-M content) and returns `Some` only after reconstruction succeeds, at which point the SM
  // holds M's content. Without it a production caller would read the stale pre-M SM under a checkpoint
  // pointer that already names M.
  let (mut e, mut wal, mut sb, mut blocks, _sm_root_m, _checkpoint_id) =
    laggard_owing_sm_reconstruct_at_m();
  let now = Instant::ZERO;

  // Precondition: checkpoint_op == M, sm_reconstruct_owed, SM holds pre-M (0-applied) content.
  assert_eq!(e.checkpoint_op(), OpNumber::with(4), "frontier is M");
  assert!(
    e.sm_reconstruct_owed(),
    "SM-content reconstruction is owed — the restore faulted"
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    0,
    "the raw SM still holds the OLD pre-M content (0 applied)"
  );

  // THE KEY ASSERTION: a production read MUST be withheld while the SM lags the durable checkpoint pointer.
  assert!(
    e.state_machine().is_none(),
    "state_machine() returns None while an SM-reconstruct obligation is owed      — exposing the stale pre-M SM to a production caller is incorrect"
  );

  // Repair M's block (the helper left it corrupt). The pending block-fetch re-arms; once a fresh
  // SyncCheckpoint for M arrives, the retry reconstructs the SM and the obligation clears.
  seed_donor_blocks(&mut blocks, 4);
  let nonce = e.sync_nonce_for_test();
  while e.poll_message().is_some() {}
  let (_donor_m, _dwal_m, dsb_m) = donor_primary_at_checkpoint(4);
  let (env_m, id_m) = donor_envelope(&dsb_m);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id_m,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env_m,
      Bytes::new(),
    )),
  );
  // Drive the storage completions until the SM reconstructs.
  for _ in 0..4 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }

  // Post-reconstruction: the obligation clears, the SM now holds M's content.
  assert!(
    !e.sm_reconstruct_owed(),
    "the obligation cleared once the SM was reconstructed"
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    4,
    "the SM now holds M's content (4 applied ops)"
  );

  // THE KEY ASSERTION: the production read resumes and returns the M-state SM.
  let sm = e
    .state_machine()
    .expect("state_machine() returns Some after reconstruction");
  assert_eq!(
    sm.applied().len(),
    4,
    "the production accessor returns the M-state SM with 4 applied ops"
  );
}

#[test]
fn a_normal_owed_sm_reconstruct_solicits_an_equal_checkpoint_repair_and_fails_over_to_a_fresh_donor()
 {
  // A NORMAL replica owes an SM-reconstruct for M=4 (a post-root restore faulted on a bit-rotted block)
  // and its ORIGINAL donor (replica 0) goes silent. The block-fetch ARQ's `RequestBlock` to the dead
  // donor is unanswerable, so the only escape is the `RequestSync` ARQ: another peer that holds M's clean
  // block (also at checkpoint M=4) must serve a fresh `SyncCheckpoint`, re-pinning the block-fetch to it.
  //
  // But a peer AT M serves a same-checkpoint request ONLY when the solicitation carries the
  // equal-checkpoint repair flag (`on_request_sync`'s `>= ` vs strict `>`). A Normal replica's
  // `send_request_sync` set that flag from `awaiting_peer_checkpoint()` alone (true only while
  // Recovering), so a Normal owed-reconstruct soliciting emitted `recovery == false` → every equal-M peer
  // stayed silent → the obligation was owed forever, `state_machine()` withheld, apply gated. The fix
  // also sets the flag while `sm_reconstruct_owed()`.
  //
  // The chain the flag unlocks: with `recovery()` set, the equal-M peer serves (its strict `>` would
  // otherwise decline at equal M), the fetch re-pins to it, M's clean block drains, the SM reconstructs,
  // and the production read resumes — without the flag there is no `SyncCheckpoint`, no failover, and the
  // strand persists.
  let (mut e, mut wal, mut sb, mut blocks, sm_root_m, id_m) = laggard_owing_sm_reconstruct_at_m();

  // Strand precondition: Normal, owed at M=4, SM withheld, M's local block still corrupt.
  assert_eq!(
    e.status(),
    Status::Normal,
    "the faulted restore left it Normal"
  );
  assert_eq!(e.checkpoint_op(), OpNumber::with(4), "the frontier is M=4");
  assert!(e.sm_reconstruct_owed(), "an SM-reconstruct is owed");
  assert!(
    e.state_machine().is_none(),
    "the production SM is withheld while the obligation is owed"
  );

  // A SEPARATE peer at the SAME checkpoint M=4 that holds M's clean block — the donor we must fail over
  // to. Modelled by a `Normal` primary-at-4 endpoint with M's block seeded in its own store, served via
  // its real `on_request_block`. (Its `SyncCheckpoint` envelope is read straight from its durable
  // checkpoint, exactly what its own serve path would ship.)
  let equal_peer = ReplicaId::new(2);
  let (_donor_m, _dwal_m, dsb_m) = donor_primary_at_checkpoint(4);
  let (env_m, env_id_m) = donor_envelope(&dsb_m);
  assert_eq!(env_id_m, id_m, "the equal-M peer's checkpoint id matches M");
  let mut peer_blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut peer_blocks, 4); // the equal-M peer has M's CLEAN block

  // The ORIGINAL donor (replica 0) is silent: drive the solicit ARQ. The block-fetch re-armed
  // `sync_solicit` at `ZERO + SYNC_SOLICIT`, so firing it past that deadline re-broadcasts `RequestSync`.
  let later = Instant::ZERO + core::time::Duration::from_millis(300);
  while e.poll_message().is_some() {}
  e.sync_timeouts(later, &mut sb, &mut blocks);
  let solicited = core::iter::from_fn(|| e.poll_message())
    .find_map(|out| match out.msg_ref() {
      Message::RequestSync(r) => Some(*r),
      _ => None,
    })
    .expect("the owed-reconstruct ARQ broadcasts a RequestSync");
  assert_eq!(
    solicited.checkpoint_op(),
    OpNumber::with(4),
    "the solicitation advertises our current checkpoint M=4"
  );

  // THE LOAD-BEARING ASSERTION: a Normal replica owing an SM-reconstruct must set the equal-checkpoint
  // repair flag so an equal-M peer answers it.
  assert!(
    solicited.recovery(),
    "a Normal owed-reconstruct solicits an EQUAL-CHECKPOINT repair (recovery flag set) so a peer at M serves it"
  );

  // What a real equal-M peer does with each variant — the protocol-level proof of the strand. Serve the
  // solicitation through the peer's actual `on_request_sync`/serve-read and observe whether it ships a
  // SyncCheckpoint. The requester `from` is replica 1 (a configured backup, distinct from the peer at 0).
  let serves = |recovery: bool| -> bool {
    let (mut peer, mut pwal, mut psb) = donor_primary_at_checkpoint(4);
    let mut pblocks = crate::block_store::MemBlockStore::new();
    seed_donor_blocks(&mut pblocks, 4);
    while peer.poll_message().is_some() {}
    peer.on_request_sync(
      later,
      &mut psb,
      Peer::Replica(ReplicaId::new(1)),
      crate::RequestSync::new(
        solicited.view(),
        OpNumber::with(4),
        ReplicaId::new(1),
        solicited.nonce(),
        recovery,
        solicited.config_id(),
      ),
    );
    // The serve-read completes on the next storage step (TestSb completes reads synchronously);
    // `handle_storage` drains it and ships the SyncCheckpoint.
    peer.handle_storage(later, &mut pwal, &mut psb, &mut pblocks);
    core::iter::from_fn(|| peer.poll_message())
      .any(|out| matches!(out.msg_ref(), Message::SyncCheckpoint(_)))
  };
  // RED mechanism: an ordinary (recovery=false) equal-M solicitation is DECLINED (strict `>` at equal M).
  assert!(
    !serves(false),
    "without the repair flag, an equal-M peer DECLINES the same-checkpoint request (the strand)"
  );
  // With the repair flag set, the same-checkpoint request IS served by an equal-M peer.
  assert!(
    serves(true),
    "with the repair flag, an equal-M peer SERVES the same-checkpoint request"
  );

  // Now complete the failover end to end with the real laggard. The equal-M peer's served
  // `SyncCheckpoint` re-pins the obligation's block-fetch to it (`refetch_sm_reconstruct`) and emits a
  // `RequestBlock` to it.
  while e.poll_message().is_some() {}
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(equal_peer),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      solicited.view(),
      OpNumber::with(4),
      id_m,
      crate::Epoch::new(0),
      0,
      equal_peer,
      solicited.nonce(),
      env_m,
      Bytes::new(),
    )),
  );
  let block_req = core::iter::from_fn(|| e.poll_message())
    .find_map(|out| match (out.to(), out.msg_ref()) {
      (Recipient::To(Peer::Replica(d)), Message::RequestBlock(addr)) if d == equal_peer => {
        Some(*addr)
      }
      _ => None,
    })
    .expect("the re-pinned fetch requests M's block from the FRESH donor (failover target)");
  assert_eq!(
    block_req, sm_root_m,
    "the re-pull targets M's root (still corrupt in our local store)"
  );

  // The fresh donor serves M's clean block (its real `on_request_block`); feed the response back. The
  // clean bytes overwrite our corrupt block, the DAG drains, and `retry_sm_reconstruct` reconstructs M.
  let (mut peer, _pwal2, _psb2) = donor_primary_at_checkpoint(4);
  while peer.poll_message().is_some() {}
  peer.on_request_block(Peer::Replica(ReplicaId::new(1)), block_req, &peer_blocks);
  let block_resp = core::iter::from_fn(|| peer.poll_message())
    .find_map(|out| match out.into_msg() {
      Message::BlockResponse(m) => Some(m),
      _ => None,
    })
    .expect("the fresh donor serves M's clean block");
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(equal_peer),
    Message::BlockResponse(block_resp),
  );
  for _ in 0..4 {
    sb.flush();
    e.handle_storage(later, &mut wal, &mut sb, &mut blocks);
  }

  // End state: the obligation cleared, the SM holds M, the production read resumes, and serving
  // (apply/serve) is no longer gated — a fresh RequestSync now submits a serve-read.
  assert!(
    !e.sm_reconstruct_owed(),
    "the failover completed the reconstruction — the obligation cleared"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the frontier stayed at M=4 (no rewind)"
  );
  let sm = e
    .state_machine()
    .expect("state_machine() returns Some once the reconstruction completes");
  assert_eq!(sm.applied().len(), 4, "the SM now holds M's content");
  while e.poll_message().is_some() {}
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(equal_peer),
    Message::RequestSync(crate::RequestSync::new(
      e.view(),
      OpNumber::with(0),
      equal_peer,
      0xF00D,
      false,
      0,
    )),
  );
  assert_eq!(
    e.sync_serving.len(),
    1,
    "serving resumes once the SM holds M — apply/serve are no longer gated"
  );
}

#[test]
fn absent_block_response_only_re_solicits_for_pinned_donor_and_active_address() {
  // An ABSENT `BlockResponse` must re-solicit a fresh `SyncCheckpoint` ONLY when BOTH hold:
  //   (1) the absent response addresses the CURRENTLY OUTSTANDING frontier block (`m.addr() == active`);
  //   (2) the sender is the PINNED DONOR (`from == bf.donor`).
  // A stale absent (for an already-fetched address), an absent from a non-donor, or an absent for a
  // different address must all be INERT — the fetch stays pinned and the ARQ drives the re-request.
  //
  // Setup: the SM DAG is seeded locally (SM frontier drains immediately), the session-table DAG root
  // is absent from the laggard's store. After delivering the `SyncCheckpoint`, the block-fetch is armed
  // with donor = slot 0 and the outstanding address = `sessions_root`.
  let (_donor_e, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");

  let mut donor_blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);

  // Laggard store: SM DAG present, session DAG absent.
  let mut blocks = crate::block_store::MemBlockStore::new();
  {
    let mut stack = std::vec![sm_root];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(addr) = stack.pop() {
      if !seen.insert(addr) {
        continue;
      }
      let block = donor_blocks
        .read_block(addr)
        .expect("SM block present in donor store");
      for child in CountSm::block_references(&block) {
        stack.push(child);
      }
      blocks.write_block(addr, block);
    }
  }
  assert!(blocks.has_block(sm_root), "laggard holds the SM DAG");
  assert!(!blocks.has_block(sessions_root), "session DAG is absent");

  let mut e = sync_backup();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let now = Instant::ZERO;

  // Trigger the sync and capture the nonce.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(crate::Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);

  // Deliver the SyncCheckpoint from donor slot 0 (primary). The SM DAG drains locally; the fetch is
  // armed with donor=0 and the active missing address = sessions_root.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  // Drain the initial RequestBlock (the first session pull).
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "block-fetch is pinned to donor slot 0"
  );

  // Helper: count RequestSync emissions in the outbox.
  let count_resyncs = |e: &mut Endpoint<CountSm>| {
    let mut n = 0u32;
    while let Some(out) = e.poll_message() {
      if matches!(out.msg_ref(), Message::RequestSync(_)) {
        n += 1;
      }
    }
    n
  };

  // (a) Absent response for a DIFFERENT (already-fetched) address — sm_root is in the store so the
  // frontier has moved past it. `m.addr() != active` → INERT, no re-solicit.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(), // from the correct donor
    Message::BlockResponse(crate::BlockResponse::new(sm_root, None)),
  );
  assert_eq!(
    count_resyncs(&mut e),
    0,
    "(a) absent for an already-fetched address must not re-solicit"
  );
  assert_eq!(e.block_fetch_donor(), Some(0), "(a) fetch stays pinned");

  // (b) Absent for the ACTIVE address but from a NON-DONOR (slot 1). `from != bf.donor` → INERT.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)), // non-donor
    Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
  );
  assert_eq!(
    count_resyncs(&mut e),
    0,
    "(b) absent from a non-donor must not re-solicit"
  );
  assert_eq!(e.block_fetch_donor(), Some(0), "(b) fetch stays pinned");

  // (c) Absent for a DIFFERENT address AND from a non-donor (double mismatch) → INERT.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)), // non-donor
    Message::BlockResponse(crate::BlockResponse::new(sm_root, None)),
  );
  assert_eq!(
    count_resyncs(&mut e),
    0,
    "(c) absent for wrong address from non-donor must not re-solicit"
  );

  // (d) Absent for the ACTIVE address FROM the pinned donor → DOES re-solicit.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(), // donor slot 0
    Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
  );
  assert_eq!(
    count_resyncs(&mut e),
    1,
    "(d) absent for active address from the pinned donor must re-solicit"
  );
}

#[test]
fn the_active_donor_absent_keeps_the_fetch_live_and_re_solicits_each_round_trip() {
  // The bound active-donor absent KEEPS the block-fetch live and re-solicits a fresh `SyncCheckpoint`
  // IMMEDIATELY — once per pruned front, not waiting for the `sync_solicit` deadline. The fetch is NOT
  // dropped: the donor's reply names its current checkpoint, and the fresh `SyncCheckpoint` re-seeds the
  // frontier onto an un-pruned root, re-discovering every already-fetched content-addressed block locally
  // and re-pulling only the new pruned-tail delta. The re-pin window is BOUNDED on the FETCH:
  // until the fresh checkpoint lands and advances the front, DUPLICATE/DELAYED absents for that same front
  // re-solicit no more (`BlockFetch::resolicited_front`), so one pruned block cannot become an unbounded
  // broadcast storm; the single re-solicit still re-pins (the donor answers it once and the front advances
  // within a round trip). This per-front re-pin is what lets a laggard track a checkpointing-and-pruning
  // donor and converge; a deadline-paced re-pin (a full `SYNC_SOLICIT` per pruned front) lets the moving
  // target outrun it. A DUPLICATE SAME-ROOT checkpoint interleaved with the duplicate absents cannot re-arm
  // the storm: rebuilding the fetch CARRIES the re-solicit latch forward across the same-root re-pin
  // (`carry_resolicit_latch`), so an unbounded flood of same-root checkpoints releases ZERO additional
  // re-solicits — the total is O(distinct roots) = O(round-trips), never one per duplicate checkpoint or
  // absent. A genuine NEW-root checkpoint resets the latch (a real new pin) so its first absent legitimately
  // re-solicits and the laggard still converges (no strand).
  let (_donor_e, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");

  // The donor's full block store (BOTH DAGs) — the source the donor serves `RequestBlock`s from once the
  // fresh checkpoint re-pins the fetch.
  let mut donor_blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);
  assert!(
    donor_blocks.has_block(sessions_root),
    "the donor holds the session-table DAG root"
  );

  // Laggard store: SM DAG present (the SM frontier drains locally), session DAG absent (the active
  // outstanding address is `sessions_root`).
  let mut blocks = crate::block_store::MemBlockStore::new();
  {
    let mut stack = std::vec![sm_root];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(addr) = stack.pop() {
      if !seen.insert(addr) {
        continue;
      }
      let block = donor_blocks
        .read_block(addr)
        .expect("SM block present in donor store");
      for child in CountSm::block_references(&block) {
        stack.push(child);
      }
      blocks.write_block(addr, block);
    }
  }
  assert!(blocks.has_block(sm_root), "laggard holds the SM DAG");
  assert!(!blocks.has_block(sessions_root), "session DAG is absent");

  let mut e = sync_backup();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut now = Instant::ZERO;

  // A SECOND donor at a STRICTLY-HIGHER checkpoint (8) — a GENUINELY NEW root (`new_sm_root` /
  // `new_sessions_root` differ from the op-4 roots). Delivered later while the op-4-root fetch is live with
  // its latch set, this is a real new pin: `carry_resolicit_latch` must RESET the latch to `None` (a
  // different root), so its first absent legitimately re-solicits and the laggard converges (no strand).
  let (_donor8_e, _dwal8, dsb8) = donor_primary_at_checkpoint(8);
  let (new_env, new_id) = donor_envelope(&dsb8);
  let (_op8, new_sm_root, new_sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&new_env).expect("op-8 donor envelope decodes");
  assert_ne!(
    new_sessions_root, sessions_root,
    "the op-8 checkpoint is a genuinely new root (front actually changes)"
  );
  let mut donor8_blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut donor8_blocks, 8);
  // Seed the laggard's op-8 SM DAG locally (mirroring the op-4 setup) so only the op-8 SESSION frontier needs
  // a pull — making the op-8 re-pin's outstanding front a single absent-able address.
  {
    let mut stack = std::vec![new_sm_root];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(addr) = stack.pop() {
      if !seen.insert(addr) {
        continue;
      }
      let block = donor8_blocks
        .read_block(addr)
        .expect("op-8 SM block present in donor store");
      for child in CountSm::block_references(&block) {
        stack.push(child);
      }
      blocks.write_block(addr, block);
    }
  }

  // Trigger the sync (a Commit advertising checkpoint 4 > head 0) and capture the nonce.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(crate::Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);

  // Deliver the donor's `SyncCheckpoint` (donor slot 0): the SM DAG drains locally, the fetch is armed
  // with donor=0 and the active missing address = `sessions_root`.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the block-fetch is pinned to donor slot 0"
  );

  // Drain the outbox and tally both message classes: `RequestSync` re-solicits and `RequestBlock`s for
  // the GC-pruned (`sessions_root`) address.
  let drain_counts = |e: &mut Endpoint<CountSm>| {
    let (mut resyncs, mut stale_block_requests) = (0u32, 0u32);
    while let Some(out) = e.poll_message() {
      match out.msg_ref() {
        Message::RequestSync(_) => resyncs += 1,
        Message::RequestBlock(addr) if *addr == sessions_root => stale_block_requests += 1,
        _ => {}
      }
    }
    (resyncs, stale_block_requests)
  };

  // FIRST active-address absent from the pinned donor → re-solicits a fresh checkpoint AND keeps the fetch
  // live (pinned to the donor): the donor is still answering, so the fetch is not dropped.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(), // donor slot 0
    Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
  );
  let (resyncs, _) = drain_counts(&mut e);
  assert_eq!(
    resyncs, 1,
    "the first active-donor absent re-solicits exactly one fresh checkpoint"
  );
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the fetch is KEPT LIVE across the absent (not dropped) so the crossing-answer signal survives"
  );

  // DUPLICATE / DELAYED active-donor absents for the SAME still-pruned front are now SUPPRESSED: the front
  // does not dedup until the fresh checkpoint lands and re-seeds it, so without per-front suppression each
  // duplicate absent in that window would re-broadcast `RequestSync` — one pruned block becoming an
  // unbounded broadcast storm. `BlockFetch::resolicited_front` bounds it to ONE re-solicit per front:
  // a burst of duplicates re-solicits ZERO more times (the count does NOT grow with the duplicate count),
  // while the fetch stays live so the in-flight fresh checkpoint still drains.
  let mut dup_resyncs = 0u32;
  for _ in 0..5 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      primary_peer(), // donor slot 0
      Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
    );
    let (resyncs, _) = drain_counts(&mut e);
    dup_resyncs += resyncs;
  }
  assert_eq!(
    dup_resyncs, 0,
    "duplicate/delayed absents for the same pruned front re-solicit no more times (bounded re-pin window)"
  );
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the fetch stays live across the duplicate absents"
  );

  // INTERLEAVED DUPLICATE SAME-ROOT CHECKPOINTS (the case neither a marker-clear-on-checkpoint NOR a
  // born-`None`-per-fetch latch can bound). A delayed DUPLICATE `SyncCheckpoint` (same op, same nonce, same
  // `sm_root`/`sessions_root`) re-enters `begin_block_sync` and REBUILDS the `BlockFetch`; because the store
  // already holds the same DAG, the front does NOT advance (it re-pins the IDENTICAL pruned `sessions_root`).
  // Were the rebuilt fetch born with a fresh `None` latch, each duplicate checkpoint would re-open one
  // re-solicit (the next absent re-arms the new fetch) — so K duplicate checkpoints would produce O(K)
  // `RequestSync` regardless of round-trips, an attacker delivering same-root checkpoints driving the rate.
  // `carry_resolicit_latch` CARRIES the latch forward across the same-root re-pin, so the rebuilt fetch
  // INHERITS `Some(sessions_root)` (already set by the first absent above) and every duplicate checkpoint +
  // its absent burst re-solicits ZERO more — the total stays O(distinct roots) = O(round-trips). Drive MANY
  // (8) duplicate checkpoints, each followed by a burst of duplicate absents, and require zero new re-solicits.
  let dup_checkpoint = |e: &mut Endpoint<CountSm>,
                        wal: &mut TestWal,
                        sb: &mut TestSb,
                        blocks: &mut crate::block_store::MemBlockStore,
                        now: Instant| {
    e.handle_message(
      now,
      wal,
      sb,
      blocks,
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
  };
  const DUP_CHECKPOINTS: u32 = 8;
  const ABSENTS_PER_CHECKPOINT: u32 = 4;
  let mut interleaved_resyncs = 0u32;
  for _ in 0..DUP_CHECKPOINTS {
    // A delayed duplicate same-root checkpoint re-pins to the IDENTICAL still-pruned front.
    dup_checkpoint(&mut e, &mut wal, &mut sb, &mut blocks, now);
    let (resyncs, _) = drain_counts(&mut e);
    interleaved_resyncs += resyncs;
    assert_eq!(
      e.block_fetch_donor(),
      Some(0),
      "the duplicate same-root checkpoint re-pins the fetch (still pinned to the donor)"
    );
    // A burst of duplicate absents for that same re-pinned (still pruned) front: the rebuilt fetch carried the
    // already-set latch, so the burst adds no re-solicit regardless of its size.
    for _ in 0..ABSENTS_PER_CHECKPOINT {
      e.handle_message(
        now,
        &mut wal,
        &mut sb,
        &mut blocks,
        primary_peer(), // donor slot 0
        Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
      );
      let (resyncs, _) = drain_counts(&mut e);
      interleaved_resyncs += resyncs;
    }
  }
  // ZERO additional re-solicits across the whole `DUP_CHECKPOINTS × ABSENTS_PER_CHECKPOINT` flood: the carried
  // latch (set by the single absent BEFORE this loop) survives every same-root rebuild, so the count is bounded
  // by DISTINCT ROOTS (one here), NOT by the duplicate-checkpoint or absent message count. A born-`None`
  // rebuild would have produced O(DUP_CHECKPOINTS) here.
  assert_eq!(
    interleaved_resyncs, 0,
    "interleaved duplicate same-root checkpoints + absents re-solicit ZERO more (the latch is carried across the \
     same-root re-pin); {DUP_CHECKPOINTS} checkpoints x {ABSENTS_PER_CHECKPOINT} absents produced \
     {interleaved_resyncs} re-solicits"
  );
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the fetch stays live across the interleaved duplicate checkpoints and absents"
  );

  // The solicit / ARQ timer fires in the re-pin window → the still-live fetch re-requests its outstanding
  // (pruned) front while the fresh checkpoints are in flight; harmless, since the absent reply keeps the
  // fetch live and re-solicits a fresh checkpoint that re-seeds the front.
  now = now + core::time::Duration::from_millis(101);
  e.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
  let _ = drain_counts(&mut e);
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the fetch is still live after the ARQ tick (awaiting the fresh checkpoint's re-pin)"
  );

  // A fresh SAME-ROOT `SyncCheckpoint` (echoing the live nonce — `send_request_sync` does not bump it)
  // RE-PINS the fetch: it re-arms the frontier, re-discovers the already-held SM DAG, and issues a fresh
  // session pull. The latch carries (same root), so this re-pin re-solicits nothing on its own — it just
  // resumes the pull.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  let mut re_pinned_request = false;
  while let Some(out) = e.poll_message() {
    if let Message::RequestBlock(addr) = out.msg_ref()
      && *addr == sessions_root
    {
      re_pinned_request = true;
    }
  }
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the fresh same-root checkpoint re-pinned the fetch to the donor"
  );
  assert!(
    re_pinned_request,
    "the re-pinned fetch resumed: it re-requested the still-missing session block"
  );

  // GENUINE NEW-ROOT CHECKPOINT → the latch RESETS (no strand). The op-4-root fetch is still live with its
  // latch set to the op-4 `sessions_root`; a strictly-newer op-8 `SyncCheckpoint` re-pins through
  // `begin_block_sync` to a DIFFERENT root, so `carry_resolicit_latch` sees the root CHANGE and resets the
  // latch to `None`. The new pin's outstanding front is the op-8 `new_sessions_root` (the op-8 SM DAG is
  // already local), so an active-donor absent for it must FIRE A FRESH re-solicit — proving the carry never
  // strands a real re-pin.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(8),
      new_id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      new_env.clone(),
      Bytes::new(),
    )),
  );
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the new-root checkpoint re-pinned the fetch to the op-8 root"
  );
  // First absent for the op-8 front → a FRESH re-solicit (the latch was reset by the new root).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::BlockResponse(crate::BlockResponse::new(new_sessions_root, None)),
  );
  let mut new_root_resyncs = 0u32;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSync(_) = out.msg_ref() {
      new_root_resyncs += 1;
    }
  }
  assert_eq!(
    new_root_resyncs, 1,
    "a genuine new-root checkpoint resets the latch, so its first absent re-solicits afresh (no strand)"
  );

  // Drive the op-8 fetch to completion (the op-8 donor serves the session blocks) → the GC-pruned recovery
  // still CONVERGES after the new-root re-pin, proving the carry suppresses only redundant re-solicits.
  loop {
    let want = match e.block_fetch_donor() {
      Some(_) => {
        let mut req = None;
        e.handle_timeout(
          now + core::time::Duration::from_millis(101),
          &mut wal,
          &mut sb,
          &mut blocks,
        );
        now = now + core::time::Duration::from_millis(101);
        while let Some(out) = e.poll_message() {
          if let Message::RequestBlock(addr) = out.msg_ref() {
            req = Some(*addr);
          }
        }
        req
      }
      None => None,
    };
    let Some(addr) = want else { break };
    let block = donor8_blocks
      .read_block(addr)
      .expect("the op-8 donor serves every requested session block");
    blocks.write_block(addr, block.clone());
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      primary_peer(),
      Message::BlockResponse(crate::BlockResponse::new(addr, Some(block))),
    );
    for _ in 0..4 {
      e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    }
    if e.state_syncs_applied() == 1 {
      break;
    }
  }
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the GC-pruned recovery completed after the new-root checkpoint re-pinned the fetch"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(8),
    "the laggard installed the new-root (op-8) synced checkpoint"
  );
}

#[test]
fn the_active_donor_absent_keeps_a_crossing_fetch_live_and_does_not_downgrade_it() {
  // The active-donor absent KEEPS the block-fetch live and re-solicits (bounded per pruned front) for a
  // CROSS-EPOCH crossing (`require_cross_epoch`) exactly as for a same-epoch sync. Here the fetch is draining
  // a GENUINE crossing reply (a foreign config + a non-empty successor membership), so its recorded
  // `crossing_answered` bit is set — that bit, not the bare fetch presence, is the "a donor has begun
  // answering a crossing" signal. While re-pinning (the one re-solicit per front, fetch kept live):
  //   - the crossing requirement survives, AND
  //   - the crossing is NOT downgraded/cancelled by same-epoch trigger evidence
  //     (`crossing_answer_in_flight` reads the live fetch as an answered crossing).
  // Then a fresh crossing `SyncCheckpoint` re-pins the fetch and the crossing proceeds (it re-requests the
  // missing block, still `require_cross_epoch`). (A SAME-CONFIG / empty-membership fetch would NOT shield —
  // that is the sibling `a_same_config_live_fetch_does_not_shield_...` case.)
  let (_donor_e, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");

  let mut donor_blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);

  // Laggard store: SM DAG present (drains locally), session DAG absent (the active outstanding address is
  // `sessions_root`).
  let mut blocks = crate::block_store::MemBlockStore::new();
  {
    let mut stack = std::vec![sm_root];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(addr) = stack.pop() {
      if !seen.insert(addr) {
        continue;
      }
      let block = donor_blocks
        .read_block(addr)
        .expect("SM block present in donor store");
      for child in CountSm::block_references(&block) {
        stack.push(child);
      }
      blocks.write_block(addr, block);
    }
  }
  assert!(blocks.has_block(sm_root), "laggard holds the SM DAG");
  assert!(!blocks.has_block(sessions_root), "session DAG is absent");

  let mut e = sync_backup();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut now = Instant::ZERO;

  // A GENUINE crossing reply: a strictly-foreign config carrying a non-empty successor membership (the
  // content-addressed SM/session DAGs are config-independent, so the same `env`/`id` integrity holds). This
  // is what makes the live fetch a real crossing answer (`crossing_answered = true`), the only thing that
  // legitimately shields the crossing from same-epoch downgrade.
  let predecessor = genesis(3);
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid");
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor, predecessor.config_id())
      .encode_body();
  let crossing_checkpoint = |nonce: u64| {
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      successor.epoch(),
      successor.config_id(),
      ReplicaId::new(0),
      nonce,
      env.clone(),
      membership_body.clone(),
    ))
  };

  // Arm a CROSSING sync (forced + `require_cross_epoch`) directly to op 4, then deliver the genuine crossing
  // `SyncCheckpoint` at op 4 echoing its nonce: `begin_block_sync` arms the block-fetch under the crossing
  // (donor=0, active missing address = `sessions_root`). The crossing requirement is enforced only at
  // `apply_sync`, never reached in the re-pin window this test exercises.
  e.arm_cross_epoch_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "the sync is armed as a crossing"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    crossing_checkpoint(nonce),
  );
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the crossing block-fetch is pinned to donor slot 0"
  );
  assert_eq!(
    e.block_fetch_crossing_answered_for_test(),
    Some(true),
    "the fetch is draining a GENUINE crossing reply (foreign config + non-empty membership)"
  );

  let drain_counts = |e: &mut Endpoint<CountSm>| {
    let (mut resyncs, mut stale_block_requests) = (0u32, 0u32);
    while let Some(out) = e.poll_message() {
      match out.msg_ref() {
        Message::RequestSync(_) => resyncs += 1,
        Message::RequestBlock(addr) if *addr == sessions_root => stale_block_requests += 1,
        _ => {}
      }
    }
    (resyncs, stale_block_requests)
  };

  // FIRST active-address absent from the pinned donor → re-solicits a fresh checkpoint AND keeps the
  // crossing fetch live (the crossing-answer signal IS the live fetch).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(), // donor slot 0
    Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
  );
  let (resyncs, _) = drain_counts(&mut e);
  assert_eq!(
    resyncs, 1,
    "the first active-donor absent re-solicits exactly one fresh checkpoint (crossing)"
  );
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the crossing fetch is KEPT LIVE across the absent (the crossing-answer signal survives)"
  );
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "the crossing requirement survives the absent"
  );

  // DUPLICATE active-donor absents for the same still-pruned front are SUPPRESSED (per-front bound), exactly
  // as for an ordinary sync — convergence is unchanged because the in-flight fresh checkpoint still re-pins.
  let mut dup_resyncs = 0u32;
  for _ in 0..5 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      primary_peer(), // donor slot 0
      Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
    );
    let (resyncs, _) = drain_counts(&mut e);
    dup_resyncs += resyncs;
  }
  assert_eq!(
    dup_resyncs, 0,
    "duplicate absents for a crossing's same pruned front re-solicit no more times (bounded)"
  );
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the crossing fetch stays live across the duplicate absents"
  );

  // A same-epoch sync trigger arriving in the re-pin window must NOT DOWNGRADE the crossing: the live fetch
  // is draining a GENUINE crossing reply (`crossing_answered`), so `crossing_answer_in_flight` is true,
  // `crossing_is_pre_answer_speculative` is false, and the downgrade does not fire. (A Commit advertising
  // checkpoint 2 > head 0 reaches the already-syncing arm.)
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(crate::Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "the crossing is NOT downgraded by same-epoch evidence while the live fetch is answering"
  );

  // The solicit / ARQ timer fires in the re-pin window → the live fetch stays pinned (awaiting the fresh
  // checkpoint's re-pin).
  now = now + core::time::Duration::from_millis(101);
  e.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
  let _ = drain_counts(&mut e);
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the crossing fetch is still live after the ARQ tick"
  );

  // A fresh crossing `SyncCheckpoint` (echoing the live nonce) RE-PINS the crossing fetch: it re-seeds the
  // frontier, re-discovers the already-held SM DAG, and re-requests the still-missing session block.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    crossing_checkpoint(nonce),
  );
  let mut re_pinned_request = false;
  while let Some(out) = e.poll_message() {
    if let Message::RequestBlock(addr) = out.msg_ref()
      && *addr == sessions_root
    {
      re_pinned_request = true;
    }
  }
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the fresh checkpoint re-pinned the crossing fetch to the donor"
  );
  assert!(
    re_pinned_request,
    "the re-pinned crossing fetch resumed: it re-requested the still-missing session block"
  );
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "the re-pinned fetch is still a crossing"
  );
}

#[test]
fn an_sm_reconstruct_re_pin_replaces_the_fetch_so_a_later_lost_block_is_arq_retried() {
  // H1 — a NON-`begin_block_sync` re-pin replaces the live block-fetch. Sequence: an owed SM-reconstruct
  // re-pulls M's DAG (`refetch_sm_reconstruct` → `rearm_sm_reconstruct_retry`); M's pinned block is
  // GC-pruned at the donor → an active-donor ABSENT KEEPS the fetch live and re-solicits; a FRESH
  // `SyncCheckpoint` at M then re-pins via the SAME reconstruct path, REPLACING the whole `block_fetch`
  // field by construction. This test asserts a block lost AFTER the re-pin IS retransmitted on the next
  // solicit tick (the re-pin left a live fetch driving `send_request_block`, no stale marker to wedge it).
  let (mut e, mut wal, mut sb, mut blocks, sm_root_m, _m_id) = laggard_owing_sm_reconstruct_at_m();
  // M's donor (slot 0) and envelope, re-derived exactly as the helper built them.
  let (_donor_e, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env_m, id_m) = donor_envelope(&dsb);
  let nonce = e.sync_nonce_for_test();
  let now = Instant::ZERO;

  // Helper: deliver a fresh `SyncCheckpoint` at M from the pinned donor (slot 0). For an owed laggard this
  // routes to `refetch_sm_reconstruct` → `rearm_sm_reconstruct_retry`, which re-arms the fetch (M's leaf is
  // corrupt locally, so the frontier wants `sm_root_m`) and emits a `RequestBlock`.
  let deliver_repin =
    |e: &mut Endpoint<CountSm>, wal: &mut TestWal, sb: &mut StepSb, blocks: &mut MemBlockStore| {
      e.handle_message(
        now,
        wal,
        sb,
        blocks,
        primary_peer(),
        Message::SyncCheckpoint(crate::SyncCheckpoint::new(
          View::new(),
          OpNumber::with(4),
          id_m,
          crate::Epoch::new(0),
          0,
          ReplicaId::new(0),
          nonce,
          env_m.clone(),
          Bytes::new(),
        )),
      );
    };

  // (1) FIRST re-pin: the obligation re-pulls M's DAG. `Fetching`, requesting `sm_root_m`.
  deliver_repin(&mut e, &mut wal, &mut sb, &mut blocks);
  let first_req = core::iter::from_fn(|| e.poll_message()).find_map(|out| match out.msg_ref() {
    Message::RequestBlock(addr) => Some(*addr),
    _ => None,
  });
  assert_eq!(
    first_req,
    Some(sm_root_m),
    "the re-armed reconstruct fetch requests M's locally-corrupt block"
  );
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the reconstruct fetch is a live Fetching pinned to the donor"
  );

  // (2) Active-donor ABSENT for the pinned block → the absent arm KEEPS the fetch live and re-solicits.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::BlockResponse(crate::BlockResponse::new(sm_root_m, None)),
  );
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the GC-pruned reconstruct pin is kept live across the absent"
  );

  // (3) A FRESH `SyncCheckpoint` at M re-pins via the SAME reconstruct path, REPLACING the whole
  // `block_fetch` field by construction.
  deliver_repin(&mut e, &mut wal, &mut sb, &mut blocks);
  // Drain (DROP) the freshly-emitted `RequestBlock` — model it (or its answer) lost on the wire.
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the re-pin installed a live fetch"
  );

  // (4) THE H1 DISCRIMINATOR: fire the solicit ARQ past its deadline. The live fetch MUST drive
  // `send_request_block` to retransmit the lost `RequestBlock(sm_root_m)`.
  e.handle_timeout(
    now + core::time::Duration::from_millis(101),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  let retried = core::iter::from_fn(|| e.poll_message())
    .any(|out| matches!(out.msg_ref(), Message::RequestBlock(addr) if *addr == sm_root_m));
  assert!(
    retried,
    "H1: the ARQ retransmits the lost block after the reconstruct re-pin (the live fetch drives \
     send_request_block)"
  );
}

#[test]
fn an_ordinary_fetch_does_not_shield_the_crossing_an_upgrade_makes_from_a_same_epoch_downgrade() {
  // H2 — the one justified hand-clear. An ORDINARY sync has a live block-fetch (an active-donor absent
  // KEEPS it live); a higher-epoch trigger then upgrades that same sync to a crossing IN PLACE. An
  // ordinary same-epoch fetch is NOT evidence the CROSSING was answered (an ordinary checkpoint can never
  // satisfy the crossing gate), so `maybe_request_cross_epoch_catchup` must DROP it — the freshly-upgraded
  // crossing starts UN-answered and remains downgradable. Otherwise `crossing_is_pre_answer_speculative`
  // would read the ordinary fetch as already-answered and shield the speculative crossing from a
  // legitimate same-epoch downgrade — wedging the node at the old epoch on a bogus hint. This test asserts
  // the upgrade drops the ordinary fetch and a subsequent same-epoch authority message cancels the
  // crossing.
  let (env, id) = donor_envelope(&donor_primary_at_checkpoint(4).2);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");

  let mut donor_blocks = crate::block_store::MemBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);

  // Laggard store: SM DAG present (drains locally), session DAG absent (the active outstanding address is
  // `sessions_root`) — the same construction the one-shot tests use to pin a fetch then quarantine it.
  let mut blocks = crate::block_store::MemBlockStore::new();
  {
    let mut stack = std::vec![sm_root];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(addr) = stack.pop() {
      if !seen.insert(addr) {
        continue;
      }
      let block = donor_blocks.read_block(addr).expect("SM block present");
      for child in CountSm::block_references(&block) {
        stack.push(child);
      }
      blocks.write_block(addr, block);
    }
  }

  let mut e = sync_backup();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let now = Instant::ZERO;

  // (1) An ORDINARY same-epoch sync (a Commit advertising checkpoint 4 > head 0), then its same-config
  // `SyncCheckpoint`: `begin_block_sync` arms a `Fetching` pinned at `sessions_root`.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(crate::Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  while e.poll_message().is_some() {}
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "setup: the sync is ordinary (no crossing yet)"
  );

  // (2) Active-donor ABSENT for the pinned session block → the ordinary pin is KEPT LIVE (donor 0).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
  );
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the ordinary sync's pin is kept live across the absent"
  );

  // (3) A higher-epoch trigger UPGRADES the ordinary sync to a crossing IN PLACE. The H2 hand-clear drops
  // the ordinary live fetch so the crossing starts un-answered.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::EpochAhead(crate::EpochAhead::new(
      crate::Epoch::new(1),
      OpNumber::with(4),
    )),
  );
  while e.poll_message().is_some() {}
  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "the higher-epoch trigger upgraded the sync to a crossing"
  );
  assert_eq!(
    e.block_fetch_donor(),
    None,
    "H2: the upgrade DROPPED the ordinary live fetch (the crossing is un-answered, a fresh checkpoint \
     will re-pin it)"
  );

  // (4) THE H2 DISCRIMINATOR: a same-epoch authority Commit is proof the node operates at its current
  // epoch, so the higher-epoch hint was stale. With the quarantine dropped, the crossing is
  // pre-answer-speculative and MUST be cancelled. Under the inherited-marker bug it would be shielded.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(crate::Commit::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "H2: the same-epoch authority message DOWNGRADED/cancelled the crossing (the inherited dead pin did \
     NOT shield the speculative crossing)"
  );
}

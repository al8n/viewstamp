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
  ClientId, Config, Header, OpNumber, Prepare, ReadOk, ReplicaId, Request, RequestNumber,
  SlotStatus, StartViewChange, View, VsrState, Wal, WalDone, block_store::InMemoryBlockStore,
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
  fn submit_append(&mut self, id: WriteId, op: OpNumber, header: Header, body: Bytes) {
    // Evict the op that last held this ring slot (op `K - capacity`), modelling the physical wrap.
    if op.get() > self.capacity {
      self.entries.remove(&(op.get() - self.capacity));
    }
    self.entries.insert(op.get(), (header, body));
    self.head = self.head.max(op.get());
    self.done.push_back(WalDone::Appended(id));
  }
  fn submit_read(&mut self, id: ReadId, op: OpNumber) {
    self.done.push_back(match self.entries.get(&op.get()) {
      Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    });
  }
  fn truncate(&mut self, above: OpNumber) -> std::vec::Vec<WriteId> {
    self.entries.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
    std::vec::Vec::new()
  }
  fn prune(&mut self, below: OpNumber) -> std::vec::Vec<WriteId> {
    self.entries.retain(|&op, _| op >= below.get());
    std::vec::Vec::new()
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
fn a_slow_envelope_write_bounds_the_checkpoint_lane_across_view_change_windows() {
  // Replica 1 of 3, over a superblock that completes ROOT writes promptly but holds every
  // checkpoint-ENVELOPE write until the test releases it (`KindSb`) — a CONFORMING backend: the
  // trait's completion-order contract covers `submit_write` calls relative to each other only, so
  // envelope writes may lag arbitrarily behind later roots. Each window completes a state-sync
  // handshake to its envelope submission (`AwaitSnapshot`), then a StartView adoption drops the
  // re-persist correlation — orphaning the envelope, which cannot be forfeited (it is with the
  // medium) — and the durable-view root completes AROUND the held envelope, re-opening every
  // endpoint-local staging gate. Without the session's envelope fence each window adds one more
  // orphaned envelope to the medium and the session ledger, each retaining its full snapshot
  // bytes: the unbounded backlog. The fence must hold the lane at ONE outstanding envelope
  // through every window, and once the held writes are released a fresh sync must complete
  // durably (the deferral is deferral, not a wedge).
  const WINDOWS: u64 = 6;
  let (_donor, donor_storage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&donor_storage);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4); // both DAGs local: every fetch drains without a RequestBlock
  let mut e = sync_backup();
  let (wal, sb) = (TestWal::default(), KindSb::default());
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);

  let sync_to_staging = |e: &mut Endpoint<CountSm>,
                         storage: &mut Storage<TestWal, KindSb, CountSm>,
                         blocks: &mut InMemoryBlockStore,
                         view: u64| {
    e.handle_message(
      now,
      storage,
      primary_peer(),
      Message::Commit(Commit::new(
        View::with(view),
        OpNumber::with(4),
        OpNumber::with(4),
        crate::Epoch::new(0),
        0,
      )),
    );
    while e.poll_message().is_some() {}
    // Window 1 arms the ordinary out-of-reach sync (checkpoint 4 > head 0); after an adoption at
    // the checkpoint floor, later windows arm the FORCED escalation over the checkpoint-subsumed
    // sub-floor gap instead. Either way one handshake is outstanding — read its live nonce.
    let nonce = e.sync_nonce_for_test();
    e.handle_message(
      now,
      storage,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::with(view),
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
    e.storage_step(now, storage, blocks);
    while e.poll_message().is_some() {}
    while e.poll_event().is_some() {}
  };

  for k in 1..=WINDOWS {
    let (view, next_view) = (3 * (k - 1), 3 * k);
    sync_to_staging(&mut e, &mut storage, &mut blocks, view);
    assert!(
      storage.checkpoints_in_flight() <= 1,
      "window {k}: the envelope lane grew past its bound ({} envelope writes outstanding)",
      storage.checkpoints_in_flight(),
    );
    if k == 1 {
      assert_eq!(
        e.pending_checkpoint_is_sync_for_test(),
        Some(true),
        "window 1: the handshake staged the re-persist to its envelope step"
      );
    } else {
      // Later windows: the handshake completes and the install is RETAINED, but its staging
      // DEFERS behind the orphaned envelope still on the medium — nothing new is submitted.
      assert_eq!(
        e.pending_checkpoint_is_sync_for_test(),
        None,
        "window {k}: staging deferred while the orphaned envelope drains"
      );
      assert!(
        e.sync_target_for_test().is_some(),
        "window {k}: the deferred sync stays armed (the cadence re-drives it)"
      );
    }
    // The adoption of the next view drops the re-persist correlation at its envelope step (only a
    // staged ROOT defers view transitions), orphaning the in-flight envelope. The StartView is the
    // truthful one a view-`next_view` primary at the durable checkpoint 4 sends: head 4, commit 4,
    // an empty tail above the checkpoint floor 4.
    e.handle_message(
      now,
      &mut storage,
      primary_peer(),
      Message::StartView(
        crate::StartView::new(
          View::with(next_view),
          OpNumber::with(4),
          OpNumber::with(4),
          crate::Epoch::new(0),
          0,
          ReplicaId::new(0),
          std::vec::Vec::new(),
        )
        .with_checkpoint_op(OpNumber::with(4)),
      ),
    );
    // The durable-view root completes AROUND the held envelope (kind-scoped ordering — the
    // contract's actual latitude), restoring Normal at the new view with every endpoint-local
    // staging gate clear.
    storage.sb_mut().flush_roots();
    e.storage_step(now, &mut storage, &mut blocks);
    while e.poll_message().is_some() {}
    while e.poll_event().is_some() {}
    assert_eq!(e.view(), View::with(next_view), "window {k}: adopted view");
    assert_eq!(e.status(), Status::Normal, "window {k}: Normal again");
    assert!(
      storage.checkpoints_in_flight() <= 1,
      "window {k}: the envelope lane grew past its bound after the adoption ({} outstanding)",
      storage.checkpoints_in_flight(),
    );
    assert!(
      storage.sb_mut().env_inflight.len() <= 1,
      "window {k}: the backend holds more than one envelope write ({} held)",
      storage.sb_mut().env_inflight.len(),
    );
  }

  // Release the held envelope: the orphan completes (settling out of the session ledger with no
  // live correlation — tolerated), the lane empties, and a fresh handshake now runs to a DURABLE
  // synced checkpoint: envelope → root → install. The fence never wedged the lane.
  storage.sb_mut().flush_envelopes();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(storage.checkpoints_in_flight(), 0, "the orphan drained");
  sync_to_staging(&mut e, &mut storage, &mut blocks, 3 * WINDOWS);
  assert_eq!(
    e.pending_checkpoint_is_sync_for_test(),
    Some(true),
    "the drained lane admits the fresh re-persist"
  );
  for _ in 0..4 {
    storage.sb_mut().flush_envelopes();
    storage.sb_mut().flush_roots();
    e.storage_step(now, &mut storage, &mut blocks);
    while e.poll_message().is_some() {}
    while e.poll_event().is_some() {}
    if !storage.has_inflight() {
      break;
    }
  }
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the released lane carried the synced checkpoint to durability"
  );
  assert!(
    e.sync_target_for_test().is_none(),
    "the completed sync tore down its handshake"
  );
  assert!(!storage.has_inflight(), "the medium quiesced");
}

#[test]
fn stale_checkpoint_prepare_triggers_request_sync() {
  // A `Prepare` (not just a Commit) carrying checkpoint_op > our head also triggers the sync — the
  // this commit signal closes the last trigger gap for a backup that only ever hears Prepares.
  let mut e = sync_backup();
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  e.handle_message(now, &mut storage, primary_peer(), prepare_ck(9, 8, 8));
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  for op in 1..=8 {
    e.handle_message(now, &mut storage, primary_peer(), prepare(op, 0));
    e.storage_step(now, &mut storage, &mut blocks);
  }
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut storage,
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  let (mut e, mut storage) = donor_primary_at_checkpoint(2);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  while e.poll_message().is_some() {} // drain prepares/replies from the warm-up
  e.handle_message(
    now,
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks); // the checkpoint read completes → ship SyncCheckpoint
  let mut shipped = None;
  while let Some(out) = e.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      shipped = Some((out.to(), s.clone()));
    }
  }
  let (to, s) = shipped.expect("primary ships a SyncCheckpoint");
  assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(2))));
  assert_eq!(s.checkpoint_op(), OpNumber::with(2));
  assert_eq!(s.checkpoint_id(), storage.sb().state().checkpoint_id());
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
  let (mut e, mut storage) = donor_primary_at_checkpoint(2);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    solicit(0xAAAA),
  );
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    solicit(0xBBBB),
  );
  assert_eq!(
    e.sync_serving.len(),
    1,
    "one outstanding serve per requester — the repeat solicit must not stack a second read"
  );
  e.storage_step(now, &mut storage, &mut blocks); // the single serve-read completes
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
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    solicit(0xCCCC),
  );
  e.storage_step(now, &mut storage, &mut blocks);
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
    let (mut e, mut storage) = donor_primary_at_checkpoint(2);
    let mut blocks = crate::block_store::InMemoryBlockStore::new();
    while e.poll_message().is_some() {} // drain the warm-up
    e.handle_message(
      now,
      &mut storage,
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
    e.storage_step(now, &mut storage, &mut blocks); // clean read completes → ship SyncCheckpoint
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
      storage.sb().state().checkpoint_id(),
      "the served id is the donor's durable checkpoint id"
    );
  }

  // Corrupt case: the read returns bytes that PARSE (same op bound) but hash to a DIFFERENT id than the
  // durable root — the serve path must DROP it (no SyncCheckpoint).
  {
    let (mut e, mut storage) = donor_primary_at_checkpoint(2);
    let mut blocks = crate::block_store::InMemoryBlockStore::new();
    while e.poll_message().is_some() {} // drain the warm-up
    // Sanity: the genuine snapshot hashes to the durable id (so the corruption is the only difference).
    let (_genuine, durable_id) = donor_envelope(&storage);
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
    storage.sb_mut().checkpoint = Some((OpNumber::with(2), corrupt_env));
    assert_eq!(
      storage.sb().state().checkpoint_id(),
      durable_id,
      "the durable root id is unchanged by the snapshot-region corruption"
    );
    e.handle_message(
      now,
      &mut storage,
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
    e.storage_step(now, &mut storage, &mut blocks); // the corrupt read completes → must be DROPPED
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(e.poll_message().is_none(), "nothing newer → silent");
}

#[test]
fn a_slot_shifted_member_soliciting_from_a_far_config_is_served() {
  // The donor-side half of the far-behind rejoin (finding: a retained member offline across three
  // legal changes can never re-sync). A SLOT-SHIFTED requester binds `from` to its CURRENT slot (the
  // transport resolves its stable id in the donor's active membership) but stamps its OLD slot as
  // `claimed`, so the strict binding (`sender_is_member`) fails and admission falls to the cross-epoch
  // relaxation. That relaxation no longer requires the claimed `config_id` to be in the donor's
  // two-deep lineage ring: a member stranded across MORE than that window carries a `config_id` the
  // donor no longer recognizes, yet it is exactly the member that must be served to rejoin. Serving is
  // safe at any config age — the reply grants the requester no authority and is content-verified on
  // install — so the donor answers a solicitation whose `config_id` is a far, unrecognized ancestor.
  let now = Instant::ZERO;
  let (mut donor, mut storage) = donor_primary_at_checkpoint(2);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  while donor.poll_message().is_some() {} // drain warm-up

  // A recovery RequestSync at the donor's checkpoint from member slot 2 (its resolved `from`), stamping
  // a DIFFERENT old slot (1) — the slot-shift shape — and a FAR config_id the donor does not recognize
  // (not its own, not in its lineage ring). `from` = the transport-resolved current slot 2.
  const FAR_CONFIG: u128 = 0xFA2_FA2_FA2;
  assert!(
    !donor.in_lineage_for_test(FAR_CONFIG),
    "the solicited config is outside the donor's lineage — the pre-fix rejection point"
  );
  donor.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)), // the transport-authenticated CURRENT slot
    Message::RequestSync(crate::RequestSync::new(
      donor.view(),
      OpNumber::with(2),
      ReplicaId::new(1), // the stamped OLD slot — differs from `from`, so the strict path fails
      0xF00D,
      true, // recovery peer-fetch — served at/above our checkpoint
      FAR_CONFIG,
    )),
  );
  donor.storage_step(now, &mut storage, &mut blocks); // checkpoint read completes → ship SyncCheckpoint
  let mut served = None;
  while let Some(out) = donor.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      served = Some((out.to(), s.clone()));
    }
  }
  // FAIL-BEFORE: with the `in_lineage(config_id)` conjunct restored, the far config fails admission and
  // the donor serves nothing (the slot-shifted far-behind member strands). Served now: addressed to the
  // requester's resolved current slot, carrying the donor's checkpoint.
  let (to, s) = served.expect("the slot-shifted far-config solicitation IS served");
  assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(2))));
  assert_eq!(s.checkpoint_op(), OpNumber::with(2));
  assert_eq!(s.nonce(), 0xF00D);
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
  let (mut donor, mut storage) = donor_primary_at_checkpoint(2);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  while donor.poll_message().is_some() {} // drain warm-up

  // (a) A RECOVERY request at the SAME checkpoint (op 2) IS served.
  donor.handle_message(
    now,
    &mut storage,
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
  donor.storage_step(now, &mut storage, &mut blocks); // checkpoint read completes → ship SyncCheckpoint
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
    &mut storage,
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
  donor.storage_step(now, &mut storage, &mut blocks);
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
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let wal = TestWal {
    entries: BTreeMap::new(),
    head: 2, // head == checkpoint_op → empty tail; isolates the checkpoint path
    done: VecDeque::new(),
  };
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 2);
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // Drive past the per-op retry budget so it escalates to a peer fetch (pumping the recover-retry
  // timer each round — the timer owns the read-retry budget).
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
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
  let (mut peer, mut pstorage) = donor_primary_at_checkpoint(2);
  let mut pblocks = crate::block_store::InMemoryBlockStore::new();
  while peer.poll_message().is_some() {}
  peer.handle_message(
    now,
    &mut pstorage,
    Peer::Replica(ReplicaId::new(1)),
    Message::RequestSync(req),
  );
  peer.storage_step(now, &mut pstorage, &mut pblocks);
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
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(answer),
  );
  e.block_step(now, &mut storage, &mut blocks);
  // Drive the durable re-persist to completion: flush the scripted superblock each round so the two staged
  // writes (snapshot, then the root) surface and `on_sb_done` lands the root, completing recovery. (The
  // node stays Recovering until the root is durable — the install + flip-to-Normal defer to `on_sb_done`.)
  for _ in 0..16 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  // Trigger sync (Commit advertising checkpoint_op=4), capture the nonce it used.
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks); // drive the durable re-persist (TestSb synchronous)
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
    storage.sb().state().checkpoint_op(),
    OpNumber::with(4),
    "synced checkpoint is now durable"
  );
  assert_eq!(storage.sb().state().checkpoint_id(), id);
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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4); // the laggard already holds M's complete DAG (immediate drain)
  blocks.script_flush_fault(1); // the FIRST durability barrier faults; the next succeeds
  let now = Instant::ZERO;
  // Trigger the sync (a Commit advertising checkpoint_op=4) and capture its nonce.
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
  // The flush faulted → NOTHING advanced: no durable checkpoint, the in-memory frontier untouched, but
  // the verified install is RETAINED as a local-retry obligation (NOT dropped).
  assert_eq!(
    storage.sb().state().checkpoint_op(),
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
  e.sync_timeouts(later, &mut storage);
  e.storage_step(later, &mut storage, &mut blocks);
  e.storage_step(later, &mut storage, &mut blocks); // drive the now-staged durable re-persist
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
    storage.sb().state().checkpoint_op(),
    OpNumber::with(4),
    "the synced checkpoint is now durable after the retry"
  );
  assert_eq!(storage.sb().state().checkpoint_id(), id);
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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4); // the laggard already holds M's complete DAG (immediate drain)
  // A block reachable from NOTHING — neither a durable checkpoint (the laggard has none yet) nor the
  // retained install's DAG. The GC sweep below must free it, proving the sweep actually ran (not a no-op).
  blocks.put(Bytes::from_static(b"unreferenced-garbage-block"));
  blocks.script_flush_fault(1); // the FIRST durability barrier faults; the next succeeds
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(
    e.install_flush_retry_owed(),
    "the verified install is RETAINED (flush faulted) — owed, not yet staged"
  );
  let held_before = blocks.len();

  // GC fires BEFORE the local flush retry. The retained install's DAG must SURVIVE (it is a live root); the
  // unreferenced garbage block must be FREED (the sweep ran). Were the install not a GC root, its blocks
  // would be swept here and the retry would re-persist a checkpoint naming freed blocks.
  e.gc_blocks_for_test(&mut storage);
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    blocks.len(),
    held_before - 1,
    "GC swept exactly the unreferenced garbage block — the retained install's DAG survived"
  );

  // The donor is SILENT — fire ONLY the local retry. Its flush now succeeds and stages the re-persist; the
  // SAME verified checkpoint installs (its DAG was never swept) and no committed state is lost.
  let later = now + core::time::Duration::from_millis(150);
  e.sync_timeouts(later, &mut storage);
  e.storage_step(later, &mut storage, &mut blocks);
  e.storage_step(later, &mut storage, &mut blocks);
  assert!(
    !e.install_flush_retry_owed(),
    "the retry consumed the retained install once the flush succeeded"
  );
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(
    storage.sb().state().checkpoint_op(),
    OpNumber::with(4),
    "the synced checkpoint is durable after the post-GC retry"
  );
  assert_eq!(storage.sb().state().checkpoint_id(), id);
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
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("the donor envelope decodes");

  // The donor's full block store (BOTH DAGs) — the source the donor serves `RequestBlock`s from.
  let mut donor_blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);
  assert!(
    donor_blocks.has_block(sessions_root),
    "the donor holds the session-table DAG root"
  );

  // The laggard's store: seed ONLY the SM DAG (walk it from `sm_root` in the donor store), so the SM
  // frontier drains locally; the session DAG is deliberately ABSENT.
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
      blocks.put(block);
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
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut now = Instant::ZERO;

  // Trigger the sync (a Commit advertising checkpoint 4 > head 0), capture the nonce.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
  e.handle_timeout(now, &mut storage);
  e.block_step(now, &mut storage, &mut blocks);
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
        now = now + core::time::Duration::from_millis(101);
        e.handle_timeout(now, &mut storage);
        e.block_step(now, &mut storage, &mut blocks);
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
    blocks.put(block.clone());
    e.handle_message(
      now,
      &mut storage,
      primary_peer(),
      Message::BlockResponse(crate::BlockResponse::new(addr, Some(block))),
    );
    e.block_step(now, &mut storage, &mut blocks);
    for _ in 0..4 {
      e.storage_step(now, &mut storage, &mut blocks);
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
  let (_donor, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  // The laggard: replica 1 of 3 over CountSm with a HUGE checkpoint interval (so committing its own
  // little band does NOT auto-checkpoint and race the sync's persist — it stays at checkpoint 0).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  // Give the laggard a small live WAL band (ops 1,2) below the synced point so the prune is OBSERVABLE.
  let wal = TestWal::default();
  let sb = StepSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  for op in 1..=2u64 {
    e.handle_message(now, &mut storage, primary_peer(), prepare(op, 0));
    e.storage_step(now, &mut storage, &mut blocks);
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  while e.poll_message().is_some() {}
  assert!(
    storage.wal_mut().entries.contains_key(&1) && storage.wal_mut().entries.contains_key(&2),
    "the laggard holds a live WAL band {{1,2}} before syncing"
  );
  // Trigger a sync to checkpoint 4 (> head 2), then deliver the SyncCheckpoint → STAGE.
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
    storage.wal_mut().entries.contains_key(&1) && storage.wal_mut().entries.contains_key(&2),
    "the WAL is NOT pruned at STAGE (the destructive prune is deferred to the install)"
  );
  // Run the staged install's durability barrier off the pump; only its clean completion submits the
  // snapshot write (step 1).
  e.storage_step(now, &mut storage, &mut blocks);
  // Complete step 1 (snapshot durable → root submitted), still NO install (the root is now in flight).
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
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
    storage.wal_mut().entries.contains_key(&1) && storage.wal_mut().entries.contains_key(&2),
    "the WAL is still NOT pruned after step 1 (the root is not yet durable)"
  );
  // Complete step 2 (the SYNC ROOT durable) → INSTALL fires ATOMICALLY: everything advances together.
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
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
    !storage.wal_mut().entries.contains_key(&1) && !storage.wal_mut().entries.contains_key(&2),
    "the WAL is pruned at the synced point only AFTER the install (durable-before-install)"
  );
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
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
  let (_donor, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  // The laggard: replica 1 of 3 over CountSm with a HUGE checkpoint interval (so its own band does not
  // auto-checkpoint and race the sync persist — it stays at its old durable checkpoint 0).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let wal = TestWal::default();
  let sb = StepSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  // The laggard (replica 1 of 3) holds a live WAL band {1,2} below the synced point.
  let mut storage = Storage::new(wal, sb);
  for op in 1..=2u64 {
    e.handle_message(now, &mut storage, primary_peer(), prepare(op, 0));
    e.storage_step(now, &mut storage, &mut blocks);
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  while e.poll_message().is_some() {}
  // Trigger + STAGE a sync to checkpoint 4 (> head 2). The trigger Commit carries commit=0, so the
  // laggard does NOT learn a commit above its head (a known-commit above op would, correctly, fail-stop
  // canonical-log selection — that hazard is orthogonal to this test).
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  // Run the staged install's durability barrier off the pump; only its clean completion submits the
  // snapshot write.
  e.storage_step(now, &mut storage, &mut blocks);
  // Advance step 1 (snapshot durable → root submitted) but withhold the ROOT (it stays in flight).
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
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
  e.handle_timeout(later, &mut storage); // primary_idle → SVC(view 1), own bit
  e.handle_message(
    later,
    &mut storage,
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
  storage.sb_mut().flush();
  e.storage_step(later, &mut storage, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the sync installed: in-memory checkpoint_op advanced to the synced point"
  );
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
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
  e.handle_timeout(later2, &mut storage);
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
fn an_orphaned_sync_repersist_root_enters_the_recovery_fetch_at_its_landing() {
  // A staged re-persist ROOT (AwaitRoot) whose correlation a teardown drops while the write is
  // with the backend — the backstop arm of `reset_for_view_transition`, reachable by any
  // teardown path outside the `sync_repersist_root_staged` deferrals. The abandon inside that
  // arm cannot touch the submitted front, so the root lands later: same incarnation, no live
  // correlation, naming a synced checkpoint this endpoint NEVER INSTALLED (the drop also
  // discarded the staged install), above a commit floor it may hold no log band toward. The
  // landing must not pass as stale: the durable root now leads the in-memory pointer, and the
  // one clean exit is the recovery peer-fetch — reconciliation before further participation —
  // whose install then advances the pointer to the landed frontier and retires the debt.
  let (_donor, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let wal = TestWal::default();
  let sb = StepSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  // The laggard holds a live WAL band {1,2} below the synced point; the trigger Commit carries
  // commit=0, so its applied frontier stays at 0 — strictly below the synced checkpoint.
  for op in 1..=2u64 {
    e.handle_message(now, &mut storage, primary_peer(), prepare(op, 0));
    e.storage_step(now, &mut storage, &mut blocks);
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  e.storage_step(now, &mut storage, &mut blocks);
  // Snapshot durable → the re-persist ROOT is submitted and stays in flight (StepSb withholds it).
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(
    e.sync_repersist_root_staged(),
    "the re-persist root is staged and in flight"
  );

  // The teardown that orphans it: the shared reset drops the SyncRepersist correlation at every
  // step, abandoning a root the medium still owes (the abandon inside the backstop arm no-ops on
  // the submitted front) and clearing the staged install and the sync handshake with it.
  e.reset_for_view_transition(now, &mut storage);
  assert!(e.pending_checkpoint.is_none(), "the correlation is gone");
  assert!(
    e.sync_target_for_test().is_none() && e.pending_install.is_none(),
    "the staged install and the sync handshake died with the correlation"
  );

  // The orphaned root lands: uncorrelated, checkpoint-role, frontier 4 past the applied floor 0.
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
    OpNumber::with(4),
    "the durable root advanced to the synced checkpoint the orphan carried"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "the in-memory pointer holds until the reconciling install delivers the state"
  );
  assert_eq!(
    e.inherited_frontier,
    Some(OpNumber::with(4)),
    "the owed catch-up is recorded — the lockstep window stays open, in release too"
  );
  assert_eq!(
    e.repersist_orphan,
    Some(OpNumber::with(4)),
    "the landing classified as an orphaned re-persist (checkpoint role, frontier past commit_min)"
  );
  assert_eq!(
    e.commit_max(),
    OpNumber::with(4),
    "the landed commit frontier was absorbed"
  );
  assert_eq!(
    e.status(),
    Status::Recovering,
    "the endpoint entered recovery instead of participating over state it does not hold"
  );
  let refetch_nonce = captured_sync_nonce(&mut e);
  assert_eq!(
    e.sync_target_for_test(),
    Some(4),
    "the reconciling fetch is armed at the landed frontier — no reply below it can install"
  );

  // The reconciliation completes: a donor answers the re-fetch, the re-persist runs while
  // Recovering (the staged-write peel routes its completions), and the install + recovery
  // completion land the endpoint Normal at the synced point.
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      refetch_nonce,
      env,
      Bytes::new(),
    )),
  );
  e.block_step(now, &mut storage, &mut blocks);
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the fetched install advanced the pointer to the landed frontier"
  );
  assert_eq!(e.status(), Status::Normal, "recovery completed");
  assert!(
    e.repersist_orphan.is_none(),
    "reaching the frontier retired the owed reconciliation"
  );
  assert!(e.inherited_frontier.is_none(), "nothing left owed");
  assert_eq!(
    e.state_machine_ref().applied().len(),
    4,
    "the SM holds the synced state the durable root names"
  );
  assert_eq!(e.state_syncs_applied(), 1, "the reconciling sync applied");
}

/// Build the restart-in-place store the mid-recovery orphan-landing tests recover over: a backup
/// that installed a synced checkpoint L=4, then staged a second re-persist to M=8 whose ROOT is
/// still with the medium when the process dies. Returns the live storage (holding the in-flight
/// M root), the shared block store (L's DAG seeded last), the M donor's envelope + id, and the
/// config the successor recovers under.
fn store_with_orphan_root_in_flight() -> (
  Storage<TestWal, KindSb, CountSm>,
  InMemoryBlockStore,
  Bytes,
  u128,
  Config,
) {
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let wal = TestWal::default();
  let mut sb0 = TestSb::default();
  crate::format(&cfg, &genesis(3), &wal, &mut sb0).expect("format the genesis store");
  // Re-home the formatted root under the kind-split superblock so ROOT writes stay in flight until
  // an explicit `flush_roots` — the window the restart lands inside.
  let sb = KindSb {
    state: sb0.state(),
    ..KindSb::default()
  };
  let mut blocks = InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let now = Instant::ZERO;
  let mut e = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover the formatted store")
    .expect_active();
  assert_eq!(
    e.status(),
    Status::Normal,
    "a formatted backup resumes Normal"
  );
  while e.poll_message().is_some() {}

  // Sync #1 installs L=4 end to end (envelope, root, install), so the durable root names L.
  let (_d4, d4s) = donor_primary_at_checkpoint(4);
  let (env4, id4) = donor_envelope(&d4s);
  seed_donor_blocks(&mut blocks, 4);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush_envelopes();
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush_roots();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the first sync installed: the durable root names L=4"
  );
  assert_eq!(e.status(), Status::Normal);
  while e.poll_message().is_some() {}

  // Sync #2 stages the re-persist to M=8: envelope durable, ROOT submitted and withheld.
  let (_d8, d8s) = donor_primary_at_checkpoint(8);
  let (env8, id8) = donor_envelope(&d8s);
  seed_donor_blocks(&mut blocks, 8);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(8),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(8),
      id8,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env8.clone(),
      Bytes::new(),
    )),
  );
  e.block_step(now, &mut storage, &mut blocks);
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush_envelopes();
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(
    e.sync_repersist_root_staged(),
    "the M=8 re-persist root is staged and in flight"
  );
  drop(e); // the process dies; the session (and the in-flight M root) live on
  // Re-seed L=4's DAG: driving the M=8 donor swept it from the shared store (the donor's own GC
  // marks only from its live roots), and the successor's local restore of L walks it. The M
  // donor's DAG is swept in turn here; a test that installs M re-seeds it first.
  seed_donor_blocks(&mut blocks, 4);
  (storage, blocks, env8, id8, cfg)
}

#[test]
fn a_root_landing_mid_recovery_holds_the_exit_until_its_frontier_is_installed() {
  // A dead incarnation's re-persist root M=8 lands while the successor's recovery is already
  // rebuilding from the older durable checkpoint L=4 (checkpoint read verified, tail reads
  // resolved, reconstruction running). The landing latches the owed reconciliation, and the
  // recovery must not settle ANY terminal status over it: the completion re-latches the peer
  // fetch at M, and only the install of M's snapshot lets the replica resume Normal. Without the
  // completion-side check the recovery finishes at L and resumes Normal with the debt still owed
  // — participating over state the durable root supersedes.
  let (mut storage, mut blocks, env8, id8, cfg) = store_with_orphan_root_in_flight();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(3), 1, CountSm::default(), &mut storage)
    .expect("recover over the live store")
    .expect_active();
  assert_eq!(r.status(), Status::Recovering);
  assert_eq!(
    r.checkpoint_op(),
    OpNumber::with(4),
    "the recovery baselines on the landed root L"
  );

  // The recovery begins against L: the checkpoint read verifies against the still-L durable
  // root, and the reconstruct walk is now in flight (queued on the block lane).
  r.handle_storage(now, &mut storage);
  assert_eq!(r.status(), Status::Recovering);

  // M lands mid-recovery: the owed reconciliation latches, and the recovery keeps going.
  storage.sb_mut().flush_roots();
  r.handle_storage(now, &mut storage);
  assert_eq!(
    r.repersist_orphan,
    Some(OpNumber::with(8)),
    "the landing latched the orphaned re-persist debt while recovering"
  );
  assert_eq!(r.status(), Status::Recovering);

  // The reconstruction of L completes and the recovery reaches its completion decision. The debt
  // is still owed, so no terminal transition may happen: the recovery re-latches as the peer
  // fetch at M instead of resuming Normal at L.
  for _ in 0..4 {
    r.block_step(now, &mut storage, &mut blocks);
    r.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    r.status(),
    Status::Recovering,
    "recovery must not settle a terminal status while the landed frontier is uninstalled"
  );
  assert!(
    r.awaiting_peer_checkpoint_for_test(),
    "the completion re-latched the recovery as the reconciling peer fetch"
  );
  assert_eq!(
    r.sync_target_for_test(),
    Some(8),
    "the re-latched fetch targets the landed frontier"
  );
  let mut nonce = None;
  let (mut saw_dvc, mut saw_sv) = (false, false);
  while let Some(out) = r.poll_message() {
    match out.msg_ref() {
      Message::RequestSync(rs) => nonce = Some(rs.nonce()),
      Message::DoViewChange(_) => saw_dvc = true,
      Message::StartView(_) => saw_sv = true,
      _ => {}
    }
  }
  assert!(
    !saw_dvc && !saw_sv,
    "no view participation is emitted while the reconciliation is owed"
  );

  // A donor answers at M: the install advances the pointer to the landed frontier, retires the
  // debt, and ONLY THEN does recovery complete to Normal. (Re-seed M's DAG first: the L re-seed
  // above swept it, and the restore of L that needed L's DAG has completed.)
  seed_donor_blocks(&mut blocks, 8);
  r.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(8),
      id8,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce.expect("the re-latched fetch solicited"),
      env8,
      Bytes::new(),
    )),
  );
  r.block_step(now, &mut storage, &mut blocks);
  r.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush_envelopes();
  r.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush_roots();
  r.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    r.checkpoint_op(),
    OpNumber::with(8),
    "the reconciling install advanced the pointer to the landed frontier"
  );
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovery completed after the install"
  );
  assert!(r.repersist_orphan.is_none(), "the install retired the debt");
  assert!(r.inherited_frontier.is_none(), "nothing left owed");
  assert_eq!(
    r.state_machine_ref().applied().len(),
    8,
    "the SM holds the synced state the durable root names"
  );
  // The ordering pin over the whole schedule: the replica never became Normal before M's
  // snapshot was installed.
  let events: std::vec::Vec<Event> = core::iter::from_fn(|| r.poll_event()).collect();
  let installed = events
    .iter()
    .position(|ev| matches!(ev, Event::StateSyncCompleted(op) if op.get() == 8))
    .expect("the reconciling sync completed");
  let first_normal = events
    .iter()
    .position(|ev| matches!(ev, Event::StatusChanged(Status::Normal)))
    .expect("the replica resumed Normal at the end");
  assert!(
    first_normal > installed,
    "Normal was reached only after the landed frontier's snapshot installed"
  );
}

#[test]
fn a_root_landing_mid_fetch_raises_the_fetch_target_to_its_frontier() {
  // A dead incarnation's re-persist root M=8 lands while the successor's recovery is already in
  // the PEER-FETCH phase (its own checkpoint reads exhausted; the fetch armed at its own L=4).
  // The landing must retarget the in-flight fetch at the landed frontier: the solicitation then
  // asks donors for a checkpoint that subsumes the durable root, instead of soliciting L forever
  // while the timeline admission refuses every below-M reply.
  let (mut storage, mut blocks, env8, id8, cfg) = store_with_orphan_root_in_flight();
  // The local L envelope is gone: every checkpoint read faults, so the recovery escalates.
  storage.sb_mut().checkpoints.remove(&4);
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(3), 1, CountSm::default(), &mut storage)
    .expect("recover over the live store")
    .expect_active();
  assert_eq!(r.status(), Status::Recovering);
  // Burn the checkpoint-read budget on the retry cadence until the peer fetch arms.
  let mut t = now;
  for _ in 0..(RECOVER_READ_RETRIES as usize + 4) {
    r.storage_step(t, &mut storage, &mut blocks);
    if r.awaiting_peer_checkpoint_for_test() {
      break;
    }
    if let Some(deadline) = r.poll_timeout() {
      t = deadline;
      r.handle_timeout(t, &mut storage);
    }
  }
  assert!(
    r.awaiting_peer_checkpoint_for_test(),
    "the exhausted checkpoint read escalated to the peer fetch"
  );
  assert_eq!(
    r.sync_target_for_test(),
    Some(4),
    "the fetch first targets the replica's own durable checkpoint"
  );

  // M lands mid-fetch: the debt latches AND the in-flight fetch is retargeted at its frontier.
  storage.sb_mut().flush_roots();
  r.storage_step(t, &mut storage, &mut blocks);
  assert_eq!(
    r.repersist_orphan,
    Some(OpNumber::with(8)),
    "the landing latched the orphaned re-persist debt while fetching"
  );
  assert_eq!(
    r.sync_target_for_test(),
    Some(8),
    "the landing raised the in-flight fetch's target to the landed frontier"
  );
  assert_eq!(r.status(), Status::Recovering);

  // The raise governs donors only through the WIRE: the retarget's re-solicit must advertise the
  // raised floor itself (a donor gates its serve on the advertised value, not on this endpoint's
  // internal target), so donors in [4, 8) stay silent instead of answering with replies the
  // timeline admission then refuses.
  let mut nonce = None;
  let mut advertised = None;
  while let Some(out) = r.poll_message() {
    if let Message::RequestSync(rs) = out.msg_ref() {
      nonce = Some(rs.nonce());
      advertised = Some(rs.checkpoint_op().get());
    }
  }
  assert_eq!(
    advertised,
    Some(8),
    "the re-solicit advertises the raised floor on the wire"
  );
  // A donor answers at the raised target; the install retires the debt and recovery completes.
  // (Re-seed M's DAG: the helper's L re-seed swept it, and this recovery never walks L's.)
  seed_donor_blocks(&mut blocks, 8);
  r.handle_message(
    t,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(8),
      id8,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce.expect("the fetch solicited"),
      env8,
      Bytes::new(),
    )),
  );
  r.block_step(t, &mut storage, &mut blocks);
  r.storage_step(t, &mut storage, &mut blocks);
  storage.sb_mut().flush_envelopes();
  r.storage_step(t, &mut storage, &mut blocks);
  storage.sb_mut().flush_roots();
  r.storage_step(t, &mut storage, &mut blocks);
  assert_eq!(r.checkpoint_op(), OpNumber::with(8));
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovery completed at the landed frontier"
  );
  assert!(r.repersist_orphan.is_none(), "the install retired the debt");
}

#[test]
fn a_below_target_reply_cannot_pin_or_displace_the_retargeted_recovery_fetch() {
  // The retarget preserves the solicitation nonce, so a donor still at the OLD floor L=4 keeps
  // answering the old solicitation with fresh-looking replies. Every install below the landed
  // frontier M=8 is refused by the timeline admission at the very end of the transfer — so a
  // below-target reply admitted at the ingress could only arm (or wholesale REPLACE) a transfer
  // whose entire DAG is walked and then refused, displacing the one transfer that can install,
  // once per delivery. The ingress must refuse it up front, before it can touch the transfer,
  // exactly as the Normal-status ingress does.
  let (mut storage, mut blocks, env8, id8, cfg) = store_with_orphan_root_in_flight();
  // The local L envelope is gone: every checkpoint read faults, so the recovery escalates.
  storage.sb_mut().checkpoints.remove(&4);
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, genesis(3), 1, CountSm::default(), &mut storage)
    .expect("recover over the live store")
    .expect_active();
  assert_eq!(r.status(), Status::Recovering);
  // Burn the checkpoint-read budget on the retry cadence until the peer fetch arms at L=4.
  let mut t = now;
  for _ in 0..(RECOVER_READ_RETRIES as usize + 4) {
    r.storage_step(t, &mut storage, &mut blocks);
    if r.awaiting_peer_checkpoint_for_test() {
      break;
    }
    if let Some(deadline) = r.poll_timeout() {
      t = deadline;
      r.handle_timeout(t, &mut storage);
    }
  }
  assert!(
    r.awaiting_peer_checkpoint_for_test(),
    "the exhausted checkpoint read escalated to the peer fetch"
  );
  // M=8 lands mid-fetch and retargets the solicitation.
  storage.sb_mut().flush_roots();
  r.storage_step(t, &mut storage, &mut blocks);
  assert_eq!(
    r.sync_target_for_test(),
    Some(8),
    "the landing raised the in-flight fetch's target to the landed frontier"
  );
  let mut nonce = None;
  while let Some(out) = r.poll_message() {
    if let Message::RequestSync(rs) = out.msg_ref() {
      nonce = Some(rs.nonce());
    }
  }
  let nonce = nonce.expect("the fetch solicited");

  // An L=4 donor answers the old solicitation BEFORE any transfer is pinned: the reply is fresh
  // (same nonce) and reaches our own durable checkpoint, but it sits below the raised floor —
  // refused at the ingress, arming nothing.
  let (_d4, d4s) = donor_primary_at_checkpoint(4);
  let (env4, id4) = donor_envelope(&d4s);
  r.handle_message(
    t,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id4,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      nonce,
      env4.clone(),
      Bytes::new(),
    )),
  );
  assert!(
    r.block_fetch.is_none(),
    "a below-floor reply arms no transfer"
  );
  assert_eq!(
    r.sync_target_for_test(),
    Some(8),
    "the fetch stays armed at the raised floor"
  );

  // The M=8 donor answers with M's DAG not yet local: a genuine in-flight transfer pinned to M
  // (its frontier walk finds the root block missing and starts pulling).
  r.handle_message(
    t,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(8),
      id8,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env8.clone(),
      Bytes::new(),
    )),
  );
  r.block_step(t, &mut storage, &mut blocks);
  r.storage_step(t, &mut storage, &mut blocks);
  assert_eq!(
    r.block_fetch
      .as_ref()
      .map(|bf| bf.checkpoint.checkpoint_op()),
    Some(OpNumber::with(8)),
    "the at-floor reply pinned the transfer to the landed frontier"
  );

  // A second L=4 reply lands DURING the M transfer. Its DAG is fully local (the helper seeded it),
  // so admitting it would replace the pinned M transfer with one that drains instantly, walks to
  // the admission, is refused there — and leaves the fetch to start over, repeatable on every
  // delivery. The ingress floor refuses it before it can touch the transfer.
  r.handle_message(
    t,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id4,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      nonce,
      env4,
      Bytes::new(),
    )),
  );
  assert_eq!(
    r.block_fetch
      .as_ref()
      .map(|bf| bf.checkpoint.checkpoint_op()),
    Some(OpNumber::with(8)),
    "the below-floor reply neither replaced nor dropped the pinned transfer"
  );

  // Only M can install: its DAG arrives (seeded here) and a fresh at-floor reply re-pins the same
  // roots; the drain installs, retires the debt, and recovery completes at the landed frontier.
  seed_donor_blocks(&mut blocks, 8);
  r.handle_message(
    t,
    &mut storage,
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
  r.block_step(t, &mut storage, &mut blocks);
  r.storage_step(t, &mut storage, &mut blocks);
  storage.sb_mut().flush_envelopes();
  r.storage_step(t, &mut storage, &mut blocks);
  storage.sb_mut().flush_roots();
  r.storage_step(t, &mut storage, &mut blocks);
  assert_eq!(
    r.checkpoint_op(),
    OpNumber::with(8),
    "only the at-floor checkpoint installed"
  );
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovery completed at the landed frontier"
  );
  assert!(r.repersist_orphan.is_none(), "the install retired the debt");
}

#[test]
fn an_owed_debt_withholds_the_canonical_head_handouts() {
  // `on_get_view` and `on_recovery` hand out the primary's `(op, commit_max)` canonical head.
  // With an orphaned-re-persist debt owed, the landing that latched it also absorbed a commit
  // frontier that can exceed the held head while the fetch is deferred behind an own-advance arc
  // (an in-flight ordinary checkpoint, an owed reconstruct, a retained install) — the durable-view
  // fence both handlers already carry does not cover that window, and either handout would
  // fail-stop its adopter at the `commit <= op` guard. Both stay silent while the debt is owed
  // (the solicitors' timers re-solicit) and answer again once it is retired.
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let mut storage = Storage::new(TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.repersist_orphan = Some(OpNumber::with(4));
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::GetView(crate::GetView::new(
      View::new(),
      ReplicaId::new(2),
      7,
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::Recovery(crate::Recovery::new(
      ReplicaId::new(2),
      0x1234,
      crate::Epoch::new(0),
      0,
    )),
  );
  while let Some(out) = e.poll_message() {
    assert!(
      !matches!(
        out.msg_ref(),
        Message::StartView(_) | Message::RecoveryResponse(_)
      ),
      "no canonical head is handed out while the reconciliation is owed"
    );
  }
  // The debt retired (the arc it deferred to delivered the frontier): both handouts resume.
  e.repersist_orphan = None;
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::GetView(crate::GetView::new(
      View::new(),
      ReplicaId::new(2),
      7,
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::Recovery(crate::Recovery::new(
      ReplicaId::new(2),
      0x1234,
      crate::Epoch::new(0),
      0,
    )),
  );
  let (mut saw_sv, mut saw_rr) = (false, false);
  while let Some(out) = e.poll_message() {
    match out.msg_ref() {
      Message::StartView(_) => saw_sv = true,
      Message::RecoveryResponse(_) => saw_rr = true,
      _ => {}
    }
  }
  assert!(
    saw_sv && saw_rr,
    "both handouts resume once the debt is retired"
  );
}

#[test]
fn a_recovering_head_adoption_over_an_owed_orphan_debt_enters_the_fetch_instead_of_normal() {
  // The RecoveringHead exit is the one recovery completion that does not route through
  // `complete_recovery`: the canonical-head adoption settles the terminal status itself. With an
  // orphaned re-persist debt latched (its root landed while the head was unresolved — the window
  // where the fetch guard defers to the recovery in flight), the adoption must keep the head it
  // came for but enter the reconciling fetch instead of Normal: a quiescent backup settled
  // Normal here would have no commit tail to re-drive the fetch, and its next view change would
  // cast votes over the superseded pointer.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let mut storage = Storage::new(TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.status = Status::RecoveringHead;
  e.recover = Some(RecoverState::default());
  e.inherited_frontier = Some(OpNumber::with(4));
  e.repersist_orphan = Some(OpNumber::with(4));
  let flow = e.adopt_canonical_head(
    now,
    &mut storage,
    View::with(1),
    OpNumber::new(),
    OpNumber::new(),
    OpNumber::new(),
    &[],
  );
  assert!(
    flow.entered_recovery(),
    "the adoption yielded to the owed reconciliation"
  );
  assert_eq!(
    e.status(),
    Status::Recovering,
    "the exit is the reconciling fetch, never Normal over an uninstalled frontier"
  );
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "the reconciling peer fetch is latched"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(4),
    "the fetch targets the landed frontier"
  );
  assert_eq!(e.view(), View::with(1), "the adopted view stands");
  assert!(
    e.log_view.get() < e.view().get(),
    "the fetch's completion re-drives the view over installed state"
  );
}

#[test]
fn forming_a_view_over_an_owed_orphan_reconciliation_yields_to_the_recovery_fetch() {
  // The commit tail run inside `start_view_as_new_primary` can enter the orphaned-re-persist
  // reconciliation (the owed debt latched while the durable-view write was in flight, and the
  // view formation is the first tail that finds every deferral clear). Entering the fetch tears
  // the forming generation down, so the formation must STOP: continuing would overwrite
  // `Recovering` with `Normal` and stage a `StartView` for a checkpoint frontier this replica
  // never installed. The transition is returned by the commit helpers as a value, so the caller
  // short-circuits instead of carrying on over the dead generation.
  let (_donor, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let wal = TestWal::default();
  let sb = StepSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  // A live WAL band {1,2} below the synced point; the applied frontier stays at 0.
  for op in 1..=2u64 {
    e.handle_message(now, &mut storage, primary_peer(), prepare(op, 0));
    e.storage_step(now, &mut storage, &mut blocks);
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(
    e.sync_repersist_root_staged(),
    "the re-persist root is staged and in flight"
  );
  // The teardown that orphans the staged re-persist (the backstop arm of the shared reset).
  e.reset_for_view_transition(now, &mut storage);
  assert!(e.pending_checkpoint.is_none(), "the correlation is gone");

  // The node proposes and joins the view change to view 1 — the view it leads. Its
  // SendDoViewChange root queues BEHIND the orphaned root on the timeline.
  e.handle_timeout(now + core::time::Duration::from_millis(300), &mut storage);
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}

  // The orphaned root lands first (queue order): the debt latches, deferred behind the in-flight
  // durable-view write; the landing's settle releases the parked view root to the backend.
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.repersist_orphan,
    Some(OpNumber::with(4)),
    "the landing latched the debt while the durable-view write deferred the fetch"
  );
  assert_eq!(e.status(), Status::ViewChange);
  // The view root lands: the deferred DoViewChange fires (the accepted deferral window).
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  let mut voted = false;
  while let Some(m) = e.poll_message() {
    voted |= matches!(m.msg_ref(), Message::DoViewChange(_));
  }
  assert!(voted, "the deferred vote fired once the view root landed");

  // A canonical donor's DoViewChange completes the quorum: the node would now form view 1 as its
  // primary — but the commit tail inside the formation enters the owed reconciliation first, and
  // the formation must yield to it.
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![],
    )),
  );
  assert_eq!(
    e.status(),
    Status::Recovering,
    "forming the view yielded to the owed orphaned-re-persist reconciliation"
  );
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "the reconciling peer fetch is armed"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(4),
    "the fetch targets the orphaned root's landed frontier"
  );
  let mut refetch_nonce = None;
  let mut saw_sv = false;
  while let Some(out) = e.poll_message() {
    match out.msg_ref() {
      Message::RequestSync(rs) => refetch_nonce = Some(rs.nonce()),
      Message::StartView(_) => saw_sv = true,
      _ => {}
    }
  }
  assert!(
    !saw_sv,
    "no StartView is staged for the abandoned formation"
  );

  // The reconciliation completes: the install advances the pointer to the landed frontier, and
  // recovery re-drives the interrupted view change (log_view < view) — participation resumes
  // only now, over installed state.
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      refetch_nonce.expect("the reconciling fetch solicited"),
      env,
      Bytes::new(),
    )),
  );
  e.block_step(now, &mut storage, &mut blocks);
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the reconciling install advanced the pointer to the landed frontier"
  );
  assert!(e.repersist_orphan.is_none(), "the install retired the debt");
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "recovery completed into the re-driven view change (log_view < view)"
  );
  // The whole schedule never reached Normal and never staged a StartView: the formation that
  // began over the owed debt was abandoned, not completed.
  let mut saw_sv = false;
  while let Some(out) = e.poll_message() {
    saw_sv |= matches!(out.msg_ref(), Message::StartView(_));
  }
  assert!(!saw_sv, "no StartView was ever broadcast");
  let went_normal = core::iter::from_fn(|| e.poll_event())
    .any(|ev| matches!(ev, Event::StatusChanged(Status::Normal)));
  assert!(
    !went_normal,
    "the replica never resumed Normal while the reconciliation was owed"
  );
}

#[test]
fn a_debt_landing_behind_the_new_primary_root_is_reconciled_before_the_start_view() {
  // The orphaned root can land AFTER the canonical selection instead of before it: the formation
  // runs clean (no debt latched), defers participation to its StartViewAsPrimary root, and THAT
  // root queues behind the orphaned one. The orphaned landing then absorbs `commit_max` to its
  // frontier — above the formed head — and latches the debt, deferred behind the in-flight
  // durable-view write. The write's completion arm must reconcile the debt BEFORE broadcasting:
  // the formation-time bound `commit_max == commit* <= op` no longer holds at the emission, so a
  // StartView built first would carry `commit > op` and fail-stop every honest adopter at
  // `adopt_canonical_head`'s `commit <= op` guard, with this primary entering recovery only
  // afterwards.
  let (_donor, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let wal = TestWal::default();
  let sb = StepSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  // A live WAL band {1,2} below the synced point; the applied frontier stays at 0.
  for op in 1..=2u64 {
    e.handle_message(now, &mut storage, primary_peer(), prepare(op, 0));
    e.storage_step(now, &mut storage, &mut blocks);
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(
    e.sync_repersist_root_staged(),
    "the re-persist root is staged and in flight"
  );
  // The teardown that orphans the staged re-persist (the backstop arm of the shared reset).
  e.reset_for_view_transition(now, &mut storage);
  assert!(e.pending_checkpoint.is_none(), "the correlation is gone");

  // The node proposes and joins the view change to view 1 — the view it leads. Its durable-view
  // write parks behind the orphaned root on the timeline.
  e.handle_timeout(now + core::time::Duration::from_millis(300), &mut storage);
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}

  // The donor DVC completes the quorum while the orphaned root is STILL WITH THE MEDIUM: the
  // canonical selection runs with no debt latched, and the StartViewAsPrimary root supersedes the
  // parked vote root — queued behind the orphaned root.
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![],
    )),
  );
  assert_eq!(
    e.status(),
    Status::Normal,
    "the view formed; participation defers to the durable-view root"
  );
  assert!(
    e.repersist_orphan.is_none(),
    "no debt is latched at canonical-selection time"
  );
  while e.poll_message().is_some() {}

  // The orphaned root lands first (submission order): `commit_max` absorbs the landed frontier 4
  // — above the formed head 2 — and the debt latches, deferred behind the in-flight
  // StartViewAsPrimary write.
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.repersist_orphan,
    Some(OpNumber::with(4)),
    "the landing latched the debt while the durable-view write deferred the fetch"
  );
  assert_eq!(
    e.commit_max(),
    OpNumber::with(4),
    "the absorbed commit frontier now exceeds the formed head"
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "the formed head is the pre-sync 2"
  );
  assert_eq!(e.status(), Status::Normal);

  // The StartViewAsPrimary root lands: the completion arm must observe the owed debt BEFORE
  // participating — enter the reconciling fetch, emit no StartView and no Commit.
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.status(),
    Status::Recovering,
    "the completion reconciled the owed debt instead of leading over it"
  );
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "the reconciling peer fetch is armed"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(4),
    "the fetch targets the orphaned root's landed frontier"
  );
  // Nothing malformed reached the wire: no StartView, no Commit — and an honest backup receiving
  // everything that WAS emitted survives it (the malformed StartView would fail-stop it at the
  // `commit <= op` adopt guard).
  let mut backup = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::with_checkpoint_ops(1, MemberId::new(2), 1_000).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let mut bstorage = Storage::new(TestWal::default(), TestSb::default());
  let (mut saw_sv, mut saw_commit) = (false, false);
  let mut refetch_nonce = None;
  while let Some(out) = e.poll_message() {
    match out.msg_ref() {
      Message::StartView(_) => saw_sv = true,
      Message::Commit(_) => saw_commit = true,
      Message::RequestSync(rs) => refetch_nonce = Some(rs.nonce()),
      _ => {}
    }
    backup.handle_message(
      now,
      &mut bstorage,
      Peer::Replica(ReplicaId::new(1)),
      out.into_msg(),
    );
  }
  assert!(
    !saw_sv && !saw_commit,
    "no StartView or Commit is emitted before the owed debt is reconciled"
  );

  // The reconciliation completes: the install advances the pointer to the landed frontier and
  // retires the debt; the recovered ex-candidate then abdicates into the next view change rather
  // than resuming as the established primary.
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      refetch_nonce.expect("the reconciling fetch solicited"),
      env,
      Bytes::new(),
    )),
  );
  e.block_step(now, &mut storage, &mut blocks);
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the reconciling install advanced the pointer to the landed frontier"
  );
  assert!(e.repersist_orphan.is_none(), "the install retired the debt");
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  // Hold a live band {1,2} (durable).
  let mut storage = Storage::new(wal, sb);
  for op in 1..=2u64 {
    e.handle_message(now, &mut storage, primary_peer(), prepare(op, 0));
    e.storage_step(now, &mut storage, &mut blocks);
  }
  while e.poll_message().is_some() {}
  // A Commit carries commit=2 (applies the band → crosses the checkpoint boundary at op 2 → an ORDINARY
  // checkpoint fires) AND checkpoint_op=99 (far above the head → SOLICITS a state-sync). Both happen in
  // this one handler: `maybe_request_sync` arms the sync, then `advance_commit` applies + `maybe_
  // checkpoint` stages the ordinary checkpoint.
  e.handle_message(
    now,
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  // Drive the primary to op 4, commit 4 (no checkpoint — interval is huge).
  let mut storage = Storage::new(wal, sb);
  for rn in 1..=4u64 {
    e.handle_message(
      now,
      &mut storage,
      Peer::Client(ClientId::new(7)),
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      )),
    );
    e.storage_step(now, &mut storage, &mut blocks); // own append durable → own vote
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
  }
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.checkpoint_op(), OpNumber::with(0));
  while e.poll_message().is_some() {}
  // A valid checkpoint envelope at op 6 (from a donor), and an outstanding FORCED sync to it.
  let (_d, dstorage) = donor_primary_at_checkpoint(6);
  let (env, id) = donor_envelope(&dstorage);
  e.arm_forced_sync_for_test(6);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
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
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 6);
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
  assert_eq!(e.status(), Status::Recovering);
  assert!(e.awaiting_peer_checkpoint_for_test());
  while e.poll_message().is_some() {} // drain the solicited RequestSync
  let nonce = e.sync_nonce_for_test();
  // A donor at a HIGHER checkpoint (op 6 > our 2): delivering its SyncCheckpoint stages the re-persist to
  // the synced point and prunes the band (2..6] — but only once the SyncRepersist root lands in
  // `on_sb_done`.
  let (_d, dstorage) = donor_primary_at_checkpoint(6);
  let (env, id) = donor_envelope(&dstorage);
  e.handle_message(
    now,
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
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
  let (mut e, mut storage, _env, _id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
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
  let (mut e, mut storage, _env, _id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  // Trigger a sync targeting op 4 (the overstated op).
  e.handle_message(
    now,
    &mut storage,
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
  blocks.put(stale_sm.snapshot());
  // Deliver it advertising the OVERSTATED op B=4 but the bytes' REAL id → the hash gate passes, the
  // op-binding gate must reject (bound op 2 != advertised op 4).
  e.handle_message(
    now,
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks); // (no re-persist should have been staged)
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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let (_d, dstorage) = donor_primary_at_checkpoint(4);
  let (env4, id4) = donor_envelope(&dstorage);
  let now = Instant::ZERO;
  // Trigger a sync targeting 6 (the cluster's known checkpoint).
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let (_d, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let now = Instant::ZERO;
  // No trigger fired → sync is None. Deliver a (valid) SyncCheckpoint anyway.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
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
  let (mut e, mut storage, env4, id4) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let (_d2, dstorage2) = donor_primary_at_checkpoint(2);
  let (env2, id2) = donor_envelope(&dstorage2);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  // A stale lower SyncCheckpoint (op 2) arriving now: sync is already cleared, and even if it
  // weren't, `> self.checkpoint_op` fails. It must be ignored — no regression.
  e.handle_message(
    now,
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
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
  let (_donor, dstorage) = donor_primary_at_checkpoint(6);
  // Use a checkpoint at 6 so it is strictly above the hole at 2 and the head.
  let (env, id) = donor_envelope(&dstorage);
  let mut e = sync_backup();
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 6);
  let now = Instant::ZERO;
  // Manufacture a pending-repair hole at op 2 (as the recover loop would).
  e.request_repair(now, 2);
  assert!(e.repair.contains(&2), "hole registered");
  assert!(e.timers.repair_retry.is_some(), "repair timer armed");
  // Trigger + apply a sync to checkpoint 6 (above the hole).
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
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
  let mut storage = Storage::new(wal, sb);
  ep.handle_message(
    Instant::ZERO,
    &mut storage,
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  // Head op 6, commit held at 3, own checkpoint 0, a committed hole at op 4.
  ep.force_state_for_test(0, 6, 3, 0, &[4]);
  // The primary (replica 0) reports a checkpoint of 3 — BELOW the hole at 4. The max-peer floor is
  // max{self=0, r0=3} = 3 < N=4 → the hole is still in-reach (the primary has NOT pruned op 4, so a
  // RequestPrepare can still be answered) → no force-sync.
  let mut storage = Storage::new(wal, sb);
  ep.handle_message(
    Instant::ZERO,
    &mut storage,
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  // Head op 10 (ABOVE the cluster checkpoint, so the ORDINARY `> self.op` sync stays FALSE — this is
  // the precise force-sync regime), commit held at 1, own checkpoint 0, a committed hole at op 2.
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
  assert!(!ep.is_primary());
  // Only the primary (replica 0) reports — exactly a backup's real visibility. quorum_checkpoint_op
  // is still 0 here (only self + one peer report), proving the OLD quorum-gated trigger could never
  // have fired; the max-peer floor (8) is what rescues it. The primary's checkpoint (8) is BELOW the
  // head (10), so `maybe_request_sync` (`8 > 10`?) does NOT fire — ONLY the forced path can.
  let mut storage = Storage::new(wal, sb);
  ep.handle_message(
    Instant::ZERO,
    &mut storage,
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
  let (_donor, dstorage) = donor_primary_at_checkpoint(3);
  let (env, id) = donor_envelope(&dstorage);
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 4).unwrap();
  let mut ep =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 1, CountSm::default(), u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
  let mut storage = Storage::new(wal, sb);
  ep.handle_message(
    Instant::ZERO,
    &mut storage,
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
  ep.storage_step(Instant::ZERO, &mut storage, &mut blocks); // drive the durable re-persist
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
  let mut storage = Storage::new(wal, sb);
  ep.handle_message(
    now,
    &mut storage,
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
  ep.handle_message(now, &mut storage, primary_peer(), repair_prepare(0, 2, 4));
  assert!(
    ep.has_repair_hole_for_test(2),
    "the hole stays OPEN until the repair-fill append is durable"
  );
  ep.storage_step(now, &mut storage, &mut blocks); // on_wal_done: insert op 2, clear the hole, advance_commit
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
  let (_donor, dstorage) = donor_primary_at_checkpoint(2);
  let (env, _id) = donor_envelope(&dstorage);
  ep.handle_message(
    now,
    &mut storage,
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
  ep.storage_step(now, &mut storage, &mut blocks);
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 2);
  let now = Instant::ZERO;
  // Head op 4, applied frontier already at 4, own checkpoint 0 (no hole — the band is fully applied).
  ep.force_state_for_test(0, 4, 4, 0, &[]);
  ep.seed_log_entry_for_test(4);
  // Arm a forced sync to a target (2) the applied frontier (4) is already past — exactly the reordered
  // state where Part A's chokepoint never fired between the arm and the delivery below.
  ep.arm_forced_sync_for_test(2);
  let nonce = ep.sync_nonce_for_test();
  let (_donor, dstorage) = donor_primary_at_checkpoint(2);
  let (env, id) = donor_envelope(&dstorage);
  // Deliver the stale forced SyncCheckpoint at op 2. It passes the upstream guards (target 2 reached,
  // forced relaxes `<= self.op`, 2 > own checkpoint 0, integrity ok, not primary) and reaches
  // `apply_sync` with `checkpoint_op 2 < commit_min 4`. FAIL-BEFORE: panic. PASS-AFTER: dropped.
  let mut storage = Storage::new(wal, sb);
  ep.handle_message(
    now,
    &mut storage,
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
  ep.storage_step(now, &mut storage, &mut blocks);
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary(), "replica 0 at view 0 is the primary");
  // The primary holds a head at op 10 with a committed-op hole at op 2 (commit held at 1 below it).
  // (A recovered primary with a rotted committed slot the cluster long since checkpointed+pruned.)
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
  assert_eq!(ep.op(), OpNumber::with(10));
  // A backup's PrepareOk reports checkpoint_op = 8 — ABOVE the hole at 2, so the hole is snapshot-only
  // on that peer (pruned: RequestPrepare is futile). This drives the production `on_prepare_ok` →
  // `maybe_force_sync` path on the PRIMARY, rather than reaching it through a test-only shortcut.
  let mut storage = Storage::new(wal, sb);
  ep.handle_message(
    Instant::ZERO,
    &mut storage,
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
    &mut storage,
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
  // SAFETY (the heart of the hazard): the op-reuse divergence happens ONLY if the primary's `op` is
  // REWOUND below its head (force-sync resets it to the checkpoint, then new requests land at the
  // vacated op numbers that backups still hold under old bodies). The deferred forfeit guarantees `op`
  // is NEVER rewound. We drive the full strand→forfeit→serve sequence and assert `op` is monotone
  // non-decreasing throughout: a request the (still-Normal, lone-SVC) primary serves lands at a FRESH
  // op ABOVE the old head (11), never at a reused number. Were `op` instead allowed to collapse to the
  // checkpoint floor, the next request would reuse op 9/10.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, NoopSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
  let head_at_strand = ep.op().get();
  assert_eq!(head_at_strand, 10);
  // Enter the force-sync strand (flag the deferred forfeit) via a peer PrepareOk above the hole.
  let mut storage = Storage::new(wal, sb);
  ep.handle_message(
    Instant::ZERO,
    &mut storage,
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
  ep.handle_timeout(Instant::ZERO, &mut storage);
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
    &mut storage,
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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(storage.sb().state().checkpoint_op(), OpNumber::with(4));
  drop(e); // crash
  // Recover over the same session: the synced checkpoint is the durable root.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let mut recovered = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
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
  recovered.storage_step(now, &mut storage, &mut blocks); // restore SM from the synced snapshot → Normal
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
  let (_donor, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::with_checkpoint_ops(1, MemberId::new(2), 2).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.status(), Status::Normal);
  while e.poll_message().is_some() {}

  // Force a view change to view 1 (primary = replica 1): replica 2 proposes view 1 on idle, a peer
  // SVC completes the quorum → ViewChange(1) → it sends a DoViewChange to replica 1.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut storage); // primary_idle → propose view 1 (own bit)
  e.handle_message(
    later,
    &mut storage,
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
  e.storage_step(later, &mut storage, &mut blocks); // durable-view write completes → DVC is sent
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
  let sb = StepSb::default(); // async: the ordinary checkpoint root lands on a later flush
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
  let mut storage = Storage::new(wal, sb);
  e.maybe_checkpoint(&mut storage);
  e.storage_step(now, &mut storage, &mut blocks);
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
  e.handle_message(now, &mut storage, primary_peer(), prepare_ck(6, 5, 5));
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
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks); // AwaitSnapshot → submit root
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks); // AwaitRoot → advance_checkpoint_op(5) + run_gc
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
  e.handle_message(now, &mut storage, primary_peer(), prepare_ck(6, 5, 5));
  e.storage_step(now, &mut storage, &mut blocks); // drive the append → its PrepareOk
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
    storage.wal_mut().entries.contains_key(&6),
    "op 6 is durably resident in the ring after the append"
  );

  // And the cluster converges through this replica: a Commit advancing the frontier to 6 applies cleanly
  // (the backup is no longer wedged behind a phantom sync).
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(6),
      OpNumber::with(5),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.storage_step(now, &mut storage, &mut blocks);
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
  storage: &mut Storage<TestWal, TestSb, CountSm>,
  blocks: &mut InMemoryBlockStore,
) -> crate::SyncCheckpoint {
  let now = Instant::ZERO;
  while e.poll_message().is_some() {} // drain warm-up / membership-change emissions
  e.handle_message(
    now,
    storage,
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
  e.storage_step(now, storage, blocks); // the checkpoint read completes → ship SyncCheckpoint
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
  let (mut e, mut storage) = donor_primary_at_checkpoint(2);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  // SWAP to E+1 exactly as a commit-first swap does (AddLearner keeps the voter set, so replica 0 stays
  // the primary), naming reconfigure op N = 5 — ABOVE the donor's durable checkpoint (op 2). This is the
  // commit-first window: the swap is in memory (epoch = E+1) but the checkpoint does not yet reflect it.
  let successor = e
    .membership
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid");
  let predecessor_config_id = e.membership.config_id();
  e.install_membership(Instant::ZERO, Some(OpNumber::with(5)), successor.clone());
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
  let shipped = serve_request_sync(&mut e, &mut storage, &mut blocks);
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
  let shipped = serve_request_sync(&mut e, &mut storage, &mut blocks);
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
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid");

  // --- Phase 1: the WITHHELD (empty) cross-epoch answer keeps the laggard's membership. ---
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks); // the two-write persist → durable root → install
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
  let (mut e2, mut storage2, env2, id2) = sync_apply_harness(4);
  let mut blocks2 = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks2, 4);
  e2.handle_message(
    now,
    &mut storage2,
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
    &mut storage2,
    primary_peer(),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4),
        id2,
        successor.epoch(),
        successor.config_id(),
        ReplicaId::new(0),
        nonce2,
        env2.clone(),
        membership_body,
      )
      .with_config_install_op(OpNumber::with(4)),
    ),
  );
  e2.storage_step(now, &mut storage2, &mut blocks2);
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
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner(3) on the 3-voter genesis is valid"); // [0,1,2,3], chains from E0
  let e2 = e1
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(4)))
    .expect("AddLearner(4) on the E1 config is valid"); // [0,1,2,3,4], chains from E1
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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
    &mut storage,
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
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4),
        id,
        e2.epoch(),
        e2.config_id(),
        ReplicaId::new(0),
        nonce,
        env.clone(),
        e2_body,
      )
      .with_config_install_op(OpNumber::with(4)),
    ),
  );
  e.storage_step(now, &mut storage, &mut blocks); // two-write persist → durable root → install

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
  // The DURABLE root the crossing staged records the SAME scalar (recovery restores it). `storage.sb().state()` is
  // the v6 root `durable_root_with_successor` wrote naming the synced checkpoint.
  assert_eq!(
    storage.sb().state().prev_epoch(),
    crate::Epoch::new(1),
    "the DURABLE sync-successor root stamps prev_epoch = E1 (matches the live scalar by construction)"
  );
  assert_eq!(
    storage.sb().state().epoch(),
    crate::Epoch::new(2),
    "the durable root names the crossed-to epoch E2"
  );

  // RE-SERVE: a fresh E0/E1 laggard (slot 2) solicits; the installed node serves its E2 checkpoint with
  // the E2 membership chained from `lineage[0]`. A recovery-flagged RequestSync is served at/above our op.
  e.handle_message(
    now,
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks); // the serve-read completes → ship SyncCheckpoint
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
  let recovered = match Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
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
fn a_synced_producing_op_survives_a_crash_and_re_serves_verbatim_to_the_next_laggard() {
  // The TRANSITIVE chain a synced membership's producing op has to survive: a laggard that received
  // its configuration by cross-epoch sync later becomes the DONOR for the next laggard, and the op it
  // hands on must still be the op that PRODUCED the configuration — never the frontier of whichever
  // checkpoint carried it.
  //
  // The two numbers are held DISTINCT throughout: the cluster reconfigured E0 -> E1 at op `N` == 2 and
  // checkpointed on to `M` == 4, an ordinary client op past the swap. Every assertion below therefore
  // DISTINGUISHES the producing op from the crossing frontier — a serve path that re-derived the value
  // from its own `checkpoint_op` would answer 4 where 2 is owed, and each hop names the discrepancy.
  //
  // The chain is: first laggard receives `N` -> its crossing durable root records `N` -> CRASH -> recover
  // restores `N` -> it re-serves, and the answer carries `N` through a full wire round trip -> a SECOND
  // laggard installs off that answer, and both the `MembershipChanged` it reports and its own crossing
  // durable root name `N`. Each hop re-reads the value from the previous hop's durable state, so nothing
  // here can pass on a value that lives only in the first laggard's memory.
  const N: u64 = 2; // the committed Reconfigure op that produced E1
  const M: u64 = 4; // the checkpoint frontier the crossing rides — an ordinary client op above N
  const _: () = assert!(
    N != M,
    "the whole point: the two values are never interchangeable"
  );
  let e0 = genesis(3); // [0,1,2]
  let e1 = e0
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner(3) on the 3-voter genesis is valid"); // E1, chains from E0
  let e1_body =
    crate::message::ReconfigurePayload::from_membership(&e1, e0.config_id()).encode_body();

  // ── HOP 1: the first laggard crosses E0 -> E1 off the donor's checkpoint at M, carrying N. ──
  let (mut e, mut storage, env, id) = sync_apply_harness(M);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, M);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(M),
      OpNumber::with(M),
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(M),
        id,
        e1.epoch(),
        e1.config_id(),
        ReplicaId::new(0),
        nonce,
        env.clone(),
        e1_body.clone(),
      )
      .with_config_install_op(OpNumber::with(N)),
    ),
  );
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(e.state_syncs_applied(), 1, "the E0->E1 crossing applied");
  assert_eq!(e.membership, e1, "the first laggard installed E1");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(M),
    "its frontier is the crossing checkpoint M — the value a regressed serve path would hand on"
  );
  assert_eq!(
    e.config_install_op,
    OpNumber::with(N),
    "but its install record is the DONOR-CARRIED producing op N, distinct from that frontier"
  );
  assert_eq!(
    storage.sb().state().config_install_op(),
    OpNumber::with(N),
    "and the crossing durable root records N verbatim — what a crash restores"
  );

  // ── HOP 2: CRASH, then recover off that root. MemberId 1 is retained in E1, so it comes up Active. ──
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let mut donor = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  for _ in 0..8 {
    donor.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(donor.membership, e1, "the recovered node comes up at E1");
  assert_eq!(
    donor.config_install_op,
    OpNumber::with(N),
    "recover restores the producing op N from the durable root — it outlived the process, not just \
     the crossing's in-memory state"
  );
  assert!(
    donor.checkpoint_op().get() >= donor.config_install_op.get(),
    "its checkpoint covers the install, so the serve gate opens and it will attach the membership"
  );

  // ── HOP 3: the recovered node RE-SERVES as donor, and the answer survives a wire round trip. ──
  let mut laggard2 = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::with_checkpoint_ops(1, MemberId::new(2), 2).unwrap(),
    e0.clone(),
    0,
    CountSm::default(),
    u64::MAX,
  );
  laggard2.arm_cross_epoch_sync_for_test(M);
  let nonce2 = laggard2.sync_nonce_for_test();
  donor.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      donor.view(),
      OpNumber::with(0),
      ReplicaId::new(2),
      nonce2,
      true, // recovery peer-fetch — served at/above our checkpoint
      0,
    )),
  );
  donor.storage_step(now, &mut storage, &mut blocks); // the serve-read completes -> ship SyncCheckpoint
  let mut served = None;
  while let Some(out) = donor.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      served = Some(s.clone());
    }
  }
  let served = served.expect("the recovered node re-serves a SyncCheckpoint");
  // Round-trip the answer through the actual codec: the producing op and the membership are a PAIRED
  // presence on the wire (either half without the other is refused), so this also pins that a re-serve
  // emits a shape the wire accepts rather than one only direct delivery would tolerate.
  let served = match crate::decode_message(crate::encode_message(&Message::SyncCheckpoint(served)))
    .expect("the re-served answer round-trips through the wire codec")
  {
    Message::SyncCheckpoint(s) => s,
    other => panic!("the round trip returned a different message: {other:?}"),
  };
  assert_eq!(
    served.checkpoint_op(),
    OpNumber::with(M),
    "the re-serve advertises the frontier M — the value the producing op must NOT collapse into"
  );
  assert_eq!(
    served.membership(),
    &e1_body,
    "it attaches E1, chained from the verified predecessor E0 so a fresh laggard can verify it"
  );
  // THE LOAD-BEARING ASSERTION. Exact, not merely present: the answer names the op that PRODUCED E1
  // (N == 2), which this node never committed itself — it received it, stored it, and restored it. A
  // serve path that reached for its own checkpoint frontier instead would answer Some(4) here.
  assert_eq!(
    served.config_install_op(),
    Some(OpNumber::with(N)),
    "the re-serve hands on the producing op N verbatim, not its own checkpoint frontier M"
  );

  // ── HOP 4: a SECOND laggard installs off that answer; its event and its durable root both name N. ──
  let mut storage2 = Storage::new(TestWal::default(), TestSb::default());
  let mut blocks2 = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks2, M);
  laggard2.handle_message(
    now,
    &mut storage2,
    primary_peer(),
    Message::SyncCheckpoint(served),
  );
  laggard2.block_step(now, &mut storage2, &mut blocks2);
  for _ in 0..6 {
    laggard2.storage_step(now, &mut storage2, &mut blocks2);
    laggard2.block_step(now, &mut storage2, &mut blocks2);
  }
  assert_eq!(
    laggard2.state_syncs_applied(),
    1,
    "the second laggard crossed off the RE-SERVED answer"
  );
  assert_eq!(laggard2.membership, e1, "it installed the same E1");
  let mc = core::iter::from_fn(|| laggard2.poll_event())
    .find_map(|ev| match ev {
      Event::MembershipChanged(mc) => Some(mc),
      _ => None,
    })
    .expect("the crossing install reports MembershipChanged");
  assert_eq!(
    mc.op(),
    OpNumber::with(N),
    "the event an embedder folds into consensus history names the real Reconfigure op N, two hops and \
     a crash from where it was committed — not the frontier M this crossing rode"
  );
  assert_eq!(
    laggard2.config_install_op,
    OpNumber::with(N),
    "the second laggard's own install record carries N, so IT would re-serve N in turn"
  );
  assert_eq!(
    storage2.sb().state().config_install_op(),
    OpNumber::with(N),
    "and its crossing durable root records N — the chain is closed and survives another crash"
  );
}

#[test]
fn a_direct_e0_to_e3_wholesale_crossing_installs_the_content_verified_config() {
  // WHOLESALE cross-epoch crossing past MORE than the two-prior `LINEAGE_RING` window. A retained E0
  // laggard offline across three legal changes is offered an E3 successor DIRECTLY from an E3 donor — an
  // epoch DISTANCE of 3. The carried payload VERIFIES (E3's config_id chains from E2,
  // `hash(E3_membership, E2) == E3_config_id`), and that content verification is what self-certifies the
  // installed configuration: it never depended on the laggard's own lineage, so a distance-3 skip is as
  // sound to install as a single step. There is NO distance bound — the laggard crosses directly to E3
  // rather than stranding forever on a "closer donor" the protocol does not preserve (with a distance
  // bound, a retained member offline across three changes could never re-sync). The post-crossing ring stamps
  // `[E2, E0]` — the VERIFIED immediate predecessor E2 over the laggard's own prior E0 — which SKIPS the
  // intermediate E1: a bounded liveness nicety (an agnostic solicitation carrying E1 is not admitted;
  // state-sync is admitted on member identity regardless), never a safety gap, since the immediate
  // predecessor E2 is present (a re-serve chains correctly) and `prev_epoch` is E2. (Contrast the
  // distance-2 E0→E2 crossing above, which stamps the contiguous `[E1, E0]`.)
  let e0 = genesis(3); // [0,1,2]
  let e1 = e0
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner(3) on the 3-voter genesis is valid"); // E1, chains from E0
  let e2 = e1
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(4)))
    .expect("AddLearner(4) on the E1 config is valid"); // E2, chains from E1
  let e3 = e2
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(5)))
    .expect("AddLearner(5) on the E2 config is valid"); // E3, chains from E2
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
    "E3's config_id chains from E2 — the payload content-verifies, which is what makes the crossing sound"
  );

  // The laggard starts at E0 (MemberId 1, slot 1).
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  assert_eq!(
    e.membership.config_id(),
    e0.config_id(),
    "laggard starts at E0"
  );
  let now = Instant::ZERO;
  // Arm the sync exactly as the E0→E2 crossing test does: a same-epoch `Commit` advertising the higher
  // checkpoint op 4 arms an ordinary sync; the CROSSING is driven purely by the reply's higher epoch +
  // successor membership. The successor-reconstruction block in `apply_sync` runs on ANY successor-carrying
  // reply (gated on a differing config_id + non-empty membership), so the wholesale crossing applies here
  // independent of `require_cross_epoch`.
  e.handle_message(
    now,
    &mut storage,
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
  // freshness/monotone gates pass (checkpoint_op 4 > self.checkpoint_op 0), so it REACHES `apply_sync`,
  // which content-verifies the E3 payload and STAGES the wholesale crossing.
  let e3_body =
    crate::message::ReconfigurePayload::from_membership(&e3, e2.config_id()).encode_body();
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(4),
        id,
        e3.epoch(),
        e3.config_id(),
        ReplicaId::new(0),
        nonce,
        env.clone(),
        e3_body,
      )
      .with_config_install_op(OpNumber::with(4)),
    ),
  );
  e.storage_step(now, &mut storage, &mut blocks); // two-write persist → durable root → install

  // INSTALLED: the wholesale E0→E3 crossing applied directly — no distance bound stranded the laggard.
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the wholesale E0→E3 crossing applied — the content-verified config installs at any distance"
  );
  assert_eq!(
    e.membership, e3,
    "the laggard installed the E3 successor directly"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(3),
    "the laggard crossed to E3"
  );
  // The ring stamps `[E2, E0]` — the VERIFIED immediate predecessor E2 over the laggard's own prior E0.
  // It SKIPS the intermediate E1 (the ring holds two slots and E1 falls between the verified predecessor
  // and the own-prior): the bounded liveness nicety, not a safety gap.
  assert_eq!(
    e.lineage_ring_for_test(),
    [e2.config_id(), e0.config_id()],
    "the deep crossing stamped [E2, E0] — verified immediate predecessor E2, then the laggard's own prior E0"
  );
  assert!(
    e.in_lineage_for_test(e2.config_id()),
    "E2 (the immediate predecessor) admitted"
  );
  assert!(
    e.in_lineage_for_test(e0.config_id()),
    "E0 (the laggard's own prior) admitted"
  );
  assert!(
    !e.in_lineage_for_test(e1.config_id()),
    "E1 (the skipped-over intermediate) is NOT admitted — the bounded liveness nicety, never a safety gap"
  );
  // The LIVE `prev_epoch` is the VERIFIED immediate predecessor E2 (= successor.epoch() - 1 = 2), not the
  // stale own epoch E0 — so a re-serve of the E3 membership chains from E2 exactly as a fresh laggard expects.
  assert_eq!(
    e.prev_epoch,
    crate::Epoch::new(2),
    "the LIVE prev_epoch is the verified predecessor E2 (successor.epoch() - 1)"
  );
  // The DURABLE root the crossing staged records the SAME scalars (recovery restores them).
  assert_eq!(
    storage.sb().state().prev_epoch(),
    crate::Epoch::new(2),
    "the durable sync-successor root stamps prev_epoch = E2 (matches the live scalar by construction)"
  );
  assert_eq!(
    storage.sb().state().epoch(),
    crate::Epoch::new(3),
    "the durable root names the crossed-to epoch E3"
  );
}

#[test]
fn an_op_equals_n_normal_laggard_forced_syncs_across_the_epoch() {
  // The `op == N` crossing. A Normal laggard APPENDED the reconfigure op N but missed its
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  // Append ops 1..=N with commit 0 (the laggard appended the reconfigure op N but never saw its commit).
  let mut storage = Storage::new(wal, sb);
  for op in 1..=n {
    e.handle_message(now, &mut storage, primary_peer(), prepare_ck(op, 0, 0));
    e.storage_step(now, &mut storage, &mut blocks);
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

  // The successor a real swap derives off genesis (AddLearner keeps the lineage valid; epoch is E+1).
  let predecessor = genesis(3);
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid");
  let laggard_config_id = e.membership.config_id();

  // A STRICTLY-higher-epoch Commit (E+1) advertising the cluster checkpoint at N. Dropped at the
  // authority ingress, but it is the cross-epoch catch-up signal: the laggard enters the FORCED
  // peer-fetch (NOT the no-op `maybe_request_sync` path) targeting the crossing checkpoint.
  e.handle_message(
    now,
    &mut storage,
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
  blocks.put(snap.clone());
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor, predecessor.config_id())
      .encode_body();
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(n),
        id,
        successor.epoch(),
        successor.config_id(),
        ReplicaId::new(0),
        nonce,
        env.clone(),
        membership_body,
      )
      .with_config_install_op(OpNumber::with(n)),
    ),
  );
  e.block_step(now, &mut storage, &mut blocks);
  // apply_sync staged the durable re-persist (two superblock writes) + STAYED Normal; drive them.
  for _ in 0..3 {
    e.storage_step(now, &mut storage, &mut blocks);
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

/// The reconfigure op the slot-shifting `DemoteVoter(1)` swap names (the donor's checkpoint embeds it).
const SLOT_SHIFT_N: u64 = 4;

/// Build a FAR-BEHIND laggard (checkpoint 0) at the PREDECESSOR config `genesis(4) = [m0,m1,m2,m3]` that
/// has ARMED a FORCED, crossing-required cross-epoch sync toward the E+1 successor produced by a LOW-INDEX
/// `DemoteVoter(MemberId 1)` (the slot-shifting delta). The successor voters are `[m0,m2,m3]` (the
/// demotee is the learner at the tail), so the surviving
/// `MemberId 2` SHIFTS from OLD slot 2 (the laggard's E membership) to NEW slot 1 (the donor's E+1
/// membership) — the slot-shifted DONOR. The laggard itself is `MemberId 3` (retained; it shifts 3->2 in
/// E+1, but during the crossing it is still at E and resolves peers under its E membership). Returns
/// `(laggard, storage, successor, predecessor_config_id, nonce)`.
fn slot_shifted_crossing_laggard() -> (
  Endpoint<CountSm>,
  Storage<TestWal, TestSb, CountSm>,
  Membership,
  u128,
  u64,
) {
  // The laggard is MemberId 3 (slot 3) — retained across the removal, far behind, high checkpoint cadence
  // so nothing auto-checkpoints it off the bookkeeping below.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(3), 100).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(4), 0, CountSm::default(), u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let predecessor = genesis(4);
  let predecessor_config_id = e.membership.config_id();
  // The E+1 successor a LOW-INDEX DemoteVoter derives: demoting MemberId 1 from [m0,m1,m2,m3] leaves
  // voters [m0,m2,m3] + learner m1, shifting m2 (slot 2 -> 1) and m3 (slot 3 -> 2).
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::DemoteVoter(MemberId::new(1)))
    .expect("DemoteVoter(1) on a 4-voter cluster is valid (leaves 3 voters)");
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
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
  (e, storage, successor, predecessor_config_id, nonce)
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
      &mut crate::block_store::InMemoryBlockStore::new(),
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
  // FINDING (high) — the cross-epoch SERVE-REPLY binding. After a LOW-INDEX DemoteVoter shifts a retained
  // DONOR's slot, the donor stamps its WHOLE SyncCheckpoint reply with its CURRENT (E+1) slot while the
  // mid-crossing OLD-epoch laggard resolves `from` under its OLD (E) membership slot — so `from` (E-slot)
  // != claimed (E+1-slot). The STRICT `sender_is_member` binding would DROP the reply at ingress before
  // `apply_sync`. The path-sensitive reply binding admits a nonce-bound reply from an authenticated member
  // while a sync is outstanding; `apply_sync` is the real authenticator (nonce + integrity + the carried
  // successor membership), so the crossing installs.
  let (mut e, _storage, successor, predecessor_config_id, nonce) = slot_shifted_crossing_laggard();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let (env, id, membership_body) = slot_shift_crossing_envelope(&successor, predecessor_config_id);
  // `slot_shift_crossing_envelope` names the SM leaf (a default-SM snapshot) by content address; seed it
  // so the crossing install's block-fetch frontier drains locally and applies without a round trip. Seed
  // the (empty) session-table DAG too so the session frontier likewise drains locally.
  blocks.put(CountSm::default().snapshot());
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
  let mut storage = Storage::new(TestWal::default(), TestSb::default());
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(donor_old_slot), // bound under the laggard's OLD membership
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(SLOT_SHIFT_N),
        id,
        successor.epoch(),
        successor.config_id(),
        donor_current_slot, // the donor self-stamps its CURRENT (E+1) slot
        nonce,
        env.clone(),
        membership_body,
      )
      .with_config_install_op(OpNumber::with(SLOT_SHIFT_N)),
    ),
  );
  e.block_step(now, &mut storage, &mut blocks);
  // apply_sync staged the durable re-persist (two superblock writes); drive them to install.
  for _ in 0..3 {
    e.storage_step(now, &mut storage, &mut blocks);
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
  let (mut e2, mut storage2, succ2, pred2, nonce2) = slot_shifted_crossing_laggard();
  let mut blocks2 = crate::block_store::InMemoryBlockStore::new();
  let (env2, id2, body2) = slot_shift_crossing_envelope(&succ2, pred2);
  e2.handle_message(
    now,
    &mut storage2,
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
    e2.storage_step(now, &mut storage2, &mut blocks2);
  }
  assert_eq!(
    e2.state_syncs_applied(),
    0,
    "a SAME-config mismatched-self-id reply is still DROPPED by the strict binding (no relaxation)"
  );
}

#[test]
fn a_cross_epoch_fetch_rejects_a_below_n_empty_membership_reply_and_re_solicits() {
  // The CROSSING REQUIREMENT. A forced cross-epoch fetch (`require_cross_epoch`) must NOT
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let predecessor = genesis(3);
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid");
  let laggard_config_id = e.membership.config_id();
  // A higher-epoch Commit advertising the cluster checkpoint at N → the forced crossing fetch.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
  blocks.put(below_snap.clone());
  e.handle_message(
    now,
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  for _ in 0..3 {
    e.storage_step(now, &mut storage, &mut blocks);
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
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(n),
        cross_id,
        successor.epoch(),
        successor.config_id(),
        ReplicaId::new(0),
        nonce2,
        cross_env.clone(),
        membership_body,
      )
      .with_config_install_op(OpNumber::with(n)),
    ),
  );
  e.block_step(now, &mut storage, &mut blocks);
  for _ in 0..3 {
    e.storage_step(now, &mut storage, &mut blocks);
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
  // VERIFICATION IS THE AUTHORITY, not the unverified hint. The cross-epoch trigger
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let predecessor = genesis(3);
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid");
  let laggard_config_id = e.membership.config_id();

  // A higher-epoch `EpochAhead` hint carrying the BOGUS unreachable checkpoint_op → the speculative
  // crossing fetch arms with that bogus value as its (sticky) target.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
  blocks.put(CountSm::default().snapshot());
  e.handle_message(
    now,
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  for _ in 0..3 {
    e.storage_step(now, &mut storage, &mut blocks);
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
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(n),
        cross_id,
        successor.epoch(),
        successor.config_id(),
        ReplicaId::new(0),
        nonce2,
        cross_env.clone(),
        membership_body,
      )
      .with_config_install_op(OpNumber::with(n)),
    ),
  );
  e.block_step(now, &mut storage, &mut blocks);
  for _ in 0..3 {
    e.storage_step(now, &mut storage, &mut blocks);
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
fn a_stranded_learner_crosses_an_epoch_via_the_pulled_epoch_ahead_hint() {
  // THE LEARNER PULL LANE. A learner stranded ONE epoch behind has NO catch-up lane when no
  // successor-epoch primary traffic reaches it: its SOLE emission is `LearnerStatus`. This drives the
  // full round-trip: the learner's `LearnerStatus` to an E+1 member draws an `EpochAhead` hint (the
  // egress trigger `maybe_answer_lower_epoch` now recognizes), the learner arms the forced crossing sync
  // off that pulled hint, and a verified successor reply crosses it to E+1. Without `LearnerStatus` in the
  // trigger set the member answers nothing, the learner never arms the sync, and it never crosses.
  let n: u64 = 4; // the E+1 checkpoint the member advertises and a donor serves (the crossing target).

  // Epoch-0 configuration: 3 voters + the stranded learner MemberId 3. Epoch-1 successor: the same, plus
  // a new learner MemberId 4 — a valid single-delta successor chained from E0 in which MemberId 3 stays a
  // learner (so the member resolves its slot, and it crosses into a config it belongs to).
  let predecessor = genesis_with_learners(3, 1);
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(4)))
    .expect("AddLearner on the 3-voter + 1-learner genesis is valid");

  // The stranded LEARNER at E0: op 0, checkpoint 0 (checkpoint == its own op head), Normal.
  let learner_cfg = Config::with_checkpoint_ops(1, MemberId::new(3), 100).unwrap();
  let mut learner = Endpoint::<_, RestartOnly>::genesis_unchecked(
    learner_cfg,
    predecessor.clone(),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (lwal, lsb) = (TestWal::default(), TestSb::default());
  let mut lstorage = Storage::new(lwal, lsb);
  let mut lblocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  assert!(
    learner.is_learner() && learner.membership.epoch() == crate::Epoch::new(0),
    "the local node is a learner at E0"
  );
  let learner_config_id = learner.membership.config_id();

  // The learner emits its progress report — its only lane, since no E+1 primary traffic reaches it.
  // Bootstrap the cadence, then advance past it and fire; capture the emitted `LearnerStatus`.
  learner.handle_timeout(now, &mut lstorage);
  let t1 = now + core::time::Duration::from_millis(10_000);
  learner.handle_timeout(t1, &mut lstorage);
  let mut status = None;
  while let Some(out) = learner.poll_message() {
    if matches!(out.msg_ref(), Message::LearnerStatus(_)) {
      status = Some(out.into_msg());
    }
  }
  let status = status.expect("the stranded learner emits a LearnerStatus (its sole crossing lane)");

  // The E+1 MEMBER: a settled Normal voter (MemberId 0, the view-0 primary of the successor config) whose
  // cluster checkpoint is at N.
  let member_cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 100).unwrap();
  let mut member = Endpoint::<_, RestartOnly>::genesis_unchecked(
    member_cfg,
    successor.clone(),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let (mwal, msb) = (TestWal::default(), TestSb::default());
  let mut mstorage = Storage::new(mwal, msb);
  member.force_state_for_test(0, n, n, n, &[]);
  assert!(
    member.status().is_normal()
      && member.membership.epoch() == crate::Epoch::new(1)
      && member.checkpoint_op() == OpNumber::with(n),
    "the member is a settled E+1 node with checkpoint N"
  );

  // THE HINGE: the member answers the learner's LearnerStatus with EpochAhead(E+1, N). The learner
  // presents at slot 3 (its seat in the E+1 config); the member resolves it and pulls the hint back. This
  // emission is exactly what F3 adds — without the `LearnerStatus` trigger the member stays silent here.
  member.handle_message(now, &mut mstorage, Peer::Replica(ReplicaId::new(3)), status);
  let hint = member
    .poll_message()
    .expect("the member answers the learner's LearnerStatus with a hint");
  assert_eq!(
    hint.to(),
    crate::Recipient::To(Peer::Replica(ReplicaId::new(3))),
    "the pulled hint is addressed back to the learner",
  );
  let hint_msg = hint.into_msg();
  assert!(
    member.poll_message().is_none(),
    "exactly one hint per inbound LearnerStatus",
  );
  let Message::EpochAhead(h) = &hint_msg else {
    panic!(
      "the response is an EpochAhead hint, got {}",
      hint_msg.kind_str()
    );
  };
  assert_eq!(h.epoch(), crate::Epoch::new(1), "carries the E+1 epoch");
  assert_eq!(
    h.checkpoint_op(),
    OpNumber::with(n),
    "carries the E+1 checkpoint_op (the crossing target)",
  );

  // The learner consumes the SAME pulled hint (delivered from a bound retained voter) → arms the forced,
  // crossing-required cross-epoch sync targeting N.
  learner.handle_message(t1, &mut lstorage, primary_peer(), hint_msg);
  assert!(
    learner.status().is_normal()
      && learner.sync_is_forced_for_test()
      && learner.sync_requires_cross_epoch_for_test(),
    "the learner armed a crossing-required forced sync off the pulled hint (staying Normal)"
  );
  assert_eq!(
    learner.sync_target_for_test(),
    Some(n),
    "the forced sync targets the hinted checkpoint_op"
  );
  let nonce = learner.sync_nonce_for_test();

  // A donor serves the verified E+1 successor checkpoint at N → the learner crosses and installs E+1.
  let cross_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(n),
    crate::block_address(&CountSm::default().snapshot()),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut lblocks),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor, predecessor.config_id())
      .encode_body();
  lblocks.put(CountSm::default().snapshot());
  learner.handle_message(
    t1,
    &mut lstorage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(n),
        cross_id,
        successor.epoch(),
        successor.config_id(),
        ReplicaId::new(0),
        nonce,
        cross_env.clone(),
        membership_body,
      )
      .with_config_install_op(OpNumber::with(n)),
    ),
  );
  for _ in 0..3 {
    learner.storage_step(t1, &mut lstorage, &mut lblocks);
  }
  assert_eq!(
    learner.membership, successor,
    "the stranded learner CROSSED to the E+1 successor membership"
  );
  assert_ne!(
    learner.membership.config_id(),
    learner_config_id,
    "the config_id advanced off the predecessor"
  );
  assert_eq!(
    learner.membership.epoch(),
    crate::Epoch::new(1),
    "installed E+1"
  );
  assert_eq!(
    learner.forced_syncs_applied(),
    1,
    "exactly one crossing applied"
  );
  assert!(
    learner.is_learner(),
    "still a non-voting learner in the E+1 config"
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
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner is valid");
  // A REAL checkpoint envelope at op 2 (so recover's decode + bind + id checks all pass).
  let (_d, dstorage) = donor_primary_at_checkpoint(2);
  let (env, env_id) = donor_envelope(&dstorage);
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
  let wal = TestWal::default();
  let sb = TestSb {
    state: swap_root,
    done: VecDeque::new(),
    checkpoint: Some((OpNumber::with(2), env)),
  };
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis_mem, 9, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // Drive the recovery storage to completion (the checkpoint read restores the SM + sessions).
  let now = Instant::ZERO;
  for _ in 0..8 {
    e.storage_step(now, &mut storage, &mut blocks);
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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks); // drive the durable re-persist → install

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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
    &mut storage,
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
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks); // drive the durable re-persist → install

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
  let (mut e2, mut storage2, _env2, _id2) = sync_apply_harness(4);
  e2.arm_cross_epoch_sync_for_test(1000);
  e2.handle_message(
    now,
    &mut storage2,
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
    &mut storage2,
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
  let (mut e, mut storage, _env, _id) = sync_apply_harness(4);
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
    &mut storage,
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
  let (mut e, mut storage, _env, _id) = sync_apply_harness(4);
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
    &mut storage,
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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // (1) An ORDINARY same-epoch FORCED sync to the donor checkpoint (op 4), and the matching same-epoch
  // (epoch 0, empty-membership) reply → `apply_sync` STAGES the install with `successor` None.
  e.arm_forced_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
    e.storage_step(now, &mut storage, &mut blocks);
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
  let (mut e, mut storage, _env, _id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let m = 4u64; // the E+1 crossing checkpoint
  let successor_e1 = genesis(3)
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid (E+1)");

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
  blocks.put(CountSm::default().snapshot());
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor_e1, genesis(3).config_id())
      .encode_body();
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(m),
        cross_id,
        successor_e1.epoch(),
        successor_e1.config_id(),
        ReplicaId::new(0),
        nonce,
        cross_env,
        membership_body,
      )
      .with_config_install_op(OpNumber::with(m)),
    ),
  );
  e.block_step(now, &mut storage, &mut blocks);
  assert!(e.pending_install.is_some(), "the crossing install staged");
  for _ in 0..4 {
    e.storage_step(now, &mut storage, &mut blocks);
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
  let (mut e, mut storage, _env, _id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  // A REAL higher-epoch trigger sets the intent AND arms a crossing sync (NOT the `_for_test` helper).
  e.handle_message(
    now,
    &mut storage,
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
  let (mut e, mut storage, _env, _id) = sync_apply_harness(4);
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
    &mut storage,
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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");

  // Laggard store: SM DAG present (drains locally), session DAG absent — so the same-config checkpoint arms
  // a LIVE block-fetch (active address = `sessions_root`) rather than installing or staging.
  let mut donor_blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
      blocks.put(block);
    }
  }
  assert!(
    !blocks.has_block(sessions_root),
    "session DAG absent → a live fetch arms"
  );

  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let now = Instant::ZERO;

  // Arm a CROSSING sync, then deliver a SAME-CONFIG (epoch 0, empty-membership) checkpoint at op 4: the
  // cross-epoch solicit admits it onto the fetch path, arming a live fetch that does NOT present a crossing.
  e.arm_cross_epoch_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // Reach Test 1's cleared-intent state: stage an ordinary (successor None) install, pin a stale intent,
  // then clear it with a same-epoch head Commit.
  e.arm_forced_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  e.set_cross_epoch_intent_for_test(7);
  e.handle_message(
    now,
    &mut storage,
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
    e.storage_step(now, &mut storage, &mut blocks);
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
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // (1) An ORDINARY same-config FORCED sync to op 4, and its matching same-epoch (empty-membership) reply →
  // `apply_sync` STAGES the install (`successor: None`) and clears the transfer; the root is NOT yet durable.
  e.arm_forced_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
    &mut storage,
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
    e.storage_step(now, &mut storage, &mut blocks);
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
  let (mut e, mut storage, _env, _id) = sync_apply_harness(4);
  let now = Instant::ZERO;

  // A REAL higher-epoch trigger arms a bare crossing-required sync + the persistent intent (no SyncCheckpoint
  // answered it yet → no transfer, no staged install).
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  let wal = TestWal::default();
  let sb = StepSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let m = 4u64; // the E+1 crossing checkpoint op
  let successor_e1 = genesis(3)
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid (E+1)");

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
  blocks.put(CountSm::default().snapshot());
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor_e1, genesis(3).config_id())
      .encode_body();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(m),
        cross_id,
        successor_e1.epoch(),
        successor_e1.config_id(),
        ReplicaId::new(0),
        nonce,
        cross_env,
        membership_body,
      )
      .with_config_install_op(OpNumber::with(m)),
    ),
  );
  e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
  e.handle_timeout(later, &mut storage); // primary_idle → SVC(view 1), own bit
  e.handle_message(
    later,
    &mut storage,
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
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let m = 4u64; // the E+1 crossing checkpoint op
  let successor_e1 = genesis(3)
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid (E+1)");

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
  blocks.put(CountSm::default().snapshot());
  blocks.script_flush_fault(1); // the install's durability barrier faults — the crossing is RETAINED
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor_e1, genesis(3).config_id())
      .encode_body();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(m),
        cross_id,
        successor_e1.epoch(),
        successor_e1.config_id(),
        ReplicaId::new(0),
        nonce,
        cross_env,
        membership_body,
      )
      .with_config_install_op(OpNumber::with(m)),
    ),
  );
  e.storage_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
  e.handle_timeout(later, &mut storage); // primary_idle → SVC(view 1), own bit
  e.handle_message(
    later,
    &mut storage,
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
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let m = 4u64; // the E+1 crossing checkpoint op
  let successor_e1 = genesis(3)
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid (E+1)");

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
  blocks.put(CountSm::default().snapshot());
  blocks.script_flush_fault(1); // the crossing's durability barrier faults — it is RETAINED
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor_e1, genesis(3).config_id())
      .encode_body();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(m),
        cross_id,
        successor_e1.epoch(),
        successor_e1.config_id(),
        ReplicaId::new(0),
        nonce,
        cross_env,
        membership_body,
      )
      .with_config_install_op(OpNumber::with(m)),
    ),
  );
  e.storage_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);

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
  e.gc_blocks_for_test(&mut storage);
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(
    blocks.has_block(crossing_sm_root) && blocks.has_block(crossing_sessions_root),
    "the crossing's DAG roots SURVIVED GC — the retained crossing is a live root despite the stale reply"
  );

  // The original crossing still COMPLETES on the local retry (no fresh donor reply): its flush now succeeds,
  // stages the re-persist, and the SAME verified successor membership installs — the laggard crosses to E+1.
  let later = now + core::time::Duration::from_millis(150);
  e.sync_timeouts(later, &mut storage);
  e.storage_step(later, &mut storage, &mut blocks);
  for _ in 0..6 {
    e.storage_step(later, &mut storage, &mut blocks);
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
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let m = 4u64;
  let successor_e1 = genesis(3)
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid (E+1)");

  // (1) Drive the laggard into a Recovering, cross-epoch (`require_cross_epoch`) peer-fetch directly, then
  // deliver a VERIFIED crossing reply with a SCRIPTED FLUSH FAULT so the recovery `apply_sync` RETAINS the
  // crossing as an owed `pending_install` while STAYING Recovering.
  let mut storage = Storage::new(wal, sb);
  e.enter_cross_epoch_peer_fetch(now, &mut storage, OpNumber::with(m));
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
  blocks.put(CountSm::default().snapshot());
  blocks.script_flush_fault(1);
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor_e1, genesis(3).config_id())
      .encode_body();
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(
      crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(m),
        cross_id,
        successor_e1.epoch(),
        successor_e1.config_id(),
        ReplicaId::new(0),
        nonce,
        cross_env,
        membership_body,
      )
      .with_config_install_op(OpNumber::with(m)),
    ),
  );
  e.storage_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
  e.gc_blocks_for_test(&mut storage);
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(
    blocks.has_block(crossing_sm_root) && blocks.has_block(crossing_sessions_root),
    "the crossing's DAG roots SURVIVED GC despite the rejected stale recovery reply (a live GC root)"
  );

  // The crossing completes on the LOCAL recovery retry (no fresh donor reply): the flush succeeds, stages the
  // re-persist, and `on_sb_done` installs the successor — the laggard crosses into E+1 and leaves Recovering.
  let later = now + core::time::Duration::from_millis(300);
  for _ in 0..16 {
    e.recover_timeouts(later, &mut storage);
    e.storage_step(later, &mut storage, &mut blocks);
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
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  // Drive the backup to commit_min = 4, checkpoint_op = 0 (no checkpoint — interval is huge).
  // The backup has slot 1; primary (slot 0) drives Prepares and commits via PrepareOks.
  let mut storage = Storage::new(wal, sb);
  for rn in 1..=4u64 {
    e.handle_message(
      now,
      &mut storage,
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
    e.storage_step(now, &mut storage, &mut blocks); // own append → own vote
    e.handle_message(
      now,
      &mut storage,
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
  let (_, dstorage) = donor_primary_at_checkpoint(2);
  let (env2, id2) = donor_envelope(&dstorage);
  seed_donor_blocks(&mut blocks, 2);

  // Deliver the stale same-config reply at op 2 (below commit_min = 4). The freshness gates admit
  // it (op=2 > checkpoint_op=0; `require_cross_epoch` bypasses the `< target` gate). `apply_sync`
  // sees a forced sync with `checkpoint_op (2) < commit_min (4)` — without the crossing carve-out
  // it would teardown `sync`; WITH the fix it exempts a crossing and returns without clearing.
  e.handle_message(
    now,
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);

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
fn the_donor_serve_is_bounded_and_the_cap_releases_as_the_lane_drains() {
  // THE DONOR READ RUNS OFF THE PUMP, so the rate `RequestBlock`s arrive at is independent of the rate
  // the storage lane drains them. Without a bound, a peer (or a partition-induced retransmit storm)
  // would grow the job queue with the inbound rate. The cap refuses past
  // `MAX_OUTSTANDING_BLOCK_SERVES` and COUNTS the refusal; a refused request is DROPPED rather than
  // answered ABSENT, because an absent reply for a block we hold would drive the requester's
  // pruned-front re-solicit path instead of its plain ARQ re-send.
  let mut e = sync_backup();
  let mut storage = Storage::new(TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let addr = blocks.put(Bytes::from_static(b"a-served-block"));
  while e.poll_message().is_some() {}

  // Fill the window exactly, then push four more past it. Nothing is drained in between, so every
  // request lands while the previous ones are still outstanding.
  const OVER: usize = 4;
  for _ in 0..(super::MAX_OUTSTANDING_BLOCK_SERVES + OVER) {
    e.on_request_block(&mut storage, primary_peer(), addr);
  }
  // ANTI-VACUITY: the cap was genuinely REACHED — the excess is refused and counted, not merely
  // absent. Without this the assertions below would hold vacuously on an under-filled window.
  assert_eq!(
    e.block_serves_refused(),
    OVER as u64,
    "exactly the requests past the cap are refused"
  );
  assert!(
    e.has_inflight_storage(&storage),
    "the admitted serves are outstanding storage work"
  );
  assert_eq!(
    core::iter::from_fn(|| e.poll_message()).count(),
    0,
    "a refused request is DROPPED — it must not be answered ABSENT for a block we hold"
  );

  // Drain the lane: every ADMITTED serve answers, and exactly those.
  e.block_step(now, &mut storage, &mut blocks);
  let served: usize = core::iter::from_fn(|| e.poll_message())
    .filter(|out| match out.msg_ref() {
      Message::BlockResponse(m) => m.addr() == addr && m.is_present(),
      _ => false,
    })
    .count();
  assert_eq!(
    served,
    super::MAX_OUTSTANDING_BLOCK_SERVES,
    "every admitted serve answered with the block, and no refused one did"
  );

  // THE CAP RELEASES. It bounds the outstanding set, not the lifetime total: a request arriving after
  // the lane drained is served normally, so a burst costs the requester one round trip, never a wedge.
  e.on_request_block(&mut storage, primary_peer(), addr);
  e.block_step(now, &mut storage, &mut blocks);
  assert!(
    core::iter::from_fn(|| e.poll_message())
      .any(|out| matches!(out.msg_ref(), Message::BlockResponse(m) if m.addr() == addr)),
    "the window freed as the lane drained — a later request is served"
  );
  assert_eq!(
    e.block_serves_refused(),
    OVER as u64,
    "and no further refusal was counted"
  );
}

#[test]
fn a_restore_fault_arrives_asynchronously_while_the_reconstruct_obligation_gates_the_window() {
  // THE RESTORE IS STORAGE WORK, NOT CONSENSUS WORK. Rebuilding the state machine from a synced
  // checkpoint's DAG reads every block of that DAG, so it runs OFF the pump as a job — which means the
  // verify-on-read FAULT that a bit-rotted block produces arrives ASYNCHRONOUSLY, an unbounded interval
  // after the durable root that advanced the frontier to M.
  //
  // That interval is the whole point of the `SmReconstruct` obligation, and this pins its two halves:
  //
  //   * it is raised BEFORE the job, so it gates the ENTIRE window (not just the post-fault retry) —
  //     the state machine is withheld while the frontier already names M;
  //   * the fault REGRESSES NOTHING when it lands — the frontier stays at M (in lockstep with the
  //     durable root), the obligation stays owed, and the fetch re-arms to re-pull the bad block.
  //
  // Before the seam this could not be expressed: the restore ran inside `install_sync`, on the pump,
  // in the same call as the root completion, so there was no instant at which a restore was outstanding
  // and no completion to deliver a fault through.
  let (_donor_m, dstorage_m) = donor_primary_at_checkpoint(4);
  let (env_m, id_m) = donor_envelope(&dstorage_m);
  let clean_snapshot = {
    let mut donor_sm = CountSm::default();
    for rn in 1..=4u64 {
      donor_sm.apply(OpNumber::with(rn), &[rn as u8]);
    }
    donor_sm.snapshot()
  };
  let sm_root_m = crate::block_address(&clean_snapshot);

  // A huge checkpoint interval so no auto-checkpoint races the sync persist.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let wal = TestWal::default();
  let sb = StepSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // Trigger the sync, then deliver M's `SyncCheckpoint`: its DAG is already local, so the transfer
  // drains on the first walk and `apply_sync` stages the two-write re-persist.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
  e.handle_message(
    now,
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  assert!(
    e.pending_install.is_some(),
    "setup: M is staged, its re-persist in flight (pre-root)"
  );

  // The block bit-rots AFTER the transfer drained and BEFORE the reconstruct reads it — the exact
  // window the verify-on-read restore exists for. The planted bytes do not hash to `sm_root_m`.
  blocks.insert_raw(sm_root_m, Bytes::copy_from_slice(b"post-drain-bit-rot"));

  // Drive ONLY the superblock writes (snapshot, then root). The root completion runs `install_sync`,
  // which advances the frontier and ISSUES the reconstruct — and stops there, because the endpoint
  // holds no store. Deliberately NOT a lane step: this is the instant the reconstruct is outstanding.
  storage.sb_mut().flush();
  e.handle_storage(now, &mut storage);
  storage.sb_mut().flush();
  e.handle_storage(now, &mut storage);

  // ANTI-VACUITY: the RESTORE — not some other job — really is outstanding here, the obligation
  // already gates it, and the frontier has already moved to M. Without these the fault below could be
  // landing on an endpoint that never had a reconstruct in flight at all.
  let restore = storage
    .poll_block_job()
    .expect("the durable root issued the reconstruct");
  assert_eq!(
    restore.tag(),
    crate::BlockJobTag::Restore,
    "the outstanding job IS the SM reconstruct"
  );
  assert!(
    e.sm_reconstruct_owed(),
    "the obligation is raised BEFORE the job, so it covers the whole reconstruct window"
  );
  assert!(
    e.has_inflight_storage(&storage),
    "an outstanding reconstruct counts as durability work the drain must wait for"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the frontier already names M (in lockstep with the durable root) while the SM lags it"
  );
  assert_eq!(e.commit(), OpNumber::with(4), "and so does commit_min");
  assert!(
    e.state_machine().is_none(),
    "the SM is WITHHELD across the window — it does not hold M's content yet"
  );
  assert_eq!(
    e.state_syncs_applied(),
    0,
    "and the sync is not complete while the reconstruct is outstanding"
  );

  // THE FAULT ARRIVES. The job read the bit-rotted block through the verify-on-read view, so its
  // completion carries the error — an unbounded interval after the root that advanced the frontier.
  while e.poll_message().is_some() {}
  let mut cursor = crate::BlockJobCursor::new();
  let faulted = crate::execute_block_job(&mut cursor, restore, &mut blocks);
  e.on_block_done(now, &mut storage, faulted);

  // NOTHING REGRESSED. The frontier is where the durable root put it, the obligation still gates the
  // SM, and the fetch re-armed to re-pull exactly the block that failed.
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the fault rewinds no pointer — in-memory still equals the durable root"
  );
  assert_eq!(
    storage.sb_mut().state().checkpoint_op(),
    OpNumber::with(4),
    "and the durable root still names M"
  );
  assert_eq!(e.commit(), OpNumber::with(4), "commit_min is not rewound");
  assert!(
    e.sm_reconstruct_owed(),
    "the obligation STAYS owed — the SM still does not hold M"
  );
  assert!(
    e.state_machine().is_none(),
    "so the SM stays withheld rather than exposing pre-M content under a valid M pointer"
  );
  assert_eq!(
    e.state_syncs_applied(),
    0,
    "and the sync is still not complete"
  );
  e.block_step(now, &mut storage, &mut blocks);
  assert!(
    core::iter::from_fn(|| e.poll_message())
      .any(|out| matches!(out.msg_ref(), Message::RequestBlock(addr) if *addr == sm_root_m)),
    "the obligation re-armed its fetch and re-pulls the block that faulted"
  );

  // THE REPAIR. The donor answers the re-pull with the clean bytes, which overwrite the corrupt block,
  // and re-serves M's envelope — the donor-failover path. That re-pin walks the now-complete DAG and
  // re-issues the reconstruct, which this time succeeds: the SM reaches M and the sync completes
  // through the SAME tail a clean first reconstruct takes. (A re-arm that followed the FAULT alone does
  // NOT re-issue on its own — it would re-read the same bad block and spin; the fresh reply is the new
  // evidence that makes one more attempt worthwhile.)
  blocks.put(clean_snapshot);
  let later = now + core::time::Duration::from_millis(101);
  let nonce_after = e.sync_nonce_for_test();
  e.handle_message(
    later,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id_m,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce_after,
      env_m,
      Bytes::new(),
    )),
  );
  e.block_step(later, &mut storage, &mut blocks);
  for _ in 0..4 {
    storage.sb_mut().flush();
    e.storage_step(later, &mut storage, &mut blocks);
  }
  assert!(
    !e.sm_reconstruct_owed(),
    "the repaired DAG reconstructed the SM at M — the obligation is met"
  );
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "and the sync completed through the SAME tail a clean first reconstruct takes"
  );
  assert!(
    e.state_machine().is_some(),
    "the SM is exposed again once it genuinely holds M"
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
  let (_donor_m, dstorage_m) = donor_primary_at_checkpoint(4);
  let (env_m, id_m) = donor_envelope(&dstorage_m);
  let (_donor_c, dstorage_c) = donor_primary_at_checkpoint(2);
  let (env_c, id_c) = donor_envelope(&dstorage_c);
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
  let wal = TestWal::default();
  let sb = StepSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  // Seed C's block so a C reply (if not rejected) would drain its block-fetch immediately —
  // this is the adversarial block that would rewind M's durable root without the monotone reject.
  let snap_c = {
    let mut donor_sm = CountSm::default();
    for rn in 1..=2u64 {
      donor_sm.apply(OpNumber::with(rn), &[rn as u8]);
    }
    donor_sm.snapshot()
  };
  blocks.put(snap_c.clone());
  // Seed M's block so the SyncCheckpoint can drain and reach apply_sync.
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // Trigger a sync at the LOW target T=2 (Commit with checkpoint_op=2, commit_min=2).
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  assert!(
    e.pending_install.is_some(),
    "M staged: pending_install is Some while the re-persist is in flight (PRE-ROOT)"
  );

  // CORRUPT M's block AFTER staging. The corrupt bytes do not hash to sm_root_m, so the
  // verify-on-read in install_sync returns an error.
  blocks.insert_raw(sm_root_m, Bytes::copy_from_slice(b"post-stage-corruption"));

  // Drive the two-write re-persist to completion (step 1: snapshot; step 2: root).
  // `install_sync` advances the frontier to M, then FAILS the SM restore on the corrupt block.
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);

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
    storage.sb_mut().state().checkpoint_op(),
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  for _ in 0..4 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
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
  Storage<TestWal, StepSb, CountSm>,
  InMemoryBlockStore,
  BlockAddress,
  u128,
) {
  let (_donor_m, dstorage_m) = donor_primary_at_checkpoint(4);
  let (env_m, id_m) = donor_envelope(&dstorage_m);
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
  let wal = TestWal::default();
  let sb = StepSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;

  // Trigger a sync at the LOW target T=2.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  assert!(e.pending_install.is_some(), "M staged");

  // CORRUPT M's block, then drive the two-write re-persist: install_sync fails on the root completion.
  blocks.insert_raw(sm_root_m, Bytes::copy_from_slice(b"post-stage-corruption"));
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);

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
    storage.sb_mut().state().checkpoint_op(),
    OpNumber::with(4),
    "M's durable root names checkpoint_op=4 — equal to the in-memory checkpoint_op"
  );
  let m_checkpoint_id = storage.sb_mut().state().checkpoint_id();
  (e, storage, blocks, sm_root_m, m_checkpoint_id)
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
  InMemoryBlockStore,
) {
  let mut donor_sm = TwoLeafSm::default();
  for rn in 1..=ckpt {
    donor_sm.apply(OpNumber::with(rn), &[rn as u8]);
  }
  let (leaf_x, leaf_y) = donor_sm.leaves();
  let xa = block_address(&leaf_x);
  let ya = block_address(&leaf_y);
  let mut store = InMemoryBlockStore::new();
  let sm_root = {
    let mut sm = TwoLeafSm::default();
    for rn in 1..=ckpt {
      sm.apply(OpNumber::with(rn), &[rn as u8]);
    }
    // writes root + both leaves CLEAN into `store`, returns the root addr
    TwoLeafSm::materialize(&sm.checkpoint_image(), &mut store)
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
  Storage<TestWal, StepSb, TwoLeafSm>,
  InMemoryBlockStore,
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
  let wal = TestWal::default();
  let sb = StepSb::default();
  // Seed the laggard's store with the WHOLE clean DAG so the block-fetch drains locally at stage; the
  // targeted leaf is corrupted AFTER staging (mirroring the single-block helper).
  let mut blocks = InMemoryBlockStore::new();
  {
    let (_e2, _id2, _root2, _x2, _y2, donor_store) = two_leaf_dag(4);
    for addr in [sm_root_m, _x2, _y2] {
      if let Some(b) = donor_store.read_block(addr) {
        blocks.put(b);
      }
    }
    // Also seed the (empty) session-table DAG so the install frontier drains both DAGs locally.
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks);
  }
  let now = Instant::ZERO;

  // Trigger a sync at the LOW target T=2.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  assert!(e.pending_install.is_some(), "M staged");

  // Corrupt the TARGETED leaf, then drive the barrier + the two-write re-persist: install_sync's
  // restore faults on it.
  blocks.insert_raw(corrupt, Bytes::copy_from_slice(b"post-stage-corruption"));
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);

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
  let m_checkpoint_id = storage.sb_mut().state().checkpoint_id();
  (e, storage, blocks, sm_root_m, m_checkpoint_id)
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
  let (mut a, mut astorage, mut ablocks, _a_root, m_id) = laggard_owing_two_leaf_at_m(1, leaf_x);
  let (mut b, mut bstorage, mut bblocks, _b_root, _b_mid) = laggard_owing_two_leaf_at_m(2, leaf_y);

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
                 storage: &mut Storage<TestWal, StepSb, TwoLeafSm>,
                 blocks: &mut InMemoryBlockStore|
   -> crate::RequestSync {
    while e.poll_message().is_some() {}
    e.sync_timeouts(later, storage);
    e.storage_step(later, storage, blocks);
    core::iter::from_fn(|| e.poll_message())
      .find_map(|out| match out.msg_ref() {
        Message::RequestSync(r) => Some(*r),
        _ => None,
      })
      .expect("the owed-reconstruct ARQ broadcasts a RequestSync")
  };
  let a_sol = solicit(&mut a, &mut astorage, &mut ablocks);
  let b_sol = solicit(&mut b, &mut bstorage, &mut bblocks);
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
                        dstorage: &mut Storage<TestWal, StepSb, TwoLeafSm>,
                        dblocks: &mut InMemoryBlockStore,
                        to: ReplicaId,
                        sol: &crate::RequestSync|
   -> Option<crate::SyncCheckpoint> {
    while donor.poll_message().is_some() {}
    donor.on_request_sync(
      later,
      dstorage,
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
    dstorage.sb_mut().flush();
    donor.storage_step(later, dstorage, dblocks);
    core::iter::from_fn(|| donor.poll_message()).find_map(|out| match out.into_msg() {
      Message::SyncCheckpoint(m) => Some(m),
      _ => None,
    })
  };

  // B serves A's solicitation (A's failover donor), and A serves B's. Each ships a verified M envelope.
  let b_to_a = serve_envelope(&mut b, &mut bstorage, &mut bblocks, a_id, &a_sol)
    .expect("an owed B SERVES A's equal-checkpoint repair (envelope) — the decouple");
  let a_to_b = serve_envelope(&mut a, &mut astorage, &mut ablocks, b_id, &b_sol)
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
               storage: &mut Storage<TestWal, StepSb, TwoLeafSm>,
               blocks: &mut InMemoryBlockStore,
               donor: ReplicaId,
               env: crate::SyncCheckpoint|
   -> crate::BlockAddress {
    while e.poll_message().is_some() {}
    e.handle_message(
      later,
      storage,
      Peer::Replica(donor),
      Message::SyncCheckpoint(env),
    );
    e.block_step(later, storage, blocks);
    core::iter::from_fn(|| e.poll_message())
      .find_map(|out| match (out.to(), out.msg_ref()) {
        (Recipient::To(Peer::Replica(d)), Message::RequestBlock(addr)) if d == donor => Some(*addr),
        _ => None,
      })
      .expect("the re-pinned fetch requests the locally-faulted leaf from the FRESH donor")
  };
  let a_wants = repin(&mut a, &mut astorage, &mut ablocks, b_id, b_to_a);
  let b_wants = repin(&mut b, &mut bstorage, &mut bblocks, a_id, a_to_b);
  assert_eq!(a_wants, leaf_x, "A re-pulls its faulted leaf-x (from B)");
  assert_eq!(b_wants, leaf_y, "B re-pulls its faulted leaf-y (from A)");

  // THE SECOND LOAD-BEARING ASSERTION: each owed donor's `on_request_block` SERVES the CLEAN block it
  // holds (its own un-faulted leaf) via the verified read — and would return ABSENT for the leaf IT
  // faulted on (proven by `a_wants`/`b_wants` being exactly the complementary leaves).
  let serve_block = |donor: &mut Endpoint<TwoLeafSm>,
                     dstorage: &mut Storage<TestWal, StepSb, TwoLeafSm>,
                     dblocks: &mut InMemoryBlockStore,
                     to: ReplicaId,
                     addr: crate::BlockAddress|
   -> crate::BlockResponse {
    while donor.poll_message().is_some() {}
    donor.on_request_block(dstorage, Peer::Replica(to), addr);
    donor.storage_step(later, dstorage, dblocks);
    core::iter::from_fn(|| donor.poll_message())
      .find_map(|out| match out.into_msg() {
        Message::BlockResponse(m) => Some(m),
        _ => None,
      })
      .expect("the owed donor answers the block request")
  };
  // B serves A its clean leaf-x; A serves B its clean leaf-y.
  let x_from_b = serve_block(&mut b, &mut bstorage, &mut bblocks, a_id, a_wants);
  let y_from_a = serve_block(&mut a, &mut astorage, &mut ablocks, b_id, b_wants);
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
                  storage: &mut Storage<TestWal, StepSb, TwoLeafSm>,
                  blocks: &mut InMemoryBlockStore,
                  donor: ReplicaId,
                  resp: crate::BlockResponse| {
    while e.poll_message().is_some() {}
    e.handle_message(
      later,
      storage,
      Peer::Replica(donor),
      Message::BlockResponse(resp),
    );
    e.block_step(later, storage, blocks);
    for _ in 0..4 {
      storage.sb_mut().flush();
      e.storage_step(later, storage, blocks);
    }
  };
  complete(&mut a, &mut astorage, &mut ablocks, b_id, x_from_b);
  complete(&mut b, &mut bstorage, &mut bblocks, a_id, y_from_a);

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
                 storage: &mut Storage<TestWal, StepSb, TwoLeafSm>,
                 _blocks: &mut InMemoryBlockStore,
                 peer: ReplicaId| {
    while e.poll_message().is_some() {}
    e.handle_message(
      later,
      storage,
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
  resumes(&mut a, &mut astorage, &mut ablocks, b_id);
  resumes(&mut b, &mut bstorage, &mut bblocks, a_id);

  // The genuinely-unrecoverable case stays correctly FENCED, NOT weakened. Prove the boundary: a debtor
  // re-faults BOTH the locally-held leaf AND re-pins to a donor that ALSO faulted that same leaf — the
  // block is lost on every reachable donor. The envelope re-pin still succeeds, but every `RequestBlock`
  // for that leaf is answered ABSENT (verified read → None), so the fetch never drains, the obligation
  // stays owed, the frontier stays at M, and the SM stays withheld — no rewind, no weakened verification.
  // C is a slot-1 debtor that faulted leaf-x; its only reachable donor (slot 2) ALSO faulted leaf-x — so
  // leaf-x is lost on every reachable donor.
  let (mut c, mut cstorage, mut cblocks, _c_root, c_mid) = laggard_owing_two_leaf_at_m(1, leaf_x);
  let (mut bad_donor, mut bstorage2, mut bdblocks, _bd_root, _bd_mid) =
    laggard_owing_two_leaf_at_m(2, leaf_x);
  let c_sol = solicit(&mut c, &mut cstorage, &mut cblocks);
  let donor_env = serve_envelope(&mut bad_donor, &mut bstorage2, &mut bdblocks, a_id, &c_sol)
    .expect("even an owed bad-donor serves the equal-checkpoint envelope (the re-pin succeeds)");
  assert_eq!(
    donor_env.checkpoint_id(),
    c_mid,
    "the re-pin envelope names M"
  );
  let c_wants = repin(&mut c, &mut cstorage, &mut cblocks, b_id, donor_env);
  assert_eq!(c_wants, leaf_x, "C still needs leaf-x");
  // The bad donor cannot serve leaf-x (it faulted it too): `on_request_block` returns an ABSENT response.
  while bad_donor.poll_message().is_some() {}
  bad_donor.on_request_block(&mut bstorage2, Peer::Replica(a_id), c_wants);
  bad_donor.storage_step(later, &mut bstorage2, &mut bdblocks);
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
  complete(&mut c, &mut cstorage, &mut cblocks, b_id, absent);
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
  let (mut e, mut storage, mut blocks, _sm_root_m, m_checkpoint_id) =
    laggard_owing_sm_reconstruct_at_m();
  let now = Instant::ZERO;

  // Enter a view change: two peers send StartViewChange(view 1) → SVC quorum → ViewChange(1), which
  // submits a durable-VIEW write. This is the teardown + durable-root write that must not rewind M.
  for r in [1u16, 2] {
    e.handle_message(
      now,
      &mut storage,
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
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    storage.sb().state().checkpoint_op(),
    OpNumber::with(4),
    "the durable-view write named checkpoint_op=4 (== in-memory) — no rewind of M's durable root"
  );
  assert_eq!(
    storage.sb().state().checkpoint_id(),
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
    &mut storage,
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
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    storage.sb().state().checkpoint_op(),
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
  let (mut e, _storage, mut blocks, _sm_root_m, _id_m) = laggard_owing_sm_reconstruct_at_m();
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
  let (_d8, dstorage8) = donor_primary_at_checkpoint(8);
  let (env8, id8) = donor_envelope(&dstorage8);
  seed_donor_blocks(&mut blocks, 8);
  // Fire the sync-solicit timer so a fresh RequestSync (carrying the current nonce) is emitted to
  // capture, and run the frontier re-drive it queues — a reply is not admitted while the transfer is
  // mid-walk, exactly as a driver's storage step settles the lane before the next ingress.
  let mut storage = Storage::new(TestWal::default(), TestSb::default());
  e.handle_timeout(later, &mut storage);
  e.block_step(later, &mut storage, &mut blocks);
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    later,
    &mut storage,
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
  e.block_step(later, &mut storage, &mut blocks);
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
      &mut storage,
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
  let (mut e, _storage, mut blocks, _sm_root_m, _id_m) = laggard_owing_sm_reconstruct_at_m();
  let now = Instant::ZERO;
  let t1 = now + core::time::Duration::from_secs(1);
  let t2 = now + core::time::Duration::from_secs(2);

  // Stage a strictly-newer M'=8 whose flush FAULTS, leaving `pending_install(8)` retained.
  let (_d8, dstorage8) = donor_primary_at_checkpoint(8);
  let (env8, id8) = donor_envelope(&dstorage8);
  seed_donor_blocks(&mut blocks, 8);
  blocks.script_flush_fault(1);
  let mut storage = Storage::new(TestWal::default(), TestSb::default());
  e.handle_timeout(t1, &mut storage);
  e.block_step(t1, &mut storage, &mut blocks);
  let nonce1 = captured_sync_nonce(&mut e);
  e.handle_message(
    t1,
    &mut storage,
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
  e.block_step(t1, &mut storage, &mut blocks);
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
  let (_d4, dstorage4) = donor_primary_at_checkpoint(4);
  let (env4, id4) = donor_envelope(&dstorage4);
  e.handle_timeout(t2, &mut storage);
  let nonce2 = captured_sync_nonce(&mut e);
  e.handle_message(
    t2,
    &mut storage,
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
  e.block_step(t2, &mut storage, &mut blocks);
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
  let (mut e, mut storage, mut blocks, _sm_root_m, _m_checkpoint_id) =
    laggard_owing_sm_reconstruct_at_m();
  let now = Instant::ZERO;

  // (a) The obligation withholds any ordinary checkpoint: a checkpoint attempt while it is owed must start
  //     NO checkpoint write (no superblock submission). The node is Normal here (the faulted restore left
  //     it Normal), so without the obligation gate `maybe_checkpoint` could snapshot the stale SM.
  assert!(
    !storage.has_inflight(),
    "no superblock write is in flight after the faulted restore"
  );
  e.maybe_checkpoint(&mut storage);
  e.storage_step(now, &mut storage, &mut blocks);
  assert!(
    !storage.has_inflight(),
    "maybe_checkpoint started NO new checkpoint write while the SM-reconstruct obligation is owed"
  );

  // (b) A durable-VIEW write submitted while the obligation holds reads `self.checkpoint_op == 4` and so
  //     names checkpoint_op=4. Trigger it via a view change (the production path that issues one).
  for r in [1u16, 2] {
    e.handle_message(
      now,
      &mut storage,
      Peer::Replica(ReplicaId::new(r)),
      Message::StartViewChange(StartViewChange::new(
        View::with(1),
        ReplicaId::new(r),
        crate::Epoch::new(0),
        0,
      )),
    );
  }
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    storage.sb().state().checkpoint_op(),
    OpNumber::with(4),
    "the competing durable-view write named checkpoint_op=4 (== in-memory) — no rewind"
  );
  assert!(
    storage.sb().state().commit().get() >= 4,
    "and its commit is >= M=4 so the commit >= checkpoint_op root invariant holds (it is {})",
    storage.sb().state().commit().get()
  );
}

#[test]
fn an_owed_sm_reconstruct_does_not_serve_m_until_the_sm_is_restored() {
  // While the SM-reconstruct obligation is owed, `self.checkpoint_op == M` but the SM does not yet hold M:
  // the node MUST NOT serve a `SyncCheckpoint` for M (it cannot — it is missing the very block its own
  // restore faulted on, and its SM is not M). A peer's `RequestSync` must start NO serve-read while owed;
  // once the retry reconstructs the SM, serving resumes normally.
  let (mut e, mut storage, mut blocks, _sm_root_m, _id) = laggard_owing_sm_reconstruct_at_m();
  let now = Instant::ZERO;
  while e.poll_message().is_some() {} // drain anything queued by the install path

  // A peer solicits a sync. The node is Normal with `checkpoint_op == 4`, so absent the gate it would
  // submit a serve-read and ship M — but the obligation is owed, so it must stay silent.
  e.handle_message(
    now,
    &mut storage,
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
  e.storage_step(now, &mut storage, &mut blocks);
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
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      _id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      donor_envelope(&donor_primary_at_checkpoint(4).1).0,
      Bytes::new(),
    )),
  );
  e.block_step(now, &mut storage, &mut blocks);
  for _ in 0..4 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert!(
    !e.sm_reconstruct_owed(),
    "the obligation cleared once the SM reconstructed"
  );

  // Serving now resumes: a fresh RequestSync submits a serve-read.
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut storage,
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
  let (mut e, mut storage, mut blocks, _sm_root_m, _checkpoint_id) =
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
  let (_donor_m, dstorage_m) = donor_primary_at_checkpoint(4);
  let (env_m, id_m) = donor_envelope(&dstorage_m);
  e.handle_message(
    now,
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  // Drive the storage completions until the SM reconstructs.
  for _ in 0..4 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
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
  let (mut e, mut storage, mut blocks, sm_root_m, id_m) = laggard_owing_sm_reconstruct_at_m();

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
  let (_donor_m, dstorage_m) = donor_primary_at_checkpoint(4);
  let (env_m, env_id_m) = donor_envelope(&dstorage_m);
  assert_eq!(env_id_m, id_m, "the equal-M peer's checkpoint id matches M");
  let mut peer_blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut peer_blocks, 4); // the equal-M peer has M's CLEAN block

  // The ORIGINAL donor (replica 0) is silent: drive the solicit ARQ. The block-fetch re-armed
  // `sync_solicit` at `ZERO + SYNC_SOLICIT`, so firing it past that deadline re-broadcasts `RequestSync`.
  let later = Instant::ZERO + core::time::Duration::from_millis(300);
  while e.poll_message().is_some() {}
  e.sync_timeouts(later, &mut storage);
  e.storage_step(later, &mut storage, &mut blocks);
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
    let (mut peer, mut pstorage) = donor_primary_at_checkpoint(4);
    let mut pblocks = crate::block_store::InMemoryBlockStore::new();
    seed_donor_blocks(&mut pblocks, 4);
    while peer.poll_message().is_some() {}
    peer.on_request_sync(
      later,
      &mut pstorage,
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
    peer.storage_step(later, &mut pstorage, &mut pblocks);
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
    &mut storage,
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
  e.block_step(later, &mut storage, &mut blocks);
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
  let (mut peer, mut pstorage2) = donor_primary_at_checkpoint(4);
  while peer.poll_message().is_some() {}
  peer.on_request_block(&mut pstorage2, Peer::Replica(ReplicaId::new(1)), block_req);
  peer.storage_step(later, &mut pstorage2, &mut peer_blocks);
  let block_resp = core::iter::from_fn(|| peer.poll_message())
    .find_map(|out| match out.into_msg() {
      Message::BlockResponse(m) => Some(m),
      _ => None,
    })
    .expect("the fresh donor serves M's clean block");
  e.handle_message(
    later,
    &mut storage,
    Peer::Replica(equal_peer),
    Message::BlockResponse(block_resp),
  );
  e.block_step(later, &mut storage, &mut blocks);
  for _ in 0..4 {
    storage.sb_mut().flush();
    e.storage_step(later, &mut storage, &mut blocks);
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
    &mut storage,
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
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");

  let mut donor_blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);

  // Laggard store: SM DAG present, session DAG absent.
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
      blocks.put(block);
    }
  }
  assert!(blocks.has_block(sm_root), "laggard holds the SM DAG");
  assert!(!blocks.has_block(sessions_root), "session DAG is absent");

  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let now = Instant::ZERO;

  // Trigger the sync and capture the nonce.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
    primary_peer(), // from the correct donor
    Message::BlockResponse(crate::BlockResponse::new(sm_root, None)),
  );
  e.block_step(now, &mut storage, &mut blocks);
  assert_eq!(
    count_resyncs(&mut e),
    0,
    "(a) absent for an already-fetched address must not re-solicit"
  );
  assert_eq!(e.block_fetch_donor(), Some(0), "(a) fetch stays pinned");

  // (b) Absent for the ACTIVE address but from a NON-DONOR (slot 1). `from != bf.donor` → INERT.
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)), // non-donor
    Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
  );
  e.block_step(now, &mut storage, &mut blocks);
  assert_eq!(
    count_resyncs(&mut e),
    0,
    "(b) absent from a non-donor must not re-solicit"
  );
  assert_eq!(e.block_fetch_donor(), Some(0), "(b) fetch stays pinned");

  // (c) Absent for a DIFFERENT address AND from a non-donor (double mismatch) → INERT.
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)), // non-donor
    Message::BlockResponse(crate::BlockResponse::new(sm_root, None)),
  );
  e.block_step(now, &mut storage, &mut blocks);
  assert_eq!(
    count_resyncs(&mut e),
    0,
    "(c) absent for wrong address from non-donor must not re-solicit"
  );

  // (d) Absent for the ACTIVE address FROM the pinned donor → DOES re-solicit.
  e.handle_message(
    now,
    &mut storage,
    primary_peer(), // donor slot 0
    Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
  );
  e.block_step(now, &mut storage, &mut blocks);
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
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");

  // The donor's full block store (BOTH DAGs) — the source the donor serves `RequestBlock`s from once the
  // fresh checkpoint re-pins the fetch.
  let mut donor_blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);
  assert!(
    donor_blocks.has_block(sessions_root),
    "the donor holds the session-table DAG root"
  );

  // Laggard store: SM DAG present (the SM frontier drains locally), session DAG absent (the active
  // outstanding address is `sessions_root`).
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
      blocks.put(block);
    }
  }
  assert!(blocks.has_block(sm_root), "laggard holds the SM DAG");
  assert!(!blocks.has_block(sessions_root), "session DAG is absent");

  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut now = Instant::ZERO;

  // A SECOND donor at a STRICTLY-HIGHER checkpoint (8) — a GENUINELY NEW root (`new_sm_root` /
  // `new_sessions_root` differ from the op-4 roots). Delivered later while the op-4-root fetch is live with
  // its latch set, this is a real new pin: `carry_resolicit_latch` must RESET the latch to `None` (a
  // different root), so its first absent legitimately re-solicits and the laggard converges (no strand).
  let (_donor8_e, dstorage8) = donor_primary_at_checkpoint(8);
  let (new_env, new_id) = donor_envelope(&dstorage8);
  let (_op8, new_sm_root, new_sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&new_env).expect("op-8 donor envelope decodes");
  assert_ne!(
    new_sessions_root, sessions_root,
    "the op-8 checkpoint is a genuinely new root (front actually changes)"
  );
  let mut donor8_blocks = crate::block_store::InMemoryBlockStore::new();
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
      blocks.put(block);
    }
  }

  // Trigger the sync (a Commit advertising checkpoint 4 > head 0) and capture the nonce.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
    primary_peer(), // donor slot 0
    Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
  );
  e.block_step(now, &mut storage, &mut blocks);
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
      &mut storage,
      primary_peer(), // donor slot 0
      Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
    );
    e.block_step(now, &mut storage, &mut blocks);
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
                        storage: &mut Storage<TestWal, TestSb, CountSm>,
                        blocks: &mut crate::block_store::InMemoryBlockStore,
                        now: Instant| {
    e.handle_message(
      now,
      storage,
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
    e.block_step(now, storage, blocks);
  };
  const DUP_CHECKPOINTS: u32 = 8;
  const ABSENTS_PER_CHECKPOINT: u32 = 4;
  let mut interleaved_resyncs = 0u32;
  for _ in 0..DUP_CHECKPOINTS {
    // A delayed duplicate same-root checkpoint re-pins to the IDENTICAL still-pruned front.
    dup_checkpoint(&mut e, &mut storage, &mut blocks, now);
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
        &mut storage,
        primary_peer(), // donor slot 0
        Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
      );
      e.block_step(now, &mut storage, &mut blocks);
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
  e.handle_timeout(now, &mut storage);
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the new-root checkpoint re-pinned the fetch to the op-8 root"
  );
  // First absent for the op-8 front → a FRESH re-solicit (the latch was reset by the new root).
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::BlockResponse(crate::BlockResponse::new(new_sessions_root, None)),
  );
  e.block_step(now, &mut storage, &mut blocks);
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
        now = now + core::time::Duration::from_millis(101);
        e.handle_timeout(now, &mut storage);
        e.block_step(now, &mut storage, &mut blocks);
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
    blocks.put(block.clone());
    e.handle_message(
      now,
      &mut storage,
      primary_peer(),
      Message::BlockResponse(crate::BlockResponse::new(addr, Some(block))),
    );
    e.block_step(now, &mut storage, &mut blocks);
    for _ in 0..4 {
      e.storage_step(now, &mut storage, &mut blocks);
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
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");

  let mut donor_blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);

  // Laggard store: SM DAG present (drains locally), session DAG absent (the active outstanding address is
  // `sessions_root`).
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
      blocks.put(block);
    }
  }
  assert!(blocks.has_block(sm_root), "laggard holds the SM DAG");
  assert!(!blocks.has_block(sessions_root), "session DAG is absent");

  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut now = Instant::ZERO;

  // A GENUINE crossing reply: a strictly-foreign config carrying a non-empty successor membership (the
  // content-addressed SM/session DAGs are config-independent, so the same `env`/`id` integrity holds). This
  // is what makes the live fetch a real crossing answer (`crossing_answered = true`), the only thing that
  // legitimately shields the crossing from same-epoch downgrade.
  let predecessor = genesis(3);
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid");
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
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    crossing_checkpoint(nonce),
  );
  e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
    primary_peer(), // donor slot 0
    Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
  );
  e.block_step(now, &mut storage, &mut blocks);
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
      &mut storage,
      primary_peer(), // donor slot 0
      Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
    );
    e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
  e.handle_timeout(now, &mut storage);
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
    &mut storage,
    primary_peer(),
    crossing_checkpoint(nonce),
  );
  e.block_step(now, &mut storage, &mut blocks);
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
  let (mut e, mut storage, mut blocks, sm_root_m, _m_id) = laggard_owing_sm_reconstruct_at_m();
  // M's donor (slot 0) and envelope, re-derived exactly as the helper built them.
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env_m, id_m) = donor_envelope(&dstorage);
  let nonce = e.sync_nonce_for_test();
  let now = Instant::ZERO;

  // Helper: deliver a fresh `SyncCheckpoint` at M from the pinned donor (slot 0). For an owed laggard this
  // routes to `refetch_sm_reconstruct` → `rearm_sm_reconstruct_retry`, which re-arms the fetch (M's leaf is
  // corrupt locally, so the frontier wants `sm_root_m`) and emits a `RequestBlock`.
  let deliver_repin = |e: &mut Endpoint<CountSm>,
                       storage: &mut Storage<TestWal, StepSb, CountSm>,
                       blocks: &mut InMemoryBlockStore| {
    e.handle_message(
      now,
      storage,
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
    e.block_step(now, storage, blocks);
  };

  // (1) FIRST re-pin: the obligation re-pulls M's DAG. `Fetching`, requesting `sm_root_m`.
  deliver_repin(&mut e, &mut storage, &mut blocks);
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
    &mut storage,
    primary_peer(),
    Message::BlockResponse(crate::BlockResponse::new(sm_root_m, None)),
  );
  e.block_step(now, &mut storage, &mut blocks);
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the GC-pruned reconstruct pin is kept live across the absent"
  );

  // (3) A FRESH `SyncCheckpoint` at M re-pins via the SAME reconstruct path, REPLACING the whole
  // `block_fetch` field by construction.
  deliver_repin(&mut e, &mut storage, &mut blocks);
  // Drain (DROP) the freshly-emitted `RequestBlock` — model it (or its answer) lost on the wire.
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "the re-pin installed a live fetch"
  );

  // (4) THE H1 DISCRIMINATOR: fire the solicit ARQ past its deadline. The live fetch MUST drive
  // `send_request_block` to retransmit the lost `RequestBlock(sm_root_m)`.
  let arq = now + core::time::Duration::from_millis(101);
  e.handle_timeout(arq, &mut storage);
  e.block_step(arq, &mut storage, &mut blocks);
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
  let (env, id) = donor_envelope(&donor_primary_at_checkpoint(4).1);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");

  let mut donor_blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);

  // Laggard store: SM DAG present (drains locally), session DAG absent (the active outstanding address is
  // `sessions_root`) — the same construction the one-shot tests use to pin a fetch then quarantine it.
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
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
      blocks.put(block);
    }
  }

  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let now = Instant::ZERO;

  // (1) An ORDINARY same-epoch sync (a Commit advertising checkpoint 4 > head 0), then its same-config
  // `SyncCheckpoint`: `begin_block_sync` arms a `Fetching` pinned at `sessions_root`.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
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
    &mut storage,
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
  e.block_step(now, &mut storage, &mut blocks);
  while e.poll_message().is_some() {}
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "setup: the sync is ordinary (no crossing yet)"
  );

  // (2) Active-donor ABSENT for the pinned session block → the ordinary pin is KEPT LIVE (donor 0).
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::BlockResponse(crate::BlockResponse::new(sessions_root, None)),
  );
  e.block_step(now, &mut storage, &mut blocks);
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
    &mut storage,
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
    &mut storage,
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

// ── Quarantined-member identity lane (the stranded-member bridge) ──

/// A `Peer::Member` for an attested member NOT in the genesis-3 membership — a quarantined peer (its
/// stable id does not resolve to a slot, so the transport bound it under its member id).
fn quarantined() -> Peer {
  Peer::Member(MemberId::new(99))
}

#[test]
fn a_quarantined_member_reaches_no_authority_path() {
  // THE catastrophic-direction guard for the identity lane: a quarantined attested member
  // (`Peer::Member`) may ride the no-authority config-learning lane, but every VOTE / LEAD / VIEW /
  // COMMIT path must drop it with ZERO state delta — `as_replica()` is `None` for a `Peer::Member`,
  // so every authority binding rejects it by construction. This sweeps the authority kinds under a
  // quarantined `from` and asserts nothing moves.
  let mut e = backup(); // a view-0 backup of {0,1,2}
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let q = quarantined();

  // A Prepare (would append + advance the head) — inert from a quarantined member.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(now, &mut storage, q, prepare(1, 0));
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.op(),
    OpNumber::new(),
    "no append from a quarantined Prepare"
  );
  assert_eq!(e.commit(), OpNumber::new());
  assert!(
    !e.poll_message()
      .is_some_and(|o| matches!(o.msg_ref(), Message::PrepareOk(_))),
    "no PrepareOk (no vote) for a quarantined Prepare"
  );

  // A Commit (would advance commit) — inert.
  e.handle_message(
    now,
    &mut storage,
    q,
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::new(),
    "no commit advance from a quarantined Commit"
  );

  // A StartViewChange (would count toward the view-change quorum) — inert.
  let before = e.view();
  e.handle_message(
    now,
    &mut storage,
    q,
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.view(),
    before,
    "no view movement from a quarantined StartViewChange"
  );
  assert!(
    e.status().is_normal(),
    "still Normal — no view-change entered"
  );

  // A PrepareOk (would count toward a commit quorum on a primary) — inert. Drive a primary first.
  let mut p = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    u64::MAX,
  );
  let (wal2, sb2) = (TestWal::default(), TestSb::default());
  let mut storage2 = Storage::new(wal2, sb2);
  p.handle_message(
    now,
    &mut storage2,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"a"),
    )),
  );
  p.storage_step(now, &mut storage2, &mut blocks); // own append → own vote (1 of 2)
  while p.poll_message().is_some() {}
  p.handle_message(
    now,
    &mut storage2,
    quarantined(),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(1),
      ReplicaId::new(1),
      OpNumber::new(),
      crate::storage::prepare_identity(
        ClientId::new(7),
        RequestNumber::with(1),
        crate::storage::fnv1a_128(b"a"),
      ),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    p.commit(),
    OpNumber::new(),
    "a quarantined PrepareOk contributes NO vote — op 1 stays uncommitted (own vote alone is below quorum)"
  );
}

#[test]
fn a_quarantined_member_is_served_the_state_sync_checkpoint() {
  // The donor side of the quarantined-member lane: a quarantined attested member soliciting state-sync IS served the
  // checkpoint (routed back to its `Peer::Member` address) — the no-authority read that lets a
  // stranded member learn the current configuration to rejoin or discover its own retirement.
  let now = Instant::ZERO;
  let (mut donor, mut storage) = donor_primary_at_checkpoint(2);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  while donor.poll_message().is_some() {}
  donor.handle_message(
    now,
    &mut storage,
    quarantined(),
    Message::RequestSync(crate::RequestSync::new(
      donor.view(),
      OpNumber::with(2),
      ReplicaId::new(0), // any self-stamped slot; the binding keys off `from`
      0xF00D,
      true,
      0xDEAD, // a config the donor does not recognize
    )),
  );
  donor.storage_step(now, &mut storage, &mut blocks);
  let mut served = None;
  while let Some(out) = donor.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      served = Some((out.to(), s.clone()));
    }
  }
  let (to, s) = served.expect("a quarantined member's solicitation IS served");
  assert_eq!(
    to,
    Recipient::To(quarantined()),
    "the reply routes back to the Peer::Member address"
  );
  assert_eq!(s.checkpoint_op(), OpNumber::with(2));
}

#[test]
fn a_quarantined_higher_epoch_hint_arms_a_bounded_probe_that_disarms() {
  // The laggard-trigger side of that lane, plus the bounded probe. A quarantined member's higher-epoch heartbeat
  // arms a crossing sync (which blocks op-mint) AND records the quarantined donor to solicit
  // directly (the fan-out reaches only bound members — for a partitioned laggard those are its dead
  // old peers). If no crossing-presenting answer arrives, the probe DISARMS after the bounded window
  // rather than wedging forever on a possibly-corrupted hint no donor can answer.
  let mut e = backup();
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  // A quarantined higher-epoch Commit (epoch 5 > our 0) arms the crossing probe.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    quarantined(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
      crate::Epoch::new(5),
      0xDEAD,
    )),
  );
  assert!(
    e.sync_target_for_test().is_some(),
    "the crossing sync is armed"
  );
  // The laggard solicits the remembered quarantined donor directly (not only Backups).
  let mut solicited_quarantined = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::RequestSync(_)) && out.to() == Recipient::To(quarantined())
    {
      solicited_quarantined = true;
    }
  }
  assert!(
    solicited_quarantined,
    "the crossing solicits the remembered quarantined donor directly"
  );

  // No donor answers. Step the solicit timer past the bounded window — the probe disarms.
  for ms in 1..=8 {
    let t = now + core::time::Duration::from_millis(ms * 200);
    e.handle_timeout(t, &mut storage);
    while e.poll_message().is_some() {}
  }
  assert!(
    e.sync_target_for_test().is_none(),
    "the unanswered quarantine-armed crossing DISARMED — op-mint is no longer blocked forever"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "still at our durable epoch — no bogus cross"
  );
}

/// Build the GENUINE crossing `SyncCheckpoint` for `donor_primary_at_checkpoint(4)` — a foreign config
/// carrying a non-empty successor membership, so `crossing_answered` is true — echoing `nonce`.
fn crossing_checkpoint_at_4(env: &Bytes, id: u128, nonce: u64) -> Message {
  let successor = genesis(3)
    .apply_delta(&crate::SingleVoterDelta::AddLearner(MemberId::new(3)))
    .expect("AddLearner on the 3-voter genesis is valid");
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor, genesis(3).config_id())
      .encode_body();
  Message::SyncCheckpoint(
    crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      successor.epoch(),
      successor.config_id(),
      ReplicaId::new(0),
      nonce,
      env.clone(),
      membership_body,
    )
    .with_config_install_op(OpNumber::with(4)),
  )
}

#[test]
fn a_crossing_that_presents_but_never_delivers_a_block_disarms() {
  // A donor can PRESENT a crossing (a foreign config + non-empty successor membership, so
  // `crossing_answered` is true) and then crash-stop before serving any block — its DAG never arrives.
  // `crossing_answer_in_flight` stays set forever, but the fetch makes NO PROGRESS. The probe must read a
  // `sync_fetch_progress` DELTA, not the persistent crossing bit, so a presented-but-stalled crossing
  // still disarms rather than wedging op-mint at the stale epoch indefinitely.
  //
  // NEUTER CHECK: refresh the deadline on `crossing_answer_in_flight` alone (drop the progress-delta
  // check) and this stalled crossing renews forever and never disarms — the wedge R4 flags.
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  // Arm a crossing sync and deliver the crossing `SyncCheckpoint` → a block-fetch armed with
  // `crossing_answered = true`, then the donor goes silent (no BlockResponse ever arrives).
  e.arm_cross_epoch_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    crossing_checkpoint_at_4(&env, id, nonce),
  );
  e.block_step(now, &mut storage, &mut blocks);
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_crossing_answered_for_test(),
    Some(true),
    "precondition: a crossing block-fetch is in flight (crossing_answered is true)"
  );

  e.seed_quarantined_donor_for_test(now, quarantined());
  for ms in 1..=8 {
    e.handle_timeout(
      now + core::time::Duration::from_millis(ms * 200),
      &mut storage,
    );
    while e.poll_message().is_some() {}
  }
  assert!(
    e.sync_target_for_test().is_none(),
    "a crossing that PRESENTED but delivered no block makes no progress, so the probe DISARMS it"
  );
}

#[test]
fn a_progressing_crossing_survives_the_probe_then_a_stall_disarms() {
  // The other side of the progress rule: a crossing whose fetch is genuinely ADVANCING — a frontier block
  // accepted within the window — must survive, since `sync_fetch_progress` moved past the mark. Once the
  // transfer STALLS (no further blocks), the next window makes no progress and the probe disarms. Proves
  // the fix does not tear down a slow-but-progressing rejoin, only a genuinely stalled one.
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let (_op, sm_root, _sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");
  let mut donor_blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);

  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new(); // EMPTY — the whole DAG must be fetched
  let now = Instant::ZERO;

  e.arm_cross_epoch_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    crossing_checkpoint_at_4(&env, id, nonce),
  );
  e.block_step(now, &mut storage, &mut blocks);
  // The first outstanding request is the SM root; capture it.
  let mut first_req = None;
  while let Some(out) = e.poll_message() {
    if let Message::RequestBlock(addr) = out.msg_ref() {
      first_req = Some(*addr);
    }
  }
  assert_eq!(
    first_req,
    Some(sm_root),
    "the fetch first requests the SM root"
  );
  e.seed_quarantined_donor_for_test(now, quarantined());

  // WITHIN the first window (t=100ms), serve the SM root block — a frontier block ACCEPTED, so
  // `sync_fetch_progress` advances. The DAG still owes the session leaf, so the fetch stays in flight.
  let t1 = now + core::time::Duration::from_millis(100);
  let block = donor_blocks
    .read_block(sm_root)
    .expect("donor holds the SM root");
  blocks.put(block.clone());
  e.handle_message(
    t1,
    &mut storage,
    primary_peer(),
    Message::BlockResponse(crate::BlockResponse::new(sm_root, Some(block))),
  );
  e.block_step(t1, &mut storage, &mut blocks);
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_crossing_answered_for_test(),
    Some(true),
    "the crossing fetch is still in flight after accepting the SM root (the session leaf is still owed)"
  );

  // At the first deadline (t=300ms) the fetch PROGRESSED (the SM root was accepted), so the probe refreshes
  // rather than disarming.
  e.handle_timeout(now + core::time::Duration::from_millis(300), &mut storage);
  while e.poll_message().is_some() {}
  assert!(
    e.sync_target_for_test().is_some(),
    "a fetch that accepted a frontier block within the window survives — progress refreshed the deadline"
  );

  // Now the donor goes silent (no further block answers). The next window makes NO progress, so the probe
  // disarms — stepping past the refreshed deadline (300ms + 300ms = 600ms).
  for ms in 4..=14u64 {
    e.handle_timeout(
      now + core::time::Duration::from_millis(ms * 100),
      &mut storage,
    );
    while e.poll_message().is_some() {}
  }
  assert!(
    e.sync_target_for_test().is_none(),
    "once the progressing fetch STALLS, the next window makes no progress and the probe disarms"
  );
}

#[test]
fn non_crossing_block_progress_does_not_refresh_a_stalled_crossing_probe() {
  // Progress must be CROSSING-SPECIFIC. A non-crossing (below-target same-config) fetch the cross-epoch
  // solicit admits accepts blocks too, but that progress is NOT the crossing's. If it counted, an
  // old-config donor could feed ONE non-crossing block, then a quarantined donor re-pins crossing metadata
  // with NO block, and the stale progress delta would refresh the stalled crossing forever. The probe bumps
  // its progress counter only for a block accepted into a `crossing_answered` fetch, so this interleaving
  // still disarms at the crossing's deadline.
  //
  // NEUTER CHECK: bump `sync_fetch_progress` for ANY accepted block (drop the `crossing` gate) and the
  // non-crossing block's delta refreshes the crossing probe — it never disarms.
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let (_op, sm_root, _sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("donor envelope decodes");
  let mut donor_blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);

  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new(); // EMPTY — the DAG must be fetched
  let now = Instant::ZERO;

  // Arm a crossing sync, then deliver a NON-crossing reply (same config, empty membership) → a live fetch
  // with `crossing_answered = false`, armed on the SM root.
  e.arm_cross_epoch_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      genesis(3).config_id(),
      ReplicaId::new(0),
      nonce,
      env.clone(),
      Bytes::new(),
    )),
  );
  e.block_step(now, &mut storage, &mut blocks);
  let mut first_req = None;
  while let Some(out) = e.poll_message() {
    if let Message::RequestBlock(addr) = out.msg_ref() {
      first_req = Some(*addr);
    }
  }
  assert_eq!(
    e.block_fetch_crossing_answered_for_test(),
    Some(false),
    "precondition: a NON-crossing fetch is in flight"
  );
  let req = first_req.expect("the non-crossing fetch requests a block");
  assert_eq!(
    req, sm_root,
    "the non-crossing fetch first requests the SM root"
  );
  e.seed_quarantined_donor_for_test(now, quarantined());

  // Feed the requested block into the NON-crossing fetch — accepted, but NOT the crossing's progress.
  let block = donor_blocks
    .read_block(req)
    .expect("donor holds the requested block");
  blocks.put(block.clone());
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::BlockResponse(crate::BlockResponse::new(req, Some(block))),
  );
  e.block_step(now, &mut storage, &mut blocks);
  while e.poll_message().is_some() {}

  // The quarantined donor now re-pins CROSSING metadata (foreign config, non-empty membership) with the
  // same nonce → the fetch becomes `crossing_answered = true`, but delivers NO block for it.
  e.handle_message(
    now,
    &mut storage,
    quarantined(),
    crossing_checkpoint_at_4(&env, id, nonce),
  );
  e.block_step(now, &mut storage, &mut blocks);
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_crossing_answered_for_test(),
    Some(true),
    "the fetch now presents a crossing (re-pinned), but no crossing block was accepted"
  );

  // At the ORIGINAL deadline (armed at t=0 → 300ms), one step past it: the crossing made NO
  // accepted-block progress (only the earlier NON-crossing block bumped the raw counter), so `progress ==
  // mark` and the probe DISARMS. Were the non-crossing delta counted, it would refresh here and stay armed
  // one more window — the R5 wedge (a repeated interleaving would sustain it forever).
  e.handle_timeout(now + core::time::Duration::from_millis(350), &mut storage);
  while e.poll_message().is_some() {}
  assert!(
    e.sync_target_for_test().is_none(),
    "non-crossing progress does not refresh the crossing probe — the stalled crossing DISARMS at its \
     original deadline"
  );
}

#[test]
fn a_crossing_fetch_survives_interleaved_non_crossing_replies_and_completes() {
  // `send_request_sync` solicits BOTH old-config `Backups` AND the quarantined donor, so a crossing fetch
  // in progress can be raced by a later non-crossing (same-config) reply from an old-config donor. That
  // reply must NOT downgrade the crossing fetch: were it to, the crossing block would land off-frontier
  // against the non-crossing fetch, `apply_sync` would reject the non-crossing install, and each further old
  // reply would re-clear the crossing fetch — the healthy quarantined primary's next heartbeat only re-arms
  // the same losing race, stranding the member forever under HONEST timing. Interleaving a non-crossing
  // reply before every crossing block keeps the crossing fetch pinned and lets it COMPLETE and cross.
  //
  // NEUTER CHECK: drop the crossing-downgrade guard in begin_block_sync and the same-config reply evicts the
  // crossing fetch — the install never happens, `state_syncs_applied` stays 0, and the epoch stays 0.
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let mut donor_blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);

  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  let non_crossing = |nonce: u64| {
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      genesis(3).config_id(),
      ReplicaId::new(0),
      nonce,
      env.clone(),
      Bytes::new(),
    ))
  };
  let last_request = |e: &mut Endpoint<CountSm>| {
    let mut req = None;
    while let Some(out) = e.poll_message() {
      if let Message::RequestBlock(addr) = out.msg_ref() {
        req = Some(*addr);
      }
    }
    req
  };

  e.arm_cross_epoch_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();

  // The quarantined donor presents the crossing → a crossing fetch, requesting the first block.
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    quarantined(),
    crossing_checkpoint_at_4(&env, id, nonce),
  );
  e.block_step(now, &mut storage, &mut blocks);
  let mut want = last_request(&mut e);
  assert_eq!(
    e.block_fetch_crossing_answered_for_test(),
    Some(true),
    "the crossing fetch is armed"
  );

  // Drain the crossing DAG, racing an old-config NON-crossing reply in before each block.
  let mut applied = false;
  for _ in 0..12 {
    let Some(addr) = want else { break };
    // The old-config donor's non-crossing reply races the in-flight crossing block — it must be IGNORED.
    e.handle_message(now, &mut storage, primary_peer(), non_crossing(nonce));
    e.block_step(now, &mut storage, &mut blocks);
    while e.poll_message().is_some() {}
    assert_eq!(
      e.block_fetch_crossing_answered_for_test(),
      Some(true),
      "a non-crossing reply must NOT evict the live crossing fetch"
    );
    // Serve the requested crossing block from the quarantined donor.
    let block = donor_blocks
      .read_block(addr)
      .expect("donor holds the requested block");
    blocks.put(block.clone());
    e.handle_message(
      now,
      &mut storage,
      quarantined(),
      Message::BlockResponse(crate::BlockResponse::new(addr, Some(block))),
    );
    e.block_step(now, &mut storage, &mut blocks);
    want = last_request(&mut e);
    for _ in 0..4 {
      e.storage_step(now, &mut storage, &mut blocks);
    }
    if e.state_syncs_applied() == 1 {
      applied = true;
      break;
    }
  }
  assert!(
    applied,
    "the crossing fetch stayed pinned through the interleaved non-crossing replies and COMPLETED"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(1),
    "the laggard crossed to the successor epoch"
  );
}

#[test]
fn a_non_crossing_reply_does_not_shield_the_quarantine_probe() {
  // A donor answering a quarantine crossing with a NON-crossing reply — a same-config checkpoint the
  // cross-epoch solicit admits below target — arms a live `block_fetch` whose `crossing_answered` bit is
  // FALSE. That must NOT shield the probe: otherwise a donor endlessly answering with non-crossing replies
  // would hold the speculative crossing open forever, re-wedging op-mint (the exact stall the probe
  // bounds). The probe reads `crossing_answer_in_flight`, so it keeps counting and DISARMS.
  //
  // NEUTER CHECK: shield on bare `block_fetch.is_some()` and this probe never disarms while the
  // non-crossing fetch is live — the reintroduced wedge.
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  // Arm a crossing sync and deliver a SAME-CONFIG `SyncCheckpoint` (config_id == ours, empty membership)
  // echoing its nonce → a live block-fetch with `crossing_answered = false`.
  e.arm_cross_epoch_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      genesis(3).config_id(),
      ReplicaId::new(0),
      nonce,
      env.clone(),
      Bytes::new(),
    )),
  );
  e.block_step(now, &mut storage, &mut blocks);
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_crossing_answered_for_test(),
    Some(false),
    "precondition: a NON-crossing block-fetch is in flight (crossing_answered is false)"
  );

  // Mark quarantine-sourced, then step past the disarm window with NO block answers.
  e.seed_quarantined_donor_for_test(now, quarantined());
  for ms in 1..=8 {
    e.handle_timeout(
      now + core::time::Duration::from_millis(ms * 200),
      &mut storage,
    );
    while e.poll_message().is_some() {}
  }
  assert!(
    e.sync_target_for_test().is_none(),
    "a non-crossing live fetch does NOT shield the probe — the speculative crossing DISARMED"
  );
}

#[test]
fn a_quarantine_armed_crossing_in_recovery_disarms_and_escalates() {
  // A quarantine-armed crossing entered while NON-Normal lives in the Recovering peer-fetch, whose retry
  // cadence is `recover_timeouts` — NOT the Normal-only `sync_timeouts`. The probe must advance and
  // disarm THERE too, else a bogus (e.g. bit-flipped-epoch) quarantined hint would strand the node
  // Recovering forever. On disarm it abandons the speculative crossing and escalates to the next view
  // change (a live posture that resumes processing same-epoch traffic), landing where a crash+restart
  // would; a real higher epoch re-arms the crossing on its next heartbeat.
  //
  // NEUTER CHECK: remove the `advance_quarantine_probe` call from `recover_timeouts` and the crossing
  // never disarms while Recovering — the node stays stranded, exactly the wedge this bounds.
  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let now = Instant::ZERO;

  // Enter the Recovering cross-epoch peer-fetch with a quarantined donor recorded — what a `Peer::Member`
  // hint does for a non-Normal laggard (`maybe_request_cross_epoch_catchup` sets the donor, then
  // `enter_cross_epoch_peer_fetch` flips to Recovering and arms the forced crossing).
  e.seed_quarantined_donor_for_test(now, quarantined());
  let mut storage = Storage::new(wal, sb);
  e.enter_cross_epoch_peer_fetch(now, &mut storage, OpNumber::with(4));
  assert!(
    e.status().is_recovering(),
    "precondition: the non-Normal laggard entered the Recovering crossing"
  );
  assert!(
    e.sync_target_for_test().is_some(),
    "precondition: the crossing sync is armed"
  );

  // No donor answers. Step the recovery retry cadence past the bounded window.
  for ms in 1..=8 {
    e.handle_timeout(
      now + core::time::Duration::from_millis(ms * 200),
      &mut storage,
    );
    while e.poll_message().is_some() {}
  }
  assert!(
    e.sync_target_for_test().is_none(),
    "the unanswered quarantine crossing DISARMED on the recovery cadence — not stranded Recovering"
  );
  assert!(
    !e.status().is_recovering(),
    "the node abandoned the speculative recovery crossing and escalated to a live view change"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "still at our durable epoch — no bogus cross"
  );
}

#[test]
fn a_non_crossing_reply_in_recovery_does_not_shield_the_probe() {
  // The recovery twin of `a_non_crossing_reply_does_not_shield_the_quarantine_probe`: a donor answering a
  // Recovering quarantine crossing with a NON-crossing reply (same-config / empty membership — legitimate
  // during the commit-first window) arms a live block-fetch with `crossing_answered = false`. On the
  // recovery cadence too the probe must read `crossing_answer_in_flight`, NOT bare `block_fetch`, so the
  // non-crossing fetch does not hold the crossing open forever; the probe disarms and escalates.
  //
  // NEUTER CHECK: shield on bare `block_fetch.is_some()` and the node stays stranded Recovering while the
  // non-crossing fetch is live.
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let mut e = sync_backup();
  let wal = TestWal::default();
  let sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;

  let mut storage = Storage::new(wal, sb);
  e.seed_quarantined_donor_for_test(now, quarantined());
  e.enter_cross_epoch_peer_fetch(now, &mut storage, OpNumber::with(4));
  let nonce = e.sync_nonce_for_test();
  // A NON-crossing reply (same config, empty membership) admitted onto the recovery fetch path.
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      genesis(3).config_id(),
      ReplicaId::new(0),
      nonce,
      env.clone(),
      Bytes::new(),
    )),
  );
  e.block_step(now, &mut storage, &mut blocks);
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_crossing_answered_for_test(),
    Some(false),
    "precondition: a NON-crossing recovery fetch is in flight (crossing_answered is false)"
  );

  for ms in 1..=8 {
    e.handle_timeout(
      now + core::time::Duration::from_millis(ms * 200),
      &mut storage,
    );
    while e.poll_message().is_some() {}
  }
  assert!(
    e.sync_target_for_test().is_none(),
    "a non-crossing recovery fetch does NOT shield the probe — the speculative crossing DISARMED"
  );
  assert!(
    !e.status().is_recovering(),
    "the node escalated to a live view change instead of staying stranded Recovering"
  );
}

#[test]
fn sustained_higher_epoch_heartbeats_do_not_postpone_probe_expiry() {
  // The probe deadline is WALL-CLOCK, INDEPENDENT of `sync_solicit`. A quarantined laggard receiving
  // higher-epoch Commit heartbeats every 50ms — faster than the 100ms solicit window — keeps re-soliciting
  // (each re-trigger resets `sync_solicit`), so a solicit-gated probe would have its expiry slid forward
  // forever and NEVER fire, leaving `sync` armed and op-mint wedged at the stale epoch. The fixed deadline
  // fires regardless: with no crossing progress the probe disarms by the three-window bound.
  //
  // A genuine re-trigger legitimately RE-ARMS the crossing after each bounded disarm (the epoch really is
  // higher), so the crossing oscillates rather than staying dead — the property under test is that it
  // disarms AT ALL under sustained heartbeats (a sliding probe never would), not that it stays disarmed.
  //
  // NEUTER CHECK: make `arm_quarantine_probe` slide the deadline on every call (drop the is_none guard) and
  // the deadline is pushed forward by every 50ms heartbeat — it never fires, `ever_disarmed` stays false.
  let mut e = backup();
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let heartbeat = Message::Commit(Commit::new(
    View::new(),
    OpNumber::with(4),
    OpNumber::with(4),
    crate::Epoch::new(5),
    0xDEAD,
  ));

  // Arm on the first higher-epoch heartbeat (deadline = 0 + 3*100ms = 300ms).
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    Instant::ZERO,
    &mut storage,
    quarantined(),
    heartbeat.clone(),
  );
  while e.poll_message().is_some() {}
  assert!(
    e.sync_target_for_test().is_some(),
    "the crossing armed on the first quarantined higher-epoch hint"
  );

  // Deliver a heartbeat every 50ms (re-soliciting each time) with an interleaved handle_timeout, out past
  // the 300ms deadline. No SyncCheckpoint answers → no crossing progress. The probe MUST fire.
  let mut ever_disarmed = false;
  for step in 1..=12u64 {
    let t = Instant::ZERO + core::time::Duration::from_millis(step * 50);
    e.handle_message(t, &mut storage, quarantined(), heartbeat.clone());
    e.handle_timeout(t, &mut storage);
    while e.poll_message().is_some() {}
    if e.sync_target_for_test().is_none() {
      ever_disarmed = true;
      break;
    }
  }
  assert!(
    ever_disarmed,
    "the probe fired at its wall-clock deadline despite 50ms heartbeats re-soliciting — the deadline did \
     NOT slide (sync + intent + donor disarmed)"
  );
  assert_eq!(
    e.membership.epoch(),
    crate::Epoch::new(0),
    "still at our durable epoch — no bogus cross"
  );
}

#[test]
fn quarantined_serves_are_capped_independently_of_the_transport() {
  // A rotating set of DISTINCT attested-but-unresolvable `Peer::Member` requesters must NOT grow
  // `sync_serving` without bound. Each solicits a checkpoint serve whose read lingers until its (here
  // never-driven) storage completion; without an endpoint-side cap the map, its read queue, and the
  // completion scan would grow with the number of distinct valid-cert member ids that ever solicited (and
  // never quiesce). `submit_or_refresh_serve` caps concurrent quarantined serves at QUARANTINE_SERVE_LIMIT,
  // reserving the map's replica capacity independently of transport connection lifetime.
  //
  // NEUTER CHECK: drop the QUARANTINE_SERVE_LIMIT gate and the member-serve count grows to the number of
  // distinct ids that solicited (here 32) — unbounded in the number of distinct requesters.
  let (mut e, mut storage) = donor_primary_at_checkpoint(2);
  let now = Instant::ZERO;
  while e.poll_message().is_some() {} // drain warm-up

  // 32 distinct quarantined members each solicit ONCE (a foreign config so the sender binding admits the
  // Member; checkpoint 0 < our 2 so it is in reach and served). No serve-read is completed (no storage
  // drive), so every admitted serve lingers in the map.
  let foreign_config = genesis(3).config_id().wrapping_add(1);
  for id in 100..132u128 {
    e.handle_message(
      now,
      &mut storage,
      Peer::Member(MemberId::new(id)),
      Message::RequestSync(crate::RequestSync::new(
        View::with(0),
        OpNumber::with(0),
        ReplicaId::new(0),
        0xAA,
        false,
        foreign_config,
      )),
    );
    while e.poll_message().is_some() {}
  }
  let member_serves = e.sync_serving.keys().filter(|p| p.is_member()).count();
  assert!(
    member_serves <= QUARANTINE_SERVE_LIMIT,
    "quarantined serves are capped at {QUARANTINE_SERVE_LIMIT} ({member_serves} live) independently of \
     how many distinct member ids solicited"
  );
}

#[test]
fn a_transfer_drained_under_the_superblock_fence_installs_from_the_local_arq() {
  // THE DEFERRED-TRANSFER RECOVERY PATH. `on_fetch_drained` observes the single-superblock-writer
  // fence: a transfer whose frontier drains while a root is in flight installs NOTHING and stays
  // pinned. The deferred drain must then be recovered LOCALLY — every block the install needs is
  // already in this store, so making it wait on a donor's fresh `SyncCheckpoint` would strand a
  // complete transfer behind a peer that may never answer again. The ARQ walk is the local cadence
  // that owns it: on a drained frontier it re-enters the drain destination instead of emitting
  // nothing. This pins both halves: the drop under the fence is real, and the freed fence plus one
  // ARQ tick stages the install with NO donor traffic.
  //
  // NEUTER CHECK: make the `WalkPurpose::Arq` arm emit only for `Some(addr)` again and step (3) stages
  // nothing — the drained transfer sits idle until a donor happens to re-pin it.
  let (mut e, mut storage, env, id) = sync_apply_harness(4);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut blocks, 4);
  let now = Instant::ZERO;
  let reply = |nonce: u64| {
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env.clone(),
      Bytes::new(), // empty membership — an ordinary same-config install
    ))
  };

  // (1) Arm a sync and deliver a checkpoint whose WHOLE DAG is already local, so the freshly pinned
  // transfer's first (Arm) walk drains both frontiers in one step with no `RequestBlock` round trip.
  e.arm_forced_sync_for_test(4);
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    reply(e.sync_nonce_for_test()),
  );

  // (2) Occupy the fence BEFORE that walk's completion lands — a root submitted between the walk's
  // issue and its verdict is exactly the race the fence exists for.
  while e.poll_message().is_some() {} // drain the arming traffic
  e.stage_pending_checkpoint_for_test();
  e.block_step(now, &mut storage, &mut blocks);
  assert!(
    !core::iter::from_fn(|| e.poll_message())
      .any(|out| matches!(out.msg_ref(), Message::RequestBlock(_))),
    "ANTI-VACUITY: the DAG really is local — the walk DRAINED both frontiers rather than emitting a \
     pull, so the drain destination was reached under the fence"
  );
  assert!(
    e.pending_install.is_none(),
    "the drain under an occupied fence staged NOTHING — no re-persist began underneath the root"
  );
  assert!(
    e.block_fetch.is_some(),
    "and the drained transfer stays PINNED rather than being dropped with its verdict"
  );

  // (3) The occupying root lands, freeing the fence. The solicit cadence fires and re-drives the
  // stop-and-wait ARQ; its walk re-drains the (still complete) frontier and reaches the drain
  // destination the fence deferred, staging the install. NO donor reply is delivered in this step —
  // `reply` is not called again — so the resumption is purely local.
  e.pending_checkpoint = None;
  let later = now + SYNC_SOLICIT;
  e.sync_timeouts(later, &mut storage);
  assert!(
    core::iter::from_fn(|| e.poll_message())
      .any(|out| matches!(out.msg_ref(), Message::RequestSync(_))),
    "ANTI-VACUITY: the solicit cadence really fired, so this ARQ round is a live one"
  );
  e.block_step(later, &mut storage, &mut blocks);
  assert!(
    e.pending_install.is_some(),
    "the freed fence plus one ARQ tick resumed the drained transfer to a STAGED install, with no \
     donor reply"
  );
}

#[test]
fn a_donor_reply_that_always_lands_mid_walk_re_pins_a_dead_donors_transfer() {
  // THE INVERSE ORDER. Every solicit tick issues the stop-and-wait ARQ walk BEFORE broadcasting
  // `RequestSync`, so on any schedule where a donor's round trip is shorter than the block lane's
  // latency the answer arrives while that walk is still outstanding — EVERY round, not occasionally.
  // The one-pin admission refuses a reply in that window, which is correct (the walk's verdict must
  // land first) but must not DISCARD it: here the pinned donor is DEAD and the transfer still has a
  // block to pull, so the ARQ completion re-requests from a donor that will never answer and the only
  // evidence that could move the transfer — a live donor's reply — is exactly what keeps being thrown
  // away. Retaining the refused pin and re-delivering it once the walk lands turns the refusal into an
  // ordering, and the failover completes.
  //
  // NEUTER CHECK: drop the retention (increment the counter and return) and the transfer stays pinned
  // to the dead donor for every round below — `block_fetch_donor()` never moves off slot 0.
  let (_donor_e, dstorage) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dstorage);
  let (_op, sm_root, sessions_root) =
    Endpoint::<CountSm>::decode_checkpoint(&env).expect("the donor envelope decodes");

  // The full DAG, as any donor holds it.
  let mut donor_blocks = crate::block_store::InMemoryBlockStore::new();
  seed_donor_blocks(&mut donor_blocks, 4);

  // The laggard holds ONLY the SM DAG, so its frontier drains to the session root and STOPS there with
  // a genuine outstanding pull — the state a drained-frontier resumption cannot rescue.
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  {
    let mut stack = std::vec![sm_root];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(addr) = stack.pop() {
      if !seen.insert(addr) {
        continue;
      }
      let block = donor_blocks
        .read_block(addr)
        .expect("SM block present in the donor store");
      for child in CountSm::block_references(&block) {
        stack.push(child);
      }
      blocks.put(block);
    }
  }
  assert!(
    blocks.has_block(sm_root) && !blocks.has_block(sessions_root),
    "precondition: the SM DAG is local and the session DAG is not, so the fetch has a real pull \
     outstanding"
  );

  let mut e = sync_backup();
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut now = Instant::ZERO;
  // Both donors serve the SAME content-addressed checkpoint; they differ only in which slot answers,
  // and the pin follows the authenticated sender.
  let reply = |slot: u16, nonce: u64| {
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(slot),
      nonce,
      env.clone(),
      Bytes::new(),
    ))
  };
  let dead_donor = Peer::Replica(ReplicaId::new(0));
  let live_donor = Peer::Replica(ReplicaId::new(2));

  // Pin the transfer to the donor that is about to go dark.
  e.arm_forced_sync_for_test(4);
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    dead_donor,
    reply(0, e.sync_nonce_for_test()),
  );
  e.block_step(now, &mut storage, &mut blocks);
  while e.poll_message().is_some() {}
  assert_eq!(
    e.block_fetch_donor(),
    Some(0),
    "precondition: the transfer is pinned to the donor that now goes dark"
  );

  // Three rounds, each in the ORDER the schedule forces: the ARQ walk is queued, the live donor's
  // reply lands while it is outstanding, and only then does the walk complete.
  let refused_before = e.walk_pins_refused();
  let mut cursor = crate::BlockJobCursor::new();
  for _ in 0..3 {
    now = now + SYNC_SOLICIT;
    e.sync_timeouts(now, &mut storage);
    let job = storage
      .poll_block_job()
      .expect("the solicit tick queued the ARQ walk");
    assert!(
      e.transfer_walk_in_flight(),
      "ANTI-VACUITY: the walk really is outstanding when the reply below is delivered"
    );
    let refused = e.walk_pins_refused();
    e.handle_message(
      now,
      &mut storage,
      live_donor,
      reply(2, e.sync_nonce_for_test()),
    );
    assert_eq!(
      e.walk_pins_refused(),
      refused + 1,
      "ANTI-VACUITY: the reply really was refused by the one-pin admission, not admitted outright"
    );
    let done = crate::execute_block_job(&mut cursor, job, &mut blocks);
    e.on_block_done(now, &mut storage, done);
    while e.poll_message().is_some() {}
  }
  assert!(
    e.walk_pins_refused() >= refused_before + 3,
    "ANTI-VACUITY: every round's reply landed mid-walk"
  );
  assert_eq!(
    e.block_fetch_donor(),
    Some(2),
    "the deferred pin was re-delivered after each walk, so the transfer failed over to the LIVE donor"
  );

  // The live donor answers the outstanding pull, and the transfer completes. Bounded so a regression
  // that stalls the transfer fails the assertion below rather than hanging the suite.
  for _ in 0..16 {
    now = now + SYNC_SOLICIT;
    e.sync_timeouts(now, &mut storage);
    e.block_step(now, &mut storage, &mut blocks);
    let mut want = None;
    while let Some(out) = e.poll_message() {
      if let Message::RequestBlock(addr) = out.msg_ref() {
        want = Some(*addr);
      }
    }
    let Some(addr) = want else { break };
    let block = donor_blocks
      .read_block(addr)
      .expect("the live donor serves every requested block");
    e.handle_message(
      now,
      &mut storage,
      live_donor,
      Message::BlockResponse(crate::BlockResponse::new(addr, Some(block))),
    );
    for _ in 0..4 {
      e.storage_step(now, &mut storage, &mut blocks);
    }
    if e.state_syncs_applied() == 1 {
      break;
    }
  }
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the transfer installed once the failover reached a donor that answers"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "and the laggard is at the synced checkpoint"
  );
}

#[test]
fn repeated_sync_forward_over_a_ring_less_wal_is_bounded_by_the_session_append_quota() {
  // The ring-less accumulation shape, driven end to end. The backup's WAL is a proactor whose
  // submitted writes are already at the device (`ReorderWal`, capacity `u64::MAX`): appends stage
  // and complete only when the test lands them, and truncate/prune cancel NOTHING — the WAL
  // contract's latitude. Each generation the backup appends a full implied-ring window of
  // prepares (none of which complete), falls behind, and state-syncs forward: the install
  // abandons the endpoint's append OWNERSHIP (`pending`/`appending`/`deferred_appends` clear)
  // while the session's physical-write facts survive, and the prune cancels none of them. On a
  // bounded ring the slot fence would refuse the next generation at the wrap; ring-less, nothing
  // ever aliases — so before the session append quota the ledger and the device backlog grew by
  // one full window per generation with no time-independent bound. The quota must (a) admit two
  // full windows untouched (healthy operation plus one sync handover is never deferred), (b)
  // refuse the third generation's submissions retryably at the choke while the ledger holds at
  // the quota, and (c) release every parked append as the delayed writes finally complete — the
  // backlog eventually completes, deferral never wedges.
  let mut e = sync_backup();
  let (wal, sb) = (ReorderWal::new(), TestSb::default());
  let mut storage = Storage::new(wal, sb);
  let mut blocks = InMemoryBlockStore::new();
  let now = Instant::ZERO;
  let quota = storage.append_quota();
  // One implied-ring window for this config (`checkpoint_ops == 2`): the quota is two of them.
  // Every prepare carries commit 0, so the backup appends the whole window (head extends at
  // submit) while APPLYING nothing — it lags on disk, not on apply, which is the accumulation
  // shape under test (an applying backup would checkpoint every two ops and never need the sync).
  let window = quota / 2;
  let mut floor = 0u64; // the durable checkpoint the current generation appends above
  for generation in 1..=3u64 {
    for op in floor + 1..=floor + window {
      e.handle_message(now, &mut storage, primary_peer(), prepare(op, 0));
      assert!(
        storage.wal_appends_in_flight() as u64 <= quota,
        "generation {generation}: the append ledger passed the session quota at op {op} \
         ({} in flight, quota {quota})",
        storage.wal_appends_in_flight(),
      );
      while e.poll_message().is_some() {}
    }
    match generation {
      1 => assert_eq!(
        storage.wal_appends_in_flight() as u64,
        window,
        "generation 1 fits the first implied-ring window untouched"
      ),
      2 => assert_eq!(
        storage.wal_appends_in_flight() as u64,
        quota,
        "generation 2 fills the second window — the whole quota is now in flight"
      ),
      _ => {
        assert_eq!(
          storage.wal_appends_in_flight() as u64,
          quota,
          "generation 3 is refused at the choke: the ledger holds at the quota"
        );
        assert!(
          !e.deferred_appends.is_empty(),
          "the refused submissions are parked for release, not dropped"
        );
      }
    }
    if generation == 3 {
      break; // nothing more to install — the third window is parked, awaiting quiescence
    }
    // The cluster checkpointed past this backup's entire window: sync forward. The donor
    // checkpoint is fabricated at `M = head + 1` (an ordinary client-op frontier), its envelope
    // and both DAGs seeded locally so the install drains without a RequestBlock round trip. The
    // trigger is a beyond-the-gap prepare ADVERTISING checkpoint `M` with commit still 0: the
    // backup arms the stale-checkpoint sync off the advertisement alone, applying nothing.
    let m = floor + window + 1;
    let snap = CountSm::default().snapshot();
    let env = Endpoint::<CountSm>::encode_checkpoint(
      OpNumber::with(m),
      crate::block_address(&snap),
      super::super::session_blocks::encode_sessions(
        &std::collections::BTreeMap::new(),
        &mut blocks,
      ),
    );
    blocks.put(snap.clone());
    let id = crate::checkpoint_id(&env);
    e.handle_message(now, &mut storage, primary_peer(), prepare_ck(m + 1, 0, m));
    let nonce = captured_sync_nonce(&mut e);
    e.handle_message(
      now,
      &mut storage,
      primary_peer(),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        View::new(),
        OpNumber::with(m),
        id,
        crate::Epoch::new(0),
        0,
        ReplicaId::new(0),
        nonce,
        env,
        Bytes::new(),
      )),
    );
    for _ in 0..8 {
      e.block_step(now, &mut storage, &mut blocks);
      e.storage_step(now, &mut storage, &mut blocks);
    }
    assert_eq!(
      e.state_syncs_applied(),
      generation,
      "the sync-forward installed (generation {generation})"
    );
    assert_eq!(
      storage.wal_appends_in_flight() as u64,
      generation * window,
      "the install abandoned ownership but cancelled nothing: every prior generation's \
       delayed writes still occupy the session ledger"
    );
    while e.poll_message().is_some() {}
    while e.poll_event().is_some() {}
    floor = m;
  }
  // The delayed writes finally complete — arbitrarily late, as the contract allows. Every
  // completion frees quota headroom, and the release pass re-submits the parked third window;
  // land those too, until the medium owes nothing.
  for _ in 0..(4 * window + 8) {
    let staged: std::vec::Vec<u64> = storage.wal().staged_ops();
    if staged.is_empty() && storage.wal_appends_in_flight() == 0 {
      break;
    }
    for op in staged {
      storage.wal_mut().release_latest_for(op);
    }
    for _ in 0..4 {
      e.storage_step(now, &mut storage, &mut blocks);
    }
    while e.poll_message().is_some() {}
  }
  assert_eq!(
    storage.wal_appends_in_flight(),
    0,
    "every delayed and every released append completed — the ledger drained"
  );
  assert!(
    e.deferred_appends.is_empty(),
    "no parked append was stranded: quota release re-submitted the third window"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2 * (quota / 2) + 2),
    "the backup ended at the second sync-forward's checkpoint"
  );
}

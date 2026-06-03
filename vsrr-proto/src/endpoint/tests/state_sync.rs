use super::super::*;
use super::*;
use crate::{
  ClientId, Config, DoViewChange, Header, OpId, OpNumber, PreparedEntry, ReadOk, ReplicaId,
  Request, RequestNumber, SlotStatus, StartViewChange, View, VsrState, Wal, WalDone,
};
use std::collections::VecDeque;

/// A FIXED-RING WAL of `capacity` slots (the M3.2b bounded-WAL backend, modelled for the proto unit
/// tests). Op `K` occupies ring slot `K mod capacity`; appending `K` EVICTS whatever op last held that
/// slot (op `K - capacity`), so the resident set never exceeds `capacity` and a read of the
/// wrapped-over op returns `Absent` — exactly the sim's `set_capacity` semantics
/// (`vsrr_simulation::storage`). Used to drive the proto's `maybe_sync_below_ring_window` /
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
fn stale_checkpoint_commit_triggers_request_sync() {
  // replica 1 of 3, Normal, head op 0, checkpoint 0. A Commit advertising checkpoint_op=8 (> our
  // head) means the cluster checkpointed past our entire WAL → we must state-sync.
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(10),
      OpNumber::with(8),
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
}

#[test]
fn stale_checkpoint_prepare_triggers_request_sync() {
  // A `Prepare` (not just a Commit) carrying checkpoint_op > our head also triggers the sync — the
  // A2 signal closes the last trigger gap for a backup that only ever hears Prepares.
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare_ck(9, 8, 8));
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
  let now = Instant::ZERO;
  for op in 1..=8 {
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(op, 0));
    e.handle_storage(now, &mut wal, &mut sb);
  }
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(8),
      OpNumber::with(8),
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
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(10),
      OpNumber::with(8),
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
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(12),
      OpNumber::with(10),
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
  let now = Instant::ZERO;
  while e.poll_message().is_some() {} // drain prepares/replies from the warm-up
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      e.view(),
      OpNumber::with(0),
      ReplicaId::new(2),
      0xCAFE,
      false, // ordinary state-sync (not a recovery peer-fetch)
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // the checkpoint read completes → ship SyncCheckpoint
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
fn serve_sync_checkpoint_drops_a_corrupt_checkpoint_read() {
  // codex R23-F1 REGRESSION (serve path must be as strict as recover): a Normal donor at a durable
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
    while e.poll_message().is_some() {} // drain the warm-up
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestSync(crate::RequestSync::new(
        e.view(),
        OpNumber::with(0),
        ReplicaId::new(2),
        0xABCD,
        false,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb); // clean read completes → ship SyncCheckpoint
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
      &BTreeMap::new(),
      &tampered_sm.snapshot(),
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
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestSync(crate::RequestSync::new(
        e.view(),
        OpNumber::with(0),
        ReplicaId::new(2),
        0xCAFE,
        false,
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb); // the corrupt read completes → must be DROPPED
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
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::RequestSync(crate::RequestSync::new(
      e.view(),
      OpNumber::with(0),
      ReplicaId::new(0),
      1,
      false, // ordinary state-sync (not a recovery peer-fetch)
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(e.poll_message().is_none(), "nothing newer → silent");
}

#[test]
fn recovery_request_sync_is_served_by_a_peer_at_the_same_checkpoint() {
  // F2 REGRESSION (recovery peer-fetch livelock): a recovering replica whose OWN checkpoint snapshot
  // is permanently corrupt solicits a RECOVERY RequestSync advertising its (known) checkpoint_op. The
  // R2 escalation only got served by a STRICTLY-newer peer (`>`), so on an idle cluster where every
  // healthy peer holds EXACTLY the same checkpoint_op, the request was ignored forever → the recovery
  // livelocked (the cluster could stay unavailable if that replica is needed for quorum). With the
  // fix, a `recovery` request is served by a peer at an EQUAL checkpoint_op; an ordinary one is not.
  let now = Instant::ZERO;
  // A donor that is Normal at checkpoint op 2.
  let (mut donor, mut wal, mut sb) = donor_primary_at_checkpoint(2);
  while donor.poll_message().is_some() {} // drain warm-up

  // (a) A RECOVERY request at the SAME checkpoint (op 2) IS served.
  donor.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      donor.view(),
      OpNumber::with(2), // EQUAL to the donor's checkpoint
      ReplicaId::new(2),
      0xF00D,
      true, // recovery peer-fetch
    )),
  );
  donor.handle_storage(now, &mut wal, &mut sb); // checkpoint read completes → ship SyncCheckpoint
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
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      donor.view(),
      OpNumber::with(2), // EQUAL to the donor's checkpoint
      ReplicaId::new(2),
      0xBEEF,
      false, // ordinary state-sync
    )),
  );
  donor.handle_storage(now, &mut wal, &mut sb);
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
  // F2 REGRESSION (end-to-end convergence): a replica whose OWN durable checkpoint snapshot is
  // permanently unreadable escalates to a recovery peer-fetch; a Normal peer at the SAME checkpoint
  // op serves it; delivering that SyncCheckpoint converges the recovering replica to Normal. (Before
  // the fix the equal-checkpoint peer ignored the request and the replica never left Recovering.)
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
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
  .unwrap();
  let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2, // head == checkpoint_op → empty tail; isolates the checkpoint path
    done: VecDeque::new(),
  };
  let mut e = Endpoint::recover(cfg, 5, CountSm::default(), &mut wal, &mut sb);
  // Drive past the per-op retry budget so it escalates to a peer fetch.
  for _ in 0..(RECOVER_READ_RETRIES as usize + 4) {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
  }
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
  while peer.poll_message().is_some() {}
  peer.handle_message(
    now,
    &mut pwal,
    &mut psb,
    Peer::Replica(ReplicaId::new(1)),
    Message::RequestSync(req),
  );
  peer.handle_storage(now, &mut pwal, &mut psb);
  let mut answer = None;
  while let Some(out) = peer.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      answer = Some(s.clone());
    }
  }
  let answer = answer.expect("the equal-checkpoint peer SERVES the recovery request (F2)");

  // Deliver the peer's SyncCheckpoint back to the recovering replica → it applies + re-persists +
  // converges to Normal at the synced point.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(answer),
  );
  e.handle_storage(now, &mut wal, &mut sb); // drive the durable re-persist
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
  let now = Instant::ZERO;
  // Trigger sync (Commit advertising checkpoint_op=4), capture the nonce it used.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // Deliver the SyncCheckpoint.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      nonce,
      env.clone(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // drive the durable re-persist (TestSb synchronous)
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.commit_max(), OpNumber::with(4));
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(
    e.state_machine().applied().len(),
    4,
    "SM restored from the snapshot, not replayed"
  );
  assert_eq!(
    sb.state().checkpoint_op(),
    OpNumber::with(4),
    "synced checkpoint is now durable"
  );
  assert_eq!(sb.state().checkpoint_id(), id);
}

#[test]
fn state_sync_installs_atomically_only_after_the_root_is_durable() {
  // codex R24-F1 (durable-before-install): a verified SyncCheckpoint STAGES the durable re-persist
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
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 1_000).unwrap();
  let mut e = Endpoint::new(cfg, 0, CountSm::default());
  // Give the laggard a small live WAL band (ops 1,2) below the synced point so the prune is OBSERVABLE.
  let mut wal = TestWal::default();
  let mut sb = StepSb::default();
  let now = Instant::ZERO;
  for op in 1..=2u64 {
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(op, 0));
    e.handle_storage(now, &mut wal, &mut sb);
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
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
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // Baseline the OLD (pre-STAGE, post-trigger) frontier — the install must not move it before the root.
  let (base_commit, base_op, base_ckpt) = (e.commit(), e.op(), e.checkpoint_op());
  let base_applied = e.state_machine().applied().len();
  assert_eq!(
    base_ckpt,
    OpNumber::with(0),
    "the laggard is at its old checkpoint 0 before STAGE"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      nonce,
      env.clone(),
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
    e.state_machine().applied().len(),
    base_applied,
    "SM NOT restored at STAGE (still its old applied state, no snapshot installed yet)"
  );
  assert!(
    wal.entries.contains_key(&1) && wal.entries.contains_key(&2),
    "the WAL is NOT pruned at STAGE (the destructive prune is deferred to the install)"
  );
  // Complete step 1 (snapshot durable → root submitted), still NO install (the root is now in flight).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
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
  e.handle_storage(now, &mut wal, &mut sb);
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
    e.state_machine().applied().len(),
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
fn state_sync_view_change_before_the_sync_root_does_not_strand_the_committed_band() {
  // codex R24-F1 REGRESSION (the wedge). A laggard STAGES a SyncCheckpoint but a VIEW CHANGE fires
  // before the sync ROOT completes, and the laggard becomes the new PRIMARY. It must NOT advertise the
  // synced commit while carrying a STALE `checkpoint_op` over a PRUNED committed band — that strands a
  // lower laggard (which can neither RequestPrepare the pruned band nor is triggered to RequestSync,
  // since the primary advertises the old checkpoint) → cluster wedge if the donor crashes. With the
  // durable-before-install fix the STAGE no longer prunes/advances, so the view change finds the OLD
  // consistent state intact (`enter_view_change` cleanly cancels the not-yet-applied install): the band
  // is NOT pruned and `commit_min`/`checkpoint_op` are CONSISTENT (both old), so a lower laggard is not
  // stranded. FAIL-BEFORE: the laggard becomes primary with `commit == synced (4)`, `checkpoint_op ==
  // old (0)`, and the band pruned.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  // The laggard: replica 1 of 3 over CountSm with a HUGE checkpoint interval (so its own band does not
  // auto-checkpoint and race the sync persist — it stays at its old durable checkpoint 0).
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 1_000).unwrap();
  let mut e = Endpoint::new(cfg, 0, CountSm::default());
  let mut wal = TestWal::default();
  let mut sb = StepSb::default();
  let now = Instant::ZERO;
  // The laggard (replica 1 of 3) holds a live WAL band {1,2} below the synced point.
  for op in 1..=2u64 {
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(op, 0));
    e.handle_storage(now, &mut wal, &mut sb);
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
  }
  while e.poll_message().is_some() {}
  // Trigger + STAGE a sync to checkpoint 4 (> head 2). The trigger Commit carries commit=0, so the
  // laggard does NOT learn a commit above its head (a known-commit above op would, correctly, fail-stop
  // canonical-log selection — that R9-F1 hazard is orthogonal to this test).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(0),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  // Advance step 1 (snapshot durable → root submitted) but withhold the ROOT (it stays in flight).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(
    e.sync_target_for_test().is_some(),
    "the sync is still armed (the root has NOT completed → the install is pending)"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "checkpoint_op is still old at this point"
  );
  // A VIEW CHANGE fires in this window: an SVC quorum drives the laggard into ViewChange(1), and a DVC
  // quorum makes it (replica 1 = primary of view 1) the new primary — all BEFORE the sync root lands.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb); // primary_idle → SVC(view 1), own bit
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
  );
  assert_eq!(e.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  assert_eq!(
    e.sync_target_for_test(),
    None,
    "entering ViewChange cancelled the pending install (sync cleared)"
  );
  sb.flush();
  e.handle_storage(later, &mut wal, &mut sb); // complete the SendDoViewChange durable-view write
  while e.poll_message().is_some() {}
  // Feed a DVC from replica 0 (op 2, commit 0) → with our own DVC that is a quorum (2 of 3) → primary.
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(2),
      OpNumber::with(0),
      ReplicaId::new(0),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          Bytes::copy_from_slice(&[1u8]),
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          Bytes::copy_from_slice(&[2u8]),
        ),
      ],
    )),
  );
  assert!(e.is_primary(), "replica 1 became the new primary of view 1");
  // THE R24-F1 ASSERTION. The new primary did NOT install the synced state behind a stale checkpoint:
  // `commit_min` and `checkpoint_op` are CONSISTENT (both old, not commit==4/checkpoint==0), and the
  // committed band {1,2} is NOT pruned — so a lower laggard can still be served + caught up.
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "the new primary advertises its OLD durable checkpoint (the synced install never landed)"
  );
  assert!(
    e.commit().get() <= e.op().get() && e.checkpoint_op().get() <= e.commit().get(),
    "commit_min/op/checkpoint_op are consistent (checkpoint <= commit <= op), not commit==synced over a stale checkpoint"
  );
  assert_ne!(
    e.commit(),
    OpNumber::with(4),
    "commit_min was NOT advanced to the synced point by an uninstalled sync"
  );
  assert!(
    wal.entries.contains_key(&1) && wal.entries.contains_key(&2),
    "the committed band is NOT pruned (no stranded laggard): the STAGE never pruned the WAL"
  );
}

#[test]
fn an_ordinary_checkpoint_completing_during_a_solicited_sync_advances_without_clearing_it() {
  // codex R24-F1 follow-up (REGRESSION). The `on_sb_done` root-completion arm must route by whether THIS
  // root is the sync's re-persist (`pc.sync`), NOT by `self.sync.is_some()`. A sync can be merely
  // SOLICITED (armed, awaiting a SyncCheckpoint — no staged install) while an ORDINARY checkpoint
  // completes. If that ordinary completion were misrouted to the sync-install branch it would (a) NOT
  // advance `checkpoint_op` and (b) CLEAR the solicited sync — so the laggard's checkpoint never moves
  // and it re-solicits forever (the long-down-replica state-sync livelock). With the `pc.sync`
  // discriminator the ordinary checkpoint advances `checkpoint_op` and LEAVES the solicited sync armed.
  let mut e = sync_backup(); // replica 1 of 3, CountSm, checkpoint_ops = 2
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Hold a live band {1,2} (durable).
  for op in 1..=2u64 {
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(op, 0));
    e.handle_storage(now, &mut wal, &mut sb);
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
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(99),
    )),
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(99),
    "a state-sync is SOLICITED (armed) — but no SyncCheckpoint has been received, so nothing is staged"
  );
  // The in-flight checkpoint is TYPED `Ordinary`, even though a sync is concurrently solicited — the
  // discriminator the routing uses lives in the completion token (`pc.kind`), NOT in `self.sync`. This
  // is the structural property that types the R24-F1 footgun away: there is no ambient bool to confuse.
  assert_eq!(
    e.pending_checkpoint_is_sync_for_test(),
    Some(false),
    "the staged checkpoint is an ORDINARY one (CheckpointKind::Ordinary), not a sync re-persist, \
     despite the concurrently-solicited sync"
  );
  let synced_before = e.state_syncs_applied();
  // Complete the ordinary checkpoint's two superblock writes.
  e.handle_storage(now, &mut wal, &mut sb);
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
  // codex vopr seed 8 (REGRESSION). A `Normal` PRIMARY that receives a valid `SyncCheckpoint` for an
  // outstanding sync must NOT apply it in place (that would reset commit_min to the checkpoint and
  // clear the commit pipeline while it stays primary → a wedge: `try_commit` can never advance past
  // the checkpoint, and a recovered/op-reset primary can REUSE committed op numbers — the seed-52
  // divergence). Instead it STEPS DOWN: flags the deferred forfeit and drops the sync, unchanged. A
  // caught-up replica then leads.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, 1_000).unwrap(); // huge interval: no checkpoint
  let mut e = Endpoint::new(cfg, 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Drive the primary to op 4, commit 4 (no checkpoint — interval is huge).
  for rn in 1..=4u64 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(rn),
        Bytes::from(std::vec![rn as u8]),
      )),
    );
    e.handle_storage(now, &mut wal, &mut sb); // own append durable → own vote
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
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(6),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  // It must NOT have applied the sync: op/commit/checkpoint unchanged, SM not restored.
  assert_eq!(e.op(), OpNumber::with(4), "op unchanged (no apply)");
  assert_eq!(e.commit(), OpNumber::with(4), "commit unchanged (no apply)");
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "checkpoint unchanged (no apply)"
  );
  assert_eq!(
    e.state_machine().applied().len(),
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
fn sync_checkpoint_with_mismatched_id_is_rejected_not_restored() {
  // A corrupt/forged snapshot whose bytes don't hash to the advertised id MUST NOT be restored.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
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
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      advertised,
      ReplicaId::new(0),
      nonce,
      bad_env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "rejected: checkpoint not advanced"
  );
  assert_eq!(
    e.state_machine().applied().len(),
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
  // F3 REGRESSION (overstated checkpoint op over stale-but-consistent bytes): a faulty peer ships a
  // snapshot whose REAL frontier is op A=2 but advertises `checkpoint_op = B=4`. The snapshot's bytes
  // hash to the advertised `checkpoint_id` (so the existing integrity gate PASSES — the id is
  // consistent with the OLD bytes), yet B > A. Before binding the op into the hash, the receiver
  // restored the op-2 SM but advanced `commit_min`/`commit_max`/`op` to 4 — SILENTLY DROPPING the
  // committed ops in (A, B] = (2, 4]. With the fix, the op bound INSIDE the envelope (2) is compared
  // to the advertised op (4) and the mismatch REJECTS the snapshot: no restore, no commit advance.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  // Trigger a sync targeting op 4 (the overstated op).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // Build a STALE-BUT-CONSISTENT envelope: a genuine snapshot bound to op A=2, with the matching id.
  let mut stale_sm = CountSm::default();
  stale_sm.apply(OpNumber::with(1), &[1]);
  stale_sm.apply(OpNumber::with(2), &[2]);
  let stale_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    &BTreeMap::new(),
    &stale_sm.snapshot(),
  );
  let real_id = crate::checkpoint_id(&stale_env); // the id IS consistent with these (op-2) bytes
  // Deliver it advertising the OVERSTATED op B=4 but the bytes' REAL id → the hash gate passes, the
  // op-binding gate must reject (bound op 2 != advertised op 4).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4), // OVERSTATED — does not match the op bound (2) inside the snapshot
      real_id,           // matches checkpoint_id(stale_env), so the integrity gate PASSES
      ReplicaId::new(0),
      nonce,
      stale_env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // (no re-persist should have been staged)
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
    e.state_machine().applied().len(),
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
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // Deliver a SyncCheckpoint with the WRONG nonce — must be ignored.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      nonce.wrapping_add(1),
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "wrong nonce → ignored"
  );
  assert_eq!(e.state_machine().applied().len(), 0);
}

#[test]
fn sync_checkpoint_below_target_is_ignored() {
  // A SyncCheckpoint whose checkpoint_op does not even reach the target we learned the cluster has
  // committed (an out-of-date peer answering with an OLDER checkpoint) → ignored: it would not
  // advance us past the committed frontier. (Target 6; a reply at op 4 is dropped.)
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let (_d, _dw, dsb) = donor_primary_at_checkpoint(4);
  let (env4, id4) = donor_envelope(&dsb);
  let now = Instant::ZERO;
  // Trigger a sync targeting 6 (the cluster's known checkpoint).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(6),
      OpNumber::with(6),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // A stale peer answers with checkpoint 4 (< target 6): must be ignored.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id4,
      ReplicaId::new(0),
      nonce,
      env4,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
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
  let (_d, _dw, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let now = Instant::ZERO;
  // No trigger fired → sync is None. Deliver a (valid) SyncCheckpoint anyway.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      0xABCD,
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(0),
    "an unsolicited SyncCheckpoint (no outstanding sync) is ignored"
  );
  assert_eq!(e.state_machine().applied().len(), 0);
}

#[test]
fn lower_sync_checkpoint_is_ignored_after_a_higher_one() {
  // Monotonicity: after syncing to checkpoint 4, a later SyncCheckpoint advertising a LOWER
  // checkpoint must never regress us. (We forge a stale reply at the same nonce/below our point.)
  let (mut e, mut wal, mut sb, env4, id4) = sync_apply_harness(4);
  let (_d2, _dw2, dsb2) = donor_primary_at_checkpoint(2);
  let (env2, id2) = donor_envelope(&dsb2);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id4,
      ReplicaId::new(0),
      nonce,
      env4,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  // A stale lower SyncCheckpoint (op 2) arriving now: sync is already cleared, and even if it
  // weren't, `> self.checkpoint_op` fails. It must be ignored — no regression.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      id2,
      ReplicaId::new(0),
      nonce,
      env2,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
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
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(6),
      OpNumber::with(6),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(6),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.checkpoint_op(), OpNumber::with(6));
  assert!(
    e.repair.is_empty(),
    "the hole below the synced point is subsumed + cleared"
  );
  assert!(e.timers.repair_retry.is_none(), "repair timer stopped");
}

// ── M3.5 T2: force-state-sync escalation ───────────────────────────────────────────────────────

#[test]
fn a_pruned_committed_hole_forces_a_state_sync() {
  // A Normal BACKUP (replica 1 of 3) holds a repair hole at op N=2 with a head ABOVE it (op=4),
  // where a QUORUM has checkpointed past N (so RequestPrepare is futile — the op is pruned on the
  // quorum). It must (a) clear the doomed hole, (b) emit a RequestSync (not just RequestPrepare),
  // (c) record a FORCED sync targeting the quorum checkpoint.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::with(4),
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
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  // Head op 6, commit held at 3, own checkpoint 0, a committed hole at op 4.
  ep.force_state_for_test(0, 6, 3, 0, &[4]);
  // The primary (replica 0) reports a checkpoint of 3 — BELOW the hole at 4. The max-peer floor is
  // max{self=0, r0=3} = 3 < N=4 → the hole is still in-reach (the primary has NOT pruned op 4, so a
  // RequestPrepare can still be answered) → no force-sync.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::with(3),
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
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(1),
      OpNumber::with(8),
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
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
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
  // SAFETY (VOPR seed 164): a forced sync where checkpoint_op (3) <= self.op (5). The held tail
  // (3..5] is ops this replica already durably appended + ACKED, so the cluster may have COMMITTED
  // them off its vote. The OLD code discarded the tail (rewound the head to 3 + truncated the WAL),
  // destroying its only durable copy while keeping `log_view` — a later view change then took its
  // (log_view, op) as the canonical head and dropped those committed ops, the loss `adopt_canonical_
  // head`'s `op >= commit_min` assert trips on. The forced path must instead apply WITHOUT panic,
  // PRESERVE the above-floor tail (keep op 5 + its log entries), restore the SM at the snapshot, and
  // subsume the doomed hole at 2.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(3);
  let (env, id) = donor_envelope(&dsb);
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 1, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(3),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  ep.handle_storage(Instant::ZERO, &mut wal, &mut sb); // drive the durable re-persist
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
  // codex R25-F1 REGRESSION (a stale forced SyncCheckpoint reaches apply_sync). A forced sync is armed
  // for a doomed hole at target T=2, but the ORDINARY repair path completes FIRST: a peer's `Prepare`
  // fills the hole via `fill_repair`, its WAL append lands, and `advance_commit` moves `commit_min` PAST
  // T (to 4) while the forced `sync` is armed. Then a DELAYED `SyncCheckpoint(checkpoint_op = T = 2)` for
  // the now-stale target arrives. The ordinary stale-response guard (`checkpoint_op <= self.op → drop`)
  // is SKIPPED for the forced path (the M3.5/seed-164 relaxation), so the stale response would reach
  // `apply_sync` — where the forced-branch `assert!(checkpoint_op >= commit_min)` PANICKED (commit_min 4
  // > checkpoint_op 2). FAIL-BEFORE: that panic. PASS-AFTER: Part A CANCELS the satisfied forced sync the
  // moment `advance_commit` carries `commit_min` past T, so the stale response is dropped upstream (no
  // outstanding sync), the applied frontier is unchanged, and nothing is installed — no panic, no rewind.
  //
  // A real BACKUP (replica 1 of 3) over CountSm with a HUGE checkpoint interval, so applying its band
  // does NOT auto-checkpoint (which would otherwise set `pending_checkpoint` and short-circuit the path).
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 1_000).unwrap();
  let mut ep = Endpoint::new(cfg, 7, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(0),
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
    primary_peer(),
    repair_prepare(0, 2, 4),
  );
  assert!(
    ep.has_repair_hole_for_test(2),
    "the hole stays OPEN until the repair-fill append is durable (R13-F2 barrier)"
  );
  ep.handle_storage(now, &mut wal, &mut sb); // on_wal_done: insert op 2, clear the hole, advance_commit
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
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      crate::checkpoint_id(&env),
      ReplicaId::new(0),
      // a nonce that would have matched the cancelled forced sync (it is gone, so this is moot)
      7,
      env,
    )),
  );
  ep.handle_storage(now, &mut wal, &mut sb);
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
  // codex R25-F1 (Part B — the safety NET reaching `apply_sync` directly). Models the reordering where a
  // forced `SyncCheckpoint` for a target the applied frontier has ALREADY passed reaches `apply_sync`
  // (i.e. Part A's apply-loop cancel did not run between the arm and this delivery). The forced sync's
  // target (2) is `<= self.op` (so the upstream `<= self.op → drop` guard is relaxed for the forced
  // path) and `< commit_min` (4) — applying it would rewind the applied frontier. Part B DROPS it
  // gracefully (no panic, no rewind) instead of asserting; the LEGITIMATE forced sync is unaffected.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 1_000).unwrap();
  let mut ep = Endpoint::new(cfg, 7, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  ep.handle_storage(now, &mut wal, &mut sb);
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
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(2),
      ReplicaId::new(1),
      OpNumber::with(8),
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
  // The flag PERSISTS (F2) — the lone SVC has not yet formed a quorum, so the view has not changed;
  // the latch keeps the primary re-proposing + not heartbeating until it does. The op is unchanged.
  // (The step-down bootstraps `svc_message` at the retransmit cadence — codex R15 — so the re-propose
  // is serviced on the next svc_message window; tick at that 100ms boundary.)
  ep.handle_timeout(
    Instant::ZERO + core::time::Duration::from_millis(100),
    &mut wal,
    &mut sb,
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
    if let Message::StartViewChange(svc) = out.into_msg() {
      if svc.view().get() == 1 {
        saw_svc_view1 = true;
      }
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
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 4).unwrap();
  let mut ep = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
  let head_at_strand = ep.op().get();
  assert_eq!(head_at_strand, 10);
  // Enter the force-sync strand (flag the deferred forfeit) via a peer PrepareOk above the hole.
  ep.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::PrepareOk(PrepareOk::new(
      View::new(),
      OpNumber::with(2),
      ReplicaId::new(1),
      OpNumber::with(8),
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
  ep.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
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
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
  drop(e); // crash
  // Recover from the same wal/sb: the synced checkpoint is the durable root.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
  let mut recovered = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
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
  recovered.handle_storage(now, &mut wal, &mut sb); // restore SM from the synced snapshot → Normal
  assert_eq!(recovered.status(), Status::Normal);
  assert_eq!(
    recovered.state_machine().applied().len(),
    4,
    "recovered SM reflects the synced checkpoint prefix"
  );
}

// ── State-sync (M3.4a) — A6: view-change / B3-interaction safety (regression guards) ──

#[test]
fn synced_replica_reports_its_checkpoint_in_view_change() {
  // After syncing to checkpoint 4, force the replica into a view change and inspect its DVC: it must
  // report commit == 4 (the synced point) with log_view <= view and a tail that does NOT start at
  // op 1 — exactly the recover-from-checkpoint shape (this is the B3 interaction; no B3 code here).
  // Use replica 2 of 3 as the laggard: in view 1 the primary is replica 1 (not itself), so it sends
  // a DoViewChange we can capture (a replica that is itself the next primary would form the
  // canonical log directly instead of sending a DVC).
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let mut e = Endpoint::new(
    Config::with_checkpoint_ops(1, ReplicaId::new(2), 3, 2).unwrap(),
    0,
    CountSm::default(),
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::with(4),
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
    primary_peer(),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(4),
      id,
      ReplicaId::new(0),
      nonce,
      env,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.status(), Status::Normal);
  while e.poll_message().is_some() {}

  // Force a view change to view 1 (primary = replica 1): replica 2 proposes view 1 on idle, a peer
  // SVC completes the quorum → ViewChange(1) → it sends a DoViewChange to replica 1.
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb); // primary_idle → propose view 1 (own bit)
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  assert_eq!(e.status(), Status::ViewChange);
  assert_eq!(e.view(), View::with(1));
  e.handle_storage(later, &mut wal, &mut sb); // durable-view write completes → DVC is sent
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
  // codex R26-F1 (REGRESSION — the un-completable-sync WEDGE). The M3.2b backup-overflow path
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
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 5).unwrap(); // checkpoint_ops == C
  let mut e = Endpoint::new(cfg, 7, CountSm::default());
  let mut wal = RingWal::new(N);
  let mut sb = StepSb::default(); // async: the ordinary checkpoint root lands on a later flush
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
  e.maybe_checkpoint(&mut sb);
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
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare_ck(6, 5, 5));
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
  e.handle_storage(now, &mut wal, &mut sb); // AwaitSnapshot → submit root
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb); // AwaitRoot → advance_checkpoint_op(5) + run_gc
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
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare_ck(6, 5, 5));
  e.handle_storage(now, &mut wal, &mut sb); // drive the append → its PrepareOk
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
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(6),
      OpNumber::with(5),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
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
  // forced/ordinary sync is armed with `target > commit_min` (below-ring: the strict R26-F1 discriminator;
  // `maybe_force_sync`: `target = floor` over a hole held at `commit_min < floor`; ordinary: `target >
  // self.op >= commit_min`). A LOCAL checkpoint advances `checkpoint_op` to at most `commit_min` (it
  // checkpoints at `target_op = commit_min`), so `checkpoint_op <= commit_min < sync.target` always holds
  // — a local checkpoint can NEVER make `sync.target <= checkpoint_op`. So a checkpoint-advance
  // satisfied-sync cancel would be dead code; Part A closes the wedge at the root (the arm site).
}

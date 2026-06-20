use super::{super::*, *};
use crate::{
  ClientId, Config, DoViewChange, Header, OpId, OpNumber, PreparedEntry, ReadOk, ReplicaId,
  Request, RequestNumber, SlotStatus, StartViewChange, View, VsrState, Wal, WalDone,
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
      false,
      0, // ordinary state-sync (not a recovery peer-fetch)
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
fn repeat_request_sync_from_one_requester_yields_one_serve_and_one_ship() {
  // `sync_serving` is keyed by REQUESTER: a solicit burst from one replica (here two back-to-back
  // RequestSyncs, e.g. a buggy/impatient peer re-soliciting before the first serve-read completes)
  // must NOT stack a second checkpoint read — the repeat only REFRESHES the echoed nonce, and the
  // single completion ships ONE SyncCheckpoint answering the LATEST solicitation. (A map keyed per
  // minted read id would stack N reads for N solicits, each completion shipping a full snapshot.)
  let (mut e, mut wal, mut sb) = donor_primary_at_checkpoint(2);
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
    Peer::Replica(ReplicaId::new(2)),
    solicit(0xAAAA),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    solicit(0xBBBB),
  );
  assert_eq!(
    e.sync_serving.len(),
    1,
    "one outstanding serve per requester — the repeat solicit must not stack a second read"
  );
  e.handle_storage(now, &mut wal, &mut sb); // the single serve-read completes
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
    Peer::Replica(ReplicaId::new(2)),
    solicit(0xCCCC),
  );
  e.handle_storage(now, &mut wal, &mut sb);
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
        0,
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
        0,
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
      false,
      0, // ordinary state-sync (not a recovery peer-fetch)
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
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
      true,
      0, // recovery peer-fetch
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
      false,
      0, // ordinary state-sync
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
  .unwrap();
  let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2, // head == checkpoint_op → empty tail; isolates the checkpoint path
    done: VecDeque::new(),
  };
  let mut e =
    Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut wal, &mut sb).expect_active();
  // Drive past the per-op retry budget so it escalates to a peer fetch (pumping the recover-retry
  // timer each round — the timer owns the read-retry budget).
  drive_recovery_scripted_sb(&mut e, &mut wal, &mut sb, now);
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
  let answer = answer.expect("the equal-checkpoint peer SERVES the recovery request");

  // Deliver the peer's SyncCheckpoint back to the recovering replica → it STAGES the re-persist (staying
  // Recovering); once the SyncRepersist root is durable it installs + flips to Normal at the synced point.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(answer),
  );
  // Drive the durable re-persist to completion: flush the scripted superblock each round so the two staged
  // writes (snapshot, then the root) surface and `on_sb_done` lands the root, completing recovery. (The
  // node stays Recovering until the root is durable — the install + flip-to-Normal defer to `on_sb_done`.)
  for _ in 0..16 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
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
  e.handle_storage(now, &mut wal, &mut sb); // drive the durable re-persist (TestSb synchronous)
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
  let mut e = Endpoint::new(cfg, genesis(3), 0, CountSm::default());
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
fn state_sync_view_change_before_the_sync_root_does_not_strand_the_committed_band() {
  // REGRESSION (the wedge). A laggard STAGES a SyncCheckpoint but a VIEW CHANGE fires
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
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut e = Endpoint::new(cfg, genesis(3), 0, CountSm::default());
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
  // canonical-log selection — that hazard is orthogonal to this test).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0,
    )),
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
      crate::Epoch::new(0),
      0,
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
  // THE CORE ASSERTION. The new primary did NOT install the synced state behind a stale checkpoint:
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
  // REGRESSION. The `on_sb_done` root-completion arm must route by whether THIS
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
  // REGRESSION (an adversarial schedule). A `Normal` PRIMARY that receives a valid `SyncCheckpoint` for an
  // outstanding sync must NOT apply it in place (that would reset commit_min to the checkpoint and
  // clear the commit pipeline while it stays primary → a wedge: `try_commit` can never advance past
  // the checkpoint, and a recovered/op-reset primary can REUSE committed op numbers — divergence).
  // Instead it STEPS DOWN: flags the deferred forfeit and drops the sync, unchanged. A
  // caught-up replica then leads.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 1_000).unwrap(); // huge interval: no checkpoint
  let mut e = Endpoint::new(cfg, genesis(3), 0, CountSm::default());
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
  .unwrap();
  let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let mut e =
    Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut wal, &mut sb).expect_active();
  drive_recovery_scripted_sb(&mut e, &mut wal, &mut sb, now);
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
    e.handle_storage(now, &mut wal, &mut sb);
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
  e.handle_storage(now, &mut wal, &mut sb);
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
      real_id,
      crate::Epoch::new(0),
      0, // matches checkpoint_id(stale_env), so the integrity gate PASSES
      ReplicaId::new(0),
      nonce,
      stale_env,
      Bytes::new(),
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
  e.handle_storage(now, &mut wal, &mut sb);
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
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      0xABCD,
      env,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
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
      crate::Epoch::new(0),
      0,
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
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env4,
      Bytes::new(),
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
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env2,
      Bytes::new(),
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
      crate::Epoch::new(0),
      0,
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
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
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

// ── Force-state-sync escalation ────────────────────────────────────────────────────────────────

#[test]
fn a_pruned_committed_hole_forces_a_state_sync() {
  // A Normal BACKUP (replica 1 of 3) holds a repair hole at op N=2 with a head ABOVE it (op=4),
  // where a QUORUM has checkpointed past N (so RequestPrepare is futile — the op is pruned on the
  // quorum). It must (a) clear the doomed hole, (b) emit a RequestSync (not just RequestPrepare),
  // (c) record a FORCED sync targeting the quorum checkpoint.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(1), 4).unwrap();
  let mut ep = Endpoint::new(cfg, genesis(3), 7, NoopSm);
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
  let mut ep = Endpoint::new(cfg, genesis(3), 7, NoopSm);
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
  let mut ep = Endpoint::new(cfg, genesis(3), 7, NoopSm);
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
  let mut ep = Endpoint::new(cfg, genesis(3), 7, NoopSm);
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
  let mut ep = Endpoint::new(cfg, genesis(3), 1, CountSm::default());
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
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
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
  let mut ep = Endpoint::new(cfg, genesis(3), 7, CountSm::default());
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
    primary_peer(),
    repair_prepare(0, 2, 4),
  );
  assert!(
    ep.has_repair_hole_for_test(2),
    "the hole stays OPEN until the repair-fill append is durable"
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
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      // a nonce that would have matched the cancelled forced sync (it is gone, so this is moot)
      7,
      env,
      Bytes::new(),
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
  // SAFETY NET (Part B — reaching `apply_sync` directly). Models the reordering where a
  // forced `SyncCheckpoint` for a target the applied frontier has ALREADY passed reaches `apply_sync`
  // (i.e. Part A's apply-loop cancel did not run between the arm and this delivery). The forced sync's
  // target (2) is `<= self.op` (so the upstream `<= self.op → drop` guard is relaxed for the forced
  // path) and `< commit_min` (4) — applying it would rewind the applied frontier. Part B DROPS it
  // gracefully (no panic, no rewind) instead of asserting; the LEGITIMATE forced sync is unaffected.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 1_000).unwrap();
  let mut ep = Endpoint::new(cfg, genesis(3), 7, CountSm::default());
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
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
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
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::new(cfg, genesis(3), 7, NoopSm);
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
  let mut ep = Endpoint::new(cfg, genesis(3), 7, NoopSm);
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
      crate::Epoch::new(0),
      0,
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
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      env,
      Bytes::new(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
  drop(e); // crash
  // Recover from the same wal/sb: the synced checkpoint is the durable root.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let mut recovered =
    Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut wal, &mut sb).expect_active();
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
  let mut e = Endpoint::new(
    Config::with_checkpoint_ops(1, MemberId::new(2), 2).unwrap(),
    genesis(3),
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
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
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
  let mut e = Endpoint::new(cfg, genesis(3), 7, CountSm::default());
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
      crate::Epoch::new(0),
      0,
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
  // forced/ordinary sync is armed with `target > commit_min` (below-ring: the strict discriminator;
  // `maybe_force_sync`: `target = floor` over a hole held at `commit_min < floor`; ordinary: `target >
  // self.op >= commit_min`). A LOCAL checkpoint advances `checkpoint_op` to at most `commit_min` (it
  // checkpoints at `target_op = commit_min`), so `checkpoint_op <= commit_min < sync.target` always holds
  // — a local checkpoint can NEVER make `sync.target <= checkpoint_op`. So a checkpoint-advance
  // satisfied-sync cancel would be dead code; Part A closes the wedge at the root (the arm site).
}

// ── Chunked state-sync transfer: the donor side ──

/// A Normal donor (replica 0 of 3) whose DURABLE checkpoint at `ckpt` carries a `snapshot_len`-byte
/// SM snapshot — sized by the caller so the chunked-path tests can exceed the one-frame budget. The
/// checkpoint is PLANTED (durable root + readable snapshot, with the endpoint state aligned) rather
/// than driven through the commit pipeline, so a test does not shuffle tens of MiB through prepares.
fn donor_with_planted_checkpoint(
  ckpt: u64,
  snapshot_len: usize,
) -> (Endpoint<CountSm>, TestWal, TestSb, Bytes, u128) {
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), ckpt).unwrap();
  let mut e = Endpoint::new(cfg, genesis(3), 0, CountSm::default());
  let env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(ckpt),
    &BTreeMap::new(),
    &std::vec![0xA5u8; snapshot_len],
  );
  let id = crate::checkpoint_id(&env);
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(ckpt),
    OpNumber::with(ckpt),
    id,
    std::vec::Vec::new(),
  )
  .unwrap();
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: Some((OpNumber::with(ckpt), env.clone())),
  };
  e.force_state_for_test(0, ckpt, ckpt, ckpt, &[]);
  (e, TestWal::default(), sb, env, id)
}

#[test]
fn over_frame_checkpoint_is_announced_and_chunks_reassemble_it() {
  // A donor whose envelope EXCEEDS the one-frame budget answers a RequestSync with a
  // SyncCheckpointMeta announce (never an oversized SyncCheckpoint), warms its serve cache from the
  // verified read, and then serves the whole envelope as cache-sliced chunks: a max-fill first chunk
  // landing exactly on the frame cap, a partial tail chunk, and the two reassembling bit-identically
  // to the envelope. A pull at/past the end is dropped (malformed offset).
  let big = crate::message::max_unchunked_snapshot_len() + 1024;
  let (mut e, mut wal, mut sb, env, id) = donor_with_planted_checkpoint(4, big);
  assert!(
    env.len() > crate::message::max_unchunked_snapshot_len(),
    "setup: the envelope exceeds the unchunked threshold"
  );
  let now = Instant::ZERO;
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
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // serve-read completes → announce
  let mut meta = None;
  let mut whole = false;
  while let Some(out) = e.poll_message() {
    match out.msg_ref() {
      Message::SyncCheckpointMeta(m) => meta = Some((out.to(), m.clone())),
      Message::SyncCheckpoint(_) => whole = true,
      _ => {}
    }
  }
  assert!(
    !whole,
    "an over-frame envelope is NEVER shipped as one SyncCheckpoint"
  );
  let (to, m) = meta.expect("the donor announces the over-frame checkpoint");
  assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(2))));
  assert_eq!(m.checkpoint_op(), OpNumber::with(4));
  assert_eq!(m.checkpoint_id(), id);
  assert_eq!(m.total_len(), env.len() as u64);
  assert_eq!(m.nonce(), 0xCAFE);
  assert!(
    e.sync_donating.is_some(),
    "the verified serve-read warmed the donor cache"
  );

  // Pull the whole envelope chunk by chunk from the warm cache (no further superblock read).
  let pull = |e: &mut Endpoint<CountSm>, wal: &mut TestWal, sb: &mut TestSb, offset: u64| {
    e.handle_message(
      now,
      wal,
      sb,
      Peer::Replica(ReplicaId::new(2)),
      Message::RequestSyncChunk(crate::RequestSyncChunk::new(
        View::new(),
        OpNumber::with(4),
        id,
        0,
        offset,
        ReplicaId::new(2),
        0xCAFE,
      )),
    );
    let mut chunk = None;
    while let Some(out) = e.poll_message() {
      if let Message::SyncChunk(c) = out.msg_ref() {
        chunk = Some(c.clone());
      }
    }
    chunk
  };
  let first = pull(&mut e, &mut wal, &mut sb, 0).expect("the first chunk is served");
  assert!(
    e.sync_serving.is_empty(),
    "a cache-hit chunk is served WITHOUT a serve-read (zero-copy slice)"
  );
  assert_eq!(first.bytes().len(), crate::message::SYNC_CHUNK_LEN);
  assert_eq!(
    Message::SyncChunk(first.clone()).encoded_len(),
    crate::message::MAX_FRAME_LEN as usize,
    "a max-fill chunk lands exactly on the frame cap"
  );
  assert_eq!(first.total_len(), env.len() as u64);
  let tail_offset = first.bytes().len() as u64;
  let tail = pull(&mut e, &mut wal, &mut sb, tail_offset).expect("the tail chunk is served");
  assert_eq!(tail.offset(), tail_offset);
  assert_eq!(
    tail.bytes().len() as u64,
    env.len() as u64 - tail_offset,
    "the tail chunk carries exactly the remainder"
  );
  let mut staged = std::vec::Vec::with_capacity(env.len());
  staged.extend_from_slice(first.bytes());
  staged.extend_from_slice(tail.bytes());
  assert_eq!(
    staged,
    env.as_ref(),
    "the chunks reassemble the envelope bit-identically"
  );
  assert_eq!(crate::checkpoint_id(&staged), id);

  // A malformed pull at/past the end is dropped silently.
  assert!(
    pull(&mut e, &mut wal, &mut sb, env.len() as u64).is_none(),
    "an offset at the envelope end is dropped"
  );
}

#[test]
fn donor_serves_pinned_old_checkpoint_from_cache_after_advancing() {
  // The keep-serving property: the donor cache deliberately SURVIVES the donor's own checkpoint
  // advance (committed content is immutable), so a receiver pinned mid-transfer to the OLD
  // checkpoint keeps pulling its chunks rather than restarting on every donor checkpoint.
  let (mut e, mut wal, mut sb, env, id) = donor_with_planted_checkpoint(4, 64);
  let now = Instant::ZERO;
  // Warm the cache via an ordinary serve (the envelope is small → ships whole AND warms the cache).
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
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  assert!(e.sync_donating.is_some(), "cache warm after the serve");
  // The donor's own frontier advances past the cached checkpoint (head/commit/checkpoint all at 8).
  e.force_state_for_test(0, 8, 8, 8, &[]);
  // A pull pinned to the OLD (4, id) checkpoint is still served from the cache.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSyncChunk(crate::RequestSyncChunk::new(
      View::new(),
      OpNumber::with(4),
      id,
      0,
      0,
      ReplicaId::new(2),
      0xCAFE,
    )),
  );
  let mut chunk = None;
  while let Some(out) = e.poll_message() {
    if let Message::SyncChunk(c) = out.msg_ref() {
      chunk = Some(c.clone());
    }
  }
  let c = chunk.expect("the pinned OLD checkpoint is still served after the donor advanced");
  assert_eq!(c.checkpoint_op(), OpNumber::with(4));
  assert_eq!(c.checkpoint_id(), id);
  assert_eq!(
    c.bytes(),
    env.as_ref(),
    "one small chunk carries the whole envelope"
  );
}

#[test]
fn cold_cache_chunk_request_rereads_and_ships() {
  // A donor that restarted mid-transfer has a COLD cache but still holds the pinned checkpoint as
  // its durable root: a chunk pull triggers a serve-read (ServeKind::Chunk), whose verified
  // completion warms the cache AND ships the requested chunk.
  let (mut e, mut wal, mut sb, env, id) = donor_with_planted_checkpoint(4, 64);
  let now = Instant::ZERO;
  assert!(e.sync_donating.is_none(), "setup: cold cache");
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSyncChunk(crate::RequestSyncChunk::new(
      View::new(),
      OpNumber::with(4),
      id,
      0,
      8,
      ReplicaId::new(2),
      0xF00D,
    )),
  );
  assert_eq!(
    e.sync_serving.len(),
    1,
    "a cold-cache pull submits ONE serve-read for the requester"
  );
  assert!(
    e.poll_message().is_none(),
    "nothing ships until the read completes"
  );
  e.handle_storage(now, &mut wal, &mut sb); // the read completes → verify + warm + ship
  let mut chunk = None;
  while let Some(out) = e.poll_message() {
    if let Message::SyncChunk(c) = out.msg_ref() {
      chunk = Some(c.clone());
    }
  }
  let c = chunk.expect("the cold-cache pull is answered after the re-read");
  assert_eq!(c.offset(), 8);
  assert_eq!(
    c.bytes(),
    &env.as_ref()[8..],
    "the chunk starts at the requested offset"
  );
  assert!(
    e.sync_donating.is_some(),
    "the verified re-read warmed the cache"
  );
  assert!(
    e.sync_serving.is_empty(),
    "the serve entry retired on completion"
  );
}

// ── Chunked state-sync transfer: the receiver pull loop ──

/// A `SyncCheckpointMeta` announcing the `(op, id)` envelope of `total` bytes from `donor`. Same-config
/// (epoch 0, empty membership) — the cross-epoch carry is exercised by its own dedicated test.
fn meta_of(op: u64, id: u128, total: usize, donor: u16, nonce: u64) -> Message {
  Message::SyncCheckpointMeta(crate::SyncCheckpointMeta::new(
    View::new(),
    OpNumber::with(op),
    id,
    crate::Epoch::new(0),
    0,
    total as u64,
    ReplicaId::new(donor),
    nonce,
    Bytes::new(),
  ))
}

/// A `SyncChunk` carrying `env[range]` of the `(op, id)` envelope from `donor`.
fn chunk_of(
  op: u64,
  id: u128,
  env: &Bytes,
  range: core::ops::Range<usize>,
  donor: u16,
  nonce: u64,
) -> Message {
  Message::SyncChunk(crate::SyncChunk::new(
    View::new(),
    OpNumber::with(op),
    id,
    0,
    env.len() as u64,
    range.start as u64,
    ReplicaId::new(donor),
    nonce,
    env.slice(range),
  ))
}

/// Drain the laggard's outgoing queue, returning the last `RequestSyncChunk` (destination, message).
fn drain_chunk_pull(e: &mut Endpoint<CountSm>) -> Option<(Recipient, crate::RequestSyncChunk)> {
  let mut pull = None;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSyncChunk(r) = out.msg_ref() {
      pull = Some((out.to(), *r));
    }
  }
  pull
}

#[test]
fn chunked_transfer_assembles_in_order_and_installs_via_the_whole_message_path() {
  // The receiver pull loop end to end: an announce pins the transfer and pulls offset 0; each
  // accepted chunk extends the staged prefix and pulls the new frontier (stop-and-wait,
  // self-clocking); a DUPLICATE or REORDERED chunk is inert (its offset is not the frontier); the
  // final chunk's verified assembly re-enters the ordinary SyncCheckpoint path and installs with
  // the full durable-root barrier, exactly as a single-frame envelope would.
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
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // The announce pins the transfer and pulls offset 0 from the announcing donor.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    meta_of(4, id, env.len(), 0, nonce),
  );
  let (to, pull) = drain_chunk_pull(&mut e).expect("the announce triggers the first pull");
  assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(0))));
  assert_eq!(pull.offset(), 0);
  assert_eq!(pull.checkpoint_op(), OpNumber::with(4));
  assert_eq!(pull.checkpoint_id(), id);
  assert_eq!(pull.nonce(), nonce);
  // First chunk (an arbitrary split — the receiver accepts any non-empty in-order size).
  let split = 10usize.min(env.len() - 1);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, 0..split, 0, nonce),
  );
  let (_, pull) = drain_chunk_pull(&mut e).expect("an accepted chunk pulls the new frontier");
  assert_eq!(pull.offset(), split as u64);
  // A DUPLICATE of the first chunk is inert: offset 0 is no longer the frontier.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, 0..split, 0, nonce),
  );
  assert!(
    drain_chunk_pull(&mut e).is_none(),
    "a duplicate chunk neither extends the staged prefix nor re-pulls"
  );
  // A REORDERED (future-offset) chunk is likewise inert.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, (split + 1)..env.len(), 0, nonce),
  );
  assert!(
    drain_chunk_pull(&mut e).is_none(),
    "an out-of-order chunk is dropped (the ARQ re-pulls the exact frontier)"
  );
  assert_eq!(
    e.sync_transfer.as_ref().map(|t| t.staged.len()),
    Some(split),
    "the staged prefix is exactly the in-order bytes"
  );
  // The final chunk completes the assembly → verified → re-enters the SyncCheckpoint path → STAGE.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, split..env.len(), 0, nonce),
  );
  assert_eq!(
    e.sync_chunk_transfers_completed(),
    1,
    "the chunked transfer completed (assembled + verified)"
  );
  assert!(
    e.sync_transfer.is_none(),
    "the transfer is retired at completion"
  );
  e.handle_storage(now, &mut wal, &mut sb); // the two-write persist → durable root → install
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(
    e.state_machine_ref().applied().len(),
    4,
    "the SM restored from the assembled snapshot"
  );
  assert_eq!(e.state_syncs_applied(), 1, "the sync fully applied");
  assert_eq!(
    e.sync_target_for_test(),
    None,
    "the sync handshake retired on the durable root"
  );
}

#[test]
fn the_chunked_reassembly_carries_the_same_epoch_and_membership_as_the_single_frame_form() {
  // ANTI-DRIFT GUARD: the single-frame `SyncCheckpoint` and the chunked `SyncCheckpointMeta` MUST
  // carry the IDENTICAL cross-epoch header `(epoch, membership)`, so the verified chunk reassembly
  // rebuilds a `SyncCheckpoint` byte-equal in those fields to a one-frame arrival. Were the two to
  // drift again (the chunked path dropping the membership, as it once did with an `Epoch::new(0)` +
  // empty placeholder), a cross-epoch laggard whose post-swap snapshot is over-frame would never
  // install the successor configuration and stay stranded. This pins the two headers EQUAL at the
  // message level AND drives the chunked path end to end to assert the successor genuinely installs.

  // A successor chained off genesis (config_id 0) exactly as a real swap derives it — its epoch is E+1
  // and its config_id hash-chains from the predecessor, so `to_membership_verified` accepts it.
  let predecessor = genesis(3);
  let successor = predecessor
    .apply_delta(&crate::SingleVoterDelta::AddVoter(MemberId::new(3)))
    .expect("AddVoter on the 3-voter genesis is valid");
  assert_eq!(
    successor.epoch(),
    crate::Epoch::new(1),
    "the successor is E+1"
  );
  assert_ne!(
    successor.config_id(),
    predecessor.config_id(),
    "the successor chained a fresh config_id"
  );
  // The canonical wire body the donor serves — IDENTICAL bytes on both the whole and chunked paths.
  let membership =
    crate::message::ReconfigurePayload::from_membership(&successor, predecessor.config_id())
      .encode_body();

  // The same checkpoint expressed BOTH ways: the single-frame `SyncCheckpoint` and the chunked
  // announce. The donor builds the two from the SAME `self.membership`, so the header fields the
  // announce carries must equal the whole form's. (A synthetic envelope is fine here — this layer
  // compares only the carried `(epoch, membership)`, which never decode the snapshot.)
  let synth_env = Bytes::from(std::vec![0xC3u8; 64]);
  let synth_id = crate::checkpoint_id(&synth_env);
  let single_frame = crate::SyncCheckpoint::new(
    View::new(),
    OpNumber::with(4),
    synth_id,
    successor.epoch(),
    successor.config_id(),
    ReplicaId::new(0),
    0xCAFE,
    synth_env.clone(),
    membership.clone(),
  );
  let announce = crate::SyncCheckpointMeta::new(
    View::new(),
    OpNumber::with(4),
    synth_id,
    successor.epoch(),
    successor.config_id(),
    synth_env.len() as u64,
    ReplicaId::new(0),
    0xCAFE,
    membership.clone(),
  );
  // THE DRIFT GUARD: the announce's cross-epoch header equals the single-frame form's, field for field.
  assert_eq!(
    announce.epoch(),
    single_frame.epoch(),
    "the chunked announce carries the SAME epoch as the single-frame SyncCheckpoint"
  );
  assert_eq!(
    announce.membership(),
    single_frame.membership(),
    "the chunked announce carries the SAME membership as the single-frame SyncCheckpoint"
  );

  // End to end: a laggard at the PREDECESSOR config pins a cross-epoch announce of a REAL (decodable)
  // checkpoint envelope, pulls it chunk by chunk, and the verified reassembly re-enters the
  // SyncCheckpoint path — which must install the SUCCESSOR exactly as a single-frame cross-epoch
  // arrival would (the membership is carried through reassembly, not dropped to an empty placeholder).
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  assert_eq!(
    e.membership.config_id(),
    predecessor.config_id(),
    "the laggard starts at the predecessor config"
  );
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
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // Pin the cross-epoch announce (re-stamped with the laggard's live nonce) and pull from 0.
  let cross_meta = crate::SyncCheckpointMeta::new(
    View::new(),
    OpNumber::with(4),
    id,
    successor.epoch(),
    successor.config_id(),
    env.len() as u64,
    ReplicaId::new(0),
    nonce,
    membership.clone(),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpointMeta(cross_meta),
  );
  let (_, pull) = drain_chunk_pull(&mut e).expect("the cross-epoch announce pins + pulls");
  assert_eq!(pull.offset(), 0);
  // The chunks carry the successor's config_id (the agnostic field the chunk also stamps).
  let split = 24usize;
  let chunk = |range: core::ops::Range<usize>| {
    Message::SyncChunk(crate::SyncChunk::new(
      View::new(),
      OpNumber::with(4),
      id,
      successor.config_id(),
      env.len() as u64,
      range.start as u64,
      ReplicaId::new(0),
      nonce,
      env.slice(range),
    ))
  };
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), chunk(0..split));
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk(split..env.len()),
  );
  assert_eq!(
    e.sync_chunk_transfers_completed(),
    1,
    "the cross-epoch chunked transfer assembled + verified"
  );
  e.handle_storage(now, &mut wal, &mut sb); // the two-write persist → durable root → install
  // THE PAYOFF: the reassembled checkpoint installed the SUCCESSOR config (it was NOT dropped to an
  // empty/placeholder membership) — the laggard converged across the epoch boundary via the chunked path.
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the cross-epoch sync fully applied via the chunked path"
  );
  assert_eq!(
    e.membership.epoch(),
    successor.epoch(),
    "the chunked reassembly installed the SUCCESSOR epoch (the membership was carried, not lost)"
  );
  assert_eq!(
    e.membership.config_id(),
    successor.config_id(),
    "the chunked reassembly installed the SUCCESSOR config_id — identical to a single-frame install"
  );
  assert_eq!(
    e.membership, successor,
    "the laggard installed the exact successor configuration the over-frame snapshot reflected"
  );
}

/// Capture the `SyncCheckpoint` a donor ships in answer to a `RequestSync` from replica 2 (draining
/// the rest of the outbound queue).
fn serve_request_sync(
  e: &mut Endpoint<CountSm>,
  wal: &mut TestWal,
  sb: &mut TestSb,
) -> crate::SyncCheckpoint {
  let now = Instant::ZERO;
  while e.poll_message().is_some() {} // drain warm-up / membership-change emissions
  e.handle_message(
    now,
    wal,
    sb,
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
  e.handle_storage(now, wal, sb); // the checkpoint read completes → ship SyncCheckpoint
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
  let shipped = serve_request_sync(&mut e, &mut wal, &mut sb);
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
  let shipped = serve_request_sync(&mut e, &mut wal, &mut sb);
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
  e.handle_storage(now, &mut wal, &mut sb); // the two-write persist → durable root → install
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
  e2.handle_message(
    now,
    &mut wal2,
    &mut sb2,
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
  e2.handle_storage(now, &mut wal2, &mut sb2);
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
  e.handle_storage(now, &mut wal, &mut sb); // two-write persist → durable root → install

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
  e.handle_storage(now, &mut wal, &mut sb); // the serve-read completes → ship SyncCheckpoint
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
  let recovered = match Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut wal, &mut sb)
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
  e.handle_storage(now, &mut wal, &mut sb); // nothing was staged → no install drives here

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
  let mut e = Endpoint::new(cfg, genesis(3), 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Append ops 1..=N with commit 0 (the laggard appended the reconfigure op N but never saw its commit).
  for op in 1..=n {
    e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare_ck(op, 0, 0));
    e.handle_storage(now, &mut wal, &mut sb);
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
  let env = Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(n), &BTreeMap::new(), &snap);
  let id = crate::checkpoint_id(&env);
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor, predecessor.config_id())
      .encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
    e.handle_storage(now, &mut wal, &mut sb);
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
  let mut e = Endpoint::new(cfg, genesis(3), 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
  let below_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(below), &BTreeMap::new(), &below_snap);
  let below_id = crate::checkpoint_id(&below_env);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
    e.handle_storage(now, &mut wal, &mut sb);
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
  let cross_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(n), &BTreeMap::new(), &cross_snap);
  let cross_id = crate::checkpoint_id(&cross_env);
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor, predecessor.config_id())
      .encode_body();
  let nonce2 = e.sync_nonce_for_test(); // the still-armed sync's nonce
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
    e.handle_storage(now, &mut wal, &mut sb);
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
  let mut e = Endpoint::new(cfg, genesis(3), 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
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
    &BTreeMap::new(),
    &CountSm::default().snapshot(),
  );
  let below_id = crate::checkpoint_id(&below_env);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
    e.handle_storage(now, &mut wal, &mut sb);
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
    &BTreeMap::new(),
    &CountSm::default().snapshot(),
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
    e.handle_storage(now, &mut wal, &mut sb);
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
  .expect("a SwapEpoch root carrying config_install_op above its checkpoint is valid");
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
  let mut e =
    Endpoint::recover(cfg, genesis_mem, 9, CountSm::default(), &mut wal, &mut sb).expect_active();
  // Drive the recovery storage to completion (the checkpoint read restores the SM + sessions).
  let now = Instant::ZERO;
  for _ in 0..8 {
    e.handle_storage(now, &mut wal, &mut sb);
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
fn overflowing_or_empty_chunk_aborts_the_transfer_but_keeps_the_sync_armed() {
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
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // Announce a LYING total_len SMALLER than the envelope, so an honest-size chunk overflows it.
  let lying_total = env.len() - 4;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    meta_of(4, id, lying_total, 0, nonce),
  );
  assert!(e.sync_transfer.is_some(), "the transfer pinned");
  while e.poll_message().is_some() {}
  // A chunk past the announced end: offset 0 == frontier, but 0 + env.len() > lying_total → abort.
  let mut over = crate::SyncChunk::new(
    View::new(),
    OpNumber::with(4),
    id,
    0,
    lying_total as u64,
    0,
    ReplicaId::new(0),
    nonce,
    env.clone(),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncChunk(over.clone()),
  );
  assert!(
    e.sync_transfer.is_none(),
    "an overflowing chunk ABORTS the transfer (staged bytes freed)"
  );
  assert!(
    e.sync_target_for_test().is_some(),
    "the sync stays armed — the solicit timer re-announces"
  );
  // An EMPTY chunk (no progress) aborts the same way on a fresh pin.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    meta_of(4, id, lying_total, 0, nonce),
  );
  assert!(e.sync_transfer.is_some(), "re-pinned after the abort");
  while e.poll_message().is_some() {}
  over = crate::SyncChunk::new(
    View::new(),
    OpNumber::with(4),
    id,
    0,
    lying_total as u64,
    0,
    ReplicaId::new(0),
    nonce,
    Bytes::new(),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncChunk(over),
  );
  assert!(
    e.sync_transfer.is_none(),
    "an empty chunk (no progress) aborts the transfer"
  );
  assert_eq!(e.sync_chunk_transfers_completed(), 0);
  assert_eq!(e.state_syncs_applied(), 0, "nothing installed");
}

#[test]
fn oversized_meta_announce_is_ignored_and_the_sync_stays_armed() {
  // `SyncCheckpointMeta.total_len` is a wire-supplied CLAIM: a buggy donor can announce any length
  // in one small frame, and the receiver would size its staging from it before any chunk or hash
  // evidence exists. An announce above the configured envelope cap must be ignored outright — no
  // transfer pinned (so nothing is ever sized from the claim), no pull, no panic — with the
  // solicitation left armed so a sane donor's next announce proceeds normally.
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
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  // A `u64::MAX` claim (the most hostile shape; on a 32-bit target the same gates also reject it
  // as unrepresentable before anything is sized from it).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpointMeta(crate::SyncCheckpointMeta::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      u64::MAX,
      ReplicaId::new(0),
      nonce,
      Bytes::new(),
    )),
  );
  assert!(e.sync_transfer.is_none(), "the claim is never pinned");
  assert!(
    drain_chunk_pull(&mut e).is_none(),
    "no pull is issued for an inadmissible announce"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(4),
    "the sync stays armed for another donor"
  );
  // A claim just over the cap is rejected by the same admission gate.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpointMeta(crate::SyncCheckpointMeta::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      crate::MAX_SYNC_ENVELOPE_LEN + 1,
      ReplicaId::new(0),
      nonce,
      Bytes::new(),
    )),
  );
  assert!(e.sync_transfer.is_none(), "an over-cap claim is ignored");
  assert_eq!(e.sync_target_for_test(), Some(4), "still armed");
  // A subsequent IN-BOUNDS announce from another donor pins and pulls normally.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    meta_of(4, id, env.len(), 2, nonce),
  );
  let (to, pull) = drain_chunk_pull(&mut e).expect("a sane announce proceeds");
  assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(2))));
  assert_eq!(pull.offset(), 0);
  assert_eq!(
    e.sync_transfer.as_ref().map(|t| t.total_len),
    Some(env.len() as u64),
    "the pinned transfer carries the sane announce's length"
  );
}

#[test]
fn oversized_meta_announce_never_displaces_a_pinned_transfer() {
  // An inadmissible announce for a STRICTLY NEWER checkpoint (the shape that would otherwise
  // supersede the live pin) must be ignored BEFORE the supersede logic: the live pin and its
  // staged prefix survive, and the in-flight transfer still completes and installs.
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
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    meta_of(4, id, env.len(), 0, nonce),
  );
  let split = 10usize.min(env.len() - 1);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, 0..split, 0, nonce),
  );
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpointMeta(crate::SyncCheckpointMeta::new(
      View::new(),
      OpNumber::with(8),
      0xBAD,
      crate::Epoch::new(0),
      0,
      u64::MAX,
      ReplicaId::new(0),
      nonce,
      Bytes::new(),
    )),
  );
  let t = e.sync_transfer.as_ref().expect("the live pin survives");
  assert_eq!(t.checkpoint_op, OpNumber::with(4), "the pin is unchanged");
  assert_eq!(t.staged.len(), split, "the staged prefix is kept");
  assert!(
    drain_chunk_pull(&mut e).is_none(),
    "the bogus announce drives no pull"
  );
  // The pinned transfer still completes and installs through the whole-message path.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, split..env.len(), 0, nonce),
  );
  assert_eq!(e.sync_chunk_transfers_completed(), 1);
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(
    e.state_syncs_applied(),
    1,
    "the survived transfer installed"
  );
}

#[test]
fn unallocatable_meta_announce_is_ignored_and_the_sync_stays_armed() {
  // The fallible-reservation backstop behind the admission cap: with the cap raised to `u64::MAX`,
  // a `u64::MAX` claim passes admission and reaches the staging reservation, which fails
  // deterministically (`Vec` capacity is bounded by `isize::MAX` bytes) — the announce is dropped
  // with nothing pinned and the sync stays armed. (On a 32-bit target the representability gate
  // rejects the same claim earlier, with the identical observable outcome.)
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let mut e = Endpoint::new(
    Config::with_checkpoint_ops(1, MemberId::new(1), 2)
      .unwrap()
      .with_max_sync_envelope_len(u64::MAX)
      .unwrap(),
    genesis(3),
    0,
    CountSm::default(),
  );
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
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
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncCheckpointMeta(crate::SyncCheckpointMeta::new(
      View::new(),
      OpNumber::with(4),
      id,
      crate::Epoch::new(0),
      0,
      u64::MAX,
      ReplicaId::new(0),
      nonce,
      Bytes::new(),
    )),
  );
  assert!(
    e.sync_transfer.is_none(),
    "a refused reservation adopts nothing"
  );
  assert!(drain_chunk_pull(&mut e).is_none(), "no pull is issued");
  assert_eq!(e.sync_target_for_test(), Some(4), "the sync stays armed");
  // A sane announce then proceeds normally under the same (huge) cap.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    meta_of(4, id, env.len(), 0, nonce),
  );
  let (_, pull) = drain_chunk_pull(&mut e).expect("a sane announce proceeds");
  assert_eq!(pull.offset(), 0);
}

#[test]
fn assembled_envelope_with_a_mismatched_hash_is_dropped_and_the_sync_resolicits() {
  // Garbage chunks that fill the announced total but do not hash to the pinned content id must be
  // dropped at assembly — nothing reaches the install path; the sync stays armed to re-announce.
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
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    meta_of(4, id, env.len(), 0, nonce),
  );
  while e.poll_message().is_some() {}
  // One full-length chunk of WRONG bytes (right total, wrong content).
  let garbage = Bytes::from(std::vec![0xEEu8; env.len()]);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::SyncChunk(crate::SyncChunk::new(
      View::new(),
      OpNumber::with(4),
      id,
      0,
      env.len() as u64,
      0,
      ReplicaId::new(0),
      nonce,
      garbage,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(
    e.sync_transfer.is_none(),
    "the mismatched assembly dropped the transfer"
  );
  assert_eq!(
    e.sync_chunk_transfers_completed(),
    0,
    "a mismatched assembly is NOT a completed transfer"
  );
  assert_eq!(e.checkpoint_op(), OpNumber::with(0), "nothing installed");
  assert_eq!(e.state_machine_ref().applied().len(), 0, "SM untouched");
  assert!(
    e.sync_target_for_test().is_some(),
    "the sync stays armed — re-solicit finds an honest donor"
  );
}

#[test]
fn donor_failover_re_pins_the_donor_and_keeps_the_staged_prefix() {
  // Chunks of the pinned content are interchangeable across donors (the id pins the bytes): a fresh
  // announce of the SAME (op, id) from a DIFFERENT donor re-pins only the donor — the staged prefix
  // is kept and the next pull resumes at the same frontier, addressed to the new donor.
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
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    meta_of(4, id, env.len(), 0, nonce),
  );
  while e.poll_message().is_some() {}
  let split = 10usize.min(env.len() - 1);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, 0..split, 0, nonce),
  );
  while e.poll_message().is_some() {}
  assert_eq!(e.sync_transfer_donor(), Some(0), "pinned to donor 0");
  // Donor 0 dies; the re-broadcast RequestSync is answered by donor 2's announce of the SAME content.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    meta_of(4, id, env.len(), 2, nonce),
  );
  let (to, pull) = drain_chunk_pull(&mut e).expect("the failover announce resumes the pull");
  assert_eq!(
    to,
    Recipient::To(Peer::Replica(ReplicaId::new(2))),
    "the next pull is addressed to the NEW donor"
  );
  assert_eq!(
    pull.offset(),
    split as u64,
    "the staged prefix survived the failover — the pull resumes at the frontier"
  );
  assert_eq!(e.sync_transfer_donor(), Some(2));
  // The new donor finishes the transfer; it installs normally.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    chunk_of(4, id, &env, split..env.len(), 2, nonce),
  );
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.checkpoint_op(), OpNumber::with(4));
  assert_eq!(e.sync_chunk_transfers_completed(), 1);
}

#[test]
fn ordinary_transfer_completes_below_a_target_raised_mid_transfer() {
  // The ordinary target is a freshness FLOOR: a target raised while chunks are in flight (the
  // cluster checkpointed again) must NOT discard the pinned transfer — at completion the assembled
  // envelope still passes every SAFETY gate and installs (strict progress); the next trigger then
  // chases the newer checkpoint. Without this, a sustained checkpoint cadence could outrun every
  // transfer and the laggard would restart forever.
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
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    meta_of(4, id, env.len(), 0, nonce),
  );
  while e.poll_message().is_some() {}
  let split = 10usize.min(env.len() - 1);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, 0..split, 0, nonce),
  );
  while e.poll_message().is_some() {}
  // Mid-transfer the cluster checkpoints again: the target raises 4 → 9 (ordinary raise).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(0),
      OpNumber::with(9),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(9),
    "the ordinary target raised mid-transfer"
  );
  assert!(
    e.sync_transfer.is_some(),
    "the ordinary raise does NOT abort the pinned transfer"
  );
  while e.poll_message().is_some() {}
  // Complete the transfer pinned at op 4 — BELOW the raised target.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, split..env.len(), 0, nonce),
  );
  assert_eq!(e.sync_chunk_transfers_completed(), 1);
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(4),
    "the assembled transfer INSTALLED below the raised freshness floor (strict progress)"
  );
  assert_eq!(e.state_syncs_applied(), 1);
  assert_eq!(
    e.sync_target_for_test(),
    None,
    "the handshake retired; the next Commit re-fires the trigger toward 9"
  );
}

#[test]
fn forced_target_raise_aborts_the_pinned_transfer() {
  // A FORCED target is LOAD-BEARING (repair holes at/below it were cleared against a snapshot
  // at/above it), so raising it past the pinned op invalidates the transfer: the pin is dropped at
  // the raise (no wasted round trips), the strict `>= target` gate stays, and the sync re-announces
  // toward the new floor. Late chunks of the dropped pin are inert.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(4);
  let (env, id) = donor_envelope(&dsb);
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.arm_forced_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    meta_of(4, id, env.len(), 0, nonce),
  );
  assert!(e.sync_transfer.is_some(), "the forced transfer pinned at 4");
  while e.poll_message().is_some() {}
  let split = 10usize.min(env.len() - 1);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, 0..split, 0, nonce),
  );
  while e.poll_message().is_some() {}
  // The forced target raises past the pin (a higher cluster checkpoint while still forced).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(0),
      OpNumber::with(9),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    e.sync_is_forced_for_test(),
    "the raise preserved forced-ness"
  );
  assert_eq!(e.sync_target_for_test(), Some(9));
  assert!(
    e.sync_transfer.is_none(),
    "the forced raise ABORTS the transfer pinned below the new target"
  );
  // A late chunk of the dropped pin is inert.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, split..env.len(), 0, nonce),
  );
  assert_eq!(e.sync_chunk_transfers_completed(), 0);
  assert_eq!(e.state_syncs_applied(), 0);
}

#[test]
fn a_primary_does_not_start_a_chunked_transfer_it_steps_down_instead() {
  // The apply-site step-down, moved to transfer START: a primary that receives an announce for a
  // sync it could never apply in place must not burn a whole transfer pulling chunks it will
  // discard — it abdicates immediately (deferred forfeit), drops the sync, and pulls nothing.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 1_000).unwrap();
  let mut e = Endpoint::new(cfg, genesis(3), 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
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
    e.handle_storage(now, &mut wal, &mut sb);
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
  while e.poll_message().is_some() {}
  e.arm_forced_sync_for_test(6);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    meta_of(6, 0xFEED, 1024, 1, nonce),
  );
  assert!(
    e.pending_forfeit_for_test(),
    "the primary flagged the deferred forfeit at transfer START"
  );
  assert_eq!(e.sync_target_for_test(), None, "the sync was dropped");
  assert!(e.sync_transfer.is_none(), "no transfer was pinned");
  let mut pulled = false;
  while let Some(out) = e.poll_message() {
    pulled |= out.msg_ref().is_request_sync_chunk();
  }
  assert!(!pulled, "the stepping-down primary pulls NO chunks");
}

#[test]
fn recovery_peer_fetch_converges_over_a_chunked_transfer() {
  // The Recovering ingress exception extends to the chunked form of the peer-checkpoint answer: a
  // replica whose own snapshot is unreadable accepts the announce + chunks while
  // `awaiting_peer_checkpoint`, re-pulls on the recover-retry cadence, and the assembled envelope
  // re-enters `on_recover_sync_checkpoint` — converging to Normal exactly as a whole-message answer.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let now = Instant::ZERO;
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
    head: 2,
    done: VecDeque::new(),
  };
  let mut e =
    Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut wal, &mut sb).expect_active();
  // Drive to the peer-fetch escalation by pumping the recover-retry timer (its sole retry owner) each
  // round on a local advancing clock. Inlined rather than via `drive_recovery_scripted_sb` so the final
  // advanced clock stays in scope: the ARQ assertion below fires the SAME timer one retransmit later, so
  // it must advance PAST the deadline the escalation drive left armed.
  let mut now = now;
  for _ in 0..(RECOVER_READ_RETRIES as usize + 8) {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
    if !e.status().is_recovering() && !e.status().is_recovering_head() {
      break;
    }
    if let Some(deadline) = e.poll_timeout() {
      now = deadline;
      e.handle_timeout(now, &mut wal, &mut sb);
    }
  }
  assert_eq!(e.status(), Status::Recovering);
  assert!(e.awaiting_peer_checkpoint_for_test());
  let mut req = None;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSync(r) = out.msg_ref() {
      req = Some(*r);
    }
  }
  let req = req.expect("the escalation solicited");
  // The donor's checkpoint at the SAME op (2), announced chunked.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(2);
  let (env, id) = donor_envelope(&dsb);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    meta_of(2, id, env.len(), 0, req.nonce()),
  );
  let (to, pull) = drain_chunk_pull(&mut e).expect("the recovering replica pulls chunk 0");
  assert_eq!(to, Recipient::To(Peer::Replica(ReplicaId::new(0))));
  assert_eq!(pull.offset(), 0);
  // The recover-retry cadence is the ARQ here: firing it re-sends the SAME pull (the answer was lost).
  let later = now + RECOVER_READ_RETRANSMIT;
  e.handle_timeout(later, &mut wal, &mut sb);
  let (_, repull) = drain_chunk_pull(&mut e).expect("recover_retry re-drives the pull");
  assert_eq!(repull.offset(), 0, "the ARQ re-pulls the exact frontier");
  // Deliver the envelope in two chunks; the assembly completes recovery.
  let split = 10usize.min(env.len() - 1);
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    chunk_of(2, id, &env, 0..split, 0, req.nonce()),
  );
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    chunk_of(2, id, &env, split..env.len(), 0, req.nonce()),
  );
  sb.flush();
  e.handle_storage(later, &mut wal, &mut sb);
  sb.flush();
  e.handle_storage(later, &mut wal, &mut sb);
  assert_eq!(
    e.status(),
    Status::Normal,
    "the recovering replica converged via the chunked peer fetch"
  );
  assert_eq!(e.checkpoint_op(), OpNumber::with(2));
  assert!(!e.awaiting_peer_checkpoint_for_test());
  assert_eq!(e.sync_chunk_transfers_completed(), 1);
  assert_eq!(
    e.state_machine_ref().applied().len(),
    2,
    "the SM restored from the assembled snapshot"
  );
}

#[test]
fn recovery_peer_fetch_ignores_an_oversized_meta_announce() {
  // The Recovering peer-fetch ingress dispatches into the SAME `on_sync_checkpoint_meta`, so its
  // announces pass the SAME admission gates: an over-cap claim is ignored (no pin, no pull, still
  // Recovering + awaiting, sync armed), and a sane announce then proceeds.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let now = Instant::ZERO;
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
    head: 2,
    done: VecDeque::new(),
  };
  let mut e =
    Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut wal, &mut sb).expect_active();
  drive_recovery_scripted_sb(&mut e, &mut wal, &mut sb, now);
  assert_eq!(e.status(), Status::Recovering);
  assert!(e.awaiting_peer_checkpoint_for_test());
  let mut req = None;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSync(r) = out.msg_ref() {
      req = Some(*r);
    }
  }
  let req = req.expect("the escalation solicited");
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpointMeta(crate::SyncCheckpointMeta::new(
      View::new(),
      OpNumber::with(2),
      0xFEED,
      crate::Epoch::new(0),
      0,
      u64::MAX,
      ReplicaId::new(0),
      req.nonce(),
      Bytes::new(),
    )),
  );
  assert!(e.sync_transfer.is_none(), "the claim is never pinned");
  assert!(drain_chunk_pull(&mut e).is_none(), "no pull is issued");
  assert_eq!(e.status(), Status::Recovering, "still recovering");
  assert!(e.awaiting_peer_checkpoint_for_test(), "still awaiting");
  assert!(e.sync_target_for_test().is_some(), "the fetch stays armed");
  // A sane announce of the donor's real envelope then pins and pulls normally.
  let (_donor, _dwal, dsb) = donor_primary_at_checkpoint(2);
  let (env, id) = donor_envelope(&dsb);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    meta_of(2, id, env.len(), 0, req.nonce()),
  );
  let (_, pull) = drain_chunk_pull(&mut e).expect("a sane announce proceeds");
  assert_eq!(pull.offset(), 0);
}

#[test]
fn sync_solicit_timer_re_pulls_the_frontier_and_re_broadcasts() {
  // The stop-and-wait ARQ: on the solicit cadence with a transfer pinned, the receiver re-sends the
  // one outstanding chunk pull (idempotent — the exact staged frontier) AND re-broadcasts
  // RequestSync (dead-donor replacement).
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
      crate::Epoch::new(0),
      0,
    )),
  );
  let nonce = captured_sync_nonce(&mut e);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    meta_of(4, id, env.len(), 0, nonce),
  );
  let split = 10usize.min(env.len() - 1);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    chunk_of(4, id, &env, 0..split, 0, nonce),
  );
  while e.poll_message().is_some() {}
  // Fire the solicit deadline: both the frontier re-pull and the RequestSync re-broadcast go out.
  let later = now + SYNC_SOLICIT + core::time::Duration::from_millis(1);
  e.handle_timeout(later, &mut wal, &mut sb);
  let (mut saw_pull_at_frontier, mut saw_resolicit) = (false, false);
  while let Some(out) = e.poll_message() {
    match out.msg_ref() {
      Message::RequestSyncChunk(r) => saw_pull_at_frontier |= r.offset() == split as u64,
      Message::RequestSync(_) => saw_resolicit = true,
      _ => {}
    }
  }
  assert!(
    saw_pull_at_frontier,
    "the ARQ re-pulls the exact staged frontier"
  );
  assert!(
    saw_resolicit,
    "the cadence still re-broadcasts RequestSync for donor replacement"
  );
}

#[test]
fn stale_pinned_chunk_request_yields_a_fresh_offer() {
  // The donor-pruned-mid-transfer recovery: a pull pinned to a checkpoint BELOW the donor's durable
  // one (and not cached) is answered with a FRESH OFFER of the donor's current checkpoint — the
  // receiver aborts its stale pin and re-pins to the newer announce (or installs the whole message).
  let (mut e, mut wal, mut sb, _env, _id) = donor_with_planted_checkpoint(4, 64);
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSyncChunk(crate::RequestSyncChunk::new(
      View::new(),
      OpNumber::with(2), // below the donor's checkpoint (4)
      0xDEAD_BEEF,
      0, // content the donor no longer holds
      0,
      ReplicaId::new(2),
      0xF00D,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // the offer-read completes
  let mut offered = None;
  while let Some(out) = e.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      offered = Some(s.clone());
    }
  }
  let s = offered.expect("a stale pin is answered with a fresh offer of the CURRENT checkpoint");
  assert_eq!(s.checkpoint_op(), OpNumber::with(4));
  assert_eq!(s.nonce(), 0xF00D);
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
  e.handle_storage(now, &mut wal, &mut sb); // drive the durable re-persist → install

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
  e.handle_storage(now, &mut wal, &mut sb); // drive the durable re-persist → install

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
  e2.arm_cross_epoch_sync_for_test(1000);
  e2.handle_message(
    now,
    &mut wal2,
    &mut sb2,
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
fn a_pinned_chunked_cross_epoch_transfer_is_not_cancelled_by_same_epoch_traffic() {
  // R8 SCOPE GUARD: a Normal crossing that accepted a `SyncCheckpointMeta` and PINNED a `sync_transfer` (a
  // chunked transfer mid-assembly) is Normal + `pending_install` None + not awaiting — tracked ONLY by the
  // transfer. It is a GENUINE crossing in progress: cancelling its sync would drop the pinned transfer so
  // its `SyncChunk`s strand with no sync left to retry. The cancel is scoped to PRE-ANSWER crossings
  // (`sync_transfer` None), so a pinned chunked transfer SURVIVES a delayed same-epoch message.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  e.arm_cross_epoch_sync_for_test(9);
  e.sync_transfer = Some(SyncTransfer {
    checkpoint_op: OpNumber::with(9),
    checkpoint_id: 0,
    total_len: 0,
    epoch: crate::Epoch::new(0),
    config_id: 0,
    membership: Bytes::new(),
    donor: ReplicaId::new(0),
    staged: std::vec::Vec::new(),
  });
  assert!(
    e.status().is_normal() && e.pending_install.is_none() && !e.awaiting_peer_checkpoint_for_test(),
    "setup: a NORMAL pinned chunked transfer — only the sync_transfer arm of the guard excludes the cancel"
  );
  let nonce_before = e.sync_nonce_for_test();

  // A same-epoch admissible Commit (epoch 0, at the head).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
    e.sync_requires_cross_epoch_for_test(),
    "the pinned chunked transfer's sync SURVIVES the same-epoch Commit (cancelling would strand its SyncChunks)"
  );
  assert!(
    e.sync_transfer.is_some(),
    "the pinned sync_transfer is preserved (not dropped by an over-broad cancel)"
  );
  assert_eq!(
    e.sync_nonce_for_test(),
    nonce_before,
    "the sync nonce is unchanged (no cancel, no re-arm)"
  );
}

#[test]
fn a_higher_epoch_trigger_upgrades_an_ordinary_sync_to_crossing_even_when_the_target_does_not_increase()
 {
  // R9 RE-ARM completeness — the inverse of the cancel: a genuine higher-epoch trigger must PIN the
  // crossing requirement on an outstanding sync EVEN WHEN the hinted checkpoint does not exceed the current
  // target. An ordinary same-epoch sync already at/above the hint would otherwise stay ordinary, and a
  // legitimate below-target successor checkpoint would be rejected by the ordinary `< target` freshness
  // gate (or an ordinary reply would complete WITHOUT crossing) — stranding the node at the old epoch until
  // another higher-epoch trigger happens to arrive. `maybe_request_cross_epoch_catchup` now upgrades any
  // outstanding sync to forced + require_cross_epoch regardless of target monotonicity.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
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
  let now = Instant::ZERO;

  // (1) An ORDINARY same-epoch FORCED sync to the donor checkpoint (op 4), and the matching same-epoch
  // (epoch 0, empty-membership) reply → `apply_sync` STAGES the install with `successor` None.
  e.arm_forced_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
    e.handle_storage(now, &mut wal, &mut sb);
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
    &std::collections::BTreeMap::new(),
    &CountSm::default().snapshot(),
  );
  let cross_id = crate::checkpoint_id(&cross_env);
  let membership_body =
    crate::message::ReconfigurePayload::from_membership(&successor_e1, genesis(3).config_id())
      .encode_body();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
    e.handle_storage(now, &mut wal, &mut sb);
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
  // R11: the trigger-level stale downgrade (`downgrade_stale_cross_epoch_sync`) is a SAME-EPOCH evidence
  // path DISTINCT from the ingress cancel. The REAL production trigger sets BOTH the transient
  // `require_cross_epoch` bit AND the persistent `cross_epoch_intent`; this downgrade must clear the intent
  // too, else after the downgraded now-ordinary sync installs, `on_sb_done` would re-arm a crossing from
  // the still-set intent — re-introducing the stale-hint poison the intent refactor exists to remove.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  // A REAL higher-epoch trigger sets the intent AND arms a crossing sync (NOT the `_for_test` helper).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
fn a_pinned_chunked_crossing_survives_a_same_epoch_sync_trigger_via_the_shared_downgrade_scope() {
  // R12: the trigger-level downgrade shares the ingress cancel's PRE-ANSWER scope
  // (`crossing_is_pre_answer_speculative`). A pinned chunked crossing (`sync_transfer` — an in-progress
  // crossing a donor has begun answering) is NOT a bare hint, so a same-epoch sync trigger above the head
  // must PRESERVE it — the transfer, the require_cross_epoch bit, AND the persistent intent — never
  // downgrade it to ordinary and strand its SyncChunks (the ingress cancel already preserves it; the
  // trigger downgrade must too, or it tears down what the ingress deliberately kept).
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
  let now = Instant::ZERO;
  // A real higher-epoch trigger sets the intent + arms a crossing sync at target 10.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::EpochAhead(crate::EpochAhead::new(
      crate::Epoch::new(1),
      OpNumber::with(10),
    )),
  );
  // PIN a chunked transfer (a SyncCheckpointMeta accepted — the crossing is now ANSWER-DERIVED, not bare).
  e.sync_transfer = Some(SyncTransfer {
    checkpoint_op: OpNumber::with(10),
    checkpoint_id: 0,
    total_len: 0,
    epoch: crate::Epoch::new(1),
    config_id: 0,
    membership: Bytes::new(),
    donor: ReplicaId::new(0),
    staged: std::vec::Vec::new(),
  });
  assert!(
    e.sync_requires_cross_epoch_for_test()
      && e.cross_epoch_intent_for_test() == Some(10)
      && e.sync_transfer.is_some(),
    "setup: a pinned chunked crossing (answer-derived, not a bare hint)"
  );

  // A same-epoch sync trigger above the head (a same-epoch checkpoint at 4 > head 0) — the path that, while
  // the ingress cancel preserves the pinned crossing (scoped out), reaches the trigger-level downgrade.
  e.maybe_request_sync(now, OpNumber::with(4));

  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "the pinned chunked crossing's require_cross_epoch is PRESERVED (the shared pre-answer scope excludes it)"
  );
  assert_eq!(
    e.cross_epoch_intent_for_test(),
    Some(10),
    "the persistent intent is PRESERVED (not cleared by a scoped-out downgrade)"
  );
  assert!(
    e.sync_transfer.is_some(),
    "the pinned sync_transfer is PRESERVED (its SyncChunks can still assemble + install)"
  );
}

#[test]
fn a_same_epoch_message_clears_an_orphaned_cross_epoch_intent() {
  // R13: the persistent intent is DECOUPLED from the sync, so it can be ORPHANED — a path like
  // `reset_for_view_transition` clears `sync` (and `sync_transfer`/`pending_install`) without clearing the
  // intent. If the stale-evidence clear paths keyed only off `self.sync.is_some()`, no later same-epoch
  // traffic could clear the orphan, and a subsequent ordinary sync's `on_sb_done` would re-pin a bogus
  // crossing from it — re-introducing the stale-hint poison. The ingress cancel now clears an orphaned
  // intent on same-epoch evidence even when NO sync remains.
  let (mut e, mut wal, mut sb, _env, _id) = sync_apply_harness(4);
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
  // The `crossing_is_pre_answer_speculative` SUCCESSOR-awareness. An ORDINARY same-config sync stages
  // `pending_install` with `successor: None` — that is NOT a crossing. The scope predicate must still
  // allow a same-epoch clear while such an install is in flight: only a CROSSING install (one carrying a
  // successor membership) may shield a stale intent. If a `pending_install.is_some()` test shielded ANY
  // staged install, the ordinary install would complete with the stale intent intact and `on_sb_done`
  // would re-arm a bogus crossing from it — exactly the poison the intent lifecycle exists to prevent.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
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
fn after_an_ordinary_install_completes_on_sb_done_does_not_re_arm_a_crossing() {
  // The completion half of the successor-awareness: once the stale intent is cleared (the predicate let the
  // ordinary install NOT shield it), the ordinary install completing must NOT re-arm a crossing —
  // `on_sb_done` sees `cross_epoch_intent == None` and re-pins nothing. (Contrast
  // `a_staged_same_epoch_install_re_arms_the_crossing_from_the_intent_after_it_completes`, where the intent
  // SURVIVES and `on_sb_done` legitimately re-arms.) This closes the loop: a stale intent shielded by a
  // mis-scoped predicate would re-poison HERE; a correctly-cleared one cannot.
  let (mut e, mut wal, mut sb, env, id) = sync_apply_harness(4);
  let now = Instant::ZERO;

  // Reach Test 1's cleared-intent state: stage an ordinary (successor None) install, pin a stale intent,
  // then clear it with a same-epoch head Commit.
  e.arm_forced_sync_for_test(4);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
    e.handle_storage(now, &mut wal, &mut sb);
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

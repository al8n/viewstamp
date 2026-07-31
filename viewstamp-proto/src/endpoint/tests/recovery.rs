use super::{super::*, *};
use crate::{
  ClientId, Config, DoViewChange, Header, OpNumber, Prepare, PreparedEntry, Recovery,
  RecoveryResponse, ReplicaId, Request, RequestNumber, SlotStatus, StartView, StartViewChange,
  View, VsrState, Wal,
};
use std::collections::VecDeque;

/// Correlation ids for these fixture tests: the incarnation is immaterial here — the fixture
/// only echoes the id back — so every id in this module shares one.
const TEST_INCARNATION: u64 = 1;
fn read_id(seq: u64) -> ReadId {
  ReadId::new(TEST_INCARNATION, seq)
}

#[test]
fn recover_carries_the_durable_commit_so_a_known_committed_op_is_not_truncated() {
  // CONSENSUS-CRITICAL regression. `recover` set BOTH commit_min AND commit_max to
  // checkpoint_op, DISCARDING the durable known-committed frontier `state.commit()` (which can exceed
  // checkpoint_op). A replica whose durable root says op N is committed — but whose WAL slot N read back
  // stale/faulty (now DROPPED → repair hole by the vsr_headers cross-check) — recovered
  // having FORGOTTEN that N is committed. Its DoViewChange then UNDER-reported its commit (commit_min ==
  // checkpoint_op), so if the DVC quorum is this recovered replica + a LAGGARD (the other old
  // commit-quorum holder crashed/partitioned), `commit*` never reached N, the offset-union treated the
  // missing op N as an UNCOMMITTED interior gap, and `start_view_as_new_primary` TRUNCATED — LOSING the
  // known-committed op N. (N's slot read back faulty; its durable HEADER survives, so N is now kept
  // header-only as `Body::Repairing` — but this test pins the commit-frontier carry independently, the
  // belt to the Repairing suspenders.)
  //
  // Fix: `recover` sets commit_max = state.commit() (the durable known frontier, keeping commit_min ==
  // checkpoint_op), and the DVC reports commit_max (VSR's commit-number `k` = highest KNOWN committed),
  // so `commit*` reaches N → N is a COMMITTED repair hole (held + peer-repaired), never truncated.
  //
  // Setup: replica 1 of 3. Durable root: view 0, commit 2 (op 2 is KNOWN committed), checkpoint_op 0,
  // with canonical vsr_headers for ops 1 + 2. WAL head 3, but slot 2 reads back PERMANENTLY FAULTY → the
  // recover loop keeps it header-only as `Body::Repairing` (durable header), an interior committed hole.
  // Op 3 is the uncommitted tail.
  let mk_header = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2), // durable commit — op 2 is KNOWN committed cluster-wide
    OpNumber::new(),   // checkpoint_op 0
    0,
    std::vec![mk_header(1), mk_header(2)],
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(3);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // op 2's slot read permanently faults → Repairing
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovers to Normal (op 2 below the head 3 → peer-repair)"
  );
  // The faulty committed slot (durable header, only the READ faults) is KEPT header-only as a
  // `Body::Repairing` hole — its existence + identity flow into the DVC and the durable band, never a
  // bare hole a later view change could omit. The body is peer-repaired on demand.
  let entry = r
    .log
    .get(&2)
    .expect("the faulty committed op is KEPT as Repairing (durable header), not dropped");
  assert_eq!(
    entry.body,
    Body::Repairing(mk_header(2).body_checksum()),
    "kept header-only as Body::Repairing carrying the durable canonical body_checksum"
  );
  // The durable known-committed frontier is CARRIED: commit_max == 2 (NOT checkpoint_op 0). commit_min
  // stays at checkpoint_op 0 (the SM is restored to the checkpoint; the band re-applies via the WAL).
  // (FAIL-BEFORE: recover set commit_max = checkpoint_op = 0, forgetting op 2 was committed.)
  assert_eq!(
    r.commit_max(),
    OpNumber::with(2),
    "recover carries the durable commit frontier (op 2 is KNOWN committed), not checkpoint_op"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(0),
    "commit_min stays at checkpoint_op — the committed band re-applies as it is repaired/re-announced"
  );
  while r.poll_message().is_some() {} // discard recovery chatter
  while r.poll_event().is_some() {}

  // Drive replica 1 to primary of view 1 with a DVC quorum of {replica 1 (recovered), replica 0 (a
  // LAGGARD)}. The other old commit-quorum holder (replica 2) is ABSENT (crashed/partitioned). The
  // laggard holds only op 1 (head 1, commit 0) — it does NOT supply op 2 and does NOT know op 2 is
  // committed. So the ONLY donor that knows op 2 is committed is the recovered replica itself, via its
  // carried commit_max.
  r.handle_message(
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
  assert_eq!(r.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  r.storage_step(now, &mut storage, &mut blocks); // complete the SendDoViewChange durable-view write
  // The recovered replica's OWN DVC must report its KNOWN committed frontier (commit_max == 2), not
  // commit_min == 0 — otherwise the laggard quorum loses op 2. Verify it on the wire.
  let own_dvc_commit = core::iter::from_fn(|| r.poll_message())
    .filter_map(|out| match out.into_msg() {
      Message::DoViewChange(d) => Some(d.commit()),
      _ => None,
    })
    .next()
    .expect("the recovered replica sends its DVC");
  assert_eq!(
    own_dvc_commit,
    OpNumber::with(2),
    "the DVC reports the KNOWN committed frontier (commit_max == 2), so commit* covers op 2 \
     (FAIL-BEFORE: it reported commit_min == 0 and op 2 was treated as an uncommitted gap)"
  );

  // The laggard replica 0's DVC: same generation (log_view 0), head 1, commit 0, log {1} only — it
  // neither supplies op 2 nor vouches it committed. With the recovered replica's own DVC (commit 2),
  // commit* == 2, so op 2 is a COMMITTED hole — repaired, NOT truncated.
  r.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(1),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::copy_from_slice(&[1u8]),
      )],
    )),
  );
  assert!(r.is_primary(), "replica 1 became the primary of view 1");
  // op 2 is NOT truncated: the head stays at op 3 (op 2 ≤ commit* == 2 is a committed hole). The
  // commit is HELD at op 1 until op 2 is repaired. (FAIL-BEFORE: commit* == 0, op 2 was an uncommitted
  // interior gap, the head truncated to op 1, and the known-committed op 2 was LOST.)
  assert_eq!(
    r.op(),
    OpNumber::with(3),
    "the known-committed op 2 is NOT truncated — the head stays at op 3"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "op 2 is a COMMITTED repair hole (held + peer-repaired), not silently dropped"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "the commit is HELD below the known-committed hole until a peer supplies op 2"
  );

  // Pump the StartViewAsPrimary durable-view write, then a committed-vouching peer answers our
  // RequestPrepare for op 2 (commit 2 >= op 2) → fill the hole and resume the held commit to op 2. The
  // fill is a durability barrier: complete the repaired append before the hole clears.
  r.storage_step(now, &mut storage, &mut blocks);
  while r.poll_message().is_some() {}
  r.handle_message(now, &mut storage, primary_peer(), repair_prepare(0, 2, 2));
  r.storage_step(now, &mut storage, &mut blocks); // the repaired append completes → clear hole + resume
  assert!(
    !r.has_repair_hole_for_test(2),
    "the committed-vouching Prepare fills the known-committed hole"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the held commit resumes — the known-committed op 2 is RETAINED, never lost"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[(1, std::vec![1u8]), (2, std::vec![2u8])],
    "the committed log retains op 2 end to end (FAIL-BEFORE: op 2 was truncated and lost)"
  );
}

#[test]
fn recover_keeps_the_known_commit_when_durable_view_written_while_held_at_a_repair_hole() {
  // CONSENSUS-CRITICAL regression, the follow-on gap in the prior known-commit fix. That fix made
  // `recover` read `state.commit()` as the DURABLE known-committed frontier `commit_max`. But every
  // superblock ROOT write (`submit_durable_view`, the checkpoint root, a state-sync re-persist) still
  // persisted `self.commit_min` as the `VsrState` commit. So a replica HELD at `commit_min < commit_max`
  // by a stale/faulty repair hole — exactly the held-at-repair-hole shape — that completes a durable-view (or
  // checkpoint) root write and then crashes BEFORE its DoViewChange is delivered would, on `recover`,
  // read `commit_max = state.commit() == commit_min` (LOWERED below the true known frontier). The
  // recovered DVC then UNDER-reports the known commit and the truncation hazard reappears with a
  // laggard quorum.
  //
  // Fix: persist `self.commit_max` (the known-committed frontier), NOT `commit_min`, in EVERY root
  // write. `commit_max >= commit_min >= checkpoint_op`, so `try_new`'s `commit >= checkpoint_op`
  // invariant still holds; the committed-band headers stay the CONTIGUOUS canonical prefix from the log
  // (possibly SHORTER than `commit` when there are holes — `try_new` already allows that).
  //
  // Setup: replica 1 of 3, recovered into the held-at-repair-hole shape — durable root view 0,
  // commit 2 (op 2 KNOWN committed), checkpoint_op 0, vsr_headers for ops 1 + 2; WAL head 3 with slot 2
  // permanently faulty → kept header-only as `Body::Repairing` (durable header) → an interior committed
  // repair hole. So commit_max == 2 while commit_min == 0 (the SM is restored to the checkpoint; op 2 is
  // a held hole).
  let mk_header = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2), // durable commit — op 2 is KNOWN committed cluster-wide
    OpNumber::new(),   // checkpoint_op 0
    0,
    std::vec![mk_header(1), mk_header(2)],
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(3);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // op 2's slot read permanently faults → Repairing
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovers to Normal as a backup of view 0"
  );
  assert_eq!(
    r.commit_max(),
    OpNumber::with(2),
    "recover carries the durable known-committed frontier (op 2)"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(0),
    "commit_min stays at checkpoint_op — op 2 is a held hole below the known frontier"
  );
  // The faulty committed slot (durable header, only the READ faults) is KEPT header-only as a
  // `Body::Repairing` hole — a held committed hole below the known frontier, repaired on demand.
  let entry = r
    .log
    .get(&2)
    .expect("the faulty committed op is KEPT as Repairing (durable header), not dropped");
  assert_eq!(
    entry.body,
    Body::Repairing(mk_header(2).body_checksum()),
    "kept header-only as Body::Repairing carrying the durable canonical body_checksum"
  );
  while r.poll_message().is_some() {} // discard recovery chatter
  while r.poll_event().is_some() {}

  // Drive replica 1 into a view change: an SVC for view 1 (replica 1 is the primary of view 1) reaches
  // the SVC quorum {replica 1 (own) + replica 0}, so `enter_view_change` fires the `SendDoViewChange`
  // durable-view ROOT write while this replica is STILL held at commit_min 0 < commit_max 2.
  r.handle_message(
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
  assert_eq!(r.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  assert!(
    r.pending_sb_for_test(),
    "the SendDoViewChange durable-view root write is in flight"
  );
  // Complete the durable-view root write — this is the write the fix changed. The persisted `VsrState`
  // must record the KNOWN-committed frontier `commit_max == 2`, NOT `commit_min == 0`. (FAIL-BEFORE:
  // `submit_durable_view` persisted `self.commit_min`, so the root's commit was 0.)
  r.storage_step(now, &mut storage, &mut blocks);
  assert!(
    !r.pending_sb_for_test(),
    "the durable-view root write completed"
  );
  assert_eq!(
    storage.sb_mut().state().commit(),
    OpNumber::with(2),
    "the durable-view ROOT persists the known-committed frontier commit_max == 2 \
     (FAIL-BEFORE: it persisted commit_min == 0, lowering the durable frontier)"
  );
  // The committed band is the SPARSE canonical set over `(checkpoint_op .. commit_max] == (0 .. 2]`: one
  // header per HELD op. This replica HOLDS op 1 (canonical, Present) AND op 2 (header-only, kept as
  // `Body::Repairing` from its durable header), so the band records BOTH — op 2's header carries its
  // durable canonical body_checksum even though the bytes are absent. The key invariant is that a held
  // committed op keeps its canonical header even though `commit_min == 0`; a body-`Repairing` hole is
  // STILL held (existence preserved into the band + the DVC), not left header-less. (FAIL-BEFORE the
  // sparse change ranged only up to commit_min, so the band was empty.)
  assert_eq!(
    storage
      .sb_mut()
      .state()
      .committed_headers_slice()
      .iter()
      .map(|h| h.op().get())
      .collect::<std::vec::Vec<_>>(),
    std::vec![1, 2],
    "the SPARSE band records both held committed ops — op 1 (Present) and op 2 (Repairing, header-only)"
  );

  // The recovered DVC for view 1 reports the KNOWN committed frontier (commit_max == 2). Drain it.
  let own_dvc_commit = core::iter::from_fn(|| r.poll_message())
    .filter_map(|out| match out.into_msg() {
      Message::DoViewChange(d) => Some(d.commit()),
      _ => None,
    })
    .next()
    .expect("the replica sends its DVC once the view is durable");
  assert_eq!(
    own_dvc_commit,
    OpNumber::with(2),
    "the DVC reports commit_max == 2 (the known frontier), so commit* covers op 2"
  );

  // The crux: a SECOND `recover` from the persisted root reads back the frontier UNLOWERED. With the
  // bug, `storage.sb_mut().state().commit() == 0`, so the re-recovered replica would forget op 2 was committed and its
  // DVC would under-report — re-opening the laggard-quorum truncation hazard the whole fix-chain closes.
  let mut wal2 = ScriptedWal::with_entries(3);
  wal2.script_read_fault(OpNumber::with(2), u8::MAX);
  let (_, sb2) = storage.into_parts().ok().expect("the store is quiesced");
  let mut storage2 = Storage::new(wal2, sb2);
  let cfg2 = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut r2 = Endpoint::recover(cfg2, genesis(3), 0, CountSm::default(), &mut storage2)
    .expect("recover accepts this store")
    .expect_active();
  for _ in 0..32 {
    r2.storage_step(now, &mut storage2, &mut blocks);
    if !r2.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r2.commit_max(),
    OpNumber::with(2),
    "the re-recovered replica reads back the UNLOWERED known frontier (commit_max == 2) \
     (FAIL-BEFORE: the root persisted commit_min == 0, so the frontier was lost on re-recover)"
  );
  assert_eq!(
    r2.view(),
    View::with(1),
    "the re-recovered replica is in the durable view 1 the root recorded"
  );
}

#[test]
fn recover_keeps_a_body_faulty_committed_op_as_repairing_then_peer_repairs_its_body() {
  // CONSENSUS-CRITICAL. A committed/kept op whose WAL read comes back BodyFaulty — the HEADER is
  // durable, only the BODY is torn/rotted — must be KEPT in `self.log` as a `Body::Repairing` hole
  // (its existence + canonical identity preserved), NOT dropped. Dropping it forgets the op entirely,
  // so a later view-change quorum reaching only this replica for that op would LOSE the committed op
  // and re-mint its number. The fix classifies the slot exactly as a clean read does (the SAME
  // `classify_committed_slot` verdict) and, on Verified, retains it header-only as `Repairing`; the
  // body is peer-repaired on demand by the commit path.
  //
  // Setup: replica 1 of 3. Durable root: view 0, commit 1 (op 1 KNOWN committed), checkpoint_op 0,
  // canonical vsr_header for op 1. WAL head 1; op 1's slot reads back BODY-FAULTY (header durable).
  let mk_header = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(1), // durable commit — op 1 is KNOWN committed
    OpNumber::new(),   // checkpoint_op 0
    0,
    std::vec![mk_header(1)],
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(1);
  wal.script_body_faulty(OpNumber::with(1)); // header durable, body unrecoverable → BodyFaulty
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, EchoSm, &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  for _ in 0..32 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "a durable-header body-faulty op does not block recovery — the op is kept, body repaired on demand"
  );
  // The op is KEPT in the cache as a `Body::Repairing` hole carrying its durable body_checksum — NOT
  // dropped (FAIL-BEFORE: the body fault dropped the whole op from `self.log`).
  let entry = r
    .log
    .get(&1)
    .expect("the body-faulty committed op is KEPT in the log (existence preserved), not dropped");
  assert_eq!(
    entry.body,
    Body::Repairing(mk_header(1).body_checksum()),
    "kept header-only as Body::Repairing with the durable canonical body_checksum"
  );
  assert_eq!(
    entry.client,
    ClientId::new(7),
    "the durable client identity is preserved"
  );
  assert_eq!(
    entry.request,
    RequestNumber::with(1),
    "the durable request identity is preserved"
  );
  assert_eq!(
    r.commit_max(),
    OpNumber::with(1),
    "the durable known-committed frontier (op 1) is carried"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(0),
    "commit_min stays at checkpoint_op — op 1's body must arrive before it applies"
  );

  // A follow-up repaired body fills the Repairing hole to Present and recovery's tail commits. The
  // commit path holds at the `Repairing` entry and solicits `RequestPrepare`; a peer's `Prepare`
  // carrying the canonical body (the exact bytes `with_entries` stored) fills it via `fill_repair`.
  while r.poll_message().is_some() {}
  while r.poll_event().is_some() {}
  // Drive commit toward op 1 so the commit path requests the body (advance_commit holds at the hole
  // and registers a repair request).
  r.handle_message(now, &mut storage, primary_peer(), prepare(1, 1));
  r.storage_step(now, &mut storage, &mut blocks);
  assert!(
    r.has_repair_hole_for_test(1),
    "the commit path holds at the Repairing op and arms peer-repair for its body"
  );
  // The peer answers with the canonical body for op 1.
  r.handle_message(now, &mut storage, primary_peer(), repair_prepare(0, 1, 1));
  r.storage_step(now, &mut storage, &mut blocks); // the RepairFill append lands → body Present, hole clears
  assert!(
    !r.has_repair_hole_for_test(1),
    "the repaired body fills the hole — the op is no longer repair-pending"
  );
  let filled = r.log.get(&1).expect("op 1 stays held after repair");
  assert!(
    filled.body.is_present(),
    "the repaired body fills the Repairing hole to Present"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "with the body repaired, the held commit resumes and op 1 applies"
  );
}

#[test]
fn recover_drops_a_stale_committed_op_read_back_body_faulty_not_resurrected_as_repairing() {
  // GUARDS the superseded-proposal fix: a STALE/superseded committed slot must NOT be resurrected as
  // a `Repairing` hole when its read comes back BodyFaulty — it is still DROPPED (classified
  // StaleCommitted), exactly as a stale ReadOk is, so the canonical body is peer-repaired, never the
  // local stale one. Here op 2's durable WAL header identity MISMATCHES the canonical vsr_header for
  // op 2 (a different client/request/body), so `classify_committed_slot` returns StaleCommitted even
  // though the read is BodyFaulty.
  //
  // Setup: replica 1 of 3. Durable root: view 0, commit 2 (ops 1+2 KNOWN committed), checkpoint_op 0.
  // The canonical vsr_header for op 2 names a DIFFERENT identity than the WAL slot's durable header.
  let canon_header = |op: u64, client: u128| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(client),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  // The canonical (root) identity for op 2 is client 99; the WAL slot below holds client 7 → mismatch.
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::new(),
    0,
    std::vec![canon_header(1, 7), canon_header(2, 99)],
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  // `with_entries` seeds op 2 under client 7 (the STALE local identity); its read is BodyFaulty.
  let mut wal = ScriptedWal::with_entries(3);
  wal.script_body_faulty(OpNumber::with(2));
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, EchoSm, &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  for _ in 0..32 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(r.status(), Status::Normal, "recovers to Normal");
  assert!(
    !r.log.contains_key(&2),
    "a stale (identity-mismatched) committed slot read back BodyFaulty is DROPPED, NOT kept as Repairing"
  );
  assert_eq!(
    r.commit_max(),
    OpNumber::with(2),
    "the durable known-committed frontier is still carried (op 2 is a peer-repaired hole)"
  );
}

#[test]
fn recover_drops_a_genuinely_absent_committed_op_as_today() {
  // A genuinely-absent committed op (no durable header — the read is Absent, not BodyFaulty) is still
  // DROPPED as today: there is no durable header to keep, so the op cannot be retained as `Repairing`;
  // it becomes a repair hole peer-repaired on demand. Confirms the keep-as-Repairing path is gated on
  // a DURABLE header and does not change the absent-op behaviour.
  //
  // Setup: replica 1 of 3, durable commit 2 (ops 1+2 KNOWN committed). The WAL holds op 1 + the head
  // op 3, but op 2's slot is ABSENT entirely (no header, no body) — a genuine hole.
  let mk_header = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::new(),
    0,
    std::vec![mk_header(1)], // sparse: op 2 was a hole the writer did not hold
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  // Build a WAL with ops 1 + 3 only (op 2 absent): start from a 3-entry WAL, then truncate-rebuild by
  // removing op 2's slot via a permanent read fault that also has no header — simulate absence by
  // pruning op 2 out of `entries`. `with_entries(3)` then op 2 removed leaves op 2 a genuine hole.
  let mut wal = ScriptedWal::with_entries(3);
  wal.remove_entry_for_test(OpNumber::with(2)); // op 2 has NO durable header → read is Absent
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, EchoSm, &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovers to Normal (op 2 a below-head hole)"
  );
  assert!(
    !r.log.contains_key(&2),
    "a genuinely-absent committed op (no durable header) is DROPPED — it cannot be kept as Repairing"
  );
  assert_eq!(
    r.commit_max(),
    OpNumber::with(2),
    "the durable known-committed frontier is carried (op 2 peer-repaired on demand)"
  );
}

#[test]
fn recover_enters_recovering_then_reaches_normal_after_reads_drain() {
  // recover() is now a metadata-only constructor: it returns in Recovering and only reaches
  // Normal after handle_storage drains the tail reads. (Was: synchronous → Normal immediately.)
  let mut e = backup();
  let (wal, sb) = (TestWal::default(), sb_formatted());
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(now, &mut storage, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut storage, primary_peer(), prepare(2, 1));
  e.storage_step(now, &mut storage, &mut blocks);
  drop(e);

  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  assert_eq!(
    r.status(),
    Status::Recovering,
    "recover is now a metadata-only constructor (Recovering)"
  );
  r.storage_step(now, &mut storage, &mut blocks); // drain the tail reads
  assert_eq!(r.status(), Status::Normal, "tail consistent => Normal");
  assert_eq!(r.op(), OpNumber::with(2));
}

#[test]
fn recover_retries_a_transient_read_fault_then_reaches_normal() {
  // A ScriptedWal faults op 2's read ONCE, then reads clean. The Recovering loop retries and
  // reaches Normal with the real body — a transient storage fault during recovery is tolerated.
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), 1);
  let sb = sb_formatted();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    EchoSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  assert_eq!(r.status(), Status::Recovering);
  // Pump storage + the recover-retry timer until the retry clears (bounded): the timer re-reads the
  // pending op additively and the next drain consumes the now-clean completion.
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "transient read-fault retried => Normal"
  );
  assert_eq!(r.op(), OpNumber::with(2));
}

#[test]
fn recover_head_permanently_faulty_enters_recovering_head() {
  // A ScriptedWal faults op 2's (the head's) read PERMANENTLY (beyond the retry budget). The
  // replica cannot trust its head => RecoveringHead, never Normal. It then SOLICITS the canonical
  // head (a Recovery broadcast) but still casts no ack/vote in response to a re-delivered prepare.
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // exceeds the retry budget
  let sb = sb_formatted();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "permanently-faulty head => RecoveringHead"
  );
  // On entry it solicits the canonical head (Recovery); drain that — it is NOT participation.
  while let Some(out) = r.poll_message() {
    assert!(
      out.msg_ref().is_recovery(),
      "the only message a RecoveringHead replica emits on entry is a Recovery solicitation"
    );
  }
  // A RecoveringHead replica must not participate: it casts no PrepareOk on a re-delivered prepare.
  r.handle_message(now, &mut storage, primary_peer(), prepare(2, 1));
  assert!(
    r.poll_message().is_none(),
    "RecoveringHead replica emits no ack/vote in response to a prepare"
  );
}

// ── peer fault-repair (RequestPrepare → Prepare) ──

#[test]
fn recover_non_head_faulty_committed_slot_becomes_normal_and_requests_repair() {
  // A permanently-faulty NON-head committed slot must NOT strand the replica (the old behaviour) and
  // must NOT panic: the replica returns to Normal, drops the unreadable slot from its cache, and
  // — once its commit reaches the slot — broadcasts a RequestPrepare for it (peer fault-repair),
  // HOLDING its commit below the hole. The slot is NOT pre-registered as a repair hole
  // at recovery time: a faulty slot above the checkpoint may be UNCOMMITTED, and registering it then
  // would be an unfillable hole after the repair restrictions; `advance_commit` requests it ON
  // DEMAND only when commit reaches it (which only happens once it is committed).
  let (mut r, mut storage) = recovering_with_hole(3, 2);
  assert_eq!(
    r.status(),
    Status::Normal,
    "a non-head faulty committed slot peer-repairs from Normal (never strands in Recovering)"
  );
  // It did NOT pre-register op 2 as a repair hole at recovery time (commit_max is still 0, so op 2
  // is uncommitted as far as this replica knows). No RequestPrepare is solicited yet.
  assert!(
    !r.has_repair_hole_for_test(2),
    "the faulty slot is NOT pre-registered as a repair hole at recovery (it may be uncommitted)"
  );
  assert!(
    r.poll_message().is_none(),
    "no RequestPrepare is solicited at recovery time — repair is on-demand"
  );

  // Learn commit up to 3 (e.g. a Commit from the primary): op 1 applies, op 2 is a HOLE → commit
  // HELD at 1 (never skips to apply op 3 with op 2 missing). Reaching op 2 with commit now covering
  // it is exactly when `advance_commit` requests the repair ON DEMAND.
  let now = Instant::ZERO;
  r.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "commit is HELD below the hole — op 2's body is missing, so op 3 must not apply"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[(1, std::vec![1u8])],
    "only op 1 applied; the hole stops the apply strictly in order"
  );
  // NOW op 2 is registered (on demand) and solicited: advance_commit reached it once commit covered it.
  assert!(
    r.has_repair_hole_for_test(2),
    "advance_commit registers the now-committed faulty op as a repair hole on demand"
  );
  let mut asked_for_2 = false;
  while let Some(out) = r.poll_message() {
    // The hole arm solicits the contiguous run via the windowed `RequestPrepareRange` (a single-op
    // range `[2,2]` here) rather than a per-op `RequestPrepare`.
    if let Message::RequestPrepareRange(rp) = out.into_msg() {
      assert!(rp.lo() <= OpNumber::with(2) && rp.hi() >= OpNumber::with(2));
      asked_for_2 = true;
    }
  }
  assert!(
    asked_for_2,
    "the replica solicits the faulty committed op once its commit reaches it"
  );
}

#[test]
fn recover_drops_a_superseded_above_commit_tail_slot_so_the_canonical_body_is_applied() {
  // REGRESSION, CONSENSUS-CRITICAL committed-divergence. A replica's WAL can
  // retain a STALE tail op from an EARLIER view that a later view never overwrote — a proposal it appended
  // as an old-view primary, which a view change SUPERSEDED (the new view assigns that op number a DIFFERENT
  // client request). Adoption only dropped it from the in-memory cache, not the WAL. On a later crash +
  // `recover`, the loop rebuilds the cache from the WAL and re-loads that stale body; when the cluster then
  // commits the op (whose CANONICAL value differs), `advance_commit` APPLIED the stale local body → the
  // replica diverged from every other replica at that one committed op number (no second op number is minted
  // and no request is committed twice — at-most-once holds — but a single committed slot carried two values).
  //
  // The `vsr_headers` cross-check only guards the persisted committed band `(checkpoint .. commit]`;
  // a slot ABOVE the durable known-committed frontier is not in that band, so it was trusted blindly. The fix
  // generalises the cross-check: on `recover`, a self-verifying tail slot above `commit_max` whose ORIGINAL
  // header `view` is BELOW the durable `log_view` is a SUPERSEDED earlier-view proposal (we advanced our
  // `log_view` past it), so it is dropped and routed to peer-repair — the canonical body is fetched, never
  // re-derived from the stale WAL. A current-generation uncommitted tail op (`view == log_view`) is KEPT.
  //
  // Reproduction (replica 2 of 3 = a BACKUP of view 1): durable root view 1, log_view 1, commit 2, checkpoint
  // 0, with vsr_headers for the committed prefix ops 1 + 2 (current-view, canonical). The WAL holds an
  // INTERIOR stale slot op 3 (a view-0 proposal — client 9, request 99, body 0xAA) ABOVE the durable commit 2,
  // with current-view (view 1) ops 4 + 5 above it (a legitimate uncommitted tail that must be KEPT). The
  // cluster's canonical op 3 is (client 7, request 3, body [3]). Recover must DROP slot 3 (not hold its stale
  // body) yet keep 4 + 5.
  //
  // EXTENDED (CONSENSUS-CRITICAL, the re-ack follow-on gap): after recover drops the stale
  // interior op 3, a RETRANSMITTED current-view `Prepare(op 3, CANONICAL body)` arriving BEFORE any Commit
  // must NOT be re-acked off the stale Clean WAL slot. The re-ack branch now proves IDENTITY against
  // `self.log`; a missing/mismatched current-view op is (re)appended CANONICALLY (interior overwrite at
  // `pop < self.op`, NO head rewind) with the ack DEFERRED to `on_wal_done`. Asserted below: NO PrepareOk(3)
  // until the canonical body is durably appended, then exactly one; the stale [0xAA] is never acked or applied.
  let now = Instant::ZERO;
  let mk_header = |op: u64, view: u64, client: u128, request: u64, body: &[u8]| {
    Header::new(
      OpNumber::with(op),
      View::with(view),
      ClientId::new(client),
      RequestNumber::with(request),
      body,
    )
  };
  // Ops 1 + 2: current-view (view 1) canonical committed prefix. Op 3: STALE view-0 superseded INTERIOR slot.
  // Ops 4 + 5: current-view (view 1) uncommitted tail (kept — `view == log_view`), so op 3 is interior.
  let mut wal = ScriptedWal::with_entries(2); // seeds ops 1, 2 — view/body overwritten next
  wal.entries.insert(
    1,
    (mk_header(1, 1, 7, 1, &[1]), Bytes::copy_from_slice(&[1])),
  );
  wal.entries.insert(
    2,
    (mk_header(2, 1, 7, 2, &[2]), Bytes::copy_from_slice(&[2])),
  );
  wal.entries.insert(
    3,
    (
      mk_header(3, 0, 9, 99, &[0xAA]),
      Bytes::copy_from_slice(&[0xAA]),
    ),
  );
  wal.entries.insert(
    4,
    (mk_header(4, 1, 7, 4, &[4]), Bytes::copy_from_slice(&[4])),
  );
  wal.entries.insert(
    5,
    (mk_header(5, 1, 7, 5, &[5]), Bytes::copy_from_slice(&[5])),
  );
  wal.head = 5;
  let state = VsrState::try_new(
    View::with(1), // durable view 1 — recovers as a backup of view 1 (primary is replica 1)
    View::with(1), // durable log_view 1 — a view-0 tail slot is from a SUPERSEDED generation
    OpNumber::with(2), // commit 2 — ops 1 + 2 are KNOWN committed; op 3 is ABOVE the frontier
    OpNumber::new(), // checkpoint_op 0
    0,
    std::vec![mk_header(1, 1, 7, 1, &[1]), mk_header(2, 1, 7, 2, &[2])], // vsr_headers for 1 + 2
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let cfg = Config::try_new(1, MemberId::new(2)).unwrap();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  for _ in 0..32 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(r.status(), Status::Normal, "recovers to Normal in view 1");
  assert_eq!(r.view(), View::with(1), "recovered into the durable view 1");
  assert!(!r.is_primary(), "replica 2 is a BACKUP of view 1");
  // The crux of the fix: the STALE view-0 slot 3 is DROPPED from the cache (FAIL-BEFORE: it was held as
  // `(client 9, request 99, body 0xAA)` and would later be applied for the committed op). Ops 1 + 2 (current
  // view, in the committed band) are kept.
  assert!(
    !r.log.contains_key(&3),
    "FAIL-BEFORE: the superseded view-0 slot 3 must be dropped on recover (not re-loaded as committed)"
  );
  assert!(
    r.log.contains_key(&1) && r.log.contains_key(&2),
    "the current-view committed prefix (ops 1 + 2) is retained"
  );
  assert!(
    r.log.contains_key(&4) && r.log.contains_key(&5),
    "the current-view uncommitted tail (ops 4 + 5, view == log_view) is KEPT — only the older-view slot is dropped"
  );
  while r.poll_message().is_some() {} // discard recovery chatter
  while r.poll_event().is_some() {}
  // Precondition for the re-ack sub-scenario: the WAL slot 3 STILL holds the stale view-0 body [0xAA]
  // (recover dropped it only from the in-memory cache, not the durable WAL), and its slot is Clean —
  // the exact false-ack bait below.
  assert_eq!(
    storage.wal_mut().entries.get(&3).map(|(_, b)| b.as_ref()),
    Some(&[0xAAu8][..]),
    "precondition: the WAL slot 3 still holds the stale [0xAA] body (Clean), dropped only from the cache"
  );
  assert_eq!(
    storage.wal_mut().status(OpNumber::with(3)),
    SlotStatus::Clean,
    "precondition: the stale slot 3 is Clean (durably appended) — the op_durably_appended bait"
  );

  // ── CONSENSUS-CRITICAL (the follow-on gap in the stale-slot drop): the primary RETRANSMITS the
  // current-view canonical `Prepare(op 3)` BEFORE any Commit registers op 3 as a repair hole. The
  // retransmit carries the primary's `commit_min` (= 2 here, < op 3), so it does NOT auto-register op 3
  // for repair. op 3 is NOT in `self.repair`, NOT in `self.log` (dropped), and `pop = 3 <= self.op = 5`,
  // so it hits the re-ack branch. FAIL-BEFORE: that branch saw `op_durably_appended(3) == true` (the
  // stale Clean slot) and `appending` clear, and IMMEDIATELY sent `PrepareOk(3)` — false-acking an op
  // whose CANONICAL body it does NOT durably hold (it holds the stale [0xAA]). A quorum could be that
  // false ack + the primary; the primary then crashing would lose the op (append-before-ack + committed-
  // op-survival broken). The fix: the re-ack must prove IDENTITY against `self.log`; a missing/mismatched
  // current-view op is (re)appended CANONICALLY and the ack DEFERRED to `on_wal_done`.
  let primary1 = Peer::Replica(ReplicaId::new(1));
  let canonical_retransmit = Message::Prepare(Prepare::new(
    View::with(1),
    OpNumber::with(3),
    OpNumber::with(2),
    OpNumber::new(),
    crate::Epoch::new(0),
    0,
    ClientId::new(7),
    RequestNumber::with(3),
    Bytes::copy_from_slice(&[3]),
  ));
  r.handle_message(now, &mut storage, primary1, canonical_retransmit);
  // BEFORE the append completes (no handle_storage yet): NO PrepareOk(3) may have been emitted. The op was
  // missing/mismatched, so the fix (re)appends the canonical body and DEFERS the ack — it must NOT have
  // inline-acked off the stale slot. (FAIL-BEFORE: a PrepareOk(3) is emitted immediately here.)
  let acks_before: std::vec::Vec<_> = core::iter::from_fn(|| r.poll_message())
    .filter_map(|out| match out.into_msg() {
      Message::PrepareOk(ok) if ok.op() == OpNumber::with(3) => Some(ok),
      _ => None,
    })
    .collect();
  assert!(
    acks_before.is_empty(),
    "FAIL-BEFORE: no PrepareOk(3) until the canonical body is durably appended — the stale Clean slot \
     must NOT inline-ack the retransmitted Prepare (got {} premature ack(s))",
    acks_before.len()
  );
  // The canonical body is (re)appended INTERIOR at op 3 (an overwrite at pop < self.op), WITHOUT rewinding
  // the head: self.op stays 5, and the WAL slot 3 now holds the CANONICAL [3], overwriting the stale [0xAA].
  assert_eq!(
    r.op(),
    OpNumber::with(5),
    "the head is NOT rewound by the interior overwrite at op 3 (self.op stays 5)"
  );
  assert_eq!(
    storage.wal_mut().entries.get(&3).map(|(_, b)| b.as_ref()),
    Some(&[3u8][..]),
    "the canonical body [3] overwrote the stale [0xAA] in WAL slot 3 (append-before-ack: durable first)"
  );
  assert!(
    r.log.contains_key(&3),
    "op 3 is back in the cache with the canonical body (re-appended, not a held hole)"
  );

  // Now the append completes → on_wal_done clears `appending(3)` and sends EXACTLY ONE deferred PrepareOk(3).
  r.storage_step(now, &mut storage, &mut blocks);
  let acks_after: std::vec::Vec<_> = core::iter::from_fn(|| r.poll_message())
    .filter_map(|out| match out.into_msg() {
      Message::PrepareOk(ok) if ok.op() == OpNumber::with(3) => Some(ok),
      _ => None,
    })
    .collect();
  assert_eq!(
    acks_after.len(),
    1,
    "exactly ONE PrepareOk(3) is emitted, AFTER the canonical append landed (append-before-ack)"
  );

  // The crux: a Commit reaching op 3 now applies the CANONICAL body [3], NEVER the stale [0xAA]. With the
  // bug the replica would have acked op 3 off the stale slot (above) and — if the cluster committed off that
  // ack — applied [0xAA], a committed-state divergence from every replica that applied [3].
  r.handle_message(
    now,
    &mut storage,
    primary1,
    Message::Commit(Commit::new(
      View::with(1),
      OpNumber::with(3),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  r.storage_step(now, &mut storage, &mut blocks);
  assert!(
    !r.has_repair_hole_for_test(3),
    "op 3 needs no repair — its canonical body was re-appended, so the commit applies it directly"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "committed through op 3 off the re-appended canonical body"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[
      (1, std::vec![1u8]),
      (2, std::vec![2u8]),
      (3, std::vec![3u8])
    ],
    "op 3 applied the canonical body [3]; the stale [0xAA] must NEVER be applied for the committed op"
  );
}

#[test]
fn recover_does_not_pre_register_an_uncommitted_faulty_tail_slot_as_a_repair_hole() {
  // REGRESSION: a faulty slot ABOVE the checkpoint may be UNCOMMITTED. At recovery the
  // replica only knows `commit_min == commit_max == checkpoint_op`, so it must NOT pre-register the
  // slot in `self.repair`: a peer serves only `op <= commit_min` and `fill_repair` rejects
  // `commit < op`, so an uncommitted repair hole can NEVER be filled — and the `on_request`
  // guard (`!self.repair.is_empty()`) would then drop every client forever (a liveness deadlock).
  //
  // Recover with an uncommitted interior faulty slot (checkpoint 0, head 3, faulty op 2, and NO
  // Commit ever raising commit_max past 0). After recovery `self.repair` must be EMPTY (fail-before:
  // it was `{2}`), so the apply path never wedges on an unfillable hole.
  let (r, _storage) = recovering_with_hole(3, 2);
  assert_eq!(
    r.status(),
    Status::Normal,
    "the recovered backup resumes Normal (the faulty slot is dropped from the cache, not stranding)"
  );
  assert!(
    !r.has_repair_hole_for_test(2),
    "an UNCOMMITTED faulty tail slot is NOT registered as a repair hole at recovery"
  );
  assert!(
    r.repair.is_empty(),
    "the repair set is empty after recovery — no unfillable hole, no on_request deadlock"
  );

  // Liveness consequence: with an empty repair set the `on_request` guard does NOT drop
  // clients. Demonstrate on a Normal PRIMARY (the role that serves requests): with the buggy
  // pre-registration (`repair = {uncommitted op}`) `on_request` returns early and the client hangs;
  // with the empty repair the recovery now produces, the primary accepts the request and prepares it.
  let now = Instant::ZERO;
  let mk_request = || {
    Message::Request(crate::Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::copy_from_slice(b"x"),
    ))
  };
  // (a) buggy state: an uncommitted op stranded in `repair` → every client is dropped (the deadlock).
  {
    let mut p = Endpoint::<_, RestartOnly>::genesis_unchecked(
      Config::try_new(1, MemberId::new(0)).unwrap(),
      genesis(3),
      0,
      CountSm::default(),
      u64::MAX,
    );
    let mut storage = Storage::new(TestWal::default(), TestSb::default());
    p.repair.insert(5); // simulate the old pre-registration of an uncommitted faulty slot
    p.handle_message(
      now,
      &mut storage,
      Peer::Client(ClientId::new(7)),
      mk_request(),
    );
    assert!(
      p.poll_message().is_none(),
      "with a stranded uncommitted hole in `repair`, on_request drops the client (the deadlock this removes)"
    );
  }
  // (b) fixed state: empty repair (what recovery now leaves) → the primary serves the request.
  {
    let mut p = Endpoint::<_, RestartOnly>::genesis_unchecked(
      Config::try_new(1, MemberId::new(0)).unwrap(),
      genesis(3),
      0,
      CountSm::default(),
      u64::MAX,
    );
    let mut storage = Storage::new(TestWal::default(), TestSb::default());
    assert!(p.repair.is_empty(), "fresh primary has no repair holes");
    p.handle_message(
      now,
      &mut storage,
      Peer::Client(ClientId::new(7)),
      mk_request(),
    );
    let prepared = core::iter::from_fn(|| p.poll_message())
      .any(|out| matches!(out.into_msg(), Message::Prepare(_)));
    assert!(
      prepared,
      "with an empty repair set the primary serves the client (broadcasts a Prepare) — no deadlock"
    );
  }
}

#[test]
fn recovering_head_solicits_recovery_on_entry() {
  // On entering RecoveringHead the replica broadcasts a Recovery solicitation (it cannot recover
  // its head from its own disk) carrying its replica id + nonce.
  let (mut r, _storage) = recovering_head(2);
  let mut saw_recovery = false;
  while let Some(out) = r.poll_message() {
    if let Message::Recovery(rec) = out.into_msg() {
      assert_eq!(rec.replica(), ReplicaId::new(1));
      saw_recovery = true;
    }
  }
  assert!(
    saw_recovery,
    "RecoveringHead solicits the canonical head via Recovery"
  );
  // It also armed the solicitation timer so an owner driving poll_timeout keeps re-soliciting.
  assert!(
    r.poll_timeout().is_some(),
    "RecoveringHead arms the recover_head timer"
  );
}

#[test]
fn recovering_head_adopts_start_view_and_becomes_normal() {
  // A replica stuck in RecoveringHead (head slot permanently lost) receives a StartView from the
  // view's primary; it adopts the canonical head + log, persists the view, and becomes Normal —
  // the committed op it could not read locally is restored from the canonical log.
  let (mut r, mut storage) = recovering_head(2);
  while r.poll_message().is_some() {} // discard the solicitation
  let now = Instant::ZERO;
  // primary(view 1) of a 3-cluster is replica 1 — but THIS replica is replica 1, so use view 0's
  // primary (replica 0) at a view >= ours (view 0). A same-view StartView from the primary adopts
  // because a RecoveringHead replica is not Normal.
  let sv = StartView::new(
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b"),
      ),
    ],
  );
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  r.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartView(sv),
  );
  assert_eq!(
    r.status(),
    Status::Normal,
    "RecoveringHead adopts the StartView → Normal"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(2),
    "head re-established from the canonical log"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the committed prefix is restored"
  );
  // The recovery bookkeeping is cleared (structurally None in Normal).
  assert!(r.recover.is_none(), "recover state cleared on adoption");
  // The new view is persisted before participation; pump the durable-view write, then it re-acks.
  r.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(storage.sb_mut().state().view(), View::new());
}

#[test]
fn recovering_head_with_a_faulty_non_head_slot_never_applies_an_empty_body() {
  // REGRESSION (the empty-body divergence): a replica that recovers with BOTH a
  // faulty HEAD slot (→ RecoveringHead) AND a faulty NON-head committed slot must STILL drop the
  // non-head slot from its `log` cache (it holds only an EMPTY placeholder body from recover Phase 1).
  // Otherwise, when it later adopts a canonical head whose (offset) log OMITS that slot, `adopt_log`
  // PRESERVES the empty-bodied held copy, `adopt_canonical_head` retires its repair hole (it is now
  // "held"), and `advance_commit` applies it with the EMPTY body — diverging a committed op. The fix
  // drops every faulty slot from the cache on the RecoveringHead path and registers the non-head ones
  // as repair holes, so adoption keeps the hole and the commit is HELD until a peer serves the op.
  let mut wal = ScriptedWal::with_entries(4);
  wal.script_read_fault(OpNumber::with(4), u8::MAX); // faulty HEAD → RecoveringHead
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // faulty NON-head committed slot (empty in cache)
  let sb = sb_formatted();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "faulty head → RecoveringHead"
  );
  while r.poll_message().is_some() {} // discard the Recovery solicitation

  // Adopt a StartView from the view-0 primary (replica 0): canonical head op 4, commit 4, but an
  // OFFSET log carrying only ops 3,4 — it OMITS op 2 (modelling a primary whose log starts above 2).
  let sv = StartView::new(
    View::new(),
    OpNumber::with(4),
    OpNumber::with(4),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(3),
        ClientId::new(7),
        RequestNumber::with(3),
        bytes::Bytes::copy_from_slice(&[3u8]),
      ),
      PreparedEntry::new(
        OpNumber::with(4),
        ClientId::new(7),
        RequestNumber::with(4),
        bytes::Bytes::copy_from_slice(&[4u8]),
      ),
    ],
  );
  r.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartView(sv),
  );

  // Op 2 was NOT resurrected from the empty placeholder: it stays a solicited repair hole, NEVER
  // applied empty. This replica recovered from its WAL alone (no checkpoint, commit_min == 0), so it
  // had APPLIED nothing — ops 1 AND 2 are both committed-but-unapplied at adopt time. The offset
  // canonical log omits op 2 (and op 1), so BOTH become repair holes: the commit is HELD at 0 at the
  // first hole (op 1), op 2 is registered once op 1 fills. (The safety fix means an UNAPPLIED
  // omitted committed op is never resurrected from the local cache — including op 1, whose clean-read
  // WAL body could itself be a superseded proposal — so it is fetched from a peer, not trusted local.
  // This only STRENGTHENS the original guard: still no empty/stale body is ever applied to op 2.)
  assert!(
    r.has_repair_hole_for_test(2) || r.has_repair_hole_for_test(1),
    "an omitted unapplied committed op (op 1 first, then op 2) is a repair hole — never resurrected"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(0),
    "the commit is HELD below the first unfilled hole (op 1), never advanced over an empty/stale body"
  );
  // CRUCIAL: no op was ever applied with an empty body (the divergence signature).
  for (op, body) in r.state_machine_ref().applied() {
    assert!(
      !body.is_empty(),
      "op {op} was applied with an EMPTY body — the committed-op divergence this guards against"
    );
  }
  // And op 2 specifically is not applied at all yet (held — its faulty empty placeholder was dropped).
  assert!(
    !r.state_machine_ref()
      .applied()
      .iter()
      .any(|(op, _)| *op == 2),
    "op 2 is not applied until a verified body arrives"
  );
  assert!(
    !r.log.contains_key(&2),
    "op 2's faulty empty placeholder is never re-introduced into the log cache"
  );
}

#[test]
fn recovering_head_adopts_recovery_response_from_primary() {
  // The full handshake: a RecoveringHead replica's Recovery is answered by the primary with a
  // RecoveryResponse carrying the canonical head; the replica adopts it and returns to Normal.
  let (mut r, mut storage) = recovering_head(2);
  // Capture the nonce the replica solicited with (so we echo it in the primary's response).
  let mut nonce = 0;
  while let Some(out) = r.poll_message() {
    if let Message::Recovery(rec) = out.into_msg() {
      nonce = rec.nonce();
    }
  }
  let now = Instant::ZERO;
  // The primary of view 0 (replica 0) answers with its canonical log + head + commit, echoing nonce.
  let resp = RecoveryResponse::new(
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    nonce,
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b"),
      ),
    ],
  );
  r.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::RecoveryResponse(resp),
  );
  assert_eq!(
    r.status(),
    Status::Normal,
    "adopt the primary's RecoveryResponse → Normal"
  );
  assert_eq!(r.op(), OpNumber::with(2));
  assert_eq!(r.commit(), OpNumber::with(2));
  assert!(r.recover.is_none());
}

#[test]
fn recovering_head_ignores_stale_or_non_primary_recovery_response() {
  // A RecoveryResponse with the WRONG nonce (a stale prior solicitation) is ignored, and a
  // response from a NON-primary (empty log) cannot re-establish a head — the replica stays
  // RecoveringHead in both cases, never adopting an unauthoritative head.
  let (mut r, mut storage) = recovering_head(2);
  let mut nonce = 0;
  while let Some(out) = r.poll_message() {
    if let Message::Recovery(rec) = out.into_msg() {
      nonce = rec.nonce();
    }
  }
  let now = Instant::ZERO;
  // Wrong nonce → ignored.
  r.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::RecoveryResponse(RecoveryResponse::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce.wrapping_add(1),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      )],
    )),
  );
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "a wrong-nonce response is ignored"
  );
  // A response from a non-primary (replica 2, with empty log) → ignored (no canonical head).
  r.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::RecoveryResponse(RecoveryResponse::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      nonce,
      std::vec![],
    )),
  );
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "a non-primary response cannot re-establish the head"
  );
}

#[test]
fn recovering_head_does_not_participate_on_non_head_learning_messages() {
  // The guard relaxation is SURGICAL: a RecoveringHead replica processes only StartView /
  // RecoveryResponse. A Prepare/Commit/PrepareOk must NOT be acted on (no vote/ack), and must NOT
  // pull it into a view change via the higher-view rule.
  let (mut r, mut storage) = recovering_head(2);
  while r.poll_message().is_some() {} // discard the solicitation
  let now = Instant::ZERO;
  // A higher-view Prepare would normally trigger catch_up_to_view → ViewChange. It must be dropped.
  r.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::with(5),
      OpNumber::with(3),
      OpNumber::with(2),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      ClientId::new(7),
      RequestNumber::with(3),
      Bytes::from_static(b"z"),
    )),
  );
  // A current-view Prepare for an op we hold would normally re-ack. It must be dropped too.
  r.handle_message(now, &mut storage, primary_peer(), prepare(1, 0));
  // A Commit would normally advance commit. Dropped.
  r.handle_message(
    now,
    &mut storage,
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
    r.status(),
    Status::RecoveringHead,
    "no message pulled it out of RecoveringHead"
  );
  assert_eq!(r.view(), View::new(), "view unchanged (no catch-up)");
  assert!(
    r.poll_message().is_none(),
    "RecoveringHead casts no ack/vote on non-head-learning messages"
  );
}

// ── a recovered replica must NOT resume as the established primary ──

#[test]
fn recovered_primary_abdicates_to_a_view_change_instead_of_resuming_normal() {
  // A replica that was the PRIMARY of its restored view (log_view == view, replica_count > 1) must
  // NOT resume Normal with an empty pipeline (which would freeze commit at checkpoint_op and risk
  // re-executing a retried request). Per TigerBeetle replica.zig open(), it abdicates: forces a
  // view change to view+1. Replica 0 is primary of view 0; the root names view 0 / log_view 0.
  let wal = wal_in_view(2, 0);
  let sb = sb_with_view(0, 0);
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  for _ in 0..16 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::ViewChange,
    "a recovered primary abdicates (ViewChange), never resumes Normal with an empty pipeline"
  );
  assert_eq!(
    r.view(),
    View::with(1),
    "abdication forces the NEXT view (view + 1)"
  );
  // Drain the abdication's own view-change traffic (StartViewChange etc.) — it is NOT request service.
  while r.poll_message().is_some() {}
  // The double-execute hazard is closed: a fresh client request is NOT served while not Normal —
  // no Prepare to backups, no Reply to the client (on_request returns early on status != Normal).
  r.handle_message(
    now,
    &mut storage,
    Peer::Client(ClientId::new(7)),
    client_request(1),
  );
  while let Some(out) = r.poll_message() {
    let m = out.into_msg();
    assert!(
      !matches!(m, Message::Prepare(_) | Message::Reply(_)),
      "an abdicating recovered primary serves no request: neither Prepare nor Reply, got {m:?}"
    );
  }
}

#[test]
fn recovered_backup_resumes_normal_unchanged() {
  // A replica that is NOT the primary of its restored view resumes Normal (unchanged behaviour).
  // Replica 1 of 3 in view 0 is a backup (primary of view 0 is replica 0).
  let wal = wal_in_view(2, 0);
  let sb = sb_with_view(0, 0);
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  for _ in 0..16 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "a recovered backup resumes Normal (it waits for the primary's Prepare/Commit)"
  );
  assert_eq!(
    r.view(),
    View::new(),
    "a recovered backup does not advance the view"
  );
  assert_eq!(r.op(), OpNumber::with(2));
}

#[test]
fn recovered_mid_view_change_redrives_the_in_progress_view_change() {
  // log_view < view: the durable view advanced (a view change was in progress) but the new log was
  // not yet installed. On recovery the replica re-drives VC(view) — it enters ViewChange AT `view`
  // (not view+1, not Normal). Root names view 1 / log_view 0; replica 2 of 3 (a backup of view 1).
  let wal = wal_in_view(2, 0);
  let sb = sb_with_view(1, 0);
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  for _ in 0..16 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::ViewChange,
    "a replica that crashed mid-view-change re-drives the view change (ViewChange)"
  );
  assert_eq!(
    r.view(),
    View::with(1),
    "it re-drives the SAME in-progress view (log_view < view → VC at view, not view+1)"
  );
}

#[test]
fn recovered_solo_primary_resumes_normal_and_commits_its_tail() {
  // A solo cluster (replica_count == 1) is always its own primary and CANNOT view-change (no peer
  // quorum) — it must resume Normal, NOT abdicate (which would deadlock). It must also still make
  // progress: the recovered tail (ops the solo primary committed pre-crash, above the last
  // checkpoint) re-commits from the rebuilt pipeline rather than stalling on an empty inflight.
  let wal = wal_in_view(2, 0);
  let sb = sb_with_view(0, 0);
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(1),
    0,
    CountSm::default(),
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  for _ in 0..16 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "a solo replica resumes Normal (it cannot view-change)"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the solo primary re-commits its recovered tail (no stall on an empty inflight)"
  );
  // A RETRY of an already-re-committed request is DEDUPED, not re-executed: the apply-time session
  // update advanced the watermark to the recovered tail's request 2, so request 1 is stale (the
  // at-most-once guarantee holds across the crash — no duplicate op is minted).
  r.handle_message(
    now,
    &mut storage,
    Peer::Client(ClientId::new(7)),
    client_request(1),
  );
  for _ in 0..4 {
    r.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "a duplicate of a recovered-and-re-committed request mints no new op"
  );
  // And it still serves the genuinely-NEXT request end-to-end (op 3 commits).
  r.handle_message(
    now,
    &mut storage,
    Peer::Client(ClientId::new(7)),
    client_request(3),
  );
  for _ in 0..4 {
    r.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "a solo primary still commits a NEW request after recovery"
  );
}

#[test]
fn normal_primary_answers_recovery_with_canonical_response() {
  // A Normal primary answers a peer's Recovery with a RecoveryResponse carrying its canonical
  // log + head + commit, echoing the nonce. (Replica 0 is primary of view 0.)
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    EchoSm,
    u64::MAX,
  );
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Give the primary one committed op so its response is non-trivial.
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"a"),
    )),
  );
  e.storage_step(now, &mut storage, &mut blocks); // own append durable → commit op 1 (quorum 2 in N=3? no)
  while e.poll_message().is_some() {}
  // A peer (replica 2) solicits recovery.
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(2)),
    Message::Recovery(Recovery::new(
      ReplicaId::new(2),
      0x1234,
      crate::Epoch::new(0),
      0,
    )),
  );
  let mut resp = None;
  while let Some(out) = e.poll_message() {
    if let Message::RecoveryResponse(rr) = out.into_msg() {
      resp = Some(rr);
    }
  }
  let rr = resp.expect("Normal primary answers Recovery with a RecoveryResponse");
  assert_eq!(rr.replica(), ReplicaId::new(0), "answered by the primary");
  assert_eq!(rr.nonce(), 0x1234, "the nonce is echoed");
  assert_eq!(rr.op(), OpNumber::with(1), "carries the primary's head");
  assert_eq!(rr.log_slice().len(), 1, "carries the canonical log");
}

#[test]
fn has_inflight_storage_is_true_mid_append_and_false_when_quiesced() {
  // The driver-drain signal: `has_inflight_storage()` is true the moment a votable WAL append is
  // submitted (its `pending`/`appending` entries are live, the completion still owed) and false once
  // `handle_storage` drains that completion (nothing left for the driver to deliver). (Replica 0 is
  // primary of view 0; a single own-vote is below the N=3 quorum of 2, so the drain commits nothing
  // and arms no superblock write — the endpoint is genuinely quiesced afterward.)
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    u64::MAX,
  );
  let mut storage = Storage::new(TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  assert!(
    !e.has_inflight_storage(&storage),
    "a freshly-constructed endpoint owes no storage completion"
  );
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  e.handle_message(
    now,
    &mut storage,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"a"),
    )),
  );
  // Mid-flight: the append was submitted to the WAL but its `Appended` has NOT been drained, so the
  // proto still holds the in-flight `pending`/`appending` entry it owes an own-vote for.
  assert!(
    e.has_inflight_storage(&storage),
    "an outstanding WAL append must report in-flight storage"
  );
  e.storage_step(now, &mut storage, &mut blocks);
  // Drained: `on_wal_done` cleared `pending`/`appending`; the lone own-vote is below quorum so no
  // commit/checkpoint/view write was started — the endpoint owes the driver nothing.
  assert!(
    !e.has_inflight_storage(&storage),
    "after handle_storage drains the completion, no storage op is in flight"
  );
}

#[test]
fn normal_backup_answers_recovery_with_view_only() {
  // A Normal BACKUP answers a Recovery with only its view + echoed nonce (no canonical head):
  // op/commit are 0 and the log is empty. (Replica 2 is a backup of view 0.)
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    u64::MAX,
  );
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)),
    Message::Recovery(Recovery::new(
      ReplicaId::new(1),
      0x5678,
      crate::Epoch::new(0),
      0,
    )),
  );
  let mut rr = None;
  while let Some(out) = e.poll_message() {
    if let Message::RecoveryResponse(r) = out.into_msg() {
      rr = Some(r);
    }
  }
  let rr = rr.expect("a Normal backup also answers a Recovery (view only)");
  assert_eq!(rr.nonce(), 0x5678);
  assert!(
    rr.log_slice().is_empty(),
    "a backup carries no canonical log"
  );
  assert_eq!(rr.op(), OpNumber::new(), "a backup reports no head");
}

#[test]
fn recover_read_ok_with_bad_checksum_does_not_adopt_the_corrupt_body() {
  // The verify chokepoint (spec §3): a ReadOk whose body fails Header::verify is treated as a
  // fault, not adopted. With it as the head and permanently corrupt => RecoveringHead.
  let mut wal = ScriptedWal::with_entries(1);
  wal.script_corrupt_body(OpNumber::with(1)); // ReadOk with a body that fails verify, forever
  let sb = sb_formatted();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "a checksum-failing head body is never adopted"
  );
}

#[test]
fn recover_repairs_a_committed_slot_whose_wal_body_mismatches_the_persisted_header() {
  // CONSENSUS-CRITICAL regression. `recover` blindly re-derived committed ops from
  // the WAL bytes, so an ADOPTED committed slot whose WAL kept a STALE superseded body (a prior-view
  // proposal whose OWN header is internally consistent) was resurrected on crash+recover → the
  // recovered replica diverged. The fix: the durable `VsrState` carries the CANONICAL `vsr_headers`
  // for the committed band `(checkpoint_op .. commit]`, and `recover` cross-checks each committed-band
  // WAL slot's body against the persisted canonical `body_checksum`. A MISMATCH is routed to
  // peer-repair (the peer fault-repair path) instead of being trusted — the canonical body is fetched from a peer.
  //
  // Setup: replica 1 of 3. Durable root: view 0, commit 2, checkpoint_op 0, with canonical headers
  // recording op 1 = body [1] and op 2 = body [2] (bodyY). The WAL holds op 1 = [1] (canonical) but
  // op 2 = [0xBB] (bodyX — STALE), with a SELF-CONSISTENT header for [0xBB] (so plain `Header::verify`
  // passes — the stale-body hazard). Op 3 = [3] sits above the committed band (uncommitted tail).
  let canonical_op1 = Header::new(
    OpNumber::with(1),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(1),
    &[1u8],
  );
  // op 2's CANONICAL header records body [2]; this is what the durable root persists (vsr_headers).
  let canonical_op2 = Header::new(
    OpNumber::with(2),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(2),
    &[2u8],
  );
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2), // commit
    OpNumber::new(),   // checkpoint_op
    0,
    std::vec![canonical_op1, canonical_op2],
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };

  // The WAL: ops 1 + 3 canonical, but op 2 holds the STALE body [0xBB] with a header self-consistent
  // for [0xBB] (a superseded prior-view proposal the WAL never re-wrote on adoption).
  let mut wal = ScriptedWal::with_entries(3);
  let stale_body = Bytes::copy_from_slice(&[0xBBu8]);
  let stale_header = Header::new(
    OpNumber::with(2),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(2),
    &stale_body,
  );
  assert!(
    stale_header.verify(&stale_body),
    "the stale slot is SELF-CONSISTENT (its own header matches its own body) — plain verify passes"
  );
  wal.entries.insert(2, (stale_header, stale_body));

  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  for _ in 0..32 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  // The stale committed slot was DETECTED (canonical-header mismatch) and DROPPED — never adopted. The
  // replica returns to Normal (op 2 is below the head 3, so it peer-repairs rather than RecoveringHead).
  assert_eq!(
    r.status(),
    Status::Normal,
    "a stale committed slot is dropped + peer-repaired (not stranded, not RecoveringHead)"
  );
  assert!(
    !r.log.contains_key(&2),
    "the stale slot is dropped from the in-memory log so it can never be applied with the stale body"
  );
  // Recovery did not apply anything yet (commit_min == checkpoint_op == 0); the stale body [0xBB] was
  // never applied.
  assert!(
    r.state_machine_ref().applied().is_empty(),
    "nothing applied yet — the stale body [0xBB] is never re-derived from the WAL"
  );

  // The primary announces commit=2. advance_commit reaches op 2, finds the HOLE, HOLDS the commit at 1
  // (only op 1 applies), and solicits op 2 via RequestPrepare (on-demand peer-repair).
  r.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "commit HELD below the stale-detected hole — op 2's canonical body is not yet present"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "op 2 is registered as a repair hole once commit reaches it (on demand)"
  );
  let mut asked_for_2 = false;
  while let Some(out) = r.poll_message() {
    // The hole arm solicits the contiguous run via the windowed `RequestPrepareRange` (a single-op
    // range `[2,2]` here) rather than a per-op `RequestPrepare`.
    if let Message::RequestPrepareRange(rp) = out.into_msg()
      && rp.lo() <= OpNumber::with(2)
      && rp.hi() >= OpNumber::with(2)
    {
      asked_for_2 = true;
    }
  }
  assert!(
    asked_for_2,
    "the replica solicits the canonical op 2 from a peer"
  );

  // A committed-vouching peer answers with the CANONICAL op 2 (body [2], commit=2 >= op 2). This fills
  // the hole and resumes the held commit: op 2 applies with [2] (bodyY), NEVER [0xBB] (bodyX). The fill
  // is a durability barrier: complete the repaired append before the commit resumes.
  r.handle_message(now, &mut storage, primary_peer(), repair_prepare(0, 2, 2));
  r.storage_step(now, &mut storage, &mut blocks); // the repaired append completes → apply + resume
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the canonical op 2 fills the hole → the held commit resumes"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[(1, std::vec![1u8]), (2, std::vec![2u8])],
    "the applied band is CANONICAL ([1],[2]) — the stale WAL body [0xBB] was never resurrected \
     (FAIL-BEFORE: the old recover trusted the WAL and applied [0xBB], diverging)"
  );
  // The repaired canonical op 2 is durably (re)appended, so a subsequent restart reads it cleanly.
  let (h2, b2) = storage
    .wal_mut()
    .entries
    .get(&2)
    .expect("op 2 present after repair");
  assert_eq!(
    b2.as_ref(),
    &[2u8],
    "the WAL slot now holds the CANONICAL body [2]"
  );
  assert_eq!(h2.body_checksum(), canonical_op2.body_checksum());
}

#[test]
fn recover_drops_a_known_committed_op_above_the_persisted_header_prefix() {
  // CONSENSUS-CRITICAL regression. After the durable `VsrState` began persisting the
  // KNOWN-committed frontier `commit_max`, but `committed_band_headers` is only the CONTIGUOUS canonical
  // prefix above the checkpoint — so when a repair hole sits below `commit_max`, the committed-band ops
  // ABOVE the header prefix (but `<= commit_max`) carry NO canonical header. The recover cross-check must
  // NOT trust such an op's local self-verifying WAL body (it can be a STALE earlier-view body that
  // checksum-verifies); a known-committed op without a header is UNPROVEN and must be peer-repaired.
  //
  // Setup: replica 1 of 3. Durable root: view 0, commit (= commit_max) 2, checkpoint_op 0, with canonical
  // headers covering ONLY op 1 (body [1]) — the header prefix stops at op 1; op 2 is `<= commit 2` but
  // ABOVE the prefix (no header). The WAL holds op 1 = [1] (canonical, header-matched) and op 2 = [0xBB]
  // STALE with a SELF-CONSISTENT header (plain `Header::verify` passes — the exact bait). Op 3 = [3] is the
  // uncommitted tail (current generation, kept).
  let canonical_op1 = Header::new(
    OpNumber::with(1),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(1),
    &[1u8],
  );
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2), // commit == commit_max (durable known-committed frontier)
    OpNumber::new(),   // checkpoint_op
    0,
    std::vec![canonical_op1], // headers cover ONLY op 1 — op 2 is above the prefix, no header
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };

  let mut wal = ScriptedWal::with_entries(3);
  // op 1: canonical [1] (matches its header). op 3: canonical [3] (uncommitted tail). op 2: STALE [0xBB]
  // with a self-consistent header — the false-ack/false-apply bait the recovery cross-check must reject.
  let stale_body = Bytes::copy_from_slice(&[0xBBu8]);
  let stale_header = Header::new(
    OpNumber::with(2),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(2),
    &stale_body,
  );
  assert!(
    stale_header.verify(&stale_body),
    "the stale op-2 slot is self-consistent"
  );
  wal.entries.insert(2, (stale_header, stale_body));

  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  for _ in 0..32 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(r.status(), Status::Normal);
  // op 1 (header-matched) is kept; op 2 (known-committed but NO header) is DROPPED — never trusted from
  // the local WAL. FAIL-BEFORE: op 2 had `rec.canonical.get(2) == None` and `2 > durable_commit` was FALSE,
  // so it fell through to `Verified` and the stale [0xBB] was adopted into `self.log` + later applied.
  assert!(r.log.contains_key(&1), "op 1 (header-matched) is kept");
  assert!(
    !r.log.contains_key(&2),
    "op 2 is a known-committed op above the header prefix → dropped (not trusted from the stale WAL)"
  );

  // The primary announces commit=2. advance_commit applies op 1 ([1]), HOLDS at the op-2 hole, solicits it.
  r.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "commit HELD below the op-2 hole"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "op 2 is a repair hole, peer-repaired on demand"
  );

  // A committed-vouching peer answers with the CANONICAL op 2 (body [2], commit=2 >= op 2). The fill is
  // a durability barrier: complete the repaired append before the commit resumes.
  r.handle_message(now, &mut storage, primary_peer(), repair_prepare(0, 2, 2));
  r.storage_step(now, &mut storage, &mut blocks); // the repaired append completes → apply + resume
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the canonical op 2 fills the hole"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[(1, std::vec![1u8]), (2, std::vec![2u8])],
    "the applied band is CANONICAL ([1],[2]) — the stale WAL body [0xBB] was never applied \
     (FAIL-BEFORE: recover trusted the header-less committed op 2 and applied [0xBB], diverging)"
  );
}

#[test]
fn recover_keeps_a_locally_held_committed_op_above_a_lower_headerless_hole() {
  // CONSENSUS-CRITICAL regression completing the known-commit / durable-frontier fix chain. The
  // guard that drops every known-committed op (`op <= commit_max`) lacking a persisted canonical
  // header was over-broad: while the persisted band was only the CONTIGUOUS prefix above the checkpoint,
  // a SINGLE lower repair hole made all LATER committed ops header-less too — so recover deleted
  // LOCALLY-HELD canonical copies of committed ops the rule was never meant to touch. When this replica
  // was the quorum intersection for those ops (their only surviving copies), peer-repair could not vouch
  // them → the committed tail WEDGES or is LOST.
  //
  // The fix persists a SPARSE canonical header for EVERY committed-band op this replica HOLDS (skipping
  // holes), so recover verifies each held committed op individually (keep canonical) and only
  // peer-repairs ops it genuinely did NOT hold at write time.
  //
  // Setup: replica 1 of 3. Durable root: view 0, commit (= commit_max) 4, checkpoint_op 0, with SPARSE
  // canonical headers for ops 1, 3, 4 (op 2 is SKIPPED — it was a hole when the root was written). The
  // WAL HOLDS canonical op 1 = [1], op 3 = [3], op 4 = [4] (each header-matched), but op 2 reads back
  // PERMANENTLY FAULTY → a lower header-less HOLE. op 3 and op 4 sit ABOVE that hole yet are `<= commit
  // 4` (known committed) and are the canonical copies THIS replica holds — they MUST be KEPT.
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(4), // commit == commit_max (durable known-committed frontier)
    OpNumber::new(),   // checkpoint_op 0
    0,
    std::vec![mk(1), mk(3), mk(4)], // SPARSE: op 2 is a hole, skipped — ops 1,3,4 are held canonical
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  // The sparse band is recorded VERBATIM (op 2's gap is allowed); FAIL-BEFORE the contiguous `try_new`
  // truncated this to just [op 1], so ops 3 + 4 lost their canonical headers.
  assert_eq!(
    state
      .committed_headers_slice()
      .iter()
      .map(|h| h.op().get())
      .collect::<std::vec::Vec<_>>(),
    std::vec![1, 3, 4],
    "the durable root records a SPARSE canonical header for every HELD committed op (op 2 skipped)"
  );

  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  // The WAL: ops 1, 3, 4 canonical (header-matched); op 2's slot reads back permanently faulty → a hole.
  let mut wal = ScriptedWal::with_entries(4);
  wal.script_read_fault(OpNumber::with(2), u8::MAX);
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovers to Normal (the faulty op 2 is below the head 4 → peer-repair, not RecoveringHead)"
  );
  // THE CRUX: the locally-held canonical ops 3 + 4 above the lower header-less hole are KEPT —
  // each verified individually against its SPARSE canonical header. (FAIL-BEFORE: the contiguous header
  // prefix stopped at op 1, so ops 3 + 4 were header-less, `op <= commit_max` fired the over-broad drop rule, and
  // recover DROPPED them — destroying this replica's only surviving copies of the committed tail.)
  assert!(
    r.log
      .get(&3)
      .is_some_and(|e| e.body.as_present() == Some(&[3u8][..])),
    "op 3 (held canonical, sparse-header-matched) is KEPT with its canonical body \
     (FAIL-BEFORE: dropped as a header-less committed op above the lower hole)"
  );
  assert!(
    r.log
      .get(&4)
      .is_some_and(|e| e.body.as_present() == Some(&[4u8][..])),
    "op 4 (held canonical, sparse-header-matched) is KEPT with its canonical body \
     (FAIL-BEFORE: dropped as a header-less committed op above the lower hole)"
  );
  assert!(r.log.contains_key(&1), "op 1 (header-matched) is kept");
  assert!(
    !r.log.contains_key(&2),
    "op 2 is the genuine hole (no sparse header, read back faulty) → dropped + peer-repaired"
  );
  assert_eq!(
    r.commit_max(),
    OpNumber::with(4),
    "recover carries the durable known-committed frontier (commit_max == 4)"
  );
  while r.poll_message().is_some() {} // discard recovery chatter
  while r.poll_event().is_some() {}

  // The primary announces commit=4. advance_commit applies op 1 ([1]), HOLDS at the op-2 hole, solicits
  // op 2 (the ONE op this replica did not hold). It must NOT skip op 2 to apply the held 3 + 4.
  r.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(4),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "commit HELD below the op-2 hole — the in-order apply never skips the missing op"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "op 2 (the only NOT-held committed op) is the repair hole, peer-repaired on demand"
  );

  // A committed-vouching peer supplies the CANONICAL op 2 (body [2], commit=4 >= op 2). This fills the
  // ONE hole and resumes the held commit straight through the LOCALLY-HELD ops 3 + 4 — the committed
  // tail (op 3 / op 4) was never lost. The fill is a durability barrier: complete the repaired
  // append before the commit resumes.
  r.handle_message(now, &mut storage, primary_peer(), repair_prepare(0, 2, 4));
  r.storage_step(now, &mut storage, &mut blocks); // the repaired append completes → apply the held suffix
  assert_eq!(
    r.commit(),
    OpNumber::with(4),
    "the single repaired op 2 lets the held commit resume through the retained ops 3 + 4 to op 4"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[
      (1, std::vec![1u8]),
      (2, std::vec![2u8]),
      (3, std::vec![3u8]),
      (4, std::vec![4u8]),
    ],
    "the FULL canonical band 1,2,3,4 applied — ops 3 + 4 came from this replica's RETAINED copies \
     (FAIL-BEFORE: ops 3 + 4 were dropped on recover, no peer held them, and the committed tail \
     was permanently lost / the commit wedged)"
  );
}

#[test]
fn recover_reads_the_deep_tail_when_a_mid_tail_read_resolves_only_via_timeout() {
  // A deep held committed tail must be fully read even when one of its slots resolves ONLY through the
  // TIMEOUT path — a dropped/faulty read that exhausts its retry budget in `recover_timeouts`
  // (`resolve_exhausted_tail_read`) rather than a clean `on_recover_wal_done` completion. The single-pass
  // read window submits the whole `(checkpoint_op .. hi]` at once, so a slot stuck on the timeout path is
  // kept header-only as `Repairing` and never clips the ops above it. Here a mid-tail op faults on EVERY
  // read (resolving only via exhaustion); recovery still settles at the verified tail K.
  let k = RECOVER_TAIL_WINDOW + 2;
  let top = RECOVER_TAIL_WINDOW; // a mid-tail op forced onto the timeout drain path
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let headers: std::vec::Vec<Header> = (1..=k).map(mk).collect();
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(k),
    OpNumber::new(),
    0,
    headers,
  )
  .unwrap()
  .with_wal_geometry(crate::MAX_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(k);
  // The first-batch top op faults on every read → its ONLY resolution is budget exhaustion in the
  // timeout path (never a clean `on_recover_wal_done`), so the batch drains WITHOUT that op's completion.
  wal.script_read_fault(OpNumber::with(top), u8::MAX);
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), crate::MAX_CHECKPOINT_OPS).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(r.status(), Status::Recovering);
  // Drive storage drains + the recover-retry timer past the per-op budget: the faulty top op exhausts and
  // the continuation (from the timeout path) extends to the second batch, which reads K.
  let mut t = now;
  for _ in 0..(RECOVER_READ_RETRIES as usize + 20) {
    r.storage_step(t, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
    if let Some(deadline) = r.poll_timeout() {
      t = deadline;
      r.handle_timeout(t, &mut storage);
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovery completes even though the first batch drained through the timeout path"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(k),
    "the continuation fired on the TIMEOUT path — the held tail up to K is read, not clipped at the first batch"
  );
  assert!(
    r.log
      .get(&k)
      .is_some_and(|e| e.body.as_present() == Some(&[k as u8][..])),
    "the committed op K above the first batch is read + cached (the continuation reached it)"
  );
}

#[test]
fn recover_carries_a_faulting_interior_op_above_a_stale_commit_max_not_dropped_as_head() {
  // A faulting op above a STALE `commit_max` must NOT be dropped as the non-committed HEAD when it is
  // actually INTERIOR (written ops sit above it). `resolve_exhausted_tail_read` keeps EVERY placement-valid
  // durable header as `Repairing` — it does not decide head-vs-interior — and `recover_progress`, once the
  // VERIFIED head is known, promotes to `RecoveringHead` ONLY the real head. So an interior faulting op is
  // CARRIED header-only into `self.log` / a later DoViewChange (its number taken, never re-minted), even
  // though it sits above the stale `commit_max`. With a STALE durable commit (commit_max == 0 below the held
  // tail — the between-checkpoints lag), a mid-tail op faults on every read (resolving ONLY via the timeout
  // path) while ops above it are present.
  //
  // FAIL-BEFORE: the faulting op, being above the stale `commit_max`, was routed to `rec.faulty` → dropped
  // from the log → omitted from the DVC → a truncatable committed loss.
  let k = RECOVER_TAIL_WINDOW + 2;
  let top = RECOVER_TAIL_WINDOW; // a mid-tail op forced onto the timeout path
  // STALE durable commit: commit == checkpoint_op == 0 with an EMPTY committed band — ops 1..=K are HELD in
  // the WAL but their commit is not yet durable (the between-checkpoints lag), so the root vouches nothing.
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::new(),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
  )
  .unwrap()
  // FORMATTED-empty root recording this test's geometry (a `MAX_CHECKPOINT_OPS` config over a ring-less
  // WAL), so recovery's geometry fence matches and this voter recovers rather than empty-fail-stops.
  .with_wal_geometry(crate::MAX_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(k);
  wal.script_read_fault(OpNumber::with(top), u8::MAX);
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), crate::MAX_CHECKPOINT_OPS).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  let mut t = now;
  for _ in 0..(RECOVER_READ_RETRIES as usize + 20) {
    r.storage_step(t, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
    if let Some(deadline) = r.poll_timeout() {
      t = deadline;
      r.handle_timeout(t, &mut storage);
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "the head above the faulting boundary is present → Normal (not RecoveringHead)"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(k),
    "the tail above the faulting boundary is read — self.op == K"
  );
  // THE fix: the faulting batch-boundary op is CARRIED header-only (Repairing), NOT dropped as an interior
  // gap — even though it faulted while at the provisional frontier and sits above the stale commit_max.
  let entry = r
    .log
    .get(&top)
    .expect("the faulting batch-boundary op is CARRIED, not dropped from the log");
  assert!(
    matches!(entry.body, Body::Repairing(_)),
    "carried header-only as Body::Repairing (its number taken, body peer-repaired on demand)"
  );
}

#[test]
fn recovering_head_drops_the_uncommitted_faulty_head_but_keeps_a_committed_interior_repairing() {
  // The deferred faulty-HEAD promotion must make the head NOT HELD, not merely route it to `rec.faulty`:
  // `drop_faulty_committed_slots` KEEPS `Repairing` entries (committed body-repairs), so a head left in
  // `self.log` survives as an ordinary entry and a later reformation (which clears `recover` before
  // ViewChange) carries it into a DoViewChange/StartView — advertising an uncommitted head this replica
  // cannot vouch. A COMMITTED interior op whose body faulted is the CONTRAST: it stays held (`Repairing`)
  // and IS carried. Setup: commit == 2 (op 2 committed, op 4 the uncommitted head), WAL holds 1..=4; op 2
  // (interior) and op 4 (head) both fault their reads permanently.
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2), // commit == 2
    OpNumber::new(),   // checkpoint_op 0
    0,
    std::vec![mk(1), mk(2)], // committed band 1..=2 (canonical headers matching the WAL)
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(4);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // committed interior body faults permanently
  wal.script_read_fault(OpNumber::with(4), u8::MAX); // uncommitted HEAD body faults permanently
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "the uncommitted faulty head → RecoveringHead"
  );
  // THE fix: the uncommitted faulty head (op 4) is NOT HELD — removed from the log so no reformation
  // DoViewChange/StartView can advertise it.
  assert!(
    !r.log.contains_key(&4),
    "the promoted uncommitted faulty head is NOT held (removed from the log)"
  );
  // CONTRAST: the committed interior op (op 2), body-faulted, stays HELD as `Repairing` — carried into a
  // view change (its number taken; body peer-repaired on demand), never dropped.
  assert!(
    matches!(r.log.get(&2).map(|e| &e.body), Some(Body::Repairing(_))),
    "the committed interior faulty op is KEPT header-only as Repairing (held, carried)"
  );
}

#[test]
fn a_peer_checkpoint_after_a_phantom_tail_completes_recovery_at_the_verified_head() {
  // The recovery EXIT INVARIANT at the peer-checkpoint escape (`on_recover_sync_checkpoint`): recovery
  // must never leave the read phase with `self.op` still the PROVISIONAL read-window top — which, under
  // an over-counted / bit-rotted `op_head`, includes a phantom suffix this replica never wrote (an
  // unheld head a later Prepare would blind-re-ack and a DVC would falsely advertise). This pins BOTH
  // halves of that guarantee: (1) the schedule property — the reply ingress is gated on
  // `awaiting_peer_checkpoint`, and by the time it is armed the phantom band has resolved ABSENT and the
  // head has SETTLED at the verified frontier (asserted below as pending-empty + head-already-capped at
  // reply time; the sync path re-runs the settle choke anyway, so the invariant holds by construction
  // even if a future escalation lane arms `awaiting` with reads still pending); and (2) the end-to-end
  // outcome — the sync completes to Normal at the VERIFIED head, the phantom band discarded.
  //
  // Setup: a checkpoint at op 2 whose own snapshot read faults permanently (escalating to the peer
  // fetch); a BOUNDED ring (capacity 38 → scan probe bound 2 + 38 = 40) whose real slots end at op 4
  // and whose `op_head` scalar is bit-rotted to u64::MAX — the durable-header scan finds the true
  // frontier 4, so the phantom band above it is never materialized nor read.
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
  .unwrap()
  .with_wal_geometry(2, 38);
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new()); // empty → every checkpoint read faults
  let mut wal = ScriptedWal::with_entries(4); // real slots end at op 4
  wal.head = u64::MAX; // a bit-rotted head scalar
  wal.capacity = 38; // a BOUNDED ring → the read ceiling is checkpoint 2 + 38 = 40
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(e.status(), Status::Recovering);
  assert_eq!(
    e.op(),
    OpNumber::with(4),
    "the provisional head is the scanned written frontier — the phantom band is never materialized"
  );
  // Drain the tail reads + exhaust the checkpoint budget → the peer fetch. The head settles at the
  // verified frontier as soon as the tail drains — well before the reply.
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "own checkpoint exhausted → fetching from a peer"
  );
  // The schedule half of the exit invariant: by the time a reply is admissible (awaiting == true), the
  // tail has fully resolved and the head has ALREADY settled at the verified frontier.
  assert!(
    e.recover.as_ref().is_some_and(|rec| rec.pending.is_empty()),
    "every tail read resolved before the peer reply is admissible"
  );
  assert_eq!(
    e.op(),
    OpNumber::with(4),
    "the head settled at the verified frontier before the reply — the phantom band is not held"
  );
  while e.poll_message().is_some() {}

  // A peer answers with a VALID SyncCheckpoint (op 2, the genuine snapshot, matching nonce) while the
  // phantom read is still in flight.
  let good_snap = CountSm::default().snapshot();
  let good_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    crate::block_address(&good_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let good_id = crate::checkpoint_id(&good_env);
  blocks.put(good_snap.clone());
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      good_env.clone(),
      Bytes::new(),
    )),
  );
  for _ in 0..3 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "the verified peer checkpoint completes recovery"
  );
  // THE fix: the head settled at the highest WRITTEN op before the install — the phantom band is NOT
  // held into Normal.
  assert_eq!(
    e.op(),
    OpNumber::with(4),
    "the settle choke caps the head to the verified frontier before the install"
  );
  assert!(
    e.log.contains_key(&4),
    "the real tail op 4 is held; the phantom band above it is discarded"
  );
}

#[test]
fn a_staged_sync_install_with_an_untruthed_head_completes_to_recovering_head_not_normal() {
  // The peer-checkpoint escape × un-truthed head: the `awaiting_peer_checkpoint` gate in
  // `recover_progress` sits BEFORE its faulty-head → `RecoveringHead` decision, and the escape
  // (`on_recover_sync_checkpoint`) clears `recover` at staging — so without the carried verdict, a
  // permanently-faulty (occupied-but-unidentifiable) HEAD rides the staged install into `Normal`,
  // holding an op with no identity anywhere: a later `Prepare` for it would be blind-re-acked
  // (append-before-ack broken) and the DoViewChange would advertise an unheld head. The carried
  // verdict resumes the preempted decision at the install completion: `RecoveringHead`, soliciting the
  // canonical head, and a peer's `RecoveryResponse` adopts back to Normal — never a silent unheld head,
  // never a wedge.
  //
  // The triple fault: (1) the head slot's durable header bit-rotted in its `op` field — occupied
  // (occupancy-scanned into the window) but unidentifiable (placement fails, `verify_header` fails, and
  // the root's canonical band stops below it, so no witness anywhere) with its reads faulting to
  // exhaustion → `rec.faulty`; (2) the own checkpoint snapshot is permanently unreadable → the peer
  // fetch (`awaiting_peer_checkpoint`), whose gate preempts the head decision; (3) a peer serves the
  // checkpoint (M == 2 < the head), which must NOT subsume the verdict.
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
  .unwrap()
  .with_wal_geometry(2, u64::MAX);
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new()); // empty → every checkpoint read faults
  let mut wal = ScriptedWal::with_entries(6);
  let (clean, body) = wal.entries.get(&6).cloned().expect("head entry");
  let mut rotted = clean.encode();
  rotted[47] ^= 0xFF; // rot the op field — occupied, but no placement/checksum/root witness
  let rotted = Header::decode(&rotted).expect("decode does not re-validate the checksum");
  wal.entries.insert(6, (rotted, body));
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // Exhaust both budgets: the unidentifiable head lands in `rec.faulty`; the checkpoint escalates to
  // the peer fetch. The awaiting gate holds recovery open BEFORE the faulty-head decision.
  drive_recovery_scripted_sb(&mut r, &mut storage, &mut blocks, now);
  assert!(
    r.awaiting_peer_checkpoint_for_test(),
    "own checkpoint exhausted → fetching from a peer, the head decision preempted"
  );
  while r.poll_message().is_some() {}

  // A peer answers with a VALID SyncCheckpoint (op 2, genuine snapshot, matching nonce) — the escape
  // stages the install, carrying the un-truthed-head verdict.
  let good_snap = CountSm::default().snapshot();
  let good_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    crate::block_address(&good_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let good_id = crate::checkpoint_id(&good_env);
  blocks.put(good_snap.clone());
  let nonce = r.sync_nonce_for_test();
  r.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      good_env.clone(),
      Bytes::new(),
    )),
  );
  for _ in 0..3 {
    storage.sb_mut().flush();
    r.storage_step(now, &mut storage, &mut blocks);
  }
  // THE fix: the install completed (checkpoint 2 durable + restored) but the un-truthed head (6 > 2)
  // resumes the preempted decision — RecoveringHead, not Normal.
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "an un-truthed head survives the staged install → RecoveringHead, never Normal holding an unheld op"
  );
  assert_eq!(
    r.checkpoint_op(),
    OpNumber::with(2),
    "the peer checkpoint IS installed (the SM was locally unrestorable)"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(6),
    "the head stays at the written extent while the canonical head is solicited"
  );
  assert!(
    !r.log.contains_key(&6),
    "no identity is fabricated for the un-truthed head"
  );
  // The exit: the replica solicits the canonical head; the primary's RecoveryResponse re-establishes
  // it and adoption returns to Normal — the wedge-free completion.
  let mut nonce = 0;
  while let Some(out) = r.poll_message() {
    if let Message::Recovery(rec) = out.into_msg() {
      nonce = rec.nonce();
    }
  }
  assert_ne!(nonce, 0, "RecoveringHead solicited the canonical head");
  let resp = RecoveryResponse::new(
    View::new(),
    OpNumber::with(6),
    OpNumber::with(6),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    nonce,
    (3..=6u64)
      .map(|op| {
        PreparedEntry::new(
          OpNumber::with(op),
          ClientId::new(7),
          RequestNumber::with(op),
          bytes::Bytes::copy_from_slice(&[op as u8]),
        )
      })
      .collect(),
  );
  r.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::RecoveryResponse(resp),
  );
  assert_eq!(
    r.status(),
    Status::Normal,
    "the primary's canonical head re-establishes the replica — adopted back to Normal"
  );
  assert_eq!(r.op(), OpNumber::with(6), "the canonical head is adopted");
}

#[test]
fn the_flush_retry_staging_lane_carries_the_faulty_verdicts_too() {
  // The SECOND staging lane: the escape's first durability barrier FAULTS (a transient block-store
  // flush fault), so `apply_sync` stages nothing — `pending_checkpoint` stays `None`, the escape's
  // staging chokepoint is skipped, and `recover` (with the faulty verdicts) survives into the retry
  // cadence. `recover_timeouts` → `retry_install_flush` later re-flushes and stages LOCALLY, and ITS
  // teardown must run the SAME carry — a bare teardown there would drop the verdicts and the install
  // completion would flip Normal at the un-truthed head, the exact escape this branch closes, reopened
  // by one transient disk fault.
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
  .unwrap()
  .with_wal_geometry(2, u64::MAX);
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new()); // empty → every checkpoint read faults
  let mut wal = ScriptedWal::with_entries(6);
  let (clean, body) = wal.entries.get(&6).cloned().expect("head entry");
  let mut rotted = clean.encode();
  rotted[47] ^= 0xFF; // rot the op field — occupied, but no witness anywhere
  let rotted = Header::decode(&rotted).expect("decode does not re-validate the checksum");
  wal.entries.insert(6, (rotted, body));
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery_scripted_sb(&mut r, &mut storage, &mut blocks, now);
  assert!(
    r.awaiting_peer_checkpoint_for_test(),
    "own checkpoint exhausted → fetching from a peer"
  );
  while r.poll_message().is_some() {}

  // The peer answers — but the FIRST flush barrier faults, so the escape stages nothing and `recover`
  // (with the un-truthed-head verdict) survives into the retry cadence.
  let good_snap = CountSm::default().snapshot();
  let good_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    crate::block_address(&good_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let good_id = crate::checkpoint_id(&good_env);
  blocks.put(good_snap.clone());
  blocks.script_flush_fault(1); // the escape's durability barrier faults; the retry's succeeds
  let nonce = r.sync_nonce_for_test();
  r.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      good_env.clone(),
      Bytes::new(),
    )),
  );
  r.storage_step(now, &mut storage, &mut blocks);
  assert!(
    r.install_flush_retry_owed(),
    "the faulted flush retains the verified install for a local retry"
  );
  assert!(
    r.recover.is_some(),
    "the escape staged nothing — recovery bookkeeping (and its verdicts) survive into the retry"
  );
  // The retry cadence re-flushes (now succeeding) and stages locally; its teardown must carry the
  // verdicts exactly as the escape's would have.
  let later = r
    .poll_timeout()
    .expect("the recover-retry cadence stays armed while awaiting");
  r.handle_timeout(later, &mut storage);
  for _ in 0..3 {
    storage.sb_mut().flush();
    r.storage_step(later, &mut storage, &mut blocks);
  }
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "the flush-retry staging lane carries the un-truthed-head verdict — RecoveringHead, not Normal"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(6),
    "the head stays at the written extent while the canonical head is solicited"
  );
  assert!(
    !r.log.contains_key(&6),
    "no identity is fabricated for the un-truthed head"
  );
}

#[test]
fn the_staged_install_carries_every_faulty_verdict_not_just_the_untruthed_head() {
  // The carry across the staged install must be the WHOLE faulty set: the RecoveringHead
  // reform-escalation gate (`committed_band_intact`) refuses same-epoch reformation while any
  // COMMITTED-band faulty slot remains — a committed op this replica cannot vouch would be omitted
  // from its DoViewChange, so escalating could lose it. A head-only carry would rebuild `rec.faulty`
  // as `{head}`, the gate would wrongly see the committed band intact, and an all-restart quorum could
  // reform around the missing committed op.
  //
  // Setup: durable root vouches commit 5 over checkpoint 2 with a canonical band {3, 5} — a GAP at 4
  // (the writer never held it), so the self-verifying WAL slot at 4 is known-committed-but-UNPROVEN →
  // `StaleCommitted` → faulty (an interior committed-band verdict). The head 6 is occupied but
  // unidentifiable (op-field-rotted header, above the band). The own checkpoint snapshot is
  // permanently unreadable → the peer fetch; the peer serves checkpoint 2 (below both verdicts).
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(5),
    OpNumber::with(2),
    0xDEAD_BEEF,
    std::vec![mk(3), mk(5)], // the band has a GAP at 4
  )
  .unwrap()
  .with_wal_geometry(2, u64::MAX);
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new()); // empty → every checkpoint read faults
  let mut wal = ScriptedWal::with_entries(6);
  let (clean, body) = wal.entries.get(&6).cloned().expect("head entry");
  let mut rotted = clean.encode();
  rotted[47] ^= 0xFF; // rot the head's op field — occupied, no witness anywhere
  let rotted = Header::decode(&rotted).expect("decode does not re-validate the checksum");
  wal.entries.insert(6, (rotted, body));
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap(),
    genesis(3),
    5,
    CountSm::default(),
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  let now = Instant::ZERO;
  drive_recovery_scripted_sb(&mut r, &mut storage, &mut blocks, now);
  assert!(
    r.awaiting_peer_checkpoint_for_test(),
    "own checkpoint exhausted → fetching from a peer"
  );
  assert_eq!(
    r.recover
      .as_ref()
      .map(|rec| rec.faulty.iter().copied().collect::<std::vec::Vec<_>>()),
    Some(std::vec![4, 6]),
    "both verdicts settled before the escape: the unproven committed interior AND the un-truthed head"
  );
  while r.poll_message().is_some() {}

  let good_snap = CountSm::default().snapshot();
  let good_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    crate::block_address(&good_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let good_id = crate::checkpoint_id(&good_env);
  blocks.put(good_snap.clone());
  let nonce = r.sync_nonce_for_test();
  r.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      good_env.clone(),
      Bytes::new(),
    )),
  );
  for _ in 0..3 {
    storage.sb_mut().flush();
    r.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "the un-truthed head resumes the preempted decision after the install"
  );
  // THE fix: the re-armed recovery restores EVERY non-subsumed verdict — the reform gate keeps seeing
  // the committed-band faulty slot (4 <= commit_max 5) and refuses same-epoch reformation.
  assert_eq!(
    r.recover
      .as_ref()
      .map(|rec| rec.faulty.iter().copied().collect::<std::vec::Vec<_>>()),
    Some(std::vec![4, 6]),
    "the full faulty set rides the staged install — not just the head"
  );
  assert!(
    !r.log.contains_key(&4) && !r.log.contains_key(&6),
    "no identity is fabricated for either verdict"
  );
}

#[test]
fn recover_reads_a_committed_band_above_the_imposed_ring_on_a_ring_less_wal() {
  // The read ceiling is FLOORED at the durable committed frontier, by LOCAL proof: a ring-less WAL
  // (default `capacity()`) whose durable root vouches a commit ABOVE the proto-imposed ring — a tail no
  // conforming append under the ring enforcement produces, but one the geometry argument alone cannot
  // rule out for an arbitrary disk — still has its FULL committed band read. Without the floor the
  // ceiling would clip `self.op` below the durable commit, hiding held committed ops from `self.log` and
  // the DVC (a committed loss with the bytes intact on disk). The floor is safe against the
  // corrupt-scalar threat: `state.commit()` is checksum-validated and quorum-bounded, so it extends the
  // window only by genuine committed progress.
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let ring = effective_wal_capacity(u64::MAX, cfg.checkpoint_ops());
  let commit_max = ring + 848; // strictly above the imposed ring
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let headers: std::vec::Vec<Header> = (1..=commit_max).map(mk).collect();
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(commit_max), // durable commit above the imposed ring
    OpNumber::new(),            // checkpoint_op 0
    0,
    headers,
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let wal = ScriptedWal::with_entries(commit_max); // ring-less (default capacity), holds 1..=commit_max
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "the ceiling is floored at the durable commit — the full committed band is materialized"
  );
  for _ in 0..(commit_max + 8) {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(r.status(), Status::Normal, "tail consistent → Normal");
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "every held committed op above the imposed ring is read + held — no clip below the durable commit"
  );
  assert!(
    r.log
      .get(&commit_max)
      .is_some_and(|e| e.body.as_present() == Some(&[commit_max as u8][..])),
    "the top committed op is read + cached with its canonical body"
  );
}

#[test]
fn recover_finds_a_committed_tail_above_a_stale_commit_when_the_head_scalar_under_reports() {
  // The hardest under-report shape: a client-acked committed tail lives ABOVE the STALE durable commit
  // (the between-checkpoints lag — `state.commit()` witnesses nothing there) AND the `op_head` scalar is
  // bit-rotted BELOW it, so NO scalar witness covers the band. The durable-header SCAN is what finds it:
  // the ring itself is the witness (`Wal::header` is `Some` exactly for a completed append), so the
  // written extent is derived, every held op is read + held, and this replica's DoViewChange still
  // vouches the client-acked tail — no committed loss from a lying scalar plus a lagging root.
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let held = 600u64; // the written committed tail — within the proto-imposed ring, above every scalar witness
  let mut wal = ScriptedWal::with_entries(held); // holds 1..=600, each header durable
  wal.head = 10; // a corrupt-LOW head scalar, far below the real written extent
  let sb = sb_formatted(); // FORMATTED-empty root: STALE durable commit == checkpoint_op == 0
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(
    r.op(),
    OpNumber::with(held),
    "the scan derives the written extent — neither the lying scalar nor the stale commit hides it"
  );
  for _ in 0..(held + 8) {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(r.status(), Status::Normal, "tail consistent → Normal");
  assert_eq!(
    r.op(),
    OpNumber::with(held),
    "the full written tail is read + held — the DVC vouches the client-acked band"
  );
  assert!(
    r.log
      .get(&held)
      .is_some_and(|e| e.body.as_present() == Some(&[held as u8][..])),
    "the top held op is read + cached with its canonical body"
  );
}

#[test]
fn recover_does_not_skip_a_written_head_whose_header_op_field_rotted() {
  // The scan's occupancy predicate must be `header(probe).is_some()` ALONE: a written top slot whose
  // stored header rotted in its `op` FIELD fails a placement-filtered probe, and a scan that skips it
  // under-derives the extent — the held head (possibly client-acked, and ABOVE the durable root's
  // canonical band, which lags live commit progress between roots) is then never read, silently dropped
  // from `self.log`/the DVC: the committed-loss direction. With occupancy-only the slot bounds the
  // window, its read fails placement/verify and exhausts, the resolver finds no usable witness (rotted
  // header, no canonical entry — the root does not carry the op yet), and the replica conservatively
  // enters `RecoveringHead` to learn the canonical head from a peer — never Normal with the op skipped.
  let held = 6u64;
  let mut wal = ScriptedWal::with_entries(held);
  let (clean, body) = wal.entries.get(&held).cloned().expect("head entry");
  // Rot the header's OP field (canonical layout: checksum | version | op | view | client | request |
  // body_checksum, 16 bytes each — op's low byte is index 47): placement now fails, checksum stale.
  let mut rotted = clean.encode();
  rotted[47] ^= 0xFF;
  let rotted = Header::decode(&rotted).expect("decode does not re-validate the checksum");
  assert_ne!(
    rotted.op(),
    clean.op(),
    "the op field rotted — placement no longer matches"
  );
  wal.entries.insert(held, (rotted, body));
  let sb = sb_formatted(); // formatted-empty root: commit == 0, NO canonical band — the op is above every root witness
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  assert_eq!(
    r.op(),
    OpNumber::with(held),
    "the occupied slot bounds the window — the rotted op field does not shrink the scanned extent"
  );
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::RecoveringHead,
    "an unidentifiable written head is a head fault — solicit the canonical head, never skip the op"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(held),
    "the head stays at the written extent while the canonical head is solicited"
  );
}

#[test]
fn a_committed_head_whose_body_faulty_completion_carries_a_rotted_header_resolves_via_the_root() {
  // The `WalDone::BodyFaulty` variant of the rotted-header case below: the backend reports the body as
  // permanently faulty and hands back the header AS STORED — bit-rotted, `op` field intact (placement
  // passes), stored checksum stale. The BodyFaulty arm must not classify the rotted identity (without
  // the `verify_header` gate the flipped client MISMATCHES the canonical band → StaleCommitted → the
  // committed head lands faulty → `RecoveringHead`, the reform wedge): it falls to the retry path, and
  // on exhaustion the resolver's `verify_header` gate routes it through the ROOT's canonical identity —
  // a committed repair hole, recovery Normal.
  let commit_max = 6u64;
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let canonical_checksum = mk(commit_max).body_checksum();
  let headers: std::vec::Vec<Header> = (1..=commit_max).map(mk).collect();
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(commit_max),
    OpNumber::new(),
    0,
    headers,
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(commit_max);
  let (clean, body) = wal.entries.get(&commit_max).cloned().expect("head entry");
  let mut rotted = clean.encode();
  rotted[79] ^= 0xFF; // flip the client field's low byte — op survives, the checksum goes stale
  let rotted = Header::decode(&rotted).expect("decode does not re-validate the checksum");
  assert!(
    !rotted.verify_header(),
    "the rotted header fails its own checksum"
  );
  wal.entries.insert(commit_max, (rotted, body));
  wal.script_body_faulty(OpNumber::with(commit_max)); // reads answer BodyFaulty(rotted header)
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "the rotted-header BodyFaulty head resolves via the ROOT — not RecoveringHead (the reform wedge)"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "the committed head stays HELD via the root's identity"
  );
  assert_eq!(
    r.log.get(&commit_max).map(|e| &e.body),
    Some(&Body::Repairing(canonical_checksum)),
    "kept as Body::Repairing carrying the ROOT's canonical identity, not the rotted header's"
  );
}

#[test]
fn a_committed_head_with_a_bit_rotted_header_resolves_via_the_root_not_recovering_head() {
  // A durable header can bit-rot with its `op` field INTACT: placement passes, but the stored header
  // checksum no longer matches the canonical fields — the header is no witness. Without the
  // `verify_header` guard the exhaustion resolver would run the rotted identity through the canonical
  // cross-check, MISMATCH (the flipped client), classify the committed head faulty, and enter
  // `RecoveringHead` — the reformation wedge — even though the durable ROOT still vouches the true
  // identity. With the guard, a checksum-failing header is treated exactly like an absent one: the
  // root's canonical band resolves the op to `Body::Repairing` and recovery completes Normal.
  let commit_max = 6u64;
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let canonical_checksum = mk(commit_max).body_checksum();
  let headers: std::vec::Vec<Header> = (1..=commit_max).map(mk).collect();
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(commit_max),
    OpNumber::new(),
    0,
    headers,
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(commit_max);
  // Bit-rot the head's DURABLE HEADER: encode, flip the low byte of the `client` field (canonical
  // layout: checksum | version | op | view | client | request | body_checksum, 16 bytes each — client's
  // low byte is index 79), decode. The `op` field survives (placement passes) but the stored checksum
  // no longer matches the fields.
  let (clean, body) = wal.entries.get(&commit_max).cloned().expect("head entry");
  let mut rotted = clean.encode();
  rotted[79] ^= 0xFF;
  let rotted = Header::decode(&rotted).expect("decode does not re-validate the checksum");
  assert!(
    !rotted.verify_header(),
    "the rotted header fails its own checksum"
  );
  assert_eq!(
    rotted.op(),
    clean.op(),
    "the op field survived the rot (placement still passes)"
  );
  wal.entries.insert(commit_max, (rotted, body));
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "the rotted-header committed head resolves via the ROOT — not RecoveringHead (the reform wedge)"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "the committed head stays HELD via the root's identity"
  );
  assert_eq!(
    r.log.get(&commit_max).map(|e| &e.body),
    Some(&Body::Repairing(canonical_checksum)),
    "kept as Body::Repairing carrying the ROOT's canonical identity, not the rotted header's"
  );
}

#[test]
fn a_root_vouched_committed_head_whose_read_answers_absent_becomes_a_repair_hole() {
  // The ABSENT-verdict twin of the fault-to-exhaustion case below: a backend may report a fully-rotted
  // slot as a clean `WalDone::Absent` rather than faulting the read. The verdict must not depend on
  // which of the two no-slot answers the backend gives: the durable ROOT's canonical band vouches the
  // committed op, so the Absent completion resolves it header-only as `Body::Repairing` from the root's
  // identity — never a phantom to be capped away (which would silently drop the only in-memory identity
  // a later DoViewChange could carry).
  let commit_max = 6u64;
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let canonical_checksum = mk(commit_max).body_checksum();
  let headers: std::vec::Vec<Header> = (1..=commit_max).map(mk).collect();
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(commit_max),
    OpNumber::new(),
    0,
    headers,
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(commit_max);
  wal.entries.remove(&commit_max); // the slot is GONE — its read answers a clean Absent
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "the root-vouched hole completes clean"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "the committed head stays HELD via the root's identity — never capped away as a phantom"
  );
  assert_eq!(
    r.log.get(&commit_max).map(|e| &e.body),
    Some(&Body::Repairing(canonical_checksum)),
    "the Absent completion resolves through the ROOT's canonical identity"
  );
}

#[test]
fn a_poisoned_sealed_commit_does_not_force_an_unbounded_recovery_read() {
  // A corrupt in-model peer `commit` scalar can be adopted into live `commit_max` and then SEALED into
  // a durable root — so the recovery window must NOT floor at the raw `state.commit()` scalar (a dense
  // read to a poisoned frontier would allocate/queue reads without bound at every restart). The floor
  // is the root's canonical BAND top — evidence of what the writer actually held (a poisoned scalar
  // mints no headers) — so recovery reads exactly the held extent, completes Normal, and the poisoned
  // `commit_max` rides above the head as the tail-gap shape the view-change advertisement already
  // bounds (`commit_max.min(op)`).
  let held = 6u64;
  let poisoned_commit = u64::MAX / 2;
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let headers: std::vec::Vec<Header> = (1..=held).map(mk).collect();
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(poisoned_commit), // the sealed poison
    OpNumber::new(),
    0,
    headers, // the band stops at the genuinely-held extent
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let wal = ScriptedWal::with_entries(held);
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  assert_eq!(
    storage.wal_mut().done.len() as u64,
    held,
    "reads are bounded by the band's evidence — the poisoned commit scalar forces nothing"
  );
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovery completes despite the poisoned sealed commit"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(held),
    "the head is the held extent — the poisoned frontier is a tail-gap above it, not a read target"
  );
}

#[test]
fn a_root_vouched_committed_head_with_no_wal_header_becomes_a_repair_hole_not_recovering_head() {
  // A committed op whose WAL slot rotted ENTIRELY — header included — and whose reads fault to
  // exhaustion still has a second durable witness: the ROOT's canonical committed band (`rec.canonical`,
  // from the checksummed `VsrState`) carries its full `(client, request, body_checksum)` identity. The
  // exhaustion resolver falls back to it, keeping the op header-only as `Body::Repairing` (existence +
  // identity preserved; body peer-repaired on demand). Without the fallback the op lands in
  // `rec.faulty`; at the HEAD that drives `RecoveringHead`, and the reform gate refuses same-epoch
  // reformation while a committed faulty slot remains — an all-restart quorum would wedge soliciting a
  // Normal peer that does not exist, despite every root carrying the identity needed to repair.
  //
  // Setup: durable root vouches commit == 6 with dense canonical headers 1..=6; the WAL holds 1..=5
  // (op 6's slot is GONE — `wal.header(6)` is None, so the scan stops at 5 and only the commit floor
  // reaches 6) and every read of op 6 faults (a rotted slot, not a clean absence).
  let commit_max = 6u64;
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let canonical_checksum = mk(commit_max).body_checksum();
  let headers: std::vec::Vec<Header> = (1..=commit_max).map(mk).collect();
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(commit_max),
    OpNumber::new(),
    0,
    headers,
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(commit_max);
  wal.entries.remove(&commit_max); // the committed head's slot — header AND body — rotted away
  wal.script_read_fault(OpNumber::with(commit_max), u8::MAX); // its reads fault, never a clean Absent
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "the root-vouched committed head resolves to a repair hole — NOT RecoveringHead (the reform wedge)"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "the committed head stays HELD (its number taken) via the root's identity"
  );
  assert_eq!(
    r.log.get(&commit_max).map(|e| &e.body),
    Some(&Body::Repairing(canonical_checksum)),
    "kept header-only as Body::Repairing carrying the ROOT's canonical identity"
  );
}

#[test]
fn recover_reads_the_committed_band_when_the_op_head_scalar_under_reports() {
  // The durable-commit floor is INDEPENDENT of the reported head: a corrupt-LOW `op_head` scalar (the
  // symmetric rot of the inflated one the ring caps) must not hide committed slots that are still
  // readable. The WAL holds canonical ops `1..=commit_max` and the durable root vouches
  // `commit == commit_max` (checksummed, quorum-bounded — the trustworthy witness), but the head scalar
  // reports far below it. The window floors at the durable commit, the band reads back present, and the
  // verified head settles at `commit_max` — no committed op is hidden behind the lying scalar.
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let ring = effective_wal_capacity(u64::MAX, cfg.checkpoint_ops());
  let commit_max = ring + 848;
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let headers: std::vec::Vec<Header> = (1..=commit_max).map(mk).collect();
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(commit_max),
    OpNumber::new(),
    0,
    headers,
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(commit_max); // holds 1..=commit_max
  wal.head = ring; // a corrupt-LOW head scalar, far below the durable committed frontier
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "the window floors at the durable commit despite the under-reporting head scalar"
  );
  for _ in 0..(commit_max + 8) {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(r.status(), Status::Normal, "tail consistent → Normal");
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "the full committed band is read + held — the lying head scalar hides nothing committed"
  );
  assert!(
    r.log
      .get(&commit_max)
      .is_some_and(|e| e.body.as_present() == Some(&[commit_max as u8][..])),
    "the top committed op is read + cached with its canonical body"
  );
}

#[test]
fn recover_reads_held_committed_ops_above_the_default_window() {
  // CONSENSUS-CRITICAL regression. `recover`'s tail read window was capped at
  // `checkpoint_op + RECOVER_TAIL_WINDOW`, which exists ONLY to bound reads against a BOGUS `op_head`
  // (bit-rot → huge), NOT to hide the legitimate committed band. With `Config::with_checkpoint_ops >
  // RECOVER_TAIL_WINDOW` a replica can durably commit FAR past its last checkpoint, persist a durable
  // root naming `commit_max` ABOVE `checkpoint_op + RECOVER_TAIL_WINDOW`, and crash while HOLDING the
  // canonical WAL ops + sparse headers up to `commit_max`. The old cap then set `self.op =
  // checkpoint_op + RECOVER_TAIL_WINDOW` < commit_max, HIDING the held committed ops above it: the
  // replica's DVC reported `commit_max > self.op` with a `log_slice` only through the read frontier, so
  // if it is the quorum-intersection committed holder (old primary down, DVC quorum = this replica + a
  // laggard) `select_canonical_log` hit `commit* > op_head` → FAIL-STOP, or a truncating adoption
  // DESTROYED the hidden committed copies → committed-op LOSS.
  //
  // The fix raises the window floor from `checkpoint_op` to the DURABLE committed frontier
  // `state.commit()` (a checksum-validated, quorum-bounded value a corrupt superblock cannot inflate):
  // `RECOVER_TAIL_WINDOW` now bounds only the UNCOMMITTED tail above `commit_max`, so the full committed
  // band is read + cached and `self.op >= commit_max`.
  //
  // Setup: replica 1 of 3, checkpoint_op 0, durable `commit_max` two ops ABOVE the old frontier
  // (`RECOVER_TAIL_WINDOW + 2`). The WAL HOLDS canonical ops `1..=commit_max` (each header-matched) with
  // a SPARSE canonical header per op. A large `with_checkpoint_ops` models the real reachability (commit
  // far past the checkpoint without re-checkpointing).
  let commit_max = RECOVER_TAIL_WINDOW + 2; // strictly above the OLD cap (checkpoint_op 0 + window)
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let headers: std::vec::Vec<Header> = (1..=commit_max).map(mk).collect();
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(commit_max), // commit == commit_max (durable known-committed frontier)
    OpNumber::new(),            // checkpoint_op 0
    0,
    headers, // SPARSE canonical set, here fully dense 1..=commit_max (every op is HELD)
  )
  .unwrap()
  .with_wal_geometry(crate::MAX_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  // The WAL holds canonical ops 1..=commit_max (head == commit_max), each body [op] header-matched.
  let wal = ScriptedWal::with_entries(commit_max);
  // A checkpoint interval far above the window — the regime in which this hazard is reachable.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), crate::MAX_CHECKPOINT_OPS).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // `recover` submits the FIRST bounded read batch (`RECOVER_TAIL_WINDOW` slots); the continuation batches
  // THE CORE assertion: the recovered head reads the FULL durable committed band — `self.op == commit_max`,
  // NOT the old `checkpoint_op + RECOVER_TAIL_WINDOW`. The single-pass read window is bounded by the WAL
  // ring capacity (`op_head.min(checkpoint_op + capacity)` == `op_head` here), so the whole held band is
  // materialized up front. (FAIL-BEFORE: `self.op == RECOVER_TAIL_WINDOW` < commit_max, hiding the top two
  // held committed ops.)
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "recover reads up to the durable committed frontier, not checkpoint_op + RECOVER_TAIL_WINDOW"
  );
  // Drain the committed-band reads → Normal, every held op cached + verified.
  for _ in 0..(commit_max + 8) {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(r.status(), Status::Normal, "tail consistent → Normal");
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "the full committed band frontier is preserved into Normal"
  );
  assert_eq!(
    r.commit_max(),
    OpNumber::with(commit_max),
    "recover carries the durable known-committed frontier"
  );
  // The two ops above the OLD cap are READ + CACHED (not hidden, not repair holes).
  for op in [RECOVER_TAIL_WINDOW + 1, RECOVER_TAIL_WINDOW + 2] {
    assert!(
      r.log
        .get(&op)
        .is_some_and(|e| e.body.as_present() == Some(&[op as u8][..])),
      "op {op} (held committed, above the old cap) is read + cached with its canonical body"
    );
    assert!(
      !r.has_repair_hole_for_test(op),
      "op {op} is HELD, not a repair hole"
    );
  }
  while r.poll_message().is_some() {}
  while r.poll_event().is_some() {}

  // A DVC quorum where THIS replica is the only committed holder must NOT fail-stop or lose those ops.
  // Replica 1 (recovered, holds the full committed band, commit_max == commit_max) + replica 0 (a
  // LAGGARD at head/commit RECOVER_TAIL_WINDOW); replica 2 (the other old commit-quorum holder) is
  // ABSENT. Drive replica 1 to primary of view 1.
  r.handle_message(
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
  assert_eq!(r.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  r.storage_step(now, &mut storage, &mut blocks); // complete the SendDoViewChange durable-view write
  // The recovered replica's OWN DVC reports the KNOWN committed frontier == commit_max, with a
  // log_slice carrying the held band up to commit_max — so `commit* == commit_max <= op_head ==
  // commit_max` and the fail-stop does NOT trip. (FAIL-BEFORE: the DVC reported op == RECOVER_TAIL_WINDOW
  // with commit_max > op, so `commit* > op_head` → FAIL-STOP, or truncation destroyed the hidden ops.)
  let own_dvc = core::iter::from_fn(|| r.poll_message())
    .filter_map(|out| match out.into_msg() {
      Message::DoViewChange(d) => Some(d),
      _ => None,
    })
    .next()
    .expect("the recovered replica sends its DVC");
  assert_eq!(
    own_dvc.commit(),
    OpNumber::with(commit_max),
    "the DVC reports the durable known-committed frontier (== commit_max)"
  );
  assert_eq!(
    own_dvc.op(),
    OpNumber::with(commit_max),
    "the DVC head covers the full committed band — commit_max is NOT above the reported head \
     (FAIL-BEFORE: op == RECOVER_TAIL_WINDOW < commit_max)"
  );
  let top_op = own_dvc.log_slice().iter().map(|e| e.op().get()).max();
  assert_eq!(
    top_op,
    Some(commit_max),
    "the DVC log_slice carries the held committed ops up to commit_max (not just through the old cap)"
  );

  // The laggard replica 0's DVC: same generation (log_view 0), head/commit RECOVER_TAIL_WINDOW. With the
  // recovered replica's own DVC (commit_max == commit_max), `commit* == commit_max` and the head holder
  // is THIS replica — adoption must NOT fail-stop and must NOT truncate the committed band.
  r.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(RECOVER_TAIL_WINDOW),
      OpNumber::with(RECOVER_TAIL_WINDOW),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      std::vec::Vec::new(),
    )),
  );
  assert!(
    r.is_primary(),
    "replica 1 became the primary of view 1 (no fail-stop panic)"
  );
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "the committed band is NOT truncated — the head stays at commit_max \
     (FAIL-BEFORE: commit_max was above the reported head → fail-stop / committed-op loss)"
  );
  for op in [RECOVER_TAIL_WINDOW + 1, RECOVER_TAIL_WINDOW + 2] {
    assert!(
      r.log.contains_key(&op),
      "op {op} (committed, this replica's only surviving copy) is RETAINED through the view change"
    );
  }
}

#[test]
fn recover_bounds_the_read_window_for_a_ring_less_wal_with_a_corrupt_op_head() {
  // REGRESSION (the ring-less lane of the bogus-`op_head` bound): a backend that does NOT override
  // `Wal::capacity()` (the `u64::MAX` "no fixed ring" sentinel — every default/test backend) gets the
  // PROTO-IMPOSED ring as the durable-header scan's probe bound, so a bit-rotted `op_head = u64::MAX`
  // costs at most `effective_wal_capacity` header probes and — over an empty WAL — ZERO body reads,
  // never a `u64::MAX` enumeration (which would hang/OOM `recover()` before the async fault handling
  // ever ran). Recovery completes at once holding nothing.
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let wal = TestWal {
    entries: BTreeMap::new(),
    head: u64::MAX, // a bit-rotted head scalar on a ring-less backend — ignored by the scan
    done: VecDeque::new(),
  };
  let sb = sb_formatted(); // formatted-empty: models a store that ran (op_head is corrupt, not wiped)
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // Complete the genesis geometry-pin root write (the only storage completion outstanding).
  e.storage_step(Instant::ZERO, &mut storage, &mut blocks);
  assert_eq!(
    storage.wal_mut().done.len(),
    0,
    "the scan (bounded by the proto-imposed ring) found no written slot — NO reads"
  );
  assert_eq!(
    e.status(),
    Status::Normal,
    "nothing to read → Normal once the geometry pin lands"
  );
  assert_eq!(
    e.op(),
    OpNumber::new(),
    "the corrupt head is NOT held — the head derives from the (empty) scan"
  );
}

#[test]
fn recover_caps_the_read_window_when_commit_max_equals_checkpoint_op() {
  // COMPANION test (keep the bogus-`op_head` bound green): a HUGE / bit-rotted `op_head` over a bounded
  // ring with NO committed band above the checkpoint (`commit == checkpoint_op == 0`) must not drive ANY
  // read work — the head derives from the durable-header scan (which finds nothing on the empty ring)
  // floored at the durable commit (== the checkpoint here), so recovery completes at once holding
  // nothing. The corrupt superblock cannot inflate `commit` to widen the window (`VsrState` is
  // checksum-validated), and the scalar is never consulted.
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut wal = ScriptedWal::with_entries(0);
  wal.head = u64::MAX; // a pathological / bit-rotted head scalar — ignored by the scan
  wal.capacity = RECOVER_TAIL_WINDOW; // a BOUNDED ring — the scan's probe bound
  let mut sb = sb_formatted(); // formatted-empty: models a store that ran (commit == checkpoint == 0)
  // This scenario runs over a BOUNDED ring; re-stamp the durable root's geometry to that ring size so
  // recovery's capacity fence matches the live bounded WAL (`sb_formatted` defaults to the ring-less MAX).
  sb.state = sb
    .state
    .clone()
    .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, RECOVER_TAIL_WINDOW);
  assert_eq!(
    sb.state().commit(),
    sb.state().checkpoint_op(),
    "the durable root has NO committed band above the checkpoint"
  );
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // Complete the genesis geometry-pin root write (the only storage completion outstanding).
  e.storage_step(Instant::ZERO, &mut storage, &mut blocks);
  assert_eq!(
    storage.wal_mut().done.len(),
    0,
    "no written slot + no committed band → NO reads, regardless of the claimed head"
  );
  assert_eq!(
    e.status(),
    Status::Normal,
    "nothing to read → Normal once the geometry pin lands"
  );
  assert_eq!(
    e.op(),
    OpNumber::new(),
    "the bogus head above the ring is NOT held — the head derives from the (empty) scan"
  );
}

#[test]
fn recover_repairs_a_committed_slot_with_matching_body_but_wrong_client_or_request() {
  // CONSENSUS-CRITICAL regression. A committed op's identity is `(op, client, request,
  // body)`, NOT body bytes alone. Two clients can submit IDENTICAL payload bytes, so a STALE superseded
  // WAL slot that kept the SAME body but a DIFFERENT `client`/`request` would pass the body-only
  // cross-check, be adopted, and applied under the WRONG session — corrupting dedup/reply (duplicate
  // execution under the wrong client). The fix keys the canonical cross-check on FULL operation identity
  // `(client, request, body_checksum)`: a same-body-different-identity slot now MISMATCHES and is dropped
  // → peer-repaired, exactly like the stale-body case.
  //
  // Setup: replica 1 of 3. Durable root: view 0, commit 2, checkpoint_op 0. The canonical header for op 2
  // records identity `(clientB = 9, req 3, body [2])` — what the cluster actually committed. The WAL slot
  // for op 2 SELF-VERIFIES but holds a DIFFERENT identity `(clientA = 7, req 5, body [2])` with the SAME
  // body bytes [2] (so the body checksum is IDENTICAL — only client/request differ). Op 1 is clean
  // canonical; op 3 sits above the committed band (uncommitted tail).
  let client_a = ClientId::new(7);
  let client_b = ClientId::new(9);
  let canonical_op1 = Header::new(
    OpNumber::with(1),
    View::new(),
    client_a,
    RequestNumber::with(1),
    &[1u8],
  );
  // op 2's CANONICAL identity: clientB / request 3 / body [2] — persisted in the durable root (vsr_headers).
  let canonical_op2 = Header::new(
    OpNumber::with(2),
    View::new(),
    client_b,
    RequestNumber::with(3),
    &[2u8],
  );
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2), // commit
    OpNumber::new(),   // checkpoint_op
    0,
    std::vec![canonical_op1, canonical_op2],
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };

  // The WAL: ops 1 + 3 canonical, but op 2 holds the SAME body [2] under a DIFFERENT identity
  // `(clientA = 7, req 5)`. Its header self-verifies (header checksum + body checksum both valid), so
  // plain `Header::verify` passes — and its body checksum EQUALS the canonical one (same bytes). Only the
  // FULL-identity check distinguishes it.
  let mut wal = ScriptedWal::with_entries(3);
  let same_body = Bytes::copy_from_slice(&[2u8]);
  let wrong_identity_header = Header::new(
    OpNumber::with(2),
    View::new(),
    client_a,               // WRONG client (canonical is clientB)
    RequestNumber::with(5), // WRONG request (canonical is req 3)
    &same_body,
  );
  assert!(
    wrong_identity_header.verify(&same_body),
    "the wrong-identity slot is SELF-CONSISTENT — plain verify passes; only full identity differs"
  );
  assert_eq!(
    wrong_identity_header.body_checksum(),
    canonical_op2.body_checksum(),
    "the body checksum is IDENTICAL (same bytes) — a body-only check would WRONGLY trust this slot \
     (FAIL-BEFORE: same-body-different-client slot is adopted under clientA/req5)"
  );
  wal.entries.insert(2, (wrong_identity_header, same_body));

  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  for _ in 0..32 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  // The wrong-identity committed slot was DETECTED (identity mismatch) and DROPPED — never adopted.
  assert_eq!(
    r.status(),
    Status::Normal,
    "a wrong-identity committed slot is dropped + peer-repaired (not stranded, not RecoveringHead)"
  );
  assert!(
    !r.log.contains_key(&2),
    "the wrong-identity slot is dropped from the in-memory log so it can never be applied as clientA/req5"
  );
  assert!(
    r.state_machine_ref().applied().is_empty(),
    "nothing applied yet — the wrong-identity body is never re-derived from the WAL"
  );

  // The primary announces commit=2. advance_commit reaches op 2, finds the HOLE, HOLDS the commit at 1,
  // and solicits op 2 via RequestPrepare (on-demand peer-repair).
  r.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "commit HELD below the wrong-identity hole — op 2's canonical identity is not yet present"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "op 2 is registered as a repair hole once commit reaches it (on demand)"
  );
  // Drop the events from applying op 1 so the assertion below sees ONLY op 2's commit.
  while r.poll_event().is_some() {}

  // A committed-vouching peer answers with the CANONICAL op 2: identity `(clientB = 9, req 3, body [2])`,
  // commit = 2 >= op 2. This fills the hole and resumes the held commit.
  let canonical_repair = Message::Prepare(Prepare::new(
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    OpNumber::new(),
    crate::Epoch::new(0),
    0,
    client_b,
    RequestNumber::with(3),
    Bytes::copy_from_slice(&[2u8]),
  ));
  r.handle_message(now, &mut storage, primary_peer(), canonical_repair);
  r.storage_step(now, &mut storage, &mut blocks); // the repaired append completes → resume
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the canonical op 2 fills the hole → the held commit resumes"
  );
  // The op 2 that COMMITTED carries the CANONICAL session `clientB / req 3`, NEVER the stale
  // `clientA / req 5` the WAL slot held. (FAIL-BEFORE: the body-only check adopted clientA/req5.)
  let committed_op2 = core::iter::from_fn(|| r.poll_event())
    .map(|e| e.unwrap_committed())
    .find(|c| c.op() == OpNumber::with(2))
    .expect("op 2 committed event");
  assert_eq!(
    committed_op2.client(),
    client_b,
    "op 2 applied under the CANONICAL clientB — never the stale WAL clientA"
  );
  assert_eq!(
    committed_op2.request(),
    RequestNumber::with(3),
    "op 2 applied under the CANONICAL request 3 — never the stale WAL request 5"
  );
  // The dedup session table reflects clientB/req3 (the canonical identity), and clientA was never
  // advanced by op 2 (its only mention was the stale, dropped slot).
  assert_eq!(
    r.clients.get(&client_b.get()).map(|s| s.request),
    Some(RequestNumber::with(3)),
    "clientB's session watermark is the canonical request 3"
  );
  assert!(
    r.clients
      .get(&client_a.get())
      .is_none_or(|s| s.request < RequestNumber::with(5)),
    "clientA/req5 was NEVER applied — the stale slot's identity never touched a session"
  );
}

#[test]
fn recover_trusts_a_committed_slot_that_matches_its_persisted_header() {
  // The complement of the stale-body regression: a NORMAL-operation recover (no staleness) must NOT
  // spuriously peer-repair. Every committed-band WAL slot matches its persisted canonical header, so
  // recovery trusts them all — no repair hole, no dropped slot, the SM re-applies the canonical band
  // directly from the WAL once commit is announced.
  let mk_header = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  // Durable root: commit 2, checkpoint_op 0, canonical headers for ops 1 + 2 matching the WAL bodies.
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::new(),
    0,
    std::vec![mk_header(1), mk_header(2)],
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let wal = ScriptedWal::with_entries(3); // ops 1,2,3 all canonical [op]
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  for _ in 0..32 {
    r.storage_step(now, &mut storage, &mut blocks);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "a consistent tail recovers cleanly to Normal"
  );
  assert!(
    r.repair.is_empty(),
    "no spurious repair hole — every committed-band slot matched its persisted header"
  );
  assert!(
    r.log
      .get(&2)
      .is_some_and(|e| e.body.as_present() == Some(&[2u8][..])),
    "op 2 kept its canonical WAL body (trusted, not dropped)"
  );
  // Announce commit=2: both committed ops apply directly from the trusted WAL, no peer-repair needed.
  r.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "the consistent committed band applies straight through"
  );
  assert!(
    r.repair.is_empty(),
    "still no repair hole after applying the trusted band"
  );
  assert_eq!(
    r.state_machine_ref().applied(),
    &[(1, std::vec![1u8]), (2, std::vec![2u8])],
    "the trusted WAL band applied verbatim"
  );
}

#[test]
fn recovering_replica_ignores_messages_and_does_not_join_a_view_change() {
  // Non-participation: a Recovering replica must NOT process consensus messages — in particular a
  // higher-view Prepare must NOT pull it into ViewChange (the catch_up_to_view leak). It stays
  // Recovering and emits nothing until its own storage loop completes.
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), 2); // keep it Recovering (not yet drained)
  let sb = sb_formatted();
  let now = Instant::ZERO;
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  assert_eq!(r.status(), Status::Recovering);
  // A higher-view Prepare (view 5) — would normally trigger catch_up_to_view → ViewChange.
  let higher = Message::Prepare(Prepare::new(
    View::with(5),
    OpNumber::with(3),
    OpNumber::with(2),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
    ClientId::new(7),
    RequestNumber::with(3),
    Bytes::from_static(b"z"),
  ));
  r.handle_message(now, &mut storage, primary_peer(), higher);
  assert_eq!(
    r.status(),
    Status::Recovering,
    "a Recovering replica ignores a higher-view message (no catch_up_to_view)"
  );
  assert_eq!(r.view(), View::new(), "view is unchanged (no adoption)");
  assert!(
    r.poll_message().is_none(),
    "Recovering replica emits nothing"
  );
}

#[test]
fn recover_timer_resubmits_a_dropped_transient_fault() {
  // Robustness for a real async driver: if a transient fault's completion never produces a clean
  // read in the SAME drain, the recover_retry timer must re-submit pending/faulty reads so the
  // loop still terminates. Here op 2 faults twice (so one pump leaves it faulty-with-budget); a
  // timeout fires the retry, the next read is clean, and we reach Normal.
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), 2);
  let sb = sb_formatted();
  let mut now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    EchoSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  // A Recovering replica must arm a timer (so an owner driving poll_timeout makes progress).
  assert!(
    r.poll_timeout().is_some(),
    "Recovering arms the recover_retry timer"
  );
  for _ in 0..8 {
    r.storage_step(now, &mut storage, &mut blocks);
    if r.status() == Status::Normal {
      break;
    }
    // Advance to the next timer deadline and fire it (re-submits pending/faulty reads).
    if let Some(t) = r.poll_timeout() {
      now = t;
      r.handle_timeout(now, &mut storage);
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "the recover_retry timer drives the loop to termination"
  );
}

#[test]
fn recover_resolves_a_read_that_completes_after_a_retransmit() {
  // A real async WAL whose tail-read latency exceeds `RECOVER_READ_RETRANSMIT` must still recover: the
  // read submitted now completes LATER (after a retry tick), under the id it was submitted with.
  // Retransmission is ADDITIVE — `recover_timeouts` mints a fresh read id WITHOUT retiring the prior
  // ones — and the absolute per-op budget is decremented only by the timer, so when the original (slow)
  // completion finally arrives under its still-live id it RESOLVES the op and recovery reaches Normal.
  //
  // FAIL-BEFORE (the churn this fixes): the old `recover_timeouts` RE-MINTED each pending op's id every
  // tick and RETIRED the prior id (`rec.reads.retain(|_, o| o != op)`), then RESET the budget. A read
  // slower than `RECOVER_READ_RETRANSMIT` therefore always completed under an already-RETIRED id, so
  // `on_recover_wal_done`'s `rec.reads.get(&id)` missed it and dropped the completion; the budget kept
  // resetting and `rec.pending` never emptied, wedging normal recovery in `Status::Recovering` forever.
  // (The in-tree fixtures complete reads synchronously at `submit_read`, so only this DEFERRED-completion
  // model can exhibit the churn — hence the dedicated WAL capability.)
  let mk_header = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  // Replica 1 of 3. Durable root: view 0, commit 2 (ops 1 + 2 KNOWN committed), checkpoint 0, canonical
  // band [h1, h2] matching the WAL bodies. WAL head 2; op 2's read is DEFERRED (a slow async read), op 1
  // reads clean.
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::new(),
    0,
    std::vec![mk_header(1), mk_header(2)],
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_defer_read(OpNumber::with(2)); // op 2's read is HELD — it completes only on release
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(r.status(), Status::Recovering);

  // Drain op 1's clean read (resolved); op 2 stays pending with NO completion (its read is held).
  r.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    r.status(),
    Status::Recovering,
    "op 2's read has not completed yet — still recovering",
  );

  // One recover-retry tick: `recover_timeouts` re-submits op 2 ADDITIVELY (a fresh id, prior id kept)
  // and decrements its absolute budget. op 2's read is STILL held, so this enqueues no completion.
  now = now + RECOVER_READ_RETRANSMIT;
  r.handle_timeout(now, &mut storage);
  assert_eq!(
    r.status(),
    Status::Recovering,
    "still recovering after the retransmit (op 2's read remains in flight)",
  );

  // The original (slow) op-2 read now completes under its ORIGINAL id — the id a retire-on-retry
  // retransmit would already have discarded. With additive ids it is still live, so it resolves op 2.
  assert!(
    storage.wal_mut().release_deferred(OpNumber::with(2)),
    "op 2 had an outstanding (held) read to release",
  );

  // Drive to completion (pump storage + the retry timer); recovery reaches Normal with op 2 resolved.
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "the slow read's late completion (under a still-live additive id) resolves op 2 → Normal \
     (FAIL-BEFORE: a retired id dropped it and rec.pending never emptied — a permanent wedge)",
  );
  let entry = r.log.get(&2).expect("op 2 is present in the recovered log");
  assert_eq!(
    entry.body,
    Body::Present(Bytes::copy_from_slice(&[2u8])),
    "op 2 holds its REAL body from the released read (not an empty placeholder / Repairing hole)",
  );
  assert_eq!(
    entry.client,
    ClientId::new(7),
    "op 2's identity is its real client"
  );
  assert_eq!(r.op(), OpNumber::with(2), "the recovered head is op 2");
}

#[test]
fn recover_rebuilds_log_and_op_from_wal() {
  // A backup appends ops 1,2 durably, then "crashes". recover() over the SAME session rebuilds
  // op=2 with REAL bodies, view from the superblock. recover() is now metadata-only (returns
  // Recovering); a no-fault TestWal completes the tail reads in one handle_storage → Normal.
  let mut e = backup();
  let (wal, sb) = (TestWal::default(), sb_formatted());
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(now, &mut storage, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut storage, primary_peer(), prepare(2, 1));
  e.storage_step(now, &mut storage, &mut blocks);
  // Drop `e` (crash). Recover a fresh endpoint from the SAME durable wal/storage.sb_mut().
  drop(e);
  let mut recovered = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  assert_eq!(
    recovered.status(),
    Status::Recovering,
    "recover is a metadata-only constructor (Recovering)"
  );
  recovered.storage_step(now, &mut storage, &mut blocks); // drain the tail reads → Normal
  assert_eq!(
    recovered.op(),
    OpNumber::with(2),
    "op restored from the WAL head"
  );
  assert_eq!(
    recovered.view(),
    View::new(),
    "view restored from the superblock"
  );
  assert_eq!(recovered.status(), Status::Normal);
  // Recovery is read-only: the durable WAL head is unchanged.
  assert_eq!(
    storage.wal_mut().op_head(),
    OpNumber::with(2),
    "WAL head is intact after recovery"
  );
  // Body restoration itself is asserted end-to-end in `recover_restores_real_bodies`.
}

#[test]
fn recover_restores_real_bodies() {
  // recover() must rebuild REAL bodies from the WAL, not empty placeholders: the SM-apply paths
  // read `entry.body`, so an empty body would silently diverge the recovered replica. Durably
  // append ops 1,2 (bodies [1],[2]) to a backup, crash, recover with an echoing SM, then have
  // the primary announce commit=2 — the recovered backup re-applies both ops from its restored
  // WAL bodies, and the Committed events must carry the ORIGINAL bytes.
  let cfg = || Config::try_new(1, MemberId::new(1)).expect("valid cluster config");
  let (wal, sb) = (TestWal::default(), sb_formatted());
  let now = Instant::ZERO;

  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg(), genesis(3), 0, EchoSm, u64::MAX);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(now, &mut storage, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut storage, primary_peer(), prepare(2, 1));
  e.storage_step(now, &mut storage, &mut blocks);
  drop(e); // crash

  let mut recovered = Endpoint::recover(cfg(), genesis(3), 0, EchoSm, &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(recovered.status(), Status::Recovering);
  recovered.storage_step(now, &mut storage, &mut blocks); // restore the tail bodies → Normal
  assert_eq!(recovered.status(), Status::Normal);
  recovered.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );

  let mut applied = std::vec::Vec::new();
  while let Some(ev) = recovered.poll_event() {
    if let Ok(c) = ev.try_unwrap_committed() {
      applied.push((c.op().get(), c.reply().to_vec()));
    }
  }
  assert_eq!(
    applied,
    std::vec![(1u64, std::vec![1u8]), (2u64, std::vec![2u8])],
    "recovered replica re-applies ops 1,2 with their ORIGINAL restored bodies"
  );
}

#[test]
fn recover_restores_a_nonzero_durable_view() {
  // A replica that advanced its view persists it; recover() restores it (no regression to view 0,
  // which would risk a cross-view double-vote). Drive a backup into ViewChange(view 1) so it writes
  // the durable view, pump the write, then crash + recover over the SAME session.
  use crate::StartViewChange;
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    u64::MAX,
  );
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let later = Instant::ZERO + core::time::Duration::from_millis(300);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  e.handle_timeout(later, &mut storage); // primary_idle → propose view 1 (own SVC bit)
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
  ); // SVC quorum → ViewChange(view 1) → durable-view write submitted
  e.storage_step(later, &mut storage, &mut blocks); // make the durable-view write complete
  assert_eq!(
    storage.sb_mut().state().view(),
    View::with(1),
    "view 1 is durable before the crash"
  );
  assert_eq!(
    storage.sb_mut().state().log_view(),
    View::new(),
    "the view change did not complete: the durable log_view is still 0 (mid-view-change)"
  );
  drop(e); // crash

  let mut recovered = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut storage,
  )
  .expect("recover accepts this store")
  .expect_active();
  assert_eq!(
    recovered.view(),
    View::with(1),
    "recover() restores the advanced durable view (no regression to view 0)"
  );
  // The pre-crash writer never observed its backend capacity (`Endpoint::new` takes no storage), so
  // its root left that half of the geometry pair unrecorded — recovery re-pins it before settling.
  recovered.storage_step(later, &mut storage, &mut blocks);
  // The durable root is `view 1 / log_view 0` — the replica crashed MID-VIEW-CHANGE (it had
  // escalated to ViewChange(1) and persisted the view, but never installed a view-1 log). Per the
  // Per TigerBeetle replica.zig open(), recovery RE-DRIVES the in-progress view change
  // rather than resuming Normal: `log_view < view` → ViewChange at `view` (NOT Normal, which would
  // wrongly resume a never-completed view change). No op was appended (op_head == 0) and there is no
  // checkpoint, so the terminal status settles as soon as the geometry re-pin lands.
  assert_eq!(
    recovered.status(),
    Status::ViewChange,
    "a mid-view-change recovery re-drives the view change, it does not resume Normal"
  );
}

#[test]
fn recover_accepts_a_checkpoint_read_completing_under_a_superseded_id() {
  // The recover-retry timer re-submits the checkpoint read ADDITIVELY (a fresh id without retiring the
  // prior). On a real async superblock a slow read completes AFTER a retransmit minted a newer id, so its
  // `CheckpointRead` arrives under a SUPERSEDED id. `on_recover_sb_done` must accept ANY read while one is
  // outstanding (the bytes are checksum-verified regardless) — matching only the latest id would drop the
  // late completion and, with the budget no longer reset on the timer, wedge recovery in `Recovering`.
  // (The deterministic `TestSb` completes the checkpoint read on submit, so reproduce the superseded id
  // directly: re-mark `rec.checkpoint` to a fresh id before draining the original read's completion.)
  let cfg = || Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // ONE block store for the whole test — the SM checkpoint DAG must survive into recover().
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    cfg(),
    genesis(1),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let mut storage = Storage::new(wal, sb);
  for rn in 1..=2u64 {
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
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "the checkpoint is durable"
  );
  drop(e); // crash

  let mut r = Endpoint::recover(cfg(), genesis(1), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(r.status(), Status::Recovering);
  // Simulate the recover-retry timer minting a FRESH checkpoint read id before the original (slow) read's
  // completion is drained — the completion will then arrive under a SUPERSEDED id.
  let original = r
    .recover
    .as_ref()
    .unwrap()
    .checkpoint
    .expect("a checkpoint read is outstanding after recover()");
  r.recover.as_mut().unwrap().checkpoint = Some(original.wrapping_add(1000));
  // Drain: the original checkpoint read completes under `original` (now superseded). It MUST be accepted,
  // restoring the SM and completing recovery. (FAIL-BEFORE the additive accept: the superseded id is
  // ignored, the SM is never restored, and recovery stays `Recovering`.)
  for _ in 0..4 {
    r.storage_step(now, &mut storage, &mut blocks);
    if r.status() != Status::Recovering {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "the checkpoint read under a superseded id is accepted → recovery completes",
  );
  assert_eq!(
    r.state_machine_ref().applied().len(),
    2,
    "the SM is restored from the (superseded-id) checkpoint read",
  );
}

#[test]
fn recover_checkpoint_fault_storm_does_not_prematurely_escalate_then_a_valid_read_restores() {
  // TIMER-OWNERSHIP REGRESSION: the recover-retry TIMER (`recover_timeouts`) is the SOLE owner of the
  // checkpoint-read retry budget; it re-submits ADDITIVELY, so a real async superblock can have several
  // checkpoint reads in flight at once and older ones may FAULT out of order while a later one still
  // carries the valid snapshot. A `Fault` (or verify-mismatch) delivered through `on_recover_sb_done` is
  // therefore a NO-OP — it must NOT decrement the budget or escalate. Otherwise a STORM of such faults
  // would exhaust the budget and escalate to a peer fetch BEFORE the in-flight valid read lands (and the
  // valid read would then be treated as foreign and dropped — a solo/partitioned wedge). Here a storm of
  // in-band faults (far exceeding the budget) arrives WITHOUT firing the timer; recovery stays Recovering
  // with the checkpoint outstanding (NOT escalated), and the still-in-flight valid read then restores the
  // SM LOCALLY — no peer. (FAIL-BEFORE, were a fault to escalate in-band: the storm sets
  // `awaiting_peer_checkpoint`, failing the asserts below.)
  let good_snap = CountSm::default().snapshot();
  let good_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    crate::block_address(&good_snap),
    super::super::session_blocks::encode_sessions(
      &std::collections::BTreeMap::new(),
      &mut crate::block_store::InMemoryBlockStore::new(),
    ),
  );
  let good_id = crate::checkpoint_id(&good_env);
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    good_id,
    std::vec::Vec::new(),
  )
  .unwrap()
  // A running node stamps geometry on every durable root; match the recover config (checkpoint_ops
  // 2) and the ring-less test WAL's `u64::MAX` capacity so recovery sees a FORMATTED, geometry-recorded
  // solo store the fence accepts rather than fail-stopping.
  .with_wal_geometry(2, u64::MAX);
  // The Phase-1 checkpoint read submitted by recover() carries the genuine snapshot, but it stays IN
  // FLIGHT (not flushed) while the fault storm arrives.
  let sb = ScriptedCheckpointSb::new(
    state,
    VecDeque::from(std::vec![(OpNumber::with(2), good_env.clone())]),
  );
  let wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  // The envelope names the SM leaf by its content address; the leaf itself lives in the block store, so
  // recover walks the local DAG and restores from it rather than escalating to a peer fetch.
  blocks.put(good_snap.clone());
  super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks);
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(1), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(e.status(), Status::Recovering);
  assert!(
    e.recover.as_ref().unwrap().checkpoint.is_some(),
    "the Phase-1 checkpoint read is outstanding (in flight, not yet flushed)"
  );

  // A STORM of in-band checkpoint faults under arbitrary ids — none may decrement the budget or escalate.
  for k in 0..(4 * RECOVER_READ_RETRIES as u64) {
    e.on_recover_sb_done(&mut storage, SuperblockDone::Fault(read_id(9000 + k)));
  }
  assert_eq!(
    e.status(),
    Status::Recovering,
    "a storm of in-band checkpoint faults must NOT escalate — the timer owns the budget"
  );
  assert!(
    !e.awaiting_peer_checkpoint_for_test(),
    "no premature peer-fetch escalation from the in-band fault storm"
  );
  assert!(
    e.recover.as_ref().unwrap().checkpoint.is_some(),
    "the checkpoint read is still outstanding after the fault storm"
  );

  // The still-in-flight valid read lands → SM restored LOCALLY, recovery completes. No peer was needed.
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.status(),
    Status::Normal,
    "the still-in-flight valid checkpoint read restores the SM locally after the fault storm"
  );
  assert!(
    !e.awaiting_peer_checkpoint_for_test(),
    "restored from the local read — never fell back to a peer"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint_op restored from the durable root"
  );
}

#[test]
fn recover_restores_from_the_durable_checkpoint_not_op_zero() {
  // A single-replica primary commits past a checkpoint (checkpoint_ops=2), so the checkpoint is
  // durable; then it "crashes". recover() MUST restore the SM from the checkpoint snapshot and set
  // commit_min == checkpoint_op (NOT 0) — re-applying [1..=checkpoint_op] would double-apply.
  // (The implementation never prunes the WAL at this stage — so the WAL still holds ops [1..=head];
  //  the log cache is rebuilt for the tail (checkpoint_op..=head] only, the snapshot owns the rest.)
  let cfg = || Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  // ONE block store for the whole test — the SM checkpoint DAG written at commit must survive into
  // recover() (it reads the blocks back to restore the SM), exactly as the WAL + superblock persist.
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    cfg(),
    genesis(1),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let mut storage = Storage::new(wal, sb);
  for rn in 1..=2 {
    e.handle_message(now, &mut storage, Peer::Client(ClientId::new(7)), req(rn));
    e.storage_step(now, &mut storage, &mut blocks); // append durable → commit → (at op 2) checkpoint
  }
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint is durable"
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    2,
    "the live SM applied ops 1,2 before the crash"
  );
  drop(e); // crash

  // recover() restores from the checkpoint snapshot, NOT by replaying from op 0. The consensus
  // metadata (commit/checkpoint/op) is set synchronously in Phase 1; the SM snapshot restore
  // happens in the Recovering handle_storage loop (Phase 2), so pump it before the SM asserts. The
  // SAME `blocks` store carries the checkpoint DAG across the crash (the SM blocks persist).
  let mut recovered = Endpoint::recover(cfg(), genesis(1), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(recovered.status(), Status::Recovering);
  assert_eq!(
    recovered.commit(),
    OpNumber::with(2),
    "commit_min restored to the checkpoint op, not 0"
  );
  assert_eq!(
    recovered.checkpoint_op(),
    OpNumber::with(2),
    "checkpoint_op restored from the durable root"
  );
  assert_eq!(
    recovered.op(),
    OpNumber::with(2),
    "op restored from the WAL head (head >= commit_min == checkpoint_op)"
  );
  // commit_max is restored to checkpoint_op too (monotone bounds: op >= commit_max >= commit_min).
  assert_eq!(recovered.commit_max(), OpNumber::with(2));
  recovered.storage_step(now, &mut storage, &mut blocks); // restore the SM snapshot + tail bodies → Normal
  assert_eq!(recovered.status(), Status::Normal);
  // The SM was restored from the snapshot: it already reflects ops 1,2 (NOT re-applied → exactly 2).
  assert_eq!(
    recovered.state_machine_ref().applied().len(),
    2,
    "SM restored from the checkpoint snapshot (no double-apply)"
  );
  assert_eq!(
    recovered.state_machine_ref().applied(),
    &[(1u64, std::vec![1u8]), (2u64, std::vec![2u8])],
    "the restored SM reflects exactly the checkpointed applied prefix"
  );
}

#[test]
fn recover_rejects_a_mismatched_checkpoint_read_and_retries_then_restores() {
  // SAFETY REGRESSION (recover trusted an unverified checkpoint read): a `CheckpointRead` matching the
  // read id but whose CONTENT does not match the durable root (`sb.state()`) — wrong content hash or
  // wrong op — must be REJECTED (not restored) and retried within the recover budget, exactly like a
  // transient fault. Restoring a stale/corrupt snapshot while `commit_min == checkpoint_op` would be
  // silent committed-prefix loss. Here the FIRST read returns corrupt bytes (hash mismatch), the
  // SECOND returns bytes with the wrong op, and only the THIRD is the genuine snapshot.
  // The SM tail must be a VALID CountSm snapshot (an empty one = 8 zero bytes for the count), so the
  // restore on the genuine read succeeds; the verify logic under test is independent of the payload.
  let good_snap = CountSm::default().snapshot();
  let good_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    crate::block_address(&good_snap),
    super::super::session_blocks::encode_sessions(
      &std::collections::BTreeMap::new(),
      &mut crate::block_store::InMemoryBlockStore::new(),
    ),
  );
  let good_id = crate::checkpoint_id(&good_env);
  // Durable root: checkpoint at op 2, naming the GOOD envelope's content id.
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    good_id,
    std::vec::Vec::new(),
  )
  .unwrap()
  // A running node stamps geometry on every durable root; match the recover config (checkpoint_ops
  // 2) and the ring-less test WAL's `u64::MAX` capacity so recovery sees a FORMATTED, geometry-recorded
  // solo store the fence accepts rather than fail-stopping.
  .with_wal_geometry(2, u64::MAX);
  let sb = ScriptedCheckpointSb::new(
    state,
    VecDeque::from(std::vec![
      // (1) right op, WRONG bytes (hash mismatch) → rejected.
      (OpNumber::with(2), Bytes::from_static(b"CORRUPT")),
      // (2) right bytes, WRONG op (2 expected) → rejected.
      (OpNumber::with(99), good_env.clone()),
      // (3) the genuine snapshot → accepted.
      (OpNumber::with(2), good_env.clone()),
    ]),
  );
  // An empty WAL with head == checkpoint_op (2): the recover tail range (3..=2) is empty, so the ONLY
  // outstanding read is the checkpoint read — isolating the verify-and-retry behaviour.
  let wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  // The envelope names the SM leaf by content address; the leaf lives in the block store, so the genuine
  // read restores from the local DAG.
  blocks.put(good_snap.clone());
  super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks);
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(1), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(e.status(), Status::Recovering);
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "commit_min set to the checkpoint op"
  );

  // Drain #1: the corrupt-bytes read is REJECTED — SM not restored, still Recovering, a new read armed.
  storage.sb_mut().flush(); // release the Phase-1 checkpoint read (the corrupt one)
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.state_machine_ref().applied().len(),
    0,
    "a hash-mismatched read must NOT restore the SM"
  );
  assert_eq!(
    e.status(),
    Status::Recovering,
    "still recovering after rejecting the corrupt read (retry armed)"
  );

  // Pump the recover-retry timer so the next checkpoint read is submitted (the timer is the sole
  // owner of the read-retry budget).
  let t = e.poll_timeout().expect("recover-retry timer armed");
  e.handle_timeout(t, &mut storage);

  // Drain #2: the wrong-op read is REJECTED too — still no restore, still Recovering.
  storage.sb_mut().flush(); // release the retry read submitted in drain #1 (the wrong-op one)
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.state_machine_ref().applied().len(),
    0,
    "a wrong-op read must NOT restore the SM"
  );
  assert_eq!(
    e.status(),
    Status::Recovering,
    "still recovering after the wrong-op read"
  );

  // Pump the recover-retry timer again so the genuine retry read is submitted.
  let t = e.poll_timeout().expect("recover-retry timer armed");
  e.handle_timeout(t, &mut storage);

  // Drain #3: the genuine read is accepted → SM restored, recovery completes to Normal.
  storage.sb_mut().flush(); // release the retry read submitted in drain #2 (the genuine one)
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.status(),
    Status::Normal,
    "recovery completes once a VERIFIED checkpoint read lands"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "recovered at the durable checkpoint"
  );
}

#[test]
fn recover_does_not_panic_on_a_truncated_checkpoint_read() {
  // SAFETY: a truncated/malformed snapshot whose bytes pass NEITHER the hash nor parse must be
  // treated as a fault (decode → None), NOT panic recovery. We script a single garbage read followed
  // by the genuine one: the garbage is rejected (no panic, no restore), then recovery completes.
  // The SM tail must be a VALID CountSm snapshot (an empty one = 8 zero bytes for the count), so the
  // restore on the genuine read succeeds; the verify logic under test is independent of the payload.
  let good_snap = CountSm::default().snapshot();
  let good_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    crate::block_address(&good_snap),
    super::super::session_blocks::encode_sessions(
      &std::collections::BTreeMap::new(),
      &mut crate::block_store::InMemoryBlockStore::new(),
    ),
  );
  let good_id = crate::checkpoint_id(&good_env);
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    good_id,
    std::vec::Vec::new(),
  )
  .unwrap()
  // A running node stamps geometry on every durable root; match the recover config (checkpoint_ops
  // 2) and the ring-less test WAL's `u64::MAX` capacity so recovery sees a FORMATTED, geometry-recorded
  // solo store the fence accepts rather than fail-stopping.
  .with_wal_geometry(2, u64::MAX);
  let sb = ScriptedCheckpointSb::new(
    state,
    VecDeque::from(std::vec![
      // A 2-byte garbage snapshot: too short even for the 8-byte leading op → decode returns None.
      (OpNumber::with(2), Bytes::from_static(&[0xAB, 0xCD])),
      (OpNumber::with(2), good_env.clone()),
    ]),
  );
  let wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  // The envelope names the SM leaf by content address; the leaf lives in the block store so the genuine
  // read restores from the local DAG.
  blocks.put(good_snap.clone());
  super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks);
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(1), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // Drain #1: the truncated read does NOT panic — it is rejected; still Recovering.
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.status(),
    Status::Recovering,
    "a truncated snapshot is a fault (decode None), not a panic"
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    0,
    "nothing restored from garbage bytes"
  );
  // Pump the recover-retry timer so the genuine retry read is submitted.
  let t = e.poll_timeout().expect("recover-retry timer armed");
  e.handle_timeout(t, &mut storage);
  // Drain #2: the genuine read completes recovery.
  storage.sb_mut().flush();
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(
    e.status(),
    Status::Normal,
    "recovery completes on the valid read"
  );
}

#[test]
fn recover_escalates_to_a_peer_fetch_when_its_own_checkpoint_is_permanently_unreadable() {
  // REGRESSION (a permanently-corrupt own checkpoint must NOT panic recovery): when this replica's
  // OWN durable checkpoint snapshot read back unreadable/mismatched on EVERY attempt, the OLD code hit
  // an `assert!` once the per-op retry budget exhausted — crashing the replica on storage-controlled
  // bytes (a faulty/malicious superblock could do this at will). The fix ESCALATES to fetching the
  // checkpoint from a peer via state-sync (a forced sync + a `RequestSync`), staying in a recoverable
  // fault state, and completes recovery once a verified peer `SyncCheckpoint` restores the SM.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let now = Instant::ZERO;
  // Durable root: a checkpoint at op 2 naming SOME id. The scripted superblock has an EMPTY read
  // script, so EVERY `submit_read_checkpoint` FAULTS — a permanently-unreadable snapshot.
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
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new()); // empty → always faults
  // Empty WAL with head == checkpoint_op (2): the tail range is empty, isolating the checkpoint path.
  let wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(e.status(), Status::Recovering);

  // Drive well past the per-op retry budget (RECOVER_READ_RETRIES), pumping the recover-retry timer
  // each round (the timer is the sole owner of the read-retry budget). The CORE property: this NEVER
  // panics (the old `assert!` is gone).
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
  // After exhaustion the replica escalated to a peer fetch: still Recovering (SM not yet restored —
  // never silently Normal with a fresh SM at commit_min == 2), awaiting a peer checkpoint, with a
  // FORCED sync armed at our own checkpoint op and a RequestSync emitted.
  assert_eq!(
    e.status(),
    Status::Recovering,
    "a permanently-unreadable own checkpoint does NOT complete recovery (and does NOT panic)"
  );
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "the replica escalated to fetching the checkpoint from a peer"
  );
  assert!(
    e.sync_is_forced_for_test(),
    "a FORCED sync was armed for the peer fetch"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(2),
    "the forced sync targets our own checkpoint op (a peer >= it answers)"
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    0,
    "nothing restored from the unreadable snapshot"
  );
  let mut saw_request_sync = false;
  while let Some(out) = e.poll_message() {
    if let Message::RequestSync(_) = out.msg_ref() {
      saw_request_sync = true;
    }
  }
  assert!(
    saw_request_sync,
    "the replica solicited a peer checkpoint (RequestSync)"
  );

  // A peer answers with a VALID SyncCheckpoint (op 2, the genuine snapshot, matching nonce). The
  // recovering replica accepts it (the relaxed guard), restores the SM, durably re-persists, and
  // completes recovery to Normal.
  let good_snap = CountSm::default().snapshot();
  let good_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    crate::block_address(&good_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let good_id = crate::checkpoint_id(&good_env);
  // The envelope names the SM leaf by content address; seed the store so the peer-served checkpoint's
  // block-fetch frontier drains locally and installs without a RequestBlock round trip.
  blocks.put(good_snap.clone());
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      good_env.clone(),
      Bytes::new(),
    )),
  );
  // apply_sync staged the durable re-persist (two superblock writes); drive them to completion.
  for _ in 0..3 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "a verified peer SyncCheckpoint completes recovery to Normal"
  );
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "recovered at the peer's checkpoint op"
  );
  assert!(
    !e.awaiting_peer_checkpoint_for_test(),
    "the peer-fetch latch is cleared on success"
  );
  assert_eq!(
    e.sync_target_for_test(),
    None,
    "the sync is cleared once the synced checkpoint is durable"
  );
  assert_eq!(
    e.forced_syncs_applied(),
    1,
    "the recovery peer-fetch routed through apply_sync as a FORCED state-sync"
  );
}

#[test]
fn a_quarantine_hint_does_not_escalate_a_checkpoint_exhausted_local_recovery() {
  // SAFETY REGRESSION (super-high-risk): a node in a genuine CHECKPOINT-EXHAUSTED local recovery holds
  // `commit_min` AHEAD of its SM (`sm_at < commit_min` — its Phase-2 restore faulted permanently), safe
  // ONLY under the `Recovering` status exemption of the `sm_at == commit_min` witness. Its recovery sync is
  // NON-crossing (`require_cross_epoch == false`). A quarantined `Peer::Member` higher-epoch hint arms the
  // bounded probe (via `maybe_request_cross_epoch_catchup`), but `enter_cross_epoch_peer_fetch` DEFERS to
  // the in-progress recovery (early-returns on `awaiting_peer_checkpoint`), so the sync is NOT upgraded to a
  // crossing — the probe ends up armed on top of the genuine recovery. The probe must NOT tear that sync
  // down and escalate out of `Recovering`: doing so lands the node in `ViewChange`/`Normal` with an
  // unrestored SM at `commit_min == 2`, applying op 3+ over empty state — a committed-prefix loss.
  //
  // NEUTER CHECK: drop the `require_cross_epoch` gate in `advance_quarantine_probe` and the probe disarms
  // the recovery sync + `retire_recover_and_escalate` moves the node to `ViewChange` with
  // `sm_at != commit_min`, tripping the clause-(5c) `assert_invariants` in debug.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let now = Instant::ZERO;
  // Durable root: a checkpoint at op 2; the scripted superblock has an EMPTY read script, so EVERY
  // checkpoint read FAULTS — a permanently-unreadable own snapshot (SM stays unrestored).
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
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
  while e.poll_message().is_some() {}
  // Precondition: a checkpoint-exhausted local recovery — Recovering, awaiting a peer checkpoint, a
  // NON-crossing forced sync, and the SM unrestored (`commit_min == 2 > sm_at == 0`).
  assert_eq!(e.status(), Status::Recovering);
  assert!(e.awaiting_peer_checkpoint_for_test());
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "the recovery sync is NON-crossing (require_cross_epoch == false)"
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    0,
    "precondition: the SM is unrestored"
  );

  // A quarantined higher-epoch hint arms the probe ON TOP of the recovery (the crossing is NOT armed).
  e.handle_message(
    now,
    &mut storage,
    Peer::Member(MemberId::new(99)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(9),
      OpNumber::with(9),
      crate::Epoch::new(5),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  assert!(
    !e.sync_requires_cross_epoch_for_test(),
    "the hint did NOT upgrade the recovery sync to a crossing (enter_cross_epoch_peer_fetch deferred)"
  );

  // Step FAR past the probe deadline with no donor answer. The probe must NOT escalate the recovery.
  for ms in 1..=8 {
    e.handle_timeout(
      now + core::time::Duration::from_millis(ms * 200),
      &mut storage,
    );
    while e.poll_message().is_some() {}
  }
  assert_eq!(
    e.status(),
    Status::Recovering,
    "the checkpoint-exhausted recovery STAYS Recovering — the probe did NOT escalate it out with an \
     unrestored SM"
  );
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "still awaiting its peer checkpoint (the genuine recovery is intact)"
  );
  assert_eq!(
    e.state_machine_ref().applied().len(),
    0,
    "the SM is STILL unrestored — no silent committed-prefix loss"
  );
}

#[test]
fn a_cross_epoch_recovery_peer_fetch_survives_an_old_epoch_same_epoch_commit() {
  // R7 SCOPE GUARD: `cancel_stale_cross_epoch_sync` must NOT tear down a GENUINE crossing. A NON-Normal
  // recovery peer-fetch (Recovering, `awaiting_peer_checkpoint`, a `require_cross_epoch` sync — what
  // `enter_cross_epoch_peer_fetch` arms for a non-Normal laggard crossing the epoch boundary) is a real
  // crossing in progress. An OLD-EPOCH predecessor-primary `Commit` that still passes sender + epoch
  // authority reaches the ingress cancel BEFORE the Recovering dispatch drop; without the scope guard it
  // would CLEAR the sync and WEDGE the node (recovery re-solicit + the higher-epoch trigger both gate on
  // `awaiting_peer_checkpoint`, leaving no sync to drive). The cancel is scoped to PRE-STAGE NORMAL
  // speculative crossings (`is_normal()` here is false), so this survives.
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
  .unwrap()
  .with_wal_geometry(2, u64::MAX);
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new()); // empty → always faults
  let wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
  assert_eq!(e.status(), Status::Recovering);
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "setup: a non-Normal recovery peer-fetch (awaiting a peer checkpoint)"
  );

  // Escalate the peer-fetch to a CROSS-EPOCH crossing (`require_cross_epoch`) — what a higher-epoch hint to
  // this non-Normal laggard does via `enter_cross_epoch_peer_fetch`.
  e.arm_cross_epoch_sync_for_test(9);
  assert!(
    e.sync_requires_cross_epoch_for_test() && e.awaiting_peer_checkpoint_for_test(),
    "setup: a require_cross_epoch recovery peer-fetch (a genuine non-Normal crossing)"
  );
  let target_before = e.sync_target_for_test();
  let nonce_before = e.sync_nonce_for_test();

  // An OLD-EPOCH (predecessor-primary) admissible `Commit` at our epoch (0) — passes sender + epoch
  // authority in our membership, reaching the ingress cancel before the Recovering dispatch drop.
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      crate::Epoch::new(0),
      0,
    )),
  );

  assert!(
    e.sync_requires_cross_epoch_for_test(),
    "the recovery cross-epoch sync SURVIVES the old-epoch Commit (NOT cancelled — cancelling would wedge it)"
  );
  assert_eq!(
    e.sync_target_for_test(),
    target_before,
    "the sync target is unchanged (no cancel, no re-arm)"
  );
  assert_eq!(
    e.sync_nonce_for_test(),
    nonce_before,
    "the sync nonce is unchanged (no fresh handshake)"
  );
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "still awaiting the peer checkpoint — the node did not wedge"
  );
}

#[test]
fn recover_peer_fetch_on_a_primary_steps_down_via_the_abdicate_chokepoint() {
  // A recovered PRIMARY steps down on the peer-checkpoint-fetch path. The fetch RESTORES the SM from a
  // peer snapshot but leaves `inflight` (the commit pipeline) CLEARED while this replica is the PRIMARY of
  // its view — a wedge if it resumed as primary (`try_commit` can never advance past commit_min). The
  // re-persist STAGES while still Recovering and, once the SyncRepersist root is durable, `on_sb_done`
  // installs and `complete_recovery` runs: a recovered primary takes its recovered-primary path and
  // ABDICATES into a clean view change (view + 1) — the SAME step-down a DISK-recovered primary takes —
  // rather than resume Normal as the established primary with a torn-down pipeline. This is the path the
  // existing peer-fetch test (a BACKUP) does NOT exercise; here the recovering replica IS the primary of
  // view 0.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 2).unwrap();
  let now = Instant::ZERO;
  // Durable root at VIEW 0 (so replica 0 is the primary) with a checkpoint at op 2. The scripted
  // superblock has an EMPTY read script, so EVERY checkpoint read FAULTS — a permanently-unreadable
  // own snapshot, forcing the peer-fetch escalation.
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
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert!(
    e.is_primary(),
    "replica 0 recovered at view 0 is the primary of its view"
  );
  assert_eq!(e.status(), Status::Recovering);

  // Exhaust the checkpoint-read budget → escalate to a peer fetch (still Recovering, SM not restored).
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "the primary escalated to a peer fetch (its own checkpoint is unreadable)"
  );
  assert!(
    !e.pending_forfeit_for_test(),
    "not stepped down yet (still awaiting the peer snapshot)"
  );
  while e.poll_message().is_some() {}

  // A peer answers with a VALID SyncCheckpoint (op 2, matching nonce). The recovering PRIMARY stages the
  // re-persist (staying Recovering); once the SyncRepersist root is durable it installs and
  // `complete_recovery` STEPS IT DOWN — a recovered primary forces a clean view change rather than resume
  // as the established primary with a torn-down pipeline.
  let good_snap = CountSm::default().snapshot();
  let good_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    crate::block_address(&good_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let good_id = crate::checkpoint_id(&good_env);
  // The envelope names the SM leaf by content address; seed the store so the peer-served checkpoint's
  // block-fetch frontier drains locally and installs without a RequestBlock round trip.
  blocks.put(good_snap.clone());
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(1),
      nonce,
      good_env,
      Bytes::new(),
    )),
  );
  // Drive the staged re-persist to completion (flush the scripted superblock each round so the two staged
  // writes surface and `on_sb_done` lands the root, installing + completing recovery).
  for _ in 0..6 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
    if !e.status().is_recovering() {
      break;
    }
  }
  // The SM was restored (recovery completed at the peer's checkpoint) AND the primary stepped down — it
  // ABDICATED into a clean view change (`complete_recovery`'s recovered-primary path), advancing OFF its
  // own view rather than resuming Normal as the established primary with a torn-down pipeline.
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "recovery completed at the peer's checkpoint op"
  );
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "the recovered primary abdicated into a view change — it did not resume Normal as the established \
     primary with a torn-down pipeline"
  );
  assert_eq!(
    e.view(),
    View::with(1),
    "the abdication advanced OFF the recovered primary's own view (view + 1)"
  );
}

#[test]
#[should_panic(expected = "survived into the terminal recovery status")]
fn finalize_recovery_assert_catches_a_leaked_empty_faulty_slot() {
  // Regression net: the `finalize_recovery` choke debug-asserts that no
  // permanently-faulty committed-band slot survived as a POPULATED `self.log` entry (an empty-body
  // placeholder that `advance_commit`/`adopt_log` would apply empty cluster-wide — the original
  // empty-body CRITICAL). Here we LEAK one — op 5 is in `rec.faulty` AND still in `self.log` with an
  // empty body (the exact shape a future edit that stops dropping it would produce) — and assert the
  // tripwire fires. The happy paths drop the slot first, so this never trips in practice; this proves it
  // WOULD catch a bypassed drop.
  let mut e = backup();
  let mut rec = RecoverState::default();
  rec.faulty.insert(5); // op 5 read back permanently faulty …
  e.recover = Some(rec);
  e.log.insert(
    5,
    // … but its EMPTY `Present` placeholder was NOT dropped from the cache (the leak).
    LogEntry::present(ClientId::new(7), RequestNumber::with(5), Bytes::new()),
  );
  e.assert_no_faulty_committed_survives(); // must panic in debug: the leaked slot would apply empty.
}

#[test]
fn recover_does_not_panic_when_a_mismatched_checkpoint_read_always_faults_then_a_peer_serves() {
  // REGRESSION (variant): the checkpoint read MATCHES our read id but its CONTENT is permanently
  // wrong (hash mismatch on every attempt) — the verify-failure path, not a raw Fault. It must route
  // to the SAME budget→peer-fetch escalation (no panic), then a peer's good SyncCheckpoint completes.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let now = Instant::ZERO;
  let good_snap = CountSm::default().snapshot();
  let good_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(2),
    crate::block_address(&good_snap),
    super::super::session_blocks::encode_sessions(
      &std::collections::BTreeMap::new(),
      &mut crate::block_store::InMemoryBlockStore::new(),
    ),
  );
  let good_id = crate::checkpoint_id(&good_env);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  // The leaf the envelope names lives in the block store, so the peer-served checkpoint installs once
  // its block-fetch frontier drains locally (the corrupt LOCAL reads still fail the id gate before the
  // DAG walk, so the peer-fetch escalation is unaffected).
  blocks.put(good_snap.clone());
  super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks);
  // Durable root names the GOOD id at op 2, but every scripted read returns CORRUPT bytes (wrong
  // hash) — a permanently-inconsistent snapshot. Provide many corrupt reads (more than the budget).
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    good_id,
    std::vec::Vec::new(),
  )
  .unwrap()
  // A running node stamps geometry on every durable root; match the recover config (checkpoint_ops
  // 2) and the ring-less test WAL's `u64::MAX` capacity so recovery sees a FORMATTED, geometry-recorded
  // solo store the fence accepts rather than fail-stopping.
  .with_wal_geometry(2, u64::MAX);
  let corrupt_reads: VecDeque<(OpNumber, Bytes)> = (0..(RECOVER_READ_RETRIES as usize + 6))
    .map(|_| (OpNumber::with(2), Bytes::from_static(b"CORRUPT")))
    .collect();
  let sb = ScriptedCheckpointSb::new(state, corrupt_reads);
  let wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // Drive the verify-failure exhaustion (pumping the recover-retry timer each round) → must NOT panic.
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
  assert_eq!(
    e.status(),
    Status::Recovering,
    "no panic; escalated to peer fetch"
  );
  assert!(e.awaiting_peer_checkpoint_for_test());
  let nonce = e.sync_nonce_for_test();
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      good_env.clone(),
      Bytes::new(),
    )),
  );
  for _ in 0..3 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "recovery completes once a peer serves the genuine checkpoint"
  );
}

#[test]
fn recover_peer_fetch_keeps_faulty_committed_slots_as_repairing_not_applying_them_empty() {
  // CRITICAL (committed-state divergence via the peer-checkpoint-fetch recovery path): Phase 1
  // of `recover` seeds an EMPTY-body placeholder for every tail op (headers readable, bodies pending).
  // Phase 2 (`on_recover_wal_done`) verifies each; a permanently-faulty COMMITTED-band slot (op 2 here)
  // exhausts its retry budget. Its READ faults but its durable HEADER survives, so the budget-exhaustion
  // arm KEEPS it header-only as a `Body::Repairing` hole (existence + identity preserved) IN PLACE of the
  // empty placeholder — never a bare hole a later view change could omit, never a held EMPTY entry. The
  // conversion happens during phase-2 verification, NOT at the end-of-`recover_progress` drop that the
  // `awaiting_peer_checkpoint` early-return skips — so it is robust on the peer-fetch path: when the OWN
  // checkpoint snapshot is ALSO unreadable, the replica escalates to a peer fetch, `apply_sync`'s
  // held-tail retain keeps `self.log[2]` as the `Repairing` hole, and `advance_commit` treats it EXACTLY
  // like a wholly-missing slot (hold the commit + peer-repair), so it is NEVER applied with `&[]`.
  // FAIL-BEFORE: the budget-exhaustion arm dropped op 2 to `rec.faulty` without consulting the durable
  // header, the end-of-progress drop was skipped on the peer-fetch path, and `self.sm.apply(2, &[])` ran.
  //
  // Setup: replica 1 of 3, checkpoint interval 2. Durable root: commit == commit_max == 3,
  // checkpoint_op == 1, with the SPARSE canonical band headers [h2, h3]. WAL head 3 holds ops 2,3;
  // op-2's body read permanently faults; op-3 is clean. The own checkpoint (op 1) snapshot is
  // permanently unreadable, forcing the peer fetch. A peer then serves checkpoint op 1; we drive to
  // completion, then deliver a Commit(3) and observe op 2 is a repair hole that is request-repaired
  // and applied with its REAL body — never empty.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let now = Instant::ZERO;

  // The canonical bodies of the committed band. op-2's body is what a healthy peer holds and what the
  // durable root's vsr_header h2 vouches for; the WAL slot carries the SAME identity (it is genuinely
  // op 2 — only its READ faults), so the seeded `rec.canonical` is consistent.
  let body2 = Bytes::copy_from_slice(b"OP2-REAL-BODY");
  let body3 = Bytes::copy_from_slice(b"OP3-REAL-BODY");
  let h2 = Header::new(
    OpNumber::with(2),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(2),
    &body2,
  );
  let h3 = Header::new(
    OpNumber::with(3),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(3),
    &body3,
  );

  // Durable root: known-committed frontier 3, checkpoint at op 1, SPARSE band headers [h2, h3].
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(3),
    OpNumber::with(1),
    0xDEAD_BEEF, // the OWN checkpoint id; its snapshot is unreadable, so this is never matched
    std::vec![h2, h3],
  )
  .unwrap()
  .with_wal_geometry(2, u64::MAX);
  // ScriptedCheckpointSb with an EMPTY read script → every own checkpoint read FAULTS (the op-1
  // snapshot is permanently unreadable, forcing the peer-fetch escalation).
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new());

  // WAL head 3 holds ops 2 and 3 with their canonical bodies; op-2's body read PERMANENTLY faults.
  let mut entries = BTreeMap::new();
  entries.insert(2u64, (h2, body2.clone()));
  entries.insert(3u64, (h3, body3.clone()));
  let mut wal = ScriptedWal {
    entries,
    head: 3,
    capacity: u64::MAX,
    read_faults: BTreeMap::new(),
    corrupt: std::collections::BTreeSet::new(),
    body_faulty: std::collections::BTreeSet::new(),
    deferred: std::collections::BTreeSet::new(),
    deferred_reads: BTreeMap::new(),
    done: VecDeque::new(),
  };
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // never clears within any finite budget

  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(e.status(), Status::Recovering);
  assert_eq!(
    e.commit_max(),
    OpNumber::with(3),
    "the durable known-committed frontier is preserved"
  );

  // Drive past the per-op + checkpoint retry budgets so op-2 classes permanently faulty AND the own
  // checkpoint read exhausts → escalation to a peer fetch (pumping the recover-retry timer each round).
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
  assert_eq!(
    e.status(),
    Status::Recovering,
    "still recovering (own checkpoint unreadable → awaiting a peer)"
  );
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "escalated to fetching the checkpoint from a peer"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(1),
    "the forced sync targets our own checkpoint op (a peer >= it answers)"
  );

  // A peer serves checkpoint op 1. Its snapshot restores an SM that has applied exactly op 1.
  let mut peer_sm = CountSm::default();
  peer_sm.apply(OpNumber::with(1), b"OP1-REAL-BODY");
  let peer_snap = peer_sm.snapshot();
  let peer_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(1),
    crate::block_address(&peer_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let peer_id = crate::checkpoint_id(&peer_env);
  // The envelope names the SM leaf by content address; seed the store so the peer-served checkpoint's
  // block-fetch frontier drains locally and installs without a RequestBlock round trip.
  blocks.put(peer_snap.clone());
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(1),
      peer_id,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      nonce,
      peer_env,
      Bytes::new(),
    )),
  );
  // Drive the durable re-persist (two superblock writes) to completion → Normal.
  for _ in 0..3 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "the verified peer SyncCheckpoint completed recovery to Normal"
  );
  assert_eq!(e.checkpoint_op(), OpNumber::with(1), "recovered at op 1");
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "commit_min is the synced checkpoint op (op 2 is NOT applied empty)"
  );

  // THE CORE SAFETY PROPERTY (post-recovery): op 2's EMPTY placeholder was REPLACED by a `Body::Repairing`
  // hole (header-only, carrying the durable canonical body_checksum), so the apply path treats it as a
  // missing-body hole rather than a held empty entry that advance_commit would apply with `&[]`. (It is
  // not yet REGISTERED in `self.repair` — that is deferred to the on-demand `advance_commit` once commit
  // reaches it, asserted after the Commit below.) The SM reflects only the restored op 1 — op 2 was never
  // applied (empty or otherwise) on any recovery-completion path.
  let entry = e.log.get(&2).expect(
    "op 2 is KEPT as a Body::Repairing hole (durable header), neither dropped nor held empty",
  );
  assert_eq!(
    entry.body,
    Body::Repairing(h2.body_checksum()),
    "op 2 is a header-only Repairing hole (NOT a held empty entry to apply with &[])"
  );
  assert_eq!(
    e.state_machine_ref().applied(),
    &[(1u64, b"OP1-REAL-BODY".to_vec())],
    "only the restored op 1 is applied — op 2 was NEVER applied with an empty (or any) body yet"
  );

  // Drive the commit toward 3: at op 2 (a hole) advance_commit REGISTERS the repair hole, holds the
  // commit, and (re-)solicits a RequestPrepare; it must NEVER apply op 2 with `&[]`.
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "commit is HELD below the op-2 hole — op 2 is not applied empty"
  );
  assert!(
    e.has_repair_hole_for_test(2),
    "advance_commit registered op 2 as a genuine repair hole (request-repaired, NOT applied empty)"
  );
  let mut solicited_op2 = false;
  while let Some(out) = e.poll_message() {
    // The hole arm solicits the contiguous run via the windowed `RequestPrepareRange` (a single-op
    // range `[2,2]` here) rather than a per-op `RequestPrepare`.
    if let Message::RequestPrepareRange(r) = out.msg_ref()
      && r.lo() <= OpNumber::with(2)
      && r.hi() >= OpNumber::with(2)
    {
      solicited_op2 = true;
    }
  }
  assert!(
    solicited_op2,
    "the held op-2 hole is request-repaired from a committed-vouching peer"
  );

  // A peer answers with the canonical op-2 Prepare (commit >= op, real body). fill_repair stages a
  // durable append; on_wal_done then applies op 2 with its REAL body and resumes the held commit.
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(3),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ClientId::new(7),
      RequestNumber::with(2),
      body2.clone(),
    )),
  );
  e.storage_step(now, &mut storage, &mut blocks); // the repair-fill append lands → apply op 2 (real body)
  assert!(
    !e.has_repair_hole_for_test(2),
    "the op-2 hole is filled once the canonical Prepare's append is durable"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(3),
    "the held commit resumes through op 3 once op 2 is repaired"
  );
  // The decisive assertion: op 2 applied with its REAL body — the SM NEVER saw `&[]` for op 2.
  assert_eq!(
    e.state_machine_ref().applied(),
    &[
      (1u64, b"OP1-REAL-BODY".to_vec()),
      (2u64, b"OP2-REAL-BODY".to_vec()),
      (3u64, b"OP3-REAL-BODY".to_vec()),
    ],
    "op 2 applied with its CANONICAL body (never `&[]`); the committed prefix is consistent"
  );
}

#[test]
fn peer_sync_checkpoint_resolves_an_in_flight_committed_read_to_repairing_not_applies_it_empty() {
  // A peer `SyncCheckpoint` can complete recovery while a committed tail read is still in flight. The
  // peer-fetch escalation (`escalate_checkpoint_to_peer_fetch`) is NOT gated on `rec.pending`, so a
  // `SyncCheckpoint` (a `handle_message`) can race in AHEAD of a tail read's completion (a
  // `handle_storage`). `apply_sync` RETAINS the held tail above the synced checkpoint, so a committed tail
  // op's Phase-1 `Present(empty)` placeholder would survive into Normal (its later read completion is
  // ignored once `recover` is cleared) and `advance_commit` would apply it with `&[]`: committed-state
  // divergence. The fix RESOLVES every still-in-flight tail op above the synced checkpoint from its durable
  // header — a Verified committed op is KEPT header-only as `Body::Repairing` (body peer-repaired on
  // demand) — completing WITHOUT waiting on `rec.pending` (a wait would wedge: the retry timer re-mints
  // each read's id every `RECOVER_READ_RETRANSMIT`, so a read slower than that never resolves and the
  // pending set never empties).
  //
  // The deterministic `handle_storage` drains ALL WAL completions before the SB checkpoint completion, so
  // a tail read can never be in flight when the checkpoint escalates here — the race needs a real async
  // driver's interleaved completions. Reproduce that one missing condition directly: drive to a genuine
  // `awaiting_peer_checkpoint` (all tail reads settled), then re-mark a committed tail op as an in-flight
  // read with a `Present(empty)` placeholder the way an async driver would have.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let now = Instant::ZERO;
  let body2 = Bytes::copy_from_slice(b"OP2-REAL-BODY");
  let body3 = Bytes::copy_from_slice(b"OP3-REAL-BODY");
  let h2 = Header::new(
    OpNumber::with(2),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(2),
    &body2,
  );
  let h3 = Header::new(
    OpNumber::with(3),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(3),
    &body3,
  );
  // Durable root: known-committed frontier 3, checkpoint at op 1 (its own snapshot is unreadable), band
  // [h2, h3]. All WAL tail reads succeed, so the drive settles `rec.pending` to empty before escalating.
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(3),
    OpNumber::with(1),
    0xDEAD_BEEF,
    std::vec![h2, h3],
  )
  .unwrap()
  .with_wal_geometry(2, u64::MAX);
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let mut entries = BTreeMap::new();
  entries.insert(2u64, (h2, body2.clone()));
  entries.insert(3u64, (h3, body3.clone()));
  let wal = ScriptedWal {
    entries,
    head: 3,
    capacity: u64::MAX,
    read_faults: BTreeMap::new(),
    corrupt: std::collections::BTreeSet::new(),
    body_faulty: std::collections::BTreeSet::new(),
    deferred: std::collections::BTreeSet::new(),
    deferred_reads: BTreeMap::new(),
    done: VecDeque::new(),
  };
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // Drive: tail reads settle (Present), the own checkpoint read exhausts → peer-fetch escalation
  // (pumping the recover-retry timer each round).
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "escalated to a peer fetch (own checkpoint unreadable)"
  );
  assert!(
    e.recover.as_ref().is_some_and(|rec| rec.pending.is_empty()),
    "the deterministic drain settled every tail read before escalating",
  );

  // Build the verified peer SyncCheckpoint (checkpoint op 1). Captured once so the deferred and the
  // completing delivery use the SAME fresh nonce.
  let mut peer_sm = CountSm::default();
  peer_sm.apply(OpNumber::with(1), b"OP1-REAL-BODY");
  let peer_snap = peer_sm.snapshot();
  let peer_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(1),
    crate::block_address(&peer_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let peer_id = crate::checkpoint_id(&peer_env);
  // The envelope names the SM leaf by content address; seed the store so the peer-served checkpoint's
  // block-fetch frontier drains locally and installs without a RequestBlock round trip.
  blocks.put(peer_snap.clone());
  let nonce = e.sync_nonce_for_test();
  let sync = crate::SyncCheckpoint::new(
    View::new(),
    OpNumber::with(1),
    peer_id,
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    nonce,
    peer_env,
    Bytes::new(),
  );

  // Re-mark committed op 2 as an IN-FLIGHT tail read holding only a `Present(empty)` placeholder — the
  // state a real async driver leaves when the checkpoint completion + the peer SyncCheckpoint arrive
  // before op 2's WAL read does.
  e.log.insert(
    2,
    LogEntry::present(ClientId::new(7), RequestNumber::with(2), Bytes::new()),
  );
  e.recover
    .as_mut()
    .unwrap()
    .pending
    .insert(2, RECOVER_READ_RETRIES);

  // Deliver the verified SyncCheckpoint WHILE op 2's read is in flight. Recovery COMPLETES (it does not
  // wait on `rec.pending` — that could wedge), RESOLVING the in-flight committed op 2 from its durable
  // header to a header-only `Body::Repairing` hole (body peer-repaired on demand) — never a held
  // `Present(empty)` entry.
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(sync),
  );
  for _ in 0..3 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "the verified SyncCheckpoint completes recovery WITHOUT waiting on the in-flight read (no wedge)",
  );
  // THE FIX: op 2's `Present(empty)` placeholder was RESOLVED to a `Body::Repairing` hole carrying the
  // durable canonical body_checksum — NOT retained as a held empty entry. (FAIL-BEFORE: op 2 survived
  // `apply_sync` as `Some({body: EMPTY})` and a later `advance_commit` applied committed op 2 with `&[]`.)
  assert_eq!(
    e.log.get(&2).map(|entry| &entry.body),
    Some(&Body::Repairing(h2.body_checksum())),
    "the in-flight committed op 2 is a Body::Repairing hole, not a held Present(empty) entry to apply with &[]",
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "commit_min is the synced checkpoint op 1 (op 2 is a held hole below the known frontier)",
  );
  assert_eq!(
    e.state_machine_ref().applied(),
    &[(1u64, b"OP1-REAL-BODY".to_vec())],
    "only the restored op 1 is applied — committed op 2 was NEVER applied empty",
  );
}

#[test]
fn peer_sync_checkpoint_resolves_an_in_flight_uncommitted_tail_read_not_applies_it_empty() {
  // The same peer-checkpoint race for an UNCOMMITTED in-flight tail op (op == commit_max + 1). An op above
  // this replica's STALE durable `commit_max` can still be COMMITTED later — by the primary, or already
  // committed elsewhere but unlearned here before the crash — so leaving its Phase-1 `Present(empty)`
  // placeholder retained by `apply_sync` is NOT harmless: a later `Commit` makes `advance_commit` apply it
  // with `&[]`, and a view change advertises its empty-body header. The fix RESOLVES it from its durable
  // header to a header-only `Body::Repairing` hole (truncatable / peer-repaired if committed), so a
  // `Commit` HOLDS + peer-repairs instead of applying empty.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let now = Instant::ZERO;
  let body2 = Bytes::copy_from_slice(b"OP2-REAL-BODY");
  let body3 = Bytes::copy_from_slice(b"OP3-REAL-BODY");
  let h2 = Header::new(
    OpNumber::with(2),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(2),
    &body2,
  );
  let h3 = Header::new(
    OpNumber::with(3),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(3),
    &body3,
  );
  // Durable root: commit 2 (op 2 committed, band [h2]), checkpoint op 1 (its snapshot unreadable). op 3 is
  // the UNCOMMITTED tail (op 3 == commit_max + 1).
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(1),
    0xDEAD_BEEF,
    std::vec![h2],
  )
  .unwrap()
  .with_wal_geometry(2, u64::MAX);
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let mut entries = BTreeMap::new();
  entries.insert(2u64, (h2, body2.clone()));
  entries.insert(3u64, (h3, body3.clone()));
  let wal = ScriptedWal {
    entries,
    head: 3,
    capacity: u64::MAX,
    read_faults: BTreeMap::new(),
    corrupt: std::collections::BTreeSet::new(),
    body_faulty: std::collections::BTreeSet::new(),
    deferred: std::collections::BTreeSet::new(),
    deferred_reads: BTreeMap::new(),
    done: VecDeque::new(),
  };
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "escalated to a peer fetch (own checkpoint unreadable)"
  );
  let mut peer_sm = CountSm::default();
  peer_sm.apply(OpNumber::with(1), b"OP1-REAL-BODY");
  let peer_snap = peer_sm.snapshot();
  let peer_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(1),
    crate::block_address(&peer_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let peer_id = crate::checkpoint_id(&peer_env);
  // The envelope names the SM leaf by content address; seed the store so the peer-served checkpoint's
  // block-fetch frontier drains locally and installs without a RequestBlock round trip.
  blocks.put(peer_snap.clone());
  let nonce = e.sync_nonce_for_test();
  let sync = crate::SyncCheckpoint::new(
    View::new(),
    OpNumber::with(1),
    peer_id,
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    nonce,
    peer_env,
    Bytes::new(),
  );
  // Re-mark UNCOMMITTED op 3 (== commit_max + 1) as an in-flight tail read with a `Present(empty)` placeholder.
  e.log.insert(
    3,
    LogEntry::present(ClientId::new(7), RequestNumber::with(3), Bytes::new()),
  );
  e.recover
    .as_mut()
    .unwrap()
    .pending
    .insert(3, RECOVER_READ_RETRIES);
  // Deliver the verified SyncCheckpoint while op 3's read is in flight → completes, resolving op 3 to a
  // header-only `Body::Repairing` hole (it is uncommitted, so kept on its durable header without a
  // canonical cross-check).
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(sync),
  );
  for _ in 0..3 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "the SyncCheckpoint completes recovery WITHOUT waiting on the in-flight read (no wedge)",
  );
  assert_eq!(
    e.log.get(&3).map(|entry| &entry.body),
    Some(&Body::Repairing(h3.body_checksum())),
    "the in-flight UNCOMMITTED op 3 is resolved to a Body::Repairing hole — not a held Present(empty) entry",
  );
  // A Commit for op 3 (committing op 3) must HOLD at its Repairing hole + peer-repair, NEVER apply op 3
  // with `&[]`. (FAIL-BEFORE: op 3's Present(empty) survived and advance_commit applied op 3 empty.)
  e.handle_message(
    now,
    &mut storage,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    e.state_machine_ref()
      .applied()
      .iter()
      .all(|(op, _)| *op != 3),
    "committed op 3 is HELD at its Repairing hole (peer-repaired), NEVER applied with &[]",
  );
  assert!(
    e.commit().get() < 3,
    "commit is held below the op-3 Repairing hole — op 3 is not applied",
  );
}

#[test]
fn peer_sync_checkpoint_drops_a_superseded_above_commit_in_flight_tail_read() {
  // An in-flight UNCOMMITTED tail op whose durable header is a SUPERSEDED earlier-view proposal (its
  // `view` is BELOW this replica's durable `log_view`) must NOT be kept as a canonical `Body::Repairing`
  // hole: the replica already advanced `log_view` past that generation, so the slot is an abandoned
  // proposal. If kept, a `Commit` for the op registers the STALE Repairing as a repair hole and
  // `fill_repair` then rejects the REAL committed body (its identity differs) — `commit_min` wedges — and
  // a view change advertises the stale header as the canonical tail identity. The resolution runs the SAME
  // `classify_committed_slot` verdict the Fault arm does, whose above-commit arm classes a `slot_view <
  // log_view` slot StaleCommitted, so it is DROPPED to a peer-repaired hole the canonical op then fills.
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 2).unwrap();
  let now = Instant::ZERO;
  let body2 = Bytes::copy_from_slice(b"OP2-REAL-BODY");
  let stale3 = Bytes::copy_from_slice(b"OP3-STALE-V0");
  let h2 = Header::new(
    OpNumber::with(2),
    View::with(1),
    ClientId::new(7),
    RequestNumber::with(2),
    &body2,
  );
  // op 3's durable WAL header is a stale view-0 proposal — BELOW the durable log_view 1.
  let h3_stale = Header::new(
    OpNumber::with(3),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(3),
    &stale3,
  );
  // Durable root: view 1, log_view 1, commit 2 (op 2 committed, band [h2]), checkpoint op 1.
  let state = VsrState::try_new(
    View::with(1),
    View::with(1),
    OpNumber::with(2),
    OpNumber::with(1),
    0xDEAD_BEEF,
    std::vec![h2],
  )
  .unwrap()
  .with_wal_geometry(2, u64::MAX);
  let sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let mut entries = BTreeMap::new();
  entries.insert(2u64, (h2, body2.clone()));
  entries.insert(3u64, (h3_stale, stale3.clone()));
  let wal = ScriptedWal {
    entries,
    head: 3,
    capacity: u64::MAX,
    read_faults: BTreeMap::new(),
    corrupt: std::collections::BTreeSet::new(),
    body_faulty: std::collections::BTreeSet::new(),
    deferred: std::collections::BTreeSet::new(),
    deferred_reads: BTreeMap::new(),
    done: VecDeque::new(),
  };
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 5, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery_scripted_sb(&mut e, &mut storage, &mut blocks, now);
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "escalated to a peer fetch"
  );
  let mut peer_sm = CountSm::default();
  peer_sm.apply(OpNumber::with(1), b"OP1-REAL-BODY");
  let peer_snap = peer_sm.snapshot();
  let peer_env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(1),
    crate::block_address(&peer_snap),
    super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks),
  );
  let peer_id = crate::checkpoint_id(&peer_env);
  // The envelope names the SM leaf by content address; seed the store so the peer-served checkpoint's
  // block-fetch frontier drains locally and installs without a RequestBlock round trip.
  blocks.put(peer_snap.clone());
  let nonce = e.sync_nonce_for_test();
  let sync = crate::SyncCheckpoint::new(
    View::with(1),
    OpNumber::with(1),
    peer_id,
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    nonce,
    peer_env,
    Bytes::new(),
  );
  // Re-mark the SUPERSEDED op 3 as an in-flight tail read with a `Present(empty)` placeholder.
  e.log.insert(
    3,
    LogEntry::present(ClientId::new(7), RequestNumber::with(3), Bytes::new()),
  );
  e.recover
    .as_mut()
    .unwrap()
    .pending
    .insert(3, RECOVER_READ_RETRIES);
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(sync),
  );
  // Stage the re-persist (the node stays Recovering), then drive the scripted superblock to land the
  // SyncRepersist root, which installs + completes recovery.
  for _ in 0..6 {
    storage.sb_mut().flush();
    e.storage_step(now, &mut storage, &mut blocks);
    if !e.status().is_recovering() {
      break;
    }
  }
  // Recovery COMPLETES (no wedge) — it leaves Recovering. (Member 1 is the primary of the recovered view 1
  // here, so `complete_recovery` abdicates into a view change; a non-primary backup would resume Normal.
  // The terminal status is incidental to this test — the subject is the dropped superseded slot below.)
  assert!(
    !e.status().is_recovering(),
    "recovery completes (no wedge) — it leaves Recovering"
  );
  // THE FIX: the superseded above-commit slot is DROPPED to a peer-repaired hole — NOT kept as a stale
  // Body::Repairing entry whose identity a later `fill_repair` would require the REAL committed body to
  // match (rejecting it, wedging commit_min) and whose header a view change would advertise as canonical.
  // (FAIL-BEFORE the classify gate: op 3 was kept as Repairing(h3_stale checksum).) With no stale entry,
  // the canonical view-1 op 3 fills the hole through the ordinary committed-hole repair path (a hole
  // `advance_commit` registers + `fill_repair` fills — see the peer-fetch recovery test).
  assert!(
    !e.log.contains_key(&3),
    "the superseded view-0 op 3 is dropped to a hole, not kept as a stale Body::Repairing entry",
  );
}

#[test]
fn fault_exhaustion_adopts_the_full_durable_header_identity_not_a_stale_placeholder() {
  // The Fault-path keep-as-Repairing promotion must adopt the FULL identity (client, request,
  // body_checksum) of the durable header it consults at retry-exhaustion — never splice the durable
  // body_checksum onto a Phase-1 placeholder's STALE (client, request). A mixed identity (old
  // client/request, new checksum) is UNFILLABLE by peer repair — `fill_repair` validates all three
  // fields — so it would wedge the committed op or carry the wrong identity through a re-formation.
  //
  // The deterministic WAL returns a STABLE header, so Phase-1 and the fault-exhaustion fallback normally
  // read the SAME identity. Force the divergence an in-model header resolution can produce: Phase-1 reads
  // header H1 (client 99, request 99) for committed op 2 and seeds a placeholder with it; the durable
  // root's canonical band vouches a DIFFERENT identity H2 (client 20, request 20). Between Phase-1 and op
  // 2's read-fault retry exhaustion, replace the WAL's durable header for op 2 with H2 (the resolution
  // that now agrees with the band). The fallback reads H2, classifies it Verified, and must keep op 2 as
  // Body::Repairing with H2's FULL identity — NOT (client 99, request 99, Repairing(H2 checksum)).
  let mk = |op: u64, client: u128, request: u64, body: &[u8]| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(client),
      RequestNumber::with(request),
      body,
    )
  };
  let canon2 = Bytes::copy_from_slice(b"OP2-CANON");
  let h2_canon = mk(2, 20, 20, &canon2); // the canonical identity the band vouches
  let h1_phase1 = mk(2, 99, 99, b"OP2-STALE"); // a DIFFERENT identity Phase-1 reads first
  let h1 = mk(1, 7, 1, b"\x01");
  let body3 = Bytes::copy_from_slice(b"OP3");
  let h3 = mk(3, 7, 3, &body3);
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2), // commit 2: ops 1 + 2 committed
    OpNumber::new(),   // checkpoint_op 0
    0,
    std::vec![h1, h2_canon], // canonical band vouches H2 for op 2
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut entries = BTreeMap::new();
  entries.insert(1u64, (h1, Bytes::copy_from_slice(b"\x01")));
  entries.insert(2u64, (h1_phase1, Bytes::copy_from_slice(b"OP2-STALE"))); // Phase-1 reads H1 here
  entries.insert(3u64, (h3, body3.clone()));
  let mut wal = ScriptedWal {
    entries,
    head: 3,
    capacity: u64::MAX,
    read_faults: BTreeMap::new(),
    corrupt: std::collections::BTreeSet::new(),
    body_faulty: std::collections::BTreeSet::new(),
    deferred: std::collections::BTreeSet::new(),
    deferred_reads: BTreeMap::new(),
    done: VecDeque::new(),
  };
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // op 2's read always faults → fault-exhaustion path
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(
    r.log.get(&2).map(|e| e.client),
    Some(ClientId::new(99)),
    "precondition: Phase-1 seeded op 2's placeholder with the STALE H1 identity (client 99)",
  );
  // The in-model header resolution now agrees with the canonical band: op 2's durable header becomes H2.
  storage
    .wal_mut()
    .entries
    .insert(2u64, (h2_canon, canon2.clone()));
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovers to Normal (op 2 a held committed Repairing hole below head 3)",
  );
  // THE FIX: op 2 is kept as Body::Repairing with H2's FULL identity — client 20, request 20, the
  // canonical checksum — NOT a mixed (client 99, request 99, Repairing(H2 checksum)).
  let entry = r
    .log
    .get(&2)
    .expect("op 2 is kept as a Repairing committed hole");
  assert_eq!(
    entry.client,
    ClientId::new(20),
    "adopts the durable header's client (FAIL-BEFORE: the stale Phase-1 client 99 survived)",
  );
  assert_eq!(
    entry.request,
    RequestNumber::with(20),
    "adopts the durable header's request (FAIL-BEFORE: the stale Phase-1 request 99 survived)",
  );
  assert_eq!(
    entry.body,
    Body::Repairing(h2_canon.body_checksum()),
    "Body::Repairing carrying the canonical body_checksum",
  );
}

#[test]
fn fault_exhaustion_rejects_a_misdirected_durable_header() {
  // The Fault-path promotion applies the SAME placement guard as the ReadOk/BodyFaulty arms: the durable
  // header it consults must be FOR `op`. `Wal::header` returns the header at op's slot, which a misdirected
  // write can leave holding a SIBLING op's header — even one whose identity coincides with op's canonical.
  // Such a header is not a trustworthy read of THIS op, so the op is left `rec.faulty` (a peer-repaired
  // hole), never promoted to Repairing off a misplaced slot.
  //
  // Setup: committed op 2, canonical identity (client 20, request 20). The WAL slot for op 2 holds a header
  // stamped for a DIFFERENT op (op 99) that otherwise carries op-2's canonical identity — so only the
  // placement check (h.op() == op), NOT classify, distinguishes it. op 2's read faults → fault-exhaustion
  // → the misplaced header is rejected → op 2 stays a dropped/peer-repaired hole, not a Repairing entry.
  let stamped = |slot_stamp: u64, client: u128, request: u64, body: &[u8]| {
    // `slot_stamp` is the op number STAMPED in the header (what `header().op()` returns); the entry is
    // stored at its own WAL key. A misdirected slot stores a header whose stamp differs from its key.
    Header::new(
      OpNumber::with(slot_stamp),
      View::new(),
      ClientId::new(client),
      RequestNumber::with(request),
      body,
    )
  };
  let canon2 = Bytes::copy_from_slice(b"OP2-CANON");
  let h2_canon = stamped(2, 20, 20, &canon2);
  let h1 = stamped(1, 7, 1, b"\x01");
  let body3 = Bytes::copy_from_slice(b"OP3");
  let h3 = stamped(3, 7, 3, &body3);
  // op 2's slot holds a header STAMPED op 99 but carrying op-2's canonical identity (client 20, request
  // 20, canonical body) — passes classify, fails placement.
  let misdirected = stamped(99, 20, 20, &canon2);
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::new(),
    0,
    std::vec![h1, h2_canon],
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut entries = BTreeMap::new();
  entries.insert(1u64, (h1, Bytes::copy_from_slice(b"\x01")));
  entries.insert(2u64, (misdirected, canon2.clone()));
  entries.insert(3u64, (h3, body3.clone()));
  let mut wal = ScriptedWal {
    entries,
    head: 3,
    capacity: u64::MAX,
    read_faults: BTreeMap::new(),
    corrupt: std::collections::BTreeSet::new(),
    body_faulty: std::collections::BTreeSet::new(),
    deferred: std::collections::BTreeSet::new(),
    deferred_reads: BTreeMap::new(),
    done: VecDeque::new(),
  };
  wal.script_read_fault(OpNumber::with(2), u8::MAX);
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, now);
  assert_eq!(r.status(), Status::Normal, "recovers to Normal");
  // THE PLACEMENT GUARD: op 2 is NOT promoted to Repairing off the misplaced (op-99-stamped) header — it
  // is dropped to a peer-repaired hole. (FAIL-BEFORE the placement check: classify accepted the
  // identity-matching header and op 2 was kept as a Repairing entry off a misplaced slot.)
  assert!(
    r.log
      .get(&2)
      .is_none_or(|e| !matches!(e.body, Body::Repairing(_))),
    "op 2 is not kept as Repairing off a misdirected (op-99-stamped) header — it is a peer-repaired hole",
  );
  assert_eq!(
    r.commit_max(),
    OpNumber::with(2),
    "op 2 is still KNOWN committed (the durable frontier is carried) and will be peer-repaired",
  );
}

#[test]
fn recover_with_no_checkpoint_is_unchanged() {
  // Backward-compat guard: with checkpoint_op == 0 (no checkpoint yet), recover() behaves EXACTLY
  // as the no-checkpoint path — commit_min == commit_max == 0, a fresh SM (0 applied), log cache [1..=head].
  let cfg = || Config::try_new(1, MemberId::new(1)).unwrap();
  let (wal, sb) = (TestWal::default(), sb_formatted());
  let now = Instant::ZERO;
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    cfg(),
    genesis(3),
    0,
    CountSm::default(),
    u64::MAX,
  );
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  e.handle_message(now, &mut storage, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut storage, primary_peer(), prepare(2, 1));
  e.storage_step(now, &mut storage, &mut blocks);
  assert_eq!(e.checkpoint_op(), OpNumber::with(0), "no checkpoint taken");
  drop(e);

  let mut recovered = Endpoint::recover(cfg(), genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(recovered.status(), Status::Recovering);
  recovered.storage_step(now, &mut storage, &mut blocks); // drain the tail reads → Normal
  assert_eq!(recovered.status(), Status::Normal);
  assert_eq!(recovered.op(), OpNumber::with(2), "op from the WAL head");
  assert_eq!(
    recovered.commit(),
    OpNumber::with(0),
    "no checkpoint → commit_min stays 0"
  );
  assert_eq!(recovered.commit_max(), OpNumber::with(0));
  assert_eq!(recovered.checkpoint_op(), OpNumber::with(0));
  assert_eq!(
    recovered.state_machine_ref().applied().len(),
    0,
    "no checkpoint → fresh SM, nothing restored/applied"
  );
}

#[test]
fn recover_bounds_the_read_window_for_a_huge_op_head() {
  // REGRESSION (unbounded read submission): a corrupt/buggy `Wal` reporting an enormous `op_head` must
  // NOT make `recover()` bookkeep + submit a read per slot from `checkpoint_op+1` up to that head
  // (billions of inserts/reads/allocations). The head is DERIVED from the durable-header scan over the
  // ring — the scalar is never consulted — so a bit-rotted head over an EMPTY bounded ring
  // (`capacity == RECOVER_TAIL_WINDOW`) submits NO body reads at all and recovery completes immediately
  // at the checkpoint. (Before deriving, this looped ~u64::MAX times and never returned.)
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut wal = ScriptedWal::with_entries(0);
  wal.head = u64::MAX; // a pathological / bit-rotted head scalar — ignored by the scan
  wal.capacity = RECOVER_TAIL_WINDOW; // a BOUNDED ring — the scan's probe bound
  let mut sb = sb_formatted(); // formatted-empty: models a store that ran (op_head is corrupt, not wiped)
  // This scenario runs over a BOUNDED ring; re-stamp the durable root's geometry to that ring size so
  // recovery's capacity fence matches the live bounded WAL (`sb_formatted` defaults to the ring-less MAX).
  sb.state = sb
    .state
    .clone()
    .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, RECOVER_TAIL_WINDOW);
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // Complete the genesis geometry-pin root write (the only storage completion outstanding).
  e.storage_step(Instant::ZERO, &mut storage, &mut blocks);
  // The scan found no written slot and there is nothing committed → nothing to read, no phantom
  // read storm, and recovery completes once the geometry pin lands.
  assert_eq!(
    storage.wal_mut().done.len(),
    0,
    "a corrupt head scalar over an empty ring submits NO reads — the scan found no written slot"
  );
  assert_eq!(
    e.status(),
    Status::Normal,
    "nothing to read → Normal once the geometry pin lands"
  );
  assert_eq!(
    e.op(),
    OpNumber::new(),
    "the corrupt head scalar is NOT held — the head derives from the (empty) scan"
  );
}

#[test]
fn recover_does_not_overflow_with_a_checkpoint_op_near_u64_max() {
  // REGRESSION (overflow): `checkpoint_op + 1` and `checkpoint_op + RECOVER_TAIL_WINDOW` must use
  // SATURATING arithmetic so a `checkpoint_op` near `u64::MAX` (a corrupt durable root) cannot
  // overflow-panic while computing the tail window. Here the durable root claims a checkpoint at
  // `u64::MAX - 1` and the WAL head equals it, so the tail range is empty — recovery must construct
  // cleanly (no panic) with no tail reads. (The checkpoint READ itself faults — no snapshot — which
  // the budget/peer-fetch path handles; we only assert the constructor does not overflow.)
  let near_max = u64::MAX - 1;
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(near_max),
    OpNumber::with(near_max),
    0,
    std::vec::Vec::new(),
  )
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None, // the checkpoint read will fault (no snapshot) — not under test here
  };
  let wal = TestWal {
    entries: BTreeMap::new(),
    head: near_max, // head == checkpoint_op → empty tail range
    done: VecDeque::new(),
  };
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  // The CORE assertion is simply that this does not overflow-panic.
  let mut storage = Storage::new(wal, sb);
  let e = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(e.status(), Status::Recovering);
  assert_eq!(
    storage.wal_mut().done.len(),
    0,
    "head == checkpoint_op → the tail range is empty, no tail reads submitted"
  );
}

#[test]
fn recover_op_stays_at_the_verified_frontier_not_the_raw_head() {
  // REGRESSION (a SAFETY regression introduced by the read-window cap): the fix capped the
  // recover READ window at `checkpoint_op + RECOVER_TAIL_WINDOW` but still set `self.op =
  // head.max(checkpoint_op)` (the RAW head). When `head` is far above the window, ops in `(frontier,
  // head]` are "held" per `self.op` yet were NEVER read/verified/cached — so `on_prepare`'s `pop <=
  // self.op` branch would BLIND-RE-ACK them without consulting `self.log`, voting for ops never
  // durably appended (append-before-ack broken → a committed op can be lost if the primary counted
  // that false ack and then died). With the fix `self.op` is the VERIFIED read frontier `hi`, so an
  // op above it is NOT held and a later `Prepare` for it APPENDS (idempotent re-send) before any ack.
  let checkpoint_op = 2u64;
  let frontier = checkpoint_op + RECOVER_TAIL_WINDOW;
  let head = frontier + 1000; // a pathological / bit-rotted head FAR above the read window
  // A CountSm checkpoint at op 2 (applied ops 1,2) + its envelope, with the durable root naming it.
  let mut donor_sm = CountSm::default();
  donor_sm.apply(OpNumber::with(1), &[1]);
  donor_sm.apply(OpNumber::with(2), &[2]);
  let donor_snap = donor_sm.snapshot();
  let env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(checkpoint_op),
    crate::block_address(&donor_snap),
    super::super::session_blocks::encode_sessions(
      &std::collections::BTreeMap::new(),
      &mut crate::block_store::InMemoryBlockStore::new(),
    ),
  );
  let id = crate::checkpoint_id(&env);
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(checkpoint_op),
    OpNumber::with(checkpoint_op),
    id,
    std::vec::Vec::new(),
  )
  .unwrap()
  .with_wal_geometry(RECOVER_TAIL_WINDOW, u64::MAX);
  // A WAL whose head is the pathological value, but which actually HOLDS only the in-window tail
  // `(checkpoint_op ..= frontier]` (reads above the frontier are never submitted). Each tail header is
  // a current-view (view 0) entry so a later Prepare at `frontier+1` is contiguous with the frontier.
  let mut entries = BTreeMap::new();
  for op in (checkpoint_op + 1)..=frontier {
    let h = Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    );
    entries.insert(op, (h, Bytes::from(std::vec![op as u8])));
  }
  let wal = TestWal {
    entries,
    head,
    done: VecDeque::new(),
  };
  let sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: Some((OpNumber::with(checkpoint_op), env)),
  };
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), RECOVER_TAIL_WINDOW).unwrap();
  let now = Instant::ZERO;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  // The envelope names the SM leaf by content address; the leaf lives in the block store so recover
  // restores from the local DAG.
  blocks.put(donor_snap.clone());
  super::super::session_blocks::encode_sessions(&std::collections::BTreeMap::new(), &mut blocks);
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // The head DERIVES from the durable-header scan — the raw scalar is never consulted — so the
  // provisional head is the true written frontier IMMEDIATELY: the phantom band `(frontier, head]`
  // (which the lying scalar claims) has no headers to find and is never materialized nor read.
  assert_eq!(
    e.op(),
    OpNumber::with(frontier),
    "the provisional head is the scanned written frontier — the raw scalar is never consulted"
  );
  // Drive the in-window tail reads + the checkpoint read to completion → Normal.
  while e.status() != Status::Normal {
    e.storage_step(now, &mut storage, &mut blocks);
  }
  // THE core assertion: the recovered head is the VERIFIED read frontier, NOT the raw (pathological) head —
  // the phantom `(frontier, head]` read ABSENT and `recover_progress` capped `self.op` at the highest
  // written op.
  assert_eq!(
    e.op(),
    OpNumber::with(frontier),
    "frontier preserved into Normal — the verified read frontier, never the raw head"
  );
  assert_ne!(
    e.op(),
    OpNumber::with(head),
    "must NOT hold the raw (pathological) head"
  );
  while e.poll_message().is_some() {} // drain everything emitted during recovery

  // A `Prepare` for an op in `(frontier, head]` (here `frontier+1`) must be APPENDED, not blind
  // re-acked: it is `== self.op + 1`, so it takes the append branch. Observable: `self.op` ADVANCES
  // to it (a re-ack would leave op unchanged) and the durable WAL gains the entry; the PrepareOk is
  // DEFERRED to the append completion (no immediate PrepareOk is emitted before the WAL append lands).
  let danger = frontier + 1;
  let p = Prepare::new(
    View::new(),
    OpNumber::with(danger),
    OpNumber::with(frontier),
    OpNumber::with(checkpoint_op),
    crate::Epoch::new(0),
    0,
    ClientId::new(7),
    RequestNumber::with(danger),
    Bytes::from(std::vec![0xAB]),
  );
  e.handle_message(now, &mut storage, primary_peer(), Message::Prepare(p));
  assert_eq!(
    e.op(),
    OpNumber::with(danger),
    "a Prepare above the frontier is APPENDED (op advances), not blind-re-acked",
  );
  assert!(
    storage.wal_mut().entries.contains_key(&danger),
    "the durable WAL gained the appended op (append-before-ack honored)",
  );
  // No PrepareOk for `danger` is emitted yet — it is deferred until the WAL append completes (a blind
  // re-ack would have emitted one INLINE, before the op was durable).
  let premature_ack = {
    let mut found = false;
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.msg_ref()
        && ok.op() == OpNumber::with(danger)
      {
        found = true;
      }
    }
    found
  };
  assert!(
    !premature_ack,
    "no PrepareOk before the append is durable — the false-re-ack path is closed",
  );
}

#[test]
fn recover_restores_the_persisted_log_floor_capped_at_the_recovered_head() {
  // The root persists the writer's adoption-learned carried-log floor. Recovery RESTORES it
  // (without the durable floor, recovery would restart it at the own checkpoint and re-learn it
  // from the next carrier — the un-synced crash window where the restarted node's own carrier could
  // over-span), capped at the recovered head: a floor above what the WAL actually retained has
  // nothing left to bound below it, and the cap keeps the `op >= log_floor` invariant.
  let mk_header = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::new(),
    0,
    std::vec![mk_header(1), mk_header(2)],
  )
  .unwrap()
  .with_log_floor(OpNumber::with(2))
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  // RESTORE: the WAL retained the whole band (head 3 >= floor 2) → the floor restores verbatim.
  let sb = TestSb {
    state: state.clone(),
    done: VecDeque::new(),
    checkpoint: None,
  };
  let wal = ScriptedWal::with_entries(3);
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery(&mut r, &mut storage, &mut blocks, Instant::ZERO);
  assert_eq!(
    r.log_floor,
    OpNumber::with(2),
    "the persisted adoption-learned floor restores (FAIL-BEFORE: restarted at checkpoint_op 0)"
  );
  // CAP: a root whose floor exceeds everything the recovery can re-derive — the band header for
  // op 2 was never held (a SPARSE band: the floor came from an adoption's cluster evidence, not a
  // local hold) and the WAL retained only op 1 → the recovered head is 1 (scan 1, canonical band
  // top 1) and the floor caps there (`op >= log_floor` holds; the force-sync escalation re-learns
  // the cluster floor upward, exactly as with no durable floor at all).
  let sparse = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::new(),
    0,
    std::vec![mk_header(1)],
  )
  .unwrap()
  .with_log_floor(OpNumber::with(2))
  .unwrap()
  .with_wal_geometry(crate::config::DEFAULT_CHECKPOINT_OPS, u64::MAX);
  let sb2 = TestSb {
    state: sparse,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let wal2 = ScriptedWal::with_entries(1);
  let cfg2 = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut blocks2 = crate::block_store::InMemoryBlockStore::new();
  let mut storage2 = Storage::new(wal2, sb2);
  let mut r2 = Endpoint::recover(cfg2, genesis(3), 0, CountSm::default(), &mut storage2)
    .expect("recover accepts this store")
    .expect_active();
  drive_recovery(&mut r2, &mut storage2, &mut blocks2, Instant::ZERO);
  assert_eq!(
    r2.log_floor,
    OpNumber::with(1),
    "a floor above the recovered head caps at the head (nothing below it left to bound)"
  );
}

#[test]
fn a_durable_root_write_carries_the_live_log_floor() {
  // Every durable-root writer threads the LIVE vouched floor into the root (the v7 scalar), so the
  // floor a crash would restore is the one the node actually carries — not its own checkpoint. Pin
  // the threading through the seal writer (`submit_durable_view` → the shared root builder): raise
  // the in-memory floor above the checkpoint, seal, and read the durable root back.
  let mut e = Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    u64::MAX,
  );
  let mut storage = Storage::new(TestWal::default(), sb_at_checkpoint(2));
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  e.force_state_for_test(0, 6, 6, 2, &[]);
  e.log_floor = OpNumber::with(4); // an adoption-learned floor above the own checkpoint (2)
  assert!(
    e.seal_committed_frontier(&mut storage),
    "a Normal node with no in-flight storage seals"
  );
  e.storage_step(Instant::ZERO, &mut storage, &mut blocks);
  assert_eq!(
    storage.sb_mut().state.log_floor(),
    OpNumber::with(4),
    "the durable root carries the live floor, not the checkpoint restart value"
  );
}

#[test]
fn recover_derives_the_head_when_the_op_head_scalar_under_reports_zero() {
  // CONSENSUS-CRITICAL regression (the amnesia direction of the advisory-scalar hazard): a FORMATTED
  // store that RAN — its durable HEADERS hold ops 1..=3 — but whose `op_head()` scalar reads back 0 (a
  // lost write / bit-rot of the scalar, exactly the fault class its contract names) must still recover
  // the full written extent. The scan derives the head from `Wal::header` occupancy, so the lying scalar
  // is never consulted, and the durable format witness means this voter recovers rather than fail-stops.
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut wal = ScriptedWal::with_entries(3);
  wal.head = 0; // the under-reporting scalar — hides all three written slots if trusted
  let sb = sb_formatted(); // a FORMATTED root (the store ran); only the op_head scalar rotted
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  assert_eq!(
    e.op(),
    OpNumber::with(3),
    "the head derives from the durable headers, never the advisory scalar"
  );
  // Complete the tail reads.
  e.storage_step(Instant::ZERO, &mut storage, &mut blocks);
  assert_eq!(e.status(), Status::Normal, "the tail verifies clean");
  assert_eq!(
    e.op(),
    OpNumber::with(3),
    "all three written slots are held after recovery"
  );
}

#[test]
fn recover_fails_stops_a_virgin_voter_even_with_surviving_wal_headers() {
  // CONSENSUS-CRITICAL regression — the exact wipe-amnesia hole the durable-format gate closes. A VOTER
  // whose durable root is empty (`VsrState::new()`) but whose WAL still holds committed headers (ops
  // 1..=3) is a wiped/unformatted store: its format witness AND the durable view it voted in are gone,
  // even though the log survived. It must FAIL-STOP, never silently recover the surviving tail under
  // unvalidated live geometry — recovering it would let an amnesiac voter re-enter the voting set and a
  // view re-decide an already-committed op number. (A voter's genesis always writes a durable format
  // root via `Genesis::commit`, so a virgin voter root can only mean a wipe.)
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let wal = ScriptedWal::with_entries(3); // committed headers survive the wipe of the root
  let sb = TestSb::default(); // the WIPED root: empty `VsrState::new()`, geometry gone
  let mut storage = Storage::new(wal, sb);
  let err = Endpoint::recover(
    cfg,
    genesis(3), // member 1 of 3 is a VOTER
    0,
    CountSm::default(),
    &mut storage,
  )
  .map(|_| ())
  .expect_err("a virgin voter with surviving WAL headers must fail-stop, not recover the tail");
  assert_eq!(err, RecoverError::UnformattedVoter);
  assert!(
    storage.wal_mut().done.is_empty(),
    "the refusal is fail-fast: no storage read was submitted"
  );
}

#[test]
fn recover_resumes_a_virgin_learner_with_surviving_wal_headers() {
  // The learner exemption, the counterpoint to the voter fail-stop above: a non-voting LEARNER never
  // votes, so an empty durable root carries no amnesia risk — it may resume empty and state-sync from
  // the voters. Same virgin root + surviving headers as the voter case, but the local member is a
  // learner (slot 3 of a 3-voter + 1-learner membership), so recovery proceeds instead of fail-stopping.
  let cfg = Config::try_new(1, MemberId::new(3)).unwrap();
  let membership = Membership::from_durable_parts(
    Epoch::new(0),
    3,
    1,
    (0..4u128).map(MemberId::new).collect(),
    0,
  )
  .expect("valid 3-voter + 1-learner genesis membership");
  let wal = ScriptedWal::with_entries(3);
  let sb = TestSb::default(); // virgin root — a learner may resume over it
  let mut storage = Storage::new(wal, sb);
  let recovered = Endpoint::recover(cfg, membership, 0, CountSm::default(), &mut storage)
    .expect("a virgin learner resumes (it never votes)");
  assert!(
    matches!(recovered, Recovered::Active(_)),
    "the learner recovers Active, not fail-stop"
  );
}

#[test]
fn genesis_commit_writes_a_durable_root_so_the_voter_recovers() {
  // The correct-by-construction core of the gate: the ONLY public route to a runnable voter is
  // `Genesis::commit`, which writes a durable FORMAT root. Commit a fresh voter over a virgin store,
  // prove the store is now FORMATTED (a nonzero geometry a wipe cannot forge), then recover over that
  // same store — it RESUMES (Active), the exact opposite of the empty-root fail-stop. A `Genesis` that
  // is never committed yields no runnable endpoint (its `#[must_use]` type-state), so a voter can only
  // ever come to exist over a store carrying this durable root.
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let wal = TestWal::default();
  let mut sb = TestSb::default();
  assert_eq!(sb.state, VsrState::new(), "precondition: a virgin store");
  let endpoint =
    Endpoint::<CountSm, RestartOnly>::new(cfg, genesis(3), 0, CountSm::default(), u64::MAX)
      .commit(&wal, &mut sb)
      .expect("genesis commit formats the virgin store");
  assert_eq!(
    endpoint.view(),
    View::new(),
    "genesis in-memory state: view 0"
  );
  assert_ne!(
    sb.state,
    VsrState::new(),
    "the store is now FORMATTED — a durable root landed synchronously"
  );
  assert_ne!(
    sb.state.checkpoint_ops(),
    0,
    "the format witness: a nonzero recorded geometry an empty-consensus wipe can never forge"
  );
  // Recover over that committed store: the durable format root means this voter RESUMES rather than
  // fail-stopping — the counterpoint to `recover_fails_stops_a_virgin_voter_even_with_surviving_wal_headers`.
  let mut storage = Storage::new(wal, sb);
  let recovered = Endpoint::<CountSm, RestartOnly>::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    &mut storage,
  )
  .expect("a formatted voter store recovers, never fail-stops");
  assert!(
    matches!(recovered, Recovered::Active(_)),
    "the formatted voter resumes Active over its own durable root"
  );
}

#[test]
fn genesis_commit_refuses_a_declared_capacity_that_disagrees_with_the_backend() {
  // CONSENSUS-SAFETY guard on the genesis path: `format` pins the ACTUAL `wal.capacity()` into the
  // durable genesis root, so a `Genesis` that DECLARED a different capacity would build a runnable voter
  // whose in-memory geometry contradicts its own durable root — the WAL laid out under one capacity while
  // the next checkpoint/view root stamps the other. That can later pass recovery's geometry fence yet
  // scan under a layout different from the WAL's real one, recreating the hidden-committed-tail amnesia
  // the fence exists to prevent. `commit` refuses the mismatch BEFORE `format` submits any write, so the
  // store stays VIRGIN and no runnable endpoint is produced.
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut wal = ScriptedWal::with_entries(0);
  wal.capacity = 200; // a bounded ring, comfortably above the floor (33) so ONLY the mismatch fires
  let mut sb = TestSb::default();
  assert_eq!(sb.state, VsrState::new(), "precondition: a virgin store");
  // Declare the unbounded default (u64::MAX) while the backend reports the 200-slot ring.
  let err = Endpoint::<CountSm, RestartOnly>::new(cfg, genesis(3), 0, CountSm::default(), u64::MAX)
    .commit(&wal, &mut sb)
    .map(|_| ())
    .expect_err(
      "a declared/actual WAL-capacity mismatch must be refused, yielding no runnable endpoint",
    );
  assert_eq!(
    err,
    crate::FormatError::WalCapacityMismatch {
      declared: u64::MAX,
      actual: 200,
    }
  );
  assert_eq!(
    sb.state(),
    VsrState::new(),
    "the store stays VIRGIN — the mismatch is refused before any durable genesis root is written"
  );
}

#[test]
fn recover_refuses_a_changed_checkpoint_ops() {
  // The WAL-GEOMETRY fence: the recovery scan window is derived from `checkpoint_ops`, so a restart
  // under a different interval than the durable root pinned could clip a committed tail out of the
  // window. Recovery refuses fail-fast instead.
  let wal = ScriptedWal::with_entries(0);
  let sb = TestSb {
    state: VsrState::new().with_wal_geometry(32, u64::MAX),
    ..Default::default()
  };
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 16).unwrap();
  let mut storage = Storage::new(wal, sb);
  let err = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .map(|_| ())
    .expect_err("a shrunk checkpoint interval must be refused");
  assert_eq!(
    err,
    RecoverError::CheckpointOpsChanged {
      stored: 32,
      configured: 16,
    }
  );
  assert!(
    storage.wal_mut().done.is_empty(),
    "the refusal is fail-fast: no storage read was submitted"
  );
}

#[test]
fn recover_refuses_a_changed_wal_capacity() {
  // The other half of the geometry pair: a bounded backend reopened under a different capacity
  // relocates every ring slot (op → slot placement is capacity-derived) and moves the scan ceiling,
  // so recovery refuses the mismatch; an explicit offline migration is the supported path.
  let wal = ScriptedWal::with_entries(0); // reports u64::MAX (ring-less)
  let sb = TestSb {
    state: VsrState::new().with_wal_geometry(32, 1000),
    ..Default::default()
  };
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap(); // checkpoint_ops 32 matches
  let mut storage = Storage::new(wal, sb);
  let err = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .map(|_| ())
    .expect_err("a changed backend capacity must be refused");
  assert_eq!(
    err,
    RecoverError::WalCapacityChanged {
      stored: 1000,
      reported: u64::MAX,
    }
  );
}

#[test]
fn recover_refuses_a_non_virgin_root_with_unrecorded_geometry() {
  // FAIL-CLOSED on an un-stamped root: a NON-virgin durable root that records NO WAL geometry
  // (both halves zero — `with_wal_geometry` never called) is REFUSED before any storage I/O.
  // Recovery never scans a store on trust when the geometry its scan window is derived from was never
  // pinned (a drift could silently move the window off a committed tail); such a store is migrated
  // offline to a root recording its verified geometry. This is the belt to the
  // construction-time suspenders (every live endpoint stamps a nonzero pair): the fence still refuses a
  // residual unstamped root rather than blessing the live geometry as if it were the writer's.
  let wal = ScriptedWal::with_entries(0); // reports u64::MAX (ring-less), well above the floor
  let unstamped = VsrState::try_new(
    View::with(1),
    View::with(1),
    OpNumber::new(),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
  )
  .unwrap(); // a ran, never-stamped root: `with_wal_geometry` never called → the (0, 0) sentinel pair
  assert_ne!(
    unstamped,
    VsrState::new(),
    "precondition: non-virgin (a ran store) — a virgin store would skip the fence"
  );
  assert_eq!(
    (unstamped.checkpoint_ops(), unstamped.wal_capacity()),
    (0, 0),
    "precondition: the un-stamped root records no geometry"
  );
  let sb = TestSb {
    state: unstamped,
    ..Default::default()
  };
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();
  let mut storage = Storage::new(wal, sb);
  let err = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .map(|_| ())
    .expect_err("a non-virgin geometry-unrecorded root must be refused");
  assert_eq!(
    err,
    RecoverError::GeometryNotRecorded {
      checkpoint_ops: 0,
      wal_capacity: 0,
    }
  );
  assert!(
    storage.wal_mut().done.is_empty(),
    "the refusal is fail-fast: no storage read was submitted"
  );
}

#[test]
fn recover_refuses_a_wal_below_the_liveness_floor() {
  // A ring at or below one checkpoint interval can never release the mint stall (nothing prunes
  // mid-interval), wedging the primary — refused fail-fast with the published floor in the error.
  let mut wal = ScriptedWal::with_entries(0);
  wal.capacity = 16; // below the floor for interval 32
  let sb = TestSb::default();
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 32).unwrap();
  assert_eq!(cfg.minimum_wal_capacity(), 33, "interval + 1");
  let mut storage = Storage::new(wal, sb);
  let err = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .map(|_| ())
    .expect_err("a WAL below the liveness floor must be refused");
  assert_eq!(
    err,
    RecoverError::WalCapacityBelowMinimum {
      capacity: 16,
      minimum: 33,
    }
  );
}

#[test]
fn format_pins_geometry_and_fences_a_shrunk_restart() {
  // `format` is the SOLE geometry pinner: it stamps the WAL-geometry pair into the durable genesis
  // root at cluster creation, so a later restart under a different interval is refused (the recovery
  // scan window is derived from it — a shrink would clip a committed tail). Recovery itself never
  // pins (auto-pinning an unpinned store would bless the live geometry as if it were the writer's).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(1), 32).unwrap();
  let mut wal = ScriptedWal::with_entries(0);
  wal.capacity = 200;
  let mut sb = TestSb::default();
  crate::format(&cfg, &genesis(3), &wal, &mut sb).expect("a virgin store formats");
  assert_eq!(
    (sb.state.checkpoint_ops(), sb.state.wal_capacity()),
    (32, 200),
    "format pins the live geometry pair into the genesis root"
  );
  // Recovery over the formatted store settles synchronously (empty WAL, nothing to read).
  let mut storage = Storage::new(wal, sb);
  let e = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("the formatted store recovers")
    .expect_active();
  assert_eq!(
    e.status(),
    Status::Normal,
    "member 1 is a backup slot, so it resumes Normal (only a primary slot's exemption is gated)"
  );
  drop(e);
  // A restart under a SHRUNK interval is refused off the pinned genesis root.
  let shrunk = Config::with_checkpoint_ops(1, MemberId::new(1), 16).unwrap();
  let err = Endpoint::recover(shrunk, genesis(3), 0, CountSm::default(), &mut storage)
    .map(|_| ())
    .expect_err("the pinned geometry fences the restart");
  assert_eq!(
    err,
    RecoverError::CheckpointOpsChanged {
      stored: 32,
      configured: 16,
    }
  );
}

#[test]
fn a_formatted_genesis_store_resumes_the_view_0_primary() {
  // The genesis path: a FORMATTED store (a real cluster-creation `format` wrote its pinned genesis
  // root) whose designated view-0 primary recovers resumes Normal at view 0 and serves — no spurious
  // startup view change. The format witness is what makes this SOUND: it is a durable marker a wipe
  // cannot forge, so only a genuinely-created cluster's primary takes this path.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap(); // slot 0 leads view 0
  let wal = ScriptedWal::with_entries(0);
  let mut sb = TestSb::default();
  crate::format(&cfg, &genesis(3), &wal, &mut sb).expect("a virgin store formats");
  let mut storage = Storage::new(wal, sb);
  let e = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("the formatted store recovers")
    .expect_active();
  assert_eq!(
    e.status(),
    Status::Normal,
    "a formatted genesis primary resumes Normal, no spurious view change"
  );
  assert_eq!(e.view(), View::new(), "it serves at view 0");
}

#[test]
fn a_wiped_multi_node_voter_fails_stop_rather_than_participating() {
  // THE wipe-amnesia fix. A wiped MULTI-NODE voter's disk is replaced
  // with an empty store whose consensus scalars (view 0, op 0, commit 0) are byte-identical to a
  // genuine genesis — but it carries NO format witness. It must NOT re-enter the voting set with an
  // empty log: abdicating as primary OR resuming as a backup would still let it join a view-change
  // quorum, and a wipe destroys exactly the durable vote that made the old commit quorum intersect
  // the new one — so that quorum could commit a DIFFERENT value at an already-committed op number
  // (e.g. op X committed on slots {0,1}; slot 1 wiped; a partition to {1,2}; slot 1 leads view 1 with
  // slot 2, neither holding X). Fail-stop is the only safe outcome — the wiped node re-provisions
  // (format as a new member, or restore from backup) before rejoining. The ONLY difference from the
  // genesis test above is the absent `format` call.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap(); // slot 0, a voter
  let wal = ScriptedWal::with_entries(0); // wiped: empty WAL
  let sb = TestSb::default(); // wiped: empty root (VsrState::new())
  let err = Endpoint::recover(
    cfg,
    genesis(3),
    0,
    CountSm::default(),
    &mut Storage::new(wal, sb),
  )
  .map(|_| ())
  .expect_err("a wiped multi-node voter must fail-stop, not participate");
  assert_eq!(err, RecoverError::UnformattedVoter);
}

#[test]
fn a_recovered_formatted_primary_with_any_appended_op_still_abdicates() {
  // The exemption's boundary: even a FORMATTED store's primary abdicates once it holds ANY durable
  // op — one appended op means a pipeline/session state the restart lost, so resuming as the
  // established primary is unsafe. The exemption is only the literally-empty formatted-genesis state.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap(); // slot 0 leads view 0
  let wal = ScriptedWal::with_entries(1); // one appended (uncommitted) op
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  crate::format(&cfg, &genesis(3), &wal, &mut sb).expect("formats");
  let mut storage = Storage::new(wal, sb);
  let mut e = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts this store")
    .expect_active();
  // Complete the op-1 tail read; the terminal decision then abdicates despite the format witness.
  e.storage_step(Instant::ZERO, &mut storage, &mut blocks);
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "a formatted primary with durable history still abdicates to a clean view change"
  );
  assert_eq!(e.view(), View::with(1), "abdication targets view + 1");
}

#[test]
fn format_refuses_an_already_initialized_store() {
  // `format` is the once-per-store cluster-creation step: it never clobbers a store that already
  // carries a durable root (an existing member restarts via `recover`, not `format`). This is what
  // stops a second `format` from re-genesis-ing a live member's disk.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap();
  let wal = ScriptedWal::with_entries(0);
  let mut sb = TestSb::default();
  crate::format(&cfg, &genesis(3), &wal, &mut sb).expect("the first format succeeds");
  let err = crate::format(&cfg, &genesis(3), &wal, &mut sb)
    .expect_err("a second format over the now-initialized store is refused");
  assert_eq!(err, crate::FormatError::AlreadyInitialized);
}

#[test]
fn format_over_an_async_superblock_reports_the_write_is_not_durable() {
  // `format` runs at cluster creation, BEFORE any driver run loop exists to pump async I/O, so it
  // requires the genesis-root write to complete SYNCHRONOUSLY. `StepSb` models a real async
  // superblock: `submit_write` queues the write in-flight, and `poll` yields nothing until an
  // external `flush` (the run loop's job) makes it durable. `format` must therefore NOT silently
  // return Ok over a store whose root never landed — a later `recover` would read it as unformatted,
  // or a crash would lose it. It returns `WriteNotDurable`, and the store stays empty.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap();
  let wal = ScriptedWal::with_entries(0);
  let mut sb = StepSb::default();
  let err = crate::format(&cfg, &genesis(3), &wal, &mut sb)
    .expect_err("an async superblock cannot complete the genesis write synchronously");
  assert_eq!(err, crate::FormatError::WriteNotDurable);
  assert_eq!(
    sb.state(),
    VsrState::new(),
    "the store stays UNformatted — no durable genesis root was witnessed"
  );
  // And a synchronous superblock DOES format (the write lands on the first poll).
  let mut sync_sb = TestSb::default();
  crate::format(&cfg, &genesis(3), &wal, &mut sync_sb).expect("a synchronous superblock formats");
  assert_ne!(
    sync_sb.state().checkpoint_ops(),
    0,
    "the synchronous store is now formatted (a nonzero pinned checkpoint_ops witness)"
  );
}

#[test]
fn a_leaked_format_completion_cannot_release_a_view_change_write() {
  // CONSENSUS-SAFETY regression. `format` writes its genesis root under an INCARNATION of its own,
  // which no endpoint recovered over the store ever holds. So even if a `format` on an async
  // superblock leaks its write (it returned WriteNotDurable but the write lands later), the late
  // `Wrote` is refused at the incarnation choke and is inert. Were `format` to share the recovered
  // endpoint's incarnation, that leaked completion could match the endpoint's first-minted
  // durable-view-change root (sequences restart at 1 in every incarnation) and falsely release the
  // `DoViewChange` before its own root is durable — a durable-view-before-participate violation.
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap(); // member 1 leads view 1
  let wal0 = ScriptedWal::with_entries(0);
  let mut sb0 = TestSb::default();
  crate::format(&cfg, &genesis(3), &wal0, &mut sb0).expect("format the genesis store");
  let wal = wal0;
  let sb = sb0;
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts the formatted store")
    .expect_active();
  assert_eq!(
    r.status(),
    Status::Normal,
    "member 1 resumes Normal as a backup"
  );
  while r.poll_message().is_some() {}

  // Drive member 1 into a view change to view 1: an SVC(1) from replica 0 reaches the 2-of-3 SVC
  // quorum {replica 0, own}, so `enter_view_change` submits the SendDoViewChange durable-view root.
  r.handle_message(
    Instant::ZERO,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(r.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  assert!(
    r.pending_sb_for_test(),
    "the SendDoViewChange durable-view root write is in flight"
  );
  while r.poll_message().is_some() {} // discard the SVC chatter; watch for a DVC below

  // Deliver LEAKED format completions — the shape `format` produces when its genesis write lands
  // after `format` already returned `WriteNotDurable`. `format` tags that write with an incarnation
  // of its own, so the INCARNATION alone is what makes these inert. The adversarial part is therefore
  // the sequence number: sequences restart at 1 in every incarnation, so this sweeps the range this
  // endpoint has actually minted — including the exact seq its in-flight `pending_sb` holds. Under a
  // seq-only correlation one of these would collide, release the view-change write, and emit a
  // `DoViewChange` before its durable-view root was durable.
  let foreign = r.own_incarnation().wrapping_add(1);
  for seq in 1..=4 {
    r.on_sb_done(
      Instant::ZERO,
      &mut storage,
      crate::storage::SbPolled {
        done: crate::storage::SuperblockDone::Wrote(crate::WriteId::new(foreign, seq)),
        landed_root: None,
      },
    );
  }
  assert_eq!(
    r.foreign_completions_rejected(),
    4,
    "every leaked completion was REFUSED at the incarnation choke, not merely left unmatched"
  );
  assert!(
    r.pending_sb_for_test(),
    "a leaked format completion does NOT release the view-change write"
  );
  assert!(
    !r.poll_message()
      .is_some_and(|m| matches!(m.msg_ref(), Message::DoViewChange(_))),
    "no DoViewChange is emitted by the leaked format completion"
  );

  // The REAL durable-view completion still releases it normally.
  r.storage_step(Instant::ZERO, &mut storage, &mut blocks);
  assert!(
    !r.pending_sb_for_test(),
    "the actual durable-view root write completes and releases the DoViewChange"
  );
}

#[test]
fn recovery_over_an_inflight_root_baselines_on_the_effective_root_and_defers_behind_it() {
  // CONSENSUS-SAFETY regression (durable-view monotonicity across an in-place rebuild). A
  // predecessor endpoint submits its view-1 durable-view root; before it lands, the driver
  // rebuilds the endpoint over the SAME live session. The successor must come up AT the
  // timeline's view — the landed root still says view 0, but the in-flight root lands in queue
  // order underneath it, so a successor baselined on the landed root would later write its own
  // view-0-or-below root AFTER the view-1 landing and regress the medium's durable view. And the
  // successor's own re-driven root must DEFER behind the predecessor's outstanding one (the root
  // fence), reaching the backend only once the inherited landing settles.
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap(); // member 1 leads view 1
  let wal0 = ScriptedWal::with_entries(0);
  let mut sb0 = TestSb::default();
  crate::format(&cfg, &genesis(3), &wal0, &mut sb0).expect("format the genesis store");
  // Re-home the formatted root under an ASYNC superblock, so root writes stay in flight until an
  // explicit flush — the window an in-place rebuild lands inside.
  let sb = StepSb {
    state: sb0.state(),
    ..StepSb::default()
  };
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let mut storage = Storage::new(wal0, sb);
  let mut a = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover accepts the formatted store")
    .expect_active();
  assert_eq!(a.status(), Status::Normal);
  while a.poll_message().is_some() {}

  // The predecessor enters the view change to view 1: its SendDoViewChange durable-view root is
  // submitted and stays IN FLIGHT (StepSb never flushes on its own).
  a.handle_message(
    Instant::ZERO,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(a.status(), Status::ViewChange);
  assert!(
    a.pending_sb_for_test(),
    "the view-1 root write is in flight"
  );
  drop(a); // the driver replaces the endpoint; the session (and the in-flight root) live on

  // The successor recovers over the live session. Its baseline is the EFFECTIVE root — view 1 —
  // not the landed view-0 root; a voter recovered with `log_view < view` re-drives the view
  // change, so it submits its OWN view-1 root, which the session PARKS behind the predecessor's.
  let mut b = Endpoint::recover(cfg, genesis(3), 1, CountSm::default(), &mut storage)
    .expect("recover accepts the live store")
    .expect_active();
  assert_eq!(
    b.view(),
    View::with(1),
    "the successor baselines on the effective root, never below the timeline"
  );
  assert_eq!(
    b.status(),
    Status::ViewChange,
    "log_view < view: the successor re-drives the in-progress view change"
  );
  assert!(
    b.pending_sb_for_test(),
    "the re-driven view-1 root is pending"
  );
  while b.poll_message().is_some() {}

  // First flush: ONLY the predecessor's root can land — the successor's is parked behind it. Its
  // landing settles through the session (the completion itself is refused as foreign), lifts the
  // durable-view witness, and releases the parked root to the backend; the successor's own write
  // is still in flight, so its DoViewChange stays deferred.
  storage.sb_mut().flush();
  b.storage_step(Instant::ZERO, &mut storage, &mut blocks);
  assert!(
    b.pending_sb_for_test(),
    "the successor's own root was only just released to the backend — not yet durable"
  );
  assert!(
    !b.poll_message()
      .is_some_and(|m| matches!(m.msg_ref(), Message::DoViewChange(_))),
    "no vote is cast while the successor's own view write is outstanding"
  );

  // Second flush: the released root lands, the view is durable, and the deferred vote fires.
  storage.sb_mut().flush();
  b.storage_step(Instant::ZERO, &mut storage, &mut blocks);
  assert!(
    !b.pending_sb_for_test(),
    "the successor's re-driven root landed after the predecessor's, in queue order"
  );
  assert!(!storage.has_inflight(), "the root timeline drained");
}

#[test]
fn a_cancellation_naming_a_dead_incarnations_write_is_refused_at_the_choke() {
  // A `truncate`/`prune` synchronous-cancellation list is COMPLETION-EQUIVALENT data: after a
  // restart in place (the storage layer outlives the endpoint), a conforming backend still holds
  // the DEAD endpoint's staged writes and reports THEIR ids when a truncate trims them. Those ids
  // name a previous incarnation the successor never minted, so they must be refused at the same
  // incarnation rule the completion routers enforce — not treated as a backend-contract violation
  // by the unknown-id assertion, and never keyed into the successor's correlation tables.
  let cfg = Config::try_new(1, MemberId::new(2)).unwrap(); // member 2: a backup of views 0 and 1
  let wal = ReorderWal::new().cancelling();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  crate::format(&cfg, &genesis(3), &wal, &mut sb).expect("format the genesis store");

  // The predecessor stages an op-1 append (the ReorderWal withholds its completion — the write is
  // with the device) and is dropped WITHOUT a drain: the restart-in-place shape.
  let mut storage = Storage::new(wal, sb);
  let mut dead = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover the formatted store")
    .expect_active();
  assert_eq!(dead.status(), Status::Normal, "resumes Normal as a backup");
  dead.handle_message(Instant::ZERO, &mut storage, primary_peer(), prepare(1, 0));
  assert_eq!(
    storage.wal_mut().staged_ops(),
    std::vec![1],
    "the predecessor's append is staged, its completion withheld"
  );
  drop(dead);

  // The successor recovers over the SAME live storage: a fresh incarnation, no writes of its own.
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover over the live storage")
    .expect_active();
  while r.poll_message().is_some() {}

  // Adopt view 1 at canonical head 0 — BELOW the staged op — so the adoption's truncate
  // synchronously cancels the dead incarnation's staged write and returns ITS id.
  r.handle_message(
    Instant::ZERO,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(StartView::new(
      View::with(1),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(1),
      std::vec![],
    )),
  );
  assert_eq!(r.view(), View::with(1), "the adoption completed");
  assert_eq!(
    r.foreign_completions_rejected(),
    1,
    "the dead incarnation's cancelled id was REFUSED at the incarnation choke"
  );
  assert_eq!(
    storage.wal_mut().staged_ops(),
    std::vec![] as std::vec::Vec<u64>,
    "the backend genuinely discarded the dead write — nothing can land late"
  );
  // Drain the adoption's durable-view write: with the dead id refused (and its write proven
  // cancelled by the backend), the successor owes and is owed nothing.
  r.storage_step(Instant::ZERO, &mut storage, &mut blocks);
  assert!(
    !r.has_inflight_storage(&storage),
    "no bookkeeping exists for the dead incarnation's write"
  );
}

#[test]
fn a_foreign_cancellation_cannot_retire_a_live_writes_fence_witness() {
  // The COLLISION shape of the refused-cancellation rule. Sequences restart at 1 in every
  // incarnation, so a dead incarnation's cancelled id can carry the SAME sequence number as a write
  // the successor has live at the device. Retiring by sequence alone would remove the SUCCESSOR's
  // fence witness — the `wal_writes` entry proving its own write is still un-quiesced — so a
  // conflicting re-append could submit while the old bytes can still land (the reordering the
  // slot-quiescence fence exists to prevent), and a graceful-shutdown drain would read quiesced
  // while a write the cluster may act on is still with the device.
  let cfg = Config::try_new(1, MemberId::new(2)).unwrap(); // member 2: a backup of views 0 and 1
  let wal = ReorderWal::new().cancelling();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  crate::format(&cfg, &genesis(3), &wal, &mut sb).expect("format the genesis store");
  let mut storage = Storage::new(wal, sb);
  let mut r = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover the formatted store")
    .expect_active();
  while r.poll_message().is_some() {}

  // The successor's own live write: a view-0 Prepare for op 1 stages an append whose completion
  // the device still owes.
  r.handle_message(Instant::ZERO, &mut storage, primary_peer(), prepare(1, 0));
  let own = *storage
    .wal_mut()
    .staged_ids()
    .first()
    .expect("op 1's append is staged");
  // The dead incarnation's leftover, still with the device across a restart in place: its id
  // carries the live write's SEQUENCE under a DIFFERENT incarnation. Staged at op 2 so the
  // truncate below cancels IT while the live op-1 write survives.
  let foreign = crate::WriteId::new(own.incarnation().wrapping_add(1), own.seq());
  let (header, body) = ReorderWal::predecessor_append(2);
  assert_eq!(
    storage.submit_append(foreign, OpNumber::with(2), header, body),
    crate::storage::AppendSubmission::Submitted,
    "the predecessor's append went to the device through the session that outlives it"
  );

  // Adopt view 1 at canonical head 1 (op 1 committed): the truncate above op 1 cancels ONLY the
  // foreign op-2 write and reports its colliding id; the live op-1 write stays with the device.
  r.handle_message(
    Instant::ZERO,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(StartView::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(1),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(&[1]),
      )],
    )),
  );
  assert_eq!(r.view(), View::with(1), "the adoption completed");
  r.storage_step(Instant::ZERO, &mut storage, &mut blocks); // drain the durable-view write
  assert_eq!(
    storage.wal_mut().staged_ops(),
    std::vec![1],
    "the live op-1 write is still with the device"
  );
  assert!(
    r.has_inflight_storage(&storage),
    "the live write's fence witness is INTACT — the colliding foreign id retired nothing"
  );
  assert_eq!(
    r.foreign_completions_rejected(),
    1,
    "the foreign cancellation was refused at the incarnation choke"
  );

  // The kept witness then drains through the write's OWN completion, exactly once: the abandoned
  // append lands, its completion retires the witness, and the endpoint quiesces.
  assert!(
    storage.wal_mut().release_latest_for(1),
    "the live write lands"
  );
  r.storage_step(Instant::ZERO, &mut storage, &mut blocks);
  assert!(
    !r.has_inflight_storage(&storage),
    "the witness retires via the write's own completion"
  );
}

/// Once a slot's writes have all quiesced, the durable slot holds the identity the replica's vote
/// named — across an endpoint rebuild over live storage exactly as within one incarnation.
///
/// The slot-quiescence fence keeps this within one incarnation: `wal_writes` remembers every
/// un-quiesced physical write, and `submit_or_defer_append` defers any re-append that would touch
/// the same slot until the old write's completion proves it settled. This test drives the SAME
/// schedule across a rebuild: the predecessor endpoint leaves an un-cancellable op-1 append with the
/// device (a proactor write nothing can recall), the successor is built over the live storage, a
/// view change legitimately re-mints op 1 for a DIFFERENT operation, and the successor appends and
/// votes for the replacement. The device then completes the two writes newest-first — an order the
/// `Wal` contract expressly permits — so the predecessor's abandoned bytes land LAST, over the slot
/// whose content the successor's `PrepareOk` already named to the primary. The vote is counted
/// toward a commit quorum by content address, so the durable slot silently disagreeing with it is
/// the committed-value-loss shape: on the next recovery this replica re-serves the predecessor's
/// operation at op 1 with a fully self-consistent header.
///
/// The release loop is schedule-agnostic (it lands whatever is staged, newest-first per op, feeding
/// each completion to the endpoint), so it expresses both the current submit-immediately behaviour
/// and a fence that defers the successor's re-append until the predecessor's write settles: under
/// either, once nothing is staged, the durable identity at op 1 must equal the voted identity.
#[test]
fn a_predecessors_late_landing_never_evicts_a_slot_the_successor_voted() {
  let cfg = Config::try_new(1, MemberId::new(2)).unwrap(); // member 2: a backup of views 0 and 1
  // NON-cancelling: `truncate`/`prune` keep staged writes in flight (un-cancellable device writes),
  // and completions release only when the test lands them — newest-first per op.
  let wal = ReorderWal::new();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  crate::format(&cfg, &genesis(3), &wal, &mut sb).expect("format the genesis store");

  // The predecessor stages an op-1 append (completion withheld — the write is with the device) and
  // is dropped WITHOUT a drain: the restart-in-place shape. Append-before-ack holds, so it never
  // voted for op 1 — no other replica knows the op exists.
  let mut storage = Storage::new(wal, sb);
  let mut dead = Endpoint::recover(cfg, genesis(3), 0, CountSm::default(), &mut storage)
    .expect("recover the formatted store")
    .expect_active();
  assert_eq!(dead.status(), Status::Normal, "resumes Normal as a backup");
  dead.handle_message(Instant::ZERO, &mut storage, primary_peer(), prepare(1, 0));
  assert_eq!(
    storage.wal_mut().staged_ops(),
    std::vec![1],
    "the predecessor's append is staged, its completion withheld, when the endpoint is replaced"
  );
  drop(dead);

  // The successor recovers over the SAME live storage. Its scan reads only landed entries, so op 1
  // is absent and its head is 0 — and its fence witness set starts empty.
  let mut r = Endpoint::recover(cfg, genesis(3), 1, CountSm::default(), &mut storage)
    .expect("recover over the live storage")
    .expect_active();
  while r.poll_message().is_some() {}

  // View 1 formed without this replica (nobody holds op 1 — it was never acked), and its primary
  // re-mints op 1 for a DIFFERENT operation. The successor adopts the canonical log and re-appends
  // op 1 with the replacement identity; commit 0 leaves it uncommitted, so the adoption owes the
  // new primary a `PrepareOk` for it once the append completes.
  let replacement = bytes::Bytes::from_static(b"replacement");
  r.handle_message(
    Instant::ZERO,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(StartView::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(1),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(9),
        RequestNumber::with(1),
        replacement.clone(),
      )],
    )),
  );
  assert_eq!(r.view(), View::with(1), "the adoption completed");
  r.storage_step(Instant::ZERO, &mut storage, &mut blocks); // drain the durable-view write

  // Land every staged write for op 1, newest-first — the completion order the `Wal` contract
  // permits and the one that lands the abandoned predecessor bytes LAST. Each landing's completion
  // is fed to the endpoint before the next; a deferred re-append the fence releases mid-loop simply
  // re-enters the staged set and is landed too. Capture the vote the successor emits along the way.
  let mut voted: Option<u128> = None;
  let mut landings = 0;
  while storage.wal_mut().staged_len() > 0 {
    landings += 1;
    assert!(landings <= 8, "the release loop settles");
    assert!(
      storage.wal_mut().release_latest_for(1),
      "every write staged by this schedule targets op 1"
    );
    r.storage_step(Instant::ZERO, &mut storage, &mut blocks);
    while let Some(out) = r.poll_message() {
      if let Message::PrepareOk(ok) = out.msg_ref()
        && ok.op() == OpNumber::with(1)
        && ok.view() == View::with(1)
      {
        voted = Some(ok.prepare_checksum());
      }
    }
  }

  // ANTI-VACUITY: the successor really voted (the primary will count this toward a commit quorum),
  // and the predecessor's late completion really was delivered into the successor and refused — the
  // landing happened, it just answered a dead endpoint.
  let voted = voted.expect("the successor votes for op 1 once its own append completes");
  assert_eq!(
    r.foreign_completions_rejected(),
    1,
    "the predecessor's completion was delivered across the rebuild and refused at the choke"
  );

  // THE INVARIANT: every write to op 1 has quiesced, so the durable slot must hold exactly the
  // identity the vote named. A mismatch is the predecessor's abandoned operation sitting,
  // self-consistent, where the voted replacement was — committed-value loss on the next recovery.
  let header = storage
    .wal_mut()
    .header(OpNumber::with(1))
    .expect("op 1 is durable");
  let durable =
    crate::storage::prepare_identity(header.client(), header.request(), header.body_checksum());
  assert_eq!(
    durable, voted,
    "op 1's writes have all quiesced, but the durable slot does not hold the identity the \
     successor's PrepareOk named — the predecessor's late landing evicted the voted operation"
  );
  assert_eq!(
    storage.wal_mut().durable_body(1),
    Some(replacement),
    "the durable body at op 1 is the voted replacement"
  );
}

#[test]
fn a_wiped_solo_voter_fails_stop_rather_than_serving_a_new_history() {
  // CONSENSUS-SAFETY regression. A solo cluster (replica_count 1) that committed
  // acked ops, then had its only disk WIPED, comes back with an empty UNFORMATTED store. It has no
  // quorum to abdicate to and no peer to sync from, so resuming Normal would silently authorize a NEW
  // history (a fresh op 1) over the forgotten acked ops. Recovery must FAIL-STOP instead — the loss
  // of the only copy is beyond the fault budget and must be surfaced (re-format or restore).
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap();
  let wal = ScriptedWal::with_entries(0); // wiped: empty WAL
  let sb = TestSb::default(); // wiped: unformatted superblock
  let err = Endpoint::recover(
    cfg,
    genesis(1),
    0,
    CountSm::default(),
    &mut Storage::new(wal, sb),
  )
  .map(|_| ())
  .expect_err("a wiped solo voter must fail-stop, not resume");
  assert_eq!(err, RecoverError::UnformattedVoter);
  // A FORMATTED solo genesis is exempt (the format witness is present) and recovers Normal as usual.
  let wal2 = ScriptedWal::with_entries(0);
  let mut sb2 = TestSb::default();
  crate::format(&cfg, &genesis(1), &wal2, &mut sb2).expect("format the solo genesis store");
  let e = Endpoint::recover(
    cfg,
    genesis(1),
    0,
    CountSm::default(),
    &mut Storage::new(wal2, sb2),
  )
  .expect("a formatted solo store recovers")
  .expect_active();
  assert_eq!(
    e.status(),
    Status::Normal,
    "the formatted solo voter resumes Normal"
  );
}

#[test]
fn a_second_format_attempt_does_not_confirm_off_the_first_attempts_completion() {
  // RETRY-SAFETY regression. `format` confirms success by requiring the durable root to equal
  // EXACTLY the root this call submitted: it drains completions without inspecting ids (each
  // attempt tags its write with a fresh private incarnation), so that root equality is the whole
  // retry-safety guard. A second attempt whose write is still in flight therefore cannot falsely
  // confirm off a first attempt's completion. Here `StepSb` holds writes in flight until `flush`,
  // so neither format attempt sees its root become durable: both must report WriteNotDurable.
  let cfg = Config::try_new(1, MemberId::new(0)).unwrap();
  let wal = ScriptedWal::with_entries(0);
  let mut sb = StepSb::default();
  // Attempt A: submits a genesis root; the async StepSb does not complete it synchronously.
  let a = crate::format(&cfg, &genesis(3), &wal, &mut sb);
  assert_eq!(
    a,
    Err(crate::FormatError::WriteNotDurable),
    "attempt A: write not durable yet"
  );
  // Attempt B over the SAME (still empty) store: A's write is still outstanding, tagged with A's
  // own private incarnation. B must NOT confirm success off A's pending completion — the store's
  // durable root is still empty.
  let b = crate::format(&cfg, &genesis(3), &wal, &mut sb);
  assert_eq!(
    b,
    Err(crate::FormatError::WriteNotDurable),
    "attempt B: must not falsely confirm off A"
  );
  assert_eq!(
    sb.state(),
    VsrState::new(),
    "the store stays unformatted — neither attempt confirmed a durable root"
  );
}

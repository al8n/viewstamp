use super::super::*;
use super::*;
use crate::{
  ClientId, Config, DoViewChange, Header, OpNumber, Prepare, PreparedEntry, Recovery,
  RecoveryResponse, ReplicaId, Request, RequestNumber, SlotStatus, StartView, StartViewChange,
  View, VsrState, Wal,
};
use std::collections::VecDeque;

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
  // known-committed op N.
  //
  // Fix: `recover` sets commit_max = state.commit() (the durable known frontier, keeping commit_min ==
  // checkpoint_op), and the DVC reports commit_max (VSR's commit-number `k` = highest KNOWN committed),
  // so `commit*` reaches N → N is a COMMITTED repair hole (held + peer-repaired), never truncated.
  //
  // Setup: replica 1 of 3. Durable root: view 0, commit 2 (op 2 is KNOWN committed), checkpoint_op 0,
  // with canonical vsr_headers for ops 1 + 2. WAL head 3, but slot 2 reads back PERMANENTLY FAULTY → the
  // recover loop drops it (an interior committed hole). Op 3 is the uncommitted tail.
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
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(3);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // op 2's slot is permanently faulty → dropped
  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "recovers to Normal (op 2 below the head 3 → peer-repair)"
  );
  assert!(
    !r.log.contains_key(&2),
    "the faulty committed slot is dropped from the cache (interior hole)"
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
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  assert_eq!(r.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  r.handle_storage(now, &mut wal, &mut sb); // complete the SendDoViewChange durable-view write
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
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(1),
      OpNumber::with(0),
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
  r.handle_storage(now, &mut wal, &mut sb);
  while r.poll_message().is_some() {}
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );
  r.handle_storage(now, &mut wal, &mut sb); // the repaired append completes → clear hole + resume
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
  // permanently faulty → dropped → an interior committed repair hole. So commit_max == 2 while
  // commit_min == 0 (the SM is restored to the checkpoint; op 2 is a held hole).
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
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(3);
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // op 2's slot is permanently faulty → dropped
  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
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
  assert!(
    !r.log.contains_key(&2),
    "the faulty committed slot is dropped from the cache (interior hole, repaired on demand)"
  );
  while r.poll_message().is_some() {} // discard recovery chatter
  while r.poll_event().is_some() {}

  // Drive replica 1 into a view change: an SVC for view 1 (replica 1 is the primary of view 1) reaches
  // the SVC quorum {replica 1 (own) + replica 0}, so `enter_view_change` fires the `SendDoViewChange`
  // durable-view ROOT write while this replica is STILL held at commit_min 0 < commit_max 2.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  assert_eq!(r.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  assert!(
    r.pending_sb_for_test(),
    "the SendDoViewChange durable-view root write is in flight"
  );
  // Complete the durable-view root write — this is the write the fix changed. The persisted `VsrState`
  // must record the KNOWN-committed frontier `commit_max == 2`, NOT `commit_min == 0`. (FAIL-BEFORE:
  // `submit_durable_view` persisted `self.commit_min`, so the root's commit was 0.)
  r.handle_storage(now, &mut wal, &mut sb);
  assert!(
    !r.pending_sb_for_test(),
    "the durable-view root write completed"
  );
  assert_eq!(
    sb.state().commit(),
    OpNumber::with(2),
    "the durable-view ROOT persists the known-committed frontier commit_max == 2 \
     (FAIL-BEFORE: it persisted commit_min == 0, lowering the durable frontier)"
  );
  // The committed band is now the SPARSE canonical set over `(checkpoint_op .. commit_max] == (0 .. 2]`
  //: one header per HELD op, skipping the op-2 hole. This replica HOLDS op 1 (canonical)
  // but op 2 read back faulty → dropped, so the band records ONLY op 1 — SHORTER than `commit == 2` and
  // with a gap at op 2. The header list is legitimately shorter than `commit`, and the key invariant
  // is that op 1 (a held committed op) keeps its canonical header even though `commit_min == 0`,
  // while the genuinely-not-held op 2 is left header-less
  // and peer-repaired on the next recover. (FAIL-BEFORE the sparse change ranged only up to commit_min,
  // so the band was empty.)
  assert_eq!(
    sb.state()
      .committed_headers_slice()
      .iter()
      .map(|h| h.op().get())
      .collect::<std::vec::Vec<_>>(),
    std::vec![1],
    "the SPARSE band records the held op 1, skips the op-2 hole — shorter than commit == 2, with a gap"
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
  // bug, `sb.state().commit() == 0`, so the re-recovered replica would forget op 2 was committed and its
  // DVC would under-report — re-opening the laggard-quorum truncation hazard the whole fix-chain closes.
  let mut wal2 = ScriptedWal::with_entries(3);
  wal2.script_read_fault(OpNumber::with(2), u8::MAX);
  let cfg2 = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let mut r2 = Endpoint::recover(cfg2, 0, CountSm::default(), &mut wal2, &mut sb);
  for _ in 0..32 {
    r2.handle_storage(now, &mut wal2, &mut sb);
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
fn recover_enters_recovering_then_reaches_normal_after_reads_drain() {
  // recover() is now a metadata-only constructor: it returns in Recovering and only reaches
  // Normal after handle_storage drains the tail reads. (Was: synchronous → Normal immediately.)
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  drop(e);

  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  assert_eq!(
    r.status(),
    Status::Recovering,
    "recover is now a metadata-only constructor (Recovering)"
  );
  r.handle_storage(now, &mut wal, &mut sb); // drain the tail reads
  assert_eq!(r.status(), Status::Normal, "tail consistent => Normal");
  assert_eq!(r.op(), OpNumber::with(2));
}

#[test]
fn recover_retries_a_transient_read_fault_then_reaches_normal() {
  // A ScriptedWal faults op 2's read ONCE, then reads clean. The Recovering loop retries and
  // reaches Normal with the real body — a transient storage fault during recovery is tolerated.
  let mut wal = ScriptedWal::with_entries(2);
  wal.script_read_fault(OpNumber::with(2), 1);
  let mut sb = TestSb::default();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    EchoSm,
    &mut wal,
    &mut sb,
  );
  assert_eq!(r.status(), Status::Recovering);
  // Pump until the retry clears (bounded): each handle_storage drains one round + re-submits.
  for _ in 0..8 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() == Status::Normal {
      break;
    }
  }
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
  let mut sb = TestSb::default();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() != Status::Recovering {
      break;
    }
  }
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
  r.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
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
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
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
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(3), OpNumber::new())),
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
    if let Message::RequestPrepare(rp) = out.into_msg() {
      assert_eq!(rp.op(), OpNumber::with(2));
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
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let cfg = Config::try_new(1, ReplicaId::new(2), 3).unwrap();
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
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
    wal.entries.get(&3).map(|(_, b)| b.as_ref()),
    Some(&[0xAAu8][..]),
    "precondition: the WAL slot 3 still holds the stale [0xAA] body (Clean), dropped only from the cache"
  );
  assert_eq!(
    wal.status(OpNumber::with(3)),
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
    OpNumber::with(2), // primary's commit_min (< op 3): does NOT register op 3 for repair (before-Commit)
    OpNumber::new(),
    ClientId::new(7), // CANONICAL identity (client 7, request 3, body [3]) — differs from the
    RequestNumber::with(3), // stale slot's (client 9, request 99, body [0xAA])
    Bytes::copy_from_slice(&[3]),
  ));
  r.handle_message(now, &mut wal, &mut sb, primary1, canonical_retransmit);
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
    wal.entries.get(&3).map(|(_, b)| b.as_ref()),
    Some(&[3u8][..]),
    "the canonical body [3] overwrote the stale [0xAA] in WAL slot 3 (append-before-ack: durable first)"
  );
  assert!(
    r.log.contains_key(&3),
    "op 3 is back in the cache with the canonical body (re-appended, not a held hole)"
  );

  // Now the append completes → on_wal_done clears `appending(3)` and sends EXACTLY ONE deferred PrepareOk(3).
  r.handle_storage(now, &mut wal, &mut sb);
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
    &mut wal,
    &mut sb,
    primary1,
    Message::Commit(Commit::new(
      View::with(1),
      OpNumber::with(3),
      OpNumber::new(),
    )),
  );
  r.handle_storage(now, &mut wal, &mut sb);
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
  let (r, _wal, _sb) = recovering_with_hole(3, 2);
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
    let mut p = Endpoint::new(
      Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
      0,
      CountSm::default(),
    );
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    p.repair.insert(5); // simulate the old pre-registration of an uncommitted faulty slot
    p.handle_message(
      now,
      &mut wal,
      &mut sb,
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
    let mut p = Endpoint::new(
      Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
      0,
      CountSm::default(),
    );
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    assert!(p.repair.is_empty(), "fresh primary has no repair holes");
    p.handle_message(
      now,
      &mut wal,
      &mut sb,
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
  let (mut r, _wal, _sb) = recovering_head(2);
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
  let (mut r, mut wal, mut sb) = recovering_head(2);
  while r.poll_message().is_some() {} // discard the solicitation
  let now = Instant::ZERO;
  // primary(view 1) of a 3-cluster is replica 1 — but THIS replica is replica 1, so use view 0's
  // primary (replica 0) at a view >= ours (view 0). A same-view StartView from the primary adopts
  // because a RecoveringHead replica is not Normal.
  let sv = StartView::new(
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    ReplicaId::new(0), // primary of view 0
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
    &mut wal,
    &mut sb,
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
  r.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(sb.state().view(), View::new());
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
  let mut sb = TestSb::default();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    CountSm::default(),
    &mut wal,
    &mut sb,
  );
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() != Status::Recovering {
      break;
    }
  }
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
    &mut wal,
    &mut sb,
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
  let (mut r, mut wal, mut sb) = recovering_head(2);
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
    &mut wal,
    &mut sb,
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
  let (mut r, mut wal, mut sb) = recovering_head(2);
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
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::RecoveryResponse(RecoveryResponse::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(2),
      ReplicaId::new(0),
      nonce.wrapping_add(1), // stale/forged
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
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::RecoveryResponse(RecoveryResponse::new(
      View::new(),
      OpNumber::new(),
      OpNumber::new(),
      ReplicaId::new(2), // NOT primary(view 0)
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
  let (mut r, mut wal, mut sb) = recovering_head(2);
  while r.poll_message().is_some() {} // discard the solicitation
  let now = Instant::ZERO;
  // A higher-view Prepare would normally trigger catch_up_to_view → ViewChange. It must be dropped.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::with(5),
      OpNumber::with(3),
      OpNumber::with(2),
      OpNumber::with(0),
      ClientId::new(7),
      RequestNumber::with(3),
      Bytes::from_static(b"z"),
    )),
  );
  // A current-view Prepare for an op we hold would normally re-ack. It must be dropped too.
  r.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  // A Commit would normally advance commit. Dropped.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(1), OpNumber::new())),
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
  let mut wal = wal_in_view(2, 0);
  let mut sb = sb_with_view(0, 0);
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(0), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
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
    &mut wal,
    &mut sb,
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
  let mut wal = wal_in_view(2, 0);
  let mut sb = sb_with_view(0, 0);
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
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
  let mut wal = wal_in_view(2, 0);
  let mut sb = sb_with_view(1, 0);
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(2), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
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
  let mut wal = wal_in_view(2, 0);
  let mut sb = sb_with_view(0, 0);
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(0), 1).unwrap(),
    0,
    CountSm::default(),
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
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
  // And it still serves a fresh request end-to-end (op 3 commits).
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    client_request(1),
  );
  for _ in 0..4 {
    r.handle_storage(now, &mut wal, &mut sb);
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
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, EchoSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Give the primary one committed op so its response is non-trivial.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"a"),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // own append durable → commit op 1 (quorum 2 in N=3? no)
  while e.poll_message().is_some() {}
  // A peer (replica 2) solicits recovery.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::Recovery(Recovery::new(ReplicaId::new(2), 0x1234)),
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
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  assert!(
    !e.has_inflight_storage(),
    "a freshly-constructed endpoint owes no storage completion"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
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
    e.has_inflight_storage(),
    "an outstanding WAL append must report in-flight storage"
  );
  e.handle_storage(now, &mut wal, &mut sb);
  // Drained: `on_wal_done` cleared `pending`/`appending`; the lone own-vote is below quorum so no
  // commit/checkpoint/view write was started — the endpoint owes the driver nothing.
  assert!(
    !e.has_inflight_storage(),
    "after handle_storage drains the completion, no storage op is in flight"
  );
}

#[test]
fn normal_backup_answers_recovery_with_view_only() {
  // A Normal BACKUP answers a Recovery with only its view + echoed nonce (no canonical head):
  // op/commit are 0 and the log is empty. (Replica 2 is a backup of view 0.)
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(2), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::Recovery(Recovery::new(ReplicaId::new(1), 0x5678)),
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
  let mut sb = TestSb::default();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  for _ in 0..16 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() != Status::Recovering {
      break;
    }
  }
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
  .unwrap();
  let mut sb = TestSb {
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

  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
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
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
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
    if let Message::RequestPrepare(rp) = out.into_msg() {
      if rp.op() == OpNumber::with(2) {
        asked_for_2 = true;
      }
    }
  }
  assert!(
    asked_for_2,
    "the replica solicits the canonical op 2 from a peer"
  );

  // A committed-vouching peer answers with the CANONICAL op 2 (body [2], commit=2 >= op 2). This fills
  // the hole and resumes the held commit: op 2 applies with [2] (bodyY), NEVER [0xBB] (bodyX). The fill
  // is a durability barrier: complete the repaired append before the commit resumes.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );
  r.handle_storage(now, &mut wal, &mut sb); // the repaired append completes → apply + resume
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
  let (h2, b2) = wal.entries.get(&2).expect("op 2 present after repair");
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
  .unwrap();
  let mut sb = TestSb {
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

  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
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
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
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
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );
  r.handle_storage(now, &mut wal, &mut sb); // the repaired append completes → apply + resume
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
  .unwrap();
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

  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  // The WAL: ops 1, 3, 4 canonical (header-matched); op 2's slot reads back permanently faulty → a hole.
  let mut wal = ScriptedWal::with_entries(4);
  wal.script_read_fault(OpNumber::with(2), u8::MAX);
  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
    if !r.status().is_recovering() {
      break;
    }
  }
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
    r.log.get(&3).is_some_and(|e| e.body.as_ref() == [3u8]),
    "op 3 (held canonical, sparse-header-matched) is KEPT with its canonical body \
     (FAIL-BEFORE: dropped as a header-less committed op above the lower hole)"
  );
  assert!(
    r.log.get(&4).is_some_and(|e| e.body.as_ref() == [4u8]),
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
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(4), OpNumber::new())),
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
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    repair_prepare(0, 2, 4),
  );
  r.handle_storage(now, &mut wal, &mut sb); // the repaired append completes → apply the held suffix
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
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  // The WAL holds canonical ops 1..=commit_max (head == commit_max), each body [op] header-matched.
  let mut wal = ScriptedWal::with_entries(commit_max);
  // A checkpoint interval far above the window — the regime in which this hazard is reachable.
  let cfg =
    Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, crate::MAX_CHECKPOINT_OPS).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  // THE CORE assertion: the recovered head reads the FULL durable committed band — `self.op >=
  // commit_max`, NOT the old `checkpoint_op + RECOVER_TAIL_WINDOW`. (FAIL-BEFORE: `self.op ==
  // RECOVER_TAIL_WINDOW` < commit_max, hiding the top two held committed ops.)
  assert_eq!(
    r.op(),
    OpNumber::with(commit_max),
    "recover reads up to the durable committed frontier, not checkpoint_op + RECOVER_TAIL_WINDOW \
     (FAIL-BEFORE: self.op == {} < commit_max {commit_max})",
    RECOVER_TAIL_WINDOW
  );
  assert!(
    r.op().get() > RECOVER_TAIL_WINDOW,
    "the held committed band above the OLD cap is NOT hidden"
  );
  // Drain the committed-band reads → Normal, every held op cached + verified.
  for _ in 0..(commit_max + 8) {
    r.handle_storage(now, &mut wal, &mut sb);
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
        .is_some_and(|e| e.body.as_ref() == [op as u8]),
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
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  assert_eq!(r.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  r.handle_storage(now, &mut wal, &mut sb); // complete the SendDoViewChange durable-view write
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
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(RECOVER_TAIL_WINDOW),
      OpNumber::with(RECOVER_TAIL_WINDOW),
      ReplicaId::new(0),
      std::vec::Vec::new(), // the laggard carries no entries (it does not supply the top band)
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
fn recover_caps_the_read_window_when_commit_max_equals_checkpoint_op() {
  // COMPANION test (keep the bogus-`op_head` bound green): when `commit_max == checkpoint_op` (a
  // synced/fresh root with NO committed band above the checkpoint) a HUGE `op_head` must STILL cap at
  // `checkpoint_op + RECOVER_TAIL_WINDOW` — the window bounds the uncommitted tail against bit-rot, and
  // a corrupt superblock cannot inflate `commit_max` to widen it. This is the bogus-head defense the
  // recovery window bound must not weaken.
  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let mut wal = ScriptedWal::with_entries(0);
  wal.head = u64::MAX; // a pathological / bit-rotted head
  let mut sb = TestSb::default(); // VsrState::new(): commit == checkpoint_op == 0
  assert_eq!(
    sb.state().commit(),
    sb.state().checkpoint_op(),
    "the durable root has NO committed band above the checkpoint"
  );
  let now = Instant::ZERO;
  let e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(e.status(), Status::Recovering);
  // With commit_max == checkpoint_op == 0, the floor is checkpoint_op, so `hi` caps at
  // `checkpoint_op + RECOVER_TAIL_WINDOW`: exactly RECOVER_TAIL_WINDOW reads, NOT u64::MAX.
  assert_eq!(
    wal.done.len() as u64,
    RECOVER_TAIL_WINDOW,
    "a bogus huge op_head with no committed band still caps at RECOVER_TAIL_WINDOW"
  );
  assert_eq!(
    e.op(),
    OpNumber::with(RECOVER_TAIL_WINDOW),
    "self.op is the verified frontier checkpoint_op + RECOVER_TAIL_WINDOW (the bogus head is NOT held)"
  );
  let _ = now;
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
  .unwrap();
  let mut sb = TestSb {
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

  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
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
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
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
    OpNumber::with(2), // commit >= op → a committed repair value
    OpNumber::new(),
    client_b,
    RequestNumber::with(3),
    Bytes::copy_from_slice(&[2u8]),
  ));
  r.handle_message(now, &mut wal, &mut sb, primary_peer(), canonical_repair);
  r.handle_storage(now, &mut wal, &mut sb); // the repaired append completes → resume
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
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  };
  let mut wal = ScriptedWal::with_entries(3); // ops 1,2,3 all canonical [op]
  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..32 {
    r.handle_storage(now, &mut wal, &mut sb);
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
    r.log.get(&2).is_some_and(|e| e.body.as_ref() == [2u8]),
    "op 2 kept its canonical WAL body (trusted, not dropped)"
  );
  // Announce commit=2: both committed ops apply directly from the trusted WAL, no peer-repair needed.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
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
  let mut sb = TestSb::default();
  let now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  assert_eq!(r.status(), Status::Recovering);
  // A higher-view Prepare (view 5) — would normally trigger catch_up_to_view → ViewChange.
  let higher = Message::Prepare(Prepare::new(
    View::with(5),
    OpNumber::with(3),
    OpNumber::with(2),
    OpNumber::with(0),
    ClientId::new(7),
    RequestNumber::with(3),
    Bytes::from_static(b"z"),
  ));
  r.handle_message(now, &mut wal, &mut sb, primary_peer(), higher);
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
  let mut sb = TestSb::default();
  let mut now = Instant::ZERO;
  let mut r = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    EchoSm,
    &mut wal,
    &mut sb,
  );
  // A Recovering replica must arm a timer (so an owner driving poll_timeout makes progress).
  assert!(
    r.poll_timeout().is_some(),
    "Recovering arms the recover_retry timer"
  );
  for _ in 0..8 {
    r.handle_storage(now, &mut wal, &mut sb);
    if r.status() == Status::Normal {
      break;
    }
    // Advance to the next timer deadline and fire it (re-submits pending/faulty reads).
    if let Some(t) = r.poll_timeout() {
      now = t;
      r.handle_timeout(now, &mut wal, &mut sb);
    }
  }
  assert_eq!(
    r.status(),
    Status::Normal,
    "the recover_retry timer drives the loop to termination"
  );
}

#[test]
fn recover_rebuilds_log_and_op_from_wal() {
  // A backup appends ops 1,2 durably, then "crashes". recover() from the SAME wal/sb rebuilds
  // op=2 with REAL bodies, view from the superblock. recover() is now metadata-only (returns
  // Recovering); a no-fault TestWal completes the tail reads in one handle_storage → Normal.
  let mut e = backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  // Drop `e` (crash). Recover a fresh endpoint from the SAME durable wal/sb.
  drop(e);
  let mut recovered = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  assert_eq!(
    recovered.status(),
    Status::Recovering,
    "recover is a metadata-only constructor (Recovering)"
  );
  recovered.handle_storage(now, &mut wal, &mut sb); // drain the tail reads → Normal
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
    wal.op_head(),
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
  let cfg = || Config::try_new(1, ReplicaId::new(1), 3).expect("valid cluster config");
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;

  let mut e = Endpoint::new(cfg(), 0, EchoSm);
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  drop(e); // crash

  let mut recovered = Endpoint::recover(cfg(), 0, EchoSm, &mut wal, &mut sb);
  assert_eq!(recovered.status(), Status::Recovering);
  recovered.handle_storage(now, &mut wal, &mut sb); // restore the tail bodies → Normal
  assert_eq!(recovered.status(), Status::Normal);
  recovered.handle_message(
    now,
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(View::new(), OpNumber::with(2), OpNumber::new())),
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
  // the durable view, pump the write, then crash + recover from the SAME wal/sb.
  use crate::StartViewChange;
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(1), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let later = Instant::ZERO + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb); // primary_idle → propose view 1 (own SVC bit)
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
  ); // SVC quorum → ViewChange(view 1) → durable-view write submitted
  e.handle_storage(later, &mut wal, &mut sb); // make the durable-view write complete
  assert_eq!(
    sb.state().view(),
    View::with(1),
    "view 1 is durable before the crash"
  );
  assert_eq!(
    sb.state().log_view(),
    View::new(),
    "the view change did not complete: the durable log_view is still 0 (mid-view-change)"
  );
  drop(e); // crash

  let recovered = Endpoint::recover(
    Config::try_new(1, ReplicaId::new(1), 3).unwrap(),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
  );
  assert_eq!(
    recovered.view(),
    View::with(1),
    "recover() restores the advanced durable view (no regression to view 0)"
  );
  // The durable root is `view 1 / log_view 0` — the replica crashed MID-VIEW-CHANGE (it had
  // escalated to ViewChange(1) and persisted the view, but never installed a view-1 log). Per the
  // Per TigerBeetle replica.zig open(), recovery RE-DRIVES the in-progress view change
  // rather than resuming Normal: `log_view < view` → ViewChange at `view` (NOT Normal, which would
  // wrongly resume a never-completed view change). No op was appended (op_head == 0) and there is no
  // checkpoint, so the empty-WAL fast path settles the terminal status directly in recover().
  assert_eq!(
    recovered.status(),
    Status::ViewChange,
    "a mid-view-change recovery re-drives the view change, it does not resume Normal"
  );
}

#[test]
fn recover_restores_from_the_durable_checkpoint_not_op_zero() {
  // A single-replica primary commits past a checkpoint (checkpoint_ops=2), so the checkpoint is
  // durable; then it "crashes". recover() MUST restore the SM from the checkpoint snapshot and set
  // commit_min == checkpoint_op (NOT 0) — re-applying [1..=checkpoint_op] would double-apply.
  // (The implementation never prunes the WAL at this stage — so the WAL still holds ops [1..=head];
  //  the log cache is rebuilt for the tail (checkpoint_op..=head] only, the snapshot owns the rest.)
  let cfg = || Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let req = |rn: u64| {
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(rn),
      Bytes::from(std::vec![rn as u8]),
    ))
  };
  let mut e = Endpoint::new(cfg(), 0, CountSm::default());
  for rn in 1..=2 {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      req(rn),
    );
    e.handle_storage(now, &mut wal, &mut sb); // append durable → commit → (at op 2) checkpoint
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
  // happens in the Recovering handle_storage loop (Phase 2), so pump it before the SM asserts.
  let mut recovered = Endpoint::recover(cfg(), 0, CountSm::default(), &mut wal, &mut sb);
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
  recovered.handle_storage(now, &mut wal, &mut sb); // restore the SM snapshot + tail bodies → Normal
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
  let good_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
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
  .unwrap();
  let mut sb = ScriptedCheckpointSb::new(
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
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let now = Instant::ZERO;
  let mut e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(e.status(), Status::Recovering);
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "commit_min set to the checkpoint op"
  );

  // Drain #1: the corrupt-bytes read is REJECTED — SM not restored, still Recovering, a new read armed.
  sb.flush(); // release the Phase-1 checkpoint read (the corrupt one)
  e.handle_storage(now, &mut wal, &mut sb);
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

  // Drain #2: the wrong-op read is REJECTED too — still no restore, still Recovering.
  sb.flush(); // release the retry read submitted in drain #1 (the wrong-op one)
  e.handle_storage(now, &mut wal, &mut sb);
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

  // Drain #3: the genuine read is accepted → SM restored, recovery completes to Normal.
  sb.flush(); // release the retry read submitted in drain #2 (the genuine one)
  e.handle_storage(now, &mut wal, &mut sb);
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
  let good_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
  let good_id = crate::checkpoint_id(&good_env);
  let state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(2),
    OpNumber::with(2),
    good_id,
    std::vec::Vec::new(),
  )
  .unwrap();
  let mut sb = ScriptedCheckpointSb::new(
    state,
    VecDeque::from(std::vec![
      // A 2-byte garbage snapshot: too short even for the 8-byte leading op → decode returns None.
      (OpNumber::with(2), Bytes::from_static(&[0xAB, 0xCD])),
      (OpNumber::with(2), good_env.clone()),
    ]),
  );
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 1, 2).unwrap();
  let now = Instant::ZERO;
  let mut e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  // Drain #1: the truncated read does NOT panic — it is rejected; still Recovering.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
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
  // Drain #2: the genuine read completes recovery.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
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
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
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
  .unwrap();
  let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new()); // empty → always faults
  // Empty WAL with head == checkpoint_op (2): the tail range is empty, isolating the checkpoint path.
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let mut e = Endpoint::recover(cfg, 5, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(e.status(), Status::Recovering);

  // Drive well past the per-op retry budget (RECOVER_READ_RETRIES). Each round: flush the inflight
  // fault, then drain. The CORE property: this NEVER panics (the old `assert!` is gone).
  for _ in 0..(RECOVER_READ_RETRIES as usize + 4) {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
  }
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
  let good_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
  let good_id = crate::checkpoint_id(&good_env);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      ReplicaId::new(0),
      nonce,
      good_env.clone(),
    )),
  );
  // apply_sync staged the durable re-persist (two superblock writes); drive them to completion.
  for _ in 0..3 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
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
fn recover_peer_fetch_on_a_primary_steps_down_via_the_abdicate_chokepoint() {
  // The `abdicate_if_primary` chokepoint, site 3 — `on_recover_sync_checkpoint`. The
  // peer-checkpoint fetch RESTORES the SM from a peer snapshot but leaves `inflight` (the commit
  // pipeline) CLEARED while this replica remains the PRIMARY of its view — a wedge if it resumed as
  // primary (`try_commit` can never advance past commit_min). So a multi-replica primary that completes
  // recovery via the peer fetch ABDICATES through the SAME deferred-forfeit chokepoint as the two
  // state-sync sites: it flags `pending_forfeit` (the next `primary_timeouts` re-proposes view + 1)
  // rather than resume Normal as the established primary. This is the path the existing peer-fetch test
  // (a BACKUP) does NOT exercise; here the recovering replica IS the primary of view 0.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, 2).unwrap();
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
  .unwrap();
  let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new());
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let mut e = Endpoint::recover(cfg, 5, CountSm::default(), &mut wal, &mut sb);
  assert!(
    e.is_primary(),
    "replica 0 recovered at view 0 is the primary of its view"
  );
  assert_eq!(e.status(), Status::Recovering);

  // Exhaust the checkpoint-read budget → escalate to a peer fetch (still Recovering, SM not restored).
  for _ in 0..(RECOVER_READ_RETRIES as usize + 4) {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert!(
    e.awaiting_peer_checkpoint_for_test(),
    "the primary escalated to a peer fetch (its own checkpoint is unreadable)"
  );
  assert!(
    !e.pending_forfeit_for_test(),
    "not stepped down yet (still awaiting the peer snapshot)"
  );
  while e.poll_message().is_some() {}

  // A peer answers with a VALID SyncCheckpoint (op 2, matching nonce). The recovering PRIMARY restores
  // the SM via apply_sync, flips Normal — and then the `abdicate_if_primary` chokepoint STEPS IT DOWN.
  let good_snap = CountSm::default().snapshot();
  let good_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
  let good_id = crate::checkpoint_id(&good_env);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(1)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      ReplicaId::new(1),
      nonce,
      good_env,
    )),
  );
  // Drive the staged re-persist to completion.
  for _ in 0..3 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
  }
  // The SM was restored (recovery completed at the peer's checkpoint) AND the primary stepped down.
  assert_eq!(
    e.checkpoint_op(),
    OpNumber::with(2),
    "recovery completed at the peer's checkpoint op"
  );
  assert!(
    e.pending_forfeit_for_test(),
    "the recovered primary abdicated via the abdicate_if_primary chokepoint — it did not \
     resume Normal as the established primary with a torn-down pipeline"
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
    LogEntry {
      client: ClientId::new(7),
      request: RequestNumber::with(5),
      body: Bytes::new(), // … but its EMPTY placeholder was NOT dropped from the cache (the leak).
    },
  );
  e.assert_no_faulty_committed_survives(); // must panic in debug: the leaked slot would apply empty.
}

#[test]
fn recover_does_not_panic_when_a_mismatched_checkpoint_read_always_faults_then_a_peer_serves() {
  // REGRESSION (variant): the checkpoint read MATCHES our read id but its CONTENT is permanently
  // wrong (hash mismatch on every attempt) — the verify-failure path, not a raw Fault. It must route
  // to the SAME budget→peer-fetch escalation (no panic), then a peer's good SyncCheckpoint completes.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
  let now = Instant::ZERO;
  let good_snap = CountSm::default().snapshot();
  let good_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(2), &BTreeMap::new(), &good_snap);
  let good_id = crate::checkpoint_id(&good_env);
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
  .unwrap();
  let corrupt_reads: VecDeque<(OpNumber, Bytes)> = (0..(RECOVER_READ_RETRIES as usize + 6))
    .map(|_| (OpNumber::with(2), Bytes::from_static(b"CORRUPT")))
    .collect();
  let mut sb = ScriptedCheckpointSb::new(state, corrupt_reads);
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: 2,
    done: VecDeque::new(),
  };
  let mut e = Endpoint::recover(cfg, 5, CountSm::default(), &mut wal, &mut sb);
  for _ in 0..(RECOVER_READ_RETRIES as usize + 8) {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb); // must NOT panic on the verify-failure exhaustion
  }
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
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(2),
      good_id,
      ReplicaId::new(0),
      nonce,
      good_env.clone(),
    )),
  );
  for _ in 0..3 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(
    e.status(),
    Status::Normal,
    "recovery completes once a peer serves the genuine checkpoint"
  );
}

#[test]
fn recover_peer_fetch_drops_faulty_committed_slots_instead_of_applying_them_empty() {
  // CRITICAL (committed-state divergence via the peer-checkpoint-fetch recovery path): Phase 1
  // of `recover` seeds an EMPTY-body placeholder for every tail op (headers readable, bodies pending).
  // Phase 2 verifies each; a permanently-faulty COMMITTED-band slot (op 2 here) exhausts its retry
  // budget and lands in `rec.faulty` — but its empty placeholder stays in `self.log`. The protective
  // drop that turns such a slot into a genuine repair hole lives at the END of `recover_progress`,
  // BELOW the `awaiting_peer_checkpoint` early-return. So when the OWN checkpoint snapshot is ALSO
  // unreadable, the replica escalates to a peer fetch, every later `recover_progress` early-returns
  // ABOVE the drop, and `on_recover_sync_checkpoint` then sets `recover = None` + `apply_sync` WITHOUT
  // dropping the faulty slot — `apply_sync`'s held-tail retain keeps `self.log[2] = {body: EMPTY}`. A
  // later `Commit`/`advance_commit` finds `Some({body: EMPTY})` (NOT a hole) and applies the committed
  // op with `&[]` → divergence. FAIL-BEFORE: `self.sm.apply(2, &[])` runs (op 2 applied empty) / op 2
  // is not a repair hole.
  //
  // Setup: replica 1 of 3, checkpoint interval 2. Durable root: commit == commit_max == 3,
  // checkpoint_op == 1, with the SPARSE canonical band headers [h2, h3]. WAL head 3 holds ops 2,3;
  // op-2's body read permanently faults; op-3 is clean. The own checkpoint (op 1) snapshot is
  // permanently unreadable, forcing the peer fetch. A peer then serves checkpoint op 1; we drive to
  // completion, then deliver a Commit(3) and observe op 2 is a repair hole that is request-repaired
  // and applied with its REAL body — never empty.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, 2).unwrap();
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
  .unwrap();
  // ScriptedCheckpointSb with an EMPTY read script → every own checkpoint read FAULTS (the op-1
  // snapshot is permanently unreadable, forcing the peer-fetch escalation).
  let mut sb = ScriptedCheckpointSb::new(state, VecDeque::new());

  // WAL head 3 holds ops 2 and 3 with their canonical bodies; op-2's body read PERMANENTLY faults.
  let mut entries = BTreeMap::new();
  entries.insert(2u64, (h2, body2.clone()));
  entries.insert(3u64, (h3, body3.clone()));
  let mut wal = ScriptedWal {
    entries,
    head: 3,
    read_faults: BTreeMap::new(),
    corrupt: std::collections::BTreeSet::new(),
    done: VecDeque::new(),
  };
  wal.script_read_fault(OpNumber::with(2), u8::MAX); // never clears within any finite budget

  let mut e = Endpoint::recover(cfg, 5, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(e.status(), Status::Recovering);
  assert_eq!(
    e.commit_max(),
    OpNumber::with(3),
    "the durable known-committed frontier is preserved"
  );

  // Drive past the per-op + checkpoint retry budgets so op-2 classes permanently faulty AND the own
  // checkpoint read exhausts → escalation to a peer fetch.
  for _ in 0..(RECOVER_READ_RETRIES as usize + 4) {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
  }
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
  let peer_env =
    Endpoint::<CountSm>::encode_checkpoint(OpNumber::with(1), &BTreeMap::new(), &peer_snap);
  let peer_id = crate::checkpoint_id(&peer_env);
  let nonce = e.sync_nonce_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::SyncCheckpoint(crate::SyncCheckpoint::new(
      View::new(),
      OpNumber::with(1),
      peer_id,
      ReplicaId::new(0),
      nonce,
      peer_env,
    )),
  );
  // Drive the durable re-persist (two superblock writes) to completion → Normal.
  for _ in 0..3 {
    sb.flush();
    e.handle_storage(now, &mut wal, &mut sb);
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

  // THE CORE SAFETY PROPERTY (post-recovery): op 2's EMPTY placeholder was DROPPED from `self.log`, so
  // the apply path treats it as a missing-body hole rather than a held empty entry that advance_commit
  // would apply with `&[]`. (It is not yet REGISTERED in `self.repair` — that is deferred to the
  // on-demand `advance_commit` once commit reaches it, asserted after the Commit below.) The SM reflects
  // only the restored op 1 — op 2 was never applied (empty or otherwise) on any recovery-completion path.
  assert!(
    !e.has_log_entry_for_test(2),
    "op 2's empty placeholder was dropped from the log cache (NOT a held empty entry to apply with &[])"
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
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::with(1),
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
    if let Message::RequestPrepare(r) = out.msg_ref() {
      if r.op() == OpNumber::with(2) {
        solicited_op2 = true;
      }
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
    &mut wal,
    &mut sb,
    primary_peer(),
    Message::Prepare(Prepare::new(
      View::new(),
      OpNumber::with(2),
      OpNumber::with(3), // the answering holder's commit >= op (it committed op 2)
      OpNumber::with(1),
      ClientId::new(7),
      RequestNumber::with(2),
      body2.clone(),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb); // the repair-fill append lands → apply op 2 (real body)
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
fn recover_with_no_checkpoint_is_unchanged() {
  // Backward-compat guard: with checkpoint_op == 0 (no checkpoint yet), recover() behaves EXACTLY
  // as the no-checkpoint path — commit_min == commit_max == 0, a fresh SM (0 applied), log cache [1..=head].
  let cfg = || Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  let mut e = Endpoint::new(cfg(), 0, CountSm::default());
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(1, 0));
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), prepare(2, 1));
  e.handle_storage(now, &mut wal, &mut sb);
  assert_eq!(e.checkpoint_op(), OpNumber::with(0), "no checkpoint taken");
  drop(e);

  let mut recovered = Endpoint::recover(cfg(), 0, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(recovered.status(), Status::Recovering);
  recovered.handle_storage(now, &mut wal, &mut sb); // drain the tail reads → Normal
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
  // REGRESSION (unbounded read submission): a corrupt/buggy `Wal` reporting an enormous
  // `op_head` must NOT make `recover()` bookkeep + submit a read per slot from `checkpoint_op+1`
  // up to that head (billions of inserts/reads/allocations before any async fault-handling runs).
  // With the fix, the per-recover window is capped at `RECOVER_TAIL_WINDOW`, so at most that many
  // reads are submitted regardless of the claimed head. (Before the fix this loops ~u64::MAX times
  // and never returns.)
  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: u64::MAX, // a pathological / bit-rotted head
    done: VecDeque::new(),
  };
  let mut sb = TestSb::default(); // no checkpoint (checkpoint_op == 0) → no checkpoint read
  let e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(e.status(), Status::Recovering);
  // `recover()` submits exactly one read per materialized tail slot, each queued in the WAL's
  // `done` buffer. The count must be bounded by the window, never the claimed head.
  assert!(
    wal.done.len() as u64 <= RECOVER_TAIL_WINDOW,
    "recover submitted {} reads — must be capped at RECOVER_TAIL_WINDOW ({RECOVER_TAIL_WINDOW})",
    wal.done.len()
  );
  assert_eq!(
    wal.done.len() as u64,
    RECOVER_TAIL_WINDOW,
    "with a head far above the window, exactly RECOVER_TAIL_WINDOW slots are materialized"
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
  .unwrap();
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None, // the checkpoint read will fault (no snapshot) — not under test here
  };
  let mut wal = TestWal {
    entries: BTreeMap::new(),
    head: near_max, // head == checkpoint_op → empty tail range
    done: VecDeque::new(),
  };
  let cfg = Config::try_new(1, ReplicaId::new(1), 3).unwrap();
  // The CORE assertion is simply that this does not overflow-panic.
  let e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  assert_eq!(e.status(), Status::Recovering);
  assert_eq!(
    wal.done.len(),
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
  let env = Endpoint::<CountSm>::encode_checkpoint(
    OpNumber::with(checkpoint_op),
    &BTreeMap::new(),
    &donor_sm.snapshot(),
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
  .unwrap();
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
  let mut wal = TestWal {
    entries,
    head,
    done: VecDeque::new(),
  };
  let mut sb = TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: Some((OpNumber::with(checkpoint_op), env)),
  };
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(1), 3, RECOVER_TAIL_WINDOW).unwrap();
  let now = Instant::ZERO;
  let mut e = Endpoint::recover(cfg, 0, CountSm::default(), &mut wal, &mut sb);
  // THE core assertion: the recovered head is the VERIFIED read frontier, NOT the raw head.
  assert_eq!(
    e.op(),
    OpNumber::with(frontier),
    "recover holds the verified read frontier, never the raw (pathological) head"
  );
  assert_ne!(e.op(), OpNumber::with(head), "must NOT hold the raw head");
  // Drive the in-window tail reads + the checkpoint read to completion → Normal.
  while e.status() != Status::Normal {
    e.handle_storage(now, &mut wal, &mut sb);
  }
  assert_eq!(
    e.op(),
    OpNumber::with(frontier),
    "frontier preserved into Normal"
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
    OpNumber::with(frontier), // commit (does not advance past held)
    OpNumber::with(checkpoint_op),
    ClientId::new(7),
    RequestNumber::with(danger),
    Bytes::from(std::vec![0xAB]),
  );
  e.handle_message(now, &mut wal, &mut sb, primary_peer(), Message::Prepare(p));
  assert_eq!(
    e.op(),
    OpNumber::with(danger),
    "a Prepare above the frontier is APPENDED (op advances), not blind-re-acked",
  );
  assert!(
    wal.entries.contains_key(&danger),
    "the durable WAL gained the appended op (append-before-ack honored)",
  );
  // No PrepareOk for `danger` is emitted yet — it is deferred until the WAL append completes (a blind
  // re-ack would have emitted one INLINE, before the op was durable).
  let premature_ack = {
    let mut found = false;
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.msg_ref() {
        if ok.op() == OpNumber::with(danger) {
          found = true;
        }
      }
    }
    found
  };
  assert!(
    !premature_ack,
    "no PrepareOk before the append is durable — the false-re-ack path is closed",
  );
}

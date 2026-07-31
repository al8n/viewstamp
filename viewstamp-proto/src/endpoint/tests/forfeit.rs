use super::*;
use crate::{ClientId, Config, OpNumber, ReplicaId, Request, RequestNumber, View};

#[test]
fn a_forfeiting_primary_drops_client_requests_no_op_reuse() {
  // REGRESSION (an adversarial schedule). A primary that has FLAGGED a forfeit (decided to step down)
  // must NOT assign new ops to client requests: a primary reaches this state after an op-resetting
  // recovery/state-sync left it primary of a view the cluster has moved PAST, so a fresh
  // op-assignment would REUSE a committed op number with DIFFERENT bytes (the stale-primary op-reuse
  // divergence). We reuse the sync-step-down path to arm the forfeit cleanly (NO repair hole and
  // commit_max == commit_min, so the only guard that can drop the request is the `pending_forfeit`
  // one — not the unapplied-prefix guard).
  let cfg = Config::with_checkpoint_ops(1, MemberId::new(0), 1_000).unwrap();
  let mut e =
    Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 0, CountSm::default(), u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  let now = Instant::ZERO;
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
    e.storage_step(now, &mut storage, &mut blocks);
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
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert_eq!(e.commit_max(), OpNumber::with(4), "no unapplied prefix");
  assert!(!e.has_repair_hole_for_test(3), "no repair hole");
  // Arm the forfeit via the sync-step-down path (primary receiving a valid forced SyncCheckpoint).
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
  assert!(
    e.pending_forfeit_for_test(),
    "the primary is now forfeiting"
  );
  while e.poll_message().is_some() {}
  // A fresh client request arrives while the forfeit is pending: it MUST be dropped (no op assigned).
  e.handle_message(
    now,
    &mut storage,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from_static(b"x"),
    )),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(4),
    "a forfeiting primary must NOT assign a new op to a client request (op-reuse guard)"
  );
  let mut saw_prepare = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::Prepare(_)) {
      saw_prepare = true;
    }
  }
  assert!(
    !saw_prepare,
    "a forfeiting primary emits no Prepare for a new request"
  );
}

#[test]
fn a_lagging_primary_forfeits_after_the_grace_period() {
  // Primary (replica 0 of 3), checkpoint_ops=4 ⇒ forfeit lag bound = 4. A quorum reports
  // checkpoint_op = 8 while the primary's own checkpoint_op stays 0 (it is stuck — repairing/
  // syncing while the cluster raced ahead). After the grace period the primary must FORFEIT by
  // PROPOSING a view change (broadcast StartViewChange for view 1) via the SVC machinery — NOT a
  // unilateral view jump (it stays in its own view until a real SVC quorum forms).
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 1, NoopSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary());
  // Two peers report checkpoint_op = 8 (a quorum of 2-of-3 incl. neither self) → the primary's
  // own checkpoint (0) lags the quorum checkpoint (8) by 8 >= the bound 4.
  ep.inject_peer_checkpoint_for_test(1, 8);
  ep.inject_peer_checkpoint_for_test(2, 8);
  assert_eq!(
    ep.quorum_checkpoint_op(),
    OpNumber::with(8),
    "the quorum-checkpoint floor is 8, a full interval beyond the primary's 0"
  );
  // First primary timeout ARMS the grace timer but does NOT forfeit yet (anti-storm: a transient
  // lag must persist for the grace window before the primary steps down).
  let mut storage = Storage::new(wal, sb);
  ep.handle_timeout(Instant::ZERO, &mut storage);
  assert!(
    ep.forfeit_armed_for_test(),
    "the lagging primary armed the forfeit grace timer"
  );
  assert_eq!(
    ep.view().get(),
    0,
    "no forfeit before the grace period elapses (no SVC yet)"
  );
  let mut saw_svc_before_grace = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(svc) = out.into_msg()
      && svc.view().get() == 1
    {
      saw_svc_before_grace = true;
    }
  }
  assert!(
    !saw_svc_before_grace,
    "the primary must NOT propose a view change before the grace period elapses"
  );
  // Advance past the grace period (300ms) and tick again → forfeit: it proposes view 1 (SVC).
  let later = Instant::ZERO + core::time::Duration::from_millis(400);
  ep.handle_timeout(later, &mut storage);
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
    "a stuck primary forfeits by PROPOSING the next view (StartViewChange for view 1), not a unilateral jump"
  );
  assert!(
    !ep.forfeit_armed_for_test(),
    "the grace timer is disarmed once the forfeit fires (no same-view re-forfeit)"
  );
}

#[test]
fn a_healthy_primary_never_forfeits() {
  // The primary keeps pace: its own checkpoint advances in step with the quorum's. The forfeit
  // condition (lag >= a full checkpoint interval) is never satisfied, so the grace timer never
  // arms and no view change is ever proposed — the anti-storm guarantee in steady state.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 1, NoopSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary());
  // A consistent durable state at the checkpoint (commit_min == op == checkpoint_op == 8): a real
  // checkpoint snapshots the SM at `commit_min`, so `checkpoint_op <= commit_min` always — set them
  // together so the handler-exit `assert_invariants` (commit_min >= checkpoint_op) holds.
  ep.force_state_for_test(0, 8, 8, 8, &[]);
  ep.inject_peer_checkpoint_for_test(1, 8);
  ep.inject_peer_checkpoint_for_test(2, 8); // quorum checkpoint 8 == own 8 → lag 0 < bound 4
  let mut storage = Storage::new(wal, sb);
  for ms in [0u64, 400, 800] {
    ep.handle_timeout(
      Instant::ZERO + core::time::Duration::from_millis(ms),
      &mut storage,
    );
    assert!(
      !ep.forfeit_armed_for_test(),
      "forfeit grace is never armed for a healthy primary (ms={ms})"
    );
  }
  assert_eq!(ep.view().get(), 0, "a healthy primary never forfeits");
  let mut saw_svc = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(_) = out.into_msg() {
      saw_svc = true;
    }
  }
  assert!(
    !saw_svc,
    "a healthy primary never proposes a forfeit-driven view change"
  );
}

#[test]
fn a_backup_never_forfeits_even_when_behind() {
  // A BACKUP (replica 1) far behind the quorum checkpoint must NOT forfeit — forfeit is a PRIMARY
  // stepping aside; a behind backup catches up via state-sync/force-sync. The forfeit check lives
  // only on the primary path (primary_timeouts), so the backup never arms it.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(1), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 1, NoopSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  assert!(!ep.is_primary());
  ep.inject_peer_checkpoint_for_test(0, 8);
  ep.inject_peer_checkpoint_for_test(2, 8);
  let mut storage = Storage::new(wal, sb);
  for ms in [0u64, 400, 800] {
    ep.handle_timeout(
      Instant::ZERO + core::time::Duration::from_millis(ms),
      &mut storage,
    );
  }
  assert!(
    !ep.forfeit_armed_for_test(),
    "a backup never arms forfeit (forfeit is exclusively a primary stepping aside)"
  );
}

#[test]
fn solo_primary_with_a_permanent_repair_hole_stays_normal_and_does_not_view_change() {
  // REGRESSION (low-severity): `maybe_forfeit` computed `stuck = lag >= forfeit_checkpoint_lag() ||
  // !self.repair.is_empty()` with NO `replica_count > 1` gate (unlike its four sibling sites). For a
  // SOLO cluster `quorum_view_change() == 1`, so a forfeit → `propose_next_view` →
  // `maybe_start_view_change` would satisfy the VC quorum with the replica's OWN SVC bit alone →
  // transition to ViewChange(view+1); no peer ever sends a StartView, and `view_change_timeouts`
  // re-proposes forever → permanent livelock dropping all client traffic. A solo replica must instead
  // stay Normal and hold commit below the unfillable hole (the precondition — a permanent
  // committed-WAL-slot fault with no peer to repair from — is itself unrecoverable, hence LOW; but
  // abdicating to a non-existent quorum is strictly worse than holding). FAIL-BEFORE: transitions to
  // ViewChange / climbs views.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(1), 1, NoopSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary(), "a solo replica is always its own primary");
  // A permanent committed-but-faulty repair hole at op 3 (no peer exists to serve it); head at op 5,
  // commit HELD at 2 below the hole. This is the unrecoverable solo precondition.
  ep.force_state_for_test(0, 5, 2, 0, &[3]);
  assert!(
    ep.has_repair_hole_for_test(3),
    "the permanent hole is registered"
  );
  assert_eq!(
    ep.commit(),
    OpNumber::with(2),
    "commit starts held below the hole"
  );

  // Drive primary_timeouts WELL past FORFEIT_GRACE (300ms) + VIEW_CHANGE_STATUS (500ms): a buggy solo
  // replica would arm the grace timer, forfeit, satisfy its own 1-of-1 VC quorum, enter ViewChange, and
  // then climb views via view_change_status. The fixed solo replica never forfeits → stays Normal.
  let mut storage = Storage::new(wal, sb);
  for ms in [0u64, 100, 350, 700, 1000, 1500, 2000] {
    ep.handle_timeout(
      Instant::ZERO + core::time::Duration::from_millis(ms),
      &mut storage,
    );
    assert_eq!(
      ep.status(),
      Status::Normal,
      "a solo replica must STAY Normal — never abdicate to a non-existent quorum (ms={ms})"
    );
    assert_eq!(
      ep.view().get(),
      0,
      "a solo replica never climbs views via a forfeit-driven view change (ms={ms})"
    );
  }
  assert!(
    !ep.forfeit_armed_for_test(),
    "a solo replica never even arms the forfeit grace timer"
  );
  // It proposed no view change at all (no StartViewChange ever left the replica).
  let mut saw_svc = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(_) = out.into_msg() {
      saw_svc = true;
    }
  }
  assert!(
    !saw_svc,
    "a solo replica never proposes a forfeit-driven view change"
  );
  // The commit is STILL held below the hole — the op is not lost, it is simply unrecoverable here.
  assert_eq!(
    ep.commit(),
    OpNumber::with(2),
    "commit stays held below the unfillable hole (the op is held, not abandoned)"
  );
}

#[test]
fn a_transiently_lagging_primary_recovers_and_disarms_without_forfeiting() {
  // Anti-storm: a primary that briefly lags (arming the grace timer) but CATCHES UP before the
  // grace elapses must DISARM and never forfeit. Models a primary that was momentarily behind on
  // checkpoint, then checkpointed in step with the cluster within the grace window.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 1, NoopSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary());
  ep.inject_peer_checkpoint_for_test(1, 8);
  ep.inject_peer_checkpoint_for_test(2, 8); // quorum 8, own 0 → lag 8 >= 4 → arms
  let mut storage = Storage::new(wal, sb);
  ep.handle_timeout(Instant::ZERO, &mut storage);
  assert!(ep.forfeit_armed_for_test(), "the lag armed the grace timer");
  // The primary catches its own checkpoint up to the quorum BEFORE the grace elapses. A real catch-up
  // checkpoints at the (now-advanced) `commit_min`, so move commit/op/checkpoint together to 8 — a
  // consistent durable state that satisfies the handler-exit `assert_invariants`. (`force_state_for_test`
  // leaves the armed grace timer intact, which the next tick disarms once the lag is 0.)
  ep.force_state_for_test(0, 8, 8, 8, &[]); // lag now 0 < bound 4
  let mid = Instant::ZERO + core::time::Duration::from_millis(100); // still within the 300ms grace
  ep.handle_timeout(mid, &mut storage);
  assert!(
    !ep.forfeit_armed_for_test(),
    "catching up disarms the grace timer (the transient lag does not forfeit)"
  );
  // Even well past the original grace deadline, no forfeit fires.
  let later = Instant::ZERO + core::time::Duration::from_millis(400);
  ep.handle_timeout(later, &mut storage);
  assert_eq!(
    ep.view().get(),
    0,
    "a primary that caught up never forfeits"
  );
  let mut saw_svc = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(_) = out.into_msg() {
      saw_svc = true;
    }
  }
  assert!(!saw_svc, "no forfeit-driven view change after catch-up");
}

#[test]
fn a_primary_stuck_on_an_unfillable_committed_hole_forfeits_after_the_grace_period() {
  // LIVENESS REGRESSION: a new primary can adopt a canonical head with a COMMITTED
  // interior hole the offset-union could not carry (a committed op a holder checkpointed + pruned
  // past, so it lives only inside a peer's checkpoint snapshot — unservable via `RequestPrepare`).
  // Such a primary is stuck: its commit is HELD below the hole, it cannot serve clients, it cannot
  // fill the hole (no peer can answer), and — holding none of the band above its commit — it
  // retransmits nothing, so backups never ack and no reactive check re-fires. It must FORFEIT so a
  // caught-up replica (the checkpoint holder) leads. Here: primary (replica 0 of 3), commit held at
  // 1 with a committed `repair` hole at op 2 that NO peer answers; after the grace window it must
  // forfeit by PROPOSING view 1 (StartViewChange) — even though its checkpoint does NOT lag (the
  // OTHER forfeit condition is off), so this isolates the unfillable-hole trigger.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 1, NoopSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary());
  // Head 10, commit HELD at 1 below a committed hole at op 2, own checkpoint 1 == quorum (no
  // checkpoint-lag). Checkpoint == commit_min (a real checkpoint snapshots the SM at `commit_min`, so
  // `checkpoint_op <= commit_min`) and the hole sits ABOVE the checkpoint — a consistent, reachable
  // state that satisfies the handler-exit `assert_invariants` while still isolating the unfillable-hole
  // forfeit trigger from the checkpoint-lag one (lag 0).
  ep.force_state_for_test(0, 10, 1, 1, &[2]);
  ep.inject_peer_checkpoint_for_test(1, 1);
  ep.inject_peer_checkpoint_for_test(2, 1); // quorum 1 == own 1 → lag 0 (the lag trigger is OFF)
  // First primary tick ARMS the grace timer (the hole is outstanding) but does NOT forfeit yet.
  let mut storage = Storage::new(wal, sb);
  ep.handle_timeout(Instant::ZERO, &mut storage);
  assert!(
    ep.forfeit_armed_for_test(),
    "an outstanding committed repair hole arms the forfeit grace timer"
  );
  assert_eq!(ep.view().get(), 0, "no forfeit before the grace elapses");
  while ep.poll_message().is_some() {}
  // Past the grace window, with the hole STILL unfilled (no peer answered) → forfeit (propose view 1).
  let later = Instant::ZERO + core::time::Duration::from_millis(400);
  ep.handle_timeout(later, &mut storage);
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
    "a primary stuck on an unfillable committed hole forfeits (proposes view 1) after the grace window"
  );
}

#[test]
fn a_primary_whose_committed_hole_fills_within_grace_does_not_forfeit() {
  // ANTI-STORM complement of the above: a committed repair hole that a peer CAN serve is filled by
  // the answering `Prepare` well within the grace window, emptying `repair` and DISARMING the
  // forfeit — so a FILLABLE hole (the ordinary repair case) never triggers a view change. Primary
  // (replica 0 of 3), commit held at 1 with a hole at op 2; a peer answers with op 2's
  // committed-vouching Prepare (commit 2 >= op 2) before the grace elapses.
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 1, NoopSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::InMemoryBlockStore::new();
  assert!(ep.is_primary());
  // Head 2, commit 1, a committed hole at op 2, own checkpoint 0 (no checkpoint-lag peers injected).
  ep.force_state_for_test(0, 2, 1, 0, &[2]);
  // First tick arms the grace timer (the hole is outstanding).
  let mut storage = Storage::new(wal, sb);
  ep.handle_timeout(Instant::ZERO, &mut storage);
  assert!(
    ep.forfeit_armed_for_test(),
    "the outstanding committed hole arms the grace timer"
  );
  while ep.poll_message().is_some() {}
  // A peer answers our RequestPrepare with op 2's committed-vouching Prepare → fills the hole (once the
  // repaired append is durable — the durability barrier).
  ep.handle_message(
    Instant::ZERO,
    &mut storage,
    primary_peer(),
    repair_prepare(0, 2, 2),
  );
  ep.storage_step(Instant::ZERO, &mut storage, &mut blocks); // the repaired append completes → clear the hole
  assert!(
    !ep.has_repair_hole_for_test(2),
    "the committed-vouching Prepare fills the hole"
  );
  // Next tick within the grace window: the hole is gone → the grace timer DISARMS, no forfeit.
  let mid = Instant::ZERO + core::time::Duration::from_millis(100);
  ep.handle_timeout(mid, &mut storage);
  assert!(
    !ep.forfeit_armed_for_test(),
    "filling the hole disarms the grace timer (a fillable hole does not forfeit)"
  );
  let later = Instant::ZERO + core::time::Duration::from_millis(400);
  ep.handle_timeout(later, &mut storage);
  let mut saw_svc = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(_) = out.into_msg() {
      saw_svc = true;
    }
  }
  assert!(
    !saw_svc && ep.view().get() == 0,
    "a primary whose committed hole filled in time never forfeits"
  );
}

#[test]
fn a_forfeiting_primary_keeps_proposing_and_stops_heartbeating_until_the_view_changes() {
  // REGRESSION (a one-shot forfeit can be LOST → the cluster wedges): when the FIRST forfeit
  // StartViewChange is dropped/partitioned, the OLD code cleared `pending_forfeit` one-shot and the
  // primary RESUMED heartbeating — so every backup kept resetting its `primary_idle` (none started
  // its own VC) and the SVC retransmit timer was never serviced while Normal, wedging the cluster
  // below the unrepairable hole. The fix keeps forfeiting until the view actually changes: on the SVC
  // retransmit cadence the primary RE-PROPOSES view+1 AND skips the commit heartbeat + prepare
  // retransmit, so backups stop hearing the primary and join the SVC. Here we DROP every emitted SVC
  // and tick repeatedly AT the retransmit cadence (100ms apart, so the `svc_message` timer is due each
  // tick): the primary must (a) re-broadcast the SVC each due tick, (b) NEVER emit a Commit heartbeat,
  // and (c) keep `pending_forfeit` latched — none of which the one-shot code did. (The companion test
  // `..._rate_limits_its_svc_rebroadcast_...` ticks at SUB-cadence spacing to pin the rate limit.)
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, NoopSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary(), "replica 0 at view 0 is the primary");
  // Enter the force-sync strand → the primary flags a deferred forfeit (a committed hole at op 2 a
  // peer has already checkpointed+pruned past).
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
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
  assert!(
    ep.pending_forfeit_for_test(),
    "the strand flagged a deferred forfeit"
  );
  while ep.poll_message().is_some() {} // discard anything emitted on entry

  // Tick the primary repeatedly at advancing times, DROPPING every emitted message (the SVC is
  // partitioned away). Across EVERY tick: an SVC for view 1 is re-proposed, and NO Commit heartbeat
  // is ever emitted. The view never changes (the lone SVC forms no quorum), and the flag persists.
  for i in 0..5u64 {
    let now = Instant::ZERO + core::time::Duration::from_millis(100 * (i + 1));
    ep.handle_timeout(now, &mut storage);
    let mut saw_svc_view1 = false;
    let mut saw_commit_heartbeat = false;
    while let Some(out) = ep.poll_message() {
      match out.into_msg() {
        Message::StartViewChange(svc) if svc.view().get() == 1 => saw_svc_view1 = true,
        Message::Commit(_) => saw_commit_heartbeat = true,
        _ => {}
      }
    }
    assert!(
      saw_svc_view1,
      "tick {i}: the forfeiting primary RE-PROPOSES view 1 each due tick (idempotent re-broadcast under loss)"
    );
    assert!(
      !saw_commit_heartbeat,
      "tick {i}: the forfeiting primary must NOT heartbeat (so backups idle-out and join the SVC) — \
       the one-shot code resumed heartbeating here and wedged the cluster"
    );
    assert_eq!(
      ep.view().get(),
      0,
      "tick {i}: view unchanged while the lone SVC forms no quorum"
    );
    assert!(
      ep.pending_forfeit_for_test(),
      "tick {i}: the forfeit latch PERSISTS until the view actually changes"
    );
  }

  // Now a backup's StartViewChange for view 1 ARRIVES → with the primary's own bit, an SVC quorum
  // (2-of-3) forms → the view changes. Leaving Normal-primary CLEARS the latch (the new generation
  // re-evaluates from scratch), so the cluster is unwedged.
  let now = Instant::ZERO + core::time::Duration::from_millis(700);
  ep.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(crate::StartViewChange::new(
      View::with(1),
      ReplicaId::new(1),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    ep.view().get(),
    1,
    "an SVC quorum (primary + one backup) forms → the view changes (the cluster is NOT wedged)"
  );
  assert!(
    ep.status().is_view_change(),
    "the primary transitioned into the view change for view 1"
  );
  assert!(
    !ep.pending_forfeit_for_test(),
    "leaving Normal-primary clears the forfeit latch (no cross-view leak)"
  );
}

#[test]
fn a_forfeiting_primary_rate_limits_its_svc_rebroadcast_within_one_retransmit_window() {
  // LIVENESS REGRESSION (an adversarial schedule): a forfeiting primary RE-PROPOSES view+1 to keep stepping
  // down under loss — but it must do so on the SVC-retransmit CADENCE, not on EVERY `handle_timeout`
  // tick. The old code called `forfeit()` → `propose_next_view()` → `join_svc()` → `push_svc()`
  // unconditionally each primary tick, so a primary stuck `pending_forfeit` while the cluster ran on
  // in a higher view broadcast an SVC EVERY tick — an unbounded StartViewChange STORM. In the
  // simulator (Instant is nanos; the clock advances to the nearest pending deadline) that storm
  // floods the network and PINS the virtual clock to sub-millisecond steps, starving the live view's
  // primary's 50ms Commit heartbeat → the stale-view holdout never hears the new view to catch up,
  // and the cluster livelocks. The fix gates the re-broadcast on the `svc_message` timer (exactly
  // like `view_change_timeouts`): one SVC per `VC_MESSAGE_RETRANSMIT` window, no per-tick storm.
  //
  // Here we tick the forfeiting primary MANY times all WITHIN a single retransmit window (sub-window
  // spacing), dropping every message: exactly ONE SVC may be emitted across the whole window (the
  // first), never one-per-tick. (Heartbeat suppression + latch persistence are covered by the sibling
  // test above; this one isolates the rate limit.)
  let cfg = Config::with_checkpoint_ops(0, MemberId::new(0), 4).unwrap();
  let mut ep = Endpoint::<_, RestartOnly>::genesis_unchecked(cfg, genesis(3), 7, NoopSm, u64::MAX);
  let (wal, sb) = (TestWal::default(), TestSb::default());
  assert!(ep.is_primary(), "replica 0 at view 0 is the primary");
  // Enter the force-sync strand → the primary flags a deferred forfeit (a committed hole at op 2 a
  // peer has already checkpointed + pruned past), mirroring the sibling persistence test's setup.
  ep.force_state_for_test(0, 10, 1, 0, &[2]);
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
  assert!(
    ep.pending_forfeit_for_test(),
    "the strand flagged a deferred forfeit"
  );
  while ep.poll_message().is_some() {} // discard the entry-time SVC

  // Tick repeatedly WITHIN one VC_MESSAGE_RETRANSMIT (100ms) window — sub-window spacing (10ms apart,
  // ten ticks span 0<t<100ms, none crossing the cadence boundary) — dropping every message. Across
  // the WHOLE window the primary may emit at most ONE SVC (the storm emitted one PER tick).
  let mut svc_count = 0usize;
  for i in 0..10u64 {
    // Times 10ms, 20ms, .. 100ms — all at or before the first retransmit deadline (armed at entry +
    // 100ms). The 100ms tick is the boundary where exactly one re-broadcast is allowed.
    let now = Instant::ZERO + core::time::Duration::from_millis(10 * (i + 1));
    ep.handle_timeout(now, &mut storage);
    while let Some(out) = ep.poll_message() {
      if let Message::StartViewChange(svc) = out.into_msg()
        && svc.view().get() == 1
      {
        svc_count += 1;
      }
    }
  }
  assert!(
    svc_count <= 1,
    "a forfeiting primary rate-limits its SVC to the retransmit cadence (at most one per \
     VC_MESSAGE_RETRANSMIT window) — got {svc_count} (the per-tick STORM that pins the sim clock and \
     starves the live primary's heartbeat → a re-broadcast livelock)"
  );
  assert!(
    ep.pending_forfeit_for_test(),
    "the forfeit latch still persists (rate-limiting the broadcast does not abandon the step-down)"
  );

  // After the cadence elapses, the next due tick DOES re-broadcast (still stepping down under loss).
  let past_window = Instant::ZERO + core::time::Duration::from_millis(250);
  ep.handle_timeout(past_window, &mut storage);
  let mut saw_svc_after_window = false;
  while let Some(out) = ep.poll_message() {
    if let Message::StartViewChange(svc) = out.into_msg()
      && svc.view().get() == 1
    {
      saw_svc_after_window = true;
    }
  }
  assert!(
    saw_svc_after_window,
    "once the retransmit window elapses the forfeiting primary re-broadcasts the SVC (persistent \
     step-down under loss is preserved — only the per-tick storm is removed)"
  );
}

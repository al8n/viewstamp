use super::*;
use crate::{
  ClientId, Config, OpNumber, ReplicaId, Request, RequestNumber, StartViewChange, Superblock, View,
  Wal,
};

#[test]
fn new_primary_in_pending_view_window_does_not_spin_a_poll_timeout_driver() {
  // A replica that just became Normal primary of a new view but whose durable-view write is still in
  // flight (`pending_sb`, the durable-view-before-participate window) deferred `arm_timers` to
  // `on_sb_done` — so the STALE ViewChange cadence timers
  // (`svc_message`/`dvc_message`/`view_change_status`, armed by `enter_view_change`) are STILL armed and
  // are status-foreign: `primary_timeouts`' `pending_sb` early-return does NOT service them, and
  // `view_change_timeouts` (which would) runs only in ViewChange status. A poll_timeout()-driven driver
  // therefore advances virtual time to the earliest stale deadline, `handle_timeout` does nothing for
  // it, and `poll_timeout()` re-returns the SAME deadline → the clock spins at that instant, never
  // reaching the in-flight superblock completion that would begin participation → the new primary wedges
  // (the cluster never gets a primary for the new view). The fix RETIRES those stale timers in the
  // `pending_sb` branch (the window is driven purely by the superblock completion, not a timer).
  let (mut e, mut wal, mut sb) = primed_new_primary_in_pending_view_window();
  let now = Instant::ZERO;
  assert!(e.is_primary() && e.status().is_normal() && e.pending_sb_for_test());
  // FAIL-BEFORE: the first `handle_timeout` at the stale deadline does not advance/clear it, so the
  // SECOND `poll_timeout()` returns the same instant → the strict-advance assert fires (spin). The
  // superblock write is deliberately NOT flushed, so the only way out is the (broken) timer path.
  // Once the stale timers are retired and nothing else is armed, `poll_timeout()` is `None` — the
  // CORRECT terminal state for this window (the replica is driven purely by the superblock completion,
  // no timer), so the `while let` exits cleanly. FAIL-BEFORE it never reaches `None`: the stale
  // ViewChange deadline is re-returned every step and the strict-advance assert fires (spin).
  let mut last = now; // strictly before the first armed deadline
  let mut steps = 0usize;
  while let Some(due) = e.poll_timeout() {
    assert!(
      due > last,
      "poll_timeout must strictly ADVANCE in the pending-view window, not spin on a stale ViewChange \
       deadline ({due:?} <= {last:?})"
    );
    last = due;
    e.handle_timeout(due, &mut wal, &mut sb);
    while e.poll_message().is_some() {}
    steps += 1;
    assert!(
      steps < 64,
      "the pending-view window must settle to a non-spinning state within a few ticks"
    );
    // Defensive: the window must not have silently resolved itself off a timer (it should resolve only
    // via the superblock completion, which we have NOT delivered).
    assert!(
      e.pending_sb_for_test(),
      "the durable-view window stays open until the superblock completes (no timer resolves it)"
    );
  }
  // PASS-AFTER: the durable-view completion (not a timer) is what begins participation. Deliver it and
  // confirm the new primary now broadcasts its StartView and arms its real Normal-primary timers.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb);
  assert!(
    !e.pending_sb_for_test(),
    "the view is now durable (the superblock completion, not a timer, resolved the window)"
  );
  let mut saw_start_view = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::StartView(_)) {
      saw_start_view = true;
    }
  }
  assert!(
    saw_start_view,
    "once the view is durable the new primary begins participating (broadcasts StartView)"
  );
  assert_eq!(
    e.poll_timeout(),
    Some(now + COMMIT_HEARTBEAT),
    "and it arms its real Normal-primary heartbeat timer (participation resumed cleanly)"
  );
}

#[test]
fn view_changing_replica_with_a_repair_hole_does_not_spin_a_poll_timeout_driver() {
  // A replica holding a committed-op
  // `repair` hole that enters ViewChange keeps the hole (no transition clears `repair`), and
  // `arm_timers` re-arms `repair_retry` whenever `repair` is non-empty REGARDLESS of status. But
  // `handle_timeout` GATES `repair_timeouts` on `Status::Normal` (only a Normal replica solicits/serves
  // a hole), so in ViewChange the `repair_retry` timer is armed-but-never-serviced: `view_change_timeouts`
  // ignores it. After the first tick re-arms svc/dvc to the next cadence, `repair_retry` stays at its
  // (earlier) deadline, so `poll_timeout()` pins there and a deadline-driven driver SPINS — the view
  // change never progresses. The fix gates `arm_timers`' `repair_retry` arming on `Status::Normal`, so
  // the arm-site condition matches the service-site gate and no orphaned timer is left in ViewChange.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap(); // replica 1: backup of view 0
  let mut e = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  // A Normal backup holding a committed-op repair hole at op 2 (commit held at 1 below it).
  e.force_state_for_test(0, 10, 1, 0, &[2]);
  assert!(!e.is_primary());
  assert!(
    e.has_repair_hole_for_test(2),
    "precondition: a repair hole is outstanding"
  );
  // Drive into ViewChange(1): the primary-idle timeout proposes view 1, and replica 0's SVC completes
  // the quorum → transition to ViewChange while STILL holding the repair hole.
  e.handle_timeout(
    Instant::ZERO + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
  );
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
  );
  assert_eq!(e.status(), Status::ViewChange, "now view-changing");
  assert!(
    e.has_repair_hole_for_test(2),
    "the repair hole is carried into the view change (no transition clears it)"
  );
  while e.poll_message().is_some() {}
  // Drive PURELY via poll_timeout() and assert the clock strictly advances (never spins on the
  // unserviced `repair_retry`) AND the view change keeps making progress (re-broadcasts its SVC/DVC
  // across multiple strictly-advancing cadence windows).
  let mut last = Instant::ZERO; // strictly before the first armed deadline (100ms)
  let mut distinct_advances = 0usize;
  for _ in 0..64 {
    let due = e
      .poll_timeout()
      .expect("a timer is armed while view-changing");
    assert!(
      due > last,
      "poll_timeout must strictly ADVANCE while view-changing, not spin on the unserviced \
       repair_retry timer ({due:?} <= {last:?})"
    );
    last = due;
    distinct_advances += 1;
    e.handle_timeout(due, &mut wal, &mut sb);
    while e.poll_message().is_some() {}
    if distinct_advances >= 5 {
      break; // five strictly-advancing windows is ample proof the clock is not pinned
    }
  }
  assert!(
    distinct_advances >= 5,
    "the view-changing replica's clock advances through multiple cadence windows (no spin)"
  );
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "it is still driving the view change (it did not get stuck / silently leave)"
  );
}

#[test]
fn forfeiting_primary_does_not_spin_a_poll_timeout_driver() {
  // LIVENESS (follow-on of the forfeit-storm fix). A forfeiting primary STOPS
  // heartbeating, but a poll_timeout()-driven driver (a real async driver advances virtual time to the
  // EARLIEST armed deadline, then calls handle_timeout) WEDGES at the stale `commit` deadline if that
  // deadline is left armed-and-due: `primary_timeouts`' `pending_forfeit` branch returns early WITHOUT
  // servicing/re-arming `commit`, so `poll_timeout()` keeps returning the SAME (earlier-than-svc_message)
  // commit deadline → the clock never advances to the svc_message cadence → the view change never
  // progresses (the cluster wedges: the old primary is silent but does not step down). The fix RETIRES
  // `commit`/`prepare` in the forfeit branch so `svc_message` is the sole primary-side driver.
  //
  // We arm the forfeit the REAL way on an EXISTING, heartbeating primary: a primary that has committed
  // a tail (so it would heartbeat) receives a valid forced `SyncCheckpoint` → it STEPS DOWN
  // (`pending_forfeit`) rather than apply the sync in place (the op-reuse guard). This arms the
  // forfeit with NO repair hole and NO grace timer, so the ONLY armed cadence timer is the heartbeat
  // `commit` (50ms COMMIT_HEARTBEAT) — earlier than the post-forfeit `svc_message` (100ms
  // VC_MESSAGE_RETRANSMIT) — which is exactly the stale spinner.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, 1_000).unwrap();
  let mut e = Endpoint::new(cfg, 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let now = Instant::ZERO;
  // Commit a tail (head == commit == 4) the real way: client requests → own append durable → a peer's
  // PrepareOk commits each. No repair hole, commit_max == commit_min (a clean, healthy primary).
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
        // content-address the vote to op rn's full identity (client 7, request rn, body [rn])
        crate::storage::prepare_identity(
          ClientId::new(7),
          RequestNumber::with(rn),
          crate::storage::fnv1a_128(&[rn as u8]),
        ),
      )),
    );
  }
  assert_eq!(e.op(), OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  assert!(!e.has_repair_hole_for_test(3), "no repair hole");
  // Tick the primary ONCE so its `commit` heartbeat timer is armed (a real primary is heartbeating
  // before it forfeits — the bug needs `commit` already armed when `pending_forfeit` is set).
  e.handle_timeout(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  let commit_deadline = e
    .poll_timeout()
    .expect("the heartbeating primary armed its commit timer");
  assert_eq!(
    commit_deadline,
    now + core::time::Duration::from_millis(50),
    "precondition: the only armed timer is the 50ms commit heartbeat"
  );
  // Now arm the forfeit the REAL way: a valid forced SyncCheckpoint on this (still-heartbeating)
  // primary makes it STEP DOWN (the op-reuse guard) — `pending_forfeit` is set while `commit`
  // is already armed at 50ms. No grace timer / repair hole is involved (clean step-down path).
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
  assert!(
    e.pending_forfeit_for_test(),
    "the heartbeating primary is now forfeiting (it stepped down rather than apply the sync)"
  );
  while e.poll_message().is_some() {}

  // Drive the endpoint PURELY via poll_timeout() — exactly as a real deadline-driven driver does —
  // and assert the clock STRICTLY ADVANCES (never spins on the stale commit deadline) AND the primary
  // re-broadcasts the StartViewChange{view+1} across MULTIPLE svc_message windows (persistent
  // step-down under loss — the latch must keep re-proposing, not stop).
  //
  // FAIL-BEFORE (fix reverted): the forfeit branch leaves `commit` armed-and-due, so poll_timeout()
  // returns 50ms every step → on the SECOND advance `due (50) > last (50)` is FALSE → the strict-advance
  // assert fires (the spin), and the clock never reaches the 150ms/250ms svc windows so `proposals`
  // stays at 1 (the lone re-broadcast on the pinned instant, which a wedged real clock never escapes).
  // PASS-AFTER: 50ms (commit/prepare RETIRED here) → svc at 150ms, 250ms, ... each re-broadcasts.
  let mut last = now; // strictly before the first (50ms) deadline
  let mut proposals_at_distinct_instants = 0usize;
  let mut last_proposal_instant: Option<Instant> = None;
  for _ in 0..64 {
    let due = e
      .poll_timeout()
      .expect("a timer is armed while forfeiting (svc_message keeps the primary re-proposing)");
    assert!(
      due > last,
      "poll_timeout must strictly ADVANCE, not spin on a stale commit deadline ({due:?} <= {last:?})"
    );
    last = due;
    e.handle_timeout(due, &mut wal, &mut sb);
    let mut proposed_this_step = false;
    while let Some(out) = e.poll_message() {
      if let Message::StartViewChange(svc) = out.into_msg() {
        if svc.view().get() == 1 {
          proposed_this_step = true;
        }
      }
    }
    if proposed_this_step && last_proposal_instant != Some(due) {
      proposals_at_distinct_instants += 1;
      last_proposal_instant = Some(due);
    }
    if proposals_at_distinct_instants >= 3 {
      break; // saw persistent re-proposal across >= 3 strictly-advancing svc windows
    }
  }
  assert!(
    proposals_at_distinct_instants >= 3,
    "a forfeiting primary must reach svc_message and RE-broadcast StartViewChange{{view+1}} on its \
     retransmit cadence across multiple windows (persistent step-down); saw \
     {proposals_at_distinct_instants}"
  );
  // The forfeit is still latched (the view has not changed — a lone SVC cannot form a quorum here), so
  // the persistent step-down is preserved end to end (it never resumed heartbeating).
  assert!(
    e.pending_forfeit_for_test(),
    "the forfeit PERSISTS across the whole poll_timeout-driven sequence (never resumes heartbeating)"
  );
  assert_eq!(
    e.view(),
    View::new(),
    "the primary stays in its own view until a real SVC quorum forms (lone SVC does not inflate it)"
  );
}

#[test]
fn normal_backup_does_not_spin_a_poll_timeout_driver_after_an_idle_svc() {
  // LIVENESS (the timer-wedge class). A Normal BACKUP whose primary went silent fires
  // its `primary_idle` timeout → `on_primary_idle` → `propose_next_view` → `join_svc`, which ARMS
  // `svc_message` (the SVC retransmit) at the VC_MESSAGE_RETRANSMIT (100ms) cadence — EARLIER than the
  // re-armed `primary_idle` (200ms). But the Normal-backup branch of `handle_timeout` services ONLY
  // `primary_idle`, NOT `svc_message`, and `view_change_timeouts` (which would) runs only in ViewChange
  // status. So while the backup stays Normal (its peers' SVCs are lost → no view-change quorum forms),
  // `svc_message` is armed-but-never-serviced: a poll_timeout()-driven driver advances virtual time to
  // the 100ms `svc_message` deadline, `handle_timeout` does NOTHING for it, and `poll_timeout()`
  // re-returns the SAME instant → the clock SPINS at 100ms, never re-broadcasting the StartViewChange
  // and never advancing → the cluster cannot fail over (the SVC is never retransmitted under loss).
  //
  // The fix makes the Normal-backup branch SERVICE `svc_message` when armed+due (re-broadcast
  // the StartViewChange{view+1} on its retransmit cadence) AND `poll_timeout`'s serviceable filter then
  // returns it only where it is acted on, so the clock strictly advances and the SVC is re-broadcast
  // across multiple windows.
  let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap(); // replica 1: backup of view 0
  let mut e = Endpoint::new(cfg, 7, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  assert!(!e.is_primary());
  // Bootstrap the idle timer: the first Normal-backup tick only ARMS `primary_idle` (= now + 200ms), it
  // does not fire (the deadline is in the future). Tick at ZERO to arm it.
  e.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  // The primary went silent: fire the primary_idle timeout at 200ms. `on_primary_idle` proposes view 1
  // and `join_svc` arms `svc_message` at 200ms + 100ms = 300ms (and re-arms `primary_idle` to 400ms).
  let t_idle = Instant::ZERO + core::time::Duration::from_millis(200);
  e.handle_timeout(t_idle, &mut wal, &mut sb);
  assert_eq!(
    e.status(),
    Status::Normal,
    "a lone backup proposing view 1 stays Normal (no SVC quorum from one bit in a 3-cluster)"
  );
  // It broadcast its own StartViewChange{1}. (Its peers' SVCs are LOST — never delivered — so no quorum
  // ever forms; the backup must keep re-broadcasting its own on the retransmit cadence.)
  let mut proposed_initial = false;
  while let Some(out) = e.poll_message() {
    if let Message::StartViewChange(svc) = out.msg_ref() {
      if svc.view().get() == 1 {
        proposed_initial = true;
      }
    }
  }
  assert!(
    proposed_initial,
    "precondition: the idled backup proposed StartViewChange{{1}} (arming svc_message)"
  );
  // Drive PURELY via poll_timeout() — exactly as a real deadline-driven driver does — and assert the
  // clock STRICTLY ADVANCES (never spins on the unserviced `svc_message`) AND the backup re-broadcasts
  // its StartViewChange{1} across MULTIPLE strictly-advancing windows.
  //
  // FAIL-BEFORE (fix reverted): the Normal-backup branch leaves `svc_message` armed-and-due at 300ms,
  // so poll_timeout() returns 300ms every step → on the SECOND advance `due (300) > last (300)` is FALSE
  // → the strict-advance assert fires (the spin), and the SVC is never re-broadcast (the lone broadcast
  // sits on the pinned instant a wedged real clock never escapes).
  // PASS-AFTER: svc_message is serviced + re-armed (300 → 400 → 500 ...) each re-broadcasting the SVC.
  let mut last = t_idle; // strictly before the first armed (300ms) svc_message deadline
  let mut rebroadcasts_at_distinct_instants = 0usize;
  let mut last_rebroadcast_instant: Option<Instant> = None;
  for _ in 0..64 {
    let due = e
      .poll_timeout()
      .expect("a timer is armed (svc_message keeps the backup re-proposing under loss)");
    assert!(
      due > last,
      "poll_timeout must strictly ADVANCE, not spin on a stale svc_message deadline \
       ({due:?} <= {last:?})"
    );
    last = due;
    e.handle_timeout(due, &mut wal, &mut sb);
    let mut rebroadcast_this_step = false;
    while let Some(out) = e.poll_message() {
      if let Message::StartViewChange(svc) = out.msg_ref() {
        if svc.view().get() == 1 {
          rebroadcast_this_step = true;
        }
      }
    }
    if rebroadcast_this_step && last_rebroadcast_instant != Some(due) {
      rebroadcasts_at_distinct_instants += 1;
      last_rebroadcast_instant = Some(due);
    }
    if rebroadcasts_at_distinct_instants >= 3 {
      break; // persistent re-broadcast across >= 3 strictly-advancing svc windows
    }
  }
  assert!(
    rebroadcasts_at_distinct_instants >= 3,
    "an idled Normal backup must re-broadcast StartViewChange{{1}} on its retransmit cadence across \
     multiple strictly-advancing windows (no spin); saw {rebroadcasts_at_distinct_instants}"
  );
  // It is still a Normal backup driving the proposal (the lost SVCs never formed a quorum), so the
  // persistent re-proposal is preserved end to end.
  assert_eq!(
    e.status(),
    Status::Normal,
    "still a Normal backup re-proposing (the lost peer SVCs never formed a view-change quorum)"
  );
}

#[test]
fn primary_with_armed_grace_does_not_spin_after_forced_forfeit() {
  // LIVENESS (the timer-wedge class). A `Normal` primary can ARM its `forfeit_armed`
  // grace timer (it holds a committed `repair` hole → `maybe_forfeit` arms the grace) and THEN be
  // forced into `pending_forfeit` via the force-sync / sync-checkpoint STEP-DOWN (a forced
  // `SyncCheckpoint` on a primary sets `pending_forfeit` rather than applying the sync — the
  // op-reuse guard — and does NOT go through `forfeit()`, so it never disarms the grace). The
  // `pending_forfeit` branch of `primary_timeouts` retires `commit`/`prepare` and re-proposes on the
  // `svc_message` cadence, but it NEVER calls `maybe_forfeit` and (before the fix) NEVER cleared
  // `forfeit_armed` — so the grace deadline is left armed-and-due, unserviced. A poll_timeout()-driven
  // driver advances to the grace deadline, `handle_timeout` does nothing for it (the pending_forfeit
  // branch ignores it), and `poll_timeout()` re-returns it → the clock SPINS on the stale grace
  // deadline, never progressing the step-down → the cluster wedges below the unfillable hole.
  //
  // The fix retires `self.forfeit_armed = None` in the `pending_forfeit` branch (and the
  // serviceability filter no longer returns it once `pending_forfeit` holds), so `svc_message` is the
  // sole primary-side driver and the clock strictly advances to the step-down re-proposal.
  let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, 1_000).unwrap();
  let mut e = Endpoint::new(cfg, 0, CountSm::default());
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  // A Normal PRIMARY (replica 0, view 0) holding a committed `repair` hole at op 2 (commit held at 1
  // below it, head 10). `force_state_for_test` arms `repair_retry` and leaves commit_max > commit_min.
  e.force_state_for_test(0, 10, 1, 0, &[2]);
  assert!(e.is_primary() && e.status().is_normal());
  assert!(
    e.has_repair_hole_for_test(2),
    "precondition: the primary holds a committed repair hole"
  );
  // Tick the primary so `maybe_forfeit` observes the outstanding hole and ARMS the grace timer
  // (FORFEIT_GRACE = 300ms). It is NOT yet forfeiting — the grace must elapse first.
  let now = Instant::ZERO;
  e.handle_timeout(now, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  assert!(
    e.forfeit_armed_for_test(),
    "the primary armed the forfeit grace timer (outstanding committed hole)"
  );
  assert!(
    !e.pending_forfeit_for_test(),
    "but it is not yet forfeiting (within the grace window)"
  );
  // Now force the step-down the REAL way (NOT via forfeit()): a valid FORCED SyncCheckpoint on this
  // primary makes it set `pending_forfeit` (the op-reuse guard) WITHOUT disarming the grace
  // timer (`on_sync_checkpoint`'s primary branch only sets the flag + drops the sync). The grace timer
  // (armed at 300ms) is therefore left armed alongside `pending_forfeit` — exactly the stale spinner.
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
  assert!(
    e.pending_forfeit_for_test(),
    "the primary stepped down (pending_forfeit) rather than apply the forced sync in place"
  );
  while e.poll_message().is_some() {}
  // Drive PURELY via poll_timeout() and assert the clock STRICTLY ADVANCES (never spins on the stale
  // grace deadline) AND the forfeiting primary re-proposes StartViewChange{1} across MULTIPLE
  // svc_message windows (persistent step-down under loss).
  //
  // FAIL-BEFORE (fix reverted): the `pending_forfeit` branch leaves `forfeit_armed` armed-and-due at
  // 300ms; once the svc cadence (100,200,300,400..) passes it, poll_timeout() returns 300ms every step
  // → the strict-advance assert fires (the spin) the instant virtual time reaches the stale grace
  // deadline. PASS-AFTER: forfeit_armed is RETIRED, so svc_message (100ms cadence) is the sole driver
  // and the clock advances cleanly through multiple re-proposal windows.
  // CRUCIAL: keep driving until virtual time CROSSES the 300ms grace deadline — the spin only manifests
  // once `poll_timeout`'s min reaches the stale `forfeit_armed` instant (the svc cadence 100,200,300..
  // re-arms FORWARD, so a stale 300ms grace deadline is re-returned only once `last` reaches 300ms).
  let grace_deadline = now + FORFEIT_GRACE; // 300ms — the stale forfeit_armed deadline, if left armed
  let mut last = now; // strictly before the first armed deadline
  let mut proposals_at_distinct_instants = 0usize;
  let mut last_proposal_instant: Option<Instant> = None;
  for _ in 0..64 {
    let due = e
      .poll_timeout()
      .expect("a timer is armed while forfeiting (svc_message keeps the primary re-proposing)");
    assert!(
      due > last,
      "poll_timeout must strictly ADVANCE, not spin on a stale forfeit grace deadline \
       ({due:?} <= {last:?})"
    );
    last = due;
    e.handle_timeout(due, &mut wal, &mut sb);
    let mut proposed_this_step = false;
    while let Some(out) = e.poll_message() {
      if let Message::StartViewChange(svc) = out.msg_ref() {
        if svc.view().get() == 1 {
          proposed_this_step = true;
        }
      }
    }
    if proposed_this_step && last_proposal_instant != Some(due) {
      proposals_at_distinct_instants += 1;
      last_proposal_instant = Some(due);
    }
    // Require BOTH persistent re-proposal AND that the clock advanced strictly PAST the stale grace
    // deadline (so the fail-before spin at 300ms is genuinely exercised, not skipped by an early break).
    if proposals_at_distinct_instants >= 3 && last > grace_deadline {
      break;
    }
  }
  assert!(
    proposals_at_distinct_instants >= 3 && last > grace_deadline,
    "a force-forfeiting primary must reach svc_message and re-broadcast StartViewChange{{1}} across \
     multiple strictly-advancing windows PAST the stale grace deadline (no spin); saw \
     {proposals_at_distinct_instants} proposals, last={last:?}"
  );
  assert!(
    e.pending_forfeit_for_test(),
    "the forfeit PERSISTS across the whole poll_timeout-driven sequence (no spin, no resume)"
  );
}

#[test]
fn poll_timeout_only_returns_serviceable_timers() {
  // The INVARIANT this whole refactor establishes: `poll_timeout` returns ONLY timers the
  // current (status, substate) will actually SERVICE in `handle_timeout`. Equivalently, EVERY deadline
  // `poll_timeout()` returns is one `handle_timeout` then makes progress on — so firing it strictly
  // advances the clock (it is serviced/re-armed forward or cleared, never re-returned at the same
  // instant). A small matrix drives a replica through each status/substate and asserts that property
  // directly: for each, the first `poll_timeout()` is fired and the NEXT `poll_timeout()` is strictly
  // later (or absent) — i.e. no status/substate yields a non-serviceable poll_timeout that pins the
  // clock. This is the tick-invisible spin the deadline-driven driver hits; the assert closes it.
  //
  // `progresses(e, w, sb)`: fire the earliest armed timer once and assert the next deadline strictly
  // advances past it (or is None). Returns the (advanced) deadline so the caller can iterate windows.
  fn assert_strictly_advances<S: StateMachine, W: Wal, B: Superblock>(
    e: &mut Endpoint<S>,
    wal: &mut W,
    sb: &mut B,
    label: &str,
  ) {
    let Some(due) = e.poll_timeout() else {
      return; // no armed timer — vacuously serviceable (nothing to spin on).
    };
    e.handle_timeout(due, wal, sb);
    while e.poll_message().is_some() {}
    if let Some(next) = e.poll_timeout() {
      assert!(
        next > due,
        "[{label}] poll_timeout returned a NON-serviceable timer: firing {due:?} did not advance the \
         clock (next {next:?} <= {due:?}) — the deadline-driven spin this refactor forbids"
      );
    }
  }

  // (1) Normal PRIMARY (heartbeating): commit/prepare/forfeit_armed serviceable.
  {
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, 1_000).unwrap();
    let mut e = Endpoint::new(cfg, 0, CountSm::default());
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    // Commit a tail so prepare would also be relevant, then tick to arm the heartbeat.
    for rn in 1..=3u64 {
      e.handle_message(
        Instant::ZERO,
        &mut wal,
        &mut sb,
        Peer::Client(ClientId::new(7)),
        Message::Request(Request::new(
          ClientId::new(7),
          RequestNumber::with(rn),
          Bytes::from(std::vec![rn as u8]),
        )),
      );
      e.handle_storage(Instant::ZERO, &mut wal, &mut sb);
      e.handle_message(
        Instant::ZERO,
        &mut wal,
        &mut sb,
        Peer::Replica(ReplicaId::new(1)),
        Message::PrepareOk(PrepareOk::new(
          View::new(),
          OpNumber::with(rn),
          ReplicaId::new(1),
          OpNumber::new(),
          // content-address the vote to op rn's full identity (client 7, request rn, body [rn])
          crate::storage::prepare_identity(
            ClientId::new(7),
            RequestNumber::with(rn),
            crate::storage::fnv1a_128(&[rn as u8]),
          ),
        )),
      );
    }
    while e.poll_message().is_some() {}
    for _ in 0..8 {
      assert_strictly_advances(&mut e, &mut wal, &mut sb, "normal-primary");
    }
  }

  // (2) Normal PRIMARY then forced into pending_forfeit (the force-forfeited substate): only svc_message drives.
  {
    let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(0), 3, 1_000).unwrap();
    let mut e = Endpoint::new(cfg, 0, CountSm::default());
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    e.force_state_for_test(0, 10, 1, 0, &[2]); // committed repair hole → grace arms on the next tick
    e.handle_timeout(Instant::ZERO, &mut wal, &mut sb);
    while e.poll_message().is_some() {}
    let (_d, _dw, dsb) = donor_primary_at_checkpoint(6);
    let (env, id) = donor_envelope(&dsb);
    e.arm_forced_sync_for_test(6);
    let nonce = e.sync_nonce_for_test();
    e.handle_message(
      Instant::ZERO,
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
    assert!(e.pending_forfeit_for_test());
    while e.poll_message().is_some() {}
    for _ in 0..8 {
      assert_strictly_advances(&mut e, &mut wal, &mut sb, "normal-primary-pending_forfeit");
    }
  }

  // (3) Normal BACKUP that proposed an idle SVC (the idle-SVC substate): primary_idle + svc_message.
  {
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
    let mut e = Endpoint::new(cfg, 7, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    e.handle_timeout(
      Instant::ZERO + core::time::Duration::from_millis(200),
      &mut wal,
      &mut sb,
    );
    assert!(e.status().is_normal() && !e.is_primary());
    while e.poll_message().is_some() {}
    for _ in 0..8 {
      assert_strictly_advances(&mut e, &mut wal, &mut sb, "normal-backup+svc");
    }
  }

  // (4) ViewChange (active SVC driver): svc_message + dvc_message + view_change_status.
  {
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
    let mut e = Endpoint::new(cfg, 7, NoopSm);
    let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
    // Drive into ViewChange(1) via an SVC quorum (replica 0 + our own bit).
    e.handle_timeout(
      Instant::ZERO + core::time::Duration::from_millis(200),
      &mut wal,
      &mut sb,
    );
    e.handle_message(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(0)),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(0))),
    );
    assert_eq!(e.status(), Status::ViewChange);
    e.handle_storage(Instant::ZERO, &mut wal, &mut sb); // land the durable-view write so it participates
    while e.poll_message().is_some() {}
    for _ in 0..8 {
      assert_strictly_advances(&mut e, &mut wal, &mut sb, "view-change");
    }
  }

  // (5) Recovering: recover_retry drives (and any sync_solicit armed by the peer-fetch must NOT spin).
  {
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
    let mut sb = TestSb::default();
    // A WAL whose tail read faults forever on a non-head slot → the recover loop keeps retrying.
    let mut wal = ScriptedWal::with_entries(3);
    wal.script_read_fault(OpNumber::with(2), u8::MAX);
    let mut e = Endpoint::recover(cfg, 7, NoopSm, &mut wal, &mut sb);
    assert!(e.status().is_recovering() || e.status().is_recovering_head());
    e.handle_storage(Instant::ZERO, &mut wal, &mut sb);
    while e.poll_message().is_some() {}
    for _ in 0..8 {
      assert_strictly_advances(&mut e, &mut wal, &mut sb, "recovering");
    }
  }

  // (6) RecoveringHead: recover_head drives the Recovery re-solicitation.
  {
    let cfg = Config::with_checkpoint_ops(0, ReplicaId::new(1), 3, 4).unwrap();
    let mut sb = TestSb::default();
    // The HEAD slot reads back permanently faulty → RecoveringHead.
    let mut wal = ScriptedWal::with_entries(3);
    wal.script_read_fault(OpNumber::with(3), u8::MAX);
    let mut e = Endpoint::recover(cfg, 7, NoopSm, &mut wal, &mut sb);
    // Drain the recover loop to its terminal RecoveringHead (re-submit the faulty head read until the
    // budget exhausts), driving purely via the recover_retry timer.
    for _ in 0..64 {
      e.handle_storage(Instant::ZERO, &mut wal, &mut sb);
      if e.status().is_recovering_head() {
        break;
      }
      if let Some(due) = e.poll_timeout() {
        e.handle_timeout(due, &mut wal, &mut sb);
      }
    }
    assert_eq!(
      e.status(),
      Status::RecoveringHead,
      "the permanently-faulty head drove the replica to RecoveringHead"
    );
    while e.poll_message().is_some() {}
    for _ in 0..8 {
      assert_strictly_advances(&mut e, &mut wal, &mut sb, "recovering-head");
    }
  }
}

#[test]
fn sustained_client_load_does_not_starve_the_prepare_retransmit() {
  // A primary with an UNCOMMITTED op (its lone own vote is below the 2-of-3 quorum) arms the
  // prepare retransmit at T. Every accepted client request ends in `arm_timers`, so re-arming to
  // `now + PREPARE_RETRANSMIT` on each accept would let a steady sub-interval request cadence
  // slide the deadline forever: one lost Prepare broadcast under sustained load then never
  // retransmits — backups buffer the tail above the loss as future ops (their arrival still
  // resets `primary_idle`, so no failover) and the commit wedges below it until the load pauses a
  // full interval. The deadline must be PRESERVED across accepts (it may only move earlier), so
  // the retransmit fires at T despite continuous accepts.
  let mut e = Endpoint::new(Config::try_new(1, ReplicaId::new(0), 3).unwrap(), 0, NoopSm);
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let t0 = Instant::ZERO;

  // T0: accept request 1 → op 1, own append durable (own vote only — no quorum, stays uncommitted);
  // the prepare retransmit is armed at T = t0 + PREPARE_RETRANSMIT.
  e.handle_message(
    t0,
    &mut wal,
    &mut sb,
    Peer::Client(ClientId::new(7)),
    client_request(1),
  );
  e.handle_storage(t0, &mut wal, &mut sb);
  while e.poll_message().is_some() {}
  let deadline = t0 + PREPARE_RETRANSMIT;
  assert_eq!(
    e.timers.prepare,
    Some(deadline),
    "an uncommitted op arms the prepare retransmit"
  );

  // Continuous accepts at a sub-interval cadence (each < PREPARE_RETRANSMIT after the last): the
  // armed deadline must NOT move past T — neither the prepare timer itself nor the earliest
  // serviceable deadline a poll_timeout()-driven driver would wake on.
  for (i, ms) in [40u64, 80].into_iter().enumerate() {
    let now = t0 + core::time::Duration::from_millis(ms);
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      Peer::Client(ClientId::new(7)),
      client_request(2 + i as u64),
    );
    e.handle_storage(now, &mut wal, &mut sb);
    while e.poll_message().is_some() {}
    assert_eq!(
      e.timers.prepare,
      Some(deadline),
      "accepting a request at T-ε must not move the prepare deadline past T"
    );
    let due = e.poll_timeout().expect("primary timers armed");
    assert!(
      due <= deadline,
      "poll_timeout must stay at/before the armed retransmit deadline ({due:?} > {deadline:?})"
    );
  }

  // At T the retransmit FIRES: the whole uncommitted tail is re-broadcast (as the byte-bounded
  // `PrepareBatch`), so op 1 — whose accept-time Prepare may have been lost — reaches the backups
  // despite the continuous accepts.
  e.handle_timeout(deadline, &mut wal, &mut sb);
  let mut resent = std::collections::BTreeSet::new();
  while let Some(out) = e.poll_message() {
    if let Message::PrepareBatch(b) = out.msg_ref() {
      resent.extend(b.log_slice().iter().map(|entry| entry.op().get()));
    }
  }
  assert_eq!(
    resent,
    (1..=3u64).collect::<std::collections::BTreeSet<u64>>(),
    "the retransmit at T re-broadcasts every uncommitted op"
  );
}

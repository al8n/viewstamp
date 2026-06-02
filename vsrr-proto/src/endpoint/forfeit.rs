use super::*;

impl<S: StateMachine> Endpoint<S> {
  /// M3.5 T3 — the forfeit gate. A `Normal` primary that is genuinely STUCK steps down (via a view
  /// change) so a caught-up replica leads, rather than wedge the cluster (clients whose requests sit
  /// above its stalled commit never finish). Two independent stuck-conditions, both grace-timed:
  ///
  /// 1. **Checkpoint lag.** Its own durable `checkpoint_op` lags the quorum's by at least a full
  ///    checkpoint interval (`config.forfeit_checkpoint_lag()`) — it cannot checkpoint because it is
  ///    repairing/syncing while the cluster raced ahead.
  /// 2. **Unfillable committed hole (liveness, VOPR seed 36).** It holds a `repair` hole — a COMMITTED
  ///    op below its head it cannot apply (registered only for `commit_min + 1 <= commit_max`). If that
  ///    op was CHECKPOINTED + PRUNED past on its holders (the residual case of `select_canonical_log`'s
  ///    offset-union: a committed op no canonical donor's LOG carries, so it lives only inside a peer's
  ///    checkpoint snapshot), NO peer can answer the primary's `RequestPrepare` and the only recovery is
  ///    a state-sync of that snapshot — which a PRIMARY must NOT do (force-syncing a primary resets
  ///    `self.op` below its head and reuses op numbers in this view → committed-state divergence; see
  ///    `maybe_force_sync`'s primary guard). Such a primary cannot serve clients (its commit is stuck
  ///    below the hole), cannot fill it, and — holding none of `(commit_min .. op]` — retransmits
  ///    nothing, so backups never ack and never re-trigger any reactive check: it WEDGES the cluster.
  ///    Forfeiting hands the view to a more-caught-up replica (the holder whose checkpoint covers the
  ///    band leads cleanly; it does not re-forfeit), and THIS replica then recovers the band as a
  ///    BACKUP via the ordinary force-sync escalation. The grace timer makes this self-limiting: a
  ///    FILLABLE hole (a peer holds it un-pruned, in or out of the DVC quorum — the case the
  ///    seeding-site B4 path covers) is repaired by the answering `Prepare` well within `FORFEIT_GRACE`,
  ///    emptying `repair` and DISARMING the forfeit; only a hole that persists the WHOLE window — i.e.
  ///    one no peer can serve — actually steps the primary down. No committed op is lost (it survives in
  ///    the holder's checkpoint throughout).
  ///
  /// **Anti-storm (load-bearing).** The grace timer is the key gate: the condition must hold
  /// CONTINUOUSLY for `FORFEIT_GRACE` before the primary actually steps down, so a transient lag /
  /// in-flight repair never triggers a view change. The checkpoint-lag signal is additionally
  /// quorum-gated (`quorum_checkpoint_op()`, the quorum-th order statistic over the monotone per-peer
  /// reports) and bounded at a *full* interval, so a single ahead peer cannot induce a forfeit and a
  /// healthy primary that checkpoints in lock-step never arms it. `saturating_sub` guards the
  /// (defensive) case where the primary's own checkpoint is somehow ahead of the quorum's.
  pub(crate) fn maybe_forfeit<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    // Only ever called from `primary_timeouts` (the Normal-primary tick); a backup behind on
    // checkpoint catches up via state-sync/force-sync and never forfeits.
    debug_assert!(self.status.is_normal() && self.is_primary());
    // SOLO guard (mirrors the four sibling sites: `complete_recovery`, `maybe_force_sync`,
    // `on_sync_checkpoint`, `on_recover_sync_checkpoint`). A SOLO replica (`replica_count == 1`) is its
    // own primary and CANNOT view-change — `quorum_view_change() == 1`, so forfeiting would propose
    // `view + 1`, satisfy the VC quorum with its OWN SVC bit alone, transition to ViewChange, and then
    // livelock in `view_change_timeouts` (no peer ever sends a StartView) — dropping all client traffic
    // forever. A solo replica must instead stay Normal and HOLD commit below any unfillable hole. The
    // forfeit precondition (a permanent committed-WAL-slot fault with no peer to repair from) is itself
    // unrecoverable on a solo cluster, but abdicating to a non-existent quorum is strictly worse than
    // holding. So a solo replica never forfeits (and never even arms the grace timer).
    if self.config.replica_count() <= 1 {
      // Disarm any stale grace timer defensively (it can only have been set before this guard existed;
      // a solo replica never arms it now).
      self.forfeit_armed = None;
      return;
    }
    let lag = self
      .quorum_checkpoint_op()
      .get()
      .saturating_sub(self.checkpoint_op.get());
    // Stuck iff EITHER the checkpoint lags a full interval OR an unfilled committed `repair` hole is
    // outstanding (a committed op `<= commit_max` the apply loop is held below — see the doc). The
    // grace timer disarms a hole that fills in time, so a fillable hole never forfeits.
    let stuck = lag >= self.config.forfeit_checkpoint_lag() || !self.repair.is_empty();
    match (stuck, self.forfeit_armed) {
      // Caught up (or never behind): disarm — a transient lag / in-flight repair does not forfeit.
      (false, _) => self.forfeit_armed = None,
      // Newly stuck: arm the grace timer; do NOT step down yet.
      (true, None) => self.forfeit_armed = Some(now + FORFEIT_GRACE),
      // Stuck for the whole grace window: forfeit.
      (true, Some(deadline)) if deadline <= now => self.forfeit(now, sb),
      // Still within the grace window: wait.
      (true, Some(_)) => {}
    }
  }

  /// Forfeit primacy: step down by PROPOSING the next view (broadcast `StartViewChange`) via the
  /// existing SVC machinery — exactly as a backup's idle timeout does (`on_primary_idle` →
  /// `propose_next_view`). A caught-up replica's SVC quorum then forms and a more-up-to-date primary
  /// takes over.
  ///
  /// It deliberately does **NOT** unilaterally jump the view (`transition_to_view_change_status`):
  /// that would strand this replica alone in `ViewChange` if peers do not follow, wedging the cluster
  /// until idle timers fire. A lone `StartViewChange` cannot inflate the view (a real SVC quorum is
  /// required to transition), so proposing is the safe, established path. The grace + quorum gates in
  /// `maybe_forfeit` (and the force-sync-strand gate in `maybe_force_sync`) ensure this only fires
  /// when genuinely stuck.
  ///
  /// **Persistent until the view changes (F2).** A SINGLE proposed `StartViewChange` can be
  /// dropped/partitioned; were the primary to then resume heartbeating, every backup would keep
  /// resetting its `primary_idle` (never starting its own VC) and the cluster would wedge below the
  /// hole. So forfeiting LATCHES `pending_forfeit`: while set, `primary_timeouts` re-proposes `view+1`
  /// each tick AND stops heartbeating (backups idle-out and join the SVC → quorum → the view changes).
  /// The flag is cleared only when this replica LEAVES Normal-primary (the transition handlers clear
  /// it), so the latch self-resolves exactly when the forfeit succeeds and never leaks across views.
  /// The grace timer is disarmed here (the persistent latch, not the grace timer, now drives retries).
  pub(crate) fn forfeit<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    self.forfeit_armed = None;
    self.pending_forfeit = true;
    self.propose_next_view(now, sb);
  }

  /// Flag the DEFERRED-forfeit step-down a PRIMARY raises off the M3.5 force-sync / sync-checkpoint
  /// strand (`maybe_force_sync` / `on_sync_checkpoint` / `on_recover_sync_checkpoint`) — it must NOT
  /// force-sync (that reuses op numbers; see those sites), so it steps down instead and the next
  /// `primary_timeouts` tick re-proposes `view + 1`. Unlike [`Self::forfeit`] this is raised OUTSIDE a
  /// primary tick (from a message handler), so it does NOT itself propose; but it MUST bootstrap a
  /// SERVICEABLE wake so a `poll_timeout`-driven driver actually reaches that next tick.
  ///
  /// Bootstrapping `svc_message` (codex R15) is load-bearing: once `pending_forfeit` is set,
  /// `serviceable_now` makes `commit`/`prepare`/`forfeit_armed` NON-serviceable (the `pending_forfeit`
  /// branch of `primary_timeouts` retires them and never heartbeats), so the ONLY primary-side timer the
  /// filtered `poll_timeout` may return while forfeiting is `svc_message`. Were it left unarmed here, a
  /// step-down raised from a message handler would leave `poll_timeout` with no serviceable primary
  /// timer — a deadline-driven driver would sleep forever and never reach the re-propose tick (a wedge
  /// just as fatal as the spin).
  ///
  /// Armed at the retransmit cadence (`now + VC_MESSAGE_RETRANSMIT`), exactly as `forfeit()` (via
  /// `propose_next_view` -> `join_svc`) and a backup's idle-SVC do — so the step-down re-proposes
  /// `view + 1` on the NEXT svc_message window. `poll_timeout` therefore always returns a STRICTLY-FUTURE
  /// serviceable deadline while forfeiting (no due-now first deadline that would alias the flag instant),
  /// and the next `primary_timeouts` tick at-or-after that deadline services it (`svc_message <= now` ⇒
  /// re-propose; `join_svc` then re-arms forward, so the no-orphan-due assert holds). Idempotent:
  /// re-flagging just re-bootstraps the cadence (the latch is cleared only on leaving Normal-primary).
  pub(crate) fn defer_forfeit(&mut self, now: Instant) {
    self.pending_forfeit = true;
    self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
  }

  pub(crate) fn on_primary_idle<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    self.propose_next_view(now, sb);
  }

  /// Propose moving to `self.view + 1`: adopt it as the SVC target (if higher than the current
  /// target), set our own bit, broadcast `StartViewChange{target}`, and transition on quorum.
  pub(crate) fn propose_next_view<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    let target = View::with(self.view.get() + 1);
    if target.get() > self.svc_target.get() {
      self.svc_target = target;
      self.svc_from = 0;
    }
    self.join_svc(now);
    self.maybe_start_view_change(now, sb);
  }
}

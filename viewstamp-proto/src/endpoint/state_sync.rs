use super::*;

impl<S: StateMachine, R: Reconfig> Endpoint<S, R> {
  // ── State-sync: the trigger + the lagging replica's solicitation ──

  /// The state-sync TRIGGER. A replica enters state-sync iff it is `Normal` AND it learns of a cluster
  /// checkpoint strictly ABOVE its own head (`incoming_checkpoint > self.op`), via a `checkpoint_op`
  /// carried on a `Commit`/`Prepare`/`PrepareOk`. A checkpoint at op `C` means a quorum committed AND
  /// applied through `C`, so ops `[1..=C]` are committed cluster-wide and may be pruned at the source;
  /// if `C > self.op`, this replica's entire WAL is below the cluster checkpoint, so neither retransmit
  /// (`commit_min+1..=op`) nor peer fault-repair (a single in-reach op) can close a gap that starts
  /// under its own head — it must fetch the checkpoint itself. (`> self.op`, not `>= self.op`: an equal
  /// head means it holds exactly up to the checkpoint and can apply forward by the ordinary path; and
  /// not `> self.checkpoint_op`, because a replica whose tail still reaches the cluster checkpoint
  /// catches up by ordinary commit-application — state-sync is only for an out-of-reach gap.) This is
  /// the conservative, minimal trigger: it never fires when ordinary catch-up suffices, so by
  /// construction it never syncs past uncommitted state.
  ///
  /// Anti-thrash: if a sync is already outstanding (`self.sync.is_some()`) we only RAISE the target
  /// and re-solicit; we do not start a second handshake.
  pub(crate) fn maybe_request_sync(&mut self, now: Instant, incoming_checkpoint: OpNumber) {
    if !self.status.is_normal() {
      return; // Recovering/RecoveringHead/ViewChange have their own catch-up; never sync from there.
    }
    if incoming_checkpoint.get() <= self.op.get() {
      return; // in reach — ordinary commit-application (or peer-repair) catches us up.
    }
    // Already syncing? First DOWNGRADE any stale cross-epoch sync on this same-epoch evidence
    // (target-independent — see [`Self::downgrade_stale_cross_epoch_sync`]); that re-targets to the
    // reachable `incoming_checkpoint`, so skip the raise below. Otherwise only RAISE the target if this
    // checkpoint is newer, then re-solicit on the timer cadence — no fresh handshake per heartbeat.
    if self.sync.is_some() {
      if self.downgrade_stale_cross_epoch_sync(incoming_checkpoint) {
        return;
      }
      if let Some(s) = self.sync
        && incoming_checkpoint.get() > s.target.get()
      {
        self.sync = Some(SyncState {
          target: incoming_checkpoint,
          nonce: s.nonce,
          // Preserve the in-flight sync's forced-ness when only raising the target (an ordinary
          // higher checkpoint does not downgrade an outstanding forced sync's assert-relaxation).
          forced: s.forced,
          require_cross_epoch: false,
        });
        // A FORCED target raised past a pinned chunked transfer invalidates it (the strict
        // `>= target` gate is load-bearing there); an ordinary raise keeps the pin (it completes
        // below the raised freshness floor).
        self.drop_transfer_below_forced_target();
      }
      return;
    }
    // Fresh trigger: arm + solicit through the single fresh-arm chokepoint.
    self.arm_sync(now, incoming_checkpoint, false, false);
  }

  /// The SINGLE fresh-arm chokepoint for a state-sync handshake: bump the freshness nonce
  /// deterministically (the sim seeds `self.nonce` from the prng; a simple increment keeps it
  /// deterministic + distinct from the prior recovery/get-view nonce), record the target (and whether
  /// the sync is FORCED — the relaxed `apply_sync` invariant), emit the
  /// [`Event::StateSyncStarted`] observability event, and broadcast the solicitation. Every site that
  /// arms a sync from `None` routes here (`maybe_request_sync`, `maybe_force_sync`,
  /// `maybe_sync_below_ring_window`, the recovery peer-fetch escalation); target RAISES on an
  /// outstanding sync stay at their sites (they re-target the same handshake, not a fresh arm).
  pub(crate) fn arm_sync(
    &mut self,
    now: Instant,
    target: OpNumber,
    forced: bool,
    require_cross_epoch: bool,
  ) {
    debug_assert!(self.sync.is_none(), "arm_sync is the FRESH-arm path only");
    self.nonce = self.nonce.wrapping_add(1);
    self.sync = Some(SyncState {
      target,
      nonce: self.nonce,
      forced,
      require_cross_epoch,
    });
    self.events.push_back(Event::StateSyncStarted(target));
    self.send_request_sync(now);
  }

  /// A SECONDARY trigger-level backstop for the cross-epoch poisoning hazard. The PRIMARY whole-class guard
  /// is [`Self::cancel_stale_cross_epoch_sync`], which cancels a stale `require_cross_epoch` sync on ANY
  /// same-epoch admissible message at the ingress (before dispatch) — so by the time a same-epoch sync
  /// trigger runs the stale crossing is normally already gone. As a backstop, ANY ordinary SAME-EPOCH sync
  /// trigger evidence here ALSO DOWNGRADES a stale `require_cross_epoch` sync, INDEPENDENT of target
  /// monotonicity. Called at
  /// the top of every same-epoch trigger's already-syncing (`Some(s)`) arm (`maybe_request_sync`,
  /// `maybe_sync_below_ring_window`, `maybe_force_sync`) with that trigger's own reachable same-epoch
  /// `target`. Returns `true` iff it consumed the downgrade (the caller then SKIPS its own target raise —
  /// this re-targeted the sync); `false` leaves the sync untouched for the caller's ordinary raise path.
  ///
  /// # Why target-INDEPENDENT
  ///
  /// A speculative `require_cross_epoch` sync is armed in Normal by the pre-binding higher-epoch /
  /// `EpochAhead` hook ([`Self::maybe_request_cross_epoch_catchup`]) BEFORE any successor checkpoint is
  /// verified, pinned to the HINT's `checkpoint_op` — which a STALE/misrouted hint can set UNREACHABLY
  /// HIGH. The earlier per-site fix cleared the bit ONLY when a same-epoch checkpoint RAISED the target
  /// (`incoming > s.target`); but a legitimate same-epoch checkpoint ABOVE this replica's head yet BELOW
  /// the bogus high target takes the non-raise path, so the bit PERSISTED — and `apply_sync` then rejects
  /// every same-config reply FOREVER (it keeps demanding a successor that never comes), poisoning ordinary
  /// catch-up. So the downgrade must NOT depend on the target moving: a same-epoch trigger that learns ANY
  /// reachable cluster checkpoint clears the crossing requirement and RE-TARGETS the sync to that reachable
  /// same-epoch checkpoint (the bogus high target is discarded — otherwise the
  /// `incoming_checkpoint < s.target` freshness drop in `handle_sync_checkpoint` would still reject the
  /// below-bogus reply even with the bit cleared).
  ///
  /// # Why a GENUINE crossing is NOT stranded
  ///
  /// The cross-epoch trigger re-arms `require_cross_epoch = true` AFRESH on the NEXT higher-epoch heartbeat
  /// / `EpochAhead` (`maybe_request_cross_epoch_catchup` for a Normal laggard; `enter_cross_epoch_peer_fetch`
  /// → `escalate_checkpoint_to_peer_fetch(.., true)` for a non-Normal one), and that hook runs pre-binding
  /// on EVERY message. So while a real higher epoch is still advertised the crossing requirement is
  /// re-established whenever it is needed; only a STALE hint (no higher epoch actually being advertised)
  /// stays downgraded. (A genuine cross-epoch reply still crosses via `apply_sync`'s verified-successor
  /// path regardless of this bit — the bit only governs the REJECT-below-target solicitation policy.)
  ///
  /// `forced` is PRESERVED (`s.forced`): a downgraded crossing sync stays forced (its `apply_sync`
  /// assert-relaxation — never-rewind-the-applied-frontier — is correct for a same-epoch checkpoint at/above
  /// our commit frontier), matching the raise path's "an ordinary higher checkpoint does not downgrade an
  /// outstanding forced sync's assert-relaxation".
  fn downgrade_stale_cross_epoch_sync(&mut self, target: OpNumber) -> bool {
    let Some(s) = self.sync else {
      return false; // no sync outstanding — nothing to downgrade.
    };
    if !s.require_cross_epoch {
      return false; // an ordinary / forced same-epoch sync — leave the caller's raise path to it.
    }
    if !self.crossing_is_pre_answer_speculative() {
      // A GENUINE in-progress crossing (a STAGED install, a PINNED chunked `sync_transfer`, or a NON-Normal
      // recovery peer-fetch) — PRESERVE it exactly as the ingress cancel does (the shared pre-answer scope);
      // never downgrade it to ordinary nor clear its intent. A donor has begun answering this crossing; it
      // must complete on its own path. (The caller's raise path is target-gated and a below-swap same-epoch
      // checkpoint is below the crossing target, so it cannot fire here either.)
      return false;
    }
    self.sync = Some(SyncState {
      target,
      nonce: s.nonce,
      forced: s.forced,
      require_cross_epoch: false,
    });
    // The re-target may LOWER the (bogus-high) cross-epoch target onto the reachable same-epoch one. The
    // sync is now a forced, NON-cross-epoch sync, so `drop_transfer_below_forced_target` engages: it
    // PRUNES any chunked transfer pinned BELOW the new same-epoch target — exactly a now-stale cross-epoch
    // transfer that the downgrade abandoned (a transfer at/above the new target survives and installs
    // same-epoch). A fresh announce re-pins on the next solicit.
    self.drop_transfer_below_forced_target();
    // This downgrade is SAME-EPOCH evidence the crossing requirement was STALE (a sync trigger learned a
    // reachable same-epoch checkpoint), so clear the PERSISTENT intent too — exactly as the ingress cancel
    // does. Otherwise `on_sb_done` would re-arm a crossing from the still-set intent once this now-ORDINARY
    // sync installs, re-introducing the stale-hint poison the intent refactor exists to remove.
    self.cross_epoch_intent = None;
    true
  }

  /// a backup that has fallen BELOW its bounded-WAL RING WINDOW state-syncs instead of
  /// overwriting an un-pruned slot. Called from [`Self::on_prepare`]'s head-extend branch BEFORE the
  /// append, with the incoming `Prepare`. Returns `true` (caller DROPS the prepare, appending nothing)
  /// when this replica cannot durably hold the prepare without wrapping away an op it has NOT yet
  /// checkpoint-subsumed; `false` (no overflow) ⇒ the append proceeds normally.
  ///
  /// # Why a backup can overflow (the bounded-WAL crux)
  ///
  /// A bounded WAL is a ring of `wal.capacity()` slots: appending op `K` PHYSICALLY overwrites slot
  /// `K mod capacity`, whose last occupant was op `K - capacity`. That overwrite is safe ONLY if
  /// `K - capacity` is below this replica's prune floor (checkpoint-subsumed) — i.e. `K -
  /// self.checkpoint_op <= capacity`. The PRIMARY enforces this by stalling op-assignment on the QUORUM
  /// floor ([`Self::on_request`]), so an IN-QUORUM backup never overflows (its checkpoint tracks the
  /// quorum's). But a SUB-QUORUM laggard — one whose own `checkpoint_op` has fallen far below the cluster
  /// checkpoint while its head kept extending (e.g. it adopted a canonical head over a held-commit hole
  /// after a view change, so `commit_min`/`checkpoint_op` are pinned low while `op` ran ahead) — receives
  /// fresh head-extending `Prepare`s whose op `K` satisfies `K - self.checkpoint_op > capacity`. Appending
  /// `K` would overwrite the un-pruned slot `K - capacity`, breaking the resident-tail invariant `recover`
  /// relies on (`(checkpoint_op .. head]` must fit the ring) — on a later crash, `recover` would request
  /// the wrapped-away ops below the resident range and spuriously fault. The ORDINARY sync trigger
  /// ([`Self::maybe_request_sync`]) does NOT catch this: it fires only on `incoming_checkpoint > self.op`,
  /// but here the laggard's HEAD kept up (`p.checkpoint_op() <= self.op`) while only its CHECKPOINT lagged.
  ///
  /// # The fix — jump to the cluster checkpoint
  ///
  /// Such a laggard cannot hold the full live tail in its ring; it must JUMP its checkpoint forward via
  /// state-sync. The target is the cluster checkpoint the `Prepare` advertises, `C = p.checkpoint_op()`:
  /// the primary's stall guarantees `C >= K - capacity` (the primary kept `K - prune_floor(primary) <=
  /// capacity` and `prune_floor(primary) <= C`), so syncing to `C` advances `self.checkpoint_op` past the
  /// overflowing slot `K - capacity`, restoring `head - checkpoint_op <= capacity`. `C` may be AT or BELOW
  /// our head (the head ran ahead of the cluster checkpoint), so this is the FORCED-style sync (it applies
  /// a checkpoint `<= self.op`, preserving the resident held tail `(C .. head]` — those slots are the last
  /// `<= capacity` ring writes, so they are present); the ordinary `> self.op` requirement does not hold.
  ///
  /// We arm the forced sync ONLY when `C` is a VALID forward target — `C > self.checkpoint_op` (advances
  /// us) AND `C > self.commit_min` (STRICT — the cluster checkpoint is ABOVE our applied frontier, so the
  /// band `(commit_min .. C]` is folded into the cluster snapshot and may be wrapped away from every ring
  /// → a state-sync is the ONLY recovery; this strict form also keeps `apply_sync`'s `>= commit_min`
  /// forced assert satisfied with room to spare).
  ///
  /// When `C <= self.commit_min` (the laggard has ALREADY APPLIED through the cluster checkpoint) we do
  /// NOT sync — we still DROP the prepare (back-pressure, the primary-stall analogue), and let our OWN
  /// pending/next checkpoint advance `checkpoint_op` (freeing the ring), after which the retransmitted
  /// Prepare fits and is appended. This is GUARANTEED to release: the backup is applied through
  /// `commit_min >= C > K - capacity > checkpoint_op`, so it sits at/past a checkpoint boundary (its
  /// `commit_min` is a full interval above its stale `checkpoint_op`), meaning a local ordinary
  /// checkpoint for `commit_min` is already triggered/in-flight (`maybe_checkpoint` fires the moment
  /// `commit_min >= checkpoint_op + checkpoint_ops`) and WILL land — advancing `checkpoint_op` and
  /// shrinking `head - checkpoint_op` below `capacity`. So the back-pressure self-releases with no wedge.
  ///
  /// **Why STRICT, not `>=`.** The `C == self.commit_min`
  /// case is the bug. Arming there targets `C == commit_min`; the backup's OWN in-flight ordinary
  /// checkpoint for `commit_min` then lands, advancing `self.checkpoint_op` to `C`. But
  /// `cancel_forced_sync_if_satisfied` fires only on a COMMIT advance, never a CHECKPOINT advance, so the
  /// forced sync stays armed at `target == C == checkpoint_op`. An equal `SyncCheckpoint(C)` is then
  /// REJECTED by `on_sync_checkpoint`'s `checkpoint_op <= self.checkpoint_op` guard (syncing to a
  /// checkpoint we already hold is a no-op) → the forced sync can NEVER complete, and while
  /// `sync.is_some()` `on_prepare` DROPS every retransmitted Prepare → the cluster WEDGES through this
  /// replica (it already holds the checkpoint it needed, yet is stuck "syncing" forever). The strict
  /// discriminator folds `C == commit_min` into the back-pressure path, where the local checkpoint
  /// releases it cleanly. (A genuine below-ring laggard has `C > commit_min` and still force-syncs.)
  ///
  /// Anti-thrash + integration: a sync already outstanding is only RE-TARGETED upward (mirroring
  /// `maybe_request_sync`/`maybe_force_sync`); the caller's existing `if self.sync.is_some() { return }`
  /// guard then drops every subsequent overflowing prepare until the sync installs. Unbounded WAL
  /// (`capacity == u64::MAX`) can never overflow, so this is inert for the default — and for an in-quorum
  /// backup under a bounded ring (its checkpoint tracks the quorum, so `K - checkpoint_op <= capacity`).
  pub(crate) fn maybe_sync_below_ring_window<W: Wal>(
    &mut self,
    now: Instant,
    wal: &W,
    pop: u64,
    cluster_checkpoint: OpNumber,
  ) -> bool {
    // Only the head-extend append can overwrite a ring slot; the caller invokes this for `pop ==
    // self.op + 1`. Appending `pop` reuses slot `pop mod capacity` (last held by `pop - capacity`); it is
    // an UN-pruned overwrite iff `pop - self.checkpoint_op > capacity`. Unbounded ⇒ never.
    let capacity = wal.capacity();
    if pop.saturating_sub(self.checkpoint_op.get()) <= capacity {
      return false; // fits the ring (or unbounded) — append normally.
    }
    // We have fallen below the ring window: appending `pop` would wrap away the un-pruned op `pop -
    // capacity`. DROP the prepare (do not overwrite a needed slot). Additionally, if the cluster
    // checkpoint the Prepare advertises is a VALID forward sync target, JUMP to it via a forced sync.
    //
    // The discriminator is STRICT — `target > self.commit_min`, NOT `>=`. Arm a sync ONLY
    // when the cluster checkpoint is STRICTLY ABOVE our applied frontier: then the band `(commit_min ..
    // target]` is folded into the cluster snapshot AND may be wrapped away from every ring, so a sync is
    // the SOLE recovery. When `target <= self.commit_min` we have ALREADY APPLIED through the cluster
    // checkpoint — the ring is full ONLY because our OWN `checkpoint_op` lags (an ordinary checkpoint for
    // `commit_min` is in flight / pending), NOT because we are missing committed state — so do NOT arm a
    // sync; just back-pressure (drop, below). The `==` case is the latent bug: arming there targets
    // `commit_min`, and a LOCAL checkpoint then advances `checkpoint_op` to `commit_min == target`,
    // leaving the sync un-completable (an equal `SyncCheckpoint` is rejected by `on_sync_checkpoint`'s
    // `checkpoint_op <= self.checkpoint_op` guard) — a liveness WEDGE (`on_prepare` drops retransmits
    // while `sync.is_some()`).
    let target = cluster_checkpoint;
    let valid_sync_target =
      target.get() > self.checkpoint_op.get() && target.get() > self.commit_min.get();
    if valid_sync_target {
      // Observability (non-vacuity): count this below-ring-window overflow — a head-extending Prepare
      // was DROPPED because appending it would overwrite an un-pruned ring slot, and state-sync is the
      // recovery (the cluster checkpoint is a valid forward target). Counted for BOTH the fresh-arm and
      // the already-outstanding arms below: the SAME delivery that brings the overflowing head-extend
      // usually carries the commit/floor information whose `advance_commit` → `maybe_force_sync` ran a
      // moment earlier in `on_prepare` and already armed the sync — so by the time this guard runs, the
      // sync is typically outstanding. The counter witnesses the guard ENGAGING on a genuine overflow
      // (drop + sync-recovery, vs wedging or overwriting), not which trigger within the same delivery
      // armed the sync first. The `valid_sync_target == false` back-pressure case
      // (already applied through the cluster checkpoint; a local checkpoint releases the ring) stays
      // UNCOUNTED — no sync is the recovery there.
      self.below_ring_window_syncs += 1;
      // A below-ring-window jump is SAME-EPOCH forced evidence: DOWNGRADE any stale cross-epoch sync
      // (target-independent), re-targeting to this reachable cluster checkpoint. If it consumed the
      // downgrade, the sync is set — skip the raise below.
      if !self.downgrade_stale_cross_epoch_sync(target) {
        match self.sync {
          // Already syncing: only raise the target (keep it forced — applying a checkpoint `<= self.op`).
          Some(s) if target.get() > s.target.get() => {
            self.sync = Some(SyncState {
              target,
              nonce: s.nonce,
              forced: true,
              require_cross_epoch: false,
            });
            // The now-forced raised target invalidates a chunked transfer pinned below it.
            self.drop_transfer_below_forced_target();
          }
          Some(_) => {} // a sync to >= target is already outstanding — let it run (anti-thrash).
          None => self.arm_sync(now, target, true, false),
        }
      }
    }
    // Either way the overflowing prepare is dropped (the un-pruned slot is preserved); if no sync was
    // armed (the `target <= commit_min` back-pressure case), the local checkpoint for `commit_min`
    // (`>= target`) lands and advances `checkpoint_op`, restoring the window so the next retransmit fits.
    true
  }

  /// The force-state-sync escalation (the safety-critical core). A `Normal` replica holding a
  /// peer-fault-`repair` hole at op `N` whose `RequestPrepare` has become FUTILE — because a peer has
  /// checkpointed past `N` (`max_peer_checkpoint_op() >= N`), so that peer captured `N` in a checkpoint
  /// snapshot and pruned the servable prepare — clears the doomed hole(s) and forces a `RequestSync` to
  /// that peer checkpoint (which is `>= N`, so its snapshot subsumes `N`). This closes the GC +
  /// permanent-fault + partition strand the `run_gc` doc-comment flagged: without it, such a replica's
  /// ordinary sync trigger (`> self.op`) is FALSE (its head is above the cluster checkpoint) and no
  /// peer can serve the pruned `N`, so it is stuck at `commit_min == N-1` forever.
  ///
  /// # The floor is the MAX peer checkpoint, not the quorum-th (the backup-visibility fix)
  ///
  /// The floor is [`Self::max_peer_checkpoint_op`] — the highest checkpoint ANY peer (or self) has
  /// reported — NOT [`Self::quorum_checkpoint_op`]. A backup only ever records the PRIMARY's checkpoint
  /// (it hears `Commit` from the primary; `PrepareOk`s — the only other checkpoint-bearing message —
  /// flow to the primary, never between backups), so on a backup the quorum-th floor is structurally
  /// pinned to ~0 and could NEVER cross a hole → the escalation would never fire and the backup would
  /// hang forever (the exact strand this method exists to break). A single peer reporting
  /// `checkpoint_op >= N` already proves a servable snapshot `>= N` exists — and that is precisely the
  /// source the ordinary sync already trusts ([`Self::maybe_request_sync`] targets a single peer's
  /// reported checkpoint, integrity-gated by `on_sync_checkpoint`'s `checkpoint_id` check). So keying
  /// on a single peer's checkpoint is no weaker than the ordinary sync's own trust model.
  ///
  /// # Safety — never abandons a committed op without the snapshot replacing it
  ///
  /// We only clear holes `<= floor` and set the forced sync target to exactly `floor`. Every repair
  /// hole is a COMMITTED op (`advance_commit`/`commit_op` register a hole only at `commit_min + 1 <=
  /// commit_max`, never for an uncommitted op), so a cleared hole `M (<= floor)` is (a) subsumed by the
  /// synced snapshot (`apply_sync` restores the SM through `floor >= M`, recovering `M`'s effect) and
  /// (b) never an uncommitted decision we were free to drop anyway. A committed op `M` is never lost —
  /// merely relocated from "a servable prepare" to "inside the checkpoint", exactly the case-(1)
  /// argument in the `run_gc` proof. The forced sync target is a checkpoint a `Normal` peer demonstrably
  /// made durable+pruned past, so that peer can answer the `RequestSync`. No commit advances past `N`
  /// until the snapshot (`>= N`) is applied: the hole holds `commit_min` at `N-1` until `apply_sync`
  /// sets `commit_min = floor >= N`. The forced path NEVER fires while every hole is still IN-REACH
  /// (above the floor, i.e. no peer has pruned it yet) — it does not pre-empt the cheap single-op
  /// `RequestPrepare` repair; and even if it fires while some lagging peer could still serve the
  /// prepare, whichever recovery (the `Prepare` or the `SyncCheckpoint`) lands first wins, with no
  /// committed op lost either way.
  ///
  /// # Anti-thrash
  ///
  /// A forced sync, once outstanding (`self.sync.is_some()`), is not re-issued — we only RAISE its
  /// target if `floor` grew, exactly mirroring the ordinary trigger. Clearing the doomed holes stops
  /// the futile `RequestPrepare` retransmit (the `repair_retry` timer disarms when `repair` empties).
  pub(crate) fn maybe_force_sync(&mut self, now: Instant) {
    if !self.status.is_normal() || self.repair.is_empty() {
      return; // only a Normal replica with an outstanding repair hole can be in this strand.
    }
    let floor = self.max_peer_checkpoint_op();
    if floor.get() == 0 {
      return; // no peer-checkpoint floor known yet (e.g. partitioned) — stay dormant.
    }
    // Any hole AT/BELOW the peer-checkpoint floor is snapshot-only on its reporter: that peer pruned
    // the prepare, so `RequestPrepare` for it cannot be answered there. A hole strictly ABOVE the floor
    // is still in-reach (no peer has pruned it) → keep using the cheap single-op repair, do NOT escalate.
    if !self.repair.iter().any(|&op| op <= floor.get()) {
      return;
    }
    // SAFETY: a PRIMARY must NOT force-sync. The force-sync below resets `self.op` to `floor`
    // (BELOW the primary's head) and clears the log/inflight; the primary would then accept new client
    // requests at REUSED op numbers in the SAME view, and backups still holding the old entries would
    // re-ack them from `on_prepare`'s `pop <= self.op` branch WITHOUT comparing bodies — the primary
    // commits body B while backups applied body A for the same op = committed-state divergence. So a
    // primary that reaches this strand (an unservable, checkpoint-subsumed hole) steps DOWN instead, via
    // the single `abdicate_if_primary` chokepoint: it flags the deferred forfeit (+ the
    // serviceable `svc_message` wake) which the next primary tick (`primary_timeouts`) acts on, and we
    // RETURN here without arming the forced sync. A caught-up replica then leads and the subsumed hole is
    // recovered via that primary's ordinary checkpoint flow. (Gating force-sync off the primary WITHOUT
    // this step-down would wedge a stuck laggard-primary, since its lag may be below the
    // checkpoint-interval forfeit threshold — hence forfeit, not no-op.)
    if self.abdicate_if_primary(now) {
      return;
    }
    // Clear every snapshot-only hole; the forced sync to `floor` subsumes them all (its snapshot is
    // `>= max such hole`). A hole above the floor (if any) stays and continues ordinary repair.
    self.repair.retain(|&op| op > floor.get());
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
    }
    // Solicit (or re-target) a FORCED sync to the peer-checkpoint floor. The floor is SAME-EPOCH forced
    // evidence: DOWNGRADE any stale cross-epoch sync (target-independent), re-targeting to it; if it
    // consumed the downgrade the sync is set — skip the raise below.
    if !self.downgrade_stale_cross_epoch_sync(floor) {
      match self.sync {
        Some(s) if floor.get() > s.target.get() => {
          // Raise an outstanding sync's target to the floor and mark it forced (the discard-direction
          // assert in `apply_sync` must use the relaxed invariant for this synced checkpoint).
          self.sync = Some(SyncState {
            target: floor,
            nonce: s.nonce,
            forced: true,
            require_cross_epoch: false,
          });
          // The now-forced raised target invalidates a chunked transfer pinned below it.
          self.drop_transfer_below_forced_target();
        }
        Some(_) => {} // a sync to >= floor is already outstanding — let it run (anti-thrash).
        None => self.arm_sync(now, floor, true, false),
      }
    }
  }

  /// Broadcast a `RequestSync` advertising our CURRENT (stale) checkpoint + the live sync nonce, and
  /// (re)arm the solicit timer. An ordinary state-sync request is answered only by a `Normal` peer with
  /// a STRICTLY-newer durable checkpoint; a RECOVERY peer-fetch (`awaiting_peer_checkpoint()` — our own
  /// checkpoint snapshot is permanently unreadable) sets the `recovery` flag so a peer at the SAME
  /// `checkpoint_op` also serves it (without this, an idle cluster where every healthy peer holds
  /// exactly our checkpoint_op ignores the request forever → recovery livelocks).
  pub(crate) fn send_request_sync(&mut self, now: Instant) {
    let nonce = self.sync.map_or(self.nonce, |s| s.nonce);
    let recovery = self.awaiting_peer_checkpoint();
    self.emit(Outgoing::new(
      Recipient::Backups,
      Message::RequestSync(crate::RequestSync::new(
        self.view,
        self.checkpoint_op,
        self.local_slot(),
        nonce,
        recovery,
        self.membership.config_id(),
      )),
    ));
    self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
  }

  /// State-sync solicit timer: while a sync is outstanding, re-broadcast `RequestSync` and re-arm.
  /// Doubles as the chunked transfer's ARQ: with a transfer pinned, FIRST re-send the one
  /// outstanding stop-and-wait chunk pull (the request or its answer may have been lost — the
  /// staged frontier is exactly the next offset, so the re-send is idempotent), THEN re-broadcast
  /// `RequestSync` (dead-donor replacement: a fresh announce from any live holder of the pinned
  /// content re-pins the transfer and resumes at the same frontier). Cleared when the synced
  /// checkpoint goes durable (`on_sb_done` clears `sync` + this timer).
  pub(crate) fn sync_timeouts(&mut self, now: Instant) {
    if self.timers.sync_solicit.is_none_or(|d| d > now) {
      return;
    }
    if self.sync.is_none() {
      self.timers.sync_solicit = None;
      return;
    }
    if let Some(offset) = self.sync_transfer.as_ref().map(|t| t.staged.len() as u64) {
      self.send_request_sync_chunk(now, offset);
    }
    self.send_request_sync(now);
  }

  /// Send the chunked transfer's one outstanding pull: a `RequestSyncChunk` for the pinned
  /// `(checkpoint_op, checkpoint_id)` at `offset` (always the staged frontier), addressed to the
  /// pinned donor, echoing the live sync nonce. Re-arms the solicit deadline while Normal (the
  /// stop-and-wait ARQ rides it); while Recovering the `recover_retry` cadence re-drives the pull
  /// instead (`sync_solicit` is not serviced there). No-op without a pinned transfer + live sync.
  pub(super) fn send_request_sync_chunk(&mut self, now: Instant, offset: u64) {
    let Some(t) = &self.sync_transfer else {
      return;
    };
    let Some(s) = self.sync else {
      return;
    };
    let (checkpoint_op, checkpoint_id, donor) = (t.checkpoint_op, t.checkpoint_id, t.donor);
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(donor)),
      Message::RequestSyncChunk(crate::RequestSyncChunk::new(
        self.view,
        checkpoint_op,
        checkpoint_id,
        self.membership.config_id(),
        offset,
        self.local_slot(),
        s.nonce,
      )),
    ));
    if self.status.is_normal() {
      self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
    }
  }

  /// Abort a pinned chunked transfer a FORCED-sync target raise has invalidated: a forced target is
  /// LOAD-BEARING (`maybe_force_sync` cleared repair holes at/below it against a snapshot at/above
  /// it), so the strict `>= target` install gate stays — a transfer pinned BELOW the raised target
  /// can never install and would only burn round trips. Dropping it frees the staged bytes; `sync`
  /// stays armed, so the solicit timer re-announces and a fresh pin at/above the new target starts
  /// over. An ORDINARY sync's raise deliberately does NOT abort: its target is a freshness floor and
  /// the pinned transfer still installs below it (strict progress — see the assembled carve-out in
  /// `handle_sync_checkpoint`); the next trigger then chases the newer checkpoint.
  ///
  /// A CROSS-EPOCH crossing fetch (`require_cross_epoch`) likewise does NOT abort on a raise: its
  /// target is only the SOLICIT floor, NOT a hard install bound (the VERIFIED successor membership is
  /// the crossing authority — `apply_sync`). A higher-epoch hint (possibly bogus, unreachably high)
  /// must not discard a legitimately-pinned below-hint crossing transfer that would still cross.
  pub(crate) fn drop_transfer_below_forced_target(&mut self) {
    let Some(s) = self.sync else {
      return;
    };
    if !s.forced || s.require_cross_epoch {
      return;
    }
    if self
      .sync_transfer
      .as_ref()
      .is_some_and(|t| t.checkpoint_op.get() < s.target.get())
    {
      self.sync_transfer = None;
    }
  }

  // ── State-sync: the peer side — answer a RequestSync from the durable checkpoint ──

  /// Answer a peer's `RequestSync` by shipping our latest DURABLE checkpoint, iff we are `Normal` and
  /// hold a checkpoint strictly NEWER than the requester's (else stay silent — never ship a megabyte
  /// snapshot for a no-op). Any caught-up replica (primary or backup) may answer: a committed
  /// checkpoint is immutable cluster-wide, so any holder is authoritative for its content. We do not
  /// keep the encoded envelope in memory after a checkpoint completes, so we read it back from the
  /// superblock (`submit_read_checkpoint`) and record the read in `sync_serving`; the completion
  /// (`on_sb_done`) ships the `SyncCheckpoint`.
  ///
  /// The requester is the authenticated `from`'s CURRENT slot — NOT the self-claimed `m.replica()`. A
  /// CROSS-EPOCH laggard stamps its OLD (stale, possibly-shifted) slot into the request; the transport
  /// bound `from` to its CURRENT slot in OUR active membership, and the sender binding
  /// ([`Self::sender_admits_solicitation`]) already admitted it on `from`'s member identity. Keying the
  /// serve + addressing the reply by `from`'s current slot is what makes the `SyncCheckpoint` ROUTE BACK
  /// to the laggard (the transports route `Peer::Replica(slot)` by slot index — a reply to the stale
  /// claimed slot would be misrouted to whoever now occupies it). On the common same-slot path
  /// `from`'s slot == `m.replica()`, so this is byte-identical.
  pub(crate) fn on_request_sync<B: Superblock>(
    &mut self,
    _now: Instant,
    sb: &mut B,
    from: Peer,
    m: crate::RequestSync,
  ) {
    if !self.status.is_normal() {
      return; // only a Normal replica has a trustworthy durable checkpoint to serve
    }
    // The requester is the authenticated `from`'s CURRENT slot (the sender binding admitted it as a
    // current member), NOT the self-claimed `m.replica()` — so a slot-shifted cross-epoch laggard's reply
    // routes to where it now lives. `from` is a `Peer::Replica` in range here (the binding guaranteed it).
    let Some(requester) = from.as_replica() else {
      return;
    };
    if requester.get() >= self.membership.node_count() {
      return; // the requester must be a configured cluster member (in `0..node_count`)
    }
    if self.checkpoint_op.get() == 0 {
      return; // nothing durable to serve — silent.
    }
    // A RECOVERY peer-fetch is served at an EQUAL checkpoint too: the requester's OWN snapshot
    // bytes are corrupt, so it needs ours even at the same `checkpoint_op`. (We are `Normal` — checked
    // above — so our durable snapshot is trustworthy.) An ordinary state-sync request keeps the strict
    // `>`: never ship a megabyte snapshot for a no-op when the requester is already at our checkpoint.
    let in_reach = if m.recovery() {
      self.checkpoint_op.get() >= m.checkpoint_op().get()
    } else {
      self.checkpoint_op.get() > m.checkpoint_op().get()
    };
    if !in_reach {
      return; // nothing the requester needs from us — silent.
    }
    // ONE outstanding serve per requester (the structural bound on `sync_serving`): while this
    // requester's serve-read is still in flight, a repeat `RequestSync` only REFRESHES the echoed
    // nonce + serve kind — the completion then answers the LATEST solicitation — and issues NO
    // second checkpoint read. Without the dedupe, a buggy peer's solicit burst would stack N concurrent
    // reads, each completion shipping a full snapshot. (A same-nonce burst — the timer-retransmit
    // common case — is answered identically; a re-armed sync's newer nonce is shipped without an
    // extra round trip.)
    self.submit_or_refresh_serve(sb, requester, m.nonce(), ServeKind::Offer);
  }

  /// Record (or refresh) the single in-flight serve for `requester`. If a serve-read is already
  /// outstanding, only the echoed nonce + serve kind are refreshed in place (the completion answers
  /// the LATEST solicitation) — no second checkpoint read is issued; otherwise submit one read and
  /// insert the entry. The structural one-read-per-requester bound on `sync_serving`.
  fn submit_or_refresh_serve<B: Superblock>(
    &mut self,
    sb: &mut B,
    requester: ReplicaId,
    nonce: u64,
    kind: ServeKind,
  ) {
    if let Some(serving) = self.sync_serving.get_mut(&requester) {
      serving.nonce = nonce;
      serving.kind = kind;
      return;
    }
    let id = self.mint_op_id();
    sb.submit_read_checkpoint(id);
    self.sync_serving.insert(
      requester,
      SyncServe {
        read: id.get(),
        nonce,
        kind,
      },
    );
  }

  /// Ship the answer for a completed serve-read (the read `on_request_sync` /
  /// `on_request_sync_chunk` issued), per the recorded [`ServeKind`]: the whole `SyncCheckpoint`
  /// when the envelope fits one frame, a `SyncCheckpointMeta` announce when it does not (the
  /// requester then pulls chunks), or one `SyncChunk` for a cold-cache pull. Binds the shipped
  /// `checkpoint_id` to the shipped bytes via `checkpoint_id(cr.snapshot())`, then VERIFIES that
  /// id equals our DURABLE checkpoint id (`sb.state().checkpoint_id()`) — so a CORRUPT-but-
  /// parseable read (an in-model disk fault) cannot make us ship a self-consistent-but-wrong (id, bytes)
  /// pair the requester would accept and restore (it only re-checks `checkpoint_id(snapshot) == advertised
  /// id`); a mismatch DROPS the read (the serve path is then as strict as `recover`'s `id_ok` gate). The
  /// verified bytes also fill the donor serve cache (`sync_donating`), so subsequent chunk pulls are
  /// zero-copy slices with no further superblock read. Also re-checks status + view-durability +
  /// replica range at SHIP time (all may have changed between submit and completion): if we are no
  /// longer Normal, or our view is no longer durable, we drop the reply.
  pub(crate) fn serve_sync_checkpoint<B: Superblock>(&mut self, sb: &B, cr: crate::CheckpointRead) {
    // Serve entries are keyed by REQUESTER (one outstanding serve each); match this completion
    // against the recorded read `OpId`. No match ⇒ not a serve-read we issued (a stale/foreign
    // completion) — ignore. The scan is bounded by `replica_count` (<= 64).
    let Some((to, nonce, kind)) = self
      .sync_serving
      .iter()
      .find(|(_, s)| s.read == cr.id().get())
      .map(|(&to, s)| (to, s.nonce, s.kind))
    else {
      return;
    };
    self.sync_serving.remove(&to);
    // Durable-view-before-participate: the shipped `SyncCheckpoint` advertises
    // `self.view` (see below). A replica in its view-CHANGING `pending_sb` window (a new primary between
    // `start_view_as_new_primary` and the `on_sb_done` that makes its view durable — or any replica mid
    // `AdoptedStartView`/`SendDoViewChange` write) is `Normal` but its view is NOT yet recoverable;
    // serving a `SyncCheckpoint(self.view)` now would advertise a view a crash could roll back — the
    // same hazard the `Prepare`/`Commit`/`StartView`/`RecoveryResponse` paths gate on. A commit-first
    // SwapEpoch root does NOT raise this fence (the view is durable through an epoch swap —
    // [`Self::pending_durable_view`]). The served checkpoint is committed and its CONTENT is
    // view-independent, so the requester loses nothing by waiting: it re-solicits on its `sync_solicit`
    // timer and a Normal+durable peer answers (and we answer once our own view is durable). Negligible
    // liveness cost; consistent with the class — the same shape as the `on_request_prepare` drop. (The
    // submit side, `on_request_sync`, also gates on status, but this SHIP-time gate is the load-bearing
    // one: the view may have advanced between the read submit and its completion.)
    if !self.status.is_normal() || self.pending_durable_view() {
      return; // no longer a trustworthy server, or our view is not yet durable — drop.
    }
    if to.get() >= self.membership.node_count() {
      return; // the requester must be a configured cluster member (in `0..node_count`)
    }
    // Only ship when the READ's op matches our CURRENT durable `checkpoint_op`: we advertise
    // `cr.op()` and bind it into the snapshot, so the op we ship must be the one whose bytes these are.
    // If we checkpointed forward between submit and completion (a newer checkpoint write landed), the
    // returned bytes may be the OLD snapshot under a stale op — drop rather than ship a mismatched pair
    // (the requester re-solicits and gets our fresh checkpoint).
    if cr.op() != self.checkpoint_op {
      return;
    }
    let snapshot = cr.snapshot_bytes();
    let id = crate::checkpoint_id(&snapshot);
    // Integrity: a checkpoint READ may return CORRUPT-but-parseable bytes (an in-model
    // DISK FAULT — bit-rot in the snapshot region that still decodes). Serving them would ship a
    // SELF-CONSISTENT (id, snapshot) pair the requester cannot distinguish from a good one: it only
    // re-checks `checkpoint_id(snapshot) == advertised id` (`on_sync_checkpoint`), which HOLDS because we
    // computed `id` from the corrupt bytes — so it would restore CORRUPTED SM/session state. Verify the
    // read bytes against our OWN DURABLE checkpoint id (`sb.state().checkpoint_id()` — the same authority
    // `recover` uses for its `id_ok` gate, recovery.rs): a corrupt read does NOT hash to it. The `cr.op()
    // == self.checkpoint_op` gate above already pinned the durable op, so this completes the (op, id)
    // match against the durable root — the serve path is now exactly as strict as recover. On mismatch
    // DROP it (the requester re-solicits and another peer, or our next clean read, serves).
    if id != sb.state().checkpoint_id() {
      return;
    }
    // The read is VERIFIED (op-matched + durable-id-matched) — fill the donor serve cache so this
    // requester's (and any other pinned receiver's) chunk pulls are zero-copy slices of these bytes,
    // with no superblock re-read + re-hash per chunk.
    self.sync_donating = Some(SyncDonating {
      checkpoint_op: cr.op(),
      checkpoint_id: id,
      snapshot: snapshot.clone(),
    });
    // Serve the SUCCESSOR membership the snapshot reflects: the canonical `ReconfigurePayload` of our
    // CURRENT configuration, chained from its predecessor (`self.lineage[0]` — the immediate-predecessor
    // `config_id`, == our own at genesis), so a CROSS-EPOCH laggard can reconstruct + VERIFY it from the
    // carried `(epoch, config_id, membership)`. A same-epoch requester leaves it unread.
    //
    // XI-b SERVE GATE (CP-safety): attach the membership ONLY when the served checkpoint REFLECTS it —
    // `checkpoint_op >= config_install_op`, where `config_install_op` is the op of the last reconfigure that
    // produced our current membership. A donor that has swapped to E+1 but whose checkpoint is still BELOW
    // the reconfigure op `N` (the commit-first window) serves an EMPTY membership: the laggard then installs
    // the SM frontier (op `M < N`) but KEEPS its current membership and catches the band up THROUGH `N`
    // via the commit-first path — so it reaches E+1 only once it durably holds the committed prefix through
    // `N`, exactly the premise the NORMAL path enforces. Without this gate the donor would attach its
    // CURRENT (E+1) membership to a checkpoint at `M < N`, and the laggard would install E+1 at frontier `M`
    // WITHOUT that prefix and could vote in E+1 unsafely. A same-config sync already serves empty (the
    // `apply_sync` cross-epoch branch only fires when `config_id` differs); this additionally withholds a
    // cross-epoch membership the donor's checkpoint does not yet reflect. The gate reads `self.checkpoint_op`
    // (== `cr.op()`, pinned above) and the restored-on-recover `self.config_install_op`.
    let membership = if self.checkpoint_op.get() >= self.config_install_op.get() {
      crate::message::ReconfigurePayload::from_membership(&self.membership, self.lineage[0])
        .encode_body()
    } else {
      Bytes::new()
    };
    match kind {
      ServeKind::Offer => {
        // The membership rides the SAME frame as the snapshot, so the unchunked budget is reduced by
        // its length: ship whole only when snapshot + membership + framing all fit one frame.
        if snapshot.len()
          <= crate::message::max_unchunked_snapshot_len_with_membership(membership.len())
        {
          // The unchunked fast path: the whole envelope + membership fit one frame — ship it whole.
          self.emit(Outgoing::new(
            Recipient::To(Peer::Replica(to)),
            Message::SyncCheckpoint(crate::SyncCheckpoint::new(
              self.view,
              cr.op(),
              id,
              self.membership.epoch(),
              self.membership.config_id(),
              self.local_slot(),
              nonce,
              snapshot,
              membership,
            )),
          ));
        } else {
          // Too large for one frame: announce it (op, content id, total length) and let the
          // requester pull chunks. `total_len` descends from this VERIFIED read, so the receiver can
          // size its reassembly buffer to exactly the envelope it will verify. Carry the SAME
          // `(epoch, config_id, membership)` header as the single-frame `SyncCheckpoint` so the
          // verified reassembly rebuilds an IDENTICAL checkpoint — a cross-epoch laggard whose
          // post-swap snapshot is over-frame still installs the successor configuration.
          self.emit(Outgoing::new(
            Recipient::To(Peer::Replica(to)),
            Message::SyncCheckpointMeta(crate::SyncCheckpointMeta::new(
              self.view,
              cr.op(),
              id,
              self.membership.epoch(),
              self.membership.config_id(),
              snapshot.len() as u64,
              self.local_slot(),
              nonce,
              membership,
            )),
          ));
        }
      }
      // A cold-cache chunk pull: the cache is now warm — ship the requested chunk (a malformed
      // offset at/past the end is dropped; the requester's transfer state never asks for one).
      ServeKind::Chunk { offset } => self.ship_sync_chunk(to, nonce, offset),
    }
  }

  /// Ship one `SyncChunk` of the cached (`sync_donating`) envelope at `offset`, zero-copy. Drops a
  /// malformed `offset` at/past the envelope end (nothing to serve there — a correct receiver's
  /// next-offset never reaches it, so this only rejects a corrupt/buggy pull). The caller has
  /// already gated status/durable-view/range and verified the cache covers the pinned checkpoint.
  fn ship_sync_chunk(&mut self, to: ReplicaId, nonce: u64, offset: u64) {
    let Some(d) = &self.sync_donating else {
      return;
    };
    let total_len = d.snapshot.len() as u64;
    if offset >= total_len {
      return;
    }
    let end = offset
      .saturating_add(crate::message::SYNC_CHUNK_LEN as u64)
      .min(total_len);
    let chunk = d.snapshot.slice(offset as usize..end as usize);
    let (checkpoint_op, checkpoint_id) = (d.checkpoint_op, d.checkpoint_id);
    let config_id = self.membership.config_id();
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(to)),
      Message::SyncChunk(crate::SyncChunk::new(
        self.view,
        checkpoint_op,
        checkpoint_id,
        config_id,
        total_len,
        offset,
        self.local_slot(),
        nonce,
        chunk,
      )),
    ));
  }

  /// Answer a peer's `RequestSyncChunk` — one chunk of the checkpoint envelope it has pinned
  /// `(checkpoint_op, checkpoint_id)`. Gates like the serve completion (Normal + durable view +
  /// replica range: a `SyncChunk` advertises `self.view`), then in order:
  ///
  /// - **Cache hit** — the pinned checkpoint is exactly the cached `sync_donating` content: ship the
  ///   chunk as a zero-copy slice. This serves BOTH the common warm case and the donor-advanced case
  ///   (the cache deliberately outlives the donor's own checkpoint advance — committed content is
  ///   immutable — so a pinned mid-transfer receiver finishes pulling the OLD checkpoint).
  /// - **Cold cache, current checkpoint** — the pin matches our durable root `(checkpoint_op, id)`
  ///   but the cache is cold (e.g. we restarted mid-transfer): re-read the snapshot
  ///   ([`ServeKind::Chunk`]); the verified completion warms the cache and ships the chunk.
  /// - **Stale pin** — the pinned op is BELOW our durable checkpoint and not cached (we pruned past
  ///   it / restarted): treat it as a fresh `RequestSync` ([`ServeKind::Offer`]) — the completion
  ///   offers our CURRENT checkpoint (whole or chunked), and the requester re-pins to it. This is
  ///   the donor-pruned-mid-transfer recovery.
  /// - Otherwise stay silent (a pin we cannot serve — the requester's solicit timer re-broadcasts
  ///   `RequestSync` and another peer answers).
  ///
  /// The requester is the authenticated `from`'s CURRENT slot (the [`Self::sender_admits_solicitation`]
  /// binding admitted it as a current member), NOT the self-claimed `m.replica()` — so a SLOT-SHIFTED
  /// cross-epoch laggard's chunk reply routes to where it now lives, exactly as [`Self::on_request_sync`]
  /// keys + addresses its serve by `from`. (The pin `(checkpoint_op, checkpoint_id)` still selects WHICH
  /// envelope to ship; only the reply RECIPIENT / serve key is taken from `from`.)
  pub(crate) fn on_request_sync_chunk<B: Superblock>(
    &mut self,
    _now: Instant,
    sb: &mut B,
    from: Peer,
    m: crate::RequestSyncChunk,
  ) {
    if !self.status.is_normal() {
      return; // only a Normal replica has a trustworthy durable checkpoint to serve
    }
    let Some(requester) = from.as_replica() else {
      return; // a client / non-replica never pulls chunks (the binding guaranteed a Peer::Replica).
    };
    if requester.get() >= self.membership.node_count() {
      return; // the requester must be a configured cluster member (in `0..node_count`)
    }
    // Durable-view-before-participate at the DIRECT-ship gate: a cache-hit chunk is emitted from
    // this handler (no read completion re-gates it), and a `SyncChunk` advertises `self.view` — so
    // drop while a view-CHANGING write is in flight, exactly as `serve_sync_checkpoint` does at ship
    // time. A commit-first SwapEpoch root does NOT raise this fence (the view is durable through an epoch
    // swap — [`Self::pending_durable_view`]). The requester re-solicits; we answer once the view is durable.
    if self.pending_durable_view() {
      return;
    }
    if let Some(d) = &self.sync_donating
      && d.checkpoint_op == m.checkpoint_op()
      && d.checkpoint_id == m.checkpoint_id()
    {
      self.ship_sync_chunk(requester, m.nonce(), m.offset());
      return;
    }
    if self.checkpoint_op.get() == 0 {
      return; // nothing durable to serve — silent.
    }
    if m.checkpoint_op() == self.checkpoint_op && m.checkpoint_id() == sb.state().checkpoint_id() {
      // Cold cache, current durable checkpoint: re-read, then ship the chunk from the verified
      // completion (which also warms the cache for the rest of the transfer).
      self.submit_or_refresh_serve(
        sb,
        requester,
        m.nonce(),
        ServeKind::Chunk { offset: m.offset() },
      );
      return;
    }
    if m.checkpoint_op().get() < self.checkpoint_op.get() {
      // The pinned checkpoint is gone here (pruned / never ours) but we hold something STRICTLY
      // newer: offer it fresh — the receiver aborts its stale pin and re-pins to the new announce.
      self.submit_or_refresh_serve(sb, requester, m.nonce(), ServeKind::Offer);
    }
    // Anything else (a pin at/above our checkpoint that is not our content) is unanswerable here —
    // stay silent; the requester's re-broadcast finds a peer that holds it.
  }

  // ── State-sync: apply a verified SyncCheckpoint (the safety-critical core) ──

  /// Receive a `SyncCheckpoint`. Runs the §2.5 guard cascade (status; matching outstanding sync;
  /// nonce; advances past `target`, our head, and our checkpoint), then the LOAD-BEARING integrity
  /// gate — `checkpoint_id(snapshot) == checkpoint_id` — and only then `apply_sync`. A failed
  /// integrity check (a corrupt/forged snapshot) is REJECTED without touching the SM, leaving `sync`
  /// armed so the timer re-solicits (another peer answers).
  pub(crate) fn on_sync_checkpoint<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: crate::SyncCheckpoint,
  ) {
    self.handle_sync_checkpoint(now, wal, sb, m, false);
  }

  /// The body of [`Self::on_sync_checkpoint`], shared with the chunked-transfer completion.
  /// `assembled` marks an envelope REASSEMBLED from a chunked transfer (vs one that arrived whole):
  /// it relaxes exactly ONE guard — the `>= target` freshness gate for an ORDINARY sync — because
  /// an ordinary target is a freshness FLOOR, not a safety bound: a target raised mid-transfer
  /// (the cluster checkpointed again while chunks were in flight) must not discard a fully-pulled,
  /// verified envelope that still passes every SAFETY gate (`> self.op` for ordinary, monotone over
  /// our own checkpoint, the content hash, the decode bind-check). Installing it is strict progress;
  /// the very next `Commit` re-fires the trigger and a follow-up sync chases the newer checkpoint.
  /// Without the carve-out a sustained checkpoint cadence could raise the target faster than any
  /// transfer completes and the laggard would restart forever. A FORCED sync keeps the strict gate
  /// even when assembled — its target is LOAD-BEARING (`maybe_force_sync` cleared repair holes
  /// at/below it against a snapshot at/above it), so a below-target install could strand a cleared
  /// hole; the raise sites instead abort the pinned transfer outright
  /// ([`Self::drop_transfer_below_forced_target`]).
  fn handle_sync_checkpoint<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    _wal: &mut W,
    sb: &mut B,
    m: crate::SyncCheckpoint,
    assembled: bool,
  ) {
    // Freshness + relevance: we must be a Normal replica with an outstanding sync whose nonce matches.
    if !self.status.is_normal() {
      return;
    }
    let Some(s) = self.sync else {
      return; // no sync outstanding (already applied / never triggered) — ignore.
    };
    if m.nonce() != s.nonce {
      return; // a reply to a prior solicitation / forged — not fresh.
    }
    // SINGLE-SUPERBLOCK-WRITER: a sync install must not be STAGED while ANY superblock root is
    // outstanding — the same fence `maybe_checkpoint`/`maybe_swap_epoch` gate on
    // (`pending_sb.is_none() && pending_checkpoint.is_none()`). Two cases:
    //
    // - `pending_checkpoint` — the persist window: the adopted checkpoint is being made durable (an
    //   ordinary checkpoint, OR this very sync's own two-write re-persist); a second SyncCheckpoint
    //   arriving then is dropped (we already chose a snapshot and are persisting it).
    // - `pending_sb` — a durable-VIEW or a commit-first SwapEpoch root in flight. Staging a
    //   `SyncRepersist` here would let THIS node's own SwapEpoch completion's forced checkpoint
    //   (`on_sb_done`'s SwapEpoch arm calls `force_checkpoint` unconditionally) OVERWRITE the sync's
    //   `pending_checkpoint` tracker — leaving the staged `pending_install` orphaned (a permanent
    //   outstanding sync that blocks future same-epoch state-sync + graceful drain). So DEFER the reply
    //   while a root is in flight; `sync` stays armed (forced + `require_cross_epoch` + target intact),
    //   so the solicit timer re-fetches once the root lands and its forced checkpoint clears.
    if self.pending_sb.is_some() || self.pending_checkpoint.is_some() {
      return;
    }
    if m.checkpoint_op().get() < s.target.get()
      && (!assembled || s.forced)
      && !s.require_cross_epoch
    {
      // Does not advance us past what we know the cluster has committed — ignore. TWO carve-outs:
      //
      // - an ASSEMBLED ORDINARY transfer completing below a target raised mid-transfer — the target is a
      //   freshness floor there, and the safety gates below still run (see the method doc).
      // - a CROSS-EPOCH crossing fetch (`require_cross_epoch`): the hinted `target` (an EpochAhead /
      //   higher-epoch `checkpoint_op`) is NOT a hard crossing bound — a buggy/misrouted hint can pin it
      //   UNREACHABLY high. The real crossing authority is the VERIFIED successor membership, checked in
      //   `apply_sync` (`successor.is_some()`); a verified successor reply comes only from a donor at/above
      //   the reconfigure op `N`, so it is a real crossing even BELOW a bogus target. Let it reach
      //   `apply_sync`, where the monotone-own-checkpoint gate (`> self.checkpoint_op`, just below), the
      //   no-rewind (`>= commit_min`), and the successor verification are the true admission. Without this
      //   carve-out a bogus hinted target would reject every valid below-hint successor reply forever.
      return;
    }
    // The `<= self.op` drop is ONLY for the ordinary trigger: there, an equal/lower checkpoint means a
    // racing tail-apply already covered it (no sync needed). A FORCED sync deliberately targets
    // a checkpoint AT/BELOW our head — we hold a tail above a pruned committed hole — so this guard
    // must NOT drop it; the forced sync MUST apply to subsume the hole. Forced safety is gated instead
    // on `>= self.checkpoint_op` below (advances our own checkpoint) + `apply_sync`'s `>= commit_min`
    // assert (never rewinds the applied frontier — which holds since target `>= N > commit_min`).
    if !s.forced && m.checkpoint_op().get() <= self.op.get() {
      return; // a racing tail-apply already covered the checkpoint — no sync needed (re-assert trigger).
    }
    if m.checkpoint_op().get() <= self.checkpoint_op.get() {
      return; // never regress our own checkpoint (monotone).
    }
    // The load-bearing integrity gate: never restore a snapshot whose bytes do not hash to the
    // advertised id (corrupt / forged / torn). Verified BEFORE any SM mutation. Keep `sync` armed so
    // the solicit timer re-fetches from another peer.
    if crate::checkpoint_id(m.snapshot()) != m.checkpoint_id() {
      return;
    }
    // A PRIMARY must NOT APPLY a state-sync in
    // place. `apply_sync` resets `commit_min` to the synced checkpoint and CLEARS `inflight` (the
    // commit pipeline) while KEEPING `self.op` (the held tail) and staying Normal primary — but it does
    // NOT rebuild the pipeline for the retained committed tail `(commit_min .. op]`, so the primary's
    // `try_commit` wedges forever at the checkpoint (the missing inflight entry at `commit_min + 1`
    // breaks the strictly-in-order commit loop, and re-acked PrepareOks drop on the empty `inflight`).
    // `maybe_force_sync` ALREADY guards the ARM site (a primary reaching the unservable-hole strand
    // sets `pending_forfeit` instead of force-syncing — see its safety note), but a forced/ordinary
    // sync ARMED while this replica was a BACKUP can still be DELIVERED after it (re)gained primacy, so
    // the guard must also hold at the APPLY site. Mirror the arm-site decision via the single
    // `abdicate_if_primary` chokepoint: a multi-replica primary that would apply a sync STEPS
    // DOWN — the chokepoint flags the deferred forfeit (+ the serviceable `svc_message` wake) which the
    // next `primary_timeouts` acts on (re-propose `view + 1`), and we DROP the rejected sync (its
    // `sync_solicit`, the only other timer this path armed) and skip the in-place apply. A caught-up
    // replica then leads (every replica already holds the committed tail durably), and THIS replica
    // recovers any pruned hole as a BACKUP via the ordinary force-sync escalation once it is no longer
    // primary. No committed op is lost (the synced snapshot is never discarded — it is simply re-fetched
    // as a backup; `commit_min` never rewinds). This is the same invariant `complete_recovery` enforces
    // for a restarted primary (abdicate rather than resume with a torn-down pipeline).
    //
    // EXCEPTION — a CROSSING sync (`require_cross_epoch`) must APPLY in place even on a primary, NOT
    // abdicate-and-drop. The abdicate rule guards a SAME-epoch in-place sync that KEEPS the retained tail
    // `(commit_min .. op]` and would wedge the un-rebuilt pipeline; a crossing forces `held_tail = false`
    // (the old-epoch tail above the crossing checkpoint is DISCARDED — it is not valid in E+1), so
    // `apply_sync` lands `commit_min == op == checkpoint_op` with NO retained tail and the wedge cannot
    // arise. And the abdication itself is FUTILE here: a STALE-epoch primary (a voter stranded at the OLD
    // epoch when the reconfiguration committed, still naming itself primary of its old view) has no
    // surviving same-epoch quorum to elect a successor, so the deferred forfeit never completes — it would
    // re-arm + re-drop the crossing forever, wedging the cluster short of convergence. Crossing is the
    // legitimate convergence path: `apply_sync` installs the verified successor membership, after which
    // this node operates in E+1 (its primacy re-derived there) and `catch_up_to_view` converges its view
    // off the new primary's now-same-epoch heartbeats.
    if !s.require_cross_epoch && self.abdicate_if_primary(now) {
      self.sync = None;
      self.sync_transfer = None;
      self.timers.sync_solicit = None;
      return;
    }
    self.apply_sync(now, sb, &m);
  }

  /// Receive a `SyncCheckpointMeta` — a donor announcing a checkpoint too large for one frame. Runs
  /// the BYTE-FREE PREFIX of the install cascade (so a transfer is never pinned for an envelope its
  /// assembly would fail), then pins/extends the chunked transfer and sends the first/next pull.
  ///
  /// The announced `total_len` is ADMISSION-GATED before anything is sized from it (it is a wire
  /// claim, not yet evidence): a length over the configured cap
  /// ([`Config::max_sync_envelope_len`](crate::Config::max_sync_envelope_len)) or beyond this
  /// target's address width is ignored outright, and the staging reservation itself is fallible —
  /// each refusal leaves any live pin and the armed `sync` untouched, so a buggy donor's announce
  /// costs nothing and a sane donor's next announce proceeds.
  ///
  /// Status dispatch mirrors the `SyncCheckpoint` ingress: `Normal` runs the ordinary cascade
  /// (`>= target` unless forced; ordinary `> self.op`; monotone over our own checkpoint; a primary
  /// ABDICATES at transfer START — it must never burn a whole transfer pulling an envelope its
  /// apply-site step-down would discard); the `Recovering` peer-fetch runs
  /// `on_recover_sync_checkpoint`'s prefix (the announced checkpoint must reach our own corrupt
  /// one). Pin transitions:
  /// - **No transfer** → pin `(op, id, total_len, donor)` and pull from offset 0.
  /// - **Same content pinned** (`(op, id)` equal — non-Byzantine id-match ⇒ content-match) → re-pin
  ///   the DONOR only (failover to a live holder), KEEP the staged prefix (chunks are
  ///   interchangeable across donors), and re-pull at the staged frontier. A same-id announce whose
  ///   `total_len` disagrees is a faulty donor — ignored.
  /// - **Strictly newer checkpoint** (passed the gates) → the pin is superseded: drop the staged
  ///   bytes and re-pin fresh.
  /// - Anything older/different → ignore (the live pin keeps pulling).
  pub(crate) fn on_sync_checkpoint_meta(&mut self, now: Instant, m: crate::SyncCheckpointMeta) {
    let recovering = self.status.is_recovering() && self.awaiting_peer_checkpoint();
    if !self.status.is_normal() && !recovering {
      return;
    }
    let Some(s) = self.sync else {
      return; // no sync outstanding — ignore.
    };
    if m.nonce() != s.nonce {
      return; // a reply to a prior solicitation / forged — not fresh.
    }
    // SINGLE-SUPERBLOCK-WRITER (the same fence as `handle_sync_checkpoint`): pin no new transfer
    // while a checkpoint persist OR a durable-VIEW/SwapEpoch root is in flight — a SwapEpoch
    // completion's forced checkpoint would otherwise collide with a staged sync re-persist. `sync`
    // stays armed; the solicit timer re-announces once the root lands.
    if self.pending_sb.is_some() || self.pending_checkpoint.is_some() {
      return; // already persisting a chosen snapshot / a root is in flight — no new transfer.
    }
    if m.total_len() == 0 {
      return; // malformed: no checkpoint envelope is empty (op u64 + session count u32 at least).
    }
    // The announced length is a wire-supplied CLAIM, admitted only under the configured envelope cap
    // and this target's address width (see the admission doc above) — a buggy peer's one small frame
    // can never drive an unbounded reservation, and an inadmissible announce is IGNORED (no pin
    // displaced, no abdication, sync stays armed). Runs for BOTH the Normal and the Recovering
    // peer-fetch ingress (both dispatch here), keeping the two paths' admission identical.
    if m.total_len() > self.config.max_sync_envelope_len() {
      return;
    }
    let Ok(announced_len) = usize::try_from(m.total_len()) else {
      return; // not representable on this target (32-bit) — the same ignore as over-cap.
    };
    if recovering {
      // The peer-fetch prefix (`on_recover_sync_checkpoint`): the announced checkpoint must at
      // least reach our own (corrupt) one, else its snapshot cannot subsume it.
      if m.checkpoint_op().get() < self.checkpoint_op.get() {
        return;
      }
    } else {
      // The byte-free prefix of `handle_sync_checkpoint`'s cascade. No assembled carve-out here:
      // a FRESH pin below the current target would assemble an envelope the forced gate rejects,
      // and an ordinary in-progress transfer re-pins through the same-content arm below (which
      // does not re-run this prefix — by then the floor is the pinned content's to keep).
      let same_pin = self.sync_transfer.as_ref().is_some_and(|t| {
        t.checkpoint_op == m.checkpoint_op() && t.checkpoint_id == m.checkpoint_id()
      });
      if !same_pin {
        // The `< target` floor is RELAXED for a CROSS-EPOCH crossing fetch (`require_cross_epoch`),
        // mirroring `handle_sync_checkpoint`: the hinted target is not a hard crossing bound (a bogus
        // hint can pin it unreachably high), so a large crossing snapshot below it must still PIN here —
        // its verified successor membership is the real crossing authority, enforced when the reassembled
        // envelope re-enters `handle_sync_checkpoint`/`apply_sync`. The monotone-own-checkpoint gate just
        // below still runs, so a below-our-checkpoint announce is still rejected.
        if m.checkpoint_op().get() < s.target.get() && !s.require_cross_epoch {
          return;
        }
        if !s.forced && m.checkpoint_op().get() <= self.op.get() {
          return;
        }
        if m.checkpoint_op().get() <= self.checkpoint_op.get() {
          return;
        }
        // A PRIMARY must not pull a transfer it could never apply (`handle_sync_checkpoint` steps
        // down at the APPLY site): abdicate at transfer START instead, before any chunk flows. EXCEPT a
        // CROSSING transfer (`require_cross_epoch`), which `handle_sync_checkpoint` APPLIES in place on a
        // primary (the crossing discards the old-epoch tail, so no pipeline wedge — and a stale-epoch
        // primary's abdication is futile); so it must PIN + pull here too rather than abdicate-and-drop,
        // matching the apply-site carve-out.
        if !s.require_cross_epoch && self.abdicate_if_primary(now) {
          self.sync = None;
          self.sync_transfer = None;
          self.timers.sync_solicit = None;
          return;
        }
      }
    }
    if let Some(t) = self.sync_transfer.as_mut() {
      if t.checkpoint_op == m.checkpoint_op() && t.checkpoint_id == m.checkpoint_id() {
        if t.total_len != m.total_len() {
          return; // a same-id announce with a different length is a faulty donor — ignore.
        }
        // Donor failover: same pinned content from a (possibly different) live holder — keep the
        // staged prefix and resume pulling from the frontier, now addressed to this announcer.
        t.donor = m.replica();
        let offset = t.staged.len() as u64;
        self.send_request_sync_chunk(now, offset);
        return;
      }
      if m.checkpoint_op().get() <= t.checkpoint_op.get() {
        return; // an older (or same-op different-content) announce never displaces the live pin.
      }
      // A strictly newer checkpoint passed the gates: the pinned transfer is superseded.
    }
    // Reserve the staging buffer FALLIBLY before adopting the pin: the announce passed the
    // admission cap, but the cap is an operator choice the allocator can still refuse. On refusal
    // nothing is adopted — a live pinned transfer survives untouched and `sync` stays armed (the
    // same keep-armed outcome as the inadmissible-announce ignore above; the solicit timer
    // re-announces). The exact reservation is the transfer's full extent, so `on_sync_chunk`'s
    // appends stay within capacity through the append-only growth to exactly `total_len`.
    let mut staged = std::vec::Vec::new();
    if staged.try_reserve_exact(announced_len).is_err() {
      return;
    }
    self.sync_transfer = Some(SyncTransfer {
      checkpoint_op: m.checkpoint_op(),
      checkpoint_id: m.checkpoint_id(),
      total_len: m.total_len(),
      epoch: m.epoch(),
      config_id: m.config_id(),
      membership: m.membership_bytes(),
      donor: m.replica(),
      staged,
    });
    self.send_request_sync_chunk(now, 0);
  }

  /// Receive a `SyncChunk` — one pulled piece of the pinned envelope. Guard cascade: status dispatch
  /// (Normal, or the Recovering peer-fetch); live sync + nonce; not mid-persist; the chunk's
  /// `(checkpoint_op, checkpoint_id, total_len)` all equal the pin; `offset` is EXACTLY the staged
  /// frontier (dups and reorders are inert — the ARQ re-pulls the frontier). A chunk that makes no
  /// progress (empty) or would overflow the announced total aborts the transfer — staged bytes
  /// freed, `sync` KEPT armed so the solicit timer re-announces and a fresh pin starts over.
  ///
  /// On the last chunk the WHOLE assembly is verified against the pinned content id BEFORE anything
  /// reaches the install path (a mismatched assembly is dropped the same abort-keep-sync way); the
  /// verified envelope then re-enters the EXISTING whole-message entry point —
  /// [`Self::on_sync_checkpoint`]'s body for a Normal receiver, `on_recover_sync_checkpoint` for the
  /// recovery peer-fetch — so the cascade, fallible decode, op bind-check, staged persist, and
  /// durable-root-before-destructive install barrier are bit-identical to a single-frame
  /// `SyncCheckpoint`.
  pub(crate) fn on_sync_chunk<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: crate::SyncChunk,
  ) {
    let recovering = self.status.is_recovering() && self.awaiting_peer_checkpoint();
    if !self.status.is_normal() && !recovering {
      return;
    }
    let Some(s) = self.sync else {
      return; // no sync outstanding — ignore.
    };
    if m.nonce() != s.nonce {
      return; // a reply to a prior solicitation / forged — not fresh.
    }
    // SINGLE-SUPERBLOCK-WRITER (the same fence as `handle_sync_checkpoint`): drop chunks while a
    // checkpoint persist OR a durable-VIEW/SwapEpoch root is in flight — the final chunk would re-enter
    // `handle_sync_checkpoint`, which now defers on a live root, so its install staging must not begin
    // here either. `sync` stays armed; the solicit timer re-announces once the root lands.
    if self.pending_sb.is_some() || self.pending_checkpoint.is_some() {
      return; // already persisting a chosen snapshot / a root is in flight — late chunks are moot.
    }
    let Some(t) = self.sync_transfer.as_mut() else {
      return; // no transfer pinned (never announced / already completed) — ignore.
    };
    if t.checkpoint_op != m.checkpoint_op()
      || t.checkpoint_id != m.checkpoint_id()
      || t.total_len != m.total_len()
    {
      return; // a chunk of some other content — inert against the pin.
    }
    if m.offset() != t.staged.len() as u64 {
      return; // out-of-order / duplicate — inert (the ARQ re-pulls the exact frontier).
    }
    let new_len = t.staged.len() as u64 + m.bytes().len() as u64;
    if m.bytes().is_empty() || new_len > t.total_len {
      // No progress, or past the announced end: a faulty donor. Abort the transfer (free the
      // staged bytes) but KEEP the sync armed — the solicit timer re-announces and re-pins fresh.
      self.sync_transfer = None;
      return;
    }
    t.staged.extend_from_slice(m.bytes());
    // The freshest live server answers the next pull (it just proved it holds the content).
    t.donor = m.replica();
    if new_len < t.total_len {
      self.send_request_sync_chunk(now, new_len);
      return;
    }
    // Assembly complete. Verify the WHOLE envelope against the pinned content id BEFORE anything
    // reaches the install path: the pinned id descends from the donor's durable root, so a torn /
    // corrupt assembly (or garbage chunks) cannot hash to it. A mismatch drops the transfer
    // (abort-keep-sync: the timer re-announces; chunks re-pull from scratch).
    let Some(t) = self.sync_transfer.take() else {
      return;
    };
    if crate::checkpoint_id(&t.staged) != t.checkpoint_id {
      return;
    }
    self.sync_chunk_transfers_completed += 1;
    // Re-enter the EXISTING whole-message path bit-identically: every gate, the decode, the op
    // bind-check, the staged two-write persist, and the durable-root install barrier run exactly as
    // they would for a `SyncCheckpoint` that arrived in one frame. The `SyncCheckpointMeta` announce
    // carried the SAME `(epoch, config_id, membership)` header as the whole form (pinned into the
    // transfer), so a CROSS-EPOCH sync that fell to the chunked path — a large post-swap snapshot —
    // installs the successor configuration exactly as a one-frame arrival would; a same-config sync
    // carries an empty membership that is simply left unread.
    let assembled = crate::SyncCheckpoint::new(
      m.view(),
      t.checkpoint_op,
      t.checkpoint_id,
      t.epoch,
      // The PINNED config id (from the announce), NOT this final `SyncChunk`'s donor-current id — a
      // donor reconfiguration/failover mid-transfer would otherwise splice a later config id onto the
      // announce's membership and fail the `(membership, config_id)` verification.
      t.config_id,
      m.replica(),
      s.nonce,
      Bytes::from(t.staged),
      t.membership,
    );
    if recovering {
      self.on_recover_sync_checkpoint(now, wal, sb, assembled);
    } else {
      self.handle_sync_checkpoint(now, wal, sb, assembled, true);
    }
  }

  /// STAGE a verified `SyncCheckpoint`. Runs the up-front
  /// VERIFICATION (the forced-vs-ordinary release-active assert, the fallible decode, the BIND-CHECK)
  /// — these mutate nothing — then stages the durable re-persist (the two superblock writes, reusing the
  /// checkpoint sequence) and REMEMBERS the install in `pending_install`. The DESTRUCTIVE install
  /// (restore the SM/sessions, advance `commit_min`/`commit_max`/`op`, prune the WAL, advance
  /// `checkpoint_op`) is DEFERRED to [`Self::install_sync`], which runs ATOMICALLY in `on_sb_done` only
  /// once the sync ROOT (step 2) is durable. `sync` stays `Some` until then, so a crash mid-persist
  /// re-solicits (the durable root still names the OLD checkpoint until step 2 lands).
  ///
  /// **Why defer the install (durable-before-install).** The destructive effects
  /// (pruning the WAL + advancing `commit_min`/`op`) are IRREVERSIBLE; the rest of viewstamp only performs
  /// such effects AFTER the durable record justifying them has landed (the normal checkpoint path GCs
  /// only after its root is durable; durable-view gates participation on `pending_sb`). The old
  /// `apply_sync` was the lone violator: it pruned the band + advanced `commit_min`/`op` EAGERLY, before
  /// the sync checkpoint root was durable, leaving a window where the replica was `Normal` with
  /// `commit_min == op == synced_op` and the band PRUNED but `checkpoint_op` STILL OLD. A view change in
  /// that window dropped the (not-yet-durable) sync and could make the replica a PRIMARY advertising the
  /// OLD `checkpoint_op` over a PRUNED committed band — a laggard below the band could then neither
  /// `RequestPrepare` (pruned) nor was it triggered to `RequestSync` (the primary advertised the old
  /// checkpoint) → cluster wedge if the donor crashed. Deferring the install to the durable root closes
  /// the window: during STAGE the replica keeps its OLD (consistent, if stale) state, so a view change
  /// finds it intact and cleanly cancels the install ([`Self::enter_view_change`] clears `sync` +
  /// `pending_install`), and — since STAGE never advanced `commit_min`/`op` — the replica structurally
  /// cannot advertise the synced commit until the install lands. This mirrors TigerBeetle, where the
  /// superblock write is the commit point and the synced checkpoint installs only after it is durable.
  ///
  /// **No committed op the replica already held AHEAD of the sync can be lost.** On the ORDINARY
  /// trigger the synced `checkpoint_op > self.op`, so the replica's entire held log `[..=self.op]` is
  /// at or below the synced point — every op `<= checkpoint_op` is already reflected in the snapshot the
  /// install restores. A *committed* op above `self.op` is impossible (committing an op requires having
  /// prepared it, which would put it `<= self.op`); the only thing discarded is a stale/uncommitted tail
  /// at or below the synced checkpoint, which is safe.
  ///
  /// On the FORCED path ([`Self::maybe_force_sync`]) the synced `checkpoint_op` may instead be
  /// `<= self.op` (the replica holds a tail ABOVE a pruned committed hole). The held tail
  /// `(checkpoint_op .. self.op]` is then **PRESERVED, not discarded** by the install — the `held_tail`
  /// decision captured HERE is what `install_sync` honours. Those ops were
  /// already durably APPENDED + ACKED by this replica (it voted for them), so the cluster may have
  /// COMMITTED them off its vote. The forced sync's *purpose* is only to recover the doomed hole(s) `N
  /// (<= checkpoint_op)` (subsumed by the restored snapshot); the acked tail above the floor must
  /// survive. `self.op` is FROZEN across the STAGE→install window (`on_prepare` drops while
  /// `sync.is_some()`), so the `held_tail` decision is identical at install time. The release-active
  /// safety guard below branches: ordinary ⇒ the fail-stop assert `checkpoint_op > self.op` (its
  /// `<= self.op` case is dropped upstream in `on_sync_checkpoint`, so reaching it here is a genuine
  /// trigger-loosening bug — fail loudly, matching `select_canonical_log`'s style); forced ⇒ the true
  /// invariant `checkpoint_op >= commit_min` (never rewind the applied frontier), where a VIOLATION is
  /// a reordered STALE response, not a bug — DROP it gracefully (see below), never panic.
  ///
  /// **Drop a stale forced SyncCheckpoint below the applied frontier.** The
  /// forced path relaxes the upstream stale-response guard to admit a checkpoint `<= self.op` (the
  /// held-tail case). That relaxation also lets a DELAYED forced `SyncCheckpoint` for a target the
  /// ordinary repair path has since SATISFIED (`commit_min` advanced PAST it) reach here below the
  /// applied frontier (`checkpoint_op < commit_min`). Part A normally CANCELS such a forced sync the
  /// moment commit catches up (so `on_sync_checkpoint` drops the late response at its `sync.is_none`
  /// guard and never calls us), but this is the load-bearing SAFETY NET for any path that still arrives:
  /// applying it would `set_commit_min` BACKWARD (a committed-op-survival violation the install's own
  /// `>= commit_min` debug-assert + the `set_commit_min` monotone choke would trip). So DROP it (early
  /// return, nothing staged) instead of asserting — a crash on a valid in-model reordering is itself a
  /// liveness/DoS bug. The LEGITIMATE forced sync (`commit_min <= checkpoint_op <= self.op`, the
  /// held-tail case) still STAGEs + INSTALLs unchanged.
  ///
  /// **Never sync past uncommitted state.** The synced `checkpoint_op` is, by definition, a checkpoint
  /// a peer made durable — a quorum committed+applied through it — and we additionally gate on
  /// `>= sync.target`, itself derived from a committed-cluster message. So we never adopt a snapshot
  /// above the committed frontier.
  pub(crate) fn apply_sync<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    m: &crate::SyncCheckpoint,
  ) {
    let checkpoint_op = m.checkpoint_op();
    // Release-active safety guard, branched on whether this is a FORCED sync.
    if self.sync.is_some_and(|s| s.forced) {
      // FORCED path. The synced checkpoint may legitimately sit at/below our head (we hold a tail above
      // a pruned committed hole under an adversarial schedule), so the ordinary `> self.op` requirement is relaxed.
      // The TRUE invariant is `checkpoint_op >= commit_min` (never rewind the applied frontier). A
      // VIOLATION here is a reordered STALE forced SyncCheckpoint: a forced sync whose
      // target the ordinary repair path already SATISFIED (`commit_min` advanced PAST it), arriving late.
      // DROP it gracefully — applying it would `set_commit_min` BACKWARD (a committed-op rewind). Part A
      // (`cancel_forced_sync_if_satisfied`) normally clears such a forced sync the moment commit catches
      // up, so `on_sync_checkpoint` drops the late response upstream and never reaches us; this is the
      // load-bearing safety net for any path that still arrives. We have mutated nothing, so an early
      // return is clean. Cancel the stale sync + its solicit timer (the target is already satisfied — its
      // own commit-frontier `> sync.target`, so there is nothing left to fetch); the install's own
      // `>= commit_min` debug-assert + the monotone `set_commit_min` choke remain the backstop a genuine
      // commit_min rewind would still trip. The LEGITIMATE forced sync (`commit_min <= checkpoint_op <=
      // self.op`) falls through and STAGEs normally.
      if checkpoint_op.get() < self.commit_min.get() {
        self.sync = None;
        self.sync_transfer = None;
        self.timers.sync_solicit = None;
        return;
      }
    } else {
      // ORDINARY path: the synced checkpoint is strictly above our head, so discarding our held log
      // `[..=op]` cannot drop a committed op. The `<= self.op` case is dropped upstream in
      // `on_sync_checkpoint` (the racing-tail-apply guard), so reaching here with `checkpoint_op <=
      // self.op` is a genuine trigger-loosening bug — keep the FAIL-STOP assert (it makes such a
      // regression fail loudly rather than silently drop a committed op, matching `select_canonical_log`).
      // `self.op` is FROZEN across the STAGE→install window (`on_prepare` drops while `sync.is_some()`),
      // so this holds identically at install time.
      assert!(
        checkpoint_op.get() > self.op.get(),
        "state-sync must not discard a held op above the synced checkpoint (checkpoint_op {} <= op {})",
        checkpoint_op.get(),
        self.op.get()
      );
    }
    // Decode the verified envelope FIRST (before staging anything irreversible). `on_sync_checkpoint`
    // already verified `checkpoint_id(snapshot) == m.checkpoint_id()`, so the bytes are the right
    // checkpoint; but a malformed/truncated envelope (a buggy encoder, or corruption that somehow
    // preserved the hash) must NOT panic — reject it as a fault and leave `sync` armed so the solicit
    // timer re-fetches from another peer. We have mutated nothing yet, so an early return is clean.
    let Some((bound_op, sessions, sm_tail)) = Self::decode_checkpoint(m.snapshot()) else {
      return;
    };
    // BIND-CHECK (safety): the op hashed INTO the snapshot must equal the advertised `checkpoint_op`
    // the install will advance `commit_min`/`commit_max`/`op` to. A faulty peer can ship STALE snapshot
    // bytes (whose real frontier is op A) under an OVERSTATED `checkpoint_op = B > A` whose hash still
    // matches the old bytes; without this check the install would restore the OLDER SM yet advance the
    // frontier to B — silently dropping the committed ops in `(A, B]`. Reject (no staging; `sync` stays
    // armed so another peer answers) rather than drop committed state.
    if bound_op != checkpoint_op {
      return;
    }
    // PRESERVE-TAIL decision, captured for the deferred install: does this sync
    // land BELOW our held head? Only the FORCED path can (the ordinary assert above guarantees
    // `checkpoint_op > self.op`). When it does, `install_sync` PRESERVES the band `(checkpoint_op ..
    // self.op]` rather than discarding it — those ops were already durably APPENDED + ACKED, so the
    // cluster may have committed them off our vote. `self.op` is frozen across the window, so this
    // decision is stable until install. Own an OWNED zero-copy slice of the SM-tail bytes (the
    // `decode_checkpoint` borrow into the wire envelope does not outlive `m`), so the install restores
    // without re-decoding.
    //
    // OVERRIDDEN below for a CROSSING install (`successor.is_some()`): a cross-epoch crossing snapshot is
    // authoritative for E+1, so EVERY op the laggard holds above the crossing checkpoint must be discarded
    // — they were appended in the OLD epoch's lineage (the cluster swapped at `N <= M == checkpoint_op`) and
    // are NOT valid E+1 ops. The held-tail preservation argument ("the cluster may have committed them off
    // our vote") holds only for a SAME-epoch forced sync; a NORMAL-status speculative laggard
    // ([`Self::cross_epoch_speculative_sync`]) may have appended such an old-epoch tail above `M` while the
    // sync was armed, so crossing MUST force `held_tail = false`.
    let mut held_tail = checkpoint_op.get() < self.op.get();
    let tail_offset = m.snapshot().len() - sm_tail.len();
    let sm_tail = m.snapshot_bytes().slice(tail_offset..);
    // CROSS-EPOCH catch-up: the served snapshot reflects a configuration AHEAD of ours (its `config_id`
    // differs from our active one). How we handle it depends on whether the donor ATTACHED its successor
    // membership — which (post-XI-b-serve-gate) it does ONLY when its checkpoint REFLECTS that membership
    // (`checkpoint_op >= config_install_op`, i.e. at/above the reconfigure op `N`):
    //
    // - NON-EMPTY membership ⟹ the donor's checkpoint is at/above `N`, so this snapshot frontier IS in E+1.
    //   Reconstruct + VERIFY the successor from the carried `(epoch, config_id, membership)` (the bytes
    //   hash-chain to the carried `config_id` — `to_membership_verified` recomputes `hash(membership,
    //   prev_config_id)` and rejects a mismatch, so a forged/corrupt membership cannot install) and install
    //   it ATOMICALLY with the frontier. A non-empty membership that does NOT verify is corrupt/forged —
    //   DROP the whole sync (stage NOTHING; `sync` stays armed so the solicit timer re-fetches), since
    //   advancing the frontier into an epoch whose configuration we cannot reconstruct would strand us.
    //
    // - EMPTY membership ⟹ the donor WITHHELD it (its checkpoint `M < N`, the commit-first swap window):
    //   this snapshot frontier is BELOW the reconfigure op, so it is still an E-prefix. Install the SM
    //   frontier but KEEP our current membership (`successor = None`) and catch the band `(M .. N]` up via
    //   the ordinary repair/commit path — swapping to E+1 only at `N` through the commit-first path (XI-b:
    //   the committed prefix through `N` is held before E+1 is reached). Installing here (rather than
    //   dropping) lets a laggard whose needed ops are pruned everywhere still make progress off the donor's
    //   below-`N` checkpoint. (Under the crash-fault threat model an empty cross-epoch membership comes
    //   only from this honest withhold; a same-config sync also serves empty and likewise keeps `successor
    //   = None`, byte-identical to the pre-reconfiguration behavior.)
    let successor = if m.config_id() != self.membership.config_id() && !m.membership().is_empty() {
      let Some(payload) = crate::message::ReconfigurePayload::decode_body(m.membership()).ok()
      else {
        return;
      };
      // VERIFY the carried successor reconstructs to its claimed `config_id` (the hash-chain
      // `hash(membership, prev_config_id) == config_id`), and CAPTURE the verified predecessor id — the
      // `prev_config_id` the payload pinned, the value that made this verification succeed. It is the
      // immediate predecessor in the configuration lineage (NOT the laggard's own current `config_id`,
      // which on a MULTI-epoch skip is an EARLIER ancestor), so it MUST flow into the install + the
      // durable root so the re-served membership chains from it. Throwing it away (keeping only the
      // membership) and re-deriving the predecessor from the stale current config is the lineage break a
      // direct E0→E2 crossing would suffer.
      let verified_prev = payload.prev_config_id();
      match payload.to_membership_verified(m.epoch(), m.config_id()) {
        Ok(successor) => {
          // MULTI-epoch DISTANCE bound (XI-b lineage representability). The crossing carries exactly ONE
          // verified predecessor — `verified_prev`, the installed config's IMMEDIATE predecessor. With the
          // laggard's own current `config_id` shifted in beneath it, the post-crossing ring holds a
          // TWO-element chain `[verified_prev, own_prior]`: enough to represent a skip of at most
          // [`LINEAGE_RING`] epochs (E(n)→E(n+1) needs slot 0; E(n)→E(n+2) needs both slots). A DEEPER skip
          // (E0→E3: the receiver has NOT proved the missing E2<-E1<-E0 chain, and the single carried `prev`
          // cannot reconstruct it — `verified_prev` is E2, whose real predecessor E1 the ring cannot hold)
          // is REJECTED here: the epoch DISTANCE `successor.epoch() - current.epoch()` exceeds what one
          // carried predecessor can chain. A successor that is NOT strictly ahead (`<= current.epoch()`) is
          // likewise not a forward crossing. Either way stage NOTHING and return — `sync` stays armed so the
          // solicit timer re-fetches / a closer (smaller-skip) donor is tried — rather than mis-install a
          // lineage the ring cannot prove. Saturating subtraction keeps the scalar arithmetic underflow-free.
          // The single-change E(n)→E(n+1) (distance 1) path always passes (1 <= LINEAGE_RING), unaffected.
          let current_epoch = self.membership.epoch();
          let distance = successor.epoch().get().saturating_sub(current_epoch.get());
          if successor.epoch() <= current_epoch || distance > LINEAGE_RING as u64 {
            return;
          }
          Some((successor, verified_prev))
        }
        Err(_) => return,
      }
    } else {
      None
    };
    // CROSSING discards the old-epoch tail. A snapshot that installs the SUCCESSOR membership crosses us
    // into E+1, where every op we hold above the crossing checkpoint `M` is a stale OLD-epoch entry (the
    // cluster swapped at `N <= M`): force `held_tail = false` so the install truncates to `M`, never
    // preserving a tail that is not in E+1's lineage. (For a SAME-config sync `successor == None` and the
    // held-tail preservation is unchanged — byte-identical.)
    if successor.is_some() {
      held_tail = false;
    }
    // CROSSING REQUIREMENT (the cross-epoch crossing fetch — [`SyncState::require_cross_epoch`]). A laggard
    // stranded at the OLD epoch fetching to cross into E+1 MUST install a strictly-higher epoch carrying the
    // successor membership; it can NOT settle for a reply that would install with `successor = None` and exit
    // STILL at the old epoch. The authority is the VERIFICATION, not the unverified hint: `successor.is_some()`
    // captures the real crossing (different `config_id` AND non-empty membership AND the bytes hash-chain to
    // the carried `config_id` via `to_membership_verified`). It is REQUIRED here — a same-config or
    // empty-membership reply (a donor in the transient force-checkpoint window serving its `M < N` checkpoint)
    // is REJECTED: stage NOTHING and return, leaving `sync`/`pending_install` consistent (identical to the
    // corrupt-membership `None => return` drop above) so the solicit timer re-fetches until a donor's E+1
    // crossing checkpoint lands (#1 guarantees one exists, restart-survivably).
    //
    // The hinted `target` (an EpochAhead / higher-epoch `checkpoint_op`) is NOT a hard crossing bound here —
    // only the SOLICIT floor (which donor checkpoint to request). A buggy/misrouted higher-epoch message
    // (even from an out-of-config replica) could carry an UNREACHABLE `checkpoint_op` that `target` only
    // RAISES toward; gating install on `checkpoint_op >= target` would then let a bogus hint PIN the crossing
    // to a point no honest donor can satisfy and reject every VALID below-hint successor reply forever. A
    // verified successor-membership checkpoint comes ONLY from a donor whose checkpoint is at/above the
    // reconfigure op `N` (the `config_install_op` XI-b serve gate withholds the membership below `N`), so it
    // is ALWAYS a real crossing even when below a bogus hinted target — cross to it and catch the rest up via
    // the ordinary E+1 machinery. No-rewind is unaffected: the forced path already dropped any
    // `checkpoint_op < commit_min` reply above, and `install_sync`'s `>= commit_min` debug-assert remains the
    // backstop. An ordinary / non-cross-epoch sync (`require_cross_epoch == false`) skips this and keeps the
    // empty-membership `successor = None` behavior byte-identical.
    if let Some(s) = self.sync
      && s.require_cross_epoch
      && successor.is_none()
    {
      return;
    }
    // Stage the durable re-persist, reusing the checkpoint two-write sequence so a crash recovers to
    // the synced point (not the stale one) ONLY once the root lands. Step 1: write the snapshot under
    // our own superblock; step 2 (in `on_sb_done`) writes the new VsrState root naming it, which then
    // drives `install_sync`. `sync` + `pending_install` stay armed until step 2 completes. (No
    // checkpoint can already be in flight — `on_sync_checkpoint` gates on `pending_checkpoint.is_none()`.)
    let id = self.mint_op_id();
    sb.submit_write_checkpoint(id, checkpoint_op, m.snapshot_bytes());
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op: checkpoint_op,
      checkpoint_id: m.checkpoint_id(),
      step: CheckpointStep::AwaitSnapshot(id),
      // a STATE-SYNC re-persist: the root completion routes to the install
      kind: CheckpointKind::SyncRepersist,
    });
    // REMEMBER the install — applied atomically by `install_sync` when the root is durable. Until then
    // the replica keeps its OLD (consistent, if stale) in-memory + durable state: NOTHING destructive
    // (no SM restore, no `commit_min`/`op` advance, no WAL prune) happens yet, so a view change in this
    // window cancels cleanly with no pruned-but-stale band (the durable-before-install guarantee).
    // Split the verified crossing pair into the two `PendingInstall` fields: the successor membership and
    // the VERIFIED predecessor `config_id` it chains from (the value that satisfied the hash-chain). The
    // install + its durable root stamp the lineage from THIS verified chain, never re-deriving it from the
    // stale current config — so a re-served crossing recomputes the SAME `config_id` a fresh laggard expects.
    let (successor, successor_prev_config_id) = match successor {
      Some((membership, prev)) => (Some(membership), Some(prev)),
      None => (None, None),
    };
    self.pending_install = Some(PendingInstall {
      checkpoint_op,
      sessions,
      sm_tail,
      held_tail,
      successor,
      successor_prev_config_id,
    });
    // A snapshot is chosen and persisting: any in-progress chunked transfer is superseded (a
    // single-frame `SyncCheckpoint` racing a pinned transfer landed first — its staged bytes are
    // moot, and `pending_checkpoint` blocks new chunk activity until the persist resolves).
    self.sync_transfer = None;
    // Keep re-soliciting until the persist's root write completes (defends a fault mid-persist).
    self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
  }

  /// INSTALL a staged `SyncCheckpoint` — the DESTRUCTIVE half of
  /// [`Self::apply_sync`]. Restores the SM + sessions, advances `commit_min`/`commit_max`/`op` to the
  /// synced point (preserving the forced-sync held tail), and prunes the WAL. (The caller advances
  /// `self.checkpoint_op` — see the note at the tail — so the durable checkpoint pointer moves only when
  /// the synced root is durable.) BOTH paths run it in `on_sb_done` once the sync ROOT (step 2) is
  /// durable, the destructive effects then ATOMICALLY justified by that durable root: the Normal
  /// deferred-sync path (already Normal) and the recovery peer-fetch path (which STAGED the re-persist and
  /// STAYED `Recovering`, then `complete_recovery` flips it to Normal right after this install). After the
  /// caller advances `checkpoint_op`, `(checkpoint_op, the durable root id)` and `commit_min`/`op` are ALL
  /// consistent at the synced point: there is no window where `checkpoint_op` lags a pruned band, so a
  /// synced replica can never become primary advertising a checkpoint below a pruned committed band. It is
  /// idempotent against intervening state: `self.op`/`commit_min`/`commit_max` are frozen across the
  /// STAGE→here window (`advance_commit` is suppressed while `pending_install`, and `on_prepare` drops
  /// while `sync.is_some()`), so the captured `held_tail` and the monotonic advances below are exactly as
  /// they would have been at STAGE time.
  pub(crate) fn install_sync<W: Wal>(&mut self, wal: &mut W, install: PendingInstall) {
    let PendingInstall {
      checkpoint_op,
      sessions,
      sm_tail,
      held_tail,
      successor,
      successor_prev_config_id,
    } = install;
    // Defensive monotonicity (never rewind the applied frontier): `commit_min` is frozen below the
    // doomed hole on the forced path (the hole `<= checkpoint_op` blocks `advance_commit`) and is `<
    // checkpoint_op` on the ordinary path, so this advance is always forward. Asserted in debug builds
    // to catch any future relaxation that would let the window advance `commit_min` past the snapshot.
    debug_assert!(
      checkpoint_op.get() >= self.commit_min.get(),
      "install must not rewind the applied frontier (checkpoint_op {} < commit_min {})",
      checkpoint_op.get(),
      self.commit_min.get()
    );
    // Restore the SM and the client-session table from the decoded snapshot.
    self.sm.restore(&sm_tail);
    self.clients = sessions;
    // Advance metadata monotonically to the synced point. `commit_min` becomes the synced frontier;
    // `commit_max` keeps the higher learned commit (a held tail we are about to re-apply may already be
    // known-committed). With no held tail, `op == commit_max == commit_min == checkpoint_op` (the
    // post-recover-from-checkpoint shape); with a held tail, `self.op` and `commit_max` stay, so
    // `op >= commit_max >= commit_min == checkpoint_op` still holds. The universal monotone floor is
    // asserted in `set_commit_min`; the richer rewind assert above adds the forced-vs-ordinary proof.
    self.set_commit_min(checkpoint_op);
    self.commit_max = OpNumber::with(self.commit_max.get().max(checkpoint_op.get()));
    if !held_tail {
      self.op = checkpoint_op;
      self.commit_max = checkpoint_op;
    }
    // Drop in-memory state the snapshot subsumes. Below the checkpoint everything is folded into the
    // snapshot; ABOVE it we keep the retained tail (held_tail) so a possibly-committed acked op is not
    // lost. Any pending-repair hole AT/BELOW the checkpoint is subsumed (cleared); a hole strictly
    // above it (held_tail only) stays solicited (the recovered tail may still have an interior faulty
    // slot the snapshot does not cover).
    //
    // The log cache trim is the SHARED post-checkpoint rule ([`Self::trim_log_to_checkpoint`], common
    // with `run_gc`): drop every op `<= checkpoint_op`, retaining the held tail `(checkpoint_op ..
    // head]`. The committed-survival witness floor is the LOCAL synced `checkpoint_op` (the snapshot
    // restored above), NOT `self.checkpoint_op` — the deferred-advance leaves `self.checkpoint_op`
    // at the OLD value until the caller records the synced root.
    self.trim_log_to_checkpoint(checkpoint_op.get(), checkpoint_op.get());
    // The remaining teardown is site-specific (NOT the shared trim): a sync lands as a BACKUP and
    // fully tears the pipeline down — `clear()` (not retain-above-floor) so a far-future buffered
    // prepare ABOVE the synced checkpoint cannot survive a snapshot that invalidates it.
    self.inflight.clear();
    self.buffer.clear();
    self.repair.retain(|&op| op > checkpoint_op.get());
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
    }
    self.pending.clear();
    // In-flight WAL appends are abandoned here too; their op numbers must not linger as "in flight"
    // (a stale completion finds no `pending` entry and is ignored) — keep `appending` in lockstep.
    self.appending.clear();
    // Rebuild the durable WAL. Drop any stale slots strictly ABOVE our head (a stale higher generation
    // that would otherwise read back as a wrong head on a later restart) — `truncate(self.op)`, which
    // is a no-op when no tail is held (`self.op == checkpoint_op`) and preserves the retained tail
    // `(checkpoint_op .. op]` otherwise. Then free slots strictly BELOW the checkpoint (superseded by
    // the snapshot). The durable ROOT (already written) names `commit = checkpoint_op`, so a later
    // `recover()` restores the SM at the synced point and re-reads the retained tail from the WAL.
    //
    // `prune(checkpoint_op)` frees `< checkpoint_op`, deliberately RETAINING the slot AT `checkpoint_op`
    // — so a no-held-tail sync (`self.op == checkpoint_op`, just truncated above) leaves a NON-EMPTY WAL
    // with `op_head() == checkpoint_op`, not an empty WAL that would read back head 0 on restart. This
    // is why the WAL prune is NOT folded into the shared post-checkpoint trim: `run_gc` frees `<= floor`
    // (`prune(floor+1)`) because it has no such WAL-head constraint, so the two sites legitimately use a
    // different prune FLOOR. Only the in-memory log trim above is common ([`Self::trim_log_to_checkpoint`]).
    wal.truncate(self.op);
    wal.prune(checkpoint_op);
    // CROSS-EPOCH catch-up: install the SUCCESSOR membership the synced snapshot reflects, atomically with
    // the rest of this durable-root-justified install. `apply_sync` already reconstructed + VERIFIED it
    // from the carried `(epoch, config_id, membership)` (the `config_id` hash-chain check), so this is a
    // checked configuration; `install_membership` performs the SAME side effects as the commit-first epoch
    // swap (set `self.membership`/`self.prev_epoch`, `push_lineage`, `recompute_quorum_checkpoint`, the
    // removed-leader abdication). A SAME-config sync (`successor == None`) skips this entirely —
    // byte-identical to the pre-reconfiguration install. Pass `None` for the reconfigure op: a cross-epoch
    // sync install emits NO `MembershipChanged` — the laggard synced PAST the Reconfigure op and cannot
    // name it, so naming the sync frontier (a client op) would misreport the consensus-layer applied gap;
    // the swap is observed via the sync completion + the installed membership, and the replicas that
    // committed the Reconfigure op directly report its number.
    if let Some(successor) = successor {
      // THE GOAL IS MET: this install actually crosses — it advances the epoch and installs the successor
      // membership. CLEAR the persistent crossing intent so `on_sb_done`'s re-arm sees `None` and does NOT
      // re-arm a crossing sync forever after the node has already crossed (the intent re-arms only a
      // NON-crossing install). Cleared HERE, inside the successor branch, so it fires on exactly the
      // crossing installs and never on a same-config (`successor == None`) one.
      self.cross_epoch_intent = None;
      // Capture the laggard's own current `config_id` BEFORE the swap — its prior-config slot in the
      // post-crossing lineage.
      let own_prior_config_id = self.membership.config_id();
      self.install_membership(None, successor);
      // prev_epoch from the VERIFIED chain (the backward-link scalar, the analogue of the lineage-ring fix
      // below). `install_membership` set `self.prev_epoch = old self.membership.epoch()` (the laggard's own
      // stale epoch) — correct ONLY for a SINGLE-epoch crossing, where that IS the installed config's
      // immediate predecessor. On a MULTI-epoch skip the predecessor is `successor.epoch() - 1` (E2→E1),
      // NOT the laggard's stale E0; leaving E0 would record "E2 chains from epoch 0" while the ring above
      // correctly says `[E1, E0]` — the contradiction a recovered node restores and the lineage checker
      // reads as a fork. After `install_membership`, `self.membership` IS the successor, so its epoch is the
      // crossing target; subtract one for the predecessor. This stamps the EXACT value
      // `durable_root_with_successor` writes (`successor.epoch() - 1`), so a node recovering off that root
      // restores the identical scalar. Single-epoch (`old epoch == successor.epoch() - 1`) is a no-op,
      // byte-identical. Saturating to stay underflow-free; the `apply_sync` distance bound proved a crossing
      // has `successor.epoch() >= 1`.
      self.prev_epoch = crate::Epoch::new(self.membership.epoch().get().saturating_sub(1));
      // LINEAGE from the VERIFIED chain (the XI-b hash-chain fix). `install_membership`'s default
      // `push_lineage` placed the laggard's own prior (`own_prior_config_id`) at the ring's slot 0 — correct
      // ONLY for a SINGLE-epoch crossing, where that prior IS the installed config's immediate predecessor.
      // On a MULTI-epoch skip (a retained E0 laggard syncing a successor verified against E1) the installed
      // config's immediate predecessor is the VERIFIED `prev_config_id` (E1), NOT E0 — so push that on top,
      // making the ring `[E1, E0, ..]` most-recent-first (the verified immediate predecessor, then the
      // laggard's own prior). Without this the ring would be `[E0, ..]` and a later re-serve of the successor
      // membership would chain it from E0, recomputing a `config_id` that NO fresh laggard expects — breaking
      // the documented two-prior lineage window. The single-epoch case (`prev == own_prior`) takes neither
      // extra push, byte-identical to before. `apply_sync` already bounded any skip the ring cannot represent.
      if let Some(verified_prev) = successor_prev_config_id
        && verified_prev != own_prior_config_id
      {
        self.push_lineage(verified_prev);
      }
      // `install_membership(None, ..)` does not set `config_install_op` (a cross-epoch sync has no LOCAL
      // reconfigure op — the laggard synced PAST it). Set it to the synced frontier `checkpoint_op`: the
      // donor attached this successor only because ITS checkpoint reached the reconfigure op `N`, and the
      // laggard's synced `checkpoint_op` equals that donor checkpoint, so `checkpoint_op >= N`. This is a
      // safe, restart-survivable lower bound that lets this node (now a potential donor) re-serve E+1 at or
      // above its own frontier while never offering it below it. `checkpoint_op` is the staged install op
      // (`self.checkpoint_op` is advanced to it by the caller immediately after, in the same arm).
      self.config_install_op = checkpoint_op;
      // CONSUME any LOCAL staged swap this crossing SUPERSEDED. A laggard can commit a `Reconfigure` op
      // and stage `pending_swap` (the successor membership), enter ViewChange before its SwapEpoch root
      // installs, then get crossed cross-epoch by a higher-epoch heartbeat: `enter_cross_epoch_peer_fetch`
      // PRESERVES `pending_swap` (`reset_for_view_transition` keeps the committed change), and THIS install
      // then advances `self.membership` to the synced successor. The staged swap is now STALE — its
      // successor chained from the OLD (pre-crossing) config that no longer exists here. Left intact, the
      // caller's `maybe_swap_epoch` (or a commit tail) would re-submit a DUPLICATE SwapEpoch root stamped
      // with the just-installed config as its OWN predecessor — pushing it into the lineage ring a second
      // time, emitting a bogus `MembershipChanged`, and evicting legitimate older ancestors. So clear it
      // here, at the crossing, alongside any in-flight `SwapEpoch` action (belt-and-suspenders: the sync
      // re-persist is the in-flight write on this path, but a stale `SwapEpoch` action must not outlive the
      // swap it staged). `maybe_swap_epoch`'s chain-validation is the structural backstop for any other
      // supersession path; this is the direct cleanup at the cross-epoch crossing. With no staged swap
      // (the laggard never proposed one) this is a no-op, keeping that path byte-identical.
      self.pending_swap = None;
      if matches!(self.pending_sb, Some((_, PendingSbAction::SwapEpoch(_, _)))) {
        self.pending_sb = None;
      }
    }
    // NOTE: `self.checkpoint_op` is advanced to the synced op by the CALLER (`on_sb_done`'s sync
    // re-persist arm) — NOT here — because it must move only when the synced checkpoint ROOT is durable.
    // BOTH paths run `install_sync` at root completion, so the caller advances `checkpoint_op` in the same
    // arm, immediately after: the durable checkpoint pointer moves in lockstep with the durable root that
    // justifies it, leaving no window where `checkpoint_op` names a checkpoint whose snapshot is not yet
    // durable.
  }
}

use super::*;

impl<S: StateMachine> BlockFetch<S> {
  /// Pumps BOTH the SM and session frontiers and returns the next MISSING block to fetch across the two
  /// DAGs, or `None` when BOTH are fully present (the install can run). The SM DAG is drained first and
  /// the session DAG second — a deterministic order so the fetch sequence is stable — but completion
  /// requires both: a missing SM block is returned while the SM frontier has one, else the next missing
  /// session block, else `None`. A bound breach in EITHER walk surfaces as `Err` (the caller aborts the
  /// fetch). `addr` and `on_block` route to whichever frontier owns the address: a `BlockResponse` for an
  /// SM address feeds `block_sync`, one for a session address feeds `session_sync`; an off-frontier
  /// address is inert in both.
  pub(crate) fn next_missing(
    &mut self,
    blocks: &dyn BlockStore,
  ) -> Result<Option<BlockAddress>, super::block_sync::BlockSyncError> {
    if let Some(addr) = self.block_sync.next_request(blocks)? {
      return Ok(Some(addr));
    }
    self.session_sync.next_request(blocks)
  }
}

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
      // NOT a bare pre-answer crossing — PRESERVE the sync, never re-target it. Two cases the narrowed
      // predicate covers: a GENUINE answered crossing (a live `block_fetch` — kept live even across an
      // active-donor absent — or a NON-Normal recovery peer-fetch — a donor has begun answering; it must
      // complete on its own path), and
      // a COMMITTED STAGED install (`pending_install` set) whose re-target would corrupt the in-flight
      // install. Either way leaving the sync intact keeps the `pending_install => sync` coupling. The
      // PERSISTENT intent is NOT cleared here. A SAME-CONFIG staged install's (irrelevant) intent does not
      // leak — the ingress cancel runs on the same same-epoch admissible message (before this trigger
      // dispatches) and clears it there. A VERIFIED CROSSING staged install's intent is DELIBERATELY KEPT by
      // both this path and the ingress cancel: it is a committed crossing the intent backs, so same-epoch
      // traffic must not strand the laggard at the old epoch if a later view transition cancels the pre-root
      // install. (The caller's raise path is target-gated and a below-swap same-epoch checkpoint is below the
      // crossing target, so it cannot fire here either.)
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
    self.quarantined_donor = None;
    self.quarantine_probe_deadline = None;
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
    // self.op + 1`. Appending `pop` reuses slot `pop mod capacity` (last held by `pop - capacity`); it
    // is an UN-pruned overwrite iff `pop - self.checkpoint_op > capacity`. The EFFECTIVE ring
    // (`effective_wal_capacity` — the backend's own, or the proto-imposed ring for a ring-less backend):
    // enforcing it here is the backup half of the `op_head <= checkpoint_op + effective` geometry that
    // `recover()`'s read ceiling leans on.
    let capacity = self.effective_wal_capacity(wal);
    if pop.saturating_sub(self.checkpoint_op.get()) <= capacity {
      return false; // fits the ring — append normally.
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
  /// a STRICTLY-newer durable checkpoint; an EQUAL-CHECKPOINT block repair sets the `recovery` flag so a
  /// peer at the SAME `checkpoint_op` also serves it. Two distinct states need that equal-checkpoint
  /// serve, both because our OWN copy of `checkpoint_op`'s block DAG is unusable and we need a clean copy
  /// from a peer that holds it:
  ///
  /// - a RECOVERY peer-fetch (`awaiting_peer_checkpoint()`) — our own checkpoint snapshot read back
  ///   permanently corrupt;
  /// - an owed SM-RECONSTRUCT (`sm_reconstruct_owed()`) — a post-root restore for a synced checkpoint M
  ///   faulted (`self.checkpoint_op == M`), so M's block DAG is being re-pulled to retry the restore;
  ///   should M's pinned donor go dark, the block-fetch ARQ's `RequestBlock` is unanswerable and only a
  ///   FRESH `SyncCheckpoint` from another peer at M can re-pin the fetch (donor failover, served by
  ///   `refetch_sm_reconstruct`) — but that peer is itself AT M, so it answers only an equal-checkpoint
  ///   solicitation.
  ///
  /// Without the flag in either case, an idle cluster where every healthy peer holds exactly our
  /// `checkpoint_op` ignores the request forever → the recovery / the owed reconstruct livelocks.
  pub(crate) fn send_request_sync(&mut self, now: Instant) {
    let nonce = self.sync.map_or(self.nonce, |s| s.nonce);
    let recovery = self.awaiting_peer_checkpoint() || self.sm_reconstruct_owed();
    let request = crate::RequestSync::new(
      self.view,
      self.checkpoint_op,
      self.local_slot(),
      nonce,
      recovery,
      self.membership.config_id(),
    );
    self.emit(Outgoing::new(
      Recipient::Backups,
      Message::RequestSync(request),
    ));
    // ALSO solicit a remembered QUARANTINED donor directly: the `Backups` fan-out reaches only
    // bound members, but a crossing armed by a quarantined member (#65) must reach the donor whose
    // slot this laggard cannot yet resolve — its old bound peers are gone.
    if let Some(donor) = self.quarantined_donor {
      self.emit(Outgoing::new(
        Recipient::To(donor),
        Message::RequestSync(request),
      ));
    }
    self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
  }

  /// State-sync solicit timer: while a sync is outstanding, re-broadcast `RequestSync` and re-arm.
  /// Doubles as the block-fetch transfer's ARQ: with a block-fetch in progress, FIRST re-send the one
  /// outstanding stop-and-wait `RequestBlock` (the request or its answer may have been lost — the
  /// frontier's next-missing address is recomputed from the store, so the re-send is idempotent), THEN
  /// re-broadcast `RequestSync` (dead-donor replacement: a fresh `SyncCheckpoint` from any live holder
  /// re-pins the donor and the block-fetch resumes at the same frontier). Cleared when the synced
  /// checkpoint goes durable (`on_sb_done` clears `sync` + this timer).
  pub(crate) fn sync_timeouts<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
    if self.timers.sync_solicit.is_none_or(|d| d > now) {
      return;
    }
    if self.sync.is_none() {
      self.timers.sync_solicit = None;
      return;
    }
    // FIRST, self-heal an owed LOCAL install whose flush barrier faulted: the complete verified DAG is
    // already in our store, so re-attempt the flush + the durable re-persist LOCALLY — no donor reply is
    // needed. A transient disk fault that dropped the only locally-usable checkpoint thus completes the
    // sync the moment a flush succeeds, even if the donor has since crashed. (A no-op when none is owed,
    // or when a superblock root is in flight — `retry_install_flush` re-defers on that fence.)
    self.retry_install_flush(now, sb, blocks);
    // The controlled retry deadline fired: re-send the one outstanding `RequestBlock` and re-broadcast
    // `RequestSync` (the 100ms ARQ heartbeat — the lost-checkpoint retry, and dead-donor failover). The
    // active-donor-absent per-front re-solicit is bounded ON THE FETCH (`BlockFetch::resolicited_front`), so
    // a dropped re-solicit is retried here without a marker to clear.
    self.send_request_block(now, blocks);
    self.send_request_sync(now);
  }

  /// Service the bounded QUARANTINE probe against its wall-clock deadline and report whether it DISARMED.
  /// The probe bounds a crossing armed SOLELY by a quarantined member's higher-epoch evidence (the #65
  /// C-side / a possibly bit-flipped epoch scalar no donor can answer): left unbounded it would keep a
  /// speculative cross-epoch `sync` armed forever, wedging op-mint at the stale epoch. It is the
  /// epoch-plane twin of the view-plane catch-up revert.
  ///
  /// A no-op until the [`Endpoint::quarantine_probe_deadline`] is DUE. When due, the crossing is torn
  /// down UNLESS a donor has genuinely begun answering a crossing — the shield reads
  /// [`Self::crossing_answer_in_flight`] (a live `block_fetch` whose reply genuinely PRESENTS a crossing,
  /// its `crossing_answered` bit), NOT a bare `block_fetch.is_some()`: the cross-epoch solicit admits
  /// below-target same-config / empty replies that arm a NON-crossing fetch, which must NOT shield the
  /// probe (else a donor answering only with non-crossing replies would hold it open forever). It also
  /// shields on `pending_install` (a staged install — REQUIRED: the disarm clears `sync`, so disarming
  /// under a live `pending_install` would breach the `pending_install ⟹ sync` invariant; a staged install
  /// is transient and completes on its own root) and on `sm_reconstruct` (a post-install SM retry). Any of
  /// these REFRESHES the deadline forward so a genuine DAG transfer or two-write superblock persist
  /// spanning several windows survives; `install_sync` clears the probe on completion.
  ///
  /// Serviced ONCE per `handle_timeout`, at the TOP, BEFORE the status dispatch — so its expiry is on a
  /// wall-clock deadline INDEPENDENT of the `sync_solicit` cadence that a quarantined higher-epoch
  /// heartbeat keeps re-soliciting (a solicit-gated probe would slide forever under sustained heartbeats).
  /// On disarm it clears the crossing state (the sync, its intent, the remembered donor, the probe
  /// deadline, any block-fetch, and the solicit timer); the CALLER performs the status-appropriate safe
  /// landing (Recovering escalates to the next view change; Normal / ViewChange just drop the crossing).
  /// A RESOLVED-member hint would have cleared `quarantined_donor` (authoritative, unbounded), so this is
  /// inert unless the crossing is genuinely quarantine-only.
  pub(crate) fn advance_quarantine_probe(&mut self, now: Instant) -> bool {
    match self.quarantine_probe_deadline {
      Some(deadline) if deadline <= now => {}
      _ => return false, // not armed, or not yet due
    }
    // The probe bounds a speculative quarantine CROSSING only (a forced `require_cross_epoch` sync). If the
    // current sync is NOT a crossing — a genuine SAME-EPOCH local recovery (`require_cross_epoch == false`),
    // which a quarantined higher-epoch hint may have armed the probe on TOP of when
    // `enter_cross_epoch_peer_fetch` deferred to that in-progress recovery instead of arming a crossing —
    // the probe must NOT touch it. A checkpoint-exhausted local recovery holds `commit_min` AHEAD of the SM
    // (`sm_at < commit_min`, its Phase-2 restore not yet done), safe ONLY under the `Recovering` status
    // exemption of the `sm_at == commit_min` witness; tearing down its `sync` and escalating out of
    // `Recovering` (the disarm's Recovering landing) would let it reach `Normal` with an unrestored SM —
    // a silent committed-prefix loss. Clear only the dangling probe bookkeeping (so the timer does not spin
    // or breach the no-orphan-due invariant); leave the genuine recovery / sync intact, no escalation.
    if !self.sync.is_some_and(|s| s.require_cross_epoch) {
      self.quarantined_donor = None;
      self.quarantine_probe_deadline = None;
      self.quarantine_probe_progress_mark = 0;
      return false;
    }
    // A staged install or an owed SM-reconstruct is a VERIFIED, committed crossing near completion — it
    // finishes on its own durable root, NOT a donor — so shield unconditionally (this also keeps the
    // disarm from breaching the `pending_install ⟹ sync` invariant, since disarm clears `sync`).
    if self.pending_install.is_some() || self.sm_reconstruct_owed() {
      self.refresh_quarantine_probe(now);
      return false;
    }
    // A crossing FETCH shields only while it makes OBSERVABLE PROGRESS — a frontier block accepted since
    // the deadline was last set (`sync_fetch_progress` advanced past the mark). `crossing_answer_in_flight`
    // alone is a PERSISTENT bit: a donor that presented a crossing checkpoint then crash-stopped (or whose
    // DAG never arrives) keeps it set forever, so refreshing on it would renew the probe indefinitely with
    // no progress. Requiring a progress delta tears down a STALLED crossing while a genuinely slow transfer
    // (blocks still arriving) survives; `install_sync` clears the probe on completion.
    if self.crossing_answer_in_flight()
      && self.sync_fetch_progress != self.quarantine_probe_progress_mark
    {
      self.refresh_quarantine_probe(now);
      return false;
    }
    self.sync = None;
    self.cross_epoch_intent = None;
    self.quarantined_donor = None;
    self.quarantine_probe_deadline = None;
    self.quarantine_probe_progress_mark = 0;
    self.block_fetch = None;
    self.timers.sync_solicit = None;
    true
  }

  /// Abort the in-flight block-DAG fetch after a reachable-block-bound breach — a malformed / foreign /
  /// oversized source DAG exceeded `MAX_REACHABLE_BLOCKS` while draining a frontier. COUNT it
  /// (`dag_walks_capped`) for observability, then free the fetch; `sync` stays armed, so the solicit timer
  /// re-solicits and a fresh `SyncCheckpoint` re-pins the donor (the content-addressed blocks already
  /// written survive). Every bound-breach abort that drops a live `block_fetch` routes through here so the
  /// counter is honest — an otherwise-silent re-walk loop stays visible.
  pub(super) fn abort_oversized_block_fetch(&mut self) {
    self.dag_walks_capped += 1;
    self.block_fetch = None;
  }

  /// Send the block-fetch transfer's one outstanding pull: a `RequestBlock` for the next MISSING block
  /// across the COMBINED frontier (the SM checkpoint DAG, then the session-table DAG), addressed to the
  /// pinned donor, while Normal re-arming the solicit deadline (the stop-and-wait ARQ rides it); while
  /// Recovering the `recover_retry` cadence re-drives the pull instead (`sync_solicit` is not serviced
  /// there). No-op without an in-progress block-fetch + live sync, or when BOTH frontiers have drained
  /// (nothing missing — the next `BlockResponse` / completion installs). A bound breach in either DAG (a
  /// malformed/foreign DAG) aborts the block-fetch (dropped here) but keeps `sync` armed so the solicit
  /// timer re-solicits a fresh checkpoint.
  pub(super) fn send_request_block(&mut self, now: Instant, blocks: &mut dyn BlockStore) {
    if self.sync.is_none() {
      return;
    }
    // No live block-fetch (a `None` soliciting state) is inert by this match: the solicit half of the ARQ
    // still re-broadcasts `RequestSync` to fetch a fresh checkpoint. A live fetch whose front was just
    // GC-pruned re-requests that front here once more (harmless — the absent reply keeps the fetch live and
    // re-solicits a fresh checkpoint, which re-seeds the front).
    let Some(bf) = self.block_fetch.as_mut() else {
      return;
    };
    let donor = bf.donor;
    // Re-request the next missing block across BOTH frontiers (SM DAG first, then session DAG) — the
    // same combined drain `next_missing` the install path pumps. Pumping only `block_sync` here would
    // stop retransmitting once the SM DAG drains and the sole outstanding block is a SESSION block: a
    // dropped session `RequestBlock`/`BlockResponse` would then strand the install until a fresh
    // `SyncCheckpoint` re-pinned it. The combined frontier re-drives whichever DAG still owes a block.
    let next = match bf.next_missing(&*blocks) {
      Ok(next) => next,
      Err(_) => {
        // A malformed/foreign DAG exceeded the reachable-block bound: abort the transfer (counted, freed)
        // but keep `sync` armed — the solicit timer re-solicits and a fresh checkpoint re-pins.
        self.abort_oversized_block_fetch();
        return;
      }
    };
    if let Some(addr) = next {
      self.emit(Outgoing::new(
        Recipient::To(donor),
        Message::RequestBlock(addr),
      ));
    }
    if self.status.is_normal() {
      self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
    }
  }

  /// Abort an in-progress block-fetch a FORCED-sync target raise has invalidated: a forced target is
  /// LOAD-BEARING (`maybe_force_sync` cleared repair holes at/below it against a snapshot at/above
  /// it), so the strict `>= target` install gate stays — a block-fetch pinned BELOW the raised target
  /// can never install and would only burn round trips. Dropping it frees the in-flight frontier;
  /// `sync` stays armed, so the solicit timer re-solicits and a fresh pin at/above the new target
  /// starts over (the blocks already written survive in the store, re-discovered on the next sync). An
  /// ORDINARY sync's raise deliberately does NOT abort: its target is a freshness floor and the pinned
  /// block-fetch still installs below it (strict progress — see the carve-out in `handle_sync_checkpoint`);
  /// the next trigger then chases the newer checkpoint.
  ///
  /// A CROSS-EPOCH crossing fetch (`require_cross_epoch`) likewise does NOT abort on a raise: its
  /// target is only the SOLICIT floor, NOT a hard install bound (the VERIFIED successor membership is
  /// the crossing authority — `apply_sync`). A higher-epoch hint (possibly bogus, unreachably high)
  /// must not discard a legitimately-pinned below-hint crossing block-fetch that would still cross.
  pub(crate) fn drop_transfer_below_forced_target(&mut self) {
    let Some(s) = self.sync else {
      return;
    };
    if !s.forced || s.require_cross_epoch {
      return;
    }
    // A live block-fetch carries the pinned checkpoint to compare; drop it when it is pinned strictly
    // below the raised forced target (it can never install).
    if self
      .block_fetch
      .as_ref()
      .is_some_and(|bf| bf.checkpoint.checkpoint_op().get() < s.target.get())
    {
      self.block_fetch = None;
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
    // An SM-RECONSTRUCT obligation owed (`self.checkpoint_op == M` durably, but a CONTENT block of M's DAG
    // bit-rotted — the very fault that failed our own `sm.restore`) DECOUPLES from donation: it gates our
    // OWN apply/serve of un-reconstructed SM CONTENT, but does NOT make M's durable checkpoint ENVELOPE
    // un-servable. The envelope (`serve_sync_checkpoint` re-verifies it against `sb.state().checkpoint_id()`)
    // names M's `sm_root` + sessions and is byte-correct regardless of the faulted leaf; serving it lets a
    // PEER DEBTOR at M re-pin its own block-fetch to us, after which `on_request_block` answers its
    // `RequestBlock`s via the verified-read path (each CLEAN block we hold; an ABSENT response for the leaf
    // WE faulted on). So two debtors with COMPLEMENTARY corruption each serve the other the block it is
    // missing and BOTH reconstruct — the live quorum unwedges instead of both staying silent. We therefore
    // decline ONLY the ORDINARY (`>`) serve while owed (a fresh full-laggard is better served by a healthy
    // donor holding the whole DAG) and SERVE the equal-checkpoint repair (`m.recovery()`) below; the
    // per-block absence of our faulted leaf still routes that one block elsewhere, never exposing
    // un-reconstructed SM content.
    if self.sm_reconstruct_owed() && !m.recovery() {
      return;
    }
    // The requester is the authenticated `from` `Peer` — keyed and addressed by it, NOT the
    // self-claimed `m.replica()`, so a slot-shifted cross-epoch laggard's reply routes to where it
    // now lives. A `Peer::Replica(slot)` (a current member the sender binding admitted) must be a
    // configured slot; a `Peer::Member(id)` is a QUARANTINED attested member the sender binding
    // admitted for config-learning (its id does not resolve in our membership, which is exactly why
    // it is soliciting), served the same no-authority checkpoint read. A client / raw non-peer never
    // reaches here (the binding dropped it).
    match from {
      Peer::Replica(slot) if slot.get() < self.membership.node_count() => {}
      Peer::Member(_) => {}
      _ => return,
    }
    if self.checkpoint_op.get() == 0 {
      return; // nothing durable to serve — silent.
    }
    // An EQUAL-CHECKPOINT block-repair request is served at an EQUAL checkpoint too: the requester's OWN
    // copy of `checkpoint_op`'s block DAG is unusable (its snapshot read back corrupt while Recovering, or
    // a synced checkpoint's restore faulted on a bit-rotted block), so it needs ours even at the same
    // `checkpoint_op`. We are `Normal` (checked above) and our durable checkpoint ENVELOPE + the CLEAN
    // blocks of its DAG are trustworthy to serve even when WE OWE a reconstruct (the envelope is
    // body-independent of the one faulted leaf, and `on_request_block` serves each block via the verified
    // read — returning ABSENT for whatever leaf WE faulted on, so the requester fetches that one elsewhere).
    // An ordinary state-sync request keeps the strict `>`: never ship a megabyte snapshot for a no-op when
    // the requester is already at our checkpoint.
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
    // nonce — the completion then answers the LATEST solicitation — and issues NO second checkpoint
    // read. Without the dedupe, a buggy peer's solicit burst would stack N concurrent reads. (A
    // same-nonce burst — the timer-retransmit common case — is answered identically; a re-armed sync's
    // newer nonce is shipped without an extra round trip.)
    self.submit_or_refresh_serve(sb, from, m.nonce());
  }

  /// Record (or refresh) the single in-flight serve for `requester` (keyed by its `Peer` — a current
  /// member's slot or a quarantined attested member). If a serve-read is already outstanding, only
  /// the echoed nonce is refreshed in place (the completion answers the LATEST solicitation) — no
  /// second checkpoint read is issued; otherwise submit one read and insert the entry. The structural
  /// one-read-per-requester bound on `sync_serving`.
  fn submit_or_refresh_serve<B: Superblock>(&mut self, sb: &mut B, requester: Peer, nonce: u64) {
    if let Some(serving) = self.sync_serving.get_mut(&requester) {
      serving.nonce = nonce;
      return;
    }
    // Endpoint-side bound on QUARANTINED (`Peer::Member`) serves, INDEPENDENT of transport connection
    // lifetime: a `Peer::Replica` requester is bounded by `node_count` (a configured slot), but a rotating
    // set of distinct attested-but-unresolvable member ids would each insert a lingering serve-read and
    // grow `sync_serving` (its read queue + completion scan) without limit — falsifying the map's bound and
    // blocking `has_inflight_storage` quiescence. A NEW quarantined serve past [`QUARANTINE_SERVE_LIMIT`] is
    // REFUSED (no read submitted); it re-solicits and is served once an in-flight member serve completes and
    // frees a slot. This reserves the map's replica capacity independently of how many member conns exist.
    if requester.is_member()
      && self.sync_serving.keys().filter(|p| p.is_member()).count() >= QUARANTINE_SERVE_LIMIT
    {
      return;
    }
    let id = self.mint_op_id();
    sb.submit_read_checkpoint(id);
    self.sync_serving.insert(
      requester,
      SyncServe {
        read: id.get(),
        nonce,
      },
    );
  }

  /// Ship the answer for a completed serve-read (the read `on_request_sync` issued): the whole
  /// `SyncCheckpoint` envelope, which is now ALWAYS frame-sized (op + sessions + a 16-byte SM root —
  /// the SM bytes live in the block DAG, served separately by `RequestBlock`). Binds the shipped
  /// `checkpoint_id` to the shipped bytes via `checkpoint_id(cr.snapshot())`, then VERIFIES that
  /// id equals our DURABLE checkpoint id (`sb.state().checkpoint_id()`) — so a CORRUPT-but-
  /// parseable read (an in-model disk fault) cannot make us ship a self-consistent-but-wrong (id, bytes)
  /// pair the requester would accept and restore (it only re-checks `checkpoint_id(snapshot) == advertised
  /// id`); a mismatch DROPS the read (the serve path is then as strict as `recover`'s `id_ok` gate). Also
  /// re-checks status + view-durability + replica range at SHIP time (all may have changed between submit
  /// and completion): if we are no longer Normal, or our view is no longer durable, we drop the reply.
  pub(crate) fn serve_sync_checkpoint<B: Superblock>(&mut self, sb: &B, cr: crate::CheckpointRead) {
    // Serve entries are keyed by REQUESTER (one outstanding serve each); match this completion
    // against the recorded read `OpId`. No match ⇒ not a serve-read we issued (a stale/foreign
    // completion) — ignore. The scan is bounded by `replica_count` (<= 64).
    let Some((to, nonce)) = self
      .sync_serving
      .iter()
      .find(|(_, s)| s.read == cr.id().get())
      .map(|(&to, s)| (to, s.nonce))
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
    // A `Peer::Replica` requester must still be a configured slot (its membership could have shrunk
    // between submit and completion); a `Peer::Member` (quarantined attested member) has no slot and
    // is served the same no-authority envelope.
    match to {
      Peer::Replica(slot) if slot.get() < self.membership.node_count() => {}
      Peer::Member(_) => {}
      _ => return,
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
    // Ship the whole envelope as one `SyncCheckpoint`. It is always frame-sized now: the SM bytes
    // are no longer in the envelope (only a 16-byte SM root), and the carried membership is bounded by
    // the active member set — so the over-frame chunked announce/pull path is gone. The requester
    // verifies the envelope id, then walks the SM checkpoint DAG rooted at the decoded `sm_root`,
    // fetching the blocks it is missing via `RequestBlock`.
    self.emit(Outgoing::new(
      Recipient::To(to),
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
  }

  /// Serve a peer's `RequestBlock` for one content-addressed SM checkpoint block: reply with a
  /// `BlockResponse` carrying the block bytes if we hold the addressed block, or an ABSENT response if
  /// we do not. STATELESS and content-addressed: there is no donor cache, no cold-cache re-read, and no
  /// pin — the block IS its hash, so the requester verifies it on receipt and any member that holds it
  /// is an interchangeable donor. A block fetch carries no quorum authority (the block self-verifies),
  /// so any status / view is fine to serve from; the requester is the authenticated `from` (the ingress
  /// `sender_matches` bound it to a configured member), to whom the reply routes.
  pub(crate) fn on_request_block(
    &mut self,
    from: Peer,
    addr: crate::BlockAddress,
    blocks: &dyn BlockStore,
  ) {
    // The requester is `from` — a current member (`Peer::Replica`) or a quarantined attested member
    // (`Peer::Member`) fetching the SM DAG of the checkpoint it is installing; a client / raw non-peer
    // never reaches here (the binding dropped it).
    if from.is_client() {
      return;
    }
    // Serve the block only if its local bytes hash back to `addr`; a corrupt local block (bit-rot, a
    // misdirected write) is served as ABSENT rather than handed over to fail the requester's verify and
    // force a reject-and-retry. The requester then solicits a clean copy from another donor.
    let block = crate::block_store::read_verified_block(blocks, addr);
    self.emit(Outgoing::new(
      Recipient::To(from),
      Message::BlockResponse(crate::BlockResponse::new(addr, block)),
    ));
  }

  // ── State-sync: apply a verified SyncCheckpoint (the safety-critical core) ──

  /// Receive a `SyncCheckpoint`. Runs the §2.5 guard cascade (status; matching outstanding sync;
  /// nonce; advances past `target`, our head, and our checkpoint), then the LOAD-BEARING integrity
  /// gate — `checkpoint_id(snapshot) == checkpoint_id` — and only then begins fetching the SM
  /// checkpoint DAG (`apply_sync` once the DAG drains). A failed integrity check (a corrupt/forged
  /// snapshot) is REJECTED without touching the SM, leaving `sync` armed so the timer re-solicits.
  pub(crate) fn on_sync_checkpoint<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
    from: Peer,
    m: crate::SyncCheckpoint,
  ) {
    self.handle_sync_checkpoint(now, wal, sb, blocks, from, m);
  }

  /// The body of [`Self::on_sync_checkpoint`]. Runs the §2.5 guard cascade + integrity gate, then —
  /// instead of installing inline — begins fetching the SM checkpoint DAG rooted at the envelope's
  /// `sm_root` via [`Self::begin_block_sync`]: if the laggard already holds every reachable block
  /// (an unchanged checkpoint), it installs immediately; otherwise it arms a block-fetch and pulls the
  /// missing blocks, installing on drain. The freshness gates here are the FLOOR; the block-fetch is
  /// the transfer underneath them (a target raised mid-fetch aborts a FORCED pin via
  /// [`Self::drop_transfer_below_forced_target`], and keeps an ORDINARY pin — it installs below the
  /// raised floor as strict progress, the next `Commit` chasing the newer checkpoint).
  fn handle_sync_checkpoint<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
    from: Peer,
    m: crate::SyncCheckpoint,
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
    // SM-RECONSTRUCT obligation owed (a post-root restore faulted; `self.checkpoint_op == M`): a fresh
    // reply AT M re-pulls M's DAG from THIS donor — donor FAILOVER, the path that re-arms the obligation's
    // block-fetch when its pinned donor died (the ordinary `<= self.checkpoint_op == M` reject just below
    // would otherwise drop it, stranding the obligation on a dead donor). A reply ABOVE M falls through to
    // supersede the obligation forward via `begin_block_sync`; a reply BELOW M is dropped below as usual.
    //
    // GATE on `pending_install.is_none()`: while the obligation is owed, a strictly-newer install may be
    // RETAINED as `pending_install` (a superseding sync staged, then its flush faulted — `pending_checkpoint`
    // is `None`, so the in-flight-write defer above does NOT catch it). That newer install subsumes M and is
    // retried LOCALLY (`retry_install_flush`); running the same-M reconstruct here would, on success, clear
    // `sm_reconstruct` + `sync` (via `retry_sm_reconstruct` / `complete_state_sync`) and ORPHAN the retained
    // `pending_install` — tripping `pending_install ⟹ sync` (debug) or wedging the apply gate with no sync
    // left to drive the install (release). The equal-M reply is stale below the staged newer install, so drop
    // it here (it falls through to the monotone `<= checkpoint_op` reject); a view transition that later
    // cancels the retained install clears `pending_install`, and this same-M path resumes.
    if self.sm_reconstruct_owed()
      && self.pending_install.is_none()
      && m.checkpoint_op() == self.checkpoint_op
    {
      // Trust the bytes only if they hash to the advertised id (the same integrity gate the ordinary path
      // applies below) before re-pinning the fetch to this donor's `sm_root`.
      if crate::checkpoint_id(m.snapshot()) != m.checkpoint_id() {
        return;
      }
      self.refetch_sm_reconstruct(now, wal, sb, blocks, from, &m);
      return;
    }
    if m.checkpoint_op().get() < s.target.get() && !s.require_cross_epoch {
      // Does not advance us past what we know the cluster has committed — ignore. ONE carve-out:
      //
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
    //
    // EXCEPTION — an SM-RECONSTRUCT obligation must NEVER be torn down here: M's durable root is already
    // written and `self.checkpoint_op == M`, so a fresh reply is either `< M` (already dropped above) or a
    // strictly-newer `> M` that legitimately supersedes the obligation FORWARD. A node that became a Normal
    // primary through a view change while the obligation was owed must complete it (or be superseded) — let
    // this `> M` reply fall through to `begin_block_sync` rather than abdicate-and-drop.
    if !s.require_cross_epoch && !self.sm_reconstruct_owed() && self.abdicate_if_primary(now) {
      self.sync = None;
      self.block_fetch = None;
      // The ingress gate above (`pending_sb`/`pending_checkpoint` is_some → return) means any live
      // `pending_install` here is a RETAINED-but-not-staged install (a flush-faulted re-persist still
      // owed) — never a staged one. Tearing the sync down drops it too; nothing destructive ran, so the
      // drained blocks survive in the store for a fresh sync, exactly as a view-change reset.
      self.pending_install = None;
      self.timers.sync_solicit = None;
      return;
    }
    self.begin_block_sync(now, sb, blocks, from, m);
  }

  /// Carry the re-solicit latch ([`BlockFetch::resolicited_front`]) forward across a re-pin that
  /// rebuilds the fetch onto the SAME content-addressed DAG. The active-donor-absent re-solicit fires at
  /// most once per pruned front, but each arming site REPLACES `self.block_fetch` wholesale — so absent
  /// the carry, a DUPLICATE/DELAYED `SyncCheckpoint` naming the SAME `(sm_root, sessions_root)` (a re-pin
  /// that does not advance the front) would rebuild with a fresh `None` latch and re-open one re-solicit
  /// per such duplicate. A flood of same-root checkpoints, each trailed by a duplicate absent, would then
  /// drive one re-solicit per delivered duplicate — bounded by the adversary's delivery rate, not by
  /// round-trips.
  ///
  /// Both roots are content addresses: equal roots name the IDENTICAL DAG, so the rebuilt fetch re-walks
  /// the same blocks (already-fetched ones re-discovered locally from the store) and re-derives the same
  /// active front. The carried latch therefore still names the SAME pruned front the prior fetch
  /// re-solicited, and skipping the repeat is exactly correct. Given the new fetch's roots and the prior
  /// `block_fetch`, return the latch to seed the new fetch with: the prior fetch's `resolicited_front`
  /// when BOTH roots match (a same-root re-pin), else `None`. A re-pin to a DIFFERENT root is a genuine
  /// new pin whose first absent must legitimately re-solicit, so it resets to `None` (never suppress a
  /// real re-pin's re-solicit — that would strand the laggard).
  pub(crate) fn carry_resolicit_latch(
    &self,
    new_sm_root: BlockAddress,
    new_sessions_root: BlockAddress,
  ) -> Option<BlockAddress> {
    let prev = self.block_fetch.as_ref()?;
    if prev.sm_root == new_sm_root && prev.sessions_root == new_sessions_root {
      prev.resolicited_front
    } else {
      None
    }
  }

  /// Bridge the verified `SyncCheckpoint` to the SM-checkpoint-DAG block fetch. The envelope's SM
  /// state is no longer carried inline — only a 16-byte `sm_root` — so before `apply_sync` can restore
  /// the SM, the laggard must hold every block reachable from `sm_root`. Decode the root, then:
  ///
  /// - If the store ALREADY HOLDS the whole DAG (an unchanged checkpoint, or a re-delivered one), the
  ///   block-fetch completes immediately and we install via [`Self::apply_sync`].
  /// - Otherwise arm a [`BlockFetch`] (a `BlockSync` frontier seeded at `sm_root` + the pinned donor)
  ///   and send the first `RequestBlock`. The transfer drains over the `BlockResponse`/ARQ cadence;
  ///   when it does, [`Self::on_block_response`] replays this exact message into `apply_sync`.
  ///
  /// The pinned donor is the message's AUTHENTICATED sender slot (`from.as_replica()` — the slot the
  /// sender-binding check established this laggard can route to), NOT the donor's SELF-CLAIMED
  /// [`SyncCheckpoint::replica`]. The two agree on the same-epoch path; they DIVERGE for a cross-epoch
  /// donor whose slot SHIFTED across a reconfiguration, where `replica()` is the donor's successor-epoch
  /// slot (un-routeable in the OLD-epoch laggard's membership) while `from` is the slot the laggard
  /// actually reaches. Pinning to `from` is what makes the follow-up `RequestBlock` reach the real donor;
  /// `replica()` remains the self-claimed identity / config payload field only. A non-routeable `from` (a
  /// client peer, never a checkpoint sender) or a malformed envelope (no decodable root) is dropped
  /// (nothing staged; `sync` stays armed so the solicit timer re-fetches). `next_request` is pumped
  /// immediately so a root the store already holds reports complete on the first pump (not only after a
  /// reply).
  fn begin_block_sync<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
    from: Peer,
    m: crate::SyncCheckpoint,
  ) {
    // Decode the envelope to extract BOTH content-addressed DAG roots. The bytes already passed the
    // `checkpoint_id` integrity gate, but a malformed/truncated envelope must not panic — reject it as a
    // fault and leave `sync` armed so the solicit timer re-fetches from another peer.
    let Some((_, sm_root, sessions_root)) = Self::decode_checkpoint(m.snapshot()) else {
      return;
    };
    // A reply reaching here while an SM-reconstruct obligation is owed is, by the ingress gates, a
    // STRICTLY-NEWER checkpoint (`> self.checkpoint_op == M`): it SUPERSEDES the obligation forward — its
    // own install reconstructs the SM to the newer point, subsuming M. The obligation is KEPT owed through
    // this fetch AND through the staged-but-pre-root install: it is dropped only when `install_sync`
    // actually installs the replacement (root durable, non-cancellable). Clearing it here (as the code
    // previously did) opened a window where the SM is still pre-M yet NEITHER `sm_reconstruct` NOR
    // `pending_install` gates the apply loop — a Commit heartbeat could then apply held-tail ops over the
    // stale SM (divergence) — and if this fetch STALLS, or `apply_sync` REJECTS the reply (a same-config /
    // empty-membership reply admitted here under `require_cross_epoch`), or a view transition CANCELS the
    // pre-root install, the obligation must survive to keep reconstructing M rather than vanish.
    // The drain (`on_block_response`) routes by comparing the drained fetch's checkpoint op to
    // `self.checkpoint_op`: a SAME-M fetch is the SM-content retry, a NEWER M' re-stages via `apply_sync`.
    // A RETAINED-but-not-staged install (a prior verified install whose flush faulted, still owed as
    // `pending_install` with no in-flight checkpoint — the ingress gate above rules out a staged one) is LEFT
    // INTACT here: it is the local flush-retry source, a LIVE GC root (`gc_blocks` marks its DAG), AND — for a
    // verified crossing — the shield that holds `cross_epoch_intent` against same-epoch authority. It must
    // survive until a REPLACEMENT is actually staged, never on entry to a fresh fetch: this fetch may yet
    // STALL or its reply be REJECTED by `apply_sync` (a stale same-config / empty-membership reply admitted
    // here under `require_cross_epoch` is only rejected there), and clearing now would leave nothing to
    // re-flush, drop the owed DAG's GC mark, and reopen a crossing strand before any replacement exists. The
    // owed install is dropped ONLY when `apply_sync` stages a fresh `PendingInstall` (which atomically
    // REPLACES it) or a teardown (view transition / abdicate / stale-below) cancels it.
    // Pin the donor to the AUTHENTICATED sender slot the binding check established, not the donor's
    // self-claimed (possibly shifted) `replica()`. The donor `Peer` is a current member
    // (`Peer::Replica`) or a quarantined attested member (`Peer::Member`); a client cannot have
    // answered this sync, so drop defensively (keeping `sync` armed for the re-solicit) rather than
    // fabricate a target.
    if from.is_client() {
      return;
    }
    // PROVENANCE-AWARE replacement: a reply that does NOT present a crossing must never DOWNGRADE a live
    // crossing fetch. The cross-epoch solicit admits below-target same-config / empty-membership replies
    // onto the fetch path (they may arm a fetch when none exists), and `send_request_sync` solicits both
    // old-config `Backups` AND the quarantined donor — so once the quarantined donor has presented a
    // genuine crossing and its block pull is outstanding, a LATER same-config reply from an old-config
    // donor would otherwise evict that crossing fetch. Its crossing block then lands OFF-FRONTIER against
    // the non-crossing fetch and can never install the successor; once the old DAG is cached each old reply
    // immediately re-clears the crossing fetch, and the healthy quarantined primary's next heartbeat only
    // re-arms the same losing race — stranding the member in an endless disarm/rearm cycle under honest
    // timing. Keep the crossing fetch (its ARQ re-drives its own pull); ignore the non-crossing reply.
    // A crossing reply (fresher or duplicate crossing metadata) still supersedes normally below.
    if self
      .block_fetch
      .as_ref()
      .is_some_and(|bf| bf.crossing_answered)
      && !self.checkpoint_presents_crossing(&m)
    {
      return;
    }
    let donor = from;
    // Seed both frontiers (SM + session) and pump them once so a DAG the store already holds reports
    // complete immediately (a root the store holds advances to drained only after the first
    // `next_request`, never on `new` alone). A bound breach (a foreign/malformed DAG) in either drops the
    // fetch and keeps `sync` armed.
    let mut bf = BlockFetch {
      checkpoint: m.clone(),
      sm_root,
      sessions_root,
      donor,
      block_sync: super::block_sync::BlockSync::new(sm_root),
      session_sync: super::block_sync::BlockSync::new(sessions_root),
      // Record whether this reply genuinely PRESENTS a crossing (foreign config + non-empty membership),
      // computed before `apply_sync` verifies the membership hash-chain. A same-config / empty-membership
      // reply the cross-epoch solicit admitted below target arms a NON-crossing fetch, which must not shield
      // a stale `cross_epoch_intent` — the crossing-answer predicates read this bit, not `block_fetch.is_some()`.
      crossing_answered: self.checkpoint_presents_crossing(&m),
      // Carry the re-solicit latch forward iff this re-pin names the SAME content-addressed DAG: a
      // DUPLICATE same-root checkpoint re-walks the same front, so it inherits the latch and re-solicits no
      // more. A re-pin to a DIFFERENT root resets to `None`, so the new pin's first absent legitimately
      // re-solicits.
      resolicited_front: self.carry_resolicit_latch(sm_root, sessions_root),
    };
    let next = match bf.next_missing(&*blocks) {
      Ok(next) => next,
      // The fresh checkpoint's DAG breached the reachable-block bound: count it and drop the new (local,
      // not-yet-installed) `bf`; any prior fetch is left to its own ARQ.
      Err(_) => {
        self.dag_walks_capped += 1;
        return;
      }
    };
    // This fresh `SyncCheckpoint` re-pins to a LIVE address + routeable donor, re-seeding the frontier's
    // front. Both arms below REPLACE the whole `block_fetch` field, so a prior fetch whose front an
    // active-donor absent left GC-pruned is superseded by construction. The re-solicit latch is CARRIED
    // FORWARD across a same-root re-pin (above), so a duplicate same-root checkpoint cannot re-arm it; only
    // a genuine NEW root re-opens one re-solicit (no separate clear; the early returns above — a malformed
    // envelope / non-routeable donor — leave the existing fetch untouched, so the solicit timer keeps
    // re-soliciting until a clean checkpoint arrives).
    match next {
      None => {
        // BOTH DAGs are already present — install now (no fetch needed). Drop any prior fetch (a
        // superseding checkpoint replaced it) before staging.
        self.block_fetch = None;
        self.apply_sync(now, sb, blocks, donor, &m);
      }
      Some(addr) => {
        // Arm the block-fetch and send the first pull. Supersedes any prior fetch (a strictly newer
        // checkpoint passed the gates above), abandoning its frontier; the already-written blocks survive
        // in the store and are re-discovered if still reachable.
        self.block_fetch = Some(bf);
        self.emit(Outgoing::new(
          Recipient::To(donor),
          Message::RequestBlock(addr),
        ));
        self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
      }
    }
  }

  /// Receive a `BlockResponse` — one fetched block of the SM checkpoint DAG the in-progress block-fetch
  /// is pulling. Feeds the bytes into the [`BlockSync`] frontier (which VERIFIES the block hashes to the
  /// requested address, writes it to the store, and enqueues its not-yet-held children), then either
  /// sends the next `RequestBlock` or — when the frontier drains — replays the pinned `SyncCheckpoint`
  /// into the install path ([`Self::apply_sync`] for a Normal receiver, `on_recover_sync_checkpoint` for
  /// the recovery peer-fetch). An ABSENT response, a hash mismatch, or a non-frontier address is inert:
  /// the frontier's next-missing is re-requested. A bound breach (a malformed/foreign DAG) aborts the
  /// block-fetch but keeps `sync` armed so the solicit timer re-solicits a fresh checkpoint.
  pub(crate) fn on_block_response<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
    from: Peer,
    m: crate::BlockResponse,
  ) {
    let recovering = self.status.is_recovering() && self.awaiting_peer_checkpoint();
    if !self.status.is_normal() && !recovering {
      return;
    }
    if self.sync.is_none() {
      return; // no sync outstanding — a late/foreign block response is inert.
    }
    // Whether this response carried a block. An ABSENT response means the pinned donor does NOT hold the
    // requested block — it checkpointed forward and GC pruned the (now-superseded) block this frontier is
    // pinned to — and drives the re-pin below (re-solicit a fresh checkpoint the donors still hold) rather
    // than the ordinary next-block pull.
    let present = m.block().is_some();
    // Defer while a superblock root is in flight (the same single-writer fence the rest of the install
    // path observes): the staged re-persist must not begin while a root is outstanding. The block-fetch
    // stays pinned; the solicit timer / ARQ re-drives the pull once the root lands.
    if self.pending_sb.is_some() || self.pending_checkpoint.is_some() {
      return;
    }
    let Some(bf) = self.block_fetch.as_mut() else {
      return; // no live block-fetch (soliciting / already drained) — ignore.
    };
    // Whether THIS fetch is draining a genuine CROSSING reply — only crossing progress counts toward the
    // quarantine probe. A non-crossing (below-target same-config / empty-membership) fetch the cross-epoch
    // solicit admitted accepts blocks too, but that progress is NOT the crossing's: were it counted, an
    // old-config donor could feed one non-crossing block, then a quarantined donor re-pins crossing
    // metadata with NO block, and the stale delta would refresh a stalled crossing forever.
    let crossing = bf.crossing_answered;
    // Feed a PRESENT block into BOTH frontiers (an absent response carries nothing to write). The block
    // belongs to exactly one DAG — the owning frontier `Accepts` it; the other reports `NonFrontier`
    // (the address is not the address it is waiting on), which is inert by construction. A hash mismatch
    // or a bound breach is surfaced by `on_block`: a mismatch leaves the block re-requestable; a bound
    // breach (in either DAG) aborts the fetch.
    // Whether this response ADVANCED a frontier — a block was accepted into the SM or session DAG. The
    // bounded quarantine probe reads `sync_fetch_progress` as its "the crossing is genuinely progressing"
    // signal, so it is bumped (once) below — for a CROSSING fetch only — after the `bf` borrow releases.
    let mut accepted = false;
    if let Some(bytes) = m.block() {
      let bytes = Bytes::copy_from_slice(bytes);
      let sm_outcome = bf
        .block_sync
        .on_block(m.addr(), bytes.clone(), &mut *blocks);
      let session_outcome = bf.session_sync.on_block(m.addr(), bytes, &mut *blocks);
      for outcome in [sm_outcome, session_outcome] {
        match outcome {
          Ok(super::block_sync::BlockOutcome::Accepted) => accepted = true,
          Ok(super::block_sync::BlockOutcome::NonFrontier) => {
            // The block is not this frontier's outstanding address (the OTHER DAG owns it, or it is a
            // delayed/superseded response): inert by construction. Re-drive the pull below.
          }
          Err(super::block_sync::BlockSyncError::AddressMismatch { .. }) => {
            // A corrupt/substituted block: not written, still re-requestable. Re-drive the pull below.
          }
          Err(super::block_sync::BlockSyncError::TooManyBlocks) => {
            // A malformed/foreign DAG: abort the transfer (counted), keep `sync` armed (solicit re-fetches).
            self.abort_oversized_block_fetch();
            return;
          }
        }
      }
    }
    // Re-pump BOTH frontiers: both drained ⇒ install; otherwise request the next missing block (SM DAG
    // first, then session DAG) from the pinned donor (dead-donor failover is the `sync_solicit` ARQ's
    // job: it re-broadcasts `RequestSync`, and a fresh `SyncCheckpoint` re-pins the donor — the
    // content-addressed blocks already written survive).
    let next = match bf.next_missing(&*blocks) {
      Ok(next) => next,
      Err(_) => {
        // Bound breach while draining: abort the transfer (counted, freed); the solicit ARQ re-pins.
        self.abort_oversized_block_fetch();
        return;
      }
    };
    // The `bf` borrow has released: record CROSSING frontier progress for the bounded probe. Only a block
    // accepted into a genuine crossing fetch (`crossing`) counts — a non-crossing fetch's progress must not
    // refresh a later crossing probe. A stalled crossing (a donor that presented a crossing checkpoint then
    // went silent) never reaches here with `accepted && crossing`, so its deadline is not refreshed and it
    // disarms; a genuinely advancing crossing transfer bumps this and the probe survives.
    if accepted && crossing {
      self.sync_fetch_progress = self.sync_fetch_progress.wrapping_add(1);
    }
    match next {
      Some(addr) if present => {
        // Genuine transfer PROGRESS: re-request the next missing block from the pinned donor and re-arm
        // the ARQ deadline. The pinned checkpoint is still serviceable, so stay on it.
        let donor = bf.donor;
        self.emit(Outgoing::new(
          Recipient::To(donor),
          Message::RequestBlock(addr),
        ));
        self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
      }
      Some(active) => {
        // ABSENT reply: the pinned donor does NOT hold the requested block — it checkpointed forward and
        // GC pruned this now-superseded block, so re-requesting it from the same donor can never succeed.
        // Two conditions gate the re-solicit below: the absent response must be for the CURRENTLY
        // OUTSTANDING frontier address (`m.addr() == active`) and from the PINNED DONOR (`from ==
        // bf.donor`). A response for an already-fetched or off-frontier address, or from a non-donor, is
        // INERT — leave the fetch pinned and let the ARQ re-drive the outstanding pull at the next solicit
        // deadline. This prevents a stale out-of-order absent (or a spoofed absent from a non-donor) from
        // triggering a re-solicit.
        let donor = bf.donor;
        if m.addr() != active || from != donor {
          return;
        }
        // KEEP THE FETCH LIVE and re-solicit a fresh `SyncCheckpoint` immediately. The fetch is NOT
        // dropped: a donor's reply names its CURRENT checkpoint (whose blocks it still holds), and the
        // fresh `SyncCheckpoint` re-seeds the frontier via `begin_block_sync` onto an un-pruned root —
        // re-discovering every content-addressed block already fetched locally and re-pulling only the new
        // generation's pruned-tail delta. Re-soliciting per round trip (rather than waiting for the
        // `sync_solicit` deadline) is load-bearing for liveness: while the cluster checkpoints faster than
        // one `SYNC_SOLICIT` period it prunes a new generation every couple of periods, so a deadline-paced
        // re-pin lets the target advance (and GC) many generations between re-pins and the laggard never
        // converges; re-pinning the instant the front becomes pruned tracks the moving target at network
        // speed.
        //
        // BOUND the re-pin window ON THE FETCH. The live front alone does NOT dedup until the fresh
        // checkpoint wins the race and `begin_block_sync` re-seeds it — in the window BETWEEN this absent and
        // that answer, every DUPLICATE or DELAYED absent for the same front re-satisfies the gate above and
        // would re-broadcast `RequestSync`, turning one pruned block into an unbounded broadcast/read storm.
        // `resolicited_front` records the front THIS fetch already re-solicited for and SKIPS a repeat: at
        // most ONE re-solicit fires per front. It has no mid-life clear — it is born with the fetch and dies
        // with it, and a fresh `BlockFetch` replacing `self.block_fetch` CARRIES it forward across a same-root
        // re-pin (`Endpoint::carry_resolicit_latch`). So a DUPLICATE same-root checkpoint that does not advance
        // the front rebuilds the fetch INHERITING this latch and re-solicits no more; only a genuine NEW root
        // re-opens one re-solicit. Total re-solicits are O(distinct roots) = O(round-trips), even under an
        // unbounded same-root flood. The single re-solicit per new pruned front is preserved, so convergence
        // is unchanged.
        if bf.resolicited_front == Some(active) {
          return; // this fetch has already re-solicited for this exact pruned front.
        }
        bf.resolicited_front = Some(active);
        // A CROSS-EPOCH crossing fetch is handled identically: the live `block_fetch` carries its recorded
        // `crossing_answered` bit, so `crossing_answer_in_flight` still reads the crossing as answered across
        // the re-pin window — a same-epoch trigger cannot wrongly downgrade a genuine in-progress crossing.
        self.send_request_sync(now);
      }
      None => {
        // The DAG is fully present. TWO drain destinations:
        //
        // - An SM-RECONSTRUCT obligation is owed (a post-root restore faulted; M's root is already durable
        //   and `self.checkpoint_op == M`): RETRY `sm.restore` DIRECTLY against the unchanged M pointer — do
        //   NOT re-stage (re-writing M's root would be redundant, and `apply_sync` would reject M anyway as
        //   `<= self.checkpoint_op`). On success the obligation clears + the sync completes; on a still-bad
        //   block the obligation re-arms and re-pulls.
        // - Otherwise this is the ORDINARY first drain of a staged sync: replay the pinned checkpoint into
        //   the install path. The recovery replay re-derives a routeable `from` from the donor the
        //   block-fetch was pinned to (the slot the original sender-binding check established): if it has to
        //   re-arm a peer-fetch it must address the SAME routeable donor, never the checkpoint's self-claimed
        //   (possibly shifted) `replica()`.
        // Route by comparing the drained fetch's checkpoint op to `self.checkpoint_op` (`== M` while an
        // obligation is owed), NOT by the bare owed flag: with the obligation now KEPT across a superseding
        // fetch, the owed flag alone can no longer distinguish the SM-content retry (a fetch still pinned to
        // M) from a strictly-newer M' fetch that must re-stage. A SAME-M fetch reconstructs the SM directly
        // against M's unchanged pointer; a NEWER M' falls through to `apply_sync` (which stages the M'
        // install and atomically clears the M obligation).
        let same_checkpoint_retry = self.sm_reconstruct_owed()
          && self
            .block_fetch
            .as_ref()
            .is_some_and(|bf| bf.checkpoint.checkpoint_op() == self.checkpoint_op);
        if same_checkpoint_retry {
          self.block_fetch = None;
          if self.retry_sm_reconstruct(now, wal, sb, blocks) {
            // The SM reconstructed + the sync completed → a staged epoch swap that was waiting for a free
            // superblock now gets its slot (the same re-trigger `on_sb_done`'s tail makes).
            self.maybe_swap_epoch(sb);
          }
          return;
        }
        let bf = self
          .block_fetch
          .take()
          .expect("just held a live block-fetch");
        let donor = bf.donor;
        let checkpoint = bf.checkpoint;
        if recovering {
          self.on_recover_sync_checkpoint(now, wal, sb, blocks, donor, checkpoint);
        } else {
          self.apply_sync(now, sb, blocks, donor, &checkpoint);
        }
      }
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
    blocks: &mut dyn BlockStore,
    donor: Peer,
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
      // return is clean.
      //
      // A CROSS-EPOCH crossing fetch (`require_cross_epoch`) is the ONE forced sync that must NOT be
      // CANCELLED here: its target is a HIGHER-epoch checkpoint at/above the reconfigure op `N`, strictly
      // above this laggard's applied frontier (`commit_min < N`), so the crossing is NEVER satisfied by a
      // below-`commit_min` reply. Such a reply is a stale SAME-config checkpoint a donor served from its own
      // below-`N` point — IRRELEVANT to the crossing (on the block-fetch path it can drain in here
      // immediately, since the laggard already holds its own below-`N` DAG). IGNORE it but KEEP the crossing
      // armed so the solicit timer re-fetches until a verified successor at/above `N` lands — mirroring the
      // `require_cross_epoch` carve-outs the `on_sync_checkpoint` freshness gates make. Cancelling here
      // would tear the crossing down on a stale reply and strand the laggard at the old epoch.
      //
      // For a NON-crossing forced sync, cancel the stale sync + its solicit timer (the target is already
      // satisfied — its own commit-frontier `> sync.target`, so there is nothing left to fetch); the
      // install's own `>= commit_min` debug-assert + the monotone `set_commit_min` choke remain the
      // backstop a genuine commit_min rewind would still trip. The LEGITIMATE forced sync (`commit_min <=
      // checkpoint_op <= self.op`) falls through and STAGEs normally.
      if checkpoint_op.get() < self.commit_min.get() {
        if !self.sync.is_some_and(|s| s.require_cross_epoch) {
          self.sync = None;
          self.block_fetch = None;
          // Reached only with `pending_checkpoint`/`pending_sb` None (the ingress gate), so any live
          // `pending_install` is a RETAINED-but-not-staged install owed by a prior flush-faulted attempt —
          // drop it with the torn-down sync (nothing destructive ran; the drained blocks survive).
          self.pending_install = None;
          self.timers.sync_solicit = None;
        }
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
    // timer re-fetches from another peer. We have mutated nothing yet, so an early return is clean. The
    // SM/session bytes are NOT in the envelope — only the two DAG roots, whose blocks the block-fetch
    // already drained.
    let Some((bound_op, sm_root, sessions_root)) = Self::decode_checkpoint(m.snapshot()) else {
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
    // decision is stable until install.
    //
    // OVERRIDDEN below for a CROSSING install (`successor.is_some()`): a cross-epoch crossing snapshot is
    // authoritative for E+1, so EVERY op the laggard holds above the crossing checkpoint must be discarded
    // — they were appended in the OLD epoch's lineage (the cluster swapped at `N <= M == checkpoint_op`) and
    // are NOT valid E+1 ops. The held-tail preservation argument ("the cluster may have committed them off
    // our vote") holds only for a SAME-epoch forced sync; a NORMAL-status speculative laggard
    // ([`Self::cross_epoch_speculative_sync`]) may have appended such an old-epoch tail above `M` while the
    // sync was armed, so crossing MUST force `held_tail = false`.
    let mut held_tail = checkpoint_op.get() < self.op.get();
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
          // The crossing must be strictly FORWARD — a successor at or below our current epoch is not a
          // forward crossing (stage nothing; `sync` stays armed so the solicit timer re-fetches). There
          // is NO multi-epoch distance bound: the successor membership is WHOLESALE content-verified
          // (`to_membership_verified` recomputed `hash(membership, prev_config_id) == config_id` above),
          // which self-certifies the installed configuration at ANY distance — the verification proves the
          // membership the requester installs, and never depends on the requester's OWN lineage. A deep
          // skip (E0→E3) is therefore as sound to install as a single step: the content check is identical,
          // and canonical VR / TigerBeetle re-admit a far-behind replica by WHOLESALE state transfer of the
          // verified current configuration, not by walking an intermediate E1←E2 chain the receiver was
          // never going to verify anyway. The post-crossing lineage ring then holds `[verified_prev,
          // own_prior]` (below), which on a skip deeper than [`LINEAGE_RING`] omits the intermediate
          // ancestors — a BOUNDED LIVENESS nicety (the ring only widens AGNOSTIC recent-ancestor admission;
          // a skipped-over intermediate config's agnostic solicitation is simply not admitted, and
          // state-sync — the very path a stranded laggard uses — is admitted on member identity regardless,
          // see `sender_admits_solicitation`), never a safety property. Removing the bound is what lets a
          // member offline across more than two legal changes rejoin instead of stranding forever on a
          // "closer donor" the protocol does not preserve.
          if successor.epoch() <= self.membership.epoch() {
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
    // Assemble the verified install — every field the durable re-persist + the deferred `install_sync`
    // need. Split the verified crossing pair into the two `PendingInstall` fields: the successor
    // membership and the VERIFIED predecessor `config_id` it chains from (the value that satisfied the
    // hash-chain). The install + its durable root stamp the lineage from THIS verified chain, never
    // re-deriving it from the stale current config — so a re-served crossing recomputes the SAME
    // `config_id` a fresh laggard expects.
    let (successor, successor_prev_config_id) = match successor {
      Some((membership, prev)) => (Some(membership), Some(prev)),
      None => (None, None),
    };
    let install = PendingInstall {
      checkpoint_op,
      sessions_root,
      sm_root,
      held_tail,
      successor,
      successor_prev_config_id,
      // Carry the verified envelope + its authenticated donor so a post-root SM-restore fault can re-fetch
      // THIS checkpoint's bit-rotted block and retry the restore against the same DAG (the fields flow into
      // the `SmReconstruct` obligation `install_sync` raises on a restore fault — see `PendingInstall`).
      checkpoint: m.clone(),
      donor,
    };
    // RETAIN the verified install as a staged-but-owed `pending_install` BEFORE the durability barrier.
    // Nothing destructive has run (no SM restore, no `commit_min`/`op` advance, no WAL prune); the install
    // is OWED until both its flush AND its `submit_write_checkpoint` succeed (see `flush_and_stage_install`).
    // A flush fault simply leaves it OWED — re-attempted locally by the sync solicit cadence with no fresh
    // donor reply — and a view change in this window cancels it cleanly exactly like any `pending_install`.
    // Because `pending_install` is a LIVE GC root (`gc_blocks` marks both its DAG roots), the drained blocks
    // survive any intervening checkpoint GC while the flush is owed.
    //
    // KEEP any owed SM-reconstruct obligation for an OLDER checkpoint M through this staging — do NOT clear
    // it here. The pre-root `pending_install` is CANCELLABLE: a view transition (`reset_for_view_transition`)
    // drops it before its root lands. Clearing `sm_reconstruct` at stage time would then leave the SM behind
    // the durable `checkpoint_op == M` with NEITHER gate set (`pending_install` cancelled, `sm_reconstruct`
    // gone), so a Commit heartbeat could `advance_commit` / `state_machine()` over stale pre-M content —
    // committed-state divergence. The apply gate (`pending_install.is_some() || sm_reconstruct_owed()`) must
    // stay closed until the SM ACTUALLY holds this checkpoint's content, which only `install_sync` (running
    // when the root is durable, non-cancellable) establishes: on a clean restore it clears the obligation
    // (the SM now reflects `>= M`), on a restore fault it re-raises it for THIS checkpoint — either way
    // consistent with the then-advanced `checkpoint_op`. `reset_for_view_transition` KEEPS `sm_reconstruct`
    // (and its `sync`) across a pre-root cancel, so a fresh reconstruct is driven. Both gates coexisting here
    // is invariant-clean: `checkpoint_op` is still M until `install_sync` advances it, so `sm_reconstruct.op
    // == checkpoint_op` holds, and M's DAG stays GC-rooted by the durable checkpoint root regardless.
    self.pending_install = Some(install);
    self.flush_and_stage_install(now, sb, blocks);
  }

  /// DURABILITY BARRIER + STAGE for the OWED `pending_install`: flush the synced checkpoint's blocks (BOTH
  /// DAGs were drained into the local store before [`Self::apply_sync`] retained the install) durable, then
  /// stage the two-write re-persist that carries the synced checkpoint to durability — so a crash recovers
  /// to the synced point only once the root lands, never to a checkpoint naming un-flushed blocks. Step 1
  /// writes the snapshot under our own superblock; step 2 (in [`Self::on_sb_done`]) writes the new
  /// `VsrState` root naming it, which then drives [`Self::install_sync`]. `sync` + `pending_install` stay
  /// armed until step 2 completes.
  ///
  /// On a FLUSH FAULT it stages NOTHING and leaves `pending_install` OWED (the install stays retained, the
  /// drained DAG GC-protected as a live root), re-arming the solicit cadence — so a transient disk fault
  /// self-heals locally instead of stalling the sync forever once the donor goes dark. The retry needs NO
  /// fresh donor reply; it only re-attempts the flush. Shared by the first-attempt [`Self::apply_sync`] (a
  /// clean flush stages on the spot) and the local cadence ([`Self::retry_install_flush`] after a transient
  /// fault), so the STAGE is byte-identical either way.
  ///
  /// Single-writer fenced: while a superblock root is in flight (`pending_sb` / `pending_checkpoint`, the
  /// latter being this install's own SyncRepersist once it stages) the re-persist must not begin, so it is
  /// deferred — the install stays owed and the cadence re-drives it once the root lands.
  pub(crate) fn flush_and_stage_install<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
    if self.pending_install.is_none() {
      return; // no owed install — nothing to flush/stage.
    }
    // The same single-superblock-writer fence the rest of the install path observes: a staged re-persist
    // must not begin while a root is outstanding. The install stays owed; the cadence re-drives it. (On the
    // clean first attempt `apply_sync`'s ingress gate already guarantees both are `None`.)
    if self.pending_sb.is_some() || self.pending_checkpoint.is_some() {
      return;
    }
    // Retry the durability barrier over the (still-present) drained blocks. Only on a CLEAN flush do we
    // stage — a fault leaves `pending_install` owed, and `sync` stays armed so the cadence re-attempts.
    if self.blocks_flush_failed(blocks) {
      self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
      return;
    }
    // Read the staged values out of the owed install. `pending_install` is a LIVE GC root, so its blocks are
    // guaranteed present — assert the SM + session DAG roots survived as a cheap structural backstop before
    // naming them in the durable checkpoint.
    let install = self.pending_install.as_ref().expect("just checked Some");
    let target_op = install.checkpoint_op;
    let checkpoint_id = install.checkpoint.checkpoint_id();
    let sm_root = install.sm_root;
    let sessions_root = install.sessions_root;
    let snapshot = install.checkpoint.snapshot_bytes();
    debug_assert!(
      blocks.read_block(sm_root).is_some() && blocks.read_block(sessions_root).is_some(),
      "the owed install's DAG roots must still be present (a live GC root) before submit_write_checkpoint"
    );
    let id = self.mint_op_id();
    sb.submit_write_checkpoint(id, target_op, snapshot);
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op,
      checkpoint_id,
      sm_root,
      sessions_root,
      step: CheckpointStep::AwaitSnapshot(id),
      // a STATE-SYNC re-persist: the root completion routes to the install
      kind: CheckpointKind::SyncRepersist,
    });
    // A checkpoint is chosen and persisting: the block-fetch that pulled its DAG is done (the frontier
    // drained before `apply_sync` retained the install). `pending_checkpoint` now blocks any new
    // block-fetch until the persist resolves; the still-owed `pending_install` is applied atomically by
    // `install_sync` when the root is durable.
    self.block_fetch = None;
    // Keep re-soliciting until the persist's root write completes (defends a fault mid-persist).
    self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
  }

  /// Re-attempt the LOCAL durable install of an OWED `pending_install` whose flush barrier has not yet
  /// succeeded ([`Self::apply_sync`] retained it on a flush fault). The complete verified DAG is already in
  /// the local store (a live GC root), so this needs NO fresh donor reply — it only re-drives
  /// [`Self::flush_and_stage_install`], which retries [`BlockStore::flush`] and, once it succeeds, stages
  /// the two-write re-persist exactly as the first attempt would have. A still-failing flush leaves the
  /// install owed for the next cadence; a transient disk fault thus self-heals instead of stalling the sync
  /// forever if the donor crashes after the blocks were fetched. No-op once the install has STAGED (a
  /// SyncRepersist `pending_checkpoint` is in flight — the fence in `flush_and_stage_install` returns).
  pub(crate) fn retry_install_flush<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
    self.flush_and_stage_install(now, sb, blocks);
  }

  /// INSTALL a staged `SyncCheckpoint` for the synced checkpoint `M` whose re-persist ROOT (step 2) is
  /// now durable — run from [`Self::on_sb_done`]'s `SyncRepersist` completion the instant the root lands.
  ///
  /// The durable root is the commit point, so the in-memory FRONTIER advances to M UNCONDITIONALLY here:
  /// `set_commit_min(M)`, `commit_max`/`op` (preserving the forced-sync held tail), the successor
  /// membership, and `advance_checkpoint_op(M)` — leaving in-memory `checkpoint_op == M` in LOCKSTEP with
  /// the durable root, with NO window where the durable pointer leads the in-memory one. The SM-CONTENT
  /// restore (`sm.restore`) follows; it is the one effect that may still FAIL (a checkpoint block bit-
  /// rotted/was misdirected between the block-fetch drain and this verify-on-read restore):
  /// - SUCCESS ⇒ prune the WAL (`prune` + `truncate`) — the irreversible GC that is the ONLY effect held
  ///   for restore success — and return `Ok`.
  /// - FAILURE ⇒ the frontier already (correctly) names M, so REGRESS NOTHING; stash a retryable
  ///   [`SmReconstruct`] obligation (the caller re-arms a block-fetch to re-pull M's DAG and retries
  ///   `restore` against the unchanged M pointer), leave the WAL untouched, and return `Err`.
  ///
  /// This is the WARM-path analogue of cold-start `recover()`: there the pointer advances to
  /// `state.checkpoint_op()` and the SM is reconstructed lazily under the fixed pointer; here likewise the
  /// pointer is M and the SM may lag M until reconstruction completes (gated by [`Self::sm_reconstruct_owed`]
  /// against serving M / applying ops over the un-restored SM). BOTH callers run it once the root is
  /// durable: the Normal deferred-sync path (already Normal) and the recovery peer-fetch path (which STAGED
  /// the re-persist and STAYED `Recovering`, then `complete_recovery` flips it to Normal right after a
  /// successful install). `self.op`/`commit_min`/`commit_max` were frozen across the STAGE→here window
  /// (`advance_commit` is suppressed while `pending_install`, and `on_prepare` drops while `sync.is_some()`),
  /// so the captured `held_tail` and the monotonic advances below are exactly as they would have been at
  /// STAGE time.
  pub(crate) fn install_sync<W: Wal>(
    &mut self,
    now: Instant,
    wal: &mut W,
    blocks: &dyn BlockStore,
    install: PendingInstall,
  ) -> Result<(), crate::RestoreError> {
    let PendingInstall {
      checkpoint_op,
      sessions_root,
      sm_root,
      held_tail,
      successor,
      successor_prev_config_id,
      checkpoint,
      donor,
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
    // Advance the FRONTIER metadata to the synced point UNCONDITIONALLY — the durable root is the commit
    // point, so in-memory moves in lockstep with it BEFORE the (fallible) SM restore. `commit_min` becomes
    // the synced frontier; `commit_max` keeps the higher learned commit (a held tail we are about to
    // re-apply may already be known-committed). With no held tail, `op == commit_max == commit_min ==
    // checkpoint_op` (the post-recover-from-checkpoint shape); with a held tail, `self.op` and `commit_max`
    // stay, so `op >= commit_max >= commit_min == checkpoint_op` still holds. The universal monotone floor
    // is asserted in `set_commit_min`; the richer rewind assert above adds the forced-vs-ordinary proof.
    self.set_commit_min(checkpoint_op);
    self.commit_max = OpNumber::with(self.commit_max.get().max(checkpoint_op.get()));
    if !held_tail {
      self.op = checkpoint_op;
      self.commit_max = checkpoint_op;
    }
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
      self.quarantined_donor = None;
      self.quarantine_probe_deadline = None;
      // Capture the laggard's own current `config_id` BEFORE the swap — its prior-config slot in the
      // post-crossing lineage.
      let own_prior_config_id = self.membership.config_id();
      self.install_membership(now, None, successor);
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
      // byte-identical. Saturating to stay underflow-free; `apply_sync`'s strictly-forward check proved
      // `successor.epoch() > self.membership.epoch() >= 0`, so a crossing has `successor.epoch() >= 1`.
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
      // extra push, byte-identical to before. On a wholesale crossing DEEPER than the ring (past more than
      // [`LINEAGE_RING`] changes) the ring holds `[verified_prev, own_prior]` and simply OMITS the
      // intermediate ancestors: the immediate predecessor is always present (the value a re-serve chains
      // from, so the recent-lineage window stays correct), and only an agnostic solicitation carrying one of
      // the SKIPPED-OVER intermediate `config_id`s goes un-admitted here — a bounded liveness nicety
      // (state-sync is admitted on member identity regardless — `sender_admits_solicitation`), not a safety
      // gap. The content verification that made the crossing sound never depended on the ring.
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
      // above its own frontier while never offering it below it. `checkpoint_op` is the synced install op
      // (`self.checkpoint_op` is advanced to it just below, in this same call).
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
      if matches!(self.pending_sb, Some((_, PendingSbAction::SwapEpoch(_)))) {
        self.pending_sb = None;
      }
    }
    // Advance the durable checkpoint pointer to the synced op — the durable root (already written) names
    // M, so move `self.checkpoint_op` to M IN LOCKSTEP, BEFORE the (fallible) SM restore. After this the
    // in-memory `checkpoint_op` equals the durable root's, with no window where the durable pointer leads
    // the in-memory one. Done after the membership install so the quorum-checkpoint recompute it triggers
    // reads the (possibly crossed) successor voter set.
    self.advance_checkpoint_op(checkpoint_op);
    // Drop in-memory state the snapshot subsumes. Below the checkpoint everything is folded into the
    // snapshot; ABOVE it we keep the retained tail (held_tail) so a possibly-committed acked op is not
    // lost. Any pending-repair hole AT/BELOW the checkpoint is subsumed (cleared); a hole strictly
    // above it (held_tail only) stays solicited (the recovered tail may still have an interior faulty
    // slot the snapshot does not cover).
    //
    // The log cache trim is the SHARED post-checkpoint rule ([`Self::trim_log_to_checkpoint`], common
    // with `run_gc`): drop every op `<= checkpoint_op`, retaining the held tail `(checkpoint_op .. head]`.
    // The committed-survival witness floor is `self.checkpoint_op` — now advanced to the synced op above.
    self.trim_log_to_checkpoint(checkpoint_op.get(), self.checkpoint_op.get());
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
    // (a stale completion finds no `pending` entry and is ignored) — keep `appending` in lockstep,
    // and abandon any fence-deferred append the same way (the sync supersedes what it would have
    // written; its un-quiesced blocker stays in `wal_writes`, fencing the slot until it completes).
    self.appending.clear();
    self.deferred_appends.clear();
    // Reconstruct the proto-owned CLIENT SESSION TABLE and the SM CONTENT from their checkpoint DAGs,
    // both through a VERIFY-ON-READ view: the block-fetch drained BOTH DAGs before STAGE, but this
    // reconstruct runs later, so a block that bit-rots or is misdirected in that window must not be
    // installed under this valid checkpoint id. Each read checks bytes against their content address;
    // a corrupt/missing session block aborts `decode_sessions` with `None` and a corrupt/missing SM
    // block surfaces as a `RestoreError`. Reconstruct the SESSION table FIRST into a LOCAL value (so a
    // fault leaves `self.clients` unchanged), then restore the SM into a LOCAL value (committed only on
    // success). The FRONTIER is already at M (advanced above), so a fault in EITHER REGRESSES NOTHING —
    // it raises the SAME retryable [`SmReconstruct`] obligation (the caller re-arms a block-fetch to
    // re-pull both DAGs' bad blocks, which `write_block` overwrites, and retries the reconstruct against
    // the unchanged M pointer) and leaves the WAL untouched. This is the warm analogue of cold-start
    // `recover()`'s lazy reconstruct under a fixed pointer.
    let verified = crate::block_store::VerifiedBlocks::new(blocks);
    let Some(sessions) = super::session_blocks::decode_sessions(sessions_root, &verified) else {
      self.sm_reconstruct = Some(SmReconstruct {
        checkpoint_op,
        sm_root,
        sessions_root,
        checkpoint,
        donor,
      });
      return Err(crate::RestoreError::new(sessions_root));
    };
    if let Err(e) = self.sm.restore(sm_root, &verified) {
      self.sm_reconstruct = Some(SmReconstruct {
        checkpoint_op,
        sm_root,
        sessions_root,
        checkpoint,
        donor,
      });
      return Err(e);
    }
    // Both DAGs read back clean — install the session table now (the SM was already committed by
    // `restore` on success).
    self.clients = sessions;
    self.note_sm_restored(checkpoint_op);
    // The SM now holds this checkpoint's content — clear any owed reconstruction (this install is either the
    // first for this point, where none was owed, or a strictly-newer one superseding an older M obligation
    // forward; either way no SM debt remains after a clean restore).
    self.sm_reconstruct = None;
    // Restore succeeded → rebuild the durable WAL (the IRREVERSIBLE GC, the one effect held for restore
    // success). Drop any stale slots strictly ABOVE our head (a stale higher generation that would
    // otherwise read back as a wrong head on a later restart) — `truncate(self.op)`, a no-op when no tail
    // is held (`self.op == checkpoint_op`) and preserving the retained tail `(checkpoint_op .. op]`
    // otherwise. Then free slots strictly BELOW the checkpoint (superseded by the snapshot). The durable
    // ROOT (already written) names `commit = checkpoint_op`, so a later `recover()` restores the SM at the
    // synced point and re-reads the retained tail from the WAL.
    //
    // `prune(checkpoint_op)` frees `< checkpoint_op`, deliberately RETAINING the slot AT `checkpoint_op`
    // — so a no-held-tail sync (`self.op == checkpoint_op`, just truncated above) leaves a NON-EMPTY WAL
    // with `op_head() == checkpoint_op`, not an empty WAL that would read back head 0 on restart. This
    // is why the WAL prune is NOT folded into the shared post-checkpoint trim: `run_gc` frees `<= floor`
    // (`prune(floor+1)`) because it has no such WAL-head constraint, so the two sites legitimately use a
    // different prune FLOOR. Only the in-memory log trim above is common ([`Self::trim_log_to_checkpoint`]).
    let cancelled = wal.truncate(self.op);
    self.absorb_wal_cancellations(wal, cancelled);
    let cancelled = wal.prune(checkpoint_op);
    self.wal_pruned = self.wal_pruned.max(checkpoint_op.get().saturating_sub(1));
    self.absorb_wal_cancellations(wal, cancelled);
    Ok(())
  }

  /// Re-pin the owed SM-reconstruct's block-fetch to a FRESH donor (its prior donor went dark, and a new
  /// `RequestSync` answer at M arrived from a live peer — [`Self::handle_sync_checkpoint`] /
  /// [`Self::on_recover_sync_checkpoint`]). Re-point the obligation's `donor` (and refresh the carried
  /// envelope) to this live sender, then re-arm the fetch so the missing block is re-pulled from a donor
  /// that can answer. M's `sm_root` is unchanged (a checkpoint's DAG root is content-addressed), so the
  /// walk resumes against the same DAG. If the DAG is ALREADY complete in the store (the missing block was
  /// repaired out of band, or this donor's reply already carried it), retry the restore IMMEDIATELY — the
  /// re-arm left no block-fetch to drain, so nothing else would drive the completion.
  pub(crate) fn refetch_sm_reconstruct<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
    from: Peer,
    m: &crate::SyncCheckpoint,
  ) {
    if from.is_client() {
      return; // a client cannot be a donor — keep the existing pin, the timer re-solicits.
    }
    let donor = from;
    if let Some(recon) = self.sm_reconstruct.as_mut() {
      recon.donor = donor;
      recon.checkpoint = m.clone();
    }
    self.rearm_sm_reconstruct_retry(now, blocks);
    // The re-arm left `block_fetch` None iff M's DAG is already fully present — in which case no
    // `BlockResponse` will arrive to drive the drain, so retry the restore right here.
    if self.block_fetch.is_none() && self.sm_reconstruct_owed() {
      self.retry_sm_reconstruct(now, wal, sb, blocks);
    }
  }

  pub(crate) fn rearm_sm_reconstruct_retry(&mut self, now: Instant, blocks: &mut dyn BlockStore) {
    let Some(recon) = self.sm_reconstruct.as_ref() else {
      return; // no obligation owed — nothing to re-arm (defensive; the caller stashed it just above).
    };
    let sm_root = recon.sm_root;
    let sessions_root = recon.sessions_root;
    let donor = recon.donor;
    let checkpoint = recon.checkpoint.clone();
    // Re-arm the block-fetch to re-pull M's missing/corrupt block from EITHER DAG (SM or session). Both
    // arms REPLACE the whole `block_fetch` field, so any prior fetch is superseded by construction — a
    // malformed/foreign DAG (the walk's reachable-set bound breaches) leaves `block_fetch` None and the
    // serviced timer below re-solicits.
    let mut bf = BlockFetch {
      checkpoint: checkpoint.clone(),
      sm_root,
      sessions_root,
      donor,
      block_sync: super::block_sync::BlockSync::new(sm_root),
      session_sync: super::block_sync::BlockSync::new(sessions_root),
      // M is already installed (its epoch already advanced for a crossing), so this re-pin re-pulls M's DAG
      // to retry the restore — the independent `sm_reconstruct_owed()` shield governs the crossing predicates
      // here. Compute the presentation bit for consistency; against the now-current config it reads false.
      crossing_answered: self.checkpoint_presents_crossing(&checkpoint),
      // The retry re-pins M's SAME `(sm_root, sessions_root)` DAG, so carry the re-solicit latch forward: a
      // duplicate active-donor absent in the retry window cannot re-arm it. (A root change here is not
      // possible — M is fixed — so this only ever carries; the `else None` is for uniformity.)
      resolicited_front: self.carry_resolicit_latch(sm_root, sessions_root),
    };
    match bf.next_missing(&*blocks) {
      Ok(Some(addr)) => {
        self.block_fetch = Some(bf);
        self.emit(Outgoing::new(
          Recipient::To(donor),
          Message::RequestBlock(addr),
        ));
      }
      // The whole DAG reads back present-and-verified (the corrupt block was already repaired out of band):
      // no fetch to arm. The serviced re-solicit still drives the retry — a fresh M re-served by the donor
      // re-arms this fetch and retries the restore.
      Ok(None) => {
        self.block_fetch = None;
      }
      // The walk breached its reachable-block bound: count the abort and drop the fetch; the serviced
      // re-solicit still retries off a fresh M.
      Err(_) => {
        self.abort_oversized_block_fetch();
      }
    }
    // Re-arm the serviced ARQ for the node's current status.
    if self.status.is_recovering() {
      match self.recover.as_mut() {
        Some(rec) => rec.awaiting_peer_checkpoint = true,
        None => {
          self.recover = Some(RecoverState {
            awaiting_peer_checkpoint: true,
            ..RecoverState::default()
          });
        }
      }
      self.arm_timers(now);
    } else {
      self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
    }
  }

  /// Retry the SM-content restore for the owed checkpoint `M` once its DAG has re-drained into the block
  /// store ([`Self::on_block_response`] calls this instead of re-staging — M's root is already durable and
  /// `self.checkpoint_op == M`, so the only thing left is to reconstruct the SM). On success: clear the
  /// obligation, prune the WAL band the snapshot subsumes (the irreversible GC, held for restore success),
  /// GC unreachable SM blocks, and signal the state-sync as complete. On a still-faulty block: leave the
  /// obligation owed and re-arm the fetch/ARQ to pull again. Returns whether the SM is now reconstructed.
  pub(crate) fn retry_sm_reconstruct<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) -> bool {
    let Some(recon) = self.sm_reconstruct.as_ref() else {
      return true; // nothing owed — already reconstructed.
    };
    let sm_root = recon.sm_root;
    let sessions_root = recon.sessions_root;
    let checkpoint_op = recon.checkpoint_op;
    let verified = crate::block_store::VerifiedBlocks::new(&*blocks);
    // Re-attempt BOTH reconstructs (the session table FIRST into a local value, then the SM): a block
    // still bit-rotted/missing in EITHER DAG keeps the obligation owed and re-pulls. (The DAG drained per
    // the content-addressed store but a leaf still fails the verify-on-read; the re-armed fetch
    // re-requests it from the donor, whose reply overwrites the bad bytes.)
    let sessions = super::session_blocks::decode_sessions(sessions_root, &verified);
    let Some(sessions) = sessions else {
      self.rearm_sm_reconstruct_retry(now, blocks);
      return false;
    };
    if self.sm.restore(sm_root, &verified).is_err() {
      self.rearm_sm_reconstruct_retry(now, blocks);
      return false;
    }
    // Both DAGs read back clean — install the session table (the SM was committed by `restore`).
    self.clients = sessions;
    self.note_sm_restored(checkpoint_op);
    // The SM now holds M's content. The obligation is met: clear it and run the success effects the
    // `install_sync` happy path runs (the WAL prune is the irreversible GC held for restore success).
    self.sm_reconstruct = None;
    let cancelled = wal.truncate(self.op);
    self.absorb_wal_cancellations(wal, cancelled);
    // Unlike `run_gc`, no below-floor deferred retire precedes this absorb — none can exist here:
    // `install_sync` cleared `deferred_appends` wholesale at its reset, and `checkpoint_op` was
    // already advanced to the synced M BEFORE this fallible restore retried, so every deferral a
    // post-failure append could have parked sits strictly ABOVE the floor this prune frees. The
    // absorb can therefore only release above-floor waiters, the same postcondition `run_gc`
    // establishes explicitly.
    let cancelled = wal.prune(checkpoint_op);
    self.wal_pruned = self.wal_pruned.max(checkpoint_op.get().saturating_sub(1));
    self.absorb_wal_cancellations(wal, cancelled);
    // The synced checkpoint is durable + installed: prune SM blocks unreachable from the new durable
    // checkpoint root, GC the WAL caches, and complete the sync bookkeeping — the same tail as a clean
    // first-try install (it lands at exactly this point), now reached after the retry.
    self.complete_state_sync(now, sb, blocks);
    // The install advanced `checkpoint_op` (the ring window slid forward): re-drive any adopted-tail
    // append that was skipped over the old window.
    self.retry_unappended_adopted_tail(wal);
    true
  }
}

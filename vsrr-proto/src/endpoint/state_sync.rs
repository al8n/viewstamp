use super::*;

impl<S: StateMachine> Endpoint<S> {
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
    // Already syncing? Only raise the target if this checkpoint is newer, then re-solicit on the
    // timer cadence — do not emit a fresh handshake per heartbeat.
    if let Some(s) = self.sync {
      if incoming_checkpoint.get() > s.target.get() {
        self.sync = Some(SyncState {
          target: incoming_checkpoint,
          nonce: s.nonce,
          // Preserve the in-flight sync's forced-ness when only raising the target (an ordinary
          // higher checkpoint does not downgrade an outstanding forced sync's assert-relaxation).
          forced: s.forced,
        });
      }
      return;
    }
    // Fresh trigger: bump the nonce deterministically (the sim seeds `self.nonce` from the prng;
    // a simple increment keeps it deterministic + distinct from the prior recovery/get-view nonce),
    // record the target, and broadcast the solicitation.
    self.nonce = self.nonce.wrapping_add(1);
    self.sync = Some(SyncState {
      target: incoming_checkpoint,
      nonce: self.nonce,
      forced: false,
    });
    self.send_request_sync(now);
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
      match self.sync {
        // Already syncing: only raise the target (keep it forced — applying a checkpoint `<= self.op`).
        Some(s) if target.get() > s.target.get() => {
          self.sync = Some(SyncState {
            target,
            nonce: s.nonce,
            forced: true,
          });
        }
        Some(_) => {} // a sync to >= target is already outstanding — let it run (anti-thrash).
        None => {
          self.nonce = self.nonce.wrapping_add(1);
          self.sync = Some(SyncState {
            target,
            nonce: self.nonce,
            forced: true,
          });
          // Observability (non-vacuity): count this FRESH below-ring-window sync, so the Phase-B gate can
          // prove the connected backup-overflow path genuinely fired (vs the ordinary `> self.op` trigger).
          self.below_ring_window_syncs += 1;
          self.send_request_sync(now);
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
    // Solicit (or re-target) a FORCED sync to the peer-checkpoint floor.
    match self.sync {
      Some(s) if floor.get() > s.target.get() => {
        // Raise an outstanding sync's target to the floor and mark it forced (the discard-direction
        // assert in `apply_sync` must use the relaxed invariant for this synced checkpoint).
        self.sync = Some(SyncState {
          target: floor,
          nonce: s.nonce,
          forced: true,
        });
      }
      Some(_) => {} // a sync to >= floor is already outstanding — let it run (anti-thrash).
      None => {
        self.nonce = self.nonce.wrapping_add(1);
        self.sync = Some(SyncState {
          target: floor,
          nonce: self.nonce,
          forced: true,
        });
        self.send_request_sync(now);
      }
    }
  }

  /// Broadcast a `RequestSync` advertising our CURRENT (stale) checkpoint + the live sync nonce, and
  /// (re)arm the solicit timer. An ordinary state-sync request is answered only by a `Normal` peer with
  /// a STRICTLY-newer durable checkpoint; a RECOVERY peer-fetch (`awaiting_peer_checkpoint()` — our own
  /// checkpoint snapshot is permanently unreadable) sets the `recovery` flag so a peer at the SAME
  /// `checkpoint_op` also serves it (F2: without this, an idle cluster where every healthy peer holds
  /// exactly our checkpoint_op ignores the request forever → recovery livelocks).
  pub(crate) fn send_request_sync(&mut self, now: Instant) {
    let nonce = self.sync.map_or(self.nonce, |s| s.nonce);
    let recovery = self.awaiting_peer_checkpoint();
    self.emit(Outgoing::new(
      Recipient::Backups,
      Message::RequestSync(crate::RequestSync::new(
        self.view,
        self.checkpoint_op,
        self.config.replica(),
        nonce,
        recovery,
      )),
    ));
    self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
  }

  /// State-sync solicit timer: while a sync is outstanding, re-broadcast `RequestSync` and re-arm.
  /// Cleared when the synced checkpoint goes durable (`on_sb_done` clears `sync` + this timer).
  pub(crate) fn sync_timeouts(&mut self, now: Instant) {
    if self.timers.sync_solicit.is_none_or(|d| d > now) {
      return;
    }
    if self.sync.is_none() {
      self.timers.sync_solicit = None;
      return;
    }
    self.send_request_sync(now);
  }

  // ── State-sync: the peer side — answer a RequestSync from the durable checkpoint ──

  /// Answer a peer's `RequestSync` by shipping our latest DURABLE checkpoint, iff we are `Normal` and
  /// hold a checkpoint strictly NEWER than the requester's (else stay silent — never ship a megabyte
  /// snapshot for a no-op). Any caught-up replica (primary or backup) may answer: a committed
  /// checkpoint is immutable cluster-wide, so any holder is authoritative for its content. We do not
  /// keep the encoded envelope in memory after a checkpoint completes, so we read it back from the
  /// superblock (`submit_read_checkpoint`) and record the read in `sync_serving`; the completion
  /// (`on_sb_done`) ships the `SyncCheckpoint`.
  pub(crate) fn on_request_sync<B: Superblock>(
    &mut self,
    _now: Instant,
    sb: &mut B,
    m: crate::RequestSync,
  ) {
    if !self.status.is_normal() {
      return; // only a Normal replica has a trustworthy durable checkpoint to serve
    }
    if m.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    if self.checkpoint_op.get() == 0 {
      return; // nothing durable to serve — silent.
    }
    // A RECOVERY peer-fetch (F2) is served at an EQUAL checkpoint too: the requester's OWN snapshot
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
    let id = self.mint_op_id();
    sb.submit_read_checkpoint(id);
    self.sync_serving.insert(id.get(), (m.replica(), m.nonce()));
  }

  /// Ship a `SyncCheckpoint` for a completed serve-read (the read `on_request_sync` issued). Binds the
  /// shipped `checkpoint_id` to the shipped bytes via `checkpoint_id(cr.snapshot())`, then VERIFIES that
  /// id equals our DURABLE checkpoint id (`sb.state().checkpoint_id()`) — so a CORRUPT-but-
  /// parseable read (an in-model disk fault) cannot make us ship a self-consistent-but-wrong (id, bytes)
  /// pair the requester would accept and restore (it only re-checks `checkpoint_id(snapshot) == advertised
  /// id`); a mismatch DROPS the read (the serve path is then as strict as `recover`'s `id_ok` gate). Also
  /// re-checks status + view-durability + replica range at SHIP time (all may have changed between submit
  /// and completion): if we are no longer Normal, or our view is no longer durable, we drop the reply.
  pub(crate) fn serve_sync_checkpoint<B: Superblock>(&mut self, sb: &B, cr: crate::CheckpointRead) {
    let Some((to, nonce)) = self.sync_serving.remove(&cr.id().get()) else {
      return; // not a serve-read we issued (a stale/foreign completion) — ignore.
    };
    // Durable-view-before-participate: the shipped `SyncCheckpoint` advertises
    // `self.view` (see below). A replica in its `pending_sb` window (a new primary between
    // `start_view_as_new_primary` and the `on_sb_done` that makes its view durable — or any replica mid
    // `AdoptedStartView`/`SendDoViewChange` write) is `Normal` but its view is NOT yet recoverable;
    // serving a `SyncCheckpoint(self.view)` now would advertise a view a crash could roll back — the
    // same hazard the `Prepare`/`Commit`/`StartView`/`RecoveryResponse` paths gate on. The served
    // checkpoint is committed and its CONTENT is view-independent, so the requester loses nothing by
    // waiting: it re-solicits on its `sync_solicit` timer and a Normal+durable peer answers (and we
    // answer once our own view is durable). Negligible liveness cost; consistent with the class — the
    // same shape as the `on_request_prepare` drop. (The submit side, `on_request_sync`, also
    // gates on status, but this SHIP-time gate is the load-bearing one: the view may have advanced
    // between the read submit and its completion.)
    if !self.status.is_normal() || self.pending_sb.is_some() {
      return; // no longer a trustworthy server, or our view is not yet durable — drop.
    }
    if to.get() >= self.config.replica_count() {
      return; // defensive range re-check.
    }
    // Only ship when the READ's op matches our CURRENT durable `checkpoint_op` (F3): we advertise
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
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(to)),
      Message::SyncCheckpoint(crate::SyncCheckpoint::new(
        self.view,
        cr.op(),
        id,
        self.config.replica(),
        nonce,
        snapshot,
      )),
    ));
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
    _wal: &mut W,
    sb: &mut B,
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
    // Idempotency under the persist window: while the adopted checkpoint is being made durable a
    // `pending_checkpoint` is staged; a second SyncCheckpoint arriving then must be dropped (we have
    // already chosen a snapshot and are persisting it).
    if self.pending_checkpoint.is_some() {
      return;
    }
    if m.checkpoint_op().get() < s.target.get() {
      return; // does not advance us past what we know the cluster has committed — ignore.
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
    if self.abdicate_if_primary(now) {
      self.sync = None;
      self.timers.sync_solicit = None;
      return;
    }
    self.apply_sync(now, sb, &m);
  }

  /// STAGE a verified `SyncCheckpoint`. Runs the up-front
  /// VERIFICATION (the forced-vs-ordinary release-active assert, the fallible decode, the F3 BIND-CHECK)
  /// — these mutate nothing — then stages the durable re-persist (the two superblock writes, reusing the
  /// checkpoint sequence) and REMEMBERS the install in `pending_install`. The DESTRUCTIVE install
  /// (restore the SM/sessions, advance `commit_min`/`commit_max`/`op`, prune the WAL, advance
  /// `checkpoint_op`) is DEFERRED to [`Self::install_sync`], which runs ATOMICALLY in `on_sb_done` only
  /// once the sync ROOT (step 2) is durable. `sync` stays `Some` until then, so a crash mid-persist
  /// re-solicits (the durable root still names the OLD checkpoint until step 2 lands).
  ///
  /// **Why defer the install (durable-before-install).** The destructive effects
  /// (pruning the WAL + advancing `commit_min`/`op`) are IRREVERSIBLE; the rest of vsrr only performs
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
  /// held-tail / seed-164 case) still STAGEs + INSTALLs unchanged.
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
    // BIND-CHECK (F3, safety): the op hashed INTO the snapshot must equal the advertised `checkpoint_op`
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
    let held_tail = checkpoint_op.get() < self.op.get();
    let tail_offset = m.snapshot().len() - sm_tail.len();
    let sm_tail = m.snapshot_bytes().slice(tail_offset..);
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
    self.pending_install = Some(PendingInstall {
      checkpoint_op,
      sessions,
      sm_tail,
      held_tail,
    });
    // Keep re-soliciting until the persist's root write completes (defends a fault mid-persist).
    self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
  }

  /// INSTALL a staged `SyncCheckpoint` — the DESTRUCTIVE half of
  /// [`Self::apply_sync`]. Restores the SM + sessions, advances `commit_min`/`commit_max`/`op` to the
  /// synced point (preserving the forced-sync held tail), and prunes the WAL. (The caller advances
  /// `self.checkpoint_op` — see the note at the tail — so the durable checkpoint pointer moves only when
  /// the synced root is durable.) On the DEFERRED Normal path this runs in `on_sb_done` once the sync
  /// ROOT (step 2) is durable, the destructive effects then ATOMICALLY justified by that durable root; on
  /// the EAGER recovery peer-fetch path it runs at flip-to-Normal (the recovery contract forbids reaching
  /// Normal with an unrestored SM) while the re-persist completes in the background. After the caller
  /// advances `checkpoint_op`, `(checkpoint_op, the durable root id)` and `commit_min`/`op` are ALL
  /// consistent at the synced point: there is no window where `checkpoint_op` lags a pruned band, so a
  /// synced replica can never become primary advertising a checkpoint below a pruned committed band. On
  /// the deferred path it is idempotent against intervening state: `self.op`/`commit_min`/`commit_max`
  /// are frozen across the STAGE→here window (`advance_commit` is suppressed while `pending_install`, and
  /// `on_prepare` drops while `sync.is_some()`), so the captured `held_tail` and the monotonic advances
  /// below are exactly as they would have been at STAGE time.
  pub(crate) fn install_sync<W: Wal>(&mut self, wal: &mut W, install: PendingInstall) {
    let PendingInstall {
      checkpoint_op,
      sessions,
      sm_tail,
      held_tail,
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
    // NOTE: `self.checkpoint_op` is advanced to the synced op by the CALLER (`on_sb_done`'s sync
    // re-persist arm) — NOT here — because it must move only when the synced checkpoint ROOT is durable.
    // For the DEFERRED Normal path `install_sync` already runs at root completion, so the caller sets it
    // immediately after. For the EAGER recovery path `install_sync` runs at flip-to-Normal (root not yet
    // durable), and advancing `checkpoint_op` here would let a view change in the window persist a
    // durable-view root naming a `checkpoint_op` whose snapshot is not yet durable (a `checkpoint_op`↔
    // `checkpoint_id` mismatch); leaving it at the OLD value keeps any such root self-consistent (it
    // names the prior durable checkpoint) until the
    // re-persist root lands and the caller advances it.
  }
}

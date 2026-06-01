use super::*;

impl<S: StateMachine> Endpoint<S> {
  // ── State-sync (M3.4a): the trigger + the lagging replica's solicitation ──

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

  /// The M3.5 force-state-sync escalation (the safety-critical core). A `Normal` replica holding a
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
    // SAFETY (M3.5): a PRIMARY must NOT force-sync. The force-sync below resets `self.op` to `floor`
    // (BELOW the primary's head) and clears the log/inflight; the primary would then accept new client
    // requests at REUSED op numbers in the SAME view, and backups still holding the old entries would
    // re-ack them from `on_prepare`'s `pop <= self.op` branch WITHOUT comparing bodies — the primary
    // commits body B while backups applied body A for the same op = committed-state divergence. So a
    // primary that reaches this strand (an unservable, checkpoint-subsumed hole) steps DOWN instead:
    // flag the deferred forfeit, which the next primary tick (`primary_timeouts`) acts on. A caught-up
    // replica then leads and the subsumed hole is recovered via that primary's ordinary checkpoint flow.
    // (Gating force-sync off the primary WITHOUT this step-down would wedge a stuck laggard-primary,
    // since its lag may be below the checkpoint-interval forfeit threshold — hence forfeit, not no-op.)
    if self.is_primary() {
      self.pending_forfeit = true;
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
    self.outgoing.push_back(Outgoing::new(
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
    if !self.timers.sync_solicit.is_some_and(|d| d <= now) {
      return;
    }
    if self.sync.is_none() {
      self.timers.sync_solicit = None;
      return;
    }
    self.send_request_sync(now);
  }

  // ── State-sync (M3.4a): the peer side — answer a RequestSync from the durable checkpoint ──

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
  /// shipped `checkpoint_id` to the shipped bytes via `checkpoint_id(cr.snapshot())` — so even a buggy
  /// superblock that returned a snapshot inconsistent with its root id cannot make us advertise
  /// mismatched bytes (the requester re-verifies, but we must not lie cheaply). Re-checks status +
  /// replica range at SHIP time (both may have changed between submit and completion): if we are no
  /// longer Normal we drop the reply.
  pub(crate) fn serve_sync_checkpoint(&mut self, cr: crate::CheckpointRead) {
    let Some((to, nonce)) = self.sync_serving.remove(&cr.id().get()) else {
      return; // not a serve-read we issued (a stale/foreign completion) — ignore.
    };
    if !self.status.is_normal() {
      return; // no longer a trustworthy server (entered a view change / recovery) — drop.
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
    self.outgoing.push_back(Outgoing::new(
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

  // ── State-sync (M3.4a): apply a verified SyncCheckpoint (the safety-critical core) ──

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
    // racing tail-apply already covered it (no sync needed). A FORCED sync (M3.5) deliberately targets
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
    // SAFETY/LIVENESS (codex vopr seed 8, async-superblock): a PRIMARY must NOT APPLY a state-sync in
    // place. `apply_sync` resets `commit_min` to the synced checkpoint and CLEARS `inflight` (the
    // commit pipeline) while KEEPING `self.op` (the held tail) and staying Normal primary — but it does
    // NOT rebuild the pipeline for the retained committed tail `(commit_min .. op]`, so the primary's
    // `try_commit` wedges forever at the checkpoint (the missing inflight entry at `commit_min + 1`
    // breaks the strictly-in-order commit loop, and re-acked PrepareOks drop on the empty `inflight`).
    // `maybe_force_sync` ALREADY guards the ARM site (a primary reaching the unservable-hole strand
    // sets `pending_forfeit` instead of force-syncing — see its safety note), but a forced/ordinary
    // sync ARMED while this replica was a BACKUP can still be DELIVERED after it (re)gained primacy, so
    // the guard must also hold at the APPLY site. Mirror the arm-site decision: a primary that would
    // apply a sync STEPS DOWN — drop the sync and flag the deferred forfeit, which the next
    // `primary_timeouts` acts on (re-propose `view + 1`). A caught-up replica then leads (every replica
    // already holds the committed tail durably), and THIS replica recovers any pruned hole as a BACKUP
    // via the ordinary force-sync escalation once it is no longer primary. No committed op is lost (the
    // synced snapshot is never discarded — it is simply re-fetched as a backup; `commit_min` never
    // rewinds). This is the same invariant `complete_recovery` enforces for a restarted primary
    // (abdicate rather than resume with a torn-down pipeline).
    if self.is_primary() {
      self.pending_forfeit = true;
      self.sync = None;
      self.timers.sync_solicit = None;
      return;
    }
    self.apply_sync(now, wal, sb, &m);
  }

  /// Apply a verified `SyncCheckpoint`: restore the SM + sessions, advance the metadata to the synced
  /// point, rebuild the WAL/log for it, and stage the durable re-persist (two superblock writes, reusing
  /// the checkpoint sequence). `sync` stays `Some` until the root write completes (`on_sb_done`), so a
  /// crash mid-persist re-solicits.
  ///
  /// **No committed op the replica already held AHEAD of the sync can be lost.** On the ORDINARY
  /// trigger the synced `checkpoint_op > self.op`, so the replica's entire held log `[..=self.op]` is
  /// at or below the synced point — every op `<= checkpoint_op` is already reflected in the restored
  /// SM. A *committed* op above `self.op` is impossible (committing an op requires having prepared it,
  /// which would put it `<= self.op`); the only thing discarded is a stale/uncommitted tail at or
  /// below the synced checkpoint, which is safe.
  ///
  /// On the M3.5 FORCED path ([`Self::maybe_force_sync`]) the synced `checkpoint_op` may instead be
  /// `<= self.op` (the replica holds a tail ABOVE a pruned committed hole). The held tail
  /// `(checkpoint_op .. self.op]` is then **PRESERVED, not discarded** (safety, VOPR seed 164). Those
  /// ops were already durably APPENDED + ACKED by this replica (it voted for them), so the cluster may
  /// have COMMITTED them off its vote. The old code reset `self.op = checkpoint_op` and truncated the
  /// WAL — destroying this replica's only durable copy of a possibly-committed op while KEEPING its
  /// `log_view`; a later view change then took its `(log_view, op)` as the canonical generation's head
  /// and dropped those committed ops cluster-wide (no donor of that generation held them), which the
  /// adopt-time `op >= commit_min` assert detected as a committed-op rewind. The "re-fetch via
  /// `Prepare`/`Commit`" argument is NOT a safe substitute: a view change can intervene before the
  /// re-fetch and finalize a head below the lost ops. The forced sync's *purpose* is only to recover
  /// the doomed hole(s) `N (<= checkpoint_op)` (subsumed by the restored snapshot) — so we keep
  /// `self.op` and the above-floor log entries, restore the SM/sessions at the snapshot, and re-apply
  /// the retained committed tail from the natural `advance_commit` flow. `commit_min` only moves
  /// FORWARD (`checkpoint_op >= N > N-1 == commit_min`), so no applied op is rewound. The release-active
  /// assert below branches: ordinary ⇒ `checkpoint_op > self.op`; forced ⇒ the true invariant
  /// `checkpoint_op >= commit_min`. Either way it makes a trigger-loosening that violates safety fail
  /// loudly rather than silently drop a committed op (matching `select_canonical_log`'s fail-stop style).
  ///
  /// **Never sync past uncommitted state.** The synced `checkpoint_op` is, by definition, a checkpoint
  /// a peer made durable — a quorum committed+applied through it — and we additionally gate on
  /// `>= sync.target`, itself derived from a committed-cluster message. So we never adopt a snapshot
  /// above the committed frontier.
  pub(crate) fn apply_sync<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: &crate::SyncCheckpoint,
  ) {
    let checkpoint_op = m.checkpoint_op();
    // Release-active safety assert, branched on whether this is a FORCED sync (M3.5). On the ordinary
    // path the synced checkpoint is strictly above our head, so discarding our held log `[..=op]`
    // cannot drop a committed op. On the forced path it may be at/below our head (we hold a tail above
    // a pruned committed hole); the TRUE invariant there is `checkpoint_op >= commit_min` — never
    // rewind the applied frontier — and the trigger structurally guarantees `checkpoint_op >= N > N-1
    // == commit_min`, so the held tail it discards is only uncommitted ops or committed ops the quorum
    // holds and re-announces (see the method doc's case analysis).
    if self.sync.is_some_and(|s| s.forced) {
      assert!(
        checkpoint_op.get() >= self.commit_min.get(),
        "force-sync must not rewind the applied frontier (checkpoint_op {} < commit_min {})",
        checkpoint_op.get(),
        self.commit_min.get()
      );
    } else {
      assert!(
        checkpoint_op.get() > self.op.get(),
        "state-sync must not discard a held op above the synced checkpoint (checkpoint_op {} <= op {})",
        checkpoint_op.get(),
        self.op.get()
      );
    }
    // Decode the verified envelope FIRST (before any state mutation). `on_sync_checkpoint` already
    // verified `checkpoint_id(snapshot) == m.checkpoint_id()`, so the bytes are the right checkpoint;
    // but a malformed/truncated envelope (a buggy encoder, or corruption that somehow preserved the
    // hash) must NOT panic — reject it as a fault and leave `sync` armed so the solicit timer re-fetches
    // from another peer. We have mutated nothing yet, so an early return is clean.
    let Some((bound_op, sessions, sm_tail)) = Self::decode_checkpoint(m.snapshot()) else {
      return;
    };
    // BIND-CHECK (F3, safety): the op hashed INTO the snapshot must equal the advertised `checkpoint_op`
    // we are about to advance `commit_min`/`commit_max`/`op` to. A faulty peer can ship STALE snapshot
    // bytes (whose real frontier is op A) under an OVERSTATED `checkpoint_op = B > A` whose hash still
    // matches the old bytes; without this check we would restore the OLDER SM yet advance the frontier
    // to B — silently dropping the committed ops in `(A, B]`. Reject (no mutation; `sync` stays armed so
    // another peer answers) rather than drop committed state.
    if bound_op != checkpoint_op {
      return;
    }
    // PRESERVE-TAIL (safety, VOPR seed 164): does this sync land BELOW our held head? Only the FORCED
    // path can (the ordinary assert above guarantees `checkpoint_op > self.op`). When it does, the band
    // `(checkpoint_op .. self.op]` is ops we already durably APPENDED + ACKED (we voted for them with
    // `PrepareOk`/`AdoptAck`), so the cluster may have COMMITTED them off our vote. Discarding them
    // (the old `self.op = checkpoint_op` + `wal.truncate(checkpoint_op)` + `log.clear`) destroys our
    // only durable copy of a possibly-committed op while keeping `log_view` — a later view change then
    // takes our `(log_view, op)` as the canonical generation's head and drops those committed ops
    // entirely (the loss the adopt-time `op >= commit_min` assert later trips on). The forced sync's
    // *purpose* is only to recover the pruned holes AT/BELOW the floor (subsumed by the snapshot); the
    // acked tail ABOVE the floor must survive. So keep `self.op` and the above-floor log entries,
    // restore the SM/sessions at the snapshot, and let the recovered committed tail re-apply once the
    // re-persist lands (the next Commit/Prepare drives `advance_commit` over the retained log).
    let held_tail = checkpoint_op.get() < self.op.get();
    // Restore the SM and the client-session table from the decoded envelope.
    self.sm.restore(sm_tail);
    self.clients = sessions;
    // Advance metadata monotonically to the synced point. `commit_min` becomes the synced frontier;
    // `commit_max` keeps the higher learned commit (a held tail we are about to re-apply may already be
    // known-committed). With no held tail, `op == commit_max == commit_min == checkpoint_op` (the
    // post-recover-from-checkpoint shape); with a held tail, `self.op` and `commit_max` stay, so
    // `op >= commit_max >= commit_min == checkpoint_op` still holds.
    self.commit_min = checkpoint_op;
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
    self.log.retain(|&op, _| op > checkpoint_op.get());
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
    // `(checkpoint_op .. op]` otherwise. Then free slots BELOW the checkpoint (superseded by the
    // snapshot). The durable ROOT below names `commit = checkpoint_op`, so a later `recover()` restores
    // the SM at the synced point and re-reads the retained tail from the WAL.
    wal.truncate(self.op);
    wal.prune(checkpoint_op);
    // Stage the durable re-persist, reusing the checkpoint two-write sequence so a crash recovers to
    // the synced point (not the stale one). Step 1: write the snapshot under our own superblock; step
    // 2 (in `on_sb_done`) writes the new VsrState root naming it. `sync` stays armed until step 2
    // completes. (No checkpoint can already be in flight — `on_sync_checkpoint` gates on
    // `pending_checkpoint.is_none()`.)
    let id = self.mint_op_id();
    sb.submit_write_checkpoint(id, checkpoint_op, m.snapshot_bytes());
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op: checkpoint_op,
      checkpoint_id: m.checkpoint_id(),
      step: CheckpointStep::AwaitSnapshot { id },
    });
    // Keep re-soliciting until the persist's root write completes (defends a fault mid-persist).
    self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
  }
}

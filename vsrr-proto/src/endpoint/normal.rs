use super::*;

impl<S: StateMachine> Endpoint<S> {
  pub(crate) fn primary_timeouts<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    // Deferred forfeit (M3.5, safety + liveness): a primary that hit the force-sync strand
    // ([`Self::maybe_force_sync`]) flagged a step-down rather than reset its `op` (which would let it
    // reuse op numbers in this view). Act on it FIRST, on EVERY primary tick while the flag is set —
    // and crucially do NOT clear it one-shot (F2). A one-shot forfeit broadcasts a SINGLE
    // StartViewChange and then resumes heartbeating; if that lone SVC is dropped/partitioned the
    // primary keeps heartbeating, every backup keeps resetting its `primary_idle` (so none starts its
    // own view change), and the SVC retransmit timer is not serviced while Normal — the stuck primary
    // WEDGES the cluster below the unrepairable hole. Instead we keep forfeiting until the view
    // actually changes:
    //   1. RE-PROPOSE the next view each tick — `propose_next_view` is idempotent at `view+1` (it only
    //      resets the SVC collection when raising the target, never escalates to `view+2,+3` while we
    //      stay Normal-primary), so this just RE-BROADCASTS the `StartViewChange{view+1}` under loss.
    //   2. SKIP the commit heartbeat + prepare retransmit below (the early `return`), so backups STOP
    //      hearing this primary; their `primary_idle` fires and they JOIN the SVC for `view+1` → an
    //      SVC quorum forms → the view changes (a caught-up replica leads).
    // The flag is cleared ONLY when this replica LEAVES Normal-primary — the transition handlers
    // (`transition_to_view_change_status` / `adopt_canonical_head` / `catch_up_to_view` /
    // `start_view_as_new_primary`) all clear `pending_forfeit`, so once the view changes the new
    // generation re-evaluates from scratch (no same-view re-forfeit, no cross-view leak).
    if self.pending_forfeit {
      self.forfeit(now, sb);
      return;
    }
    // Durable-view-before-participate (codex R8-F1): until the new-primary view-change superblock
    // write is durable, status is Normal but the view is NOT yet recoverable. A primary must NOT
    // heartbeat (`Commit`) nor retransmit prepares (`Prepare`) in a view it could regress out of on
    // crash — those assert this replica's authority in the not-yet-durable view (the same hazard the
    // `on_get_view`/`on_recovery` gates close on the message side). Skip the whole heartbeat /
    // retransmit / forfeit-evaluation tick while the write is pending; `start_view_participate` (run
    // from `on_sb_done` once the view IS durable) arms the timers and begins committing, after which
    // ordinary ticks resume. The deferred forfeit above is exempt: it is a STEP-DOWN (it proposes a
    // higher view via `propose_next_view`), not participation as this view's primary.
    if self.pending_sb.is_some() {
      return;
    }
    // Bootstrap the heartbeat the first time we're ticked as primary.
    if self.timers.commit.is_none() {
      self.timers.commit = Some(now + COMMIT_HEARTBEAT);
    }
    if self.timers.commit.is_some_and(|d| d <= now) {
      self.outgoing.push_back(Outgoing::new(
        Recipient::Backups,
        Message::Commit(Commit::new(self.view, self.commit_min, self.checkpoint_op)),
      ));
      self.timers.commit = Some(now + COMMIT_HEARTBEAT); // re-arm THIS timer only
    }
    if self.timers.prepare.is_some_and(|d| d <= now) {
      // Retransmit every un-committed prepare, in op order (`commit_min+1 ..= op`). A backup that fell
      // BELOW the primary's `commit_min` is caught up not by this (those ops are `<= commit_min`) but by
      // its OWN tail-gap solicitation ([`Self::request_tail_gap`], driven on every Commit heartbeat),
      // which fetches the missing committed band above its head via `RequestPrepare`.
      let lo = self.commit_min.get() + 1;
      let hi = self.op.get();
      for op in lo..=hi {
        if let Some(entry) = self.log.get(&op).cloned() {
          self.outgoing.push_back(Outgoing::new(
            Recipient::Backups,
            Message::Prepare(Prepare::new(
              self.view,
              OpNumber::with(op),
              self.commit_min,
              self.checkpoint_op,
              entry.client,
              entry.request,
              entry.body,
            )),
          ));
        }
      }
      // re-arm THIS timer only (clear once everything is committed)
      self.timers.prepare = if self.commit_min.get() < self.op.get() {
        Some(now + PREPARE_RETRANSMIT)
      } else {
        None
      };
    }
    // M3.5 T3: a primary that has fallen a full checkpoint interval behind the quorum's durable
    // checkpoint — continuously for the grace window — forfeits primacy (steps down via a view
    // change). Checked each primary tick, AFTER the heartbeat/retransmit above (so an alive primary
    // still heartbeats while it is being given its grace window to catch up).
    self.maybe_forfeit(now, sb);
  }

  pub(crate) fn on_request<W: Wal>(
    &mut self,
    now: Instant,
    wal: &mut W,
    _from: Peer,
    r: crate::Request,
  ) {
    if !self.status.is_normal() || !self.is_primary() {
      return; // backups ignore; the client retries to the primary
    }
    // Durable-view-before-participate: a pending superblock view-change write means status==Normal
    // but our view is not yet persisted. Serving a request now would create+commit an op in a view
    // we could regress out of on crash. Drop it — the client retries once the view is durable.
    //
    // DEFENSE (M3.5, safety): also drop while a state-sync OR a checkpoint-persist is in flight. Both
    // can RESET `self.op` (a sync to the checkpoint via `apply_sync`; a checkpoint completion advances
    // `checkpoint_op` and GCs) — assigning a new client request an op now risks reusing an op number a
    // backup still holds under different bytes (the op-reuse divergence `maybe_force_sync`'s primary
    // step-down guards against). A primary should never be syncing in steady state, so this only ever
    // drops a request during an abnormal in-flight reset; the client retries once it settles.
    if self.pending_sb.is_some() || self.sync.is_some() || self.pending_checkpoint.is_some() {
      return;
    }
    // SAFETY (codex vopr seed 52, async-superblock): a primary that has FLAGGED a forfeit (it has
    // decided to step down — `maybe_force_sync`'s primary guard, or the F1 recovery-peer-fetch /
    // state-sync apply that reset this replica's `op` back to a checkpoint) must NOT assign new ops. It
    // has just RESET `self.op` to (a checkpoint at or below) a value the cluster has moved PAST — under
    // a NEWER view a fresh primary already committed ops at those numbers. Accepting a client request
    // now reuses a committed op number with DIFFERENT bytes (the stale-primary op-reuse divergence:
    // VOPR seed 52 had a recovered view-0 primary reuse a committed op a view-1 primary had already
    // committed). The forfeit is latched and acted on by the next `primary_timeouts` tick, but a client
    // request can arrive (via `handle_message`) BEFORE that tick — so the op-assignment gate, not just
    // the timer, must honour the abdication. Drop the request; once the view change completes a
    // caught-up primary serves it.
    if self.pending_forfeit {
      return;
    }
    // codex R5-F2: do not serve clients while our committed prefix is not yet applied. If commit_max >
    // commit_min (a committed op is known but not yet applied — e.g. held by a B4 repair hole), the client
    // session table is stale for the unapplied ops; assigning a fresh op to a retry of one of them would
    // double-execute it once the gap fills (the apply loop has no dedup). Make the primary catch up first;
    // the client retries. (A healthy steady-state primary has commit_max == commit_min, so this never fires
    // then.) `!self.repair.is_empty()` is subsumed (a hole implies commit_max > commit_min) but stated for intent.
    if self.commit_max.get() > self.commit_min.get() || !self.repair.is_empty() {
      return;
    }
    let key = r.client().get();
    let session = self.clients.entry(key).or_default();

    // Dedup against the session (clients send one request at a time, numbered 1..).
    if r.request().get() < session.request.get() {
      return; // stale
    }
    if r.request().get() == session.request.get() {
      // Duplicate of the latest accepted request.
      // Clone the cached reply data out before dropping the session borrow so
      // that pushing to self.outgoing (which requires &mut self) is borrow-safe.
      let cached = session.reply.as_ref().and_then(|(rn, body)| {
        if *rn == r.request() {
          Some((*rn, body.clone()))
        } else {
          None
        }
      });
      if let Some((rn, body)) = cached {
        let reply = Reply::new(self.view, r.client(), rn, body);
        self.outgoing.push_back(Outgoing::new(
          Recipient::To(Peer::Client(r.client())),
          Message::Reply(reply),
        ));
      }
      return; // either resent the cached reply, or it's still in flight
    }
    if r.request().get() != session.request.get() + 1 {
      return; // gap: client violated one-in-flight; ignore
    }

    // Accept: assign the next op, submit to WAL, cache, broadcast Prepare.
    // The primary's own vote is counted in on_wal_done when the append is durable.
    let client = r.client();
    let request = r.request();
    let body_bytes = r.body_bytes();
    session.request = request;
    self.op = self.op.next();
    let header = Header::new(self.op, self.view, client, request, r.body());
    let id = self.mint_op_id();
    wal.submit_append(id, self.op, header, body_bytes.clone());
    self.log.insert(
      self.op.get(),
      LogEntry {
        client,
        request,
        body: body_bytes.clone(),
      },
    );
    self.inflight.insert(
      self.op.get(),
      Inflight {
        oks: 0, // own bit set on append-done in on_wal_done
        committed: false,
      },
    );
    self.pending.insert(id.get(), Pending::Ack(self.op));
    // Append-before-ack: op is in flight until its `on_wal_done` (R7-F1). The primary's own vote is
    // likewise gated — `record_own_vote` fires only on completion — but tracking it here keeps the
    // "durable?" predicate uniform across every votable append (and the choke-point debug_assert).
    self.appending.insert(self.op.get());

    self.outgoing.push_back(Outgoing::new(
      Recipient::Backups,
      Message::Prepare(Prepare::new(
        self.view,
        self.op,
        self.commit_min,
        self.checkpoint_op,
        client,
        request,
        body_bytes,
      )),
    ));

    self.arm_timers(now);
    // NOTE: try_commit() is NOT called here — the own vote is recorded in on_wal_done when the
    // append is durable, which then calls try_commit.
  }

  /// Commits the longest contiguous quorum-acked prefix beyond `commit_min`.
  pub(crate) fn try_commit<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    let quorum = self.config.quorum() as u32;
    let mut advanced = false;
    loop {
      let next = self.commit_min.get() + 1;
      // Extract needed data while holding a short-lived shared borrow, so the
      // borrow ends before commit_op (which needs &mut self).
      let ready = self
        .inflight
        .get(&next)
        .map(|inf| (!inf.committed, inf.oks.count_ones()))
        .map(|(not_committed, ones)| not_committed && ones >= quorum)
        .unwrap_or(false);
      if !ready {
        break;
      }
      // `commit_op` HOLDS the commit (returns false without advancing) if `next`'s body read back
      // permanently faulty and must be peer-repaired — never skip a hole. Stop the loop; the repair
      // timer re-fetches it and a later try_commit resumes from exactly here.
      if !self.commit_op(now, next) {
        break;
      }
      advanced = true;
    }
    self.commit_max = OpNumber::with(self.commit_max.get().max(self.commit_min.get()));
    if advanced {
      // Tell backups the commit advanced (also serves as a heartbeat).
      self.outgoing.push_back(Outgoing::new(
        Recipient::Backups,
        Message::Commit(Commit::new(self.view, self.commit_min, self.checkpoint_op)),
      ));
    }
    // commit_min may have advanced past a checkpoint boundary — take a checkpoint if due.
    self.maybe_checkpoint(sb);
  }

  /// Applies op `op` on the primary, caches + sends the reply, emits the event. Returns `true` if it
  /// applied; `false` if the body is missing (read back permanently faulty) — in which case it
  /// registers the op for peer fault-repair and does NOT advance `commit_min`, so the caller HOLDS
  /// the commit at the hole until a peer supplies the op (B4).
  #[must_use]
  fn commit_op(&mut self, now: Instant, op: u64) -> bool {
    // Faults-as-data (the M3.3b peer fault-repair conversion): a committed op whose body read back
    // permanently faulty (bit-rot / torn) is ABSENT from the dense `log` cache (the recover loop
    // dropped it rather than adopt a wrong/empty body). Instead of panicking, hold the commit and
    // fetch the op from a peer (`RequestPrepare` → `Prepare`); a later try_commit resumes here.
    let Some(entry) = self.log.get(&op).cloned() else {
      self.request_repair(now, op);
      return false;
    };
    let reply_body = self.sm.apply(OpNumber::with(op), &entry.body);
    self.commit_min = OpNumber::with(op);
    if let Some(inflight) = self.inflight.get_mut(&op) {
      inflight.committed = true;
    }
    let session = self.clients.entry(entry.client.get()).or_default();
    session.reply = Some((entry.request, reply_body.clone()));

    self.outgoing.push_back(Outgoing::new(
      Recipient::To(Peer::Client(entry.client)),
      Message::Reply(Reply::new(
        self.view,
        entry.client,
        entry.request,
        reply_body.clone(),
      )),
    ));
    self
      .events
      .push_back(Event::Committed(crate::Committed::new(
        OpNumber::with(op),
        entry.client,
        entry.request,
        reply_body,
      )));
    true
  }

  pub(crate) fn on_prepare<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    p: Prepare,
  ) {
    // Peer fault-repair (B4): a `Prepare` answering our `RequestPrepare` for a committed-op hole is
    // handled BEFORE the view/role guards below — its op's content is view-independent (a committed op
    // is immutable), so a reply from a holder in any view fills the hole; we must NOT let the
    // higher-view rule yank us into a view change, nor the `is_primary`/same-view guards drop it (a
    // recovered PRIMARY can also hold a hole). `fill_repair` verifies (checksum + placement) and
    // returns false for a non-hole / unverifiable body, so a normal Prepare falls through unchanged.
    if self.fill_repair(now, wal, sb, &p) {
      return;
    }
    if p.view().get() > self.view.get() {
      self.catch_up_to_view(now, p.view());
      return;
    }
    if !self.status.is_normal() || p.view() != self.view || self.is_primary() {
      return;
    }
    // Heard from the primary — defer the idle timeout.
    self.note_primary_contact(now);
    // State-sync trigger: a `Prepare` from a fresh primary may be the first signal a lagging backup
    // sees of the cluster's checkpoint. If the cluster checkpointed past our WAL head, solicit a
    // SyncCheckpoint instead of buffering this (unreachable) prepare forever.
    self.maybe_request_sync(now, p.checkpoint_op());
    // While a sync is outstanding we will catch up via the snapshot, not by tail-apply: drop the
    // prepare (do not buffer ops we can never reach below the cluster checkpoint). The synced
    // checkpoint's apply rebuilds the head; the primary's next Prepare/Commit then extends the tail.
    if self.sync.is_some() {
      return;
    }
    // Durable-view-before-participate: a pending superblock view-change write means status==Normal
    // but our view is not yet persisted. Acking a prepare now would cast a vote in a view we could
    // regress out of on crash → cross-view double-vote. Drop it; the primary retransmits the prepare.
    if self.pending_sb.is_some() {
      return;
    }
    // Learn the primary's commit (apply anything we already have).
    self.advance_commit(now, sb, p.commit().get());

    let pop = p.op().get();
    if pop <= self.op.get() {
      // Already have this op; (re)ack so a lost prepare_ok is recovered. Ops are immutable within a
      // view, and the higher-view rule (top of this fn) + the `view != self.view` reject mean this
      // re-ack only fires for a current-view prepare.
      //
      // Append-before-ack (codex R7-F1): re-ack INLINE only if op `pop` is DURABLE. If its WAL append
      // is still IN FLIGHT (`self.op` advanced in `append_prepare`/`adopt_append` while the append is
      // async), this branch must NOT ack — that would vote for an op the backup has not durably
      // appended, the exact violation the primary's PREPARE_RETRANSMIT during the in-flight window
      // could trigger. SUPPRESS the inline ack: the in-flight append's own `on_wal_done` already owes
      // exactly one PrepareOk(pop) AFTER durability, so the backup still acks once, at the right time.
      // (A re-ack for an op that already completed — e.g. a genuinely lost PrepareOk — still re-acks,
      // recovering it: that is the legitimate purpose of this branch.)
      //
      // The durability oracle is the WAL itself (`op_durably_appended`), NOT just the `appending` set:
      // a view change / catch-up clears `appending` (keeping it in lockstep with `pending`) while an
      // async append abandoned in the old generation is STILL staged in the WAL — and once such an op
      // is committed (commit_min advances past it), the view-change re-append range `(commit_min+1 ..=
      // op]` never re-marks it, so `appending` alone would wrongly green-light a re-ack of a
      // committed-but-still-in-flight op (codex vopr seed 17). Consulting the WAL closes that hole: a
      // `Dirty` (in-flight) / `Empty` (truncated, not re-appended) slot above the checkpoint is not yet
      // durable; a `Clean`/`Faulty` slot or one folded into the durable checkpoint is. (We keep the
      // `appending` guard too, so the in-flight-then-just-completed window still defers its single ack
      // to `on_wal_done` rather than emitting a redundant inline duplicate.)
      if !self.appending.contains(&pop) && self.op_durably_appended(wal, pop) {
        self.send_prepare_ok(p.op());
      }
      return;
    }
    if pop == self.op.get() + 1 {
      self.append_prepare(wal, p);
      // Drain any buffered, now-contiguous prepares.
      while let Some(next) = self.buffer.remove(&(self.op.get() + 1)) {
        self.append_prepare(wal, next);
      }
      // After appending, apply any ops now available up to the learned commit.
      let target = self.commit_max.get();
      self.advance_commit(now, sb, target);
    } else {
      // Future op: buffer it, and solicit the committed band between our head and it that the primary's
      // retransmit (only `commit_min+1..=op`) will never re-send (those ops are `<= commit_min`). This
      // fills the gap so the buffered op becomes reachable instead of stranding the backup at its head.
      self.buffer.insert(pop, p);
      self.request_tail_gap();
    }
  }

  fn append_prepare<W: Wal>(&mut self, wal: &mut W, p: Prepare) {
    self.op = p.op();
    let header = Header::new(p.op(), p.view(), p.client(), p.request(), p.body());
    let id = self.mint_op_id();
    wal.submit_append(id, p.op(), header, p.body_bytes());
    self.log.insert(
      p.op().get(),
      LogEntry {
        client: p.client(),
        request: p.request(),
        body: p.body_bytes(),
      },
    );
    self.pending.insert(id.get(), Pending::Ack(p.op()));
    // Append-before-ack (R7-F1): mark op in-flight so neither this op's deferred ack NOR a
    // retransmit-driven re-ack (`on_prepare`'s `pop <= self.op` branch) can emit a PrepareOk before
    // `on_wal_done` clears it. PrepareOk is deferred to on_wal_done when the append is durable.
    self.appending.insert(p.op().get());
  }

  /// Whether op `op` is DURABLY APPENDED on this replica's own disk — the ground-truth append-before-
  /// ack oracle, read straight from the WAL/superblock rather than from the mutable `appending` set
  /// (which is reset on view transitions, so it can lose track of an async append abandoned in an old
  /// generation while its bytes are still staged). `op` is durable iff it is folded into the durable
  /// checkpoint (`op <= checkpoint_op`, its body subsumed by the snapshot) OR its WAL slot has
  /// COMPLETED its append: `Clean` (durable + checksum-valid) or `Faulty` (durably written, then later
  /// torn / bit-rotted — the append still completed; the corrupt bytes are a separate, peer-repaired
  /// concern). A `Dirty` (still in flight) or `Empty` (never written / truncated) slot above the
  /// checkpoint is NOT yet durable.
  fn op_durably_appended<W: Wal>(&self, wal: &W, op: u64) -> bool {
    op <= self.checkpoint_op.get()
      || matches!(
        wal.status(OpNumber::with(op)),
        SlotStatus::Clean | SlotStatus::Faulty
      )
  }

  /// The single append-before-ack choke point: emits a `PrepareOk` for `op` to the primary. `op` MUST
  /// be durable — NOT in `self.appending` — at every call. The `debug_assert!` is the systematic guard
  /// (codex R7-F1): any future caller that tries to ack an op whose WAL append is still in flight trips
  /// in tests, so the violation class cannot silently relocate. Callers (`on_wal_done` after the append
  /// lands; `on_prepare`'s in-flight-gated re-ack branch) are responsible for not calling this for an
  /// in-flight op — this assert backstops that contract.
  pub(crate) fn send_prepare_ok(&mut self, op: OpNumber) {
    debug_assert!(
      !self.appending.contains(&op.get()),
      "append-before-ack: PrepareOk for op {} whose WAL append is still in flight",
      op.get()
    );
    let primary = self.config.primary(self.view);
    self.outgoing.push_back(Outgoing::new(
      Recipient::To(Peer::Replica(primary)),
      Message::PrepareOk(PrepareOk::new(
        self.view,
        op,
        self.config.replica(),
        self.checkpoint_op,
      )),
    ));
  }

  /// Applies committed ops we hold, up to `min(target, op)`, strictly in order. Backups discard the
  /// reply but emit `Committed` so observers can verify agreement.
  pub(crate) fn advance_commit<B: Superblock>(&mut self, now: Instant, sb: &mut B, target: u64) {
    // Record the learned commit regardless of whether we hold the ops yet.
    self.commit_max = OpNumber::with(self.commit_max.get().max(target));
    while self.commit_min.get() < target && self.commit_min.get() < self.op.get() {
      let op = self.commit_min.get() + 1;
      // Faults-as-data (the M3.3b peer fault-repair conversion): a committed op whose body read back
      // permanently faulty (bit-rot / torn) is ABSENT from the dense `log` cache (the recover loop
      // dropped it rather than adopt a wrong/empty body). Instead of panicking, HOLD the commit at the
      // hole — never skip op N to apply N+1 — and fetch op N from a peer (`RequestPrepare` →
      // `Prepare`); a later advance_commit (after the op arrives) resumes from exactly here.
      let Some(entry) = self.log.get(&op).cloned() else {
        self.request_repair(now, op);
        break;
      };
      let reply = self.sm.apply(OpNumber::with(op), &entry.body);
      self.commit_min = OpNumber::with(op);
      // Maintain the client-session request high-water + CACHED REPLY as we apply (mirrors the
      // primary's `commit_op`). The request watermark is the at-most-once dedup watermark a
      // backup-turned-primary needs in `on_request`. It MUST be tracked here on every apply — NOT
      // reconstructed from the `log` cache when becoming primary — because M3.4b GC prunes the `log`
      // below the checkpoint, so a backup whose log is empty (everything checkpointed+pruned) would
      // otherwise carry a stale `session.request` of 0 and wedge every client on the gap check
      // (`r.request() != session.request + 1`). The snapshot also restores these on recover/state-sync,
      // so the watermark survives both GC and a checkpoint restore.
      //
      // Caching the REPLY body here (not just the watermark) closes a real liveness gap: if a client's
      // reply is LOST in flight and then the primary fails over, the new primary (this former backup)
      // sees the client's resend as a duplicate (`request == session.request`) and must resend the
      // cached reply — but the OLD code cached the reply only on the primary's `commit_op`, so a
      // backup-turned-primary had `session.reply == None` and stayed SILENT, hanging the client forever
      // even though a healthy quorum exists. The reply is the SM's deterministic apply output, so every
      // replica that applies the op can cache it (it survives the failover; for an op recovered via a
      // checkpoint snapshot the dedup watermark still gates correctness, and the recent above-checkpoint
      // ops that a lost reply concerns are always applied through here).
      let session = self.clients.entry(entry.client.get()).or_default();
      if entry.request.get() > session.request.get() {
        session.request = entry.request;
        session.reply = Some((entry.request, reply.clone()));
      }
      self
        .events
        .push_back(Event::Committed(crate::Committed::new(
          OpNumber::with(op),
          entry.client,
          entry.request,
          reply,
        )));
    }
    // commit_min may have advanced past a checkpoint boundary — take a checkpoint if due.
    self.maybe_checkpoint(sb);
  }

  /// Solicit committed ops that sit strictly ABOVE this replica's head — the band
  /// `(max(self.op, checkpoint_op) .. commit_max]` — from peers via `RequestPrepare`, so they arrive as
  /// ordinary `Prepare`s through [`Self::on_prepare`]'s append path (advancing the head + draining the
  /// buffer). Closes a real liveness gap: the primary's prepare-retransmit only covers
  /// `(commit_min_primary .. op_primary]` ([`Self::primary_timeouts`]), so a BACKUP whose head fell
  /// BELOW the primary's `commit_min` (it missed those Prepares while briefly behind) never receives the
  /// committed band `(head .. commit_min_primary]`: those ops are `<= commit_min_primary` (never
  /// retransmitted), ABOVE the cluster checkpoint (so the `> self.op` state-sync trigger is FALSE — not
  /// snapshot-only), and ABOVE its own head (so `advance_commit`'s apply loop can never reach them).
  /// Without this it stalls at its head forever — and if it is in the only surviving quorum (another
  /// replica crashed), the WHOLE cluster stalls (no caught-up quorum can form). Observed deterministically
  /// under the M3 fault envelope (a laggard crashed while two backups were transiently behind).
  ///
  /// Self-driven + self-retrying: called on every `Commit`/`Prepare` from the primary (heartbeats every
  /// `COMMIT_HEARTBEAT`), so it re-solicits until the head catches up — no dedicated timer, and it works
  /// even when the primary's pipeline is idle (`commit_min == op`, so its prepare-retransmit is off).
  /// The requested ops are NOT registered in `self.repair` (that path is for BELOW-head holes and does
  /// not advance the head) — the answering `Prepare` flows through the normal append path instead. A
  /// peer holding the op unpruned (the primary holds the whole `(checkpoint .. op]` band) answers via
  /// `on_request_prepare`. Below the checkpoint is state-sync territory ([`Self::maybe_request_sync`]),
  /// so only the above-checkpoint portion is requested. No-op for the primary, while syncing, or when
  /// caught up (`commit_max <= self.op`).
  ///
  /// **Bounded per call** by [`TAIL_GAP_WINDOW`]: the window is `(lo .. min(commit_max, lo +
  /// TAIL_GAP_WINDOW - 1)]`, so at most `TAIL_GAP_WINDOW` `RequestPrepare`s are pushed even if
  /// `commit_max` (learned from one incoming `Commit`/`Prepare`) is enormous or malformed. A real gap
  /// is closed incrementally — `request_tail_gap` runs on every heartbeat, and each answered window
  /// raises the head, sliding the window up — so a bogus huge `commit_max` can no longer flood the
  /// Sans-I/O core, while a genuinely far-behind backup catches up via state-sync, not tail-gap.
  fn request_tail_gap(&mut self) {
    if !self.status.is_normal() || self.is_primary() || self.sync.is_some() {
      return;
    }
    let lo = self.op.get().max(self.checkpoint_op.get()) + 1;
    // Cap the request window so one large/bogus `commit_max` cannot enqueue an unbounded number of
    // `RequestPrepare`s in a single call (CPU/memory DoS in the Sans-I/O core). `lo + WINDOW - 1` cannot
    // overflow in practice (op numbers are far below u64::MAX), but `saturating_*` keeps it total.
    let hi = self
      .commit_max
      .get()
      .min(lo.saturating_add(TAIL_GAP_WINDOW).saturating_sub(1));
    for op in lo..=hi {
      self.send_request_prepare(op);
    }
  }

  pub(crate) fn on_prepare_ok<B: Superblock>(&mut self, now: Instant, sb: &mut B, ok: PrepareOk) {
    if ok.view().get() > self.view.get() {
      self.catch_up_to_view(now, ok.view());
      return;
    }
    if !self.status.is_normal() || !self.is_primary() || ok.view() != self.view {
      return;
    }
    if ok.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    // Record this backup's reported checkpoint for the checkpoint-quorum (the range check above
    // guards the key). Independent of inflight: even an ok for an op we no longer track still
    // carries a fresh checkpoint report. Drives `quorum_checkpoint_op` → the GC prune floor.
    // MONOTONE: a reordered older report must never lower the recorded value (the GC floor and the
    // force-sync trigger that read it must not regress under reordering/partitions).
    self.record_peer_checkpoint(ok.replica().get(), ok.checkpoint_op());
    // State-sync trigger (symmetric): a backup reporting a checkpoint above our head means we are the
    // laggard (e.g. a partition-healed old primary). The `> self.op` gate keeps this a no-op normally.
    self.maybe_request_sync(now, ok.checkpoint_op());
    // Force-sync escalation (M3.5): a fresh quorum-checkpoint report may have just crossed a `repair`
    // hole we hold, rendering its `RequestPrepare` futile (the op is pruned everywhere on the quorum).
    self.maybe_force_sync(now);
    if let Some(inflight) = self.inflight.get_mut(&ok.op().get()) {
      inflight.oks |= 1u64 << ok.replica().get();
    }
    self.try_commit(now, sb);
  }

  pub(crate) fn on_commit<B: Superblock>(&mut self, now: Instant, sb: &mut B, c: Commit) {
    if c.view().get() > self.view.get() {
      self.catch_up_to_view(now, c.view());
      return;
    }
    if !self.status.is_normal() || c.view() != self.view || self.is_primary() {
      return;
    }
    // Heard from the primary — defer the idle timeout.
    self.note_primary_contact(now);
    // Record the primary's reported checkpoint. Harmless on a backup (only the primary reads
    // `peer_checkpoint` for GC), but it pre-seeds the map so a backup-turned-primary starts with the
    // primary's last-known checkpoint rather than 0. Bounded by `replica_count`. MONOTONE: a
    // reordered older Commit must never lower the recorded value (so the force-sync trigger this
    // backup reads via `quorum_checkpoint_op` does not regress under reordering/partitions).
    self.record_peer_checkpoint(self.config.primary(self.view).get(), c.checkpoint_op());
    // State-sync trigger: if the cluster has checkpointed past our WAL head, solicit a SyncCheckpoint
    // (the ops we'd need are below the cluster checkpoint and may be pruned — tail-apply can't reach).
    self.maybe_request_sync(now, c.checkpoint_op());
    // Force-sync escalation (M3.5): the primary's just-recorded checkpoint may have crossed a `repair`
    // hole we hold below it (pruned everywhere on the quorum) → escalate to a forced `RequestSync`.
    self.maybe_force_sync(now);
    self.advance_commit(now, sb, c.commit().get());
    // Tail-gap repair: if the primary's commit is ABOVE our head (committed ops we are missing, above
    // the cluster checkpoint), solicit them via `RequestPrepare` — the primary's retransmit (only
    // `commit_min+1..=op`) never re-sends a committed op below its own commit_min, so a backup that fell
    // behind would otherwise be stranded at its head. Self-retrying on each heartbeat until caught up.
    self.request_tail_gap();
  }
}

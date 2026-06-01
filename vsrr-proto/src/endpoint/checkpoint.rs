use super::*;

impl<S: StateMachine> Endpoint<S> {
  pub(crate) fn on_wal_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    done: WalDone,
  ) {
    // Recovery read completions route through the recover loop (verify + retry + progress).
    if self.status.is_recovering() || self.status.is_recovering_head() {
      self.on_recover_wal_done(now, wal, sb, done);
      return;
    }
    let WalDone::Appended(id) = done else {
      return; // Normal op: only an append matters (reads/faults occur during recovery).
    };
    // Append-before-ack dispatch by the recorded kind. An OpId not in `self.pending` is a
    // stale/superseded completion → ignore. (A peer-repair fill is now TRACKED as `Pending::RepairFill`
    // — codex R13-F2 — so it is no longer an untracked bare write.)
    let resolved = self.pending.remove(&id.get());
    // This op's WAL append is now durable: clear its in-flight mark BEFORE casting any ack/vote (or
    // clearing a repair hole), so the choke point (`send_prepare_ok`) sees it as durable (R7-F1) and the
    // repair-fill apply runs off a no-longer-in-flight op. Done for every tracked kind — each variant
    // carries its op number — and never in the `None` arm (a stale/superseded completion must not
    // retract an op a FRESH adopt-/repair-append just re-marked under a new OpId).
    match &resolved {
      Some(
        Pending::Ack(op)
        | Pending::AdoptVote(op)
        | Pending::AdoptAck(op)
        | Pending::RepairFill(op, _),
      ) => {
        self.appending.remove(&op.get());
      }
      None => {}
    }
    match resolved {
      Some(Pending::Ack(op)) => {
        if self.is_primary() {
          // the primary's own append is durable → record its vote and try to commit
          self.record_own_vote(op.get());
          self.try_commit(now, sb);
        } else {
          self.send_prepare_ok(op);
        }
      }
      // codex R6-F1: a new primary's adopted uncommitted-tail op is now durable → only NOW set its own
      // inflight vote and try to commit. The own vote could not be cast before this append (it was
      // seeded `oks: 0` in `start_view_as_new_primary`), so the primary never counts a vote for an op
      // it has not durably appended (append-before-ack for the view-change adoption path).
      Some(Pending::AdoptVote(op)) => {
        self.record_own_vote(op.get());
        self.try_commit(now, sb);
      }
      // codex R6-F1: a backup's adopted uncommitted-tail op is now durable → send the deferred
      // PrepareOk. No PrepareOk was sent for this op before its append completed (append-before-ack).
      Some(Pending::AdoptAck(op)) => self.send_prepare_ok(op),
      // codex R13-F2: the peer-repair fill's WAL append is now durable. ONLY NOW expose + apply it: the
      // staged canonical body lands in `self.log`, the repair hole clears, and the held commit resumes.
      // No PrepareOk/own-vote is ever sent for a repair fill (peer repair is not a vote) — this is a
      // pure durability barrier. The body was withheld from `self.log` until here, so it was never in a
      // DVC/StartView/checkpoint nor applied by a concurrent `advance_commit` before its append landed.
      // Safe even if a view change has begun since the fill was staged (the prior comment covers only the
      // PENDING window): the filled op is COMMITTED (`fill_repair` only accepts a Prepare with `commit >=
      // op`), and a committed op's body is identical across all views (committed-op survival), so applying
      // it here is CONSISTENT with adoption — a `select_canonical_log`/`adopt_log` that supersedes the log
      // re-derives this exact canonical committed body, never a divergent one.
      Some(Pending::RepairFill(op, entry)) => {
        self.log.insert(op.get(), entry);
        self.repair.remove(&op.get());
        if self.repair.is_empty() {
          self.timers.repair_retry = None;
        }
        // The hole is filled + durable → resume applying the held committed prefix from where it stalled.
        let target = self.commit_max.get();
        self.advance_commit(now, sb, target);
      }
      None => {}
    }
  }

  pub(crate) fn on_sb_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    done: SuperblockDone,
  ) {
    // Recovery checkpoint-read completions route through the recover loop (restore SM + retry).
    if self.status.is_recovering() || self.status.is_recovering_head() {
      self.on_recover_sb_done(now, wal, sb, done);
      return;
    }
    // State-sync peer side: outside recovery a `CheckpointRead`/`Fault` means a read WE issued to
    // serve a peer's `RequestSync` completed — ship the durable snapshot (or drop the serving entry
    // on a fault; the requester re-solicits). This is status-gated apart from the recover loop above
    // (that handles reads only while recovering; this handles them while Normal).
    let id = match done {
      SuperblockDone::Wrote(id) => id,
      SuperblockDone::CheckpointRead(cr) => {
        self.serve_sync_checkpoint(cr);
        return;
      }
      SuperblockDone::Fault(id) => {
        // A faulted serve-read: drop the serving entry (if any) and stay silent. (A faulted root/
        // checkpoint WRITE outside recovery is not produced by our backends; dropping is defensive.)
        self.sync_serving.remove(&id.get());
        return;
      }
    };
    // Durable-view write? (matched first; its OpId never aliases a checkpoint write's.)
    if let Some((pending_id, action)) = self.pending_sb {
      if pending_id == id {
        self.pending_sb = None;
        match action {
          PendingSbAction::SendDoViewChange => self.send_do_view_change(now),
          PendingSbAction::StartViewAsPrimary => self.start_view_participate(now, sb),
          PendingSbAction::AdoptedStartView => self.start_view_acks(wal),
        }
        return;
      }
    }
    // Checkpoint write? Distinguish the two steps by their own minted OpIds.
    if let Some(pc) = self.pending_checkpoint {
      match pc.step {
        CheckpointStep::AwaitSnapshot { id: sid } if sid == id => {
          // The snapshot is durable → advance the durable root to name the new checkpoint.
          // `commit_max >= commit_min >= target_op` always (target_op was commit_min at trigger;
          // commit_min only grows; commit_max >= commit_min), so the VsrState `commit >= checkpoint_op`
          // invariant holds → try_new can't fail.
          let root_id = self.mint_op_id();
          // The committed band the NEW root names shrinks to `(target_op .. commit_min]` (the just-
          // checkpointed prefix `[1..=target_op]` now lives in the snapshot, not the band) — pass
          // `pc.target_op` as the floor so the persisted vsr_headers match this root's `checkpoint_op`.
          // Persist the KNOWN-committed frontier `commit_max` as the commit (codex R10-F2): a root that
          // persisted the lower `commit_min` would let `recover` (which reads `state.commit()` as
          // `commit_max`, R9-F1) read back a LOWERED frontier when this replica is held at a repair hole
          // below `commit_max`. The band headers are the SPARSE canonical set — one per HELD op in
          // `(target_op .. commit_max]`, skipping holes (codex R12-F1). On a state-sync re-persist
          // `commit_min == commit_max == target_op`, so the band is empty there — unchanged.
          let state = crate::VsrState::try_new(
            self.view,
            self.log_view,
            self.commit_max,
            pc.target_op,
            pc.checkpoint_id,
            self.committed_band_headers(pc.target_op),
          )
          .expect("checkpoint root: commit_max >= target_op and log_view <= view");
          sb.submit_write(root_id, state);
          self.pending_checkpoint = Some(PendingCheckpoint {
            step: CheckpointStep::AwaitRoot { id: root_id },
            ..pc
          });
        }
        CheckpointStep::AwaitRoot { id: rid } if rid == id => {
          // The root is durable → the checkpoint is COMPLETE: advance the in-memory checkpoint_op,
          // then GC the WAL + per-op caches below the prune floor (M3.4b). GC runs AFTER the durable
          // root so the recovery point is the new checkpoint; a lost/failing prune is then safe (a
          // later checkpoint re-prunes). For a state-sync re-persist (below), the WAL was already
          // truncated+pruned in `apply_sync`, so this is idempotent (prunes below the same floor).
          self.checkpoint_op = pc.target_op;
          self.pending_checkpoint = None;
          self.run_gc(wal);
          // State-sync: if this root write completed a SYNC's durable re-persist (rather than an
          // ordinary checkpoint), the synced checkpoint is now durable → resume as a Normal backup.
          // Clear the sync bookkeeping + solicit timer and re-arm the Normal timers. (A sync and an
          // ordinary checkpoint can never be staged together: `apply_sync` runs only while
          // `sync.is_some()` and gates on `pending_checkpoint.is_none()`, and `maybe_checkpoint`
          // gates on `pending_checkpoint.is_none()` too — so `sync.is_some()` here means this root
          // belongs to the sync.)
          if let Some(s) = self.sync {
            self.sync = None;
            self.timers.sync_solicit = None;
            // Non-vacuity signal (M3.4a): a state-sync just fully applied + became durable.
            self.state_syncs_applied += 1;
            // Non-vacuity signal (M3.5 T6): distinguish a FORCE-sync (the escalation that recovers a
            // pruned committed hole below the quorum checkpoint) from an ordinary `> self.op` sync.
            if s.forced {
              self.forced_syncs_applied += 1;
            }
            self.arm_timers(now);
          }
        }
        _ => {} // a stale/superseded completion (e.g. from before a view change) — ignore
      }
    }
  }

  /// If `commit_min` has reached the next checkpoint boundary and no superblock write is pending,
  /// begin a checkpoint: snapshot the SM + client sessions, write the snapshot, and stage step 2.
  ///
  /// Called at the tails of `try_commit` and `advance_commit` — the only two sites that advance
  /// `commit_min`. The snapshot reflects the SM state at `commit_min` exactly (all ops `<= commit_min`
  /// applied, none above), so the checkpoint covers a committed+applied prefix; `target_op = commit_min`
  /// keeps the snapshot↔op correspondence exact even when a batch commit jumps past the boundary.
  pub(crate) fn maybe_checkpoint<B: Superblock>(&mut self, sb: &mut B) {
    // Only checkpoint once the view is settled and durable-consistent: Normal status AND
    // `log_view == view`. `advance_commit` is also called mid-view-change (in
    // `start_view_as_new_primary` / `on_start_view`, applying prior-view committed ops) — there
    // `self.view` is already the NEW view but `log_view` is still the old view and a
    // `submit_durable_view` is imminent; this gate keeps a checkpoint from racing that durable-view
    // write (a checkpoint and a view-change root must never both be in flight on the superblock). A
    // checkpoint due during a transition re-triggers cleanly once Normal resumes — `commit_min` is
    // preserved across the transition. In steady Normal `log_view == view` holds, so this never
    // blocks a legitimate checkpoint.
    if !self.status.is_normal() || self.log_view.get() != self.view.get() {
      return;
    }
    // Exclusion: never start while a durable-view write OR another checkpoint is in flight. (In
    // Normal, `pending_sb` is set only by a deferred view-participation write whose completion will
    // re-enter Normal; `maybe_checkpoint` then re-triggers. This is the no-double-trigger gate.)
    if self.pending_sb.is_some() || self.pending_checkpoint.is_some() {
      return;
    }
    let boundary = self.checkpoint_op.get() + self.config.checkpoint_ops();
    if self.commit_min.get() < boundary {
      return;
    }
    // Checkpoint at `commit_min` (a committed+applied boundary), not at the raw `boundary` op:
    // `commit_min` may have jumped past `boundary` in a batch commit, and the SM has applied through
    // `commit_min` (apply is forward-only) — so the snapshot reflects state through `commit_min`.
    let target_op = self.commit_min;
    let snapshot = self.sm.snapshot();
    // Bind the checkpoint op into the envelope so `checkpoint_id` covers it (F3): the written op and
    // the op hashed inside the snapshot are the SAME, so a later restore can prove they agree.
    let envelope = Self::encode_checkpoint(target_op, &self.clients, &snapshot);
    let checkpoint_id = crate::checkpoint_id(&envelope);
    let id = self.mint_op_id();
    sb.submit_write_checkpoint(id, target_op, envelope);
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op,
      checkpoint_id,
      step: CheckpointStep::AwaitSnapshot { id },
    });
  }

  // M3.2b: physical bounded-WAL slot reuse + stall-before-wrap (the `Wal` exposes a capacity; the
  // primary refuses to assign an op that would overwrite an un-pruned slot below `quorum_checkpoint_op`)
  // is a SEPARATE milestone — see the M3.2b plan. `run_gc` below is the *logical* safety half (the
  // prune floor a bounded-WAL backend would enforce as a physical stall): it tells the WAL what is
  // safe to free, never authorizing a free above what a quorum still needs.
  //
  /// Post-checkpoint garbage collection: free WAL slots + in-memory per-op cache entries the replica
  /// no longer needs, once a checkpoint's durable root has landed (called from `on_sb_done`'s
  /// `AwaitRoot` arm). Run AFTER the root is durable, so the recovery point is the new checkpoint root
  /// — a crash before/after a (possibly lost or failing) prune is safe: `recover()` re-derives the
  /// prunable prefix from the durable root and a later checkpoint re-prunes.
  ///
  /// # The prune floor (THE safety decision)
  ///
  /// An op `N` is freed only when `N <= floor`, and the floor is chosen so that **every freed op is
  /// already captured in this replica's own durable checkpoint snapshot** (`floor <= self.checkpoint_op`
  /// always). Concretely:
  /// - **primary:** `floor = min(self.checkpoint_op, quorum_checkpoint_op())` — never free an op a
  ///   `quorum` has not yet checkpointed, so a peer still in the live tail (below `quorum_checkpoint_op`)
  ///   can be served the op it is missing from THIS primary's WAL (`on_request_prepare` /
  ///   retransmit). Conservative: an unheard peer counts as 0, so a fresh primary frees nothing until
  ///   fresh `PrepareOk`s raise the quorum floor.
  /// - **backup:** `floor = self.checkpoint_op` — a backup collects no `PrepareOk`s, so its
  ///   `quorum_checkpoint_op()` is ~0 (peers default 0); gating a backup on the quorum floor would mean
  ///   it NEVER prunes and its WAL/log grow unbounded (defeating the boundedness deliverable). A backup
  ///   instead prunes below its OWN durable checkpoint — those ops are in its snapshot, so it loses
  ///   nothing locally, and it serves no peer WAL reads that the cluster relies on (the primary +
  ///   another up-to-date backup retain the live tail).
  ///
  /// # Proof no committed op is permanently lost (state-sync is the safety net)
  ///
  /// Take any committed op `N` that a laggard `L` might need, and any replica `R` that freed `N`
  /// (so `N <= R.floor <= R.checkpoint_op` — `N` is in `R`'s snapshot). Two exhaustive cases for `L`:
  ///
  /// 1. **`L` is below the cluster checkpoint** (some caught-up replica's `checkpoint_op > L.op`).
  ///    Then `L`'s state-sync trigger fires on the next `Commit`/`Prepare`/`PrepareOk` it hears
  ///    (`maybe_request_sync`: `incoming.checkpoint_op() > self.op`), and `L` fetches a checkpoint at
  ///    op `>= N` (the snapshot subsumes every op `<= N`). `L` recovers `N` via the snapshot — it never
  ///    needs the freed slot. This is exactly why GC is safe NOW (M3.4a state-sync) but was not before.
  /// 2. **`N` is above every operational replica's checkpoint** (it is in the recent committed tail).
  ///    Then NO replica has freed `N` (freeing requires `N <= checkpoint_op`), so `N` is still held by
  ///    the quorum that committed it, and `L` obtains it by ordinary retransmit (`commit_min+1..=op`)
  ///    or single-op peer fault-repair (`RequestPrepare` → `Prepare`).
  ///
  /// The load-bearing local invariant: **the apply loops never read a freed op.** `commit_op` /
  /// `advance_commit` read `self.log.get(op)` only for `op > commit_min`, and
  /// `commit_min >= checkpoint_op >= floor`, so every applied op is strictly above the floor and was
  /// never freed. Retransmit (`primary_timeouts`, op in `commit_min+1..=op`) is likewise all `> floor`.
  /// The only reads at/below the floor are *peer-serve* paths (`on_request_prepare`), which return
  /// silently on a freed op — and case (1)/(2) above show such a peer always has another route.
  ///
  /// (Formerly-residual strand, now CLOSED by the M3.5 force-state-sync escalation
  /// ([`Self::maybe_force_sync`]): a `Normal` replica holding a PERMANENTLY-faulty hole at `N` *below
  /// its own head but above its own checkpoint*, where every replica that ever held `N` has pruned it
  /// — a correlated multi-replica permanent fault on a single pruned op. Its head `>=` the cluster
  /// checkpoint, so the `> self.op` sync trigger does NOT fire, and no peer can serve the pruned op.
  /// This is reachable under the M3 gate's envelope (GC + permanent disk-faults + partitions). The
  /// escalation detects it via `quorum_checkpoint_op() >= N` (the op is now available ONLY as part of
  /// a checkpoint snapshot, every quorum member pruned the prepare), clears the doomed hole, and forces
  /// a `RequestSync` to the quorum checkpoint (`>= N`) — recovering `N` from the snapshot that subsumes
  /// it. Liveness-only (no committed op is ever lost or rewritten — `N` survives in every checkpoint
  /// snapshot, swapping a `RequestPrepare`-for-a-pruned-op for a satisfiable `RequestSync`). See §2 of
  /// the M3.5 plan and [`Self::maybe_force_sync`]'s safety proof.)
  fn run_gc<W: Wal>(&mut self, wal: &mut W) {
    let floor = if self.is_primary() {
      self
        .checkpoint_op
        .get()
        .min(self.quorum_checkpoint_op().get())
    } else {
      // A backup prunes below its OWN checkpoint (it serves no peer WAL reads the cluster relies on);
      // gating it on the quorum floor would never prune → unbounded WAL/log. See the method doc.
      self.checkpoint_op.get()
    };
    if floor == 0 {
      return; // nothing safe to free yet (no quorum-acknowledged checkpoint / no own checkpoint)
    }
    // `prune(below)` frees slots strictly below `below`; to free ops `<= floor` pass `below = floor+1`.
    wal.prune(OpNumber::with(floor + 1));
    // Trim the in-memory per-op caches to `(floor .. head]`. SAFE: the apply loops read only ops
    // `> commit_min >= checkpoint_op >= floor`, so nothing they touch is removed here; the freed
    // entries are committed+checkpointed (durable in the SM snapshot) and out of every reach path
    // except peer-serve, which has the state-sync/retransmit fallbacks proven above.
    self.log.retain(|&op, _| op > floor);
    self.inflight.retain(|&op, _| op > floor);
    self.buffer.retain(|&op, _| op > floor);
    // `clients` is intentionally NOT trimmed here: it grows per-CLIENT (bounded by the active client
    // set), not per-op, and dropping a LIVE session risks a dedup miss for a retry whose cached reply
    // is still needed. Every session was captured in the checkpoint envelope, so a crash + recover
    // rebuilds them; the unbounded-in-op structures (WAL, log, inflight, buffer) are the ones GC'd.
  }

  /// Persist the durable VSR root for the current `(view, log_view, commit_max)` and arm the
  /// participation deferred until the write completes.
  /// Overwrites any prior `pending_sb` (supersession): an older-view completion is then ignored.
  ///
  /// **Persists the KNOWN-committed frontier, not the applied one (codex R10-F2).** The `VsrState`
  /// commit is `self.commit_max` (the highest op KNOWN committed cluster-wide), NOT `self.commit_min`
  /// (the locally-applied frontier). `recover` reads `state.commit()` back as `commit_max` (R9-F1), so
  /// persisting the lower `commit_min` on a replica HELD at a repair hole below `commit_max` would lower
  /// the recovered frontier and re-open the R9-F1 laggard-quorum truncation hazard. The committed-band
  /// headers below are the SPARSE canonical set over `(checkpoint_op .. commit_max]` — one header per
  /// HELD op, skipping holes (codex R12-F1) — so they may be SHORTER than `commit` and contain gaps,
  /// which `try_new` allows.
  ///
  /// **Preserves the durable checkpoint pointer.** This write must carry the CURRENT checkpoint
  /// (`self.checkpoint_op` + the durable `checkpoint_id`), NOT zeros — a view-change root that
  /// zeroed `checkpoint_op` would regress the durable checkpoint and, once the WAL below it is GC'd
  /// (M3.2 Task 5), lose committed ops on recovery. The view transitions drop the LOGICAL
  /// `pending_checkpoint`, so `self.checkpoint_op` equals the durable checkpoint op and
  /// `sb.state().checkpoint_id()` is its matching id. (A checkpoint's step-2 root write may still be
  /// PHYSICALLY in flight when a view change issues this durable-view root write; the `Superblock`
  /// serialized root-write ordering contract guarantees this later write is the final durable root,
  /// so the stale checkpoint root cannot win.) `commit_max >= commit_min >= checkpoint_op` always holds,
  /// so `try_new`'s `commit >= checkpoint_op` invariant cannot fail.
  /// Derive the CANONICAL headers of the un-checkpointed committed band `(checkpoint_floor ..
  /// commit_max]` from `self.log`, for persistence in the durable [`crate::VsrState`] root
  /// (TigerBeetle's `vsr_headers`). `checkpoint_floor` is the `checkpoint_op` the SAME root write
  /// records — `self.checkpoint_op` for an ordinary durable-view write, but `pc.target_op` (the NEW
  /// checkpoint) for the checkpoint root write, whose band shrinks to `(target_op .. commit_max]`.
  ///
  /// **SPARSE, one header per HELD op (codex R12-F1).** The list records a header for EVERY op the log
  /// holds in `(checkpoint_floor .. commit_max]`, in ascending op order, SKIPPING holes — it does NOT
  /// stop at the first gap. This is the R12-F1 fix: the durable header set must vouch for the identity
  /// of EVERY committed-band op this replica actually holds, so `recover` can verify each held op
  /// individually rather than DROPPING a whole suffix because of one lower hole. A contiguous-prefix
  /// list left a held committed op above a lower hole HEADER-LESS, and the R11-F1 recover guard then
  /// deleted that op's only surviving copy when this replica was the quorum intersection for it.
  ///
  /// The band reaches the KNOWN-committed frontier `commit_max` (the value the same root persists,
  /// R10-F2), NOT `commit_min`: a replica HELD at `commit_min < commit_max` by a lower repair hole still
  /// HOLDS the committed ops in `(commit_min, commit_max]` (it appended+acked them; they are above the
  /// checkpoint, un-GC'd), and each must keep its canonical header. The loop is bounded at `self.op` —
  /// `min(commit_max, self.op)` — because `self.log` holds NO op above the head: ops in `(self.op,
  /// commit_max]` are the tail-gap ops this replica does not hold, which would be skipped anyway, and the
  /// cap keeps a bogus/huge learned `commit_max` (an unverified `Commit`/`Prepare` field can set it far
  /// ahead, the same reason `request_tail_gap` caps its window) from spinning an unbounded loop in the
  /// Sans-I/O core. Ops the log is missing within the bound (the held repair hole) are simply skipped —
  /// `self.log.get` returns `None` and that op gets no header, exactly the UNPROVEN/peer-repair case on
  /// `recover`.
  ///
  /// After an ADOPTION (`adopt_log`) `self.log` holds the canonical bytes for the committed band, so
  /// the body checksum each header records is canonical; in normal operation the band is the replica's
  /// own committed ops (also canonical). `VsrState::try_new` validates this sparse set (in-range,
  /// strictly-ascending ops; gaps allowed). Bounded by `min(commit_max, self.op) - checkpoint_floor`,
  /// i.e. ~one checkpoint interval (GC keeps the band small).
  ///
  /// The reconstructed `Header` carries the current root `view`; only its [`Header::body_checksum`] is
  /// load-bearing for the recovery cross-check (it is `fnv1a_128(body)`, view-independent), so the view
  /// field is informational. Empty when no held op lies in the band.
  fn committed_band_headers(&self, checkpoint_floor: OpNumber) -> std::vec::Vec<Header> {
    let lo = checkpoint_floor.get().saturating_add(1);
    // Reach the known-committed frontier but never past the head: `self.log` holds nothing above
    // `self.op`, so capping here drops no held op and keeps a bogus huge learned `commit_max` from
    // spinning an unbounded loop (a defensive bound mirroring `request_tail_gap`).
    let hi = self.commit_max.get().min(self.op.get());
    let mut headers = std::vec::Vec::new();
    for op in lo..=hi {
      // SPARSE: record a header for every HELD op, SKIPPING (not stopping at) a hole. A held committed
      // op above a lower repair hole thus keeps its canonical header (the R12-F1 fix); an op the log is
      // missing gets none and is the UNPROVEN/peer-repair case recover handles.
      let Some(entry) = self.log.get(&op) else {
        continue;
      };
      headers.push(Header::new(
        OpNumber::with(op),
        self.view,
        entry.client,
        entry.request,
        &entry.body,
      ));
    }
    headers
  }

  pub(crate) fn submit_durable_view(&mut self, action: PendingSbAction, sb: &mut impl Superblock) {
    let checkpoint_id = sb.state().checkpoint_id();
    let state = crate::VsrState::try_new(
      self.view,
      self.log_view,
      // Persist `commit_max` — the KNOWN-committed frontier — as the durable `VsrState` commit, NOT
      // `commit_min` (codex R10-F2). The R9-F1 fix made `recover` read `state.commit()` as `commit_max`,
      // so a root write that persisted the LOWER `commit_min` would, on a replica HELD at
      // `commit_min < commit_max` by a stale/faulty repair hole, make `recover` read back a LOWERED
      // frontier — the recovered DVC would then under-report the known commit and the R9-F1
      // laggard-quorum truncation hazard reappears. `commit_max >= commit_min >= checkpoint_op`, so
      // `try_new`'s `commit >= checkpoint_op` invariant still holds; the committed-band headers below
      // are the SPARSE canonical set from `self.log` — one header per HELD op in `(checkpoint_op ..
      // commit_max]`, SKIPPING holes (codex R12-F1) — so a held committed op above a lower repair hole
      // keeps its header rather than being left header-less and dropped by recover.
      self.commit_max,
      self.checkpoint_op,
      checkpoint_id,
      self.committed_band_headers(self.checkpoint_op),
    )
    .expect("durable view: log_view <= view and commit_max >= checkpoint_op");
    let id = self.mint_op_id();
    sb.submit_write(id, state);
    self.pending_sb = Some((id, action));
  }
}

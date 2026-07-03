use super::*;

impl<S: StateMachine, R: Reconfig> Endpoint<S, R> {
  pub(crate) fn on_wal_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
    done: WalDone,
  ) {
    // Recovery read completions route through the recover loop (verify + retry + progress).
    if self.status.is_recovering() || self.status.is_recovering_head() {
      self.on_recover_wal_done(now, wal, sb, blocks, done);
      return;
    }
    // A Retired (removed) replica is no longer a cluster member: drop any straggling WAL completion (a
    // pre-removal append landing after the swap retired this node), so the consensus dispatch below —
    // which casts votes and reads `local_slot()` — is unreachable. This is the STORAGE-path twin of the
    // ingress + timer Retired drops: a removed node participates in NOTHING at EVERY driver entry point
    // by construction (`install_membership` cleared the in-flight bookkeeping, so nothing is owed).
    if self.status.is_retired() {
      return;
    }
    let id = match done {
      WalDone::Appended(id) => id,
      // DEFENSIVE: a `Fault` completion whose OpId matches a pending APPEND. The `Wal` contract
      // requires appends to complete as `Appended` (the embedder retries / fail-stops internally —
      // see [`Wal::submit_append`]), so this is a contract violation — but silently dropping it
      // would LEAK the op's in-flight bookkeeping (its `Pending` entry + `appending` mark) until
      // the next view transition: the op could never be (re-)acked, `has_inflight_storage()` would
      // read true forever (breaking a graceful shutdown), and a leaked `RepairFill` would hold the
      // commit at its hole. Degrade the violation to a RETRY instead: clear the stale entry/mark
      // and re-submit the append from the still-held data, so a transient embedder fault costs one
      // round trip, not a wedge. A `Fault` not matching a pending append is a read verdict (or
      // stale/superseded) and is ignored.
      WalDone::Fault(id) => {
        if let Some(p) = self.pending.remove(&id.get()) {
          self.appending.remove(&p.op().get());
          self.resubmit_faulted_append(wal, p);
        }
        return;
      }
      _ => return, // Normal op: only appends matter (reads + their verdicts occur during recovery).
    };
    // Append-before-ack dispatch by the recorded kind. An OpId not in `self.pending` is a
    // stale/superseded completion → ignore. (A peer-repair fill is tracked as `Pending::RepairFill`
    // so it is no longer an untracked bare write.)
    let resolved = self.pending.remove(&id.get());
    // This op's WAL append is now durable: clear its in-flight mark BEFORE casting any ack/vote (or
    // clearing a repair hole), so the choke point (`send_prepare_ok`) sees it as durable and the
    // repair-fill apply runs off a no-longer-in-flight op. Done for every tracked kind — each variant
    // carries its op number — and never in the `None` arm (a stale/superseded completion must not
    // retract an op a FRESH adopt-/repair-append just re-marked under a new OpId).
    if let Some(p) = &resolved {
      self.appending.remove(&p.op().get());
    }
    match resolved {
      Some(Pending::Ack(op)) => {
        if self.is_primary() {
          // the primary's own append is durable → record its vote and try to commit
          self.record_own_vote(op.get());
          self.try_commit(now, sb, blocks);
        } else {
          self.send_prepare_ok(op);
        }
      }
      // a new primary's adopted uncommitted-tail op is now durable → only NOW set its own
      // inflight vote and try to commit. The own vote could not be cast before this append (it was
      // seeded `oks: 0` in `start_view_as_new_primary`), so the primary never counts a vote for an op
      // it has not durably appended (append-before-ack for the view-change adoption path).
      Some(Pending::AdoptVote(op)) => {
        self.record_own_vote(op.get());
        self.try_commit(now, sb, blocks);
      }
      // a backup's adopted uncommitted-tail op is now durable → send the deferred
      // PrepareOk. No PrepareOk was sent for this op before its append completed (append-before-ack).
      Some(Pending::AdoptAck(op)) => self.send_prepare_ok(op),
      // the peer-repair fill's WAL append is now durable. ONLY NOW expose + apply it: the
      // staged canonical body lands in `self.log`, the repair hole clears, and the held commit resumes.
      // No PrepareOk/own-vote is ever sent for a repair fill (peer repair is not a vote) — this is a
      // pure durability barrier. The body was withheld from `self.log` until here, so it was never in a
      // DVC/StartView/checkpoint nor applied by a concurrent `advance_commit` before its append landed.
      // Safe even if a view change has begun since the fill was staged (the prior comment covers only the
      // PENDING window): `fill_repair` accepted this body only as the CANONICAL value for the op — either
      // committed-vouched (`commit >= op`) OR matched against a kept `Repairing` hole's durable canonical
      // `body_checksum` (a view-change-carried op). A canonical op's body is identical across all views
      // (committed-op survival for the vouched case; the checksum pins the exact body for the carried
      // case), so applying it here is CONSISTENT with adoption — a `select_canonical_log`/`adopt_log` that
      // supersedes the log re-derives this exact canonical body, never a divergent one.
      Some(Pending::RepairFill(rf)) => {
        let op = rf.op();
        self.log.insert(op.get(), rf.into_entry());
        self.repair.remove(&op.get());
        if self.repair.is_empty() {
          self.timers.repair_retry = None;
        }
        // Nack-truncation: a `Present` body just landed for this op (now `Present` in `self.log`), so it
        // is no longer a repair-or-truncate candidate — a holder answered, which PROVES it was committed,
        // and it must NEVER be truncated. Drop any nack tally accrued against it. (No-op when none.)
        self.nack_from.remove(&op.get());
        // Two disjoint cases for the now-durable repaired op, by whether it is committed:
        //
        //   * COMMITTED (`op <= commit_max`): peer-repair is NOT a vote — committed-op survival means
        //     the cluster already decided this op, so casting a vote is meaningless (and would be wrong:
        //     a committed op needs no fresh quorum). Just resume applying the held committed prefix from
        //     where it stalled at this hole. This is the ordinary committed-band repair invariant.
        //
        //   * UNCOMMITTED TAIL (`op > commit_max`, with an inflight entry): a new primary adopted this
        //     op header-only (`Repairing`) from the DVC, so `start_view_as_new_primary` SKIPPED its
        //     `AdoptVote` WAL re-append (`adopt_append` has no body to write for a `Repairing` entry) and
        //     instead made it a peer-repair hole — leaving its seeded inflight entry at `oks: 0`. Now
        //     that `fill_repair` has landed the canonical body durably, the primary holds a durable copy
        //     and MUST cast its own vote (append-before-ack: the vote follows the durable append, exactly
        //     as the `AdoptVote` path does for a body-carrying adopted tail). Without it, with one backup
        //     unavailable the primary collects only one backup `PrepareOk` and can never reach a 2-of-3
        //     quorum — wedging the view despite holding the op durably. The `is_primary()` +
        //     inflight-entry guard scopes this to exactly the adopted-uncommitted-tail case (a backup, or
        //     a primary repairing a committed op, has no such inflight entry to vote on).
        if op.get() > self.commit_max.get()
          && self.is_primary()
          && self.inflight.contains_key(&op.get())
        {
          self.record_own_vote(op.get());
          self.try_commit(now, sb, blocks);
        } else {
          // The hole is filled + durable → resume applying the held committed prefix from where it
          // stalled (committed-repair case, or a backup that owes no vote).
          let target = self.commit_max.get();
          self.advance_commit(now, sb, blocks, target);
        }
      }
      None => {}
    }
  }

  /// Re-submit a WAL append whose completion FAULTED (an embedder [`Wal::submit_append`] contract
  /// violation), rebuilding it from the data the endpoint still holds so the deferred ack/vote/fill
  /// the append owes is retried rather than leaked. The caller has already removed the stale
  /// `Pending` entry + `appending` mark; this re-records both under a fresh `OpId`. Per kind:
  /// - `Ack`/`AdoptVote`/`AdoptAck`: the op's entry is in `self.log` — re-append its `Present` body
  ///   under the current view (the entry survives exactly as long as the pending action does: every
  ///   view transition clears both). An absent or body-`Repairing` entry has no bytes to re-append
  ///   (the op is checkpoint-subsumed and GC-pruned, or awaiting peer-repair), so the action is
  ///   dropped — nothing is owed off an absent body, and the retransmit/repair paths re-drive it.
  /// - `RepairFill`: the staged canonical body rides in the variant itself — re-append it and
  ///   re-stage the same fill, leaving the hole open until the retry lands (exactly as at stage
  ///   time; a still-faulting backend degrades to the solicit-retry cadence, never a silent leak).
  fn resubmit_faulted_append<W: Wal>(&mut self, wal: &mut W, kind: Pending) {
    let op = kind.op();
    let (entry, kind) = match kind {
      Pending::RepairFill(rf) => {
        let entry = rf.into_entry();
        (
          entry.clone(),
          Pending::RepairFill(RepairFill::new(op, entry)),
        )
      }
      kind => {
        let Some(entry) = self.log.get(&op.get()).cloned() else {
          return;
        };
        (entry, kind)
      }
    };
    let Some(body) = entry.body_bytes() else {
      return; // header-only: no bytes to re-append (peer-repair supplies the canonical body)
    };
    // `body_bytes()` yields a `Present` op's bytes or a `Reconfigure` op's `encode_body()` — a faulted
    // re-append of a body-bearing op (incl. a carried reconfiguration op) re-submits its canonical bytes
    // with the header over them, so the deferred ack/vote/fill it owes is retried, never leaked.
    let header = Header::new(op, self.view, entry.client, entry.request, &body);
    let id = self.mint_op_id();
    wal.submit_append(id, op, header, body);
    self.pending.insert(id.get(), kind);
    self.appending.insert(op.get());
  }

  pub(crate) fn on_sb_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
    done: SuperblockDone,
  ) {
    // Recovery checkpoint-READ completions route through the recover loop (restore SM + retry). The ONE
    // exception while Recovering is a checkpoint-WRITE completion that belongs to a STAGED re-persist: the
    // recovery peer-fetch (`on_recover_sync_checkpoint`) stages the `SyncRepersist` two-write sequence and
    // STAYS Recovering, so its `Wrote` completions must reach the `pending_checkpoint` step handling below
    // (routed by the TYPED `pc.kind`) to install + complete recovery — NOT the recover loop, whose `Wrote`
    // arm is a defensive no-op. Peel that staged-write case off here so it reaches the typed handler.
    if self.status.is_recovering() || self.status.is_recovering_head() {
      let staged_step = self.pending_checkpoint.map(|pc| match pc.step {
        CheckpointStep::AwaitSnapshot(sid) => sid,
        CheckpointStep::AwaitRoot(rid) => rid,
      });
      let is_staged_repersist_write =
        matches!(done, SuperblockDone::Wrote(id) if staged_step == Some(id));
      if !is_staged_repersist_write {
        self.on_recover_sb_done(now, sb, blocks, done);
        return;
      }
    }
    // State-sync peer side: outside recovery a `CheckpointRead`/`Fault` means a read WE issued to
    // serve a peer's `RequestSync` completed — ship the durable snapshot (or drop the serving entry
    // on a fault; the requester re-solicits). This is status-gated apart from the recover loop above
    // (that handles reads only while recovering; this handles them while Normal).
    let id = match done {
      SuperblockDone::Wrote(id) => id,
      SuperblockDone::CheckpointRead(cr) => {
        self.serve_sync_checkpoint(sb, cr);
        return;
      }
      SuperblockDone::Fault(id) => {
        // A faulted serve-read: drop the serving entry whose recorded read id matches (the map is
        // keyed by requester) and stay silent — the requester re-solicits and is then served by a
        // fresh read. (A faulted root/checkpoint WRITE outside recovery is not produced by our
        // backends; dropping is defensive.)
        self.sync_serving.retain(|_, s| s.read != id.get());
        return;
      }
    };
    // Durable-view write? (matched first; its OpId never aliases a checkpoint write's.) `take()` —
    // not a by-ref match — because `PendingSbAction::SwapEpoch` carries the (non-`Copy`) successor
    // membership the install moves out; for the unit variants it is equivalent to the prior
    // read-then-clear. Guard the id-match first so a superseded (older) completion is left intact.
    if self.pending_sb.as_ref().is_some_and(|(pid, _)| *pid == id) {
      let (_, action) = self.pending_sb.take().expect("just matched Some");
      match action {
        PendingSbAction::SendDoViewChange => self.send_do_view_change(now),
        PendingSbAction::StartViewAsPrimary => {
          self.start_view_participate(now, sb, blocks);
          // A checkpoint root that completed while this view write was in flight advanced the
          // ring window with the sweep gated (durable-view-before-participate): re-drive the
          // still-unappended adopted tail now that the view is durable. (A backup needs no such
          // call — its whole adoption-append loop runs at its completion, `start_view_acks`.)
          self.retry_unappended_adopted_tail(wal);
        }
        PendingSbAction::AdoptedStartView => self.start_view_acks(wal),
        // A frontier seal has no follow-up: the durable root now carries `commit_max`, which is all
        // the operator awaited before deriving an offline-restart successor.
        PendingSbAction::Seal => {}
        // The commit-first epoch swap's durable root landed → INSTALL the successor membership (the
        // node now participates under the new epoch/voter-set, justified by this durable root) and
        // clear the staging latch. `pending_swap` and this action carry the IDENTICAL `(op, successor)`;
        // clear the latch FIRST so `install_membership` (and any re-entrant `maybe_swap_epoch`) sees no
        // residual staging. The carried `op` is the reconfigure op number captured at stage time.
        PendingSbAction::SwapEpoch(op, successor) => {
          self.pending_swap = None;
          self.install_membership(Some(op), successor);
          // This node CROSSED into the new epoch via its OWN committed reconfigure op (not a sync) — so any
          // owed cross-epoch crossing intent is met. CLEAR it (it re-establishes from a fresh higher-epoch
          // hint if the cluster is ahead of THIS swap). Without this a node that armed the intent from a
          // hint, then crossed via its own swap, could re-arm a stale crossing on its next sync completion.
          self.cross_epoch_intent = None;
          // Force a checkpoint at the current `commit_min` (call it `M`) so the new epoch begins at a
          // checkpoint that EMBEDS the reconfigure op `N` and carries the E+1 membership — making the
          // cross-epoch serve gate `checkpoint_op (M) >= config_install_op (N)` true BY CONSTRUCTION
          // rather than an edge a quiescent donor's lagging checkpoint could withhold forever. The
          // preconditions hold: the SwapEpoch root just landed (the superblock is FREE and
          // `pending_checkpoint` is None — `maybe_swap_epoch` submitted this root only when both were),
          // and the arm runs ONLY when no view change intervened (a transition supersedes the SwapEpoch
          // id on `pending_sb`, so this completion would not have matched), so `log_view == view` still
          // holds. Commit-first ordering gives `M = commit_min >= N` (the swap committed `N`; `commit_min`
          // may have advanced past it before the root landed). GATED on still-Normal: `install_membership`
          // RETIRES this node (status → `Retired`) when the swap removed it from the configuration — a
          // removed node owns no checkpoint. A demotion to learner keeps Normal (a learner still serves /
          // can donate), so it still forces. A swap queued behind this one stays deferred: `maybe_swap_epoch`
          // below re-checks `pending_checkpoint.is_none()`, so this forced checkpoint holds it back.
          if self.status.is_normal() {
            // `force_checkpoint` snapshots the LIVE SM, so — like its two sibling force sites
            // (`maybe_checkpoint`, `maybe_pay_checkpoint_debt`) — it must never run while the SM does not yet
            // hold what `checkpoint_op` names: an owed SM-reconstruct (SM behind M) or a pre-root staged
            // install (SM about to be wholesale-replaced) would bind a WRONG snapshot at op M and
            // serve/persist stale committed state. Today an emergent cross-module fence keeps both flags
            // clear here (a Reconfigure cannot commit while either is set, and the SM-restore-fault
            // completion arm returns before `maybe_swap_epoch` ever submits a swap root), but
            // `maybe_swap_epoch` — the sole swap-root submitter — does not itself check these flags, so pin
            // the invariant locally rather than trust the emergent web; the assert catches any future path
            // that breaks the fence, and the release guard defers safely to the debt path.
            debug_assert!(
              !self.sm_reconstruct_owed() && self.pending_install.is_none(),
              "SwapEpoch-completion force_checkpoint would snapshot a stale / about-to-be-replaced SM at M",
            );
            if !self.sm_reconstruct_owed() && self.pending_install.is_none() {
              // A `false` return (block-store flush failed) — OR a deferral by the guard above — leaves the
              // self-describing debt (`config_install_op = N > checkpoint_op`) owed. That debt is durable in
              // the just-landed SwapEpoch root, so `maybe_pay_checkpoint_debt` (sticky from every
              // commit-advance tail and from recovery, under the same SM guard) re-forces it once the SM is
              // ready + a flush succeeds; the cross-epoch serve gate stays correctly withheld until then.
              // Ignored deliberately.
              let _ = self.force_checkpoint(sb, blocks);
            }
          }
        }
      }
      // A swap that committed while this write was in flight WAITED its turn (`maybe_swap_epoch`
      // deferred it); the superblock is free again now, so give it its slot. No-op when nothing is
      // staged (the common case) or when THIS completion was itself the SwapEpoch (just cleared).
      self.maybe_swap_epoch(sb);
      return;
    }
    // Checkpoint write? Distinguish the two steps by their own minted OpIds.
    if let Some(pc) = self.pending_checkpoint {
      match pc.step {
        CheckpointStep::AwaitSnapshot(sid) if sid == id => {
          // The snapshot is durable → advance the durable root to name the new checkpoint.
          let root_id = self.mint_op_id();
          // The committed band the NEW root names shrinks to `(target_op .. commit]` (the just-
          // checkpointed prefix `[1..=target_op]` now lives in the snapshot, not the band) — pass
          // `pc.target_op` as the floor so the persisted vsr_headers match this root's `checkpoint_op`.
          // Persist the KNOWN-committed frontier `commit_max` as the commit: a root that
          // persisted the lower `commit_min` would let `recover` (which reads `state.commit()` as
          // `commit_max`) read back a LOWERED frontier when this replica is held at a repair hole
          // below `commit_max`. The band headers are the SPARSE canonical set — one per HELD op in
          // `(target_op .. commit]`, skipping holes.
          //
          // commit = max(commit_max, target_op): for an ORDINARY checkpoint `commit_max >= commit_min >=
          // target_op` already (target_op was commit_min at trigger; both only grow), so the `.max` is a
          // no-op — unchanged. For a STATE-SYNC re-persist the
          // destructive install is DEFERRED to `install_sync` (it has NOT advanced `commit_max` yet), so
          // `commit_max` here may sit BELOW `target_op`; the `.max` lifts the persisted commit to the
          // synced checkpoint op. This is correct — a synced checkpoint at `target_op` proves a quorum
          // committed+applied THROUGH it — and reproduces exactly what the old eager `apply_sync`
          // persisted (it set `commit_max = target_op` before this root write). It also keeps the
          // `try_new` `commit >= checkpoint_op` invariant satisfied. The band headers over `(target_op ..
          // max(commit_max, target_op)]` are then empty for a sync (the snapshot subsumes the prefix; any
          // forced-sync held tail is still uncommitted here, so `commit_max < target_op` ⇒ empty band).
          let root_commit = OpNumber::with(self.commit_max.get().max(pc.target_op.get()));
          let headers = self.committed_band_headers(pc.target_op);
          // A CROSS-EPOCH state-sync re-persist (`pending_install.successor` is `Some`) must make the
          // SUCCESSOR membership DURABLE in THIS root — not only install it in memory at completion —
          // or a later crash/wipe would recover the OLD epoch off this root and silently revert the
          // membership install. Stamp the successor exactly as `submit_swap_epoch` does, carrying the
          // VERIFIED predecessor `config_id` so the durable lineage ring matches the in-memory crossing
          // chain (`[verified_prev, own_prior]` on a multi-epoch skip). A same-config (or non-sync)
          // checkpoint stamps the current membership unchanged.
          let successor = matches!(pc.kind, CheckpointKind::SyncRepersist)
            .then(|| {
              self.pending_install.as_ref().and_then(|pi| {
                pi.successor
                  .clone()
                  .map(|m| (m, pi.successor_prev_config_id))
              })
            })
            .flatten();
          let state = match &successor {
            Some((successor, successor_prev_config_id)) => self.durable_root_with_successor(
              self.view,
              self.log_view,
              root_commit,
              pc.target_op,
              pc.checkpoint_id,
              headers,
              successor,
              *successor_prev_config_id,
            ),
            None => self.durable_root(
              self.view,
              self.log_view,
              root_commit,
              pc.target_op,
              pc.checkpoint_id,
              // SPARSE band headers over `(target_op .. min(commit_max, op)]` — bounded by the ACTUAL
              // known-committed frontier `commit_max` (NOT the lifted `root_commit`), so for a sync
              // re-persist (where `commit_max <= target_op`) the band is empty: every op `<= target_op`
              // lives in the snapshot, and any forced-sync held tail above is not yet committed. The
              // root permits a header list SHORTER than `commit` (the prefix is vouched by the snapshot id).
              headers,
            ),
          };
          sb.submit_write(root_id, state);
          self.pending_checkpoint = Some(PendingCheckpoint {
            step: CheckpointStep::AwaitRoot(root_id),
            ..pc
          });
        }
        CheckpointStep::AwaitRoot(rid) if rid == id => {
          // The root is durable → the checkpoint is COMPLETE. Route by the TYPED `pc.kind` — whether
          // THIS root is a state-sync re-persist or an ordinary checkpoint. Matching on the kind carried
          // in the completion token (NOT `self.sync.is_some()`) makes the routing footgun structurally
          // impossible: a sync can be merely SOLICITED (armed, no staged install) while an ORDINARY
          // checkpoint completes, and routing on `self.sync` would misroute that ordinary completion to
          // the install branch — never advancing `checkpoint_op`, clearing the solicited sync, and
          // livelocking the laggard. With the kind there is no ambient `sync` bool to confuse. (Only one
          // checkpoint is ever in flight — `pending_checkpoint.is_some()` blocks both `maybe_checkpoint`
          // and a second `apply_sync` — so exactly one kind applies to this root.)
          self.pending_checkpoint = None;
          // The new checkpoint root is durable — record its SM DAG root AND its session-table DAG root as
          // the live roots the block GC marks from (both kinds: an ordinary produce and a synced
          // re-persist name a real `sm_root` + `sessions_root`).
          self.checkpoint_sm_root = Some(pc.sm_root);
          self.checkpoint_sessions_root = Some(pc.sessions_root);
          match pc.kind {
            CheckpointKind::SyncRepersist => {
              // SYNC re-persist. The synced checkpoint root is now durable (the COMMIT POINT), so INSTALL
              // the synced state via `install_sync`. BOTH paths defer the install to here: the Normal
              // state-sync path (already Normal) and the RECOVERY peer-fetch path
              // (`on_recover_sync_checkpoint`, which STAGED the re-persist and STAYED Recovering), so
              // `pending_install` is `Some` and the install runs now, atomically with the durable root. The
              // recovery path then flips to Normal via `complete_recovery` below.
              if let Some(install) = self.pending_install.take() {
                // The frontier advances regardless; only the SM-content restore can fail (a checkpoint
                // block bit-rotted/was misdirected between the block-fetch drain and this verify-on-read
                // restore). On that fault `install_sync` has ALREADY advanced the pointer to M (so NOTHING
                // is rewound — in-memory `checkpoint_op` now equals the durable root) and stashed an
                // `sm_reconstruct` obligation; the SM still holds the OLD content. RE-ARM the obligation's
                // block-fetch to re-pull M's bad block (which `write_block` overwrites), so the SAME M's DAG
                // re-drains and retries `sm.restore` DIRECTLY against the unchanged M pointer — no re-stage,
                // never waiting for a fresh, possibly-older reply. The obligation GATES serving M / applying
                // ops over the un-restored SM until the retry succeeds. SKIP the success tail (GC, the
                // completion event, the Normal/recovery flip): none of it is justified until the SM holds M.
                if let Err(_e) = self.install_sync(wal, blocks, install) {
                  self.rearm_sm_reconstruct_retry(now, blocks);
                  return;
                }
              }
              // The SM holds M's content (a clean first-try restore) → run the shared sync-completion tail
              // (GC, the completion event, the sync teardown, the Normal/recovery flip, the crossing re-arm).
              // The retry path (`retry_sm_reconstruct`) reaches the IDENTICAL tail once a re-pull finally
              // reconstructs the SM, so it lands at exactly this point.
              self.complete_state_sync(now, sb, blocks);
              // The install advanced `checkpoint_op` (the ring window slid forward): re-drive any
              // adopted-tail append that was skipped over the old window. (No-op unless the tail
              // above the completion exit's frontier holds an un-durable body — see the fn doc.)
              self.retry_unappended_adopted_tail(wal);
            }
            CheckpointKind::Ordinary => {
              // ORDINARY checkpoint: advance the in-memory checkpoint_op, then GC the WAL + per-op caches
              // below the prune floor. GC runs AFTER the durable root so the recovery point is
              // the new checkpoint; a lost/failing prune is then safe (a later checkpoint re-prunes). A
              // sync may be concurrently SOLICITED (`self.sync` armed but not staged) — it is
              // deliberately left intact here (this root is NOT its re-persist), so it completes on its
              // own handshake.
              self.advance_checkpoint_op(pc.target_op);
              // Observability: this replica's own checkpoint at `target_op` is root-durable. (A sync
              // re-persist's root reports as `StateSyncCompleted` above instead.) Scalar copy only.
              self
                .events
                .push_back(Event::CheckpointDurable(pc.target_op));
              self.run_gc(wal);
              // Prune SM checkpoint blocks unreachable from the now-durable checkpoint root (mark-and-
              // sweep from the live roots). Runs AFTER the durable root, so a freed block is provably
              // unreferenced by any live checkpoint.
              self.gc_blocks(blocks);
              // `checkpoint_op` advanced (the ring window slid forward): re-drive any adopted-tail
              // append that was skipped over the old window.
              self.retry_unappended_adopted_tail(wal);
            }
          }
        }
        _ => {} // a stale/superseded completion (e.g. from before a view change) — ignore
      }
    }
    // A checkpoint root completing (the `AwaitRoot` arm above cleared `pending_checkpoint`) frees the
    // superblock — so a reconfiguration that committed while the checkpoint was in flight, and whose
    // SwapEpoch root `maybe_swap_epoch` deferred behind it, now gets its slot. No-op when no swap is
    // staged (the common case) or a write is still in flight.
    self.maybe_swap_epoch(sb);
  }

  /// The SHARED state-sync completion tail: run once the SM holds the synced checkpoint `M`'s content (and
  /// `self.checkpoint_op == M`). Two callers reach it — the [`Self::on_sb_done`] `SyncRepersist` arm on a
  /// clean first-try restore, and [`Self::retry_sm_reconstruct`] when a re-pull finally reconstructs the SM
  /// after a post-root restore fault — so the completion is IDENTICAL whether the SM restored on the first
  /// attempt or after a retry. It GCs the now-unreachable SM blocks, signals the sync complete, tears down
  /// the sync handshake, and completes recovery (recovery peer-fetch path) or resumes as a Normal backup.
  pub(crate) fn complete_state_sync<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
    // The synced checkpoint is durable + installed: prune SM blocks unreachable from the new durable
    // checkpoint root (the old checkpoint's no-longer-referenced blocks). The sync's own block-fetch
    // already drained + cleared, so no in-flight sync-target root is live.
    self.gc_blocks(blocks);
    // Observability: the synced checkpoint is installed AND durable — the sync is complete (covers both the
    // deferred Normal install and the deferred recovery install). `self.checkpoint_op` is M (advanced by
    // the install). Scalar copy only.
    self
      .events
      .push_back(Event::StateSyncCompleted(self.checkpoint_op));
    // Resume as a Normal backup: clear the sync bookkeeping + solicit timer and re-arm timers. (`self.sync`
    // is `Some` here — the sync's re-persist completing means its handshake is the live one; this is the
    // SAME sync whose `apply_sync` staged this root. Any block-fetch was already cleared when its drain fed
    // this sync — cleared here again as the paired teardown.)
    let forced = self.sync.is_some_and(|s| s.forced);
    self.sync = None;
    self.block_fetch = None;
    self.timers.sync_solicit = None;
    // Non-vacuity signal: a state-sync just fully applied + became durable.
    self.state_syncs_applied += 1;
    // Non-vacuity signal: distinguish a FORCE-sync (the escalation that recovers a pruned committed hole
    // below the quorum checkpoint) from an ordinary `> self.op` sync.
    if forced {
      self.forced_syncs_applied += 1;
    }
    // The recovery peer-fetch path STAGED this re-persist and stayed Recovering (deferring its install +
    // flip to here); the synced state is now durable + reconstructed, so complete recovery — flip to Normal
    // and abdicate/rebuild/resume. The Normal deferred-sync path is already Normal, so it just resumes as a
    // backup.
    if self.status.is_recovering() {
      // The escape carried the recovery FAULTY verdicts across the staged install
      // (`sync_carried_faulty` — the read phase found the head occupied but with no verifiable
      // identity and no root witness, possibly alongside interior faulty slots, and the
      // awaiting-checkpoint gate preempted `recover_progress`'s `RecoveringHead` decision). Filter out
      // what the installed checkpoint SUBSUMED (the snapshot owns `[1..=checkpoint_op]`); if the head
      // is among the survivors, resume the preempted decision now: `RecoveringHead` — do not
      // participate, solicit the canonical head (a peer's `RecoveryResponse`/`StartView`
      // re-establishes it and adoption returns to Normal) — instead of completing `Normal` holding an
      // op with no identity anywhere (a later `Prepare` would be blind-re-acked and the DoViewChange
      // would advertise an unheld head). The FULL surviving set is restored into the re-armed
      // `RecoverState`, not just the head: the reform-escalation gate (`committed_band_intact`) reads
      // `rec.faulty` to refuse same-epoch reformation while a COMMITTED-band faulty slot remains — a
      // committed op this replica cannot vouch would be omitted from its DoViewChange — so dropping
      // the interior verdicts would let an all-restart quorum escalate into exactly that loss. A
      // clean-head remainder (interiors only, or nothing) completes normally: the interior slots were
      // already dropped to on-demand repair holes at the escape's finalize, the pre-existing Normal
      // semantics for non-head faults.
      let carried: std::collections::BTreeSet<u64> = core::mem::take(&mut self.sync_carried_faulty)
        .into_iter()
        .filter(|&op| op > self.checkpoint_op.get())
        .collect();
      if carried.contains(&self.op.get()) {
        // Re-arm the recovery bookkeeping the RecoveringHead machinery reads (the verdicts stay
        // flagged until adoption clears `recover`), exactly as `recover_progress`'s faulty-head
        // branch leaves it.
        self.recover = Some(RecoverState {
          faulty: carried,
          ..RecoverState::default()
        });
        self.set_status(Status::RecoveringHead);
        self.arm_timers(now);
        self.send_recovery(now);
        return;
      }
      self.complete_recovery(now, sb, blocks);
    } else {
      self.arm_timers(now);
    }
    // RE-ARM the crossing from the PERSISTENT intent. `self.sync` was just cleared (above), but a
    // higher-epoch trigger that arrived AFTER this sync STAGED its install only rewrote the (now-gone)
    // `SyncState` — the staged install completed and settled the node WITHOUT crossing. The intent OUTLIVES
    // the sync: re-arm a crossing sync to it AFRESH here so a non-crossing install that completed while a
    // crossing was owed immediately re-pins the crossing, instead of waiting for another trigger to arrive.
    // Fires EXACTLY when the intent is still owed AND the node is Normal: a crossing install MET the goal
    // and cleared the intent (`install_sync`'s successor branch), so it sees `None` here — no double-arm; a
    // recovery completion that abdicated to ViewChange is not Normal — no re-arm into a transition.
    // `self.sync.is_none()` holds (just cleared), so the `arm_sync` fresh-arm precondition is satisfied;
    // `arm_sync` only re-solicits (no re-entry into `on_sb_done`), so this cannot recurse.
    if self.status.is_normal()
      && let Some(intent) = self.cross_epoch_intent
    {
      self.arm_sync(now, intent, true, true);
    }
  }

  /// If `commit_min` has reached the next checkpoint boundary and no superblock write is pending,
  /// begin a checkpoint: snapshot the SM + client sessions, write the snapshot, and stage step 2.
  ///
  /// Called at the tails of `try_commit` and `advance_commit` — the only two sites that advance
  /// `commit_min`. The snapshot reflects the SM state at `commit_min` exactly (all ops `<= commit_min`
  /// applied, none above), so the checkpoint covers a committed+applied prefix; `target_op = commit_min`
  /// keeps the snapshot↔op correspondence exact even when a batch commit jumps past the boundary.
  pub(crate) fn maybe_checkpoint<B: Superblock>(
    &mut self,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
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
    // Exclusion: never start an ordinary checkpoint while an SM-RECONSTRUCT obligation is owed. The post-
    // root restore faulted, so `self.checkpoint_op == M` but the SM still holds the OLD content; a
    // checkpoint here (`force_checkpoint` → `self.sm.checkpoint`) would snapshot the WRONG (old) SM under
    // the forward op M. The retry reconstructs the SM at M, after which the cadence re-triggers cleanly.
    if self.sm_reconstruct_owed() {
      return;
    }
    // Exclusion: never start an ordinary checkpoint while a state-sync install is OWED — whether STAGED (its
    // own SyncRepersist `pending_checkpoint`, already excluded above) or RETAINED-but-not-staged (a flush
    // fault left it owed with NO checkpoint in flight). The install will advance `self.checkpoint_op` to the
    // synced point and replace the SM; an ordinary checkpoint racing it would snapshot the about-to-be-
    // replaced SM AND advance `checkpoint_op` + the live `checkpoint_sm_root` past the point the still-owed
    // install names, then its `gc_blocks` could leave the install incoherent. The install's local cadence
    // ([`Self::flush_and_stage_install`]) completes it, after which the ordinary cadence re-triggers cleanly.
    if self.pending_install.is_some() {
      return;
    }
    let boundary = self.checkpoint_op.get() + self.config.checkpoint_ops();
    if self.commit_min.get() < boundary {
      return;
    }
    // A `false` return means the block-store flush failed → no checkpoint was submitted. The cadence
    // re-evaluates on the next commit-advance (`commit_min` only grows), so the checkpoint is simply
    // re-attempted; there is nothing to roll back. Ignored deliberately.
    let _ = self.force_checkpoint(sb, blocks);
  }

  /// The COMMITTED dedup projection of the live session table, for a checkpoint. The live `self.clients`
  /// carries state a checkpoint must NOT persist: PROVISIONAL rows (`last_op == 0`, minted at accept time
  /// or by a new primary's watermark backfill, with no committed reply) and ACCEPT-AHEAD watermarks
  /// (`request` is bumped when an op is merely ACCEPTED, before it commits — so a known client's `request`
  /// can name an op above the committed prefix). The live table self-corrects both when their op fails to
  /// commit (a view transition purges provisionals; a repair-timeout rolls accept-ahead watermarks back to
  /// the reply-backed floor), but a checkpoint captured BEFORE those corrections would — if carried across
  /// a view change and later restored on recovery / state-sync — resurrect a dedup watermark for a
  /// TRUNCATED request, and the client's retry of it would dedup as an in-flight duplicate with no cached
  /// reply, hanging forever.
  ///
  /// So project each row to the dedup state derivable from the committed prefix alone: drop any row with
  /// no committed reply, and lower `request` to the applied request (`reply.0`). A still-uncommitted
  /// request that LATER commits re-applies on recovery and re-bumps the watermark identically, so the
  /// projection drops only the truncate-able surplus, never committed dedup state.
  pub(crate) fn committed_session_projection(&self) -> std::collections::BTreeMap<u128, Session> {
    self
      .clients
      .iter()
      .filter_map(|(&client, s)| {
        let (applied_request, _) = s.reply.as_ref()?;
        Some((
          client,
          Session {
            request: *applied_request,
            reply: s.reply.clone(),
            last_op: s.last_op,
          },
        ))
      })
      .collect()
  }

  /// Begin an ORDINARY checkpoint at `commit_min` UNCONDITIONALLY — the post-cadence-gate body of
  /// [`Self::maybe_checkpoint`] with the three guards (status/`log_view`, in-flight exclusion, cadence)
  /// STRIPPED. The caller owns the preconditions: status Normal with `log_view == view` and a FREE
  /// superblock (`pending_sb.is_none() && pending_checkpoint.is_none()`).
  ///
  /// Two callers force a checkpoint OFF the cadence — both at a point where the reconfigure op `N` must
  /// become checkpoint-covered so the cross-epoch sync serve gate (`checkpoint_op >= config_install_op`)
  /// holds: the [`Self::on_sb_done`] `SwapEpoch` arm (the live swap, just after the durable swap root
  /// landed and `install_membership` ran) and [`Self::maybe_pay_checkpoint_debt`] (a crash between the
  /// swap root and this checkpoint left a durable root with `config_install_op = N > checkpoint_op`, and
  /// recovery drives the band to `>= N` then forces the owed checkpoint). The ordinary cadence path is
  /// byte-identical to the prior inline body.
  ///
  /// Returns whether a checkpoint was SUBMITTED. It is `false` ONLY when the block-store durability
  /// barrier ([`BlockStore::flush`]) failed: the checkpoint names blocks that are not durable, so no
  /// pointer is advanced (no torn checkpoint) and the caller leaves the durable state unchanged; the
  /// cadence / debt-pay / commit-advance re-forces it next time. On success it is `true`.
  #[must_use = "a force_checkpoint that returns false did not submit (block-store flush failed); the \
                caller must not assume a checkpoint is in flight"]
  pub(crate) fn force_checkpoint<B: Superblock>(
    &mut self,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) -> bool {
    // Checkpoint at `commit_min` (a committed+applied boundary), not at the raw `boundary` op:
    // `commit_min` may have jumped past `boundary` in a batch commit, and the SM has applied through
    // `commit_min` (apply is forward-only) — so the checkpoint reflects state through `commit_min`.
    let target_op = self.commit_min;
    // Write the SM checkpoint as a content-addressed block DAG into the block store and bind its
    // root into the envelope so `checkpoint_id` covers it: the written op and the op hashed alongside
    // the root are the SAME, so a later restore can prove they agree. The envelope is now frame-bounded
    // (op + sessions + a 16-byte root); a laggard state-syncs the SM state by fetching only the blocks
    // it is missing from the DAG rooted here.
    let sm_root = self.sm.checkpoint(blocks);
    // Write the proto-owned CLIENT SESSION TABLE into the same block store as its own content-addressed
    // DAG and bind its root into the envelope: the table is no longer inline, so the envelope is always
    // frame-bounded (op + two 16-byte roots) regardless of session count or cached-reply size. A laggard
    // state-syncs the table by fetching only the session blocks it is missing from the DAG rooted here.
    // Project the live table to its COMMITTED dedup state before encoding: drop provisional rows (no
    // committed reply) and lower each accept-ahead `request` watermark to the applied request (`reply.0`).
    // A checkpoint is committed state, so it must not persist a watermark for an op above `target_op` that
    // a later view change may TRUNCATE — restoring such a row on recovery / state-sync would dedup the
    // client's retry as an in-flight duplicate with no cached reply (a permanent hang). The live table
    // self-corrects (a view transition purges provisionals, a repair-timeout rolls accept-ahead watermarks
    // back), but a checkpoint captured before those corrections must not outlive them. See
    // [`Self::committed_session_projection`].
    let sessions_root =
      super::session_blocks::encode_sessions(&self.committed_session_projection(), blocks);
    // DURABILITY BARRIER: the blocks this checkpoint NAMES must be durable BEFORE the superblock pointer
    // that references them. `write_block` is infallible with no durability guarantee, so `flush` is what
    // makes the SM + session DAGs durable; ordering it here — strictly before `submit_write_checkpoint`
    // — closes the strand where a crash after the durable checkpoint pointer but before the block
    // contents would leave the pointer naming MISSING blocks (committed state lost on restart / after a
    // peer GC). On a flush fault DO NOT advance: submit no checkpoint write and return, leaving
    // `pending_checkpoint` clear so no torn checkpoint exists; the cadence (or the debt-pay / commit-advance
    // tail) re-forces it next time, exactly like a lost WAL prune. Treated as data, mirroring a faulted read.
    if self.blocks_flush_failed(blocks) {
      return false;
    }
    let envelope = Self::encode_checkpoint(target_op, sm_root, sessions_root);
    let checkpoint_id = crate::checkpoint_id(&envelope);
    let id = self.mint_op_id();
    sb.submit_write_checkpoint(id, target_op, envelope);
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op,
      checkpoint_id,
      sm_root,
      sessions_root,
      step: CheckpointStep::AwaitSnapshot(id),
      kind: CheckpointKind::Ordinary, // not a state-sync re-persist
    });
    true
  }

  /// Flush the block store's pending writes to durability and report whether the barrier FAILED. A
  /// `true` return means the just-written checkpoint blocks are NOT durable, so the caller must NOT
  /// advance the checkpoint pointer (no torn checkpoint that names un-flushed blocks). Centralises the
  /// barrier so the ordinary-checkpoint path and the state-sync re-persist path treat a flush fault
  /// identically. (`flush` is `Ok(())` for an in-memory store, so this is a no-op there.)
  pub(crate) fn blocks_flush_failed(&self, blocks: &mut dyn BlockStore) -> bool {
    blocks.flush().is_err()
  }

  /// Pay down the self-describing CHECKPOINT DEBT a crash in the swap-checkpoint window leaves.
  ///
  /// The live epoch swap writes the SwapEpoch durable root (`config_install_op = N`) and THEN, as a
  /// SEPARATE write, forces a checkpoint at `M >= N` (the [`Self::on_sb_done`] `SwapEpoch` arm). A crash
  /// BETWEEN those two writes leaves a durable root with the E+1 membership AHEAD of the checkpoint:
  /// `config_install_op = N` but `checkpoint_op < N`. That inequality IS the debt — already durable in
  /// the superblock v6 root, needing no new field — and a donor in that state withholds the E+1
  /// membership from a cross-epoch laggard (the `checkpoint_op >= config_install_op` XI-b serve gate
  /// fails), so it MUST converge to `checkpoint_op >= config_install_op` on its own.
  ///
  /// Crucially this must DRIVE ITSELF with NO traffic: a freshly-recovered quiescent backup sits at
  /// `commit_min == checkpoint_op < N` with no incoming Commit heartbeat to advance it, so it would
  /// withhold the membership forever. So this routine, gated to a settled-Normal node with a free
  /// superblock and an OWED debt, (a) PROACTIVELY drives the committed band forward —
  /// `advance_commit(commit_max)` applies the held band and repairs any hole via the existing peer-repair
  /// path — so `commit_min` climbs toward `config_install_op` without a heartbeat; then (b) once
  /// `commit_min >= config_install_op`, forces the owed checkpoint at `commit_min`. The forced
  /// checkpoint's root landing advances `checkpoint_op` (the existing [`Self::on_sb_done`] completion),
  /// clearing the debt — `checkpoint_op >= config_install_op` becomes durable.
  ///
  /// Sticky by construction: it is called from [`Self::complete_recovery`] (the no-traffic kick) AND from
  /// every commit-advance tail (`try_commit` / `advance_commit`), so a debt that could NOT be paid at
  /// recovery (a band hole awaiting peer-repair held `commit_min` below `N`) re-checks and pays the
  /// instant the repair fill carries commit through `N`. It also survives a view change / a recovering-
  /// primary abdication: the debt is implicit in the durable root, so it is simply re-evaluated whenever
  /// the node next settles Normal and commit advances.
  ///
  /// The proactive `advance_commit` is RE-ENTRANCY-guarded ([`Self::paying_checkpoint_debt`]): reached
  /// FROM a commit-advance tail it would otherwise re-enter `advance_commit` without bound; the flag makes
  /// the inner advance a no-op (the outer advance already drove commit as far as the held log permits).
  pub(crate) fn maybe_pay_checkpoint_debt<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
    // No debt unless the durable root names a membership AHEAD of the checkpoint.
    if self.config_install_op.get() <= self.checkpoint_op.get() {
      return;
    }
    // Never force a checkpoint while an SM-RECONSTRUCT obligation is owed OR a state-sync install is OWED
    // (staged or retained-but-not-staged after a flush fault): `force_checkpoint` snapshots the live SM,
    // which in the reconstruct case still holds the OLD content (the post-root restore faulted while
    // `checkpoint_op == M`) and in the install case is about to be REPLACED by the synced state — either way
    // it would write a checkpoint from the wrong SM and advance `checkpoint_op` past the point the owed
    // install names. (A synced `checkpoint_op == M` is `>= config_install_op` for both same-config and
    // crossing installs, so the debt is normally already false here — this is the defensive backstop that
    // keeps `force_checkpoint` off the un-restored / about-to-be-replaced SM.)
    if self.sm_reconstruct_owed() || self.pending_install.is_some() {
      return;
    }
    // Settled-Normal with a free superblock — the same fence `maybe_checkpoint`/`maybe_swap_epoch` use,
    // so the forced checkpoint never races a durable-view or in-flight-checkpoint write. A non-Normal /
    // mid-transition node re-checks here once it next resumes Normal and commit advances (sticky).
    if !self.status.is_normal() || self.log_view.get() != self.view.get() {
      return;
    }
    if self.pending_sb.is_some() || self.pending_checkpoint.is_some() {
      return;
    }
    // (a) Drive the committed band forward with NO traffic so a quiescent recovered node still climbs
    // `commit_min` toward `config_install_op` (any hole repairs on the existing peer-repair path, and a
    // later advance — after the fill lands — re-enters here and resumes). Guarded against the
    // commit-advance-tail re-entry: the outer advance already moved commit as far as the held log allows.
    if !self.paying_checkpoint_debt {
      self.paying_checkpoint_debt = true;
      self.advance_commit(now, sb, blocks, self.commit_max.get());
      self.paying_checkpoint_debt = false;
    }
    // (b) Once the band reached the reconfigure op, force the owed checkpoint at `commit_min` (>= N), so
    // its durable root advances `checkpoint_op` to `>= config_install_op` and clears the debt. Re-check
    // `pending_checkpoint.is_none()`: a nested debt-pay (reached via the proactive `advance_commit`'s own
    // tail) may have already forced it — never submit a second concurrent checkpoint.
    if self.commit_min.get() >= self.config_install_op.get() && self.pending_checkpoint.is_none() {
      // A `false` return means the block-store flush failed → the owed checkpoint was NOT submitted, so
      // the debt (`config_install_op > checkpoint_op`) STAYS owed. This routine is sticky — it re-runs
      // from every commit-advance tail and from `complete_recovery` — so it re-forces the moment a later
      // flush succeeds; nothing is advanced now and the cross-epoch serve gate stays correctly withheld.
      let _ = self.force_checkpoint(sb, blocks);
    }
  }

  // Physical bounded-WAL slot reuse + stall-before-wrap (the `Wal` exposes a capacity; the
  // primary refuses to assign an op that would overwrite an un-pruned slot below `quorum_checkpoint_op`).
  // `run_gc` below is the *logical* safety half (the
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
  ///    needs the freed slot. This is exactly why GC is safe NOW but was not before.
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
  /// (Formerly-residual strand, now CLOSED by the force-state-sync escalation
  /// ([`Self::maybe_force_sync`]): a `Normal` replica holding a PERMANENTLY-faulty hole at `N` *below
  /// its own head but above its own checkpoint*, where every replica that ever held `N` has pruned it
  /// — a correlated multi-replica permanent fault on a single pruned op. Its head `>=` the cluster
  /// checkpoint, so the `> self.op` sync trigger does NOT fire, and no peer can serve the pruned op.
  /// This is reachable under the fault envelope (GC + permanent disk-faults + partitions). The
  /// escalation detects it via `quorum_checkpoint_op() >= N` (the op is now available ONLY as part of
  /// a checkpoint snapshot, every quorum member pruned the prepare), clears the doomed hole, and forces
  /// a `RequestSync` to the quorum checkpoint (`>= N`) — recovering `N` from the snapshot that subsumes
  /// it. Liveness-only (no committed op is ever lost or rewritten — `N` survives in every checkpoint
  /// snapshot, swapping a `RequestPrepare`-for-a-pruned-op for a satisfiable `RequestSync`). See
  /// [`Self::maybe_force_sync`]'s safety proof.)
  /// The PRIMARY prune floor: `min(self.checkpoint_op, quorum_checkpoint_op())` — the highest op a
  /// `quorum` has both committed AND folded into its durable checkpoint, so every op at/below it is
  /// recoverable from a snapshot cluster-wide and its WAL slot is safe to physically reuse. This is THE
  /// single definition shared by two readers:
  /// - [`run_gc`](Self::run_gc)'s PRIMARY branch — the LOGICAL free: it `prune`s WAL slots `<= floor`.
  /// - the PHYSICAL stall ([`Self::on_request`]) — op-assignment refuses to mint an op whose ring
  ///   slot still holds an UN-pruned op, i.e. it stalls when `next_op - floor > wal.capacity()`.
  ///
  /// Keeping ONE definition means the slot a bounded WAL physically reuses is exactly the slot `run_gc`
  /// has authorized freeing — the stall can never let op `K + N` overwrite op `K`'s slot before `K <=
  /// floor` (checkpoint-subsumed on a quorum). Conservative: an unheard peer counts as 0 in
  /// `quorum_checkpoint_op`, so a fresh primary's floor is low (it frees nothing / stalls earlier) until
  /// fresh `PrepareOk`s raise it — never freeing or wrapping an op too early. (A backup's `run_gc` uses
  /// its OWN `checkpoint_op`, NOT this quorum floor — see `run_gc`'s doc — and a backup never assigns
  /// ops, so the stall is primary-only and reads this directly.)
  pub(crate) fn prune_floor(&self) -> OpNumber {
    OpNumber::with(
      self
        .checkpoint_op
        .get()
        .min(self.quorum_checkpoint_op().get()),
    )
  }

  fn run_gc<W: Wal>(&mut self, wal: &mut W) {
    let floor = if self.is_primary() {
      self.prune_floor().get()
    } else {
      // A backup prunes below its OWN checkpoint (it serves no peer WAL reads the cluster relies on);
      // gating it on the quorum floor would never prune → unbounded WAL/log. See the method doc.
      self.checkpoint_op.get()
    };
    if floor == 0 {
      return; // nothing safe to free yet (no quorum-acknowledged checkpoint / no own checkpoint)
    }
    // Free the durable WAL slots the snapshot subsumes. `prune(below)` frees slots strictly below
    // `below`; to free ops `<= floor` pass `below = floor+1`. KEPT site-specific (NOT folded into the
    // shared trim): `install_sync` deliberately prunes `< checkpoint_op` (NOT `<= checkpoint_op`),
    // retaining the slot AT its synced checkpoint so a no-held-tail sync leaves `wal.op_head() ==
    // checkpoint_op` rather than an empty WAL — a different prune FLOOR for a different reason, so it
    // cannot share this line. (run_gc has no such WAL-head constraint: its `floor <= checkpoint_op`
    // ops are all in the snapshot, so freeing the boundary slot too is safe.)
    wal.prune(OpNumber::with(floor + 1));
    // Trim the in-memory `log` cache the snapshot subsumes (the canonical "the checkpoint covers it,
    // drop it" rule shared with `install_sync` — see [`Self::trim_log_to_checkpoint`]). The witness
    // floor is `self.checkpoint_op` (the durable snapshot this GC relies on).
    self.trim_log_to_checkpoint(floor, self.checkpoint_op.get());
    // Trim the primary pipeline + reorder buffer to `(floor .. head]`. KEPT site-specific (NOT folded):
    // `install_sync` fully `clear()`s both (a sync TEARS DOWN the whole pipeline — it lands as a backup
    // and a far-future buffered prepare ABOVE the synced checkpoint must NOT survive), whereas run_gc
    // only RETAINs the live tail above the GC floor for an ongoing replica. Same per-op caches, but a
    // genuinely different operation (retain-above-floor vs full clear), so each keeps its own. SAFE:
    // the apply loops read only ops `> commit_min >= checkpoint_op >= floor`, so nothing they touch is
    // removed; the freed entries are committed+checkpointed (durable in the SM snapshot).
    self.inflight.retain(|&op, _| op > floor);
    self.buffer.retain(|&op, _| op > floor);
    // `clients` is intentionally NOT trimmed here: it grows per-CLIENT (bounded by the active client
    // set), not per-op, and dropping a LIVE session risks a dedup miss for a retry whose cached reply
    // is still needed. Every session was captured in the checkpoint envelope, so a crash + recover
    // rebuilds them; the unbounded-in-op structures (WAL, log, inflight, buffer) are the ones GC'd.
  }

  /// Prune checkpoint blocks unreachable from the LIVE roots (the block-store analogue of
  /// [`Self::run_gc`]'s WAL prune). The live roots are: this replica's latest durable checkpoint's TWO
  /// DAG roots (`checkpoint_sm_root` for the SM state, `checkpoint_sessions_root` for the client-session
  /// table), both DAG roots of any IN-FLIGHT state-sync the laggard is fetching (the live `block_fetch`'s
  /// `sm_root` / `sessions_root`), AND both DAG roots of any RETAINED state-sync install (`pending_install`)
  /// whose drained DAG is not yet durable as our own checkpoint — a sync target's partially-fetched blocks
  /// AND a verified install's fully-drained blocks must survive until it installs (including the window
  /// where a flush fault leaves the install owed-but-not-staged). The store walks the reachable set from
  /// these roots and frees the rest. Called only AFTER the durable checkpoint root that establishes the new
  /// live set has landed, so no block reachable from a live checkpoint is ever freed; if we hold no durable
  /// root yet (both are `None`, no fetch in flight, no install retained), GC is skipped this cycle (nothing
  /// is safely prunable). The default `BlockStore::gc` is a no-op, so a bounded/never-GC store is correct.
  ///
  /// The two DAGs are GC'd by SEPARATE TYPED mark walks, NOT one union resolver. The SM roots
  /// (`checkpoint_sm_root` + the in-flight `sm_root`) are followed ONLY by `S::block_references`; the
  /// session roots (`checkpoint_sessions_root` + the in-flight `sessions_root`) ONLY by
  /// `session_block_references`. A session block is never handed to the SM resolver (nor vice versa) —
  /// `StateMachine::block_references` contracts only to parse the SM's OWN blocks, so a strict embedder
  /// parser handed a proto-owned session block could panic or return bogus edges. The store unions the
  /// two MARKED SETS: a block reachable from EITHER DAG survives, and because each kind's true children
  /// are always included by its own resolver, no reachable block is ever freed (over-marking only ever
  /// retains an extra block; under-marking is impossible).
  pub(crate) fn gc_blocks(&mut self, blocks: &mut dyn BlockStore) {
    // TYPED roots: an SM set and a session set, each followed by its own resolver. The in-flight
    // `block_fetch` roots are split the SAME typed way (its `sm_root` into the SM set, `sessions_root`
    // into the session set) — a sync target's partially-fetched blocks of either kind survive until
    // it installs.
    let mut sm_roots = std::vec::Vec::new();
    let mut session_roots = std::vec::Vec::new();
    if let Some(root) = self.checkpoint_sm_root {
      sm_roots.push(root);
    }
    if let Some(root) = self.checkpoint_sessions_root {
      session_roots.push(root);
    }
    if let Some(bf) = self.block_fetch.as_ref() {
      sm_roots.push(bf.sm_root);
      session_roots.push(bf.sessions_root);
    }
    // A RETAINED state-sync install (`pending_install`) names a checkpoint whose DAG is fully drained into
    // the store but not yet durable as our own checkpoint root — split its two roots the SAME typed way so
    // an ordinary checkpoint GC between staging and the install completing (or while a flush fault leaves the
    // install owed-but-not-staged) never sweeps the blocks the install will re-persist. Once it completes,
    // its roots become `checkpoint_sm_root`/`checkpoint_sessions_root` above and `pending_install` is None.
    if let Some(pi) = self.pending_install.as_ref() {
      sm_roots.push(pi.sm_root);
      session_roots.push(pi.sessions_root);
    }
    if sm_roots.is_empty() && session_roots.is_empty() {
      return; // no durable root established yet — nothing is safely prunable.
    }
    blocks.gc(&[
      crate::block_store::BlockDagWalk {
        roots: &sm_roots,
        references: &|block| S::block_references(block),
      },
      crate::block_store::BlockDagWalk {
        roots: &session_roots,
        references: &super::session_blocks::session_block_references,
      },
    ]);
  }

  /// Free the in-memory `log`-cache entries a durable checkpoint snapshot subsumes: drop every op
  /// AT/BELOW `floor`, retaining the un-checkpointed tail `(floor .. head]`. This is the SINGLE
  /// canonical "the snapshot covers it, so the log cache no longer needs it" trim, shared by
  /// post-checkpoint GC ([`Self::run_gc`]) and the state-sync install ([`Self::install_sync`]) — the
  /// one piece those two sites provably perform IDENTICALLY (both `log.retain(|op| op > floor)` behind
  /// the same committed-survival witness), extracted so a future change to the log prune FLOOR can
  /// never silently apply to one site but not the other (a latent-drift concern).
  ///
  /// `checkpoint_floor` is the durable/just-restored checkpoint the SITE relies on for the
  /// committed-survival witness (passed through to [`Self::assert_committed_survives`]): `run_gc` passes
  /// `self.checkpoint_op` (its durable snapshot); `install_sync` passes its LOCAL synced checkpoint
  /// (the deferred-advance leaves `self.checkpoint_op` STALE until the caller records the new
  /// root, so the install's own witness is the snapshot it just restored). Naming it per call keeps the
  /// witness exact and STRONG.
  ///
  /// The remaining post-checkpoint work is genuinely DIFFERENT per site and stays at each call site:
  /// `run_gc` prunes the WAL `<= floor` + RETAINs the live `inflight`/`buffer` tail above the floor (an
  /// ongoing replica's incremental GC); `install_sync` prunes the WAL `< checkpoint_op` (keeping the
  /// WAL-head slot) + `wal.truncate`s the held tail + fully `clear()`s the pipeline (a sync's complete
  /// teardown). Only this log trim is common. SAFE: the apply loops read only ops `> commit_min >=
  /// checkpoint_op >= floor`, so nothing they touch is dropped; the freed entries are
  /// committed+checkpointed (durable in the SM snapshot) and out of every reach path except peer-serve,
  /// which has the state-sync/retransmit fallbacks the `run_gc` doc proves.
  pub(super) fn trim_log_to_checkpoint(&mut self, floor: u64, checkpoint_floor: u64) {
    // Committed-survival backstop on the BOUNDARY dropped op `floor`: it is `<= checkpoint_floor`, so
    // every op dropped here (`<= floor`) is folded into the durable snapshot — the shared invariant
    // of the destructive-site trim.
    self.assert_committed_survives(floor, checkpoint_floor);
    self.log.retain(|&op, _| op > floor);
    // Every RETAINED held-tail entry must be a FAITHFULLY-resolved slot — a real `Present(body)` op or a
    // `Body::Repairing` hole — NEVER a `Present(EMPTY)` placeholder (an unresolved Phase-1 recovery seed).
    // Such an empty entry would later apply with `&[]` (`advance_commit`) or advertise an empty-body header
    // (a view-change `log_slice`). The recovery-completion paths resolve every in-flight tail op before any
    // trim/install reaches here, and Normal operation never holds an empty `Present`; this turns that
    // implicit precondition of the body-blind retain into a checked invariant.
    #[cfg(debug_assertions)]
    for (&op, entry) in &self.log {
      debug_assert!(
        !entry.body.as_present().is_some_and(|b| b.is_empty()),
        "held-tail op {op} retained as a Present(EMPTY) placeholder — a recovery completion path left an \
         in-flight tail read unresolved (it would apply empty / advertise an empty-body header)"
      );
    }
  }

  /// Persist the durable VSR root for the current `(view, log_view, commit_max)` and arm the
  /// participation deferred until the write completes.
  /// Overwrites any prior `pending_sb` (supersession): an older-view completion is then ignored.
  ///
  /// **Persists the KNOWN-committed frontier, not the applied one.** The `VsrState`
  /// commit is `self.commit_max` (the highest op KNOWN committed cluster-wide), NOT `self.commit_min`
  /// (the locally-applied frontier). `recover` reads `state.commit()` back as `commit_max`, so
  /// persisting the lower `commit_min` on a replica HELD at a repair hole below `commit_max` would lower
  /// the recovered frontier and re-open the laggard-quorum truncation hazard. The committed-band
  /// headers below are the SPARSE canonical set over `(checkpoint_op .. commit_max]` — one header per
  /// HELD op, skipping holes — so they may be SHORTER than `commit` and contain gaps,
  /// which `try_new` allows.
  ///
  /// **Preserves the durable checkpoint pointer.** This write must carry the CURRENT checkpoint
  /// (`self.checkpoint_op` + the durable `checkpoint_id`), NOT zeros — a view-change root that
  /// zeroed `checkpoint_op` would regress the durable checkpoint and, once the WAL below it is GC'd
  ///, lose committed ops on recovery. The view transitions drop the LOGICAL
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
  /// **SPARSE, one header per HELD op.** The list records a header for EVERY op the log
  /// holds in `(checkpoint_floor .. commit_max]`, in ascending op order, SKIPPING holes — it does NOT
  /// stop at the first gap. The durable header set vouches for the identity
  /// of EVERY committed-band op this replica actually holds, so `recover` can verify each held op
  /// individually rather than DROPPING a whole suffix because of one lower hole. A contiguous-prefix
  /// list would leave a held committed op above a lower hole HEADER-LESS, and the recover guard would
  /// delete that op's only surviving copy when this replica was the quorum intersection for it.
  ///
  /// The band reaches the KNOWN-committed frontier `commit_max` (the value the same root persists),
  /// NOT `commit_min`: a replica HELD at `commit_min < commit_max` by a lower repair hole still
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
  pub(crate) fn committed_band_headers(&self, checkpoint_floor: OpNumber) -> std::vec::Vec<Header> {
    let lo = checkpoint_floor.get().saturating_add(1);
    // Reach the known-committed frontier but never past the head: `self.log` holds nothing above
    // `self.op`, so capping here drops no held op and keeps a bogus huge learned `commit_max` from
    // spinning an unbounded loop (a defensive bound mirroring `request_tail_gap`).
    let hi = self.commit_max.get().min(self.op.get());
    let mut headers = std::vec::Vec::new();
    for op in lo..=hi {
      // SPARSE: record a header for every HELD op, SKIPPING (not stopping at) a hole. A held committed
      // op above a lower repair hole thus keeps its canonical header; an op the log is
      // missing gets none and is the UNPROVEN/peer-repair case recover handles.
      let Some(entry) = self.log.get(&op) else {
        continue;
      };
      // Build from the entry's canonical `body_checksum` (the load-bearing field for the recovery
      // cross-check): for a `Present` body it is `fnv1a_128(bytes)` — identical to `Header::new(...,
      // &bytes)` — and for a body-`Repairing` slot it is the stored durable checksum, so the canonical
      // header is recorded even when the bytes are absent.
      headers.push(Header::from_parts(
        OpNumber::with(op),
        self.view,
        entry.client,
        entry.request,
        entry.body.body_checksum(),
      ));
    }
    headers
  }

  pub(crate) fn submit_durable_view(&mut self, action: PendingSbAction, sb: &mut impl Superblock) {
    // COPY-FORWARD the checkpoint pair so this view-change root never rewinds the durable checkpoint. An
    // in-flight ORDINARY checkpoint at `AwaitRoot` has its durable root write STAGED AHEAD of this view
    // write (FIFO), so that root lands FIRST and advances the durable checkpoint to `target_op`; persisting
    // the stale `self.checkpoint_op` here would then rewind it. So carry that checkpoint's own
    // (`target_op`, `checkpoint_id`) verbatim — at `AwaitRoot` its snapshot bytes are already durable (the
    // `AwaitSnapshot` write completed before the root was staged), so the named pair is recoverable. In
    // every other case — no checkpoint in flight, or one still at `AwaitSnapshot` whose root is staged
    // BEHIND this view write (so it lands LAST, a monotone no-op) — the durable pair equals
    // `self.checkpoint_op` paired with the durable `checkpoint_id`. The persisted `checkpoint_op` is thus
    // monotone non-decreasing across the two concurrent writers; `commit` + the band below derive from it.
    let (checkpoint_op, checkpoint_id) = match &self.pending_checkpoint {
      Some(pc)
        if matches!(pc.kind, CheckpointKind::Ordinary)
          && matches!(pc.step, CheckpointStep::AwaitRoot(_)) =>
      {
        (pc.target_op, pc.checkpoint_id)
      }
      _ => (self.checkpoint_op, sb.state().checkpoint_id()),
    };
    let commit = OpNumber::with(self.commit_max.get().max(checkpoint_op.get()));
    let state = self.durable_root(
      self.view,
      self.log_view,
      // Persist `commit` — the KNOWN-committed frontier `commit_max` — as the durable `VsrState` commit,
      // NOT `commit_min`. `recover` reads `state.commit()` as `commit_max`, so a root that persisted the
      // LOWER `commit_min` would, on a replica HELD at `commit_min < commit_max` by a stale/faulty repair
      // hole, make `recover` read back a LOWERED frontier — the recovered DVC would then under-report the
      // known commit and the laggard-quorum truncation hazard reappears. `commit >= checkpoint_op` holds by
      // construction (the `.max` above), so the `commit >= checkpoint_op` root invariant is satisfied; the
      // committed-band headers below are the SPARSE canonical set from `self.log` — one header per HELD op
      // in `(checkpoint_op .. commit]`, SKIPPING holes — so a held committed op above a lower repair hole
      // keeps its header rather than being left header-less and dropped by recover.
      commit,
      checkpoint_op,
      checkpoint_id,
      self.committed_band_headers(checkpoint_op),
    );
    let id = self.mint_op_id();
    sb.submit_write(id, state);
    self.pending_sb = Some((id, action));
  }

  /// Seal the in-memory committed frontier into the durable superblock root: persist `commit_max`
  /// and its committed-band headers so the durable root's `commit` equals the live committed frontier.
  ///
  /// Between checkpoints (and view changes) `commit_max` advances only IN MEMORY — the durable root's
  /// commit lags it. That lag is harmless in normal operation, where a recovering node catches the gap
  /// up from a `Normal` peer. But a coordinated offline restart brings EVERY node down at the same stale
  /// durable commit, so no peer can supply a committed op above it, and the bounded recover tail window
  /// can strand such an op below the re-formed head. The operator MUST call this on every node, while
  /// it is still up and `Normal`, and AWAIT its superblock write, BEFORE reading the root to derive a
  /// successor with [`prepare_restart`](crate::prepare_restart) — so the successor root carries the
  /// true committed prefix and every committed op is read back on restart.
  ///
  /// Returns whether it sealed. It is a no-op (returns `false`) unless the node is `Normal` with NO
  /// durable work outstanding — a WAL append, a durable-view write, a checkpoint root, a state-sync
  /// install, or a sync-serve read ([`Self::has_inflight_storage`]). Refusing while any durable write
  /// is in flight is load-bearing: a seal submitted behind a queued checkpoint root would carry the
  /// stale `checkpoint_op` and land after it, reverting the checkpoint; and an operator that merely
  /// drains `has_inflight_storage` after sealing could mistake an unrelated completion for the seal.
  /// The operator therefore drains all in-flight storage FIRST, then seals (which now fires), then
  /// verifies the durable root commit matches the sealed frontier before deriving a successor.
  #[must_use = "an ignored seal may leave the durable root behind commit_max; check it fired"]
  pub fn seal_committed_frontier(&mut self, sb: &mut impl Superblock) -> bool {
    if self.status.is_normal() && !self.has_inflight_storage() {
      self.submit_durable_view(PendingSbAction::Seal, sb);
      true
    } else {
      false
    }
  }

  /// Build a durable root carrying the active [`Membership`] — a v4 root (epoch =
  /// `self.membership.epoch()`, prev_epoch = `self.prev_epoch`). Every durable-root write goes through
  /// here so the durable epoch + membership SURVIVE normal operation (checkpoints + view changes): a
  /// node that checkpoints or changes view and then crashes recovers its CURRENT configuration, never
  /// falling back to the genesis membership (which would regress its epoch — a split-brain hazard). The
  /// v4 invariant `root.epoch ==
  /// membership.epoch` holds by construction. The scalar/header invariants are the same ones
  /// [`VsrState::try_new`] checked (`log_view <= view`, `commit >= checkpoint_op`, in-band ascending
  /// headers); a violation is a caller bug, so this `expect`s like the prior `try_new` did.
  fn durable_root(
    &self,
    view: View,
    log_view: View,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    checkpoint_id: u128,
    committed_headers: std::vec::Vec<Header>,
  ) -> crate::VsrState {
    crate::VsrState::try_new_v4(
      view,
      log_view,
      commit,
      checkpoint_op,
      checkpoint_id,
      committed_headers,
      self.membership.epoch(),
      self.prev_epoch,
      self.membership.clone(),
      // The CURRENT recent-prior lineage ring (the membership written here is the current one), so a
      // node recovering off this root restores the superseded-ancestor ids and keeps admitting a retained
      // laggard's cross-epoch catch-up.
      self.lineage.to_vec(),
      // The op that produced the CURRENT membership (this root stamps `self.membership`), so a recovered
      // donor restores the cross-epoch serve gate. Once a checkpoint advances PAST a prior swap's
      // reconfigure op, the next `durable_root` carries the same `config_install_op` with a higher
      // `checkpoint_op`, so the gate flips from withhold to serve at exactly the right checkpoint.
      self.config_install_op,
    )
    .expect("durable root: log_view <= view, commit >= checkpoint_op, membership epoch consistent")
  }

  /// Mint a durable root that stamps a CROSS-EPOCH state-sync's SUCCESSOR membership — the analogue of
  /// [`Self::submit_swap_epoch`]'s successor-carrying root, but for the state-sync re-persist path. A
  /// laggard that cross-epoch state-syncs (its synced snapshot reflects a configuration ahead of its
  /// own) must make the new configuration DURABLE in the SAME root that records the synced checkpoint,
  /// not only install it in memory — otherwise a later crash/wipe recovers the OLD epoch off this root
  /// and silently REVERTS the membership install (re-stranding the replica at the old epoch). So this
  /// stamps the SUCCESSOR's `epoch`/membership and the predecessor's epoch as `prev_epoch`, and writes
  /// the POST-swap lineage ring (the superseded predecessor `config_id` shifted in — exactly what
  /// [`Endpoint::install_membership`]'s `push_lineage` builds), mirroring `submit_swap_epoch`. The
  /// consensus frontier (`view`/`log_view`/`commit`/`checkpoint_op`/`checkpoint_id` + the band headers)
  /// is the synced one, carried unchanged.
  #[allow(clippy::too_many_arguments)]
  fn durable_root_with_successor(
    &self,
    view: View,
    log_view: View,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    checkpoint_id: u128,
    committed_headers: std::vec::Vec<Header>,
    successor: &Membership,
    successor_prev_config_id: Option<u128>,
  ) -> crate::VsrState {
    // The POST-crossing lineage, from the VERIFIED chain (matching the in-memory `install_sync` push). On
    // a MULTI-epoch skip the installed config's immediate predecessor is the VERIFIED `prev_config_id`
    // (the value `to_membership_verified` checked), NOT the laggard's own current `config_id` — so the
    // ring is `[verified_prev, own_prior, ..]`. On a SINGLE-epoch crossing (`prev == own_prior`) the
    // verified predecessor IS the own prior, so the plain one-push ring is byte-identical to before.
    let own_prior = self.membership.config_id();
    let prior_config_ids = match successor_prev_config_id {
      Some(verified_prev) if verified_prev != own_prior => {
        self.lineage_after_crossing_push(own_prior, verified_prev)
      }
      _ => self.lineage_after_push(own_prior),
    };
    // The VERIFIED predecessor epoch — the backward-link scalar that MUST match the lineage ring above.
    // The installed config's immediate predecessor is `successor.epoch() - 1` (each reconfiguration is a
    // single-change-per-step that bumps the epoch by exactly one), NOT the laggard's own stale
    // `self.membership.epoch()`, which on a MULTI-epoch skip is an EARLIER ancestor. Stamping the stale
    // scalar would record "E2 chains from E0" while the ring correctly says `[E1, E0]` — a contradiction
    // a recovered node restores, which the lineage checker then reads as a non-chained successor / fork.
    // On a SINGLE-epoch crossing `self.membership.epoch() == successor.epoch() - 1` already, so this is a
    // no-op (the durable root is byte-identical). The in-memory install (`install_sync`) stamps the SAME
    // value, so a node recovering off this root restores the identical scalar. Saturating to keep it
    // underflow-free; `apply_sync`'s distance bound already proved `successor.epoch() >= 1` for a crossing.
    let prev_epoch = crate::Epoch::new(successor.epoch().get().saturating_sub(1));
    crate::VsrState::try_new_v4(
      view,
      log_view,
      commit,
      checkpoint_op,
      checkpoint_id,
      committed_headers,
      successor.epoch(),
      prev_epoch,
      successor.clone(),
      prior_config_ids,
      // A cross-epoch sync install has no LOCAL reconfigure op (the laggard synced PAST it), so carry the
      // synced frontier `checkpoint_op` as `config_install_op` — the SAME value `install_sync` sets in
      // memory. The donor attached this successor only because ITS checkpoint reached the reconfigure op
      // `N`, and this `checkpoint_op` equals that donor checkpoint, so `checkpoint_op >= N`: a safe,
      // restart-survivable lower bound for the gate on this node (now a potential re-donor).
      checkpoint_op,
    )
    .expect(
      "sync-successor root: log_view <= view, commit >= checkpoint_op, membership epoch consistent",
    )
  }
}

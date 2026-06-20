use super::*;

impl<S: StateMachine, R: Reconfig> Endpoint<S, R> {
  /// Set this replica's own vote bit on `op`'s inflight entry (no-op if the entry is gone). Used by
  /// the primary's normal-path own append (`Pending::Ack`) and the view-change adoption append
  /// (`Pending::AdoptVote`) — both record the own vote ONLY once the op's WAL append is durable.
  pub(crate) fn record_own_vote(&mut self, op: u64) {
    let own = 1u64 << self.local_slot().get();
    // The primary's own vote is for the operation IT is driving at `op`, which is exactly the operation
    // whose identity seeded this inflight entry (the `on_request` mint, the view-change adopt loop, or —
    // for an adopted `Repairing` tail — the now-`Present` peer-repaired body `fill_repair` verified
    // against the seeded canonical checksum). So it is content-addressed by construction; this assert
    // freezes that invariant so a future own-vote site casting against a divergent operation trips in tests.
    debug_assert!(
      self.inflight.get(&op).is_none_or(|inf| {
        self
          .log
          .get(&op)
          .map(|e| crate::storage::prepare_identity(e.client, e.request, e.body.body_checksum()))
          .unwrap_or(inf.prepare_checksum)
          == inf.prepare_checksum
      }),
      "own vote for op {op} disagrees with the operation the inflight entry is driving"
    );
    if let Some(inf) = self.inflight.get_mut(&op) {
      inf.oks |= own;
    }
  }

  /// Is this replica a CATCHING-UP view-changer (the higher-view rule: soliciting a `StartView` via
  /// GetView rather than driving an SVC/DVC change)? `false` outside `Status::ViewChange` (the
  /// `view_change` collection is `None` there), so this safely answers "no" in Normal/Recovering.
  pub(crate) fn catching_up(&self) -> bool {
    self.view_change.as_ref().is_some_and(|vc| vc.catching_up)
  }

  /// Has this view's canonical log already been formed (the DVC quorum was reached)? `false` outside
  /// `Status::ViewChange` (collection `None`), so it safely answers "no" there — and the
  /// `on_do_view_change` guard reads it only after the `is_view_change()` short-circuit anyway.
  fn dvc_quorum(&self) -> bool {
    self.view_change.as_ref().is_some_and(|vc| vc.dvc_quorum)
  }

  /// The prospective-primary DVC collection (read). Only ever called inside `Status::ViewChange` (where
  /// the collection is `Some`); `expect` documents that invariant.
  fn dvc_from(&self) -> &BTreeMap<ReplicaId, DoViewChange> {
    &self
      .view_change
      .as_ref()
      .expect("DVC collection read outside ViewChange")
      .dvc_from
  }

  /// The prospective-primary DVC collection (mutable). Only ever called inside `Status::ViewChange`.
  fn dvc_from_mut(&mut self) -> &mut BTreeMap<ReplicaId, DoViewChange> {
    &mut self
      .view_change
      .as_mut()
      .expect("DVC collection mutated outside ViewChange")
      .dvc_from
  }

  /// Set our own bit for `svc_target` and broadcast a `StartViewChange{svc_target}`.
  pub(crate) fn join_svc(&mut self, now: Instant) {
    self.svc_from |= 1u64 << self.local_slot().get();
    self.push_svc(self.svc_target);
    self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
  }

  /// Broadcast a `StartViewChange` for `view` to the other replicas.
  pub(crate) fn push_svc(&mut self, view: View) {
    self.emit(Outgoing::new(
      Recipient::Backups,
      Message::StartViewChange(crate::StartViewChange::new(
        view,
        self.local_slot(),
        self.membership.epoch(),
        self.membership.config_id(),
      )),
    ));
  }

  pub(crate) fn view_change_timeouts<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    if self.timers.svc_message.is_some_and(|d| d <= now) {
      self.push_svc(self.svc_target); // re-broadcast the live SVC target (drives escalation under loss)
      self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
    }
    // Gate the DVC retransmit on a DURABLE view (durable-view-before-participate in the
    // retransmit path). `enter_view_change` arms `dvc_message` AND submits the SendDoViewChange
    // durable-view write (so `pending_durable_view()` holds), with the INITIAL DVC deferred to
    // `on_sb_done`. If the async superblock write is slower than `VC_MESSAGE_RETRANSMIT`, this retransmit
    // would otherwise fire FIRST and cast the DVC — a VOTE the new primary counts toward forming the view —
    // BEFORE this replica has PERSISTED the view; a crash before the write lands then recovers the OLD
    // view after this replica helped form a quorum for the new one. So skip the send while the view
    // write is pending (the deferred `on_sb_done` casts the initial DVC and the retransmit resumes once
    // the view is durable). In ViewChange status the only in-flight `pending_sb` write is this
    // SendDoViewChange one (a SwapEpoch/Seal is Normal-only), so `!pending_durable_view()` is exactly the
    // durable-view test here. Kept in LOCKSTEP with `serviceable_now(DvcMessage)` (which gates the same
    // way), so a `dvc_message` armed-and-due during the view write is non-serviceable: `poll_timeout`
    // filters it out (no spin) and the `handle_timeout` no-orphan-due assert ignores it.
    if !self.pending_durable_view() && self.timers.dvc_message.is_some_and(|d| d <= now) {
      self.send_do_view_change(now);
      self.timers.dvc_message = Some(now + VC_MESSAGE_RETRANSMIT);
    }
    if self.timers.get_view_message.is_some_and(|d| d <= now) {
      self.send_get_view(now); // re-sends and re-arms get_view_message
    }
    if self.timers.view_change_status.is_some_and(|d| d <= now) {
      // The change did not complete (the next primary is also down, or our catch-up target is
      // unreachable): become an active SVC-driver for the next view and re-arm timers for that
      // role (clears the now-stale get_view_message; arms svc/dvc/view_change_status). Still
      // ViewChange here, so the collection is `Some`; flip the catch-up discriminant in place.
      if let Some(vc) = self.view_change.as_mut() {
        vc.catching_up = false;
      }
      self.propose_next_view(now, sb);
      self.arm_timers(now);
    }
  }

  /// A Normal backup heard from its primary this view: defer the idle timeout.
  pub(crate) fn note_primary_contact(&mut self, now: Instant) {
    if self.status.is_normal() && !self.is_primary() {
      self.arm_primary_idle(now);
    }
  }

  pub(crate) fn on_start_view_change<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    m: crate::StartViewChange,
  ) {
    if self.is_learner() {
      // A non-voting replica is not a view-change participant: it neither joins the StartViewChange
      // quorum nor casts a vote. It follows a completed view change by adopting the new primary's
      // StartView (catching up via GetView if it falls behind), never by driving the change itself.
      return;
    }
    let target = m.view();
    // `View::next()` saturates, so this comparison cannot overflow even at `view == u64::MAX`
    // (where the first clause already rejects every possible target).
    if target.get() <= self.view.get() || target.get() > self.view.next().get() {
      // stale (≤ our view), OR a jump beyond our immediate next view — do not drive an
      // unverified inflated target from a lone SVC; we catch up to a genuinely-higher view
      // via a real Prepare/Commit from its primary (the higher-view rule), not via SVCs.
      return;
    }
    if m.replica().get() >= self.membership.replica_count() as u16 {
      return; // ignore malformed/out-of-range replica id
    }
    if target.get() > self.svc_target.get() {
      // A higher target is proposed — adopt it, reset collection, and join it.
      self.svc_target = target;
      self.svc_from = 0;
      self.join_svc(now);
    }
    if target.get() == self.svc_target.get() {
      self.svc_from |= 1u64 << m.replica().get();
      self.maybe_start_view_change(now, sb);
    }
  }

  pub(crate) fn maybe_start_view_change<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    if (self.svc_from.count_ones() as usize) >= self.membership.quorum_view_change() {
      self.transition_to_view_change_status(now, sb, self.svc_target);
    }
  }

  /// Enter `ViewChange` for `view_new`, reset pipeline + quorums, defer DoViewChange until view is durable.
  ///
  /// STEADY-STATE entry: asserts `view_new > self.view` (a self-driven view change must strictly
  /// advance the view). The recovery path enters via [`Self::enter_view_change_from_recovery`], which
  /// permits `view_new == self.view` (re-driving an in-progress view change after a crash) — it shares
  /// the identical body through `enter_view_change`.
  fn transition_to_view_change_status<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    view_new: View,
  ) {
    assert!(
      view_new.get() > self.view.get(),
      "view change must strictly advance the view"
    );
    self.enter_view_change(now, sb, view_new);
  }

  /// Recovery-only `ViewChange` entry (faithful port of TigerBeetle `replica.zig` open()): a
  /// recovered replica that was Normal as the primary ABDICATES to `view + 1`, and one that crashed
  /// mid-view-change RE-DRIVES `view` (`view_new == self.view`). The steady-state strict-advance
  /// assert ([`Self::transition_to_view_change_status`]) would trip on the re-drive, so this entry
  /// uses a relaxed `view_new >= self.view` (and `> self.view` whenever `log_view == view`, the
  /// abdication case — a Normal primary must move OFF its own view). Everything else (the pipeline /
  /// quorum / pending resets, the deferred durable-view write) is identical via `enter_view_change`.
  pub(crate) fn enter_view_change_from_recovery<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    view_new: View,
  ) {
    debug_assert!(
      view_new.get() >= self.view.get(),
      "recovery view change must not regress the view"
    );
    debug_assert!(
      view_new.get() > self.view.get() || self.log_view.get() < self.view.get(),
      "an abdicating recovered primary (log_view == view) must advance OFF its own view"
    );
    self.enter_view_change(now, sb, view_new);
  }

  /// THE SINGLE CHOKEPOINT for tearing down the OLD-GENERATION in-flight state that EVERY
  /// view transition must abandon. The three transition entries — [`Self::enter_view_change`]
  /// (self-driven SVC-quorum change), [`Self::catch_up_to_view`] (higher-view catch-up), and
  /// [`Self::adopt_canonical_head`] (adopt an authoritative StartView/RecoveryResponse) — all cross a
  /// generation boundary and so MUST drop the same union of old-view sub-state; centralizing it here
  /// means a NEW in-flight sub-state is cleared on all three paths by editing ONE
  /// place (a seam bug — a half-completed durable transition leaking across the
  /// boundary because one of three hand-written resets forgot a field — cannot recur).
  ///
  /// Clears, in one place: the SVC-collection bits (`svc_from` — these stay FLAT, being live in Normal
  /// too; the DVC collection + `catching_up` discriminant instead live behind `self.view_change`, which
  /// each call site sets/`take`s around this reset — see below), the in-flight STORAGE submissions
  /// (`pending`/`appending` — abandoned old-view WAL appends whose late completion must not emit a
  /// stale-view `PrepareOk`; kept in lockstep), the stale per-replica checkpoint reports
  /// (`peer_checkpoint` — a fresh primary rebuilds the GC map from incoming `PrepareOk`/`Commit`), the
  /// in-flight checkpoint
  /// (`pending_checkpoint` — re-triggers once Normal resumes), the in-flight state-sync as the
  /// LOAD-BEARING PAIR `sync` + `pending_install` cleared TOGETHER (clearing `sync` alone would let
  /// `on_sb_done`'s install arm fire against a cancelled sync — the `assert_invariants` `pending_install
  /// ⟹ sync` clause guards exactly this) along with its `sync_solicit` timer, and the forfeit sub-state
  /// `forfeit_armed` + `pending_forfeit` (a fresh generation re-evaluates the step-down from scratch).
  ///
  /// With durable-before-install cancelling `sync`/`pending_install` finds the OLD
  /// (consistent, if stale) state intact — the STAGE never restored the SM, advanced
  /// `commit_min`/`op`, nor pruned the WAL — so there is no pruned-but-stale window; a still-behind
  /// replica re-triggers state-sync from Normal.
  ///
  /// NOT cleared here (the per-site DISTINGUISHING state each entry sets itself): the new
  /// `view`/`status`/`svc_target`; the `view_change` collection (the DVC + catch-up state — each site
  /// sets it `Some(ViewChangeCollection::entering(catching_up))` on the two ViewChange ENTRIES and
  /// `take`s it to `None` on the two EXITS to Normal, the `is_some() == is_view_change()` coupling; this
  /// reset is bidirectional — reached on both entries and the adopt EXIT — so it cannot own that
  /// direction-dependent set/take); `inflight`/`buffer` (the primary pipeline + backup reorder buffer —
  /// `adopt_canonical_head` deliberately does NOT clear them, since a Normal primary can reach it via a
  /// higher-view `on_start_view` with a live pipeline, so they stay at the two ViewChange entries);
  /// `pending_sb` (overwritten by `submit_durable_view` in the two entries that issue a durable-view
  /// write, set `None` by `catch_up_to_view` which issues none); `recover` (only the adoption path
  /// retires it); the forward `arm_timers(now)` re-arm; and `log_floor` (a MONOTONE vouched fact
  /// about durable cluster checkpoints, not per-generation in-flight state — clearing it would
  /// un-learn the floor the force-sync escalation needs after `peer_checkpoint` is dropped here).
  pub(crate) fn reset_for_view_transition(&mut self) {
    // SVC-collection bits for the OLD view (these stay flat — live in Normal too, see the struct
    // fields). The ViewChange-only DVC collection + catch-up discriminant are NOT touched here: they
    // live behind `self.view_change`, which each transition site sets (the two ViewChange entries) or
    // takes to `None` (the two exits) around this shared reset — the `view_change.is_some() ==
    // is_view_change()` coupling cannot be expressed in this BIDIRECTIONAL chokepoint (it is reached on
    // both entries AND the adopt EXIT), so the Option lifecycle stays at the call sites.
    self.svc_from = 0;
    // Abandon in-flight WAL appends from the old view: their bytes are already durable, but a late
    // completion must not emit a stale-view PrepareOk or vote on a wrong-generation op. `appending` is
    // kept in lockstep with `pending`: clearing it means a later adopt-append re-marks the op
    // fresh, and the abandoned old completion (now absent from `pending`) does not retract that fresh
    // mark in `on_wal_done`.
    self.pending.clear();
    self.appending.clear();
    // Drop stale per-member checkpoint reports: the new generation re-establishes the pipeline, so
    // old-view reports must not gate the next primary's GC. A fresh primary rebuilds the map from
    // incoming PrepareOk/Commit, staying conservative (unheard peers count as 0) until then. The
    // cleared reports are an input of the cached quorum-checkpoint statistic — recompute it. (This also
    // sweeps any entry left under a member a reconfiguration removed, though the floor consumers already
    // intersect with the current membership, so such an entry is inert until the next clear anyway.)
    self.peer_checkpoint.clear();
    self.recompute_quorum_checkpoint();
    // Drop PROVISIONAL client-session rows (`last_op == 0`): accept-time / watermark-backfill rows are
    // GENERATION-LOCAL — they exist only on the replica that minted them and are invisible to the
    // deterministic eviction. An op they covered either SURVIVED into the new generation (its row is
    // re-seeded by the new primary's backfill and becomes applied when the op applies, identically on
    // every replica) or was truncated (the row must be forgotten, or a deposed primary that later
    // leads again would dedup the client's re-mint of that request against a watermark for an op that
    // never committed — a silent permanent drop). APPLIED rows (and restored snapshot rows) persist:
    // they are the consensus table.
    self.clients.retain(|_, s| s.last_op.get() > 0);
    // Supersede any in-flight checkpoint: a view change drops it (its stale superblock completion is
    // then ignored in on_sb_done). It re-triggers once Normal resumes — commit_min is preserved.
    self.pending_checkpoint = None;
    // Release the PROPOSAL latch: an uncommitted `Reconfigure` op this primary proposed belongs to the
    // generation a view change ends. If that op rides the canonical log and RE-COMMITS under the new
    // view, `commit_reconfigure` stages its swap fresh; if it is TRUNCATED (not canonical), it never
    // commits — and a latch left `Some` here would block a future `propose_membership` FOREVER (the
    // proposed-but-never-committed deadlock). Either way the proposal phase is over, so release it (the
    // committed-but-not-installed swap, tracked separately in `pending_swap`, is NOT released — see below).
    self.reconfigure_inflight = None;
    // Drop any outstanding learner-promote-proof challenge: it is TRANSIENT promote state bound to the
    // proposing generation a view change ends. A new primary re-challenges fresh on its own
    // `propose_membership`; carrying a stale challenge across would let a pre-transition reply (or a
    // reply meant for the old generation) satisfy a post-transition mint. (The `(epoch, config_id)`
    // reply binding is the backstop; this is the primary clear.)
    self.learner_proof = None;
    // KEEP a committed-but-not-installed epoch swap across the transition. `pending_swap` is set ONLY for
    // a COMMITTED `Reconfigure` op (`stage_epoch_swap` runs at commit, after `commit_min` advanced past
    // the op), so the change is durable in the log and MUST still install — dropping it would lose a
    // committed membership change (the cluster would stay in the old epoch forever, since the new view's
    // `advance_commit` starts ABOVE the already-committed op and never re-stages it). The successor is
    // membership-derived and view-INDEPENDENT (a view change changes neither the membership nor the
    // epoch), so the staged value stays valid across the transition. Its in-flight `SwapEpoch` root (if
    // any) is superseded on the superblock by the imminent durable-view write (its stale completion is
    // ignored in `on_sb_done`), but `pending_swap` survives and `maybe_swap_epoch` RE-SUBMITS it once a
    // superblock slot frees: from `on_sb_done` when the durable-view root lands, and from the commit
    // tails (`try_commit` / `advance_commit`) for the `catch_up_to_view` path that issues no durable-view
    // write. The durable-epoch-before-participate fence holds throughout — the membership is installed
    // only off a durable SwapEpoch root, never the superseded one. (Invariant (7) — "a staged swap always
    // has a superblock write outstanding" — is momentarily relaxed across this reset: the superseding
    // durable-view write keeps a write in flight whenever a view change issues one, and the commit-tail
    // re-submit covers the no-write `catch_up_to_view` path; `assert_invariants` does not run mid-reset.)
    // Abandon any in-flight state-sync: a view change supersedes it (state-sync and view
    // change are mutually exclusive by status — §2.6). The `sync` handshake, its DEFERRED INSTALL
    // (`pending_install`), and any in-progress chunked transfer (`sync_transfer`) are cancelled
    // TOGETHER: with durable-before-install the STAGE
    // never restored the SM, advanced `commit_min`/`op`, nor pruned the WAL, so this finds the OLD
    // (consistent, if stale) state intact — there is NO pruned-but-stale window. Dropping
    // `pending_install` here also releases the staged snapshot bytes (and the transfer drop its
    // partially-assembled ones) — and, gated by the
    // `sync.is_some()` cleared alongside, the `on_sb_done` install arm can never fire against this
    // cancelled sync (the `assert_invariants` `pending_install ⟹ sync` + `sync_transfer ⟹ sync`
    // clauses guard this pairing).
    self.sync = None;
    self.pending_install = None;
    self.sync_transfer = None;
    self.timers.sync_solicit = None;
    // A view change ends this primary generation: clear any forfeit grace timer AND any
    // deferred-forfeit flag (the safety step-down — see `maybe_force_sync`). The new generation
    // re-evaluates from scratch once it resumes Normal as primary, so neither a stale grace deadline
    // nor a stale pending-forfeit must carry across (no same-view re-forfeit / cross-view leak).
    self.timers.forfeit_armed = None;
    self.pending_forfeit = false;
    // A view change ends this primary generation: drop any body-aware nack-truncation grace deadline.
    // The candidate (a header-only `Repairing` op above `commit*` with no `Present` donor) is
    // re-evaluated from scratch by the NEXT primary's `select_canonical_log` (it may again be a
    // candidate, may now be `Present` on a donor, or may be nack-truncated) — so a stale grace deadline
    // must not carry across (no cross-generation truncation, no same-view re-arm leak), exactly as the
    // forfeit sub-state above. (`arm_timers` preserves this across its reset, so this is the one place
    // that clears it on a transition; the timer is otherwise owned by `start_view_as_new_primary` /
    // the fill-cancel / the expiry truncation.)
    self.timers.repair_or_truncate = None;
  }

  /// The shared `ViewChange`-entry body (no view-advance assert — the callers assert their own
  /// contract). Resets the pipeline + quorums and defers the DoViewChange until the new view is durable.
  fn enter_view_change<B: Superblock>(&mut self, now: Instant, sb: &mut B, view_new: View) {
    self.view = view_new;
    self.set_status(Status::ViewChange);
    self.svc_target = view_new; // collect future escalations above this view
    // Tear down ALL old-generation in-flight state in one place: SVC bits, in-flight
    // appends, peer-checkpoint reports, in-flight checkpoint, in-flight sync + its deferred install, and
    // the forfeit sub-state.
    self.reset_for_view_transition();
    // ViewChange ENTRY: install a fresh ViewChange-only collection — `catching_up = false` (a real,
    // self-driven change, not the higher-view catch-up). (`is_some() == is_view_change()` coupling.)
    self.view_change = Some(ViewChangeCollection::entering(false));
    // The primary pipeline + backup reorder buffer are dropped on this self-driven entry (kept OUT of
    // the shared reset because `adopt_canonical_head` preserves a live primary pipeline).
    self.inflight.clear();
    self.buffer.clear();
    self.arm_timers(now);
    // DVC deferred to on_sb_done: persist the new view before voting in it.
    self.submit_durable_view(PendingSbAction::SendDoViewChange, sb);
  }

  /// Send our full log + position to the prospective primary of the current view.
  pub(crate) fn send_do_view_change(&mut self, _now: Instant) {
    let primary = self.membership.primary(self.view);
    let entries = self.log_entries();
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(primary)),
      Message::DoViewChange(
        crate::DoViewChange::new(
          self.view,
          self.log_view,
          self.op,
          // The DVC reports the KNOWN committed frontier `commit_max` — VSR's commit-number `k` (the
          // highest op this replica KNOWS is committed), NOT the locally-applied `commit_min`.
          // `select_canonical_log` takes `commit* = max(d.commit())`, so under-reporting
          // commit_min would let a known-committed op (whose slot is a dropped repair hole on this
          // replica) fall ABOVE `commit*` and be truncated as an uncommitted gap when the DVC quorum is
          // this replica + a laggard. Reporting commit_max keeps `commit*` at/above it, so it is a
          // COMMITTED hole the new primary HOLDS + peer-repairs (never silently dropped). Fail-stop-safe:
          // a committed op N is held by a write-quorum, which intersects the DVC quorum, so some donor
          // claims `op >= N` → `commit* (<= max commit_max == N) <= op_head` holds.
          self.commit_max,
          self.membership.epoch(),
          self.membership.config_id(),
          self.local_slot(),
          entries,
        )
        // The vouched floor of the carried log: every op this DVC omits at/below it is folded into a
        // durable cluster checkpoint. `select_canonical_log` floors its union at the canonical
        // generation's max of these, so a checkpoint-subsumed prefix never rides the view change.
        .with_checkpoint_op(self.log_floor),
      ),
    ));
  }

  /// The in-memory log as HEADER-ONLY wire entries — the OFFSET tail `(checkpoint_op .. op]` for a
  /// recover-from-checkpoint / state-synced replica (the committed prefix `[1..=checkpoint_op]` lives
  /// in the SM snapshot, not the cache), or dense `[1..=op]` for a replica that never checkpointed.
  /// `select_canonical_log` is offset-aware and UNIONs these across DVCs, so a DVC carrying only
  /// the offset tail loses no committed op at view change.
  ///
  /// **Every entry is emitted HEADER-ONLY (`Repairing`), carrying only the op's canonical
  /// `(client, request, body_checksum)`, NOT its body bytes** — even an op this replica holds
  /// `Present`. This is what keeps the three carriers that delegate here (`DoViewChange` /
  /// `StartView` / `RecoveryResponse`) UNDER the transport frame cap regardless of the body sizes
  /// of the uncheckpointed band: a header-only entry is a fixed 49 bytes, so the carrier size is
  /// independent of the ops' bodies (a full-body carrier would overflow `MAX_FRAME_LEN` for large
  /// ops — see [`crate::message::MAX_REQUEST_BODY_OVERHEAD`]). The adopter
  /// installs each as a `Repairing` hole (its number TAKEN, never re-minted) and fetches the body via
  /// the WINDOWED bulk-repair channel (`RequestPrepareRange` → `RepairBatch`) — which is what makes
  /// header-only liveness-viable even for a deep band (the per-op repair path would need one round
  /// trip per op and never converge in a calm window). `body_checksum()` is total — `fnv1a_128(bytes)`
  /// for a `Present` body, the stored durable checksum for a `Repairing` slot — and is exactly what
  /// `fill_repair` verifies the peer-supplied body against, so the canonical identity travels intact.
  pub(crate) fn log_entries(&mut self) -> std::vec::Vec<crate::PreparedEntry> {
    // Observability (non-vacuity): every DVC/StartView/RecoveryResponse log payload is built HERE,
    // so counting at this chokepoint witnesses the header-only carrier path across all three.
    self.header_only_carriers_emitted += 1;
    let entries: std::vec::Vec<crate::PreparedEntry> = self
      .log
      .iter()
      .map(|(&op, e)| {
        crate::PreparedEntry::repairing(
          OpNumber::with(op),
          e.client,
          e.request,
          e.body.body_checksum(),
        )
      })
      .collect();
    // Correct-by-construction backstop: a header-only band must fit the transport frame cap. The
    // `(checkpoint_op .. op]` band depth is bounded by the WAL/checkpoint geometry (`~6 * checkpoint_ops
    // + headroom`), and `MAX_CHECKPOINT_OPS` is capped so that worst case stays at/below
    // `MAX_HEADER_ONLY_BAND_DEPTH` (see `crate::config::MAX_CHECKPOINT_OPS`). This asserts the realized
    // count against that bound, catching a bounded-WAL embedder that sized `capacity()` beyond the `~6 *`
    // geometry the cap assumes (so an over-cap carrier trips here in tests + the VOPR, rather than being
    // silently dropped by the transport's frame guard on the send path).
    debug_assert!(
      entries.len() <= crate::message::MAX_HEADER_ONLY_BAND_DEPTH,
      "header-only view-change band of {} entries exceeds the frame-fitting bound {} — checkpoint_ops \
       and/or the WAL capacity are sized beyond the geometry MAX_CHECKPOINT_OPS assumes",
      entries.len(),
      crate::message::MAX_HEADER_ONLY_BAND_DEPTH,
    );
    entries
  }

  pub(crate) fn on_do_view_change<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: crate::DoViewChange,
  ) {
    // NOTE (deferred to a later milestone): we do not yet validate incoming DVC well-formedness
    // (commit <= op; the log is the OFFSET tail `(checkpoint .. op]`, dense WITHIN that range — it is
    // NOT required to be dense from op 1, since a recover-from-checkpoint / state-synced sender
    // legitimately omits the prefix that lives in its SM snapshot). Safe under honest crash-stop
    // peers; matters once untrusted/real-driver inputs land. The cross-DVC commit* <= op_head
    // invariant is enforced (fail-stop) in `select_canonical_log`.
    // `!is_view_change()` short-circuits BEFORE `dvc_quorum()` reads the (then-`None`) collection, so
    // the collection is `Some` on every non-returning path below (ViewChange ⟹ `view_change.is_some()`).
    if m.view() != self.view
      || !self
        .membership
        .is_primary_slot(self.local_slot(), self.view)
      || !self.status.is_view_change()
      || self.dvc_quorum()
    {
      return;
    }
    if m.replica().get() >= self.membership.replica_count() as u16 {
      return; // ignore malformed/out-of-range replica id
    }
    // Record the donor's vouched checkpoint floor, mirroring the `PrepareOk`/`Commit` recording
    // sites (monotone, range-checked above). This is what keeps the new primary's force-sync /
    // GC-quorum floors fresh across the view transition that cleared `peer_checkpoint`: a sub-floor
    // committed hole the floored union cannot carry must still cross `max_peer_checkpoint_op()` so
    // the escalation fires (the donor's checkpoint proves a servable snapshot at/above it exists).
    self.record_peer_checkpoint(m.replica(), m.checkpoint_op());
    // Ensure our own DVC is represented (keyed by replica → a self-addressed DVC is idempotent).
    // Compute the own-DVC into a local FIRST to avoid a self borrow conflict, then insert.
    let own = self.local_slot();
    if !self.dvc_from().contains_key(&own) {
      let own_dvc = crate::DoViewChange::new(
        self.view,
        self.log_view,
        self.op,
        // Report the KNOWN committed frontier `commit_max` (VSR's `k`), not `commit_min` — see
        // `send_do_view_change`. This own-DVC feeds the same `select_canonical_log`
        // `commit*` union, so it must carry the same frontier the wire DVC does.
        self.commit_max,
        self.membership.epoch(),
        self.membership.config_id(),
        self.local_slot(),
        self.log_entries(),
      )
      // The same vouched floor the wire DVC carries (`send_do_view_change`).
      .with_checkpoint_op(self.log_floor);
      self.dvc_from_mut().insert(own, own_dvc);
    }
    // Keep the most-advanced DVC per replica.
    let replace = self
      .dvc_from()
      .get(&m.replica())
      .map(|cur| (m.log_view().get(), m.op().get()) > (cur.log_view().get(), cur.op().get()))
      .unwrap_or(true);
    if replace {
      self.dvc_from_mut().insert(m.replica(), m);
    }
    if self.dvc_from().len() >= self.membership.quorum_view_change() {
      self.start_view_as_new_primary(now, wal, sb);
    }
  }

  /// VSR canonical-log selection + nack-prepare truncation — **offset-aware**.
  ///
  /// Returns `(canonical log spanning (floor* .. op_head], op_head, commit*, floor*)`:
  /// - the canonical generation is the DVCs with the greatest `log_view`;
  /// - `op_head` is that generation's head, less any provably-uncommitted tail truncated by a
  ///   `quorum_nack_prepare` of nacks (contiguous ⟹ replica `r` nacks op `X` iff `r.op < X`);
  /// - `commit*` is the greatest commit across all DVCs (commit never rewinds);
  /// - `floor*` is the canonical generation's greatest vouched checkpoint floor
  ///   (`max(d.checkpoint_op())`, capped at `commit*`): every op `<= floor*` is folded into a
  ///   canonical donor's durable checkpoint, so it is committed AND snapshot-recoverable;
  /// - the canonical log is the **UNION** of the canonical generation's entries in
  ///   `(floor* .. op_head]` — each op is sourced from ANY canonical-generation DVC that holds it —
  ///   NOT a copy of one DVC's `log_slice()`.
  ///
  /// **Why the floor.** Each donor's band is individually frame-gated (`band_at_capacity`), but the
  /// UNION of two individually-valid OFFSET bands is not: a partitioned laggard (which never
  /// state-syncs — every sync trigger requires RECEIVING a higher-checkpoint message) can be a
  /// canonical donor with an ANCIENT band, and unioning it with the current donor's band yields a
  /// canonical log near TWO band caps — whose re-emitted carrier (`log_entries()` →
  /// `StartView`/`DoViewChange`/`RecoveryResponse`) exceeds `MAX_FRAME_LEN`, is dropped by the
  /// transport, and wedges the view change. Dropping the checkpoint-subsumed prefix `<= floor*`
  /// bounds the union: the donor holding `op_head` keeps `op - log_floor <= MAX_HEADER_ONLY_BAND_DEPTH`
  /// (the carrier SPAN gate) and its advertised floor is `<= floor*`, so the union spans at most
  /// `(floor* .. op_head]` ⊆ one gated span → every carrier fits the frame (the `debug_assert` below
  /// freezes this). Every dropped op is `<= floor* <= commit*` — committed and durably APPLIED inside
  /// a canonical donor's checkpoint snapshot — so the omission is the same never-a-silent-loss case
  /// the coverage proof below covers, systematic for the sub-floor prefix.
  ///
  /// **Why the union.** A DVC log is the *offset tail*
  /// `(checkpoint_op .. op]` — a recover-from-checkpoint or state-synced donor holds only ops above
  /// its own checkpoint (the prefix `[1..=checkpoint_op]` lives in its SM snapshot). Two
  /// canonical-generation donors can therefore have DIFFERENT floors: e.g. r0 (checkpoint 4) holds
  /// `5..=10`, r1 (checkpoint 8) holds `9,10`, both head 10 commit 8. The old code copied ONE DVC's
  /// `log_slice()` via `max_by_key(op)` (ties → highest replica id), which would pick r1's `[9,10]`
  /// and **silently drop committed ops 5,6,7 that only r0 holds** — the `commit* <= op_head`
  /// fail-stop does not catch it (the dropped ops are interior). Unioning takes ops 5,6,7 from r0,
  /// so no committed op held by any canonical donor is dropped.
  ///
  /// **The present-set is the log entries themselves (no separate bitset).** An op IS present in a
  /// DVC iff a `PreparedEntry` for it is in that DVC's `log_slice()`. The `Recovering` loop drops a
  /// faulty/absent op from the in-memory `log` cache rather than caching an empty body, so
  /// `log_entries()` (and hence every DVC's `log_slice()`) already omits faulty ops: absence from a
  /// slice means "this donor cannot supply this op" — whether because it is below the donor's
  /// checkpoint floor (fine; it is in the donor's snapshot) or because the slot read back faulty
  /// (then another donor supplies it, or peer-repair does). An explicit `u64` present-bitset would be
  /// redundant with the slice AND would cap the band at 64 ops, which the offset tail (arbitrarily
  /// many ops above a checkpoint) can exceed; the slice has no such cap.
  ///
  /// **Coverage / no-committed-op-dropped proof.** Let `floor_d = (min op in d.log) - 1` (or `d.op`
  /// if d's log is empty) be donor `d`'s present-floor, and `min_floor` the minimum over the
  /// canonical generation. The committed band the canonical log must cover for the worst (lowest-
  /// floor) adopter is `(min_floor .. commit*]`. For each such op ABOVE `floor*` the union includes
  /// it iff SOME canonical donor holds it. By quorum intersection a committed op was held by some
  /// current-DVC sender, and the lowest-floor canonical donor `L` (with `floor_L == min_floor`)
  /// covers `(min_floor .. op_L]`. If `op_L >= commit*`, `L` alone covers the whole band above
  /// `floor*`. An op the union omits is one of two cases, NEITHER a silent loss:
  /// - **`op <= floor*` (the systematic, floored omission):** the op is folded into a canonical
  ///   donor's durable checkpoint — committed AND applied inside a servable snapshot. The adopter's
  ///   `advance_commit` HOLDS at the sub-floor hole and registers it for repair; `maybe_force_sync`
  ///   then escalates to state-sync, because the hole is at/below a KNOWN peer checkpoint — the
  ///   floor is learned from the DVCs themselves (`on_do_view_change` records each donor's
  ///   `checkpoint_op`) and from the adopted carrier (`adopt_canonical_head` records + raises
  ///   `log_floor` to the carried floor, which `max_peer_checkpoint_op` includes). After the sync
  ///   the adopter's state reaches `floor*` and commit resumes.
  /// - **`op > floor*` held by NO canonical donor** (the donor that committed+checkpointed it past,
  ///   plus a low-floor donor that lagged the tail): the adopter's `advance_commit` HOLDS the commit
  ///   at the missing op and `request_repair`s it from a peer (the `RequestPrepare` → `Prepare`
  ///   safety net, mirroring TigerBeetle's `repair_prepares_between`). The adopt path is fixed to NOT
  ///   destroy a held copy and NOT clear that repair request (see `adopt_log` / `adopt_canonical_head`).
  ///
  /// So the SAFETY property — no committed op is ever dropped — holds: a committed op is present in
  /// the union when any canonical donor holds it above `floor*`, and otherwise is repaired or
  /// state-synced (commit blocks until then), never skipped.
  ///
  /// Run by the prospective primary once it holds `>= quorum_view_change` DoViewChange messages.
  /// NOTE: with exactly `quorum_view_change` DVCs the truncation loop provably never fires in the
  /// contiguous model (the head-holder is one of them); truncation activates only with a larger
  /// collected set. See the `no_truncation_at_minimal_quorum` test.
  pub(crate) fn select_canonical_log(
    &mut self,
  ) -> (std::vec::Vec<crate::PreparedEntry>, u64, u64, u64) {
    let dvcs: std::vec::Vec<&crate::DoViewChange> = self.dvc_from().values().collect();
    debug_assert!(!dvcs.is_empty(), "selection requires at least one DVC");

    let log_view_star = dvcs.iter().map(|d| d.log_view().get()).max().unwrap_or(0);
    let canonical: std::vec::Vec<&crate::DoViewChange> = dvcs
      .iter()
      .copied()
      .filter(|d| d.log_view().get() == log_view_star)
      .collect();

    // `op_head` is the canonical generation's head, but BOUNDED to the ACTUALLY-represented log:
    // a malformed DVC may CLAIM `op` far above (up to `u64::MAX`) the entries it carries, which —
    // taken at face value — would (a) spin the nack-scan below `commit* ..= op_head` for billions of
    // iterations and (b) overflow `op += 1` at `u64::MAX`. We cap the claimed head at the max op
    // actually PRESENT across the canonical donors' `log_slice()` entries, never below `commit*` (a
    // committed op must survive for the fail-stop check + the `advance_commit` repair path). For an
    // HONEST DVC the head op is always present in its slice, so `max_present_op == claimed head` and
    // this is a no-op — the legitimate (in-range) case is unchanged; only a phantom claimed head
    // (above both the entries and `commit*`) is clipped to the represented range.
    let claimed_op_head = canonical.iter().map(|d| d.op().get()).max().unwrap_or(0);
    let max_present_op = canonical
      .iter()
      .flat_map(|d| d.log_slice())
      .map(|e| e.op().get())
      .max()
      .unwrap_or(0);
    let commit_star = dvcs.iter().map(|d| d.commit().get()).max().unwrap_or(0);
    let mut op_head = claimed_op_head.min(max_present_op.max(commit_star));
    // Fail-stop (in ALL builds): if a committed op exceeds the canonical generation's head, the
    // cross-DVC VSR view-change invariant is broken — panicking is strictly safer than silently
    // dropping the committed op (which a release build's `advance_commit` cap would otherwise do).
    // (Unchanged for honest inputs: there `op_head == claimed head` and this is the original check.)
    assert!(
      commit_star <= op_head,
      "VSR safety invariant violated: commit* ({commit_star}) > op_head ({op_head}) — a committed op \
       is above the canonical log head; refusing to silently drop it"
    );

    // Truncate the uncommitted tail at the first op with a nack quorum. Nacks are monotonic in op
    // (`nacks(op) = |{d : d.op() < op}|` is non-decreasing), so the original code scanned
    // `commit*+1 ..= op_head` one op at a time for the first crossing. That per-op scan is unbounded
    // when `op_head` is large; the count only CHANGES at a donor's `d.op()+1`, so we compute the
    // crossing DIRECTLY from the sorted donor ops — bounded by the DVC count, never the op range, and
    // overflow-free (saturating). This acts on the UNCOMMITTED tail `(commit* .. op_head]` only — a
    // committed op is never truncated — and yields the IDENTICAL truncation point as the per-op scan.
    let threshold = self.membership.quorum_nack_prepare();
    let mut donor_ops: std::vec::Vec<u64> = dvcs.iter().map(|d| d.op().get()).collect();
    donor_ops.sort_unstable();
    if threshold >= 1 && threshold <= donor_ops.len() {
      // `nacks(op) >= threshold` first holds at `op = donor_ops[threshold-1] + 1` (the threshold-th
      // smallest donor op, plus one); the first such op within `[commit*+1, op_head]` truncates to
      // `op - 1`. Clamp the crossing to the scan's lower bound (mirrors the loop starting at
      // `commit*+1`), then truncate iff it lands at/below the current head.
      let first_nack_op = donor_ops[threshold - 1].saturating_add(1);
      let cross = first_nack_op.max(commit_star.saturating_add(1));
      if cross <= op_head {
        op_head = cross.saturating_sub(1);
      }
    }

    // The union FLOOR: the canonical generation's greatest vouched checkpoint floor. Every op
    // `<= floor*` is folded into a canonical donor's durable checkpoint, so it is committed AND
    // recoverable from a servable snapshot — it must NOT ride the view change (the union of two
    // individually-frame-valid offset bands can otherwise exceed the frame — see the doc). Capped at
    // `commit*` so a malformed DVC advertising a floor above its own commit can never floor away an
    // op not vouched committed (for an honest donor `checkpoint_op <= commit_max`, so the cap is a
    // no-op).
    let floor_star = canonical
      .iter()
      .map(|d| d.checkpoint_op().get())
      .max()
      .unwrap_or(0)
      .min(commit_star);
    // Observability (non-vacuity): does this selection's floor actually DROP a carried entry — some
    // canonical donor holds an op `<= floor*` that the union below excludes (op numbers start at 1,
    // so a floor of 0 never matches)? A selection whose floor sits below every carried op is not
    // counted (the floor did no work there). The counter increment is deferred below the merge loop,
    // past the last use of the `dvc_from()` borrows.
    let floored_union = canonical
      .iter()
      .flat_map(|d| d.log_slice())
      .any(|e| e.op().get() <= floor_star);

    // Build the canonical log by UNIONING the canonical generation's entries in (floor* .. op_head]:
    // for each op, take its `PreparedEntry` from any canonical donor that holds it. A committed op
    // present in a low-floor donor's offset log but absent from a higher-floor donor is therefore
    // STILL included (the floor drops only the checkpoint-subsumed prefix `<= floor*`).
    // The BTreeMap keys by op so the result is ordered+gapless-where-present. A `Repairing`
    // (header-only) entry COUNTS as the op being present — its existence is what stops the op number
    // being re-minted — but when BOTH a `Present` and a `Repairing` entry exist for the same op
    // across canonical donors, `Present` WINS (prefer a real body over a repair-pending hole); a
    // `Repairing`-only op stays repair-pending in the canonical log (its body is peer-repaired after
    // adoption). Among two `Present` (or two `Repairing`) copies the choice is immaterial: every donor
    // of the canonical generation agrees on a committed op's content (same prior-view prepare), and an
    // uncommitted tail op `(commit* .. op_head]` is identical across the canonical generation too.
    let mut merged: BTreeMap<u64, crate::PreparedEntry> = BTreeMap::new();
    for d in &canonical {
      for entry in d.log_slice() {
        if entry.op().get() > floor_star && entry.op().get() <= op_head {
          match merged.entry(entry.op().get()) {
            std::collections::btree_map::Entry::Vacant(v) => {
              v.insert(entry.clone());
            }
            std::collections::btree_map::Entry::Occupied(mut o) => {
              // A real body supersedes a held `Repairing` hole for the same op; otherwise keep the
              // existing copy (Present stays Present, Repairing stays Repairing).
              if o.get().is_repairing() && !entry.is_repairing() {
                o.insert(entry.clone());
              }
            }
          }
        }
      }
    }
    let log: std::vec::Vec<crate::PreparedEntry> = merged.into_values().collect();
    if floored_union {
      self.unions_floored += 1;
    }
    // THE BOUND the floor exists for: the floored union fits ONE header-only carrier. The donor
    // holding `op_head` kept `op - log_floor <= MAX_HEADER_ONLY_BAND_DEPTH` (the carrier SPAN gate on
    // every head-growth path) and advertised `checkpoint_op == its log_floor <= floor*`, so the union
    // — distinct ops in `(floor* .. op_head]` — has at most `op_head - floor*` entries, within one
    // gated span. (Holds for honest donors; a recovered replica whose pre-crash adoption floor was
    // not yet made durable can transiently exceed its span until it re-learns the floor + syncs, so
    // this stays a debug assert, not a release fail-stop.)
    debug_assert!(
      log.len() <= crate::message::MAX_HEADER_ONLY_BAND_DEPTH,
      "floored canonical union of {} entries exceeds the frame-fitting bound {} — a donor's carrier \
       span outran its advertised checkpoint floor",
      log.len(),
      crate::message::MAX_HEADER_ONLY_BAND_DEPTH,
    );
    (log, op_head, commit_star, floor_star)
  }

  /// Adopt the canonical log from the DVC quorum and become the active primary.
  /// Canonical-log selection + nack-prepare truncation are now performed via
  /// `select_canonical_log`. Participation (StartView broadcast + try_commit) is deferred to
  /// `start_view_participate` via `on_sb_done`, once the new view is durable.
  fn start_view_as_new_primary<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
  ) {
    // A checkpoint is never logically armed when forming a new primary's view: `maybe_checkpoint`
    // is gated on Normal status, and entering ViewChange dropped `pending_checkpoint`. (A physically
    // in-flight checkpoint root write is handled by the Superblock serialized root-write ordering
    // contract — see `submit_durable_view`.)
    debug_assert!(
      self.pending_checkpoint.is_none(),
      "no checkpoint may be logically in flight when forming a new primary's view"
    );
    // Offset-aware canonical-log selection (UNION, floored at the canonical generation's vouched
    // checkpoint floor) + nack-prepare truncation (see `select_canonical_log`). The canonical log is
    // the offset tail `(floor* .. op_head]`, NOT necessarily dense `[1..=op_head]`.
    let (canonical_log, op_head, commit_star, floor_star) = self.select_canonical_log();
    // The union floor is now this primary's vouched log floor: a canonical donor's durable
    // checkpoint covers every op `<= floor*` the floored log omits. Raised BEFORE `advance_commit`
    // below, so the force-sync floor (`max_peer_checkpoint_op` includes `log_floor`) already crosses
    // any sub-floor hole the moment it is registered.
    self.raise_log_floor(OpNumber::with(floor_star));
    self.adopt_log(&canonical_log, floor_star);
    self.op = OpNumber::with(op_head);
    // Retire any pending-repair holes the adopted canonical log NOW supplies; leave the rest (a
    // committed op held by no canonical donor) for `advance_commit` below to re-`request_repair` from
    // a peer. We must NOT blanket-clear `repair` here: a committed op the union could not carry is a
    // real hole that must stay solicited, not be silently forgotten.
    let supplied: std::collections::BTreeSet<u64> =
      canonical_log.iter().map(|e| e.op().get()).collect();
    self.repair.retain(|op| !supplied.contains(op));
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
    }
    // status is still ViewChange here, so the maybe_checkpoint at advance_commit's tail is a no-op
    // (checkpoints only start in Normal) — a checkpoint must not race the StartViewAsPrimary
    // durable-view write submitted below.
    self.advance_commit(now, sb, commit_star); // apply newly-exposed committed ops (prior-view quorum decision)

    // truncate the uncommitted suffix at the FIRST interior gap above commit*. The
    // adopted canonical log is the offset-union `(min_floor .. op_head]` and may still have an interior
    // hole the union could not fill (e.g. this replica recovered a faulty/torn interior slot and dropped
    // it from the cache, and no canonical donor supplies it). The inflight-seeding loop below would
    // register an `inflight` entry for EVERY op in `(commit_min, op]` but `adopt_append` only re-appends
    // ops PRESENT in `self.log`, so a gap op would get NO vote and `try_commit` (strictly in order) would
    // wedge there FOREVER — and no peer can supply it (see the safety argument below). So drop the head
    // back below the first such gap before seeding.
    //
    // SAFETY (the gap above commit* is provably UNCOMMITTED). A committed op is held by a quorum, and the
    // current DVC set is a quorum, so by quorum intersection SOME DVC sender holds every committed op;
    // `select_canonical_log`'s offset-UNION therefore includes every committed op held by ANY canonical
    // donor. An op `G > commit*` that is ABSENT from the union is held by no canonical donor, hence was
    // never committed — and the whole suffix above `G` is uncommitted too (a committed op above an
    // uncommitted one would violate the commit prefix). Truncating it is thus safe: it mirrors
    // `select_canonical_log`'s nack-truncation of the uncommitted tail, but catches an INTERIOR gap the
    // contiguous nack-scan steps over. A gap AT or BELOW `commit*` is a COMMITTED op (a real repair
    // hole the union could not carry) — it is NOT truncated here; `advance_commit` above already HELD the
    // commit at it and `request_repair`d it from a peer (the seeding loop then only spans the gap-free
    // committed-or-truncated head). The subsequent `start_view_participate` broadcasts the now-dense
    // `self.log_entries()`, so backups adopt a gap-free log too.
    if let Some(gap) = ((commit_star + 1)..=self.op.get()).find(|op| !self.log.contains_key(op)) {
      // Committed-survival backstop on the BOUNDARY dropped op `gap` (the smallest op truncated here):
      // the quorum-intersection argument above proves everything from `gap` up is uncommitted (a gap
      // above `commit_star` is held by no canonical donor, so it was never committed), so it satisfies
      // the helper's uncommitted clause (`> commit_max`).
      self.assert_committed_survives(gap, self.checkpoint_op.get());
      self.op = OpNumber::with(gap - 1);
      self.log.retain(|&op, _| op <= self.op.get());
      // Retire any repair holes now stranded above the truncated head (mirrors the `repair.retain`
      // cleanup above): an uncommitted op above the head is not solicited.
      self.repair.retain(|&op| op <= self.op.get());
      if self.repair.is_empty() {
        self.timers.repair_retry = None;
      }
    }

    // SAFETY: physically DROP any WAL tail ABOVE the new primary's canonical head,
    // mirroring `adopt_canonical_head`. A slot above `self.op` can only hold an UNCOMMITTED earlier-view
    // proposal (the canonical head is this view's authoritative head); left in the WAL it is RE-LOADED by a
    // later `recover` and applied for a committed op the cluster assigns at that number with a DIFFERENT
    // value (a committed-divergence). Truncating drops only uncommitted ops, so no durability dip; the
    // `adopt_append` loop below re-writes the canonical `(commit_min .. op]` slots authoritatively.
    // Committed-survival backstop on the BOUNDARY freed WAL slot `self.op + 1` (the lowest slot above
    // the canonical head): nothing above the authoritative head is committed, so it is uncommitted.
    self.assert_committed_survives(self.op.get() + 1, self.checkpoint_op.get());
    wal.truncate(self.op);

    // Backfill the client-session request high-water from the adopted in-memory log tail. This is a
    // fallback that only covers the ops still cached in `self.log` (the offset tail `(floor .. op]`).
    // The AUTHORITATIVE source of the dedup watermark is now apply-time tracking in `advance_commit`
    // (and `on_request`/`commit_op` on the primary) plus the checkpoint snapshot restored on
    // recover/state-sync — those survive GC, whereas this loop does NOT (GC prunes `self.log`
    // below the checkpoint, so for a backup whose log is empty this loop finds nothing). Keeping it is
    // harmless (it can only RAISE the watermark for ops the new primary still holds) and guards the
    // edge where a session row was somehow not yet recorded. Without the apply-time tracking, a
    // backup-turned-primary with a GC'd log would carry `session.request == 0` and wedge every client
    // on `on_request`'s gap check.
    //
    // This seeds the watermark for an UNCOMMITTED `Present` adopted tail op too (an op that committed on
    // the OLD primary — the client may already hold its reply and send its NEXT request — but which this
    // quorum adopted as uncommitted because the committing replicas were partitioned out): that op will
    // re-commit here, so its watermark is needed so the client's next request is not seen as a gap. The
    // one uncommitted op whose watermark must NOT outlive a rollback is a header-only `Repairing`
    // truncation candidate whose body never arrives — `repair_or_truncate_timeouts` ROLLS the watermark
    // back when it truncates such an op (a truncated request must be processed fresh, never deduped to a
    // no-reply hang), so seeding it here is safe.
    //
    // NOTE: we do NOT reconstruct the cached *reply* body here, so a client whose prior-view reply
    // was LOST relies on the in-flight op re-committing; the lost-reply resend is liveness under loss.
    // Only HELD entries contribute (an absent op adds nothing), so iterate the retained log —
    // bounded by the band — rather than probing every op number since genesis: at a high floor a
    // dense `1..=op` probe burns minutes inside new-primary formation while peers' view-change
    // escalation cadence turns the stall into a livelock.
    for (client, request) in self
      .log
      .range(..=self.op.get())
      .map(|(_, e)| (e.client.get(), e.request))
    {
      let session = self.clients.entry(client).or_default();
      if request.get() > session.request.get() {
        session.request = request;
      }
    }

    // log_view = view BEFORE submit_durable_view (try_new requires log_view <= view).
    self.log_view = self.view;
    self.set_status(Status::Normal);
    // Observability: the new view is FORMED on this replica (the canonical log is selected and it is
    // resuming Normal as the view's primary). Scalar copy only.
    self
      .events
      .push_back(Event::ViewChanged(crate::ViewChanged::new(self.view, true)));
    // ViewChange EXIT: the canonical log has been formed and we are returning to Normal as the new
    // primary, so retire the ViewChange-only collection (DVC quorum + catch-up discriminant) to `None`
    // — the `view_change.is_some() == is_view_change()` coupling. (Previously a `dvc_quorum = true`
    // marker set here then immediately went stale as the generation ended; the Option `take`-on-exit
    // makes that lifecycle explicit and type-enforced.)
    self.view_change = None;
    // Becoming primary FRESH: a deferred-forfeit flag from a prior
    // generation must not carry in (it was cleared on entering ViewChange, but clear it defensively
    // here so a fresh primary never starts already-flagged to abdicate).
    self.pending_forfeit = false;

    // Solicit the body of any adopted UNCOMMITTED-tail op carried HEADER-ONLY (`Repairing`): a
    // committed-but-not-widely-known op whose only canonical-generation donor read its body back faulty
    // travels through the DVC as a `Repairing` entry (its existence kept so its number is never
    // re-minted), but its bytes must be fetched from a peer that holds them before this primary can
    // re-prepare + commit it. `request_repair` registers the hole + broadcasts a `RequestPrepare`,
    // KEEPING the `Repairing` entry (its canonical `body_checksum` is what `fill_repair` verifies the
    // peer-supplied body against). Once the body returns Present, the prepare-retransmit re-broadcasts it
    // and `try_commit` drives it to commit (the inflight entry seeded below holds its place meanwhile —
    // `try_commit` HOLDS in op order at the body-absent hole until the repair fills it). A `Repairing` op
    // in the COMMITTED prefix `(.. =commit_star]` was already solicited by `advance_commit` above.
    let repairing_tail: std::vec::Vec<u64> = self
      .log
      .iter()
      .filter(|(op, e)| {
        **op > self.commit_min.get() && **op <= self.op.get() && e.body.is_repairing()
      })
      .map(|(op, _)| *op)
      .collect();
    for op in repairing_tail {
      self.request_repair(now, op);
    }

    // Body-aware nack-truncation (the f-fault-model liveness closure). A header-only `Repairing` op
    // ABOVE `commit*` is a *repair-or-truncate candidate*: NO canonical-quorum donor held it `Present`
    // (the offset-UNION in `select_canonical_log` prefers `Present`, so an op that adoption left
    // `Repairing` is one no canonical donor — and no local matching body — could supply), AND it is
    // above the known-committed frontier, so the cluster never observed it committed on the collected
    // quorum. The keep-vs-truncate decision is locally UNDECIDABLE: this could be a committed op whose
    // body-holders were merely partitioned out of the DVC quorum (World A — must keep + repair),
    // or a genuinely-uncommitted no-body op (World B — must truncate, else its
    // perpetual repair hole drops every client at `on_request` forever). So we do BOTH: `request_repair`
    // above keeps repairing it, and here we arm a VIRTUAL-TIME grace. If a `Present` body arrives before
    // the deadline (a holder became reachable + answered the `RequestPrepare`) the op is KEPT — it was
    // committed after all (the fill cancels the timer, see `on_wal_done`'s `RepairFill` arm). If the
    // grace elapses with the body still absent, the uncommitted tail is truncated
    // (`repair_or_truncate_timeouts`). SAFETY within `f`: a committed op's body is WAL-durable on a
    // write-quorum, so ≥1 of its ≤f-down holders is eventually reachable and supplies the body BEFORE
    // the grace — a committed op is never truncated. (`commit*` == `commit_max` here, just raised by
    // `advance_commit(commit_star)`.) A `Repairing` op `<= commit*` is genuinely committed — NEVER a
    // candidate (it is solicited but its grace is never armed). The timer is re-armed on a single
    // earliest-due deadline for the whole candidate set; the expiry handler truncates from the LOWEST
    // still-unfilled candidate up.
    let has_candidate = self
      .log
      .iter()
      .any(|(op, e)| *op > self.commit_max.get() && e.body.is_repairing());
    if has_candidate {
      self.timers.repair_or_truncate = Some(now + REPAIR_OR_TRUNCATE_GRACE);
    }

    // Rebuild the pipeline for the genuinely-uncommitted tail `(commit_max .. op]`. The new primary
    // must NOT count its own vote for an op it adopted from a peer's DVC and holds ONLY in memory —
    // that would let it commit (and on crash+recover lose) an op it never durably appended. So seed
    // each inflight entry with `oks: 0` and durably (re-)append the adopted op tagged `AdoptVote`; the
    // own vote is set in `on_wal_done` ONLY once that append lands (append-before-ack — the same
    // discipline `on_request`/`on_prepare` use). `try_commit` (deferred to `start_view_participate`
    // after the durable-view write) then counts only votes whose appends are durable.
    //
    // Committed ops `<= commit_max` (== `commit_star` here, just raised by `advance_commit`) are NOT
    // re-appended: the cluster already guarantees them, they owe no vote, and where this primary is HELD
    // at a committed repair hole below `commit_max` (the header-only adoption case), that committed band
    // is repaired via the windowed bulk-repair channel (a filled `RepairFill` casts the own vote in
    // `on_wal_done` only for the UNCOMMITTED-tail case, `op > commit_max`). Starting the loop at
    // `commit_max + 1` rather than `commit_min + 1` is load-bearing for a deep-laggard new primary: a
    // `commit_min` lower bound would re-append the ENTIRE committed band it already holds `Present` as
    // redundant `AdoptVote` appends — hundreds of them — flooding the WAL and starving the repair fills
    // that actually advance the commit (the liveness wedge a deep header-only adoption otherwise hits).
    self.inflight.clear();
    for op in (self.commit_max.get() + 1)..=self.op.get() {
      // Content-address this adopted op's votes by the OPERATION IDENTITY (client, request, body) the
      // primary is driving. The op is present in `self.log` here (the gap-truncation above dropped any
      // op the union could not carry), so its `(client, request, body_checksum)` is total: a `Present`
      // body's computed checksum, or a `Repairing` entry's stored canonical checksum — which the
      // peer-repaired `Present` body that fills the hole matches by construction (`fill_repair` accepts
      // only a body whose `fnv1a_128` equals that canonical checksum). So a backup's `send_prepare_ok`
      // stamps the SAME identity and legitimate adopted-tail votes are counted.
      let prepare_checksum = self
        .log
        .get(&op)
        .map(|e| crate::storage::prepare_identity(e.client, e.request, e.body.body_checksum()))
        .unwrap_or(0);
      self.inflight.insert(
        op,
        Inflight {
          oks: 0, // own vote set in on_wal_done when the AdoptVote append is durable
          committed: false,
          prepare_checksum,
        },
      );
      self.adopt_append(wal, op, Pending::AdoptVote(OpNumber::with(op)));
    }

    // Defer participation (StartView broadcast + arm_timers + try_commit) to on_sb_done. The own votes
    // accrue independently as the AdoptVote appends complete; a StartView/own-vote never outruns its
    // WAL append (for replica_count > 1 the lone own vote is below quorum, and backups only ack after
    // this StartView, so no adopted op can commit before BOTH its append and the durable-view land).
    self.submit_durable_view(PendingSbAction::StartViewAsPrimary, sb);
  }

  /// Runs once the new-primary superblock write is durable: broadcast StartView + begin committing.
  pub(crate) fn start_view_participate<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    // Broadcast the canonical log to all backups, advertising the KNOWN-committed frontier
    // `commit_max` — NOT the APPLIED frontier `commit_min`. The two diverge when this new primary
    // adopted a committed header-only (`Repairing`) op: `advance_commit(commit_star)` raised
    // `commit_max` to the cross-DVC commit*, but `commit_min` STALLS below the unrepaired hole (the
    // apply loop holds there). Advertising `commit_min` would tell a backup that adopts that committed
    // op (op <= commit_max) it is merely an uncommitted tail; if repair is delayed and a SECOND view
    // change then collects that backup, its DVC would report `commit` below the op, `commit*` would
    // fall below it, and the nack scan could truncate it — re-opening the committed-op loss one view
    // change later. Advertising `commit_max` makes the backup learn the true committed point; it then
    // HOLDS at the `Repairing`/missing hole (the apply loop never applies an op it does not hold) and
    // peer-repairs it. `commit_max <= self.op` here (`commit_max == commit_star <= op_head == self.op`
    // by `select_canonical_log`'s fail-stop), so a receiver's `commit <= op` adopt guard holds.
    let entries = self.log_entries();
    self.emit(Outgoing::new(
      Recipient::Backups,
      Message::StartView(
        crate::StartView::new(
          self.view,
          self.op,
          self.commit_max,
          self.membership.epoch(),
          self.membership.config_id(),
          self.local_slot(),
          entries,
        )
        // The vouched floor of the broadcast canonical log (raised to the union's floor* during
        // `start_view_as_new_primary`): a backup below it trims its own sub-floor band and records
        // the floor, so its force-sync escalation can recover the sub-floor gap from a snapshot.
        .with_checkpoint_op(self.log_floor),
      ),
    ));

    self.arm_timers(now);
    self.try_commit(now, sb);
  }

  /// Adopt the canonical (`entries`) log for a view whose committed frontier is `commit`, floored at
  /// the vouched checkpoint floor `floor`.
  ///
  /// The canonical log is built by UNIONING the canonical generation (see
  /// `select_canonical_log`) and is the offset tail `(floor .. op_head]` — it is NOT necessarily
  /// dense `[1..=op]`, and it may even OMIT a committed op held by NO canonical donor. So adoption
  /// must be **defensive**: it preserves any *committed* op the adopter already holds (in
  /// `(floor .. commit]`) that `entries` does not supply, rather than blindly clearing the log and
  /// destroying the adopter's own durable copy of a committed op. Held *uncommitted* ops (above
  /// `commit`) are governed solely by the canonical tail (a nack-truncated / lower-generation tail
  /// must not be resurrected from a stale local copy), so they are dropped; the canonical entries
  /// then overwrite/insert authoritatively.
  ///
  /// **The floor trim.** Retained own entries `<= floor` are dropped too — the same in-memory trim
  /// `run_gc`/`trim_log_to_checkpoint` performs at the OWN `checkpoint_op`, applied at adoption time
  /// with the CANONICAL floor: every such op is folded into a durable cluster checkpoint (the
  /// caller's floor is donor-vouched), so the drop is a cache eviction with a servable snapshot
  /// behind it, never a loss. Without it a laggard adopter would keep its ancient band ALONGSIDE the
  /// adopted one, and its own next re-emitted carrier (`log_entries()` → DVC/StartView/
  /// RecoveryResponse) would span two bands — over the frame. The trim touches ONLY the adopter's
  /// retained entries, never a supplied one (`entries` are inserted unconditionally below), and only
  /// the in-memory cache — the WAL keeps its slots (a crash re-reads them; the post-adoption
  /// force-sync's `install_sync` prunes them once the snapshot lands). A committed op that neither
  /// side supplies is left for
  /// `advance_commit` to `request_repair` from a peer (it is never silently skipped) — or, below the
  /// floor, to the force-sync escalation (`maybe_force_sync`, whose floor the caller raises
  /// `log_floor` to cover).
  fn adopt_log(&mut self, entries: &[crate::PreparedEntry], floor: u64) {
    let supplied: std::collections::BTreeSet<u64> = entries.iter().map(|e| e.op().get()).collect();
    // Preserve ONLY the adopter's APPLIED prefix (`op <= self.commit_min`) that the canonical log
    // omits — those are committed ops the adopter has itself applied, so by VSR committed-op survival
    // they are immutable and canonical-by-construction (no other view committed a different value
    // there). Everything ABOVE the applied frontier is dropped so the canonical entries below are
    // authoritative; the caller's `advance_commit(adopted_commit)` then reconstructs `(commit_min ..
    // adopted_commit]` from the freshly-inserted canonical entries, falling to repair for any omission:
    //
    //   * an UNCOMMITTED tail op — superseded by the canonical tail;
    //   * an op the canonical log itself SUPPLIES — re-inserted authoritatively below;
    //   * a committed op in the UNAPPLIED band `(commit_min .. adopted_commit]` the canonical log omits —
    //     the adopter holds a body it has NOT applied, which can
    //     be a STALE uncommitted proposal from an earlier view a later view overwrote with a different
    //     committed value (`LogEntry` carries no per-entry view, so a canonical-lineage held op is
    //     indistinguishable from a superseded one). Preserving it would diverge the committed log.
    //     Dropping it turns the slot into a hole; the caller's `advance_commit` then HOLDS the commit
    //     there and `request_repair`s the CANONICAL value from a committed-vouching peer (force-sync if
    //     the band was GC'd cluster-wide). No committed op is lost — it is fetched, never trusted local.
    //
    // This reads `self.commit_min` AT ADOPT TIME, BEFORE the caller advances the commit, so the
    // predicate uses the OLD (pre-adoption) applied frontier — both callers (`adopt_canonical_head`,
    // `start_view_as_new_primary`) run `adopt_log` strictly before their `advance_commit`.
    // Before dropping the held log, capture the adopter's OWN BODY-BEARING entry for any op the canonical
    // log carries only HEADER-ONLY (`Repairing`) but the adopter already holds with a body whose checksum
    // MATCHES the canonical `body_checksum`. "Body-bearing" is a `Present` client op OR a `Reconfigure`
    // membership op (both carry wire bytes — see `Body::is_body_bearing`); ONLY a `Repairing` adopter slot
    // has nothing to preserve. The adopter's body is then the CANONICAL body the new view still needs (the
    // canonical donor read it back faulty and carried only the header), so it must NOT be destroyed by
    // overwriting the slot with a body-less `Repairing` entry: a replica that holds the body is the source
    // the new primary peer-repairs / re-commits from. The checksum match makes this safe — only the
    // canonical body is preserved, never a superseded one (a different body fails the match and is dropped).
    // The PRESERVED `Body` is kept TYPED (a `Reconfigure` stays `Reconfigure`, not flattened to `Present`),
    // or `commit_reconfigure` would miss the carried reconfiguration op at re-commit. This makes "a held
    // body wins over a matching Repairing" hold on the ADOPT side too, mirroring the union in
    // `select_canonical_log`. CRITICAL when the new primary is the SOLE quorum-intersection holder of a
    // carried reconfiguration body: dropping it would leave an unfillable hole instead of a recommit+install.
    let mut preserved_bodies: BTreeMap<u64, Body> = BTreeMap::new();
    for e in entries {
      if e.is_repairing()
        && let Some(local) = self.log.get(&e.op().get())
        && local.body.is_body_bearing()
        && local.body.body_checksum() == e.body_checksum()
      {
        preserved_bodies.insert(e.op().get(), local.body.clone());
      }
    }
    let applied_floor = self.commit_min.get();
    // Committed-survival witness for the floor trim's boundary op: everything dropped by the
    // `op > floor` clause is `<= floor`, folded into the donor-vouched durable checkpoint the caller
    // floors at (the first clause of the shared proof, with the CANONICAL floor as the witness).
    self.assert_committed_survives(floor, floor);
    self
      .log
      .retain(|&op, _| op > floor && op <= applied_floor && !supplied.contains(&op));
    for e in entries {
      // A `Present` canonical entry is adopted with its body held. A header-only `Repairing` entry is
      // adopted repair-pending (its `body_checksum` only) UNLESS the adopter already held the matching
      // canonical body (captured above) — then keep that body so this replica can serve / commit it. The
      // new primary's `start_view_as_new_primary` `request_repair`s any still-header-only tail op and the
      // commit path HOLDS at it until the body returns. Either way the op exists in `self.log`, so its
      // number is TAKEN and never re-minted.
      let body = match preserved_bodies.remove(&e.op().get()) {
        Some(body) => body,
        None => e.body_state().clone(),
      };
      let entry = LogEntry {
        client: e.client(),
        request: e.request(),
        body,
      };
      self.log.insert(e.op().get(), entry);
    }
  }

  pub(crate) fn on_start_view<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: crate::StartView,
  ) {
    // Adopt only a strictly newer view, or the current view while we have not yet returned to Normal
    // in it. Re-applying a StartView for a view we are already Normal in would rewind `op` and
    // clobber locally-appended ops. A RecoveringHead replica is NOT Normal, so a same-view StartView
    // is (correctly) adopted: it is exactly how such a replica re-establishes its faulty head.
    if m.view().get() < self.view.get()
      || (m.view().get() == self.view.get() && self.status.is_normal())
    {
      return;
    }
    if m.replica() != self.membership.primary(m.view()) {
      return; // must come from the view's primary
    }
    self.adopt_canonical_head(
      now,
      sb,
      m.view(),
      m.op(),
      m.commit(),
      m.checkpoint_op(),
      m.log_slice(),
    );
    self.truncate_wal_above_adopted_head(wal);
  }

  /// Drop any WAL tail strictly ABOVE the head this replica just adopted. Run by
  /// [`on_start_view`](Self::on_start_view) / [`on_recovery_response`](Self::on_recovery_response) right
  /// after [`adopt_canonical_head`](Self::adopt_canonical_head) sets `self.op` to the canonical head. A
  /// slot above that head can only hold an UNCOMMITTED earlier-view proposal (the canonical head is this
  /// new view's authoritative head — nothing above it is committed), and `adopt_log` only cleared the
  /// IN-MEMORY cache. Left in the WAL, such a stale slot is RE-LOADED by a later `recover` (which rebuilds
  /// the cache from the un-truncated WAL and sets `self.op` back to it) and then APPLIED for a committed op
  /// the new view assigns at that SAME number with a DIFFERENT value (committed-divergence). Truncating to
  /// `self.op` drops ONLY uncommitted ops, so there is no durability dip; the uncommitted tail is simply
  /// re-fetched from the primary as `Prepare`s. (`adopt_canonical_head` never lowers `self.op`, so this is
  /// exactly the adopted head; done in the caller because it owns the `wal` handle.)
  pub(crate) fn truncate_wal_above_adopted_head<W: Wal>(&self, wal: &mut W) {
    // Committed-survival backstop on the BOUNDARY freed WAL slot `self.op + 1`: the adopted head is the
    // view's authoritative head, so nothing strictly above it is committed (the uncommitted clause).
    self.assert_committed_survives(self.op.get() + 1, self.checkpoint_op.get());
    wal.truncate(self.op);
  }

  /// Adopt an authoritative primary's canonical head + log for `view` and return to `Normal`.
  ///
  /// Shared by [`on_start_view`](Self::on_start_view) and
  /// [`on_recovery_response`](Self::on_recovery_response): both learn the canonical head from the
  /// view's primary (a `StartView` carries it directly; a primary's `RecoveryResponse` is the
  /// recovery-handshake equivalent). Callers MUST have already verified the message is from
  /// `config.primary(view)` and is not stale (`view >= self.view`, and not a same-view re-adoption
  /// while already Normal).
  ///
  /// **No committed op is lost, and none is trusted from a possibly-stale local copy.** A
  /// `RecoveringHead` replica has already restored its durable checkpoint prefix `[1..=checkpoint_op]`
  /// into the SM during `Recovering` (so `commit_min == checkpoint_op`); the `op >= commit_min` assert
  /// below rejects any head that would rewind below that durable prefix. The adopted log is the offset
  /// tail `(min_floor .. op]` from the canonical primary (NOT necessarily dense `[1..=op]` — the
  /// primary may itself be a recover-from-checkpoint / state-synced replica whose log starts above op
  /// 1). `adopt_log` therefore preserves ONLY the adopter's APPLIED prefix (`op <= commit_min`) that
  /// the incoming offset log omits — a committed op the adopter itself applied is immutable
  /// (committed-op survival), so its local copy is canonical. A committed op in the UNAPPLIED band
  /// `(commit_min .. commit]` that the offset log omits is NOT preserved: the held body is unapplied
  /// and may be a stale superseded proposal, so `adopt_log` drops it and `advance_commit`
  /// below HOLDS the commit at it and `request_repair`s the CANONICAL value from a committed-vouching
  /// peer (the existing force-sync path takes over if it was GC'd cluster-wide). The checkpointed
  /// prefix lives in the SM, the committed tail in the (applied-preserved + adopted + repaired) log —
  /// the committed prefix is reconstructed end to end, with peer-repair as the backstop for any omitted
  /// committed op the adopter has not applied (never silently skipped, never filled from a stale local).
  // The parameters are the carried head fields of ONE message (`view`/`op`/`commit`/`checkpoint_op`/
  // `log` — both callers unpack the same accessors of a `StartView`/`RecoveryResponse`), so the arity
  // mirrors the wire shape rather than an over-wide ad-hoc surface.
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn adopt_canonical_head<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    view: View,
    op: OpNumber,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    log: &[crate::PreparedEntry],
  ) {
    assert!(
      commit.get() <= op.get(),
      "canonical head commit must not exceed its op (malformed primary)"
    );
    assert!(
      op.get() >= self.commit_min.get(),
      "must not rewind below our committed op"
    );
    self.view = view;
    // The carried checkpoint floor, capped at the carried commit: only an op vouched COMMITTED (and
    // checkpoint-subsumed) may be floored away (for an honest primary `checkpoint_op <= commit_max`,
    // so the cap is a no-op — it only defangs a malformed floor above the commit).
    let floor = checkpoint_op.get().min(commit.get());
    // The carried floor is now this adopter's vouched log floor (a durable cluster checkpoint covers
    // every op `<= floor` the carried log omits). Raised BEFORE `advance_commit` below, so the
    // force-sync floor (`max_peer_checkpoint_op` includes `log_floor`) already crosses any sub-floor
    // hole the moment the held commit registers it.
    self.raise_log_floor(OpNumber::with(floor));
    self.adopt_log(log, floor);
    self.op = op;
    // (The WAL is truncated to this adopted head by the caller — `on_start_view` /
    // `on_recovery_response` — via `truncate_wal_above_adopted_head`, dropping the uncommitted divergent
    // suffix at the source so a later `recover` cannot re-load + apply a superseded body. See that helper.)
    // Retire any pending-repair holes the adopted canonical log NOW supplies (or that the adopter's
    // own APPLIED-prefix copy now covers, since `adopt_log` kept committed held ops `op <= commit_min`).
    // Holes the canonical log omits AND the adopter does not hold remain solicited; `advance_commit`
    // below re-requests them — INCLUDING the unapplied committed band `adopt_log` just dropped. This
    // MUST happen before `advance_commit` (which may add new holes) so we never wipe a freshly-requested
    // committed-op repair.
    let now_held: std::collections::BTreeSet<u64> = self.log.keys().copied().collect();
    self.repair.retain(|op| !now_held.contains(op));
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
    }
    // status is still ViewChange/RecoveringHead here, so the maybe_checkpoint at advance_commit's
    // tail is a no-op (checkpoints only start in Normal) — a checkpoint must not race the
    // AdoptedStartView durable-view write submitted below.
    self.advance_commit(now, sb, commit.get());
    // log_view = view BEFORE submit_durable_view (try_new requires log_view <= view).
    self.log_view = view;
    self.set_status(Status::Normal);
    // Observability: this replica ADOPTED the view's canonical head (a backup — the sender is the
    // view's primary; `is_primary` is computed for totality). Scalar copy only.
    self
      .events
      .push_back(Event::ViewChanged(crate::ViewChanged::new(
        view,
        self.membership.is_primary_slot(self.local_slot(), view),
      )));
    // Tear down ALL old-generation in-flight state in one place: SVC bits (svc_from),
    // in-flight appends (pending/appending), peer-checkpoint reports, in-flight checkpoint, in-flight
    // state-sync + its deferred install (cancelled TOGETHER — adopting an authoritative canonical head
    // supersedes the sync; the adopted canonical log + the adopter's preserved APPLIED prefix supply the
    // committed prefix, with peer-repair as the backstop for the omitted unapplied committed band;
    // durable-before-install leaves the old state intact), and the forfeit sub-state. See
    // [`Self::reset_for_view_transition`]. NOTE this DELIBERATELY does NOT clear `inflight`/`buffer`:
    // a Normal primary can reach here via a higher-view `on_start_view` holding a live pipeline, so —
    // unlike the two ViewChange entries — adoption preserves it (this is the real per-site asymmetry
    // the shared reset keeps out).
    self.reset_for_view_transition();
    // Record a NON-ZERO carried floor as the sending primary's checkpoint report, mirroring
    // `on_commit`'s recording of the primary's `Commit.checkpoint_op` (monotone; the caller verified
    // the sender IS `config.primary(view)`). AFTER the shared reset — which just cleared
    // `peer_checkpoint` — so the report survives into the new generation and a sub-floor adopter's
    // `maybe_force_sync` floor (belt to `log_floor`'s braces) crosses its sub-floor holes from the
    // first trigger. A zero floor carries no information and is skipped, keeping the freshly-reset
    // map genuinely empty for a floor-less adoption.
    if floor > 0 {
      self.record_peer_checkpoint(self.membership.primary(view), OpNumber::with(floor));
    }
    // ViewChange EXIT (adoption → Normal): retire the ViewChange-only collection (DVC + catch-up). The
    // shared reset above is bidirectional, so the `take`-to-`None` lives here. (`is_some() ==
    // is_view_change()` coupling.)
    self.view_change = None;
    // Adoption re-established a trustworthy head, so the recovery bookkeeping is retired: a
    // RecoveringHead replica that reaches here via this path leaves `recover` = None (the field is
    // structurally None in every non-recovering status). A non-recovering adopter already has None.
    // (This is the distinguishing reset only the adoption path owns.)
    self.recover = None;
    // (The pending-repair set was reconciled above — holes the adopted log / applied-prefix held copies
    // now cover were retired; any committed op neither side carries — including the unapplied band
    // `adopt_log` dropped — stays solicited and was re-requested by `advance_commit`. We deliberately do
    // NOT blanket-clear `repair` here: that was the stranding bug — clearing right after
    // `advance_commit` requested a hole silently forgot a committed op.)
    self.arm_timers(now);
    // Defer held-op re-acks to on_sb_done → `start_view_acks`: persist the new view first, and there
    // WAL-(re-)append each adopted uncommitted-tail op before its PrepareOk. The adopted
    // entries are in-memory only until then; the deferred ack gates on both the view write (here) and
    // the per-op append (in `start_view_acks`) completing, so no PrepareOk precedes either.
    self.submit_durable_view(PendingSbAction::AdoptedStartView, sb);
  }

  /// Runs once the adopted-StartView superblock write is durable: re-ack held uncommitted-tail ops —
  /// but only AFTER each is durably (re-)appended to the WAL.
  ///
  /// The adopted canonical entries lived only in the in-memory `self.log` (a `StartView` /
  /// `RecoveryResponse` installs them without a WAL write). Sending a `PrepareOk` for one before it is
  /// durable would let this backup vote for an op it could lose on crash+recover. So for each held
  /// uncommitted-tail op we `adopt_append` it (tagged `Pending::AdoptAck`) and DEFER the `PrepareOk`
  /// to `on_wal_done`, which sends it when that append lands. Running here — strictly after the
  /// durable-view write completed — also satisfies durable-view-before-participate: by the time any
  /// AdoptAck append completes the new view is already persisted, so the `PrepareOk` never precedes
  /// EITHER its WAL append or the view write (no cross-view vote, no memory-only vote). A tail op the
  /// canonical log did not actually supply is not held, so `adopt_append` skips it and no ack is owed.
  ///
  /// **Re-appends ONLY the genuinely-uncommitted tail `(commit_max .. op]`, NOT the committed band
  /// `(commit_min .. commit_max]`.** A committed op (`<= commit_max`) is already decided cluster-wide —
  /// it owes NO `PrepareOk` (committed ops are not voted), and where this replica is HELD at a committed
  /// repair hole below `commit_max` (the header-only adoption case), its committed band is repaired via
  /// the windowed bulk-repair channel (`RequestPrepareRange` → `RepairBatch` → per-op `RepairFill`), NOT
  /// re-appended here. Re-appending the whole `(commit_min .. op]` would, for a laggard held deep at the
  /// first hole, re-append the ENTIRE committed band it already holds `Present` — flooding the WAL with
  /// hundreds of redundant AdoptAck appends per view change and starving the repair fills that actually
  /// advance the commit. Bounding the re-append to `(commit_max .. op]` keeps it at the pipeline-depth
  /// tail it is meant to cover.
  pub(crate) fn start_view_acks<W: Wal>(&mut self, wal: &mut W) {
    let lo = self.commit_min.get().max(self.commit_max.get());
    for op in (lo + 1)..=self.op.get() {
      self.adopt_append(wal, op, Pending::AdoptAck(OpNumber::with(op)));
    }
  }

  /// Durably (re-)append an op the replica adopted into `self.log` during a view change, recording the
  /// deferred action (`Pending::AdoptVote` for the new primary's own vote, `Pending::AdoptAck` for a
  /// backup's PrepareOk) so `on_wal_done` casts it ONLY once the append lands (append-before-ack). The op's body lives only in the in-memory `self.log` until this completes —
  /// mirroring `append_prepare`, but for the already-installed adopted entry rather than an incoming
  /// `Prepare`. Header is written under the current (new) view, as `on_request` does for a fresh op.
  /// No-op if the op is not held (a committed op the canonical log omitted is peer-repaired instead).
  fn adopt_append<W: Wal>(&mut self, wal: &mut W, op: u64, kind: Pending) {
    let Some(entry) = self.log.get(&op).cloned() else {
      return; // not held — `advance_commit`/`request_repair` recovers a committed gap; nothing to ack
    };
    // A body-`Repairing` entry has no bytes to (re-)append, so it is treated like a not-held op: skip
    // it and owe no ack — `advance_commit`/`request_repair` recovers its body from a peer. A
    // `Body::Reconfigure` op IS body-bearing (`body_bytes()` yields its `encode_body()`): it is the
    // adopted carried reconfiguration op, and a new primary that is its sole live holder MUST re-append
    // its successor bytes durably (header over those bytes), or its own vote is owed off an absent body
    // and the carried change can never re-commit.
    let Some(body) = entry.body_bytes() else {
      return;
    };
    let header = Header::new(
      OpNumber::with(op),
      self.view,
      entry.client,
      entry.request,
      &body,
    );
    let id = self.mint_op_id();
    wal.submit_append(id, OpNumber::with(op), header, body);
    self.pending.insert(id.get(), kind);
    // Append-before-ack: the adopted op is in flight until `on_wal_done`. Both adoption kinds
    // (AdoptVote → own vote, AdoptAck → PrepareOk) defer their cast to completion; tracking the op
    // here keeps the durable predicate uniform so the choke-point gate covers the adoption path too.
    self.appending.insert(op);
  }
}

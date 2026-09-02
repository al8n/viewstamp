use super::*;

impl<S: StateMachine, R: Reconfig> Endpoint<S, R> {
  /// Set this replica's own vote bit on `op`'s inflight entry (no-op if the entry is gone). Used by
  /// the primary's normal-path own append (`Pending::Ack`) and the view-change adoption append
  /// (`Pending::AdoptVote`) — both record the own vote ONLY once the op's WAL append is durable.
  pub(crate) fn record_own_vote(&mut self, op: u64) {
    // A vote is valid only from a voter of the membership in force when it is CAST, never the one
    // in force when its append was staged — the own-vote instance of the rule
    // [`Self::send_do_view_change`] states for the deferred view-change vote. A landing-driven
    // configuration install rekeys the vote bitsets but PRESERVES the pending appends and inflight
    // entries of a node it retains as a learner, so an `AdoptVote`/`Ack` append staged while this
    // node held voter authority can complete after a demotion; ORing the own bit then would place
    // a non-voter slot's bit in a tally a retained voter's bit can complete into a quorum. The
    // check lives here — the one point every own-vote lane funnels through — so no completion
    // path can cast a vote this node no longer holds the authority for. The append itself stays
    // durable and correct: a learner keeps the log; it is the VOTE that is refused.
    if !self.is_voter() {
      return;
    }
    // Never count this replica's own bit toward a reconfiguration op that seats a brand-new voter
    // against its current configuration — the own-vote half of the vote-mint screen pair (the ack
    // half is [`Self::send_prepare_ok`]). Covers every own-vote lane that sets the bit here: the
    // primary's normal-path append completion, the view-change adopted-tail re-append, and the
    // peer-repair fill of an adopted header-only tail op. The one other own-bit site — the
    // solo-voter recovery reseed ([`Self::resume_solo_voter_pipeline`]) — applies the same refusal,
    // so with both screen halves in place no compliant vote for such an op exists anywhere, and even
    // a single corrupted `PrepareOk` cannot complete a commit quorum at any cluster size — the own
    // bit it would combine with is never set.
    if self.op_is_direct_voter_add(op) {
      return;
    }
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

  pub(crate) fn view_change_timeouts<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
    if self.timers.svc_message.is_some_and(|d| d <= now) {
      self.push_svc(self.svc_target); // re-broadcast the live SVC target (drives escalation under loss)
      self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
    }
    // Gate the DVC retransmit on the DURABLE-VIEW WITNESS (durable-view-before-participate in the
    // retransmit path): the DVC is a VOTE the new primary counts toward forming the view, so it may
    // be (re)cast only while `self.view == self.durable_view` — the current view provably survives a
    // crash. `enter_view_change` arms `dvc_message` AND submits the SendDoViewChange durable-view
    // write, with the INITIAL DVC deferred to `on_sb_done` (which advances the witness, then casts);
    // if the async superblock write is slower than `VC_MESSAGE_RETRANSMIT`, this retransmit would
    // otherwise fire first and cast the vote BEFORE the view is persisted — a crash then recovers the
    // OLD view after this replica helped form a quorum for the new one. The witness equality (rather
    // than the in-flight `pending_durable_view()`) also holds the gate on any posture whose view was
    // never SUBMITTED for persistence at all — no write in flight is then vacuously true, but the
    // witness inequality still refuses the vote. Kept in LOCKSTEP with `serviceable_now(DvcMessage)`
    // (which gates the same way), so a `dvc_message` armed-and-due while the view is not durable is
    // non-serviceable: `poll_timeout` filters it out (no spin) and the `handle_timeout` no-orphan-due
    // assert ignores it.
    if self.durable_view == self.view && self.timers.dvc_message.is_some_and(|d| d <= now) {
      self.send_do_view_change(now);
      self.timers.dvc_message = Some(now + VC_MESSAGE_RETRANSMIT);
    }
    if self.timers.get_view_message.is_some_and(|d| d <= now) {
      self.send_get_view(now); // re-sends and re-arms get_view_message
    }
    if self.timers.view_change_status.is_some_and(|d| d <= now) {
      // The change did not complete (the next primary is also down, or our catch-up target is
      // unreachable): drive the next view's SVC. A CATCH-UP posture stays a catch-up while it does —
      // the discriminant deliberately never flips, because its view came from ONE unvalidated
      // advertised scalar and was never made durable: a flipped collection would migrate into the
      // DVC-casting regime (`serviceable_now(DvcMessage)` requires `!catching_up()`) and cast a
      // VOTE for that view — the durable-view-before-participate breach a crash converts into
      // cross-crash double-participation (recover at the old durable view, free to vote again).
      // The escalation only needs the SVC anyway — a PROPOSAL, not a vote, needing no durability:
      // if the advertised view was real but its primary died mid-handoff, the peers durably AT it
      // accept our successor target and the ordinary SVC-quorum entry (`enter_view_change`, which
      // persists before voting) takes over from there.
      if self.catching_up() {
        // Bound the probe: a view NOBODY validates across the whole window — no StartView /
        // RecoveryResponse adoption, no SVC takers — is the corrupted-scalar class
        // ([`MAX_VIEW_JUMP`]'s documented adversary), and the posture is otherwise un-exitable
        // (GetView for it is unanswerable, our successor SVCs are implausible to every peer, and
        // all real cluster traffic reads as stale). REVERT instead of stranding until a process
        // restart. Only voters reach this expiry (`arm_timers` leaves `view_change_status`
        // disarmed for learners), and a voter's catch-up entry advanced the view strictly above
        // the landing computed below; the guard keeps that precondition explicit.
        //
        // The landing is the TIMELINE'S BACK, not the landed root. That is where a crash during
        // this posture recovers — recovery baselines `view` on the effective root — so landing
        // there is what makes the revert equivalent to the crash it stands in for. Landing on the
        // landed view instead would drop a live endpoint BELOW a view already owed to the medium,
        // and the inherited root's landing would then lift the durable-view witness past the live
        // view. With no root in flight the two coincide and this is the landed view exactly.
        let revert_to = self.durable_view.max(storage.effective_root().view());
        let vc = self
          .view_change
          .as_mut()
          .expect("ViewChange status implies a live collection");
        vc.catchup_windows = vc.catchup_windows.saturating_add(1);
        if vc.catchup_windows >= CATCH_UP_VALIDATION_WINDOWS && self.view.get() > revert_to.get() {
          self.revert_catch_up_to_effective_view(now, revert_to);
          return;
        }
      }
      self.propose_next_view(now, storage);
      self.arm_timers(now);
    }
  }

  /// Abandon an UNVALIDATED catch-up posture and return to `revert_to` — the view a crash during
  /// the posture would recover, which is the timeline's back (the durable view raised by any root
  /// still owed to the medium), NOT the landed root's view. Vote-safe by construction: the
  /// abandoned view was adopted in memory only (never submitted for persistence — a crash at any
  /// point during the posture recovers exactly where this revert lands), and the posture cast no
  /// vote in it (the `catching_up` discriminant never flips, so the DVC regime was unreachable;
  /// SVCs are proposals, not votes).
  ///
  /// Landing on the timeline's back rather than the landed root is what keeps the durable-view
  /// witness at or below the live view: a root already owed to the medium carries a view this
  /// endpoint must not fall beneath, since its landing lifts the witness unconditionally.
  ///
  /// The landing is NOT sticky (shared with the crash-recovery path, which lands the same way): the
  /// replica returns to a view the cluster may have legitimately moved far beyond, and
  /// rejoins through either ordinary channel — authoritative traffic from a live primary re-opens
  /// the higher-view catch-up ([`Self::catch_up_to_view`]), and any live voter's strictly-higher
  /// `StartViewChange` proposal is joinable at any distance ([`Self::on_start_view_change`]), so a
  /// view that really formed and then lost its primary while this replica was partitioned through
  /// the whole window becomes reachable again the moment any of its survivors proposes a successor
  /// off its idle timer.
  ///
  /// The revert's landing depends on this replica's role at `revert_to`:
  /// - A BACKUP resumes Normal directly. The probe's entry reset dropped only generation-local state
  ///   a backup re-derives (its ack bookkeeping re-fires off the primary's retransmits; its session
  ///   rows of record are the APPLIED ones, which the reset retains), so the resumed backup is
  ///   behaviorally the pre-probe backup.
  /// - The PRIMARY of that view must NOT resume serving: the probe's entry reset destroyed
  ///   its accepted-but-uncommitted generation state (the provisional session watermarks and the
  ///   vote tallies), so a resumed primary would re-mint a retried request it already holds in its
  ///   log — a double-execution once a later view change re-commits both copies — and could never
  ///   commit the ops whose tallies were dropped. It therefore lands in the DEFERRED-FORFEIT
  ///   step-down ([`Self::defer_forfeit`] — the existing chokepoint for a primary that cannot
  ///   continue with a torn-down pipeline): minting is refused (`SteppingDown`) and the next primary
  ///   tick proposes the successor view, whose formation re-selects the canonical log (the held ops
  ///   re-commit under fresh quorums) and re-seeds the session watermarks (the retry dedups).
  fn revert_catch_up_to_effective_view(&mut self, now: Instant, revert_to: View) {
    self.view = revert_to;
    self.svc_target = self.view;
    self.svc_from = 0;
    // Exit ViewChange: the collection is the posture (`is_some() == is_view_change()` coupling).
    self.view_change = None;
    self.set_status(Status::Normal);
    self.arm_timers(now);
    if self.is_primary() {
      // AFTER `arm_timers` (whose role reset would clobber the serviceable `svc_message` wake the
      // step-down bootstraps).
      self.defer_forfeit(now);
    }
  }

  /// A Normal backup heard from its primary this view: defer the idle timeout.
  pub(crate) fn note_primary_contact(&mut self, now: Instant) {
    if self.status.is_normal() && !self.is_primary() {
      self.arm_primary_idle(now);
    }
  }

  /// Collect (and, when it raises our target, join) a peer voter's `StartViewChange{target}`
  /// proposal.
  ///
  /// ADMISSION: any target STRICTLY above our view is joinable; a target at/below it is stale and
  /// ignored. No upper bound is imposed, and convergence REQUIRES that: live voters can hold
  /// FORKED Normal views at one epoch (successive commit-first reconfigurations remap primaryship
  /// across views while a StartView / sync crossing preserves one survivor's higher view), and
  /// each fork member's exact successor is then precisely the target the others never propose —
  /// an exact-successor-only admission leaves NO target a quorum can ever share (every proposal
  /// reads as stale to the higher voter or as a jump to the lower one — a permanent fault-free
  /// wedge with no primary ever formed again), while under any-higher admission the max-view
  /// voter's `view + 1` is strictly above every live voter's view, so every live same-epoch voter
  /// joins it and a live-voter quorum always forms.
  ///
  /// Joining at any distance is vote-safe because an SVC is a PROPOSAL carrying no log/lead
  /// authority: it reaches this handler only from an authenticated CURRENT-configuration voter at
  /// the EXACT epoch (`sender_matches` binds the claimed slot; the `epoch_authority_admits` arm is
  /// STRICT), and joining mutates only the flat SVC collection (`svc_target`/`svc_from`) — the
  /// status, view, log and votes move only once `maybe_start_view_change` finds an SVC QUORUM,
  /// whose entry persists the new view BEFORE casting the DVC (durable-view-before-participate),
  /// and the joined view still FORMS only on a full DVC quorum + canonical-log selection. None of
  /// those gates reads the target's distance. (The single-advertisement catch-up path is different
  /// in kind — it ADOPTS a view off ONE unvalidated normal-traffic scalar with no quorum behind
  /// it — and stays plausibility-clamped there: see [`Self::catch_up_to_view`] /
  /// [`MAX_VIEW_JUMP`].)
  pub(crate) fn on_start_view_change<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    m: crate::StartViewChange,
  ) {
    if self.is_learner() {
      // A non-voting replica is not a view-change participant: it neither joins the StartViewChange
      // quorum nor casts a vote. It follows a completed view change by adopting the new primary's
      // StartView (catching up via GetView if it falls behind), never by driving the change itself.
      return;
    }
    let target = m.view();
    if target.get() <= self.view.get() {
      return; // stale: we are already at (or beyond) the proposed view.
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
      self.maybe_start_view_change(now, storage);
    }
  }

  pub(crate) fn maybe_start_view_change<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
    if (self.svc_from.count_ones() as usize) >= self.membership.quorum_view_change() {
      self.transition_to_view_change_status(now, storage, self.svc_target);
    }
  }

  /// Enter `ViewChange` for `view_new`, reset pipeline + quorums, defer DoViewChange until view is durable.
  ///
  /// STEADY-STATE entry: asserts `view_new > self.view` (a self-driven view change must strictly
  /// advance the view). The recovery path enters via [`Self::enter_view_change_from_recovery`], which
  /// permits `view_new == self.view` (re-driving an in-progress view change after a crash) — it shares
  /// the identical body through `enter_view_change`.
  fn transition_to_view_change_status<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    view_new: View,
  ) {
    if self.sync_repersist_root_staged() {
      // Defer the SVC-quorum view change while a state-sync re-persist root is staged: let it install to
      // the synced point first (the install is destructive — see `sync_repersist_root_staged`). The
      // `StartViewChange` quorum bits persist, so the next retransmitted SVC re-evaluates the quorum and
      // re-drives this transition once the sync installs.
      return;
    }
    assert!(
      view_new.get() > self.view.get(),
      "view change must strictly advance the view"
    );
    self.enter_view_change(now, storage, view_new);
  }

  /// Recovery-only `ViewChange` entry (faithful port of TigerBeetle `replica.zig` open()): a
  /// recovered replica that was Normal as the primary ABDICATES to `view + 1`, and one that crashed
  /// mid-view-change RE-DRIVES `view` (`view_new == self.view`). The steady-state strict-advance
  /// assert ([`Self::transition_to_view_change_status`]) would trip on the re-drive, so this entry
  /// uses a relaxed `view_new >= self.view` (and `> self.view` whenever `log_view == view`, the
  /// abdication case — a Normal primary must move OFF its own view). Everything else (the pipeline /
  /// quorum / pending resets, the deferred durable-view write) is identical via `enter_view_change`.
  pub(crate) fn enter_view_change_from_recovery<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
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
    self.enter_view_change(now, storage, view_new);
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
  pub(crate) fn reset_for_view_transition<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
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
    // A deferred append is generation state exactly like the `pending` action it would have minted:
    // abandoned here so it cannot fire later and append an old generation's bytes into a slot the
    // new generation re-drives. Its `wal_writes` blocker (if any) deliberately survives — the
    // physical write is still with the device, and the slot-quiescence fence keeps that slot
    // un-reusable until the write's completion proves it quiesced.
    self.deferred_appends.clear();
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
    // KEEP an in-flight ORDINARY checkpoint whose SUPERBLOCK half has begun: once its durable root
    // write is staged it advances the durable checkpoint pointer, and `submit_durable_view`
    // COPY-FORWARDS that checkpoint into the view-change root (persisting its target + id verbatim),
    // so the view write CARRIES it forward rather than rewinding the durable checkpoint to the stale
    // pre-checkpoint pointer. The two writes then complete independently (distinct `OpId`s) in FIFO
    // order, both naming the same checkpoint.
    //
    // DROP one still at `FlushingBlocks` — its block job is being executed off the pump, nothing of it is
    // durable, and no superblock write exists to carry forward. Dropping it here is what makes a
    // materialize that crosses a view transition unable to publish: its completion finds no matching
    // token, counts as superseded, and the blocks it wrote are unreferenced garbage the next sweep
    // frees. The cadence re-forces the checkpoint once Normal resumes, exactly as it does for a
    // checkpoint the cadence never started. (This is also why the abandoned DAG costs nothing: block
    // addresses are content-derived, so a re-forced checkpoint over the same applied state re-writes
    // byte-identical blocks.)
    //
    // A state-sync re-persist is dropped at EVERY step (its `pending_install` + `sync` are cleared
    // above, so a kept one would be orphaned + incoherent); it re-solicits, its committed prefix
    // recovered from the canonical log.
    //
    // Only the LOGICAL half is dropped, and it is the only half this reset can reach. The
    // `Materialize` job a `FlushingBlocks` drop orphans is already queued on the lane and executes to
    // completion regardless — the issue-order contract admits no retraction — and the capture slot
    // it occupies belongs to the lane, not to this endpoint, so it stays taken until the lane hands
    // the image back. That is what keeps the capture site closed across the transition rather than
    // re-opening the accumulation the split exists to bound.
    if self.pending_checkpoint.as_ref().is_some_and(|pc| {
      matches!(pc.kind, CheckpointKind::SyncRepersist)
        || matches!(pc.step, CheckpointStep::FlushingBlocks(_))
    }) {
      // A dropped re-persist can already have its ROOT staged (`AwaitRoot`): the drop ends the
      // only correlation that awaited it, so the root is abandoned with it — a parked one leaves
      // its cell (nothing will ever await or complete it), a submitted one lands UNCORRELATED
      // and the landing absorb holds its facts (`on_sb_done` lifts `commit_max`, owes the
      // frontier catch-up, and enters the orphaned-re-persist reconciliation — the synced state
      // the root names was never installed here, so the node must re-fetch it before
      // participating further). The ordinary-checkpoint KEEP above never reaches here, so a root
      // that is still awaited is never abandoned. (The view-change triggers defer while a
      // re-persist root is staged — `sync_repersist_root_staged` — so this arm is the backstop
      // for any teardown path that reaches the reset outside those triggers.)
      if let Some(PendingCheckpoint {
        step: CheckpointStep::AwaitRoot(abandoned, _),
        ..
      }) = self.pending_checkpoint
      {
        // COUNT the disown: this is the only site that drops a `Checkpoint`-role root's
        // correlation, and without the counter it fires silently — the deferral guards above it
        // all live at the CALLERS, so nothing at this layer would ever say the backstop was
        // reached. The simulation sweeps assert the count stays 0.
        self.repersist_roots_disowned += 1;
        storage.abandon_root(RootRole::Checkpoint, abandoned);
      }
      self.pending_checkpoint = None;
    }
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
    // Drop any outstanding voter-liveness-probe round: it was solicited by the generation this view
    // change ends, so its evidence must not gate a shrink the successor generation drives. A new
    // primary re-solicits fresh on its own reconfiguration; carrying a stale round across would let a
    // pre-transition answer count toward a post-transition removal. Symmetry with the install-boundary
    // clear (`install_membership`); the `(epoch, config_id)` reply binding is the backstop.
    self.health_probe = None;
    // KEEP a committed-but-not-installed epoch swap across the transition. `pending_swap` is set ONLY for
    // a COMMITTED `Reconfigure` op (`stage_epoch_swap` runs at commit, after `commit_min` advanced past
    // the op), so the change is durable in the log and MUST still install — dropping it would lose a
    // committed membership change (the cluster would stay in the old epoch forever, since the new view's
    // `advance_commit` starts ABOVE the already-committed op and never re-stages it). The successor is
    // membership-derived and view-INDEPENDENT (a view change changes neither the membership nor the
    // epoch), so the staged value stays valid across the transition. Its in-flight `SwapEpoch` root (if
    // any) is superseded on the superblock by the imminent durable-view write — its CORRELATION only:
    // the write itself stays on the session timeline, its landing still installs the successor (the
    // `on_sb_done` configuration adoption, which consumes this staged swap and emits the event), and
    // the durable-view root minted here carries the successor configuration forward off that timeline
    // (`durable_root`'s copy-forward), so no landing order can rewind the durable configuration.
    // With NO swap root in flight (the stage deferred behind an in-flight checkpoint/view write),
    // `pending_swap` survives and `maybe_swap_epoch` RE-SUBMITS it once a
    // superblock slot frees: from `on_sb_done` when the durable-view root lands, and from the commit
    // tails (`try_commit` / `advance_commit`) for the `catch_up_to_view` path that issues no durable-view
    // write. The durable-epoch-before-participate fence holds throughout — the membership installs
    // only at an epoch-advancing root's landing. (Invariant (7) — "a staged swap always
    // has a superblock write outstanding" — is momentarily relaxed across this reset: the superseding
    // durable-view write keeps a write in flight whenever a view change issues one, and the commit-tail
    // re-submit covers the no-write `catch_up_to_view` path; `assert_invariants` does not run mid-reset.)
    // Abandon any PRE-ROOT in-flight state-sync: a view change supersedes it (state-sync and view
    // change are mutually exclusive by status — §2.6). The `sync` handshake, its PRE-ROOT staging
    // (`pending_install`), and any in-progress block-DAG transfer (`block_fetch`) are cancelled TOGETHER:
    // with durable-before-install the STAGE never restored the SM, advanced `commit_min`/`op`, nor pruned
    // the WAL, so this finds the OLD (consistent, if stale) state intact — there is NO pruned-but-stale
    // window. Dropping `pending_install` here releases the staged snapshot bytes — and, gated by the
    // `sync.is_some()` cleared alongside, the `on_sb_done` install arm can never fire against a cancelled
    // sync (the `assert_invariants` `pending_install ⟹ sync` + `transfer ⟹ sync` clauses guard this).
    //
    // EXCEPTION — an SM-RECONSTRUCT obligation survives the transition. Once a synced checkpoint `M`'s
    // re-persist root is durable, `self.checkpoint_op == M` IN LOCKSTEP with the durable root: there is NO
    // pointer to rewind (in-memory already equals durable), so this is kept ONLY for LIVENESS — to keep the
    // SM-content retry alive. KEEP `sync` + `block_fetch` (a live fetch, kept whole under the kept sync) +
    // `sm_reconstruct` + the serviced ARQ across the transition; `pending_install` (a pre-root staging a
    // superseding sync may have started) is still cleared — the obligation, not that staging, is the
    // durable truth. The retry resumes the instant the node returns to Normal/Recovering; a durable-view
    // write meanwhile reads the already-correct `self.checkpoint_op == M` and cannot rewind.
    self.pending_install = None;
    if !self.sm_reconstruct_owed() {
      self.sync = None;
      self.block_fetch = None;
      self.timers.sync_solicit = None;
    } else if self.status.is_normal() {
      // The obligation survives; re-arm its serviced ARQ for the status this transition is LANDING in. The
      // callers set `self.status` before this reset, so a Normal landing (`adopt_canonical_head`, or a
      // primary start) re-arms `sync_solicit` — the path that re-pulls M's DAG and retries the restore. A
      // ViewChange landing leaves it (no ARQ is serviced there) until the node next reaches Normal and this
      // reset re-arms it; a Recovering landing (`on_recover_*`) rebuilds its own `recover`/`recover_retry`
      // right after this reset, which re-drives the peer-fetch under the kept obligation.
      self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
    }
    // A view change ends this primary generation: clear any forfeit grace timer AND any
    // deferred-forfeit flag (the safety step-down — see `maybe_force_sync`). The new generation
    // re-evaluates from scratch once it resumes Normal as primary, so neither a stale grace deadline
    // nor a stale pending-forfeit must carry across (no same-view re-forfeit / cross-view leak).
    self.timers.forfeit_armed = None;
    self.pending_forfeit = false;
    // A view change ends this primary generation: drop the nack tally. The candidate (a header-only
    // `Repairing` op above `commit*` with no `Present` donor) is re-evaluated from scratch by the NEXT
    // primary's `select_canonical_log` (it may again be a candidate, may now be `Present` on a donor, or
    // may be nack-truncated) — so a stale tally must not carry across (no cross-generation truncation): a
    // fresh generation re-gathers nacks against its OWN candidates, and a nack keyed to a candidate that no
    // longer exists (or a member no longer voting) must not linger.
    self.nack_from.clear();
  }

  /// The shared `ViewChange`-entry body (no view-advance assert — the callers assert their own
  /// contract). Resets the pipeline + quorums and defers the DoViewChange until the new view is durable.
  fn enter_view_change<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    view_new: View,
  ) {
    self.view = view_new;
    self.set_status(Status::ViewChange);
    self.svc_target = view_new; // collect future escalations above this view
    // Tear down ALL old-generation in-flight state in one place: SVC bits, in-flight
    // appends, peer-checkpoint reports, in-flight checkpoint, in-flight sync + its deferred install, and
    // the forfeit sub-state.
    self.reset_for_view_transition(now, storage);
    // ViewChange ENTRY: install a fresh ViewChange-only collection — `catching_up = false` (a real,
    // self-driven change, not the higher-view catch-up). (`is_some() == is_view_change()` coupling.)
    self.view_change = Some(ViewChangeCollection::entering(false));
    // The primary pipeline + backup reorder buffer are dropped on this self-driven entry (kept OUT of
    // the shared reset because `adopt_canonical_head` preserves a live primary pipeline).
    self.inflight.clear();
    self.buffer.clear();
    self.arm_timers(now);
    // DVC deferred to on_sb_done: persist the new view before voting in it.
    self.submit_durable_view(PendingSbAction::SendDoViewChange, storage);
  }

  /// Send our full log + position to the prospective primary of the current view. A NON-VOTER sends
  /// nothing: the vote is dropped rather than emitted.
  pub(crate) fn send_do_view_change(&mut self, _now: Instant) {
    // A vote is valid only from a voter of the membership in force when it is EMITTED, never the one
    // in force when it was staged. A durable-root landing installs the successor configuration before
    // the actions correlated with that landing run, so a node the successor demotes to a learner — or
    // drops from the configuration outright — arrives here holding a vote staged under the predecessor
    // voter set; emitting it would put a non-voter's `DoViewChange` on the wire. The timer plane
    // refuses this through `serviceable_now`, but the deferred durable-view path does not run through
    // the timer plane, so the check belongs at the emission point both paths share.
    if !self.is_voter() {
      return;
    }
    let primary = self.membership.primary(self.view);
    let entries = self.log_entries();
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(primary)),
      Message::DoViewChange(
        crate::DoViewChange::new(
          self.view,
          self.log_view,
          self.op,
          // The DVC reports the KNOWN committed frontier BOUNDED BY THE HELD HEAD, `commit_max.min(op)`
          // — VSR's commit-number `k` (the highest op this replica KNOWS is committed), but never above
          // an op it actually holds. This is the vsrr analogue of TigerBeetle advertising `commit_min`
          // (an evidence-backed frontier `<= op`): a replica vouches only for what it holds, so a bare
          // peer `commit` scalar corrupted above the head (in-model, a bit-flip — see the threat model)
          // cannot make this DVC advertise `commit > op` and trip `select_canonical_log`'s `commit* <=
          // op_head` fail-stop, halting view formation cluster-wide from one faulty peer.
          //
          // The `.min(op)` never drops a committed op. A committed op N this replica HOLDS as a dropped
          // repair hole is an INTERIOR op (`N <= op`), so `commit_max.min(op) >= N` still covers it — it
          // stays a COMMITTED hole the new primary holds + peer-repairs, exactly as before. A committed
          // op N this replica does NOT hold (`commit_max > op`, the tail-gap shape) is, by quorum
          // intersection, carried in some OTHER canonical donor's `log_slice` (`select_canonical_log`'s
          // offset-union), so it survives the selection regardless of this DVC's `commit`, and the new
          // primary re-commits it via a fresh AdoptVote quorum. Under-reporting `commit` only DEFERS such
          // an op to re-commit; it never truncates it (truncation is by the offset-union, not `commit*`).
          self.commit_max.min(self.op),
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
    storage: &mut Storage<W, B, S>,
    m: crate::DoViewChange,
  ) {
    // Incoming DVC well-formedness is NOT validated here (commit <= op; the log is the OFFSET tail
    // `(checkpoint .. op]`, dense WITHIN that range — it is NOT required to be dense from op 1, since
    // a recover-from-checkpoint / state-synced sender legitimately omits the prefix that lives in its
    // SM snapshot). That holds under the crash-stop threat model this crate targets, where a peer
    // never emits a malformed DVC; admitting untrusted senders would require validating it. The
    // cross-DVC commit* <= op_head invariant IS enforced (fail-stop) in `select_canonical_log`.
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
        // Report the known committed frontier bounded by the held head, `commit_max.min(op)` — see
        // `send_do_view_change` for the full rationale. This own-DVC feeds the same `select_canonical_log`
        // `commit*` union, so it must carry the same held-bounded frontier the wire DVC does.
        self.commit_max.min(self.op),
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
      self.start_view_as_new_primary(now, storage);
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
    storage: &mut Storage<W, B, S>,
  ) {
    // No NEW checkpoint starts when forming a new primary's view (`maybe_checkpoint` is gated on Normal
    // status). An ORDINARY checkpoint kept in flight ACROSS the transition is permitted: it completes
    // independently (distinct `OpId`) and `submit_durable_view` COPY-FORWARDS it into the view-change root
    // (see there). A state-sync re-persist was dropped on entering ViewChange (its install was cleared).
    debug_assert!(
      self
        .pending_checkpoint
        .as_ref()
        .is_none_or(|pc| matches!(pc.kind, CheckpointKind::Ordinary)),
      "only an ordinary checkpoint may be in flight when forming a new primary's view"
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
    // Re-establish the committed frontier from the view-change-authoritative `commit*`, DISCARDING any
    // stale/poisoned pre-view `commit_max`. `commit*` is the quorum-vouched, held-bounded committed
    // frontier (`<= op_head` by `select_canonical_log`, now that every DVC advertises `commit_max.min(op)`),
    // so it is the correct new authority — the vsrr analogue of TigerBeetle deriving the view's commit from
    // the JoinView quorum rather than carrying a learned hint across the transition. This must OVERWRITE,
    // not `max`: a replica that adopted a bare corrupt `commit` scalar (in-model) before becoming primary
    // would otherwise carry `commit_max > op` past here — wedging the AdoptVote tail-seeding below
    // (`(commit_max .. op]` goes empty, so the genuinely-uncommitted tail is never re-voted) and, worse,
    // broadcasting `commit_max > op` in the deferred `start_view_participate` StartView, tripping every
    // backup's `adopt_canonical_head` `commit <= op` assert. A committed op above `commit*` (the tail-gap
    // case) is carried in the canonical union and re-committed by the AdoptVote quorum below, so lowering
    // `commit_max` to `commit*` defers it, never drops it. (`advance_commit(commit*)` next is then a no-op
    // raise.)
    self.commit_max = OpNumber::with(commit_star);
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
    // (checkpoints only start in Normal) — no NEW checkpoint starts. An ordinary checkpoint kept in flight
    // across the transition is carried forward verbatim by the StartViewAsPrimary durable-view write below
    // (`submit_durable_view` copy-forwards it), so it does not rewind the durable checkpoint.
    //
    // The tail CAN, however, enter the owed orphaned-re-persist reconciliation (the debt latched
    // while a durable-view write deferred it, and this is the first tail with every deferral
    // clear): the forming generation is then torn down into the recovery peer-fetch, and the
    // formation MUST stop — continuing would overwrite `Recovering` with `Normal` and stage a
    // `StartView` for a checkpoint frontier this replica never installed. The fetched install
    // completes recovery, which re-drives the view change (`log_view < view`) over installed
    // state.
    if self
      .advance_commit(now, storage, commit_star) // apply newly-exposed committed ops (prior-view quorum decision)
      .entered_recovery()
    {
      return;
    }

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
    // Retire the appends the backend could cancel synchronously; any it could NOT cancel stay in
    // `wal_writes` as un-quiesced writes, and the adopt-append loop below defers every re-append
    // whose slot one of them still holds (the slot-quiescence fence).
    let cancelled = storage.truncate(self.op);
    self.absorb_wal_cancellations(storage, cancelled);

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
    // truncation candidate whose body never arrives — the nack-quorum truncation (`on_nack` →
    // `truncate_uncommitted_tail_from`) ROLLS the watermark back when it truncates such an op (a
    // truncated request must be processed fresh, never deduped to a no-reply hang), so seeding it
    // here is safe.
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
    // The interior-gap cut above (and `adopt_log`'s tail trim this routed through) may have truncated a
    // `Present` accept-ahead tail op while this replica formed the new view; the backfill loop only RAISES,
    // so roll any watermark that truncation orphaned back to its backed floor here too — else this new
    // primary dedups the truncated request's retransmit to a no-reply hang.
    self.reconcile_session_watermarks();

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

    // Nack-truncation (the f-fault-model liveness closure). A header-only `Repairing` op ABOVE `commit*`
    // is a *repair-or-truncate candidate*: NO canonical-quorum donor held it `Present` (the offset-UNION
    // in `select_canonical_log` prefers `Present`, so an op that adoption left `Repairing` is one no
    // canonical donor — and no local matching body — could supply), AND it is above the known-committed
    // frontier, so the cluster never observed it committed on the collected quorum. The keep-vs-truncate
    // decision is locally UNDECIDABLE: this could be a committed op whose body-holders were merely
    // partitioned out of the DVC quorum (World A — must keep + repair), or a genuinely-uncommitted no-body
    // op (World B — must truncate, else its perpetual repair hole drops every client at `on_request`
    // forever). The COUNTING proof resolves it as peers answer: `request_repair` above solicits each
    // candidate, and a peer that durably LACKS it answers a [`crate::Nack`] instead of a `Present` body.
    // A holder answering with the body fills + keeps the op (World A); once `f+1` distinct voters nack a
    // candidate ([`Self::on_nack`]) it is provably uncommitted and the tail is truncated (World B). A
    // candidate that reaches neither BLOCKS — the safety-first trade (a possibly-committed op is never
    // truncated on a timer). No deadline is armed here; truncation is event-driven on the nack quorum.

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
      self.adopt_append(storage, op, Pending::AdoptVote(OpNumber::with(op)));
    }

    // Defer participation (StartView broadcast + arm_timers + try_commit) to on_sb_done. The own votes
    // accrue independently as the AdoptVote appends complete; a StartView/own-vote never outruns its
    // WAL append (for replica_count > 1 the lone own vote is below quorum, and backups only ack after
    // this StartView, so no adopted op can commit before BOTH its append and the durable-view land).
    self.submit_durable_view(PendingSbAction::StartViewAsPrimary, storage);
  }

  /// Runs once the new-primary superblock write is durable: broadcast StartView + begin committing.
  pub(crate) fn start_view_participate<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
    // Leading the view — broadcasting its canonical log and tallying its commits — is authority
    // under the membership in force NOW, the emission-point rule `send_do_view_change` applies to
    // the deferred vote. The durable-view completion that dispatches here can outlive a
    // landing-driven configuration install (the landing installs BEFORE the correlated arms run),
    // so a node staged as the new primary can arrive demoted to a learner — or a retained voter
    // whose primary slot the successor layout remapped. Either way it no longer leads: broadcast
    // nothing and tally nothing. The role cadences the install re-armed (or retired) already
    // govern how this node follows the view's real primary.
    if !self.is_primary() {
      return;
    }
    // Reconcile an owed orphaned-re-persist debt BEFORE building the StartView. The debt can latch
    // in exactly this write's flight window: an uncorrelated checkpoint-role landing absorbs its
    // frontier into `commit_max` and records the owed reconciliation, and the reconciliation guard
    // defers to this completion arm (a durable-view write is never torn down mid-flight). Entering
    // the reconciling recovery ends this generation, so it must run before any participation is
    // staged — deferring it to the commit tail below would broadcast first and reconcile after,
    // with the prohibited participation already on the wire. Adopt-then-check mirrors the commit
    // tails: a frontier the applied prefix already covers is adopted in place and retires the debt
    // instead of tearing the generation down.
    self.maybe_adopt_inherited_frontier();
    if self
      .maybe_enter_orphan_repersist_recovery(now, storage)
      .entered_recovery()
    {
      return;
    }
    // `Continue` above means "did not enter recovery", NOT "no debt owed": the reconciliation's
    // deferral arms return it with the debt still latched. Gate participation on the debt ITSELF,
    // exactly as the `on_get_view` / `on_recovery` handouts do. The one deferral arc reachable at
    // this emission is an owed SM-reconstruct (the arc whose retry install sits below the owed
    // frontier) — the in-flight-checkpoint arc cannot coexist with a latchable debt (the
    // `force_checkpoint` timeline fence demands `commit_min` at/above the effective frontier the
    // latch demands it below), and the durable-view arc is this very completion — but the withhold
    // reads the debt, not the arc, so any future deferral shape is covered identically. A landing
    // that latched a debt also absorbed a commit frontier this canonical log may not carry
    // (`commit_max` above `op`), so a StartView built now would fail-stop every adopting backup at
    // the `commit <= op` adopt guard — in release, where the emission assert below is compiled
    // out, straight off the wire. Keep the timers armed and stand down: the deferred-to arc
    // completes, the heartbeat re-drive consumes the debt (entering the reconciling recovery, or
    // retiring it through the applied frontier), and participation resumes through that
    // resolution — the solicitors' retransmits re-drive the withheld handouts meanwhile.
    if self.repersist_orphan_owed().is_some() {
      self.arm_timers(now);
      return;
    }
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
    // peer-repairs it.
    //
    // `commit_max <= self.op` is a FORMATION-layer bound (`commit_max == commit_star <= op_head ==
    // self.op` by `select_canonical_log`'s fail-stop) and this emission runs a root-landing window
    // later, so it is re-checked HERE, at the emission layer. The in-window raiser is an
    // uncorrelated commit-proven landing: one that latched a debt was consumed above (entered,
    // retired through the applied-frontier leg, or withheld on), and one that lifted a frontier
    // the applied prefix covers keeps `commit <= op_head` because a genuinely committed op is
    // carried by some canonical donor. The assert pins the emission-layer half of the receiver's
    // `commit <= op` adopt guard against any raiser class a future absorb adds.
    debug_assert!(
      self.commit_max.get() <= self.op.get(),
      "StartView would advertise commit {} above its op {}",
      self.commit_max.get(),
      self.op.get(),
    );
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
    // Nothing follows this call AND nothing prohibited precedes it: the owed-debt reconciliation ran
    // before the StartView above, and no landing can interleave inside this synchronous arm, so the
    // tail's own re-check cannot newly tear the generation down — the discard is terminal on both
    // sides of the call.
    let _ = self.try_commit(now, storage);
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
    // The adopted canonical log dropped any uncommitted tail above the applied frontier — including a
    // deposed primary's accept-ahead `Present` op whose session watermark was bumped at accept time. Roll
    // any watermark that op left orphaned back to its backed floor (see `reconcile_session_watermarks`):
    // without this, a later retransmit of that truncated request dedups as a duplicate whose cached reply
    // is for an earlier request, so the primary resends nothing AND mints nothing, hanging the client.
    self.reconcile_session_watermarks();
  }

  /// Re-establish the session dedup-watermark backing invariant after an adoption truncated the log tail.
  /// A watermark (`Session::request`) may legitimately exceed `max(reply.request, highest in-log request
  /// for that client)` ONLY as a primary's accept-ahead while the minted op is still in `self.log`. Adopting
  /// a canonical log can DROP that op (a deposed primary's uncommitted accept-ahead tail), and the adoption
  /// path does not roll the watermark back — orphaning it. A later retransmit of that truncated request then
  /// dedups as a duplicate (`request == session.request`) whose cached reply is for an EARLIER request, so
  /// the primary resends nothing AND mints nothing: the client hangs forever and the cluster livelocks.
  ///
  /// Roll every orphaned watermark down to its backed floor. The `>` guard never RAISES (so it cannot
  /// regress a legitimate watermark — the new-primary backfill owns raising) and never lowers below the
  /// cached-reply request (so at-most-once holds: a committed request stays deduped). This mirrors the
  /// `Repairing`-hole rollback the nack-quorum truncation performs (`on_nack` →
  /// `truncate_uncommitted_tail_from`), extended to the ADOPTION-truncation of a `Present` tail op
  /// that the nack path (keyed on header-only `Repairing` candidates) does not cover.
  fn reconcile_session_watermarks(&mut self) {
    let mut highest_in_log: BTreeMap<u128, u64> = BTreeMap::new();
    for e in self.log.values() {
      let slot = highest_in_log.entry(e.client.get()).or_insert(0);
      *slot = (*slot).max(e.request.get());
    }
    for (client, session) in &mut self.clients {
      let reply_request = session.reply.as_ref().map_or(0, |(rn, _)| rn.get());
      let backed = reply_request.max(highest_in_log.get(client).copied().unwrap_or(0));
      if session.request.get() > backed {
        session.request = RequestNumber::with(backed);
      }
    }
  }

  pub(crate) fn on_start_view<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
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
    if self.sync_repersist_root_staged() {
      // Defer adopting the canonical log while a state-sync re-persist root is staged: the install
      // (destructive — see `sync_repersist_root_staged`) must complete to the synced point before we
      // overwrite `op`/`commit_min`/`self.log` with the adopted head. The primary retransmits its
      // `StartView`, re-driving the adopt from the cleanly-synced state.
      return;
    }
    // An adoption that routed into the recovery peer-fetch adopted the head as data but ended the
    // generation: leave the WAL tail to the reconciling install (it prunes and truncates at the
    // synced point), exactly as if the StartView had arrived while already Recovering.
    if self
      .adopt_canonical_head(
        now,
        storage,
        m.view(),
        m.op(),
        m.commit(),
        m.checkpoint_op(),
        m.log_slice(),
      )
      .entered_recovery()
    {
      return;
    }
    self.truncate_wal_above_adopted_head(storage);
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
  pub(crate) fn truncate_wal_above_adopted_head<W: Wal, B: Superblock>(
    &mut self,
    storage: &mut Storage<W, B, S>,
  ) {
    // Committed-survival backstop on the BOUNDARY freed WAL slot `self.op + 1`: the adopted head is the
    // view's authoritative head, so nothing strictly above it is committed (the uncommitted clause).
    self.assert_committed_survives(self.op.get() + 1, self.checkpoint_op.get());
    // Retire what the backend could cancel synchronously; the rest stay in `wal_writes`, fencing
    // every re-append to their slots until they quiesce.
    let cancelled = storage.truncate(self.op);
    self.absorb_wal_cancellations(storage, cancelled);
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
  //
  // Returns the adoption's status outcome: [`CommitFlow::EnteredRecovery`] when the commit tail
  // (or the owed-debt check below it) routed the adopter into the recovery peer-fetch instead of
  // settling Normal — the callers' post-adoption steps must short-circuit on it.
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn adopt_canonical_head<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    view: View,
    op: OpNumber,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    log: &[crate::PreparedEntry],
  ) -> CommitFlow {
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
    // tail is a no-op (checkpoints only start in Normal) — no NEW checkpoint starts; an ordinary
    // checkpoint kept in flight is carried forward verbatim by the AdoptedStartView durable-view write
    // below (`submit_durable_view` copy-forwards it), so it does not rewind the durable checkpoint.
    //
    // For a ViewChange (or Normal) adopter the tail can enter the owed orphaned-re-persist
    // reconciliation directly: the adopting generation is torn down, so the adoption stops here —
    // the head/log adoption above is pure data (memory-only), and the reconciling install decides
    // the tail when it completes recovery.
    if self
      .advance_commit(now, storage, commit.get())
      .entered_recovery()
    {
      return CommitFlow::EnteredRecovery;
    }
    // A `RecoveringHead` exit with the orphaned-re-persist debt still owed. The commit tail above
    // DEFERRED the reconciliation (a head-recovery is a recovery in flight), and this adoption is
    // that recovery's completion — the one that does not route through `complete_recovery`'s
    // refusal — so the debt is paid here, not stepped over into Normal: a quiescent backup
    // settled Normal over it would have no commit tail to re-drive the reconciliation, and its
    // next view change would cast votes over a superseded pointer. The adopted head/log stay
    // (they are the data this exit came for, superseding the head-recovery bookkeeping exactly as
    // the Normal exit below does); the endpoint enters the reconciling recovery instead of
    // Normal, and the install that completes it re-drives the view (`log_view` stays behind
    // `view`).
    if self.status.is_recovering_head() && self.repersist_orphan_owed().is_some() {
      self.enter_orphan_repersist_recovery(now, storage);
      return CommitFlow::EnteredRecovery;
    }
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
    self.reset_for_view_transition(now, storage);
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
    // (This is the distinguishing reset only the adoption path owns.) Nothing else needs retiring
    // with it: `RecoveringHead` is entered only over a drained read fence — BOTH halves, since
    // `recover_progress` holds behind `rec.pending` and behind the checkpoint phase marker, which
    // stays `Some` for as long as any submitted checkpoint read is tracked — so no read completion
    // remains owed, and any hole the adopted log re-carries `Repairing` is the ordinary peer-repair
    // lane's to fill. (The one exit that DOES re-open the checkpoint phase, the owed
    // orphaned-re-persist reconciliation, returned above rather than reaching here.) Asserted, like
    // every other site that drops the recovery bookkeeping, so no transition can silently abandon a
    // read obligation the medium still owes.
    assert!(
      self.recover.as_ref().is_none_or(|rec| {
        rec.pending.is_empty() && rec.reads.is_empty() && rec.checkpoint_reads.is_empty()
      }),
      "adopting a canonical head over an open read fence"
    );
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
    self.submit_durable_view(PendingSbAction::AdoptedStartView, storage);
    CommitFlow::Continue
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
  pub(crate) fn start_view_acks<W: Wal, B: Superblock>(&mut self, storage: &mut Storage<W, B, S>) {
    let lo = self.commit_min.get().max(self.commit_max.get());
    for op in (lo + 1)..=self.op.get() {
      self.adopt_append(storage, op, Pending::AdoptAck(OpNumber::with(op)));
    }
  }

  /// Re-drive the durable append of any adopted uncommitted-tail op whose adoption-time
  /// (re-)append was SKIPPED over the ring window ([`Self::adopt_append`]'s wrap guard). Runs at
  /// every `checkpoint_op` advance — the exact event that slides the ring window forward and makes
  /// a previously-unappendable op fit — because nothing else re-drives such an op: the adoption
  /// already installed it in `self.log` and advanced `self.op`, so a Prepare retransmit lands in
  /// the `pop <= self.op` re-ack branch (which defers to durability that never arrives), and the
  /// primary receives no retransmit at all. Without this, the skipped op is never durably held, its
  /// vote/ack is never cast, and with one backup unavailable the view wedges on an uncommittable
  /// tail despite every replica being live.
  ///
  /// The primary re-appends tagged `AdoptVote` (its own inflight vote, cast in `on_wal_done` when
  /// the append lands), a backup tagged `AdoptAck` (the deferred `PrepareOk`) — the same kinds the
  /// adoption itself used. Ops already durable, already in flight, body-less (`Repairing` — the
  /// repair channel owns those, casting the vote via the `RepairFill` completion), or still over
  /// the window (`adopt_append` re-checks) are skipped; a still-over-window op is retried at the
  /// next advance. Convergence is guaranteed by the [`Wal::capacity`] liveness contract (the ring
  /// exceeds one checkpoint interval plus the pipeline): a skip then implies the adopted committed
  /// band crosses a checkpoint boundary, so applying it keeps ordinary checkpoints firing — each
  /// advance slides the window a full interval — until the window admits the whole tail; no new
  /// client traffic or retransmit is needed to release the re-drive.
  ///
  /// GATED on no durable-view write being in flight (durable-view-before-participate): an ordinary
  /// checkpoint root submitted before a view transition survives it and may complete while the
  /// adopted view's own root is still in flight — appending then would let `on_wal_done` cast the
  /// AdoptAck's `PrepareOk` for a view this replica could still roll back from on crash. The gated
  /// advance is not lost: the durable-view completion itself re-drives (a backup re-runs the full
  /// loop via [`Self::start_view_acks`]; the new primary re-runs this sweep from its
  /// `StartViewAsPrimary` completion arm).
  pub(crate) fn retry_unappended_adopted_tail<W: Wal, B: Superblock>(
    &mut self,
    storage: &mut Storage<W, B, S>,
  ) {
    if !self.status.is_normal() || self.pending_durable_view() {
      return;
    }
    let lo = self.commit_min.get().max(self.commit_max.get());
    for op in (lo + 1)..=self.op.get() {
      if self.appending.contains(&op) || self.op_durably_appended(storage, op) {
        continue;
      }
      let kind = if self.is_primary() {
        Pending::AdoptVote(OpNumber::with(op))
      } else {
        Pending::AdoptAck(OpNumber::with(op))
      };
      self.adopt_append(storage, op, kind);
    }
  }

  /// Durably (re-)append an op the replica adopted into `self.log` during a view change, recording the
  /// deferred action (`Pending::AdoptVote` for the new primary's own vote, `Pending::AdoptAck` for a
  /// backup's PrepareOk) so `on_wal_done` casts it ONLY once the append lands (append-before-ack). The op's body lives only in the in-memory `self.log` until this completes —
  /// mirroring `append_prepare`, but for the already-installed adopted entry rather than an incoming
  /// `Prepare`. Header is written under the current (new) view, as `on_request` does for a fresh op.
  /// No-op if the op is not held (a committed op the canonical log omitted is peer-repaired instead).
  fn adopt_append<W: Wal, B: Superblock>(
    &mut self,
    storage: &mut Storage<W, B, S>,
    op: u64,
    kind: Pending,
  ) {
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
    // The ring-window discipline the head-extend paths enforce (`maybe_sync_below_ring_window`) applies
    // to the adoption (re-)append identically: a deep laggard — its own checkpoint fallen more than a
    // ring behind the adopted band — must not physically wrap a committed, un-pruned slot (appending
    // `op` evicts `op − ring`, which recovery and its peers may still need). Skip the durable append
    // and owe NO vote/ack for the op (append-before-ack: nothing lands, nothing is cast, so the op is
    // never advertised as durably held). The skip is NOT terminal: every `checkpoint_op` advance
    // re-runs the still-unappended tail through [`Self::retry_unappended_adopted_tail`], and applying
    // the adopted committed band keeps those checkpoints firing until the window admits the whole tail.
    if self.ring_append_would_wrap(storage, op) {
      return;
    }
    let header = Header::new(
      OpNumber::with(op),
      self.view,
      entry.client,
      entry.request,
      &body,
    );
    // Through the slot-quiescence choke — the canonical shape of the hazard it closes: this
    // re-append targets the SAME op a just-truncated old-view write may still hold in flight, and
    // completion reordering must not let the abandoned bytes land over the canonical value after
    // this replica's vote/ack named it.
    self.submit_or_defer_append(storage, OpNumber::with(op), header, body, kind);
    // Append-before-ack: the adopted op is in flight until `on_wal_done`. Both adoption kinds
    // (AdoptVote → own vote, AdoptAck → PrepareOk) defer their cast to completion; tracking the op
    // here keeps the durable predicate uniform so the choke-point gate covers the adoption path too.
    self.appending.insert(op);
  }
}

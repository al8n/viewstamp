use super::*;

impl<S: StateMachine> Endpoint<S> {
  /// Set this replica's own vote bit on `op`'s inflight entry (no-op if the entry is gone). Used by
  /// the primary's normal-path own append (`Pending::Ack`) and the R6-F1 view-change adoption append
  /// (`Pending::AdoptVote`) — both record the own vote ONLY once the op's WAL append is durable.
  pub(crate) fn record_own_vote(&mut self, op: u64) {
    let own = 1u64 << self.config.replica().get();
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
  fn dvc_from(&self) -> &BTreeMap<u8, DoViewChange> {
    &self
      .view_change
      .as_ref()
      .expect("DVC collection read outside ViewChange")
      .dvc_from
  }

  /// The prospective-primary DVC collection (mutable). Only ever called inside `Status::ViewChange`.
  fn dvc_from_mut(&mut self) -> &mut BTreeMap<u8, DoViewChange> {
    &mut self
      .view_change
      .as_mut()
      .expect("DVC collection mutated outside ViewChange")
      .dvc_from
  }

  /// Set our own bit for `svc_target` and broadcast a `StartViewChange{svc_target}`.
  pub(crate) fn join_svc(&mut self, now: Instant) {
    self.svc_from |= 1u64 << self.config.replica().get();
    self.push_svc(self.svc_target);
    self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
  }

  /// Broadcast a `StartViewChange` for `view` to the other replicas.
  pub(crate) fn push_svc(&mut self, view: View) {
    self.emit(Outgoing::new(
      Recipient::Backups,
      Message::StartViewChange(crate::StartViewChange::new(view, self.config.replica())),
    ));
  }

  pub(crate) fn view_change_timeouts<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    if self.timers.svc_message.is_some_and(|d| d <= now) {
      self.push_svc(self.svc_target); // re-broadcast the live SVC target (drives escalation under loss)
      self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
    }
    // Gate the DVC retransmit on a DURABLE view (codex R16-F1, durable-view-before-participate in the
    // retransmit path). `enter_view_change` arms `dvc_message` AND submits the SendDoViewChange
    // durable-view write (so `pending_sb` is set), with the INITIAL DVC deferred to `on_sb_done`. If
    // the async superblock write is slower than `VC_MESSAGE_RETRANSMIT`, this retransmit would
    // otherwise fire FIRST and cast the DVC — a VOTE the new primary counts toward forming the view —
    // BEFORE this replica has PERSISTED the view; a crash before the write lands then recovers the OLD
    // view after this replica helped form a quorum for the new one. So skip the send while the view
    // write is pending (the deferred `on_sb_done` casts the initial DVC and the retransmit resumes once
    // the view is durable). Kept in LOCKSTEP with `serviceable_now(DvcMessage)` (which also gates on
    // `pending_sb.is_none()`), so a `dvc_message` armed-and-due during `pending_sb` is non-serviceable:
    // `poll_timeout` filters it out (no spin) and the `handle_timeout` no-orphan-due assert ignores it.
    if self.pending_sb.is_none() && self.timers.dvc_message.is_some_and(|d| d <= now) {
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
      self.timers.primary_idle = Some(now + PRIMARY_IDLE);
    }
  }

  pub(crate) fn on_start_view_change<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    m: crate::StartViewChange,
  ) {
    let target = m.view();
    if target.get() <= self.view.get() || target.get() > self.view.get() + 1 {
      // stale (≤ our view), OR a jump beyond our immediate next view — do not drive an
      // unverified inflated target from a lone SVC; we catch up to a genuinely-higher view
      // via a real Prepare/Commit from its primary (the higher-view rule), not via SVCs.
      return;
    }
    if m.replica().get() >= self.config.replica_count() {
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
    if (self.svc_from.count_ones() as usize) >= self.config.quorum_view_change() {
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

  /// THE SINGLE CHOKEPOINT (audit D3) for tearing down the OLD-GENERATION in-flight state that EVERY
  /// view transition must abandon. The three transition entries — [`Self::enter_view_change`]
  /// (self-driven SVC-quorum change), [`Self::catch_up_to_view`] (higher-view catch-up), and
  /// [`Self::adopt_canonical_head`] (adopt an authoritative StartView/RecoveryResponse) — all cross a
  /// generation boundary and so MUST drop the same union of old-view sub-state; centralizing it here
  /// means a NEW in-flight sub-state added next milestone is cleared on all three paths by editing ONE
  /// place (the R24-F1-shaped seam bug — a half-completed durable transition leaking across the
  /// boundary because one of three hand-written resets forgot a field — cannot recur).
  ///
  /// Clears, in one place: the SVC-collection bits (`svc_from` — these stay FLAT, being live in Normal
  /// too; the DVC collection + `catching_up` discriminant instead live behind `self.view_change`, which
  /// each call site sets/`take`s around this reset — see below), the in-flight STORAGE submissions
  /// (`pending`/`appending` — abandoned old-view WAL appends whose late completion must not emit a
  /// stale-view `PrepareOk`; kept in lockstep per R7-F1), the stale per-replica checkpoint reports
  /// (`peer_checkpoint` — a fresh primary rebuilds the GC map from incoming `PrepareOk`/`Commit`), the
  /// in-flight checkpoint
  /// (`pending_checkpoint` — re-triggers once Normal resumes), the in-flight state-sync as the
  /// LOAD-BEARING PAIR `sync` + `pending_install` cleared TOGETHER (clearing `sync` alone would let
  /// `on_sb_done`'s install arm fire against a cancelled sync — the `assert_invariants` `pending_install
  /// ⟹ sync` clause guards exactly this) along with its `sync_solicit` timer, and the forfeit sub-state
  /// `forfeit_armed` + `pending_forfeit` (a fresh generation re-evaluates the step-down from scratch).
  ///
  /// With durable-before-install (codex R24-F1) cancelling `sync`/`pending_install` finds the OLD
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
  /// retires it); and the forward `arm_timers(now)` re-arm.
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
    // kept in lockstep with `pending` (R7-F1): clearing it means a later adopt-append re-marks the op
    // fresh, and the abandoned old completion (now absent from `pending`) does not retract that fresh
    // mark in `on_wal_done`.
    self.pending.clear();
    self.appending.clear();
    // Drop stale per-replica checkpoint reports: the new generation re-establishes the pipeline, so
    // old-view reports must not gate the next primary's GC. A fresh primary rebuilds the map from
    // incoming PrepareOk/Commit, staying conservative (unheard peers count as 0) until then.
    self.peer_checkpoint.clear();
    // Supersede any in-flight checkpoint: a view change drops it (its stale superblock completion is
    // then ignored in on_sb_done). It re-triggers once Normal resumes — commit_min is preserved.
    self.pending_checkpoint = None;
    // Abandon any in-flight state-sync (M3.4a): a view change supersedes it (state-sync and view
    // change are mutually exclusive by status — §2.6). The `sync` handshake and its DEFERRED INSTALL
    // (`pending_install`) are cancelled TOGETHER: with durable-before-install (codex R24-F1) the STAGE
    // never restored the SM, advanced `commit_min`/`op`, nor pruned the WAL, so this finds the OLD
    // (consistent, if stale) state intact — there is NO pruned-but-stale window. Dropping
    // `pending_install` here also releases the staged snapshot bytes — and, gated by the
    // `sync.is_some()` cleared alongside, the `on_sb_done` install arm can never fire against this
    // cancelled sync (the `assert_invariants` `pending_install ⟹ sync` clause guards this pairing).
    self.sync = None;
    self.pending_install = None;
    self.timers.sync_solicit = None;
    // A view change ends this primary generation: clear any forfeit grace timer (M3.5 T3) AND any
    // deferred-forfeit flag (the safety step-down — see `maybe_force_sync`). The new generation
    // re-evaluates from scratch once it resumes Normal as primary, so neither a stale grace deadline
    // nor a stale pending-forfeit must carry across (no same-view re-forfeit / cross-view leak).
    self.timers.forfeit_armed = None;
    self.pending_forfeit = false;
  }

  /// The shared `ViewChange`-entry body (no view-advance assert — the callers assert their own
  /// contract). Resets the pipeline + quorums and defers the DoViewChange until the new view is durable.
  fn enter_view_change<B: Superblock>(&mut self, now: Instant, sb: &mut B, view_new: View) {
    self.view = view_new;
    self.status = Status::ViewChange;
    self.svc_target = view_new; // collect future escalations above this view
    // Tear down ALL old-generation in-flight state in one place (audit D3): SVC bits, in-flight
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
    let primary = self.config.primary(self.view);
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(primary)),
      Message::DoViewChange(crate::DoViewChange::new(
        self.view,
        self.log_view,
        self.op,
        // The DVC reports the KNOWN committed frontier `commit_max` — VSR's commit-number `k` (the
        // highest op this replica KNOWS is committed), NOT the locally-applied `commit_min` (codex
        // R9-F1). `select_canonical_log` takes `commit* = max(d.commit())`, so under-reporting
        // commit_min would let a known-committed op (whose slot is a dropped repair hole on this
        // replica) fall ABOVE `commit*` and be truncated as an uncommitted gap when the DVC quorum is
        // this replica + a laggard. Reporting commit_max keeps `commit*` at/above it, so it is a
        // COMMITTED hole the new primary HOLDS + peer-repairs (never silently dropped). Fail-stop-safe:
        // a committed op N is held by a write-quorum, which intersects the DVC quorum, so some donor
        // claims `op >= N` → `commit* (<= max commit_max == N) <= op_head` holds.
        self.commit_max,
        self.config.replica(),
        self.log_entries(),
      )),
    ));
  }

  /// The in-memory log as wire entries — the OFFSET tail `(checkpoint_op .. op]` for a
  /// recover-from-checkpoint / state-synced replica (the committed prefix `[1..=checkpoint_op]` lives
  /// in the SM snapshot, not the cache), or dense `[1..=op]` for a replica that never checkpointed.
  /// `select_canonical_log` is offset-aware (B3) and UNIONs these across DVCs, so a DVC carrying only
  /// the offset tail loses no committed op at view change.
  pub(crate) fn log_entries(&self) -> std::vec::Vec<crate::PreparedEntry> {
    self
      .log
      .iter()
      .map(|(&op, e)| {
        crate::PreparedEntry::new(OpNumber::with(op), e.client, e.request, e.body.clone())
      })
      .collect()
  }

  pub(crate) fn on_do_view_change<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: crate::DoViewChange,
  ) {
    // NOTE (deferred to M3 message-hardening): we do not yet validate incoming DVC well-formedness
    // (commit <= op; the log is the OFFSET tail `(checkpoint .. op]`, dense WITHIN that range — it is
    // NOT required to be dense from op 1, since a recover-from-checkpoint / state-synced sender
    // legitimately omits the prefix that lives in its SM snapshot). Safe under honest crash-stop
    // peers; matters once untrusted/real-driver inputs land. The cross-DVC commit* <= op_head
    // invariant is enforced (fail-stop) in `select_canonical_log`.
    // `!is_view_change()` short-circuits BEFORE `dvc_quorum()` reads the (then-`None`) collection, so
    // the collection is `Some` on every non-returning path below (ViewChange ⟹ `view_change.is_some()`).
    if m.view() != self.view
      || !self.config.is_primary(self.view)
      || !self.status.is_view_change()
      || self.dvc_quorum()
    {
      return;
    }
    if m.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    // Ensure our own DVC is represented (keyed by replica → a self-addressed DVC is idempotent).
    // Compute the own-DVC into a local FIRST to avoid a self borrow conflict, then insert.
    let own = self.config.replica().get();
    if !self.dvc_from().contains_key(&own) {
      let own_dvc = crate::DoViewChange::new(
        self.view,
        self.log_view,
        self.op,
        // Report the KNOWN committed frontier `commit_max` (VSR's `k`), not `commit_min` — see
        // `send_do_view_change` (codex R9-F1). This own-DVC feeds the same `select_canonical_log`
        // `commit*` union, so it must carry the same frontier the wire DVC does.
        self.commit_max,
        self.config.replica(),
        self.log_entries(),
      );
      self.dvc_from_mut().insert(own, own_dvc);
    }
    // Keep the most-advanced DVC per replica.
    let replace = self
      .dvc_from()
      .get(&m.replica().get())
      .map(|cur| (m.log_view().get(), m.op().get()) > (cur.log_view().get(), cur.op().get()))
      .unwrap_or(true);
    if replace {
      self.dvc_from_mut().insert(m.replica().get(), m);
    }
    if self.dvc_from().len() >= self.config.quorum_view_change() {
      self.start_view_as_new_primary(now, wal, sb);
    }
  }

  /// VSR canonical-log selection + nack-prepare truncation — **offset-aware** (B3).
  ///
  /// Returns `(canonical log truncated to op_head, op_head, commit*)`:
  /// - the canonical generation is the DVCs with the greatest `log_view`;
  /// - `op_head` is that generation's head, less any provably-uncommitted tail truncated by a
  ///   `quorum_nack_prepare` of nacks (contiguous ⟹ replica `r` nacks op `X` iff `r.op < X`);
  /// - `commit*` is the greatest commit across all DVCs (commit never rewinds);
  /// - the canonical log is the **UNION** of the canonical generation's entries up to `op_head` —
  ///   each op is sourced from ANY canonical-generation DVC that holds it — NOT a copy of one DVC's
  ///   `log_slice()`.
  ///
  /// **Why the union (the B3 safety fix).** Since M3.2a+ a DVC log is the *offset tail*
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
  /// floor) adopter is `(min_floor .. commit*]`. For each such op the union includes it iff SOME
  /// canonical donor holds it. By quorum intersection a committed op was held by some current-DVC
  /// sender, and the lowest-floor canonical donor `L` (with `floor_L == min_floor`) covers
  /// `(min_floor .. op_L]`. If `op_L >= commit*`, `L` alone covers the whole band. In the residual
  /// case where a committed op in `(min_floor .. commit*]` is held by NO canonical donor (the donor
  /// that committed+checkpointed it past, plus a low-floor donor that lagged the tail), the union
  /// omits it — but this is **never a silent loss**: the adopter's `advance_commit` HOLDS the commit
  /// at the missing op and `request_repair`s it from a peer (the B4 `RequestPrepare` → `Prepare`
  /// safety net, mirroring TigerBeetle's `repair_prepares_between`). The adopt path is fixed to NOT
  /// destroy a held copy and NOT clear that repair request (see `adopt_log` / `adopt_canonical_head`).
  /// So the SAFETY property — no committed op is ever dropped — holds: a committed op is present in
  /// the union when any canonical donor holds it, and otherwise is repaired (commit blocks until
  /// then), never skipped.
  ///
  /// Run by the prospective primary once it holds `>= quorum_view_change` DoViewChange messages.
  /// NOTE: with exactly `quorum_view_change` DVCs the truncation loop provably never fires in the
  /// contiguous model (the head-holder is one of them); truncation activates only with a larger
  /// collected set. See the `no_truncation_at_minimal_quorum` test.
  pub(crate) fn select_canonical_log(&self) -> (std::vec::Vec<crate::PreparedEntry>, u64, u64) {
    let dvcs: std::vec::Vec<&crate::DoViewChange> = self.dvc_from().values().collect();
    debug_assert!(!dvcs.is_empty(), "selection requires at least one DVC");

    let log_view_star = dvcs.iter().map(|d| d.log_view().get()).max().unwrap_or(0);
    let canonical: std::vec::Vec<&crate::DoViewChange> = dvcs
      .iter()
      .copied()
      .filter(|d| d.log_view().get() == log_view_star)
      .collect();

    // `op_head` is the canonical generation's head, but BOUNDED to the ACTUALLY-represented log (F4):
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
    let threshold = self.config.quorum_nack_prepare();
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

    // Build the canonical log by UNIONING the canonical generation's entries up to op_head: for each
    // op, take its `PreparedEntry` from any canonical donor that holds it. A committed op present in a
    // low-floor donor's offset log but absent from a higher-floor donor is therefore STILL included.
    // The BTreeMap keys by op so the result is ordered+gapless-where-present; `or_insert_with` keeps
    // the FIRST canonical donor's copy of each op. The donor choice is immaterial: every donor of the
    // canonical generation agrees on a committed op's content (same prior-view prepare), and an
    // uncommitted tail op `(commit* .. op_head]` is identical across the canonical generation too (it
    // is the same prepared op — the canonical `op_head` holder's value).
    let mut merged: BTreeMap<u64, crate::PreparedEntry> = BTreeMap::new();
    for d in &canonical {
      for entry in d.log_slice() {
        if entry.op().get() <= op_head {
          merged
            .entry(entry.op().get())
            .or_insert_with(|| entry.clone());
        }
      }
    }
    let log: std::vec::Vec<crate::PreparedEntry> = merged.into_values().collect();
    (log, op_head, commit_star)
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
    // Offset-aware canonical-log selection (UNION) + nack-prepare truncation (see
    // `select_canonical_log`). The canonical log is the offset tail `(min_floor .. op_head]`, NOT
    // necessarily dense `[1..=op_head]`.
    let (canonical_log, op_head, commit_star) = self.select_canonical_log();
    self.adopt_log(&canonical_log);
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

    // codex R7-F2: truncate the uncommitted suffix at the FIRST interior gap above commit*. The
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
    // contiguous nack-scan steps over. A gap AT or BELOW `commit*` is a COMMITTED op (a real B4 repair
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

    // SAFETY (vopr seed 253 et al.): physically DROP any WAL tail ABOVE the new primary's canonical head,
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
    // recover/state-sync — those survive M3.4b GC, whereas this loop does NOT (GC prunes `self.log`
    // below the checkpoint, so for a backup whose log is empty this loop finds nothing). Keeping it is
    // harmless (it can only RAISE the watermark for ops the new primary still holds) and guards the
    // edge where a session row was somehow not yet recorded. Without the apply-time tracking, a
    // backup-turned-primary with a GC'd log would carry `session.request == 0` and wedge every client
    // on `on_request`'s gap check — the M3.4b boundedness/offset-view-change hang this fixed.
    //
    // NOTE (deferred to the message-loss fault-sweep milestone): we still do NOT reconstruct the
    // cached *reply* body, so a client whose prior-view reply was LOST relies on the in-flight op
    // re-committing; the lost-reply resend is liveness under loss, owned by the later milestone.
    for op in 1..=self.op.get() {
      let Some((client, request)) = self.log.get(&op).map(|e| (e.client.get(), e.request)) else {
        continue;
      };
      let session = self.clients.entry(client).or_default();
      if request.get() > session.request.get() {
        session.request = request;
      }
    }

    // log_view = view BEFORE submit_durable_view (try_new requires log_view <= view).
    self.log_view = self.view;
    self.status = Status::Normal;
    // ViewChange EXIT: the canonical log has been formed and we are returning to Normal as the new
    // primary, so retire the ViewChange-only collection (DVC quorum + catch-up discriminant) to `None`
    // — the `view_change.is_some() == is_view_change()` coupling. (Previously a `dvc_quorum = true`
    // marker set here then immediately went stale as the generation ended; the Option `take`-on-exit
    // makes that lifecycle explicit and type-enforced.)
    self.view_change = None;
    // Becoming primary FRESH: a deferred-forfeit flag (the M3.5 safety step-down) from a prior
    // generation must not carry in (it was cleared on entering ViewChange, but clear it defensively
    // here so a fresh primary never starts already-flagged to abdicate).
    self.pending_forfeit = false;

    // Rebuild the pipeline for the uncommitted tail `(commit_min, op]`. codex R6-F1: the new primary
    // must NOT count its own vote for an op it adopted from a peer's DVC and holds ONLY in memory —
    // that would let it commit (and on crash+recover lose) an op it never durably appended. So seed
    // each inflight entry with `oks: 0` and durably (re-)append the adopted op tagged `AdoptVote`; the
    // own vote is set in `on_wal_done` ONLY once that append lands (append-before-ack — the same
    // discipline `on_request`/`on_prepare` use). `try_commit` (deferred to `start_view_participate`
    // after the durable-view write) then counts only votes whose appends are durable. Committed ops
    // `<= commit_star` are NOT re-appended: the cluster already guarantees them; only the voted-on
    // uncommitted tail must be re-driven through the WAL.
    self.inflight.clear();
    for op in (self.commit_min.get() + 1)..=self.op.get() {
      self.inflight.insert(
        op,
        Inflight {
          oks: 0, // own vote set in on_wal_done when the AdoptVote append is durable
          committed: false,
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
    // Broadcast the canonical log to all backups.
    self.emit(Outgoing::new(
      Recipient::Backups,
      Message::StartView(crate::StartView::new(
        self.view,
        self.op,
        self.commit_min,
        self.config.replica(),
        self.log_entries(),
      )),
    ));

    self.arm_timers(now);
    self.try_commit(now, sb);
  }

  /// Adopt the canonical (`entries`) log for a view whose committed frontier is `commit`.
  ///
  /// The canonical log is now built by UNIONING the canonical generation (see
  /// `select_canonical_log`) and is the offset tail `(min_floor .. op_head]` — it is NOT necessarily
  /// dense `[1..=op]`, and it may even OMIT a committed op held by NO canonical donor. So adoption
  /// must be **defensive**: it preserves any *committed* op the adopter already holds (in
  /// `(.. =commit]`) that `entries` does not supply, rather than blindly clearing the log and
  /// destroying the adopter's own durable copy of a committed op. Held *uncommitted* ops (above
  /// `commit`) are governed solely by the canonical tail (a nack-truncated / lower-generation tail
  /// must not be resurrected from a stale local copy), so they are dropped; the canonical entries
  /// then overwrite/insert authoritatively. A committed op that neither side supplies is left for
  /// `advance_commit` to `request_repair` from a peer (it is never silently skipped).
  fn adopt_log(&mut self, entries: &[crate::PreparedEntry]) {
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
    //     this is the SAFETY fix (VOPR seed 24). The adopter holds a body it has NOT applied, which can
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
    let applied_floor = self.commit_min.get();
    self
      .log
      .retain(|&op, _| op <= applied_floor && !supplied.contains(&op));
    for e in entries {
      self.log.insert(
        e.op().get(),
        LogEntry {
          client: e.client(),
          request: e.request(),
          body: e.body_bytes(),
        },
      );
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
    if m.replica() != self.config.primary(m.view()) {
      return; // must come from the view's primary
    }
    self.adopt_canonical_head(now, sb, m.view(), m.op(), m.commit(), m.log_slice());
    self.truncate_wal_above_adopted_head(wal);
  }

  /// Drop any WAL tail strictly ABOVE the head this replica just adopted (vopr seed 253 et al.). Run by
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
  /// and may be a stale superseded proposal (VOPR seed 24), so `adopt_log` drops it and `advance_commit`
  /// below HOLDS the commit at it and `request_repair`s the CANONICAL value from a committed-vouching
  /// peer (the existing force-sync path takes over if it was GC'd cluster-wide). The checkpointed
  /// prefix lives in the SM, the committed tail in the (applied-preserved + adopted + repaired) log —
  /// the committed prefix is reconstructed end to end, with peer-repair as the backstop for any omitted
  /// committed op the adopter has not applied (never silently skipped, never filled from a stale local).
  pub(crate) fn adopt_canonical_head<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    view: View,
    op: OpNumber,
    commit: OpNumber,
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
    self.adopt_log(log);
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
    self.status = Status::Normal;
    // Tear down ALL old-generation in-flight state in one place (audit D3): SVC bits (svc_from),
    // in-flight appends (pending/appending), peer-checkpoint reports, in-flight checkpoint, in-flight
    // state-sync + its deferred install (cancelled TOGETHER — adopting an authoritative canonical head
    // supersedes the sync; the adopted canonical log + the adopter's preserved APPLIED prefix supply the
    // committed prefix, with peer-repair as the backstop for the omitted unapplied committed band;
    // durable-before-install R24-F1 leaves the old state intact), and the forfeit sub-state. See
    // [`Self::reset_for_view_transition`]. NOTE this DELIBERATELY does NOT clear `inflight`/`buffer`:
    // a Normal primary can reach here via a higher-view `on_start_view` holding a live pipeline, so —
    // unlike the two ViewChange entries — adoption preserves it (this is the real per-site asymmetry
    // the shared reset keeps out).
    self.reset_for_view_transition();
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
    // NOT blanket-clear `repair` here: that was the B3 stranding bug — clearing right after
    // `advance_commit` requested a hole silently forgot a committed op.)
    self.arm_timers(now);
    // Defer held-op re-acks to on_sb_done → `start_view_acks`: persist the new view first, and there
    // WAL-(re-)append each adopted uncommitted-tail op before its PrepareOk (codex R6-F1). The adopted
    // entries are in-memory only until then; the deferred ack gates on both the view write (here) and
    // the per-op append (in `start_view_acks`) completing, so no PrepareOk precedes either.
    self.submit_durable_view(PendingSbAction::AdoptedStartView, sb);
  }

  /// Runs once the adopted-StartView superblock write is durable: re-ack held uncommitted ops — but
  /// only AFTER each is durably (re-)appended to the WAL (codex R6-F1, append-before-ack).
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
  pub(crate) fn start_view_acks<W: Wal>(&mut self, wal: &mut W) {
    for op in (self.commit_min.get() + 1)..=self.op.get() {
      self.adopt_append(wal, op, Pending::AdoptAck(OpNumber::with(op)));
    }
  }

  /// Durably (re-)append an op the replica adopted into `self.log` during a view change, recording the
  /// deferred action (`Pending::AdoptVote` for the new primary's own vote, `Pending::AdoptAck` for a
  /// backup's PrepareOk) so `on_wal_done` casts it ONLY once the append lands (codex R6-F1,
  /// append-before-ack). The op's body lives only in the in-memory `self.log` until this completes —
  /// mirroring `append_prepare`, but for the already-installed adopted entry rather than an incoming
  /// `Prepare`. Header is written under the current (new) view, as `on_request` does for a fresh op.
  /// No-op if the op is not held (a committed op the canonical log omitted is peer-repaired instead).
  fn adopt_append<W: Wal>(&mut self, wal: &mut W, op: u64, kind: Pending) {
    let Some(entry) = self.log.get(&op).cloned() else {
      return; // not held — `advance_commit`/`request_repair` recovers a committed gap; nothing to ack
    };
    let header = Header::new(
      OpNumber::with(op),
      self.view,
      entry.client,
      entry.request,
      &entry.body,
    );
    let id = self.mint_op_id();
    wal.submit_append(id, OpNumber::with(op), header, entry.body);
    self.pending.insert(id.get(), kind);
    // Append-before-ack (R7-F1): the adopted op is in flight until `on_wal_done`. Both adoption kinds
    // (AdoptVote → own vote, AdoptAck → PrepareOk) defer their cast to completion; tracking the op
    // here keeps the durable predicate uniform so the choke-point gate covers the adoption path too.
    self.appending.insert(op);
  }
}

use super::*;

impl<S: StateMachine> Endpoint<S> {
  /// Register op `op` for peer fault-repair (B4): its committed body read back permanently faulty, so
  /// we drop any stale (header-only / wrong) cache entry, record the hole, immediately solicit the op
  /// from peers, and arm the repair-retry timer. The COMMIT IS HELD below `op` by the apply loops
  /// (they break at the first missing op) — this never advances `commit_min` past the hole. Idempotent
  /// per op (a re-request while already pending just re-solicits + re-arms).
  pub(crate) fn request_repair(&mut self, now: Instant, op: u64) {
    // Drop the cache entry so the apply path keeps treating this slot as a hole until a VERIFIED
    // Prepare fills it (never apply a wrong/empty body). A torn slot's header-only entry is removed;
    // a bit-rotted slot was never inserted.
    self.log.remove(&op);
    self.repair.insert(op);
    // Committed-survival backstop: this drop is a cache eviction, not a loss — `op` is now a TRACKED
    // repair hole, so the canonical committed body is re-solicited below (and the apply loop holds the
    // commit beneath it until it returns). Asserted AFTER the insert so the tracked-for-repair clause
    // holds (a committed hole here is typically `checkpoint_op < op <= commit_max`, covered by neither
    // the checkpoint nor the uncommitted clause).
    self.assert_committed_survives(op, self.checkpoint_op.get());
    self.send_request_prepare(op);
    self.timers.repair_retry = Some(now + REPAIR_RETRANSMIT);
    // Force-sync escalation (M3.5): if a quorum already checkpointed past this just-registered hole
    // (e.g. a replica recovered a rotted committed slot the cluster long since checkpointed+pruned),
    // its `RequestPrepare` is futile from the outset — escalate straight to a forced `RequestSync`.
    self.maybe_force_sync(now);
  }

  /// Broadcast a `RequestPrepare` for the single missing committed op `op` to all peers. Any peer
  /// that holds `op` answers with the `Prepare` carrying it (`on_request_prepare`). Broadcast (not
  /// primary-only) so the repair completes even mid-view-change / when the primary itself is the one
  /// missing the op.
  pub(crate) fn send_request_prepare(&mut self, op: u64) {
    self.emit(Outgoing::new(
      Recipient::Backups,
      Message::RequestPrepare(crate::RequestPrepare::new(
        self.view,
        OpNumber::with(op),
        self.config.replica(),
      )),
    ));
  }

  /// Peer-fault-repair retransmit timer: while the repair set is non-empty, re-solicit every
  /// unrepaired op and re-arm. Terminates when the last hole is filled (`fill_repair` clears the op
  /// and stops re-arming once `repair` is empty).
  pub(crate) fn repair_timeouts(&mut self, now: Instant) {
    if !self.timers.repair_retry.is_some_and(|d| d <= now) {
      return;
    }
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
      return;
    }
    let ops: std::vec::Vec<u64> = self.repair.iter().copied().collect();
    for op in ops {
      self.send_request_prepare(op);
    }
    self.timers.repair_retry = Some(now + REPAIR_RETRANSMIT);
  }

  /// Answer a peer's `RequestPrepare` for a committed op it read back faulty: if we are `Normal`, our
  /// view is DURABLE, and we hold the op's body in our log cache, reply with the `Prepare` carrying it.
  /// Only a Normal replica answers (a recovering / view-changing replica may itself hold a hole at that
  /// op). The reply's `commit` field carries our commit so the requester can also learn fresh commit
  /// progress; the op's content is view-independent, so the requester accepts it regardless of our view.
  pub(crate) fn on_request_prepare(&mut self, _now: Instant, m: crate::RequestPrepare) {
    // Durable-view-before-participate (codex R17-F1): the served `Prepare` advertises `self.view` (see
    // below). A replica in its `pending_sb` window (a new primary between `start_view_as_new_primary`
    // and the `on_sb_done` that makes its view durable — or any replica mid `AdoptedStartView`/
    // `SendDoViewChange` write) is `Normal` but its view is NOT yet recoverable; serving a repair
    // `Prepare(self.view)` now would advertise a view a crash could roll back — the same hazard the
    // primary `Prepare`/`Commit`/`StartView` paths gate on. The served op is committed and its CONTENT
    // is view-independent, so the requester loses nothing by waiting: it broadcasts the `RequestPrepare`
    // to ALL peers and retries on the repair-retransmit timer, so another Normal+durable peer answers
    // (and we answer once our own view is durable). Negligible liveness cost; consistent with the class.
    if !self.status.is_normal() || self.pending_sb.is_some() {
      return; // only a Normal replica whose view is durable may serve a (view-advertising) repair Prepare
    }
    if m.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    let op = m.op().get();
    let Some(entry) = self.log.get(&op) else {
      return; // we do not hold this op (or it is a hole for us too) — stay silent; another peer answers
    };
    // codex R5-F1: never vouch for an uncommitted op as a repair source. Serve only ops we have
    // committed (op <= commit_min) so the answering Prepare carries commit (= commit_min) >= op; an op
    // above our applied frontier is not ours to certify — stay silent and let a caught-up peer answer.
    if op > self.commit_min.get() {
      return;
    }
    let prepare = Prepare::new(
      self.view,
      OpNumber::with(op),
      self.commit_min,
      self.checkpoint_op,
      entry.client,
      entry.request,
      entry.body.clone(),
    );
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(m.replica())),
      Message::Prepare(prepare),
    ));
  }

  /// Fill a peer-supplied `Prepare` for an op in our pending-repair set (B4), then resume the held
  /// commit. Two guards protect the committed slot:
  /// - **Placement** (`p.op()` equals a hole in `self.repair`): the load-bearing check — a misdirected
  ///   or mismatched reply for any other op is rejected, so a committed slot is never filled with a
  ///   different op's body. This mirrors the recovery read-path's `header.op() == op` placement check.
  /// - **Body checksum** (`Header::verify`): the body's `body_checksum` must be self-consistent. (For
  ///   an in-process `Prepare` value the header is reconstructed from its own fields, so this is a
  ///   structural belt-and-suspenders; it becomes a genuine integrity gate when a `Prepare` arrives
  ///   over a wire codec that carries the checksum independently of the body.)
  ///
  /// The integrity of the repaired *content* rests on the VSR durability guarantee that a quorum holds
  /// every committed op's correct body (the honest-peer model) plus the placement guard above. On
  /// success the repaired body is persisted durably via a WAL append (so future reads / DVCs / a later
  /// crash-restart serve the repaired op) as a DURABILITY BARRIER (codex R13-F2): the apply, the
  /// hole-clear, and the exposure of the op all WAIT for that append to land. `fill_repair` stages the
  /// body in a [`Pending::RepairFill`] (NOT in `self.log`) + `submit_append`s + marks `op` `appending`,
  /// but keeps the hole OPEN and does NOT `advance_commit`; `on_wal_done` then inserts the body into
  /// `self.log`, removes the hole, and resumes the held commit. So a crash before `WalDone::Appended`
  /// loses only a non-durable staged copy this replica had NOT yet applied / exposed in a
  /// DVC/StartView/checkpoint — append-before-participate (durable-source) holds for peer repair too. A
  /// `Prepare` whose op is not a hole (or whose body fails the checksum) is rejected (returns `false`)
  /// so the caller falls through to the normal prepare path.
  pub(crate) fn fill_repair<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    p: &Prepare,
  ) -> bool {
    let _ = (now, &mut *sb); // the apply/advance is deferred to on_wal_done (R13-F2); no commit here
    let op = p.op().get();
    if !self.repair.contains(&op) {
      return false; // placement: not a hole we are repairing — let on_prepare handle it normally
    }
    // A RepairFill append for this op is already in flight (a duplicate/retransmitted repair Prepare):
    // the op is still a hole (kept open until durable) but staging a SECOND append would double-write.
    // Swallow the duplicate — it is a repair answer we are already making durable (R13-F2). A repair
    // hole's slot can ONLY be `appending` via a RepairFill: the normal `on_prepare` re-ack/re-append
    // branch now skips an op in `self.repair` (the repair-hole-ownership guard there), so this `appending`
    // membership unambiguously means our own in-flight RepairFill, never a normal-path append.
    if self.appending.contains(&op) {
      return true;
    }
    // SAFETY (codex R5-F1): a committed repair hole may ONLY be filled with the committed value for
    // this op. A repair answer from a peer that holds op N committed carries commit >= op (it set
    // prepare.commit = its own commit_min >= N in on_request_prepare). A STALE/reordered Prepare from an
    // old view, broadcast while its body was still UNCOMMITTED, carries commit < op — reject it (keep the
    // hole open + re-solicit) so a committed slot is never overwritten with an uncommitted old-view body.
    // Soundness: under the VSR (non-Byzantine) fault model commit >= op means the sender committed op,
    // and a committed op's body is identical across all views (committed-op survival), so the body is
    // canonical.
    if p.commit().get() < p.op().get() {
      return false;
    }
    // Reconstruct the header (also needed for the durable append below) and gate on its body checksum.
    let header = Header::new(p.op(), p.view(), p.client(), p.request(), p.body());
    if !header.verify(p.body()) {
      return false; // unverifiable body — never adopt it for a committed op; keep the hole + re-solicit
    }
    // Persist the repaired op durably (append-after-verify) as a DURABILITY BARRIER (codex R13-F2). The
    // body is staged in the `Pending::RepairFill` entry — NOT in `self.log` — so it is NOT exposed in a
    // DVC/StartView/checkpoint nor applied by a concurrently-triggered `advance_commit` while the append
    // is still in flight; `on_wal_done` inserts it into `self.log`, clears the hole, and advances the
    // commit only once `WalDone::Appended` lands. The hole stays OPEN here (commit held, op not exposed)
    // and `op` is marked `appending` so the durable-status oracle treats it as in-flight (and a
    // duplicate repair Prepare hits the early `appending` guard above instead of double-appending).
    let entry = LogEntry {
      client: p.client(),
      request: p.request(),
      body: p.body_bytes(),
    };
    let id = self.mint_op_id();
    wal.submit_append(id, p.op(), header, p.body_bytes());
    // This append owes NO PrepareOk/own-vote (peer repair is not a vote), but unlike the OLD bare write
    // it IS tracked — as a `RepairFill`, so `on_wal_done` defers the apply + hole-clear to durability.
    self
      .pending
      .insert(id.get(), Pending::RepairFill(p.op(), entry));
    self.appending.insert(op);
    true
  }
}

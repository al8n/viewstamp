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
    self.outgoing.push_back(Outgoing::new(
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

  /// Answer a peer's `RequestPrepare` for a committed op it read back faulty: if we are `Normal` and
  /// hold the op's body in our log cache, reply with the `Prepare` carrying it. Only a Normal replica
  /// answers (a recovering / view-changing replica may itself hold a hole at that op). The reply's
  /// `commit` field carries our commit so the requester can also learn fresh commit progress; the
  /// op's content is view-independent, so the requester accepts it regardless of our view.
  pub(crate) fn on_request_prepare(&mut self, _now: Instant, m: crate::RequestPrepare) {
    if !self.status.is_normal() {
      return; // only a Normal replica has a trustworthy committed log to serve from
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
    self.outgoing.push_back(Outgoing::new(
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
  /// success the body is inserted into the dense `log` cache and persisted durably via a WAL append
  /// (so future reads / DVCs / a later crash-restart serve the repaired op), the hole is cleared, and
  /// the held commit resumes. A `Prepare` whose op is not a hole (or whose body fails the checksum) is
  /// rejected (returns `false`) so the caller falls through to the normal prepare path.
  pub(crate) fn fill_repair<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    p: &Prepare,
  ) -> bool {
    let op = p.op().get();
    if !self.repair.contains(&op) {
      return false; // placement: not a hole we are repairing — let on_prepare handle it normally
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
    // Fill the dense cache and persist the repaired op durably (append-after-verify), so a subsequent
    // crash/restart reads it cleanly and a DVC/StartView we send carries it.
    self.log.insert(
      op,
      LogEntry {
        client: p.client(),
        request: p.request(),
        body: p.body_bytes(),
      },
    );
    let id = self.mint_op_id();
    wal.submit_append(id, p.op(), header, p.body_bytes());
    // NOTE: this append's completion is a bare durability write, NOT a prepare vote — we do not add it
    // to `self.pending` (no PrepareOk/own-vote is owed for a repair fill), so on_wal_done ignores it.
    self.repair.remove(&op);
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
    }
    // The hole is filled → resume applying the held committed prefix from exactly where it stalled.
    let target = self.commit_max.get();
    self.advance_commit(now, sb, target);
    true
  }
}

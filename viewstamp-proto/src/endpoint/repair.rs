use super::*;

impl<S: StateMachine> Endpoint<S> {
  /// Register op `op` for peer fault-repair: its committed body read back permanently faulty, so
  /// we drop any stale (header-only / wrong) cache entry, record the hole, immediately solicit the op
  /// from peers, and arm the repair-retry timer. The COMMIT IS HELD below `op` by the apply loops
  /// (they break at the first missing op) — this never advances `commit_min` past the hole. Idempotent
  /// per op (a re-request while already pending just re-solicits + re-arms).
  pub(crate) fn request_repair(&mut self, now: Instant, op: u64) {
    // Drop a stale PRESENT cache entry so the apply path keeps treating this slot as a hole until a
    // VERIFIED Prepare fills it (never apply a wrong/empty body). A header-only `Repairing` entry is
    // KEPT, not removed: it carries the op's durable canonical `body_checksum`, which `fill_repair`
    // uses to verify a peer-supplied body for an UNCOMMITTED-tail repair (a carried-through view-change
    // op whose donors did not vouch it committed) — and it is already a hole the apply path holds at, so
    // keeping it changes nothing about the commit hold. (A bit-rotted slot was never inserted.)
    if !matches!(self.log.get(&op), Some(e) if e.body.is_repairing()) {
      self.log.remove(&op);
    }
    self.repair.insert(op);
    // Committed-survival backstop: this drop is a cache eviction, not a loss — `op` is now a TRACKED
    // repair hole, so the canonical committed body is re-solicited below (and the apply loop holds the
    // commit beneath it until it returns). Asserted AFTER the insert so the tracked-for-repair clause
    // holds (a committed hole here is typically `checkpoint_op < op <= commit_max`, covered by neither
    // the checkpoint nor the uncommitted clause).
    self.assert_committed_survives(op, self.checkpoint_op.get());
    self.send_request_prepare(op);
    self.timers.repair_retry = Some(now + REPAIR_RETRANSMIT);
    // Force-sync escalation: if a quorum already checkpointed past this just-registered hole
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

  /// Register the CONTIGUOUS run of below-head `Repairing`/missing holes starting at `lo` for windowed
  /// peer fault-repair and solicit it as ONE [`RequestPrepareRange`]. The windowed analogue of
  /// [`Self::request_repair`]: where that solicits a single committed-op hole, this registers the whole
  /// contiguous band `[lo, hi]` and asks for it in one message, so a deep header-only adoption (a
  /// view-change carrier that installed the whole uncheckpointed log as `Repairing` holes) is repaired
  /// PIPELINED — a holder answers with a byte-bounded [`RepairBatch`] serving up to a frame's worth of
  /// ops — rather than one op per round trip (which never converges for a ~hundreds-deep band in a calm
  /// window). The commit is HELD below `lo` by the apply loops exactly as for the single-op path.
  ///
  /// `hi` is the top of the contiguous hole band, capped two ways: it never exceeds the known-committed
  /// frontier `commit_max` (ops above it are the ABOVE-head tail-gap path's job, not below-head repair)
  /// nor `lo + REPAIR_WINDOW - 1` (bounding the solicitation breadth + the per-op work this call does in
  /// the Sans-I/O core). The band stops at the first `Present` op — a filled op is not a hole, so the
  /// run is holes-only. Each hole in `[lo, hi]` is registered identically to `request_repair`'s single
  /// op, then the retry timer is armed and the force-sync escalation evaluated ONCE for the whole run.
  pub(crate) fn request_repair_run(&mut self, now: Instant, lo: u64) {
    // Walk the contiguous hole band up from `lo`, bounded by the repair window and the known-committed
    // frontier. An op is a HOLE iff it is missing from `self.log` OR held header-only (`Repairing`); a
    // `Present` op terminates the band (it is filled, not a hole). Capped at `commit_max` — a slot above
    // it is uncommitted-tail (the `request_tail_gap` ABOVE-head path), never a below-head committed hole.
    let window_top = lo.saturating_add(REPAIR_WINDOW).saturating_sub(1);
    let ceiling = self.commit_max.get().min(window_top).min(self.op.get());
    let mut hi = lo;
    while hi < ceiling {
      let next = hi + 1;
      let is_hole = !matches!(self.log.get(&next), Some(e) if e.body.is_present());
      if !is_hole {
        break;
      }
      hi = next;
    }
    // Register every hole in `[lo, hi]` exactly as `request_repair` registers a single op: drop a stale
    // `Present` cache entry so the apply path keeps treating the slot as a hole (a `Repairing` entry is
    // KEPT — it carries the durable canonical `body_checksum` `fill_repair` verifies against), insert
    // the hole, and assert the committed-survival backstop AFTER the insert (so the tracked-for-repair
    // clause holds for a committed hole in `(checkpoint_op .. commit_max]`).
    for op in lo..=hi {
      if !matches!(self.log.get(&op), Some(e) if e.body.is_repairing()) {
        self.log.remove(&op);
      }
      self.repair.insert(op);
      self.assert_committed_survives(op, self.checkpoint_op.get());
    }
    // Observability: a windowed repair solicitation is going out for the hole band. Scalar copy only.
    self
      .events
      .push_back(Event::RepairStarted(crate::RepairStarted::new(
        OpNumber::with(lo),
        OpNumber::with(hi),
      )));
    self.send_request_prepare_range(lo, hi);
    self.timers.repair_retry = Some(now + REPAIR_RETRANSMIT);
    // Force-sync escalation: if a quorum already checkpointed past these just-registered holes, the
    // range solicitation is futile from the outset — escalate straight to a forced `RequestSync`.
    self.maybe_force_sync(now);
  }

  /// Broadcast a `RequestPrepareRange` for the contiguous missing committed run `[lo, hi]` to all peers.
  /// Any peer holding (a prefix of) the run answers with a byte-bounded [`RepairBatch`]
  /// (`on_request_prepare_range`). Broadcast (not primary-only), like `send_request_prepare`, so the
  /// repair completes even mid-view-change / when the primary itself holds the holes.
  pub(crate) fn send_request_prepare_range(&mut self, lo: u64, hi: u64) {
    self.emit(Outgoing::new(
      Recipient::Backups,
      Message::RequestPrepareRange(crate::RequestPrepareRange::new(
        self.view,
        OpNumber::with(lo),
        OpNumber::with(hi),
        self.config.replica(),
      )),
    ));
  }

  /// Whether `(op, entry)` is a still-open *repair-or-truncate candidate*: a header-only `Repairing`
  /// op ABOVE the known-committed frontier `commit_max` whose body is NOT already being made durable.
  /// Three exclusions, each meaning "not a truncation candidate":
  /// - `op <= commit_max` — genuinely COMMITTED (kept + repaired, never truncated).
  /// - not `Repairing` — its body is already `Present` (filled, or never a hole).
  /// - `op` in `self.appending` — a peer answered and `fill_repair` ACCEPTED the canonical body, which
  ///   is now an in-flight `Pending::RepairFill` (the entry stays `Repairing` only until `on_wal_done`
  ///   lands the durable append). A holder answering PROVES the op was committed, so it must NEVER be
  ///   truncated — even by a grace that fires concurrently with the not-yet-durable fill. A repair
  ///   hole's slot can only be `appending` via a `RepairFill` (the normal `on_prepare` re-append branch
  ///   skips ops in `self.repair`; see `fill_repair`), so this membership unambiguously means an
  ///   accepted-but-not-yet-durable fill — treat it as body-present.
  fn is_repair_or_truncate_candidate(&self, op: u64, entry: &LogEntry) -> bool {
    op > self.commit_max.get() && entry.body.is_repairing() && !self.appending.contains(&op)
  }

  /// Whether any *repair-or-truncate candidate* remains. The candidate set shrinks via a `Present` fill
  /// (`on_wal_done`'s `RepairFill` arm turns the entry `Present`) OR the moment `fill_repair` ACCEPTS a
  /// body (the op enters `self.appending`, so `is_repair_or_truncate_candidate` excludes it) —
  /// `commit_max` cannot cross a candidate without first filling its body (the apply/`try_commit` loop
  /// HOLDS at the body-absent hole) — so re-deriving from current state is exact.
  fn has_repair_or_truncate_candidate(&self) -> bool {
    self
      .log
      .iter()
      .any(|(op, e)| self.is_repair_or_truncate_candidate(*op, e))
  }

  /// Clear the body-aware nack-truncation grace once the LAST candidate is gone (filled or
  /// learned-committed). Called after a `Present` fill lands (`on_wal_done`'s `RepairFill` arm): a
  /// holder answered, so the candidate was committed after all and must never be truncated — disarm the
  /// deadline. Idempotent (a no-op if the timer is already `None` or candidates remain).
  pub(crate) fn cancel_repair_or_truncate_if_no_candidate(&mut self) {
    if self.timers.repair_or_truncate.is_some() && !self.has_repair_or_truncate_candidate() {
      self.timers.repair_or_truncate = None;
    }
  }

  /// Body-aware nack-truncation GRACE expiry (the f-fault-model liveness closure). Run on the
  /// Normal-primary heartbeat path (after `primary_timeouts`); a no-op unless the grace deadline is due.
  ///
  /// On expiry, RE-CONFIRM the candidate from CURRENT state — any op still held `Repairing` AND still
  /// ABOVE the known-committed frontier `commit_max` (so it was not, in the meantime, filled by a
  /// `Present` body nor learned-committed). If such candidates remain, the body is provably absent
  /// across the collected quorum and the grace has elapsed with no holder answering, so it is
  /// uncommitted-or-lost-beyond-`f`: TRUNCATE from the LOWEST such candidate up — drop the whole suffix
  /// `[gap ..= self.op]` from `self.log`, lower `self.op` to the op below `gap`, drop the stranded WAL
  /// tail, and clear EVERY per-op side table for that suffix: `repair`/`inflight`, the in-flight WAL
  /// appends `pending`/`appending` (a higher suffix op can have an accepted-out-of-order `RepairFill` or
  /// an adopted-tail `AdoptVote`/`AdoptAck` in flight — its abandoned completion must not resurrect a
  /// truncated op nor vote on a reused number), and the client-session request high-water (roll back any
  /// watermark a truncated uncommitted request advanced, so the client's retry is processed fresh, not
  /// deduped to a no-reply hang). Then `on_request`'s `!repair.is_empty()` / `commit_max > commit_min`
  /// guard clears (for the no-other-hole case) and the primary serves clients again.
  ///
  /// SAFETY: every truncated op is `> commit_max` (the lowest candidate `gap` is, and the tail above it
  /// is too), so each satisfies [`Self::assert_committed_survives`]'s uncommitted clause — no committed
  /// op is ever dropped here. Within `f` faults a committed op's body is reachable on a write-quorum and
  /// answers the `RequestPrepare` BEFORE this deadline (so a committed op is never a still-unfilled
  /// candidate at expiry — it would have filled + cancelled the grace). Gated, like the heartbeat, on
  /// `participates_as_primary() && !pending_forfeit`: a not-yet-durable-view or stepping-down primary
  /// must not truncate — the deadline is PRESERVED for the post-window tick (it stays non-serviceable,
  /// so `poll_timeout` filters it and the no-orphan-due assert ignores it; no spin).
  pub(crate) fn repair_or_truncate_timeouts<W: Wal>(&mut self, now: Instant, wal: &mut W) {
    // SERVICEABILITY GATE (the SAME `serviceable_now(RepairOrTruncate)` condition, enforced HERE so a
    // DIRECT `handle_timeout` tick — the VOPR + tests call it directly, bypassing `poll_timeout`'s
    // filter — never truncates in a non-serviceable window). A not-yet-durable-view (`pending_sb`) or
    // stepping-down (`pending_forfeit`) primary must NOT mutate the tail: the deadline is PRESERVED
    // (this returns WITHOUT clearing it), staying non-serviceable so `poll_timeout` filters it and the
    // no-orphan-due assert ignores it — no spin — and the post-window tick re-confirms + truncates.
    if !self.participates_as_primary() || self.pending_forfeit {
      return;
    }
    // A no-op unless the grace is armed-and-due. (With the gate above this only fires on a serviceable
    // tick, so guarding the due-ness here ensures a serviced grace is never left armed-and-due.)
    if self.timers.repair_or_truncate.is_none_or(|d| d > now) {
      return;
    }
    // RE-CONFIRM from CURRENT state: the LOWEST still-open candidate (held `Repairing`, above
    // `commit_max`, and NOT an accepted-but-not-yet-durable repair fill — see
    // `is_repair_or_truncate_candidate`). Everything from there to the head is the still-body-absent
    // uncommitted tail. The `appending` exclusion is load-bearing: a grace firing CONCURRENTLY with a
    // fill `fill_repair` already accepted (whose append has not yet landed) must not truncate that op —
    // a holder answered, so it was committed.
    let gap = self
      .log
      .iter()
      .filter(|(op, e)| self.is_repair_or_truncate_candidate(**op, e))
      .map(|(op, _)| *op)
      .min();
    let Some(gap) = gap else {
      // The last candidate filled / was learned-committed between the arm and now — nothing to
      // truncate; just disarm the grace.
      self.timers.repair_or_truncate = None;
      return;
    };
    // Truncate the uncommitted tail `[gap ..= self.op]`. SAFETY: `gap > commit_max`, so `gap` and every
    // op above it is uncommitted — each satisfies `assert_committed_survives`'s `> commit_max` clause, so
    // no committed op is ever dropped here.
    let head = self.op.get();
    let floor = self.checkpoint_op.get();
    // Clients whose at-most-once request high-water was advanced by a now-truncated op: their watermark
    // is rolled back below (a truncated UNCOMMITTED request must be processed fresh, not deduped). Captured
    // HERE because the `(client, request)` is read off the entry before it is removed from `self.log`.
    let mut truncated_clients: std::collections::BTreeSet<u128> = std::collections::BTreeSet::new();
    for op in gap..=head {
      self.assert_committed_survives(op, floor);
      if let Some(entry) = self.log.remove(&op) {
        truncated_clients.insert(entry.client.get());
      }
      self.repair.remove(&op);
      self.inflight.remove(&op);
    }
    // Roll back the client-session request high-water for every client an op in the truncated suffix
    // advanced. New-primary adoption (`start_view_as_new_primary`) seeds the watermark from the adopted
    // in-memory tail INCLUDING an uncommitted op (needed so a client whose op committed on the OLD primary
    // can have its NEXT request accepted — see that loop). But a truncated op never committed: leaving its
    // seeded watermark would make the client's ORIGINAL retry of that exact request hit `on_request`'s
    // dedup as a DUPLICATE with NO cached reply (a truncated op has none), so the primary would silently
    // drop it and the client would HANG forever. Lower each affected client's watermark to the highest
    // request still BACKED — its cached reply's request (its last COMMITTED request — a committed op is
    // never truncated, so this floor never regresses an at-most-once guarantee) OR the highest request
    // among its SURVIVING (un-truncated, `< gap`) log entries, whichever is greater — so a truncated
    // request is re-minted fresh while a still-held lower request stays deduped. Never RAISES the watermark
    // (the `>` guard), so it only undoes a stale advance.
    for client in truncated_clients {
      // The highest request this client still holds in a SURVIVING (un-truncated, `< gap`) log entry —
      // computed first so the `&self.log` borrow ends before the `&mut self.clients` write below.
      let surviving_request = self
        .log
        .values()
        .filter(|e| e.client.get() == client)
        .map(|e| e.request.get())
        .max()
        .unwrap_or(0);
      let Some(session) = self.clients.get_mut(&client) else {
        continue;
      };
      // Its cached reply's request is its last COMMITTED request (a committed op is never truncated, so
      // this floor never regresses an at-most-once guarantee).
      let reply_request = session.reply.as_ref().map_or(0, |(rn, _)| rn.get());
      let backed = reply_request.max(surviving_request);
      if session.request.get() > backed {
        session.request = RequestNumber::with(backed);
      }
    }
    // Abandon any in-flight WAL appends for the truncated suffix, kept in LOCKSTEP exactly as
    // `reset_for_view_transition` clears `pending`/`appending` on a view change — but scoped to the
    // suffix `>= gap` rather than wholesale (a LOWER op `< gap` keeps its legitimately-in-flight append).
    // A HIGHER suffix op can hold a `Pending::RepairFill` (a peer answered its repair out of order, so
    // the gap below excludes it via `appending`) or a `Pending::AdoptVote`/`AdoptAck` (an adopted
    // `Present` tail op re-appending). After `wal.truncate(gap-1)` that append is abandoned; left in
    // `pending`/`appending` its later completion would RESURRECT the truncated op back into `self.log`
    // above the lowered `self.op` (the `RepairFill` arm), cast an own vote / `PrepareOk` for a now-reused
    // op number (`AdoptVote`/`AdoptAck`), or simply linger as a permanently-stuck in-flight
    // (`has_inflight_storage()` true forever, since `appending` never clears). `self.pending` is keyed by
    // the minted `OpId`, NOT the op number, so filter by each pending's `Pending::op()`. Dropping the
    // entry makes its WAL completion a no-op in `on_wal_done` (the `None` arm). The `appending` set IS
    // keyed by op, so trim it directly to `< gap`.
    self.pending.retain(|_, p| p.op().get() < gap);
    self.appending.retain(|&op| op < gap);
    self.op = OpNumber::with(gap - 1);
    wal.truncate(OpNumber::with(gap - 1));
    self.timers.repair_or_truncate = None;
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
    }
  }

  /// Peer-fault-repair retransmit timer: while the repair set is non-empty, re-solicit every
  /// unrepaired op and re-arm. Terminates when the last hole is filled (`fill_repair` clears the op
  /// and stops re-arming once `repair` is empty).
  ///
  /// CONTIGUOUS runs of `self.repair` are COALESCED into windowed [`RequestPrepareRange`] re-solicits
  /// (each chunk capped at [`REPAIR_WINDOW`] ops) rather than one [`RequestPrepare`] per op — so a deep
  /// header-only band (a ~hundreds-deep `Repairing` adoption) re-solicits in a handful of range messages
  /// a holder answers with byte-bounded [`RepairBatch`]es, instead of one round trip per op. `self.repair`
  /// is a `BTreeSet` (ascending), so a maximal consecutive sub-sequence is one run; a non-consecutive gap
  /// (two separate holes with a filled op between) starts a new range request.
  pub(crate) fn repair_timeouts(&mut self, now: Instant) {
    if self.timers.repair_retry.is_none_or(|d| d > now) {
      return;
    }
    if self.repair.is_empty() {
      self.timers.repair_retry = None;
      return;
    }
    let ops: std::vec::Vec<u64> = self.repair.iter().copied().collect();
    // Coalesce ascending ops into maximal contiguous runs, emitting one `RequestPrepareRange` per run
    // (chunked at `REPAIR_WINDOW` ops so a single re-solicit never spans an unbounded range). `lo`/`hi`
    // track the current open run; a break in contiguity OR a full window flushes it.
    let mut lo = ops[0];
    let mut hi = ops[0];
    for &op in &ops[1..] {
      let contiguous = op == hi + 1;
      let within_window = op < lo + REPAIR_WINDOW;
      if contiguous && within_window {
        hi = op;
      } else {
        self.send_request_prepare_range(lo, hi);
        lo = op;
        hi = op;
      }
    }
    self.send_request_prepare_range(lo, hi);
    self.timers.repair_retry = Some(now + REPAIR_RETRANSMIT);
  }

  /// Answer a peer's `RequestPrepare` for a committed op it read back faulty: if we are `Normal`, our
  /// view is DURABLE, and we hold the op's body in our log cache, reply with the `Prepare` carrying it.
  /// Only a Normal replica answers (a recovering / view-changing replica may itself hold a hole at that
  /// op). The reply's `commit` field carries our commit so the requester can also learn fresh commit
  /// progress; the op's content is view-independent, so the requester accepts it regardless of our view.
  pub(crate) fn on_request_prepare(&mut self, _now: Instant, m: crate::RequestPrepare) {
    // Durable-view-before-participate: the served `Prepare` advertises `self.view` (see
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
    // Serve an op we hold in our log at or below our head (`op <= self.op`). A body-`Repairing` entry
    // holds the op's identity but NOT its bytes (we are ourselves awaiting peer-repair of this body), so
    // we cannot serve it — stay silent and let a peer that holds the body answer.
    let Some(entry) = self.log.get(&op) else {
      return; // we do not hold this op (or it is a hole for us too) — stay silent; another peer answers
    };
    let Body::Present(body) = &entry.body else {
      return;
    };
    if op > self.op.get() {
      return; // above our head — not ours to serve
    }
    // The reply's `commit` field is our TRUTHFUL `commit_min`. For a committed op (`op <= commit_min`)
    // this vouches the body is committed (`commit >= op`), the requester's committed-hole path. For an
    // UNCOMMITTED held op (`commit_min < op <= self.op`) the reply carries `commit < op`: we do NOT
    // certify it committed — `fill_repair` accepts such a body ONLY against a locally-known canonical
    // `body_checksum` (a carried-through view-change `Repairing` hole), so a peer-held uncommitted body
    // is adopted only when it matches the canonical checksum, never trusted blindly. This lets a new
    // primary fetch the body of a view-change-carried uncommitted-tail op from a peer that holds it.
    let prepare = Prepare::new(
      self.view,
      OpNumber::with(op),
      self.commit_min,
      self.checkpoint_op,
      entry.client,
      entry.request,
      body.clone(),
    );
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(m.replica())),
      Message::Prepare(prepare),
    ));
  }

  /// Answer a peer's [`RequestPrepareRange`] for a contiguous committed run `[lo, hi]` with a
  /// BYTE-BOUNDED PREFIX of the ops we hold `Present`, as one [`RepairBatch`]. The windowed analogue of
  /// [`Self::on_request_prepare`]: same serve gate (only a `Normal` replica whose view is DURABLE serves
  /// — a `pending_sb` replica's `self.view` could roll back; the served ops are committed +
  /// view-independent, so the requester loses nothing by waiting for another holder), but it walks the
  /// run and accumulates a PREFIX rather than serving one op.
  ///
  /// **The window bound (the work cap).** The decoded `hi` is untrusted — a buggy authenticated peer
  /// could send `hi:u64::MAX` against a high `self.op`. We clamp the served interval to the SAME window
  /// the requester solicits (`lo + REPAIR_WINDOW - 1`, then our head), and iterate the `Present` entries
  /// we actually HOLD in `[lo, hi]` via `self.log.range` — never the numeric `lo..=hi` — so the scan
  /// costs only our present entries within a fixed-width window, not the requester-claimed span. This
  /// bounds the WORK; the byte cap below bounds the answer SIZE.
  ///
  /// **The byte cap (the load-bearing bound).** We accumulate `Present` entries at/below our head into a
  /// `Vec` UNTIL the running encoded size would exceed the frame budget
  /// `MAX_FRAME_LEN - REPAIR_BATCH_CARRIER_OVERHEAD`, then STOP — serving a PREFIX of the run, never an
  /// unbounded batch (the requester re-solicits the unserved tail on its next pass). This is what keeps
  /// the produced `RepairBatch` under the transport frame cap by construction, regardless of how deep the
  /// solicited run is. A `Repairing`/missing op is SKIPPED (we do not hold its body), exactly as
  /// `on_request_prepare` stays silent on a hole — the requester's `fill_repair_batch` then fills only
  /// the ops we actually served and re-solicits the rest. Always serves at least the FIRST eligible
  /// entry even if its body alone meets the budget edge (a single committed op's body fits a frame by the
  /// `max_request_body_len` bound — see [`crate::message::MAX_REQUEST_BODY_OVERHEAD`], which accounts for
  /// the single-entry `RepairBatch` carrier), so the run always makes forward progress.
  pub(crate) fn on_request_prepare_range(&mut self, _now: Instant, m: crate::RequestPrepareRange) {
    // Durable-view-before-participate (identical to `on_request_prepare`): only a Normal replica whose
    // view is durable may serve a (view-advertising) repair answer.
    if !self.status.is_normal() || self.pending_sb.is_some() {
      return;
    }
    if m.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    let lo = m.lo().get();
    // Clamp the served interval to the requester's own solicitation window (`request_repair_run` caps
    // its `hi` the same way), then to our head: the decoded `hi` is untrusted (see the doc's work cap),
    // and the clamp caps the SCAN while the byte budget below caps the answer SIZE.
    let window_top = lo.saturating_add(REPAIR_WINDOW).saturating_sub(1);
    let hi = m.hi().get().min(window_top).min(self.op.get());
    if lo > hi {
      return;
    }
    // Accumulate a byte-bounded PREFIX of the run we hold `Present`. The budget is the frame cap less
    // the `RepairBatch` carrier framing; each `Present` entry costs `present_entry_encoded_len(body)`.
    let budget =
      crate::message::MAX_FRAME_LEN as usize - crate::message::REPAIR_BATCH_CARRIER_OVERHEAD;
    let mut running = 0usize;
    let mut entries: std::vec::Vec<crate::PreparedEntry> = std::vec::Vec::new();
    // `self.log.range(lo..=hi)`, not the numeric `lo..=hi`: the scan costs only the entries we hold.
    // A `Repairing` (header-only) entry is SKIPPED — we have its identity, not its bytes — exactly as
    // `on_request_prepare` stays silent on a hole; the requester re-solicits any gap.
    for (&op, entry) in self.log.range(lo..=hi) {
      let Body::Present(body) = &entry.body else {
        continue;
      };
      let (client, request) = (entry.client, entry.request);
      let cost = crate::message::present_entry_encoded_len(body.len());
      // Stop once adding this entry would exceed the frame budget — BUT always include the first eligible
      // entry (an empty `entries` here) so a run whose lowest held op is itself near the budget still
      // makes progress (a single op's body fits a frame by the request-body bound).
      if !entries.is_empty() && running + cost > budget {
        break;
      }
      running += cost;
      entries.push(crate::PreparedEntry::new(
        OpNumber::with(op),
        client,
        request,
        body.clone(),
      ));
    }
    if entries.is_empty() {
      return; // we hold no `Present` op in the run — stay silent; another holder answers
    }
    // Observability (non-vacuity): a non-empty batch is genuinely served (every silent/empty/gated
    // path returned above), witnessing the windowed bulk-repair serve.
    self.repair_batches_served += 1;
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(m.replica())),
      Message::RepairBatch(crate::RepairBatch::new(
        self.view,
        self.commit_min,
        self.checkpoint_op,
        entries,
      )),
    ));
  }

  /// Apply a peer-supplied [`RepairBatch`] answering our [`RequestPrepareRange`]: run the EXISTING
  /// per-entry [`Self::fill_repair`] core on EACH served entry, then let the deferred per-entry durable
  /// completions resume the held commit. This is purely a PIPELINING of the single-op repair fill — NOT
  /// a relaxation of it: each entry is reconstructed into a [`Prepare`] carrying the batch's `commit`
  /// (the committed-vouch the per-op serve's `Prepare` rides) and passed through `fill_repair`, which
  /// applies its OWN placement check (`self.repair.contains(&op)`), `appending` dedup, `Header::verify`
  /// checksum, and canonical-identity-or-committed-vouch gate before staging a `Pending::RepairFill` +
  /// `submit_append` + marking `op` `appending`. So EACH entry keeps its OWN durability barrier — N
  /// served entries → N independent `RepairFill` pendings, each applied only in its own `on_wal_done`
  /// after `WalDone::Appended` — and the safety surface is IDENTICAL to the per-op path, N times: no op
  /// is applied or replied from an unverified body, and an entry whose placement/checksum/vouch fails is
  /// silently skipped (re-solicited) exactly as a single declined repair `Prepare` is. A served entry
  /// whose op is not (or no longer) one of our holes is a no-op via `fill_repair`'s placement reject.
  pub(crate) fn on_repair_batch<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: crate::RepairBatch,
  ) {
    let commit = m.commit();
    let checkpoint_op = m.checkpoint_op();
    for e in m.into_log() {
      // Reconstruct the per-entry `Prepare` the per-op repair path expects, carrying the batch's
      // `commit` as the committed-vouch (so `fill_repair`'s `commit >= op` gate sees the same signal a
      // single repair-serve `Prepare` carries). The decoded `Body::Present` bytes are MOVED out of the
      // owned entry (`into_parts`) — the decode boundary already paid the wire→owned copy, so a second
      // per-entry copy here would be pure waste on the bulk-repair path. A header-only (`Repairing`)
      // served entry has no body to fill — skip it (we cannot adopt bytes we were not given); the
      // requester re-solicits.
      let (op, client, request, body) = e.into_parts();
      let Body::Present(body) = body else {
        continue;
      };
      let prepare = Prepare::new(self.view, op, commit, checkpoint_op, client, request, body);
      // The SAME verify + durability core as the single-op path: `fill_repair` rejects this entry
      // (silently; re-solicited) or stages its own `Pending::RepairFill` — see the doc above.
      self.fill_repair(now, wal, sb, &prepare);
    }
  }

  /// Fill a peer-supplied `Prepare` for an op in our pending-repair set, then resume the held
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
  /// crash-restart serve the repaired op) as a DURABILITY BARRIER: the apply, the
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
    let _ = (now, &mut *sb); // the apply/advance is deferred to on_wal_done; no commit here
    let op = p.op().get();
    if !self.repair.contains(&op) {
      return false; // placement: not a hole we are repairing — let on_prepare handle it normally
    }
    // A RepairFill append for this op is already in flight (a duplicate/retransmitted repair Prepare):
    // the op is still a hole (kept open until durable) but staging a SECOND append would double-write.
    // Swallow the duplicate — it is a repair answer we are already making durable. A repair
    // hole's slot can ONLY be `appending` via a RepairFill: the normal `on_prepare` re-ack/re-append
    // branch now skips an op in `self.repair` (the repair-hole-ownership guard there), so this `appending`
    // membership unambiguously means our own in-flight RepairFill, never a normal-path append.
    if self.appending.contains(&op) {
      return true;
    }
    // Reconstruct the header (also needed for the durable append below) and gate on its body checksum
    // (self-consistency: the body matches its own header's embedded checksum).
    let header = Header::new(p.op(), p.view(), p.client(), p.request(), p.body());
    if !header.verify(p.body()) {
      return false; // unverifiable body — never adopt it; keep the hole + re-solicit
    }
    // SAFETY: a repair hole may ONLY be filled with the CANONICAL body for this op. Two trust sources,
    // in priority order:
    //   1. A KEPT header-only `Repairing` hole carries the op's durable canonical `(client, request,
    //      body_checksum)` (recovered from a durable WAL header / carried through a view change). The
    //      supplied body must match that FULL identity — same client+request AND
    //      `body_checksum`. This certifies the body WITHOUT a committed-vouch, so a new primary can fetch
    //      the body of a view-change-carried UNCOMMITTED-tail op from a peer that holds it (the peer's
    //      reply carries `commit < op`, but the canonical checksum is what makes it safe).
    //   2. Otherwise (a hole with no kept canonical header — the ordinary committed-band repair) the
    //      answer must come from a peer that holds op N COMMITTED, i.e. `commit >= op`: a committed op's
    //      body is identical across all views (committed-op survival), so it is canonical. A
    //      stale/reordered old-view Prepare carrying `commit < op` is rejected (keep the hole open +
    //      re-solicit) so a committed slot is never overwritten with an uncommitted old-view body.
    match self.log.get(&op) {
      Some(LogEntry {
        client,
        request,
        body: Body::Repairing(canonical_checksum),
      }) => {
        if p.client() != *client
          || p.request() != *request
          || crate::storage::fnv1a_128(p.body()) != *canonical_checksum
        {
          return false; // does not match the kept canonical identity — never adopt; keep the hole
        }
      }
      _ => {
        if p.commit().get() < p.op().get() {
          return false; // not committed-vouched and we hold no canonical header — reject
        }
      }
    }
    // Persist the repaired op durably (append-after-verify) as a DURABILITY BARRIER. The
    // body is staged in the `Pending::RepairFill` entry — NOT in `self.log` — so it is NOT exposed in a
    // DVC/StartView/checkpoint nor applied by a concurrently-triggered `advance_commit` while the append
    // is still in flight; `on_wal_done` inserts it into `self.log`, clears the hole, and advances the
    // commit only once `WalDone::Appended` lands. The hole stays OPEN here (commit held, op not exposed)
    // and `op` is marked `appending` so the durable-status oracle treats it as in-flight (and a
    // duplicate repair Prepare hits the early `appending` guard above instead of double-appending).
    let entry = LogEntry::present(p.client(), p.request(), p.body_bytes());
    let id = self.mint_op_id();
    wal.submit_append(id, p.op(), header, p.body_bytes());
    // This append owes NO PrepareOk/own-vote (peer repair is not a vote), but unlike the OLD bare write
    // it IS tracked — as a `RepairFill`, so `on_wal_done` defers the apply + hole-clear to durability.
    self.pending.insert(
      id.get(),
      Pending::RepairFill(RepairFill::new(p.op(), entry)),
    );
    self.appending.insert(op);
    // STAGE-TIME CANCEL of the body-aware nack-truncation grace: a holder ANSWERED with the canonical
    // body for this op, which PROVES the op was committed — it must NEVER be truncated. `op` is now in
    // `self.appending`, so `is_repair_or_truncate_candidate` excludes it; if it was the LAST candidate
    // the grace disarms HERE (the moment of acceptance), not only when the append lands durably in
    // `on_wal_done`. This closes the async-fill race where a fill accepted before the deadline but made
    // durable after it would otherwise let the grace fire on a still-`Repairing` (but already-answered)
    // entry. Idempotent + safe with other still-open candidates outstanding (it keeps the grace then).
    self.cancel_repair_or_truncate_if_no_candidate();
    true
  }
}

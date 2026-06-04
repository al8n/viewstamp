use super::*;

/// The committed-band recover verdict: does a recovered, SELF-VERIFYING WAL slot count as
/// the canonical body for its op, or is it a stale/superseded slot that must be peer-repaired?
///
/// Only ever computed for a slot that has ALREADY passed `Header::verify` + the placement check
/// (`header.op() == op`) at the call site — so this classifies the SELF-CONSISTENT slots, splitting
/// them into the ones we adopt and the ones we drop. Two outcomes; the `Fault` case (a torn/absent/
/// misdirected read) never reaches here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotVerdict {
  /// The slot IS the canonical body for `op` — adopt it.
  Verified,
  /// The slot is stale/unproven/superseded — drop it from the cache; `advance_commit` peer-repairs the
  /// canonical body on demand (it is NEVER re-derived from this WAL).
  StaleCommitted,
}

/// Classify a recovered, self-verifying WAL slot at `op` against the durable `vsr_headers` — the
/// committed-band recover verdict. EXTRACTED from `on_recover_wal_done` as a PURE + TOTAL
/// function so its safety (a TOTAL partition of the committed-band staleness space — no stale-committed
/// body can slip through a future reorder of the arms) is FROZEN by a unit test, not left to depend on a
/// rare schedule. Behaviour is byte-for-byte the prior in-line `match` (verified against the recover
/// tests + VOPR).
///
/// Inputs (exactly what the call site holds):
/// - `slot_identity` — the read slot's FULL committed-op identity `(client, request, body_checksum)`,
///   NOT body bytes alone: two clients can submit identical payloads, so a body-only check would trust a
///   stale slot bearing the same body under a different client/request.
/// - `canonical` — the persisted SPARSE header's identity for `op` (`None` if the writer held no header
///   for `op`: a gap / a not-held committed op).
/// - `op`, `slot_view` — the slot's op and its ORIGINAL header view.
/// - `durable_commit` — our durable known-committed frontier (`commit_max`).
/// - `durable_log_view` — our durable `log_view`.
///
/// The four mutually-exclusive, EXHAUSTIVE arms (see the cross-product test
/// `classify_committed_slot_is_total_over_the_staleness_space`):
///   * header present + identity MISMATCH → `StaleCommitted` (the persisted `vsr_headers` say a
///     different body, OR the same body under a different client/request — a superseded/stale slot).
///   * header ABSENT + KNOWN-COMMITTED (`op <= durable_commit`) → `StaleCommitted` (the SPARSE
///     set has one header per committed-band op the writer HELD, so no header ⇒ the writer did NOT hold
///     this committed op — a genuine hole / stale leftover the headers do not vouch; the local
///     self-verifying body is UNPROVEN and must be peer-repaired, never trusted).
///   * header ABSENT + ABOVE-commit (`op > durable_commit`) + SUPERSEDED view (`slot_view <
///     durable_log_view`) → `StaleCommitted` (an above-band tail op from a generation we
///     have already superseded — we advanced `log_view` past its view, so its body is an abandoned
///     earlier-view proposal).
///   * everything else → `Verified` — i.e. (a) header present + identity MATCH (a
///     locally-held canonical committed op above a LOWER header-less hole is KEPT — its own sparse header
///     vouches it), or (b) header ABSENT + ABOVE-commit + CURRENT-generation view (`slot_view >=
///     durable_log_view`) — a current uncommitted tail op, kept to be re-acked.
fn classify_committed_slot(
  slot_identity: (ClientId, RequestNumber, u128),
  canonical: Option<(ClientId, RequestNumber, u128)>,
  op: u64,
  slot_view: u64,
  durable_commit: u64,
  durable_log_view: u64,
) -> SlotVerdict {
  match canonical {
    // (1) HAS a sparse canonical header: its FULL identity must MATCH (a different body, OR the same body
    // under a different client/request, is stale). A MATCH keeps a locally-held canonical
    // committed op above a lower header-less hole.
    Some(canonical) if canonical != slot_identity => SlotVerdict::StaleCommitted,
    // (2) KNOWN-COMMITTED (`op <= durable_commit`) but NO sparse header: the writer did not hold
    // this committed op — unproven, must be peer-repaired. A HELD committed op carries a sparse header and
    // so takes the MATCH path above, not this arm.
    None if op <= durable_commit => SlotVerdict::StaleCommitted,
    // (3) ABOVE the durable committed frontier with a strictly-older view: a superseded
    // earlier-view proposal. A current-generation uncommitted tail op (`slot_view >= durable_log_view`) is
    // NOT dropped — it is kept to be re-acked.
    None if op > durable_commit && slot_view < durable_log_view => SlotVerdict::StaleCommitted,
    // (4) header present + identity match, OR above-commit current-generation tail → canonical.
    _ => SlotVerdict::Verified,
  }
}

impl<S: StateMachine> Endpoint<S> {
  /// Reconstructs an endpoint from durable storage after a restart — a **metadata-only constructor**
  /// that enters [`Status::Recovering`] and defers all fallible reads to an async `handle_storage`
  /// loop (faults-as-data; spec §2/§6). It does NOT return in `Normal`.
  ///
  /// **Phase 1 (here, sync + infallible).** Reads only synchronous trait metadata — the superblock
  /// root via `sb.state()` for `(view, log_view, checkpoint_op, checkpoint_id)` and `wal.op_head()` /
  /// `wal.header(op)` — and constructs the endpoint with:
  /// - `view = state.view()`, `log_view = state.log_view()`, `op = wal.op_head()`,
  ///   `checkpoint_op = state.checkpoint_op()`, `commit_min = checkpoint_op` (the restored SM already
  ///   reflects `[1..=checkpoint_op]`, so this prevents a double-apply), and `commit_max = state.commit()`
  ///   — the DURABLE known-committed frontier, `>= checkpoint_op` and possibly above it, so
  ///   the replica never FORGETS a known-committed op on recover (its DVC would else under-report and a
  ///   known-committed op could be truncated in a view change). `op >= commit_min` and `commit_max >=
  ///   commit_min` hold; `op >= commit_max` does NOT (a stale/faulty/truncated head can leave
  ///   `commit_max > op`, the tail-gap shape). With no checkpoint and a fresh root (`checkpoint_op ==
  ///   commit == 0`) this is the no-checkpoint behaviour: a fresh `S`, `commit_min == commit_max == 0`.
  /// - the in-memory log cache built **from headers only over the OFFSET tail** `(checkpoint_op ..
  ///   head]` (`wal.header(op)`, bodies left empty — filled by Phase 2). NOT dense `[1..=head]`: the
  ///   committed prefix `[1..=checkpoint_op]` lives in the restored SM snapshot (and a state-synced
  ///   replica has pruned its WAL there), so the cache holds only ops ABOVE the checkpoint;
  ///   `commit_min == checkpoint_op` means `[1..=checkpoint_op]` are never re-applied. View change is
  ///   **offset-aware** (`select_canonical_log` UNIONs the committed band across DVCs, so an
  ///   offset log carrying only `(checkpoint_op .. head]` is safe — no committed op a different-floor
  ///   participant needs is dropped). A slot whose `header()` is absent/faulty is still recorded as
  ///   pending (the read resolves it).
  /// - `status = Status::Recovering`, and a fresh `RecoverState`: every `op in (checkpoint_op ..
  ///   head]` is submitted via `submit_read` (minted `OpId` recorded in `recover.reads`) with a
  ///   `RECOVER_READ_RETRIES` budget in `recover.pending`; if `checkpoint_op > 0` the checkpoint
  ///   read is submitted too (its `OpId` in `recover.checkpoint`).
  ///
  /// It submits the reads (a sync, infallible trait call, mirroring `on_request`'s `submit_append`)
  /// but performs **no `poll()`** — completion handling, checksum verification, and retry all live in
  /// Phase 2. Hence the `&mut W, &mut B`.
  ///
  /// **Phase 2 (`handle_storage`, async + fallible).** `on_wal_done`/`on_sb_done` drive the reads to
  /// a consistent tail: each `ReadOk`'s body is adopted only after `Header::verify` (a torn write /
  /// bit-rot surfaces as a checksum mismatch and is treated as a fault); `Fault`/`Absent`/mismatch is
  /// retried within the budget, then classed permanently faulty; the checkpoint `CheckpointRead`
  /// restores the SM + sessions. Once every read is satisfied, `recover_progress` transitions to
  /// `Normal` (tail consistent) or `RecoveringHead` (the head slot is permanently faulty — it cannot
  /// trust its head and awaits a `StartView`). A recovered backup re-emits
  /// nothing; it waits for the primary's `Prepare`/`Commit` to re-announce commit, exactly as before.
  ///
  /// **Durable-view.** The view is persisted before any view-change participation, so `state.view()`
  /// is trustworthy: a recovered replica resumes the view it was in when it last participated.
  pub fn recover<W: Wal, B: Superblock>(
    config: Config,
    seed: u64,
    sm: S,
    wal: &mut W,
    sb: &mut B,
  ) -> Self {
    let state = sb.state();
    let nonce = Prng::new(seed).next_u64();
    let head = wal.op_head().get();
    let checkpoint_op = state.checkpoint_op().get();
    // The high end of the tail read window (the VERIFIED read frontier): the WAL head, but capped so a
    // corrupt/buggy `op_head` cannot force unbounded reads (the cap rationale is on `RECOVER_TAIL_WINDOW`).
    // The cap floor is the DURABLE committed frontier `state.commit()` (`>= checkpoint_op`), NOT
    // `checkpoint_op` alone: `RECOVER_TAIL_WINDOW` must bound only the UNCOMMITTED tail
    // above the committed band, never HIDE a committed op this replica HOLDS. `state.commit()` is the
    // writer's `commit_max` — a DURABLE, checksum-validated (`VsrState`), quorum-bounded frontier; a
    // corrupt superblock CANNOT inflate it (it would fail `VsrState` validation) and `commit_max` is at
    // most the real committed frontier, so reading up to it never reads a bogus band. With the old
    // `checkpoint_op + RECOVER_TAIL_WINDOW` floor, a durable root naming `commit_max` above that cap
    // (reachable with `Config::with_checkpoint_ops > RECOVER_TAIL_WINDOW`: commit far past the last
    // checkpoint, persist a durable-view root, crash) would cap `self.op` BELOW held committed ops — its
    // DVC would then under-report `commit_max > self.op` with a short `log_slice`, tripping
    // `select_canonical_log`'s `commit* > op_head` fail-stop (or a truncating adoption would DESTROY the
    // hidden committed copies). The loop below materializes + reads exactly `(checkpoint_op .. hi]`, so
    // `hi` is the highest op this `recover()` actually reads and verifies. When `commit_max > head` (a
    // synced/truncated replica that does NOT hold the committed ops above its head) the `head.min(..)`
    // still clamps `hi = head` — the band `(head, commit_max]` stays repair holes / peer-repaired,
    // unchanged.
    let committed_frontier = state.commit().get().max(checkpoint_op);
    let hi = head.min(committed_frontier.saturating_add(RECOVER_TAIL_WINDOW));
    // The recovered head is the VERIFIED read FRONTIER `hi`, never BELOW the durable checkpoint — NOT
    // the RAW `head` (safety). A STATE-SYNCED replica holds no WAL at or below the synced
    // checkpoint (it pruned the WAL there and never appended the tail), so its `wal.op_head()` can be
    // below `checkpoint_op`; the SM snapshot owns `[1..=checkpoint_op]`, so the recovered head must be
    // at least `checkpoint_op` to preserve `op >= commit_max >= commit_min == checkpoint_op`. The cache
    // below covers only the OFFSET tail `(checkpoint_op .. hi]` — for a synced replica that range is
    // empty; the prefix `[1..=checkpoint_op]` lives in the restored SM snapshot.
    //
    // Why `hi`, not `head`: if `head > hi` (a pathological / bit-rotted head far above the window), the
    // ops in `(hi, head]` were NEVER read/verified/cached here. Setting `self.op = head` would "hold"
    // them per the head, so `on_prepare`'s `pop <= self.op` branch would BLIND-RE-ACK them WITHOUT
    // consulting `self.log` — voting for ops this replica never durably appended (breaking
    // append-before-ack, risking a committed-op loss if the primary counted that false ack and then
    // died). Capping `self.op` at the read frontier means an op above it is NOT held: a later `Prepare`
    // for it takes the `pop == self.op + 1` APPEND branch (the primary re-sends; idempotent), durably
    // appending before any ack — correct. So: head below checkpoint → op = checkpoint; checkpoint <=
    // head <= frontier → op = head (unchanged, the legitimate small-tail case); head > frontier → op =
    // frontier (capped — the deep tail recovers incrementally as the primary re-announces it).
    let op = hi.max(checkpoint_op);

    let mut endpoint = Self {
      config,
      status: Status::Recovering,
      view: state.view(),
      op: OpNumber::with(op),
      // The restored SM reflects [1..=checkpoint_op] exactly; commit_min = checkpoint_op so those ops
      // are NOT re-applied. commit_max = state.commit() (the DURABLE known-committed frontier),
      // which is `>= checkpoint_op` (a `VsrState` invariant) and may EXCEED it: a replica whose
      // root says op N is committed must NOT forget that on recover, else its DoViewChange under-reports
      // and a known-committed op N whose WAL slot is stale/faulty (dropped → repair hole) can be
      // truncated in a view change whose quorum is this replica + a laggard. The committed band
      // (checkpoint_op .. commit_max] re-applies via `advance_commit` from the WAL (HOLDING at any
      // stale/faulty slot that became a repair hole, peer-repaired on demand). `op >= commit_max` is NOT
      // an invariant here — a stale/faulty/truncated head can leave `commit_max > op` (the tail-gap
      // shape: a committed op is KNOWN but not locally held), exactly as a normal lagging backup; only
      // `op >= commit_min` and `commit_max >= commit_min` hold. After a state-sync the durable root names
      // `commit == checkpoint_op` (apply_sync persists that), so `commit_max == checkpoint_op` there —
      // unchanged behaviour.
      commit_min: OpNumber::with(checkpoint_op),
      commit_max: state.commit(),
      log_view: state.log_view(),
      svc_from: 0,
      svc_target: state.view(),
      // ViewChange-only collection — `None` in `Status::Recovering` (this constructor's status). A
      // recovery-driven view change (`enter_view_change_from_recovery` / `catch_up_to_view`) sets it.
      view_change: None,
      nonce,
      // Dense headers-only cache; bodies filled by the Recovering loop (Phase 2).
      log: BTreeMap::new(),
      inflight: BTreeMap::new(),
      buffer: BTreeMap::new(),
      // Sessions are restored from the checkpoint snapshot in `on_sb_done` (Phase 2).
      clients: BTreeMap::new(),
      sm,
      outgoing: VecDeque::new(),
      events: VecDeque::new(),
      timers: Timers::default(),
      next_op_id: 1,
      pending: BTreeMap::new(),
      appending: std::collections::BTreeSet::new(),
      pending_sb: None,
      pending_checkpoint: None,
      checkpoint_op: OpNumber::with(checkpoint_op),
      peer_checkpoint: BTreeMap::new(),
      recover: None,
      repair: std::collections::BTreeSet::new(),
      sync: None,
      pending_install: None,
      sync_serving: BTreeMap::new(),
      state_syncs_applied: 0,
      forced_syncs_applied: 0,
      wal_stalls: 0,
      below_ring_window_syncs: 0,
      pending_forfeit: false,
    };

    // Phase 1: build the dense header cache (bodies empty) and submit the tail + checkpoint reads.
    // The cache + reads cover ONLY the tail ABOVE the checkpoint, `(checkpoint_op..=head]`: the SM
    // snapshot is authoritative for `[1..=checkpoint_op]` (those ops are never re-applied —
    // `commit_min == checkpoint_op` — and a STATE-SYNCED replica has pruned its WAL there, so reading
    // them would spuriously class pruned slots faulty). A recover-from-checkpoint replica and a
    // state-synced one are thus identical: both hold only the tail above the checkpoint, and the DVC
    // they later send carries that (offset) tail with `commit == checkpoint_op` (the offset-safe shape
    // asserted by the A6 tests). `head` may be below `checkpoint_op` for a synced replica → the range
    // is empty and recovery completes immediately at the synced point.
    let mut rec = RecoverState::default();
    // Seed the canonical committed-band IDENTITY from the durable `VsrState`'s `vsr_headers` (the
    // persisted-header cross-check, mirroring TigerBeetle). Each header is keyed by op → canonical
    // `(client, request, body_checksum)` — the FULL committed-op identity, not body bytes alone:
    // two clients can submit identical payloads, so a body-only check would trust a stale slot
    // bearing the same body under a different client/request. Phase 2 (`on_recover_wal_done`) checks a
    // committed-band WAL slot's `(client, request, body_checksum)` against this, so a stale/superseded
    // slot is detected and peer-repaired instead of
    // re-derived. The persisted `view` is intentionally excluded (see `RecoverState::canonical`):
    // `committed_band_headers()` rewrites the entry view to the root view, so it is not the original.
    // The persisted band is the SPARSE canonical set over `(checkpoint_op .. commit]`:
    // one header per committed-band op the writer HELD, op-ascending, with GAPS where the writer had a
    // hole — bounded by the checkpoint interval. Seeded as a per-op map keyed by `op`, so a gap is just
    // an op with NO canonical entry; a held committed op above a lower hole keeps its entry and is
    // verified individually. Only ops at/below the persisted `commit` are committed, so
    // we never cross-check (and thus never drop) an op the root did not record as committed.
    for h in state.committed_headers_slice() {
      rec
        .canonical
        .insert(h.op().get(), (h.client(), h.request(), h.body_checksum()));
    }
    // Bound the per-recover read-submission window: a corrupt/buggy `Wal` reporting a huge
    // `op_head` must not force unbounded bookkeeping + reads here. SATURATING `checkpoint_op + 1`
    // (never overflow), with the high end `hi` (computed above) capped at `committed_frontier +
    // RECOVER_TAIL_WINDOW` and at `head` — at most `RECOVER_TAIL_WINDOW` slots ABOVE the durable
    // committed frontier are materialized per pass (the cap bounds the uncommitted tail,
    // never the committed band, which is read in full up to the validated `commit_max`). A legitimate
    // uncommitted tail (the small un-checkpointed pipeline above the committed frontier) is far below the
    // cap; a pathological head is clipped (its deep tail is recovered incrementally / via the head-fault
    // path), never billions of reads. `self.op` was set to `hi.max(checkpoint_op)` above, so the window
    // this loop reads and the held head agree EXACTLY (no held op above the verified frontier).
    let lo = checkpoint_op.saturating_add(1);
    for op in lo..=hi {
      if let Some(h) = wal.header(OpNumber::with(op)) {
        // A Phase-1 header-only PLACEHOLDER: the body is filled in by the WAL-tail read completion
        // (`on_recover_wal_done`). Kept as a `Present(empty)` body — NOT a `Body::Repairing` hole — so
        // behavior is exactly as before this task; a recovering replica does not apply ops, so the empty
        // placeholder is never read by the commit path (it is filled, or dropped + peer-repaired, first).
        endpoint
          .log
          .insert(op, LogEntry::present(h.client(), h.request(), Bytes::new()));
      }
      // Submit a read for EVERY tail op (even one whose header is absent/faulty now): the read is
      // the authoritative resolution, and a `Fault`/`Absent` completion routes through the retry
      // path. Each read gets a minted OpId (never aliases a future real op — next_op_id grows).
      let id = endpoint.mint_op_id();
      wal.submit_read(id, OpNumber::with(op));
      rec.reads.insert(id.get(), op);
      rec.pending.insert(op, RECOVER_READ_RETRIES);
    }
    if checkpoint_op > 0 {
      let id = endpoint.mint_op_id();
      sb.submit_read_checkpoint(id);
      rec.checkpoint = Some(id.get());
      rec.checkpoint_retries = RECOVER_READ_RETRIES;
    }
    endpoint.recover = Some(rec);
    // Settle the transition decider once: an EMPTY WAL with no checkpoint (head == 0) has nothing to
    // read, so it must reach Normal here (no completion would ever arrive to drive the loop).
    // Otherwise this arms the recover_retry timer so an owner driving `poll_timeout`/`handle_timeout`
    // re-submits any read whose completion is dropped or whose transient fault clears on a later read.
    endpoint.recover_progress(Instant::ZERO, sb);
    endpoint
  }

  /// Handles a WAL completion while `Recovering`/`RecoveringHead` (Phase 2 of `recover`). Adopts a
  /// body ONLY after `Header::verify` (the faults-as-data chokepoint: a torn write / bit-rot fails
  /// verify and is treated as a `Fault`); retries `Fault`/`Absent`/mismatch within the per-slot
  /// budget, then classes the slot permanently faulty. Calls `recover_progress` after each.
  pub(crate) fn on_recover_wal_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    done: WalDone,
  ) {
    // The OpId of the completed read identifies which tail op it resolves (recover.reads). An
    // append completion (Appended) or an OpId we are not tracking is a stale/foreign completion —
    // ignore it (never panic): faults-as-data.
    let id = match &done {
      WalDone::ReadOk(r) => r.id(),
      WalDone::Absent(id) | WalDone::Fault(id) => *id,
      WalDone::BodyFaulty(bf) => bf.id(),
      WalDone::Appended(_) => return,
    };
    // Capture the durable known-committed frontier + log_view BEFORE borrowing `rec` (the above-band
    // view check reads them, and `rec` mutably borrows `self.recover`). Both are
    // immutable during the recover loop (`advance_commit` runs only after recovery completes).
    let durable_commit = self.commit_max.get();
    let durable_log_view = self.log_view.get();
    let Some(rec) = self.recover.as_mut() else {
      return;
    };
    let Some(&op) = rec.reads.get(&id.get()) else {
      return; // not one of our outstanding recovery reads (stale/superseded) — ignore.
    };
    // Decide the outcome. Four cases (the canonical set is SPARSE — one entry per committed-band op the
    // writer HELD — so it is keyed per-op and a gap is simply an op with NO entry):
    //   * Verified  — an Ok body that self-verifies, lands on the op we asked for, AND (if this op has a
    //     SPARSE canonical header) MATCHES its canonical `(client, request, body_checksum)` → adopt it.
    //     This is what KEEPS a locally-held canonical committed op above a LOWER header-less hole (its
    //     own sparse header vouches it — that op's only surviving copy is not deleted.
    //   * StaleCommitted — an Ok body that self-verifies + lands right but is a STALE/UNPROVEN slot,
    //     detected three ways: (a) it HAS a sparse canonical header and its FULL identity `(client,
    //     request, body_checksum)` MISMATCHES it (TigerBeetle's vsr_headers — a prior-view
    //     proposal whose own header is internally consistent, or a same-body-different-identity slot);
    //     (b) it is KNOWN-COMMITTED (`op <= commit_max`) but has NO sparse header — an op the
    //     writer did NOT hold when it persisted the root (a genuine hole / a stale leftover the headers
    //     do not vouch), so the local self-verifying body is UNPROVEN and must be peer-repaired, never
    //     trusted (now firing ONLY for not-held ops, since a HELD committed op gets a
    //     sparse header via case-Verified above); or (c) it is ABOVE the durable known-committed frontier
    //     AND its header `view` is BELOW our durable `log_view` — a tail op from a
    //     generation this replica has already SUPERSEDED (it advanced its `log_view` past that op's view,
    //     so the slot's body is an abandoned earlier-view proposal). Each verdict is DEFINITIVE
    //     (re-reading the same slot cannot fix it), so the slot is dropped + routed to peer-repair WITHOUT
    //     spending retries; once the cluster commits that op the canonical body is fetched, never
    //     re-derived from the stale WAL.
    //   * Fault — Absent / Fault / misdirected / a ReadOk that fails self-verify (torn/bit-rot) → retry.
    enum Outcome {
      // The full verified entry identity (client, request, body) — NOT the body alone — so a slot that
      // was already DROPPED from `self.log` as faulty (a transient that cleared on a later timer-driven
      // read, after `drop_faulty_committed_slots` ran) can be RE-INSERTED in full, not lost.
      Verified(ClientId, RequestNumber, Bytes),
      // A durable-header read whose BODY is faulty (torn/rotted/absent) but whose slot classifies
      // Verified — the op EXISTS and its identity is known, only the body must be peer-repaired. The op
      // is KEPT header-only as a `Body::Repairing` hole carrying its durable `(client, request,
      // body_checksum)`, NOT dropped: its existence is preserved so a later view change can never
      // re-mint its op number, and the commit path solicits the body on demand. (The body bytes are
      // absent, hence only the identity + canonical checksum, unlike `Verified`.)
      KeepRepairing(ClientId, RequestNumber, u128),
      StaleCommitted,
      Fault,
    }
    let outcome = match &done {
      // Adopt only a body that BOTH verifies (header + body checksums) AND lands on the op we asked
      // for. A misdirected read (a different valid slot returned under our OpId) would checksum-verify
      // cleanly, so the placement check (`header.op() == op`) guards against pairing another op's body
      // with this op's metadata — the placement-integrity defense TigerBeetle makes for misdirected IO.
      WalDone::ReadOk(r)
        if r.header().op() == OpNumber::with(op) && r.header().verify(r.body()) =>
      {
        // The self-consistent slot is canonical UNLESS it is detectably superseded/unproven. (1) If it
        // HAS a SPARSE canonical header,
        // its FULL identity `(client, request, body_checksum)` must match that header (a different body,
        // OR the SAME body under a different client/request, is stale). A MATCH here is what
        // KEEPS a locally-held canonical committed op above a lower header-less hole — its own sparse
        // header vouches it, so this replica's only surviving copy is not destroyed. The committed-band
        // `view` is NOT compared — `committed_band_headers()` rewrote it to the current root view, so it
        // is not the op's original. (2) ABOVE the durable committed frontier (`op > commit_max`, so there
        // is NO canonical header to compare), a slot whose ORIGINAL header `view` is below our durable
        // `log_view` is a superseded earlier-view proposal: we advanced `log_view` past it, so
        // its body is abandoned. A current-generation uncommitted tail op has `view == log_view` and is
        // kept (to be re-acked); only a strictly-older-view slot is dropped.
        let h = r.header();
        // The verdict (Verified vs StaleCommitted) is the PURE, exhaustively-tested
        // `classify_committed_slot`; the adopt payload `(client, request, body)` is built
        // here only for the Verified case (the body is not part of the verdict). See that function for
        // the four-arm rationale — kept there so a reorder fails a unit test.
        match classify_committed_slot(
          (h.client(), h.request(), h.body_checksum()),
          rec.canonical.get(&op).copied(),
          op,
          h.view().get(),
          durable_commit,
          durable_log_view,
        ) {
          SlotVerdict::StaleCommitted => Outcome::StaleCommitted,
          SlotVerdict::Verified => Outcome::Verified(h.client(), h.request(), r.body_bytes()),
        }
      }
      // A durable-header read whose BODY is faulty (torn/rotted/absent): we HAVE the self-verified
      // header for `op`, so run the SAME `classify_committed_slot` verdict a clean read runs — only the
      // body verdict differs (we lack the bytes). The placement check is the header's own op: a
      // BodyFaulty whose `header().op()` is NOT `op` is a misdirected-read sibling — not a trustworthy
      // read of THIS op — so it falls to `Fault` (the catch-all below) and retries.
      //   * Verified → KEEP the op header-only as `Body::Repairing` (existence preserved, body
      //     peer-repaired) rather than drop it — so a later view change can never re-mint its number.
      //   * StaleCommitted → drop + peer-repair the canonical body (a superseded/stale slot must NOT be
      //     resurrected as `Repairing`), exactly as a stale ReadOk is dropped.
      WalDone::BodyFaulty(bf) if bf.header().op() == OpNumber::with(op) => {
        let h = bf.header();
        match classify_committed_slot(
          (h.client(), h.request(), h.body_checksum()),
          rec.canonical.get(&op).copied(),
          op,
          h.view().get(),
          durable_commit,
          durable_log_view,
        ) {
          SlotVerdict::StaleCommitted => Outcome::StaleCommitted,
          SlotVerdict::Verified => {
            Outcome::KeepRepairing(h.client(), h.request(), h.body_checksum())
          }
        }
      }
      _ => Outcome::Fault, // Absent, Fault, misdirected, OR a ReadOk that fails verify (torn/bit-rot).
    };
    match outcome {
      Outcome::Verified(client, request, body) => {
        // Adopt the verified body, retiring this read. Normally the Phase-1 header-only placeholder is
        // still present and we just fill its body; but if this slot had earlier been classed faulty and
        // DROPPED from `self.log` (`drop_faulty_committed_slots`), a later timer-driven re-read that
        // clears the transient must RE-INSERT the full entry rather than silently lose the recovered op.
        rec.reads.remove(&id.get());
        rec.pending.remove(&op);
        rec.faulty.remove(&op);
        match self.log.get_mut(&op) {
          Some(entry) => entry.body = Body::Present(body),
          None => {
            self
              .log
              .insert(op, LogEntry::present(client, request, body));
          }
        }
      }
      Outcome::KeepRepairing(client, request, body_checksum) => {
        // KEEP the op header-only as a `Body::Repairing` hole, retiring this read. Its existence +
        // canonical identity (client, request, body_checksum) survive the body fault, so a later view
        // change cannot re-mint its op number; the bytes are absent and the commit path peer-repairs
        // them ON DEMAND (`advance_commit`/`commit_op` hold at a `Repairing` entry and `request_repair`
        // its body). It is NOT added to `rec.faulty`: the op is fully RESOLVED here (the durable header
        // makes its existence certain), so it must NOT be dropped by `drop_faulty_committed_slots` nor
        // re-read — unlike a no-durable-header `Fault`, which IS faulty. A `Repairing` entry already
        // present (a re-read after a prior body fault) is left as-is; a Phase-1 `Present(empty)`
        // placeholder is REPLACED with the `Repairing` hole (the empty body must never apply).
        rec.reads.remove(&id.get());
        rec.pending.remove(&op);
        rec.faulty.remove(&op);
        match self.log.get_mut(&op) {
          Some(entry) => entry.body = Body::Repairing(body_checksum),
          None => {
            self.log.insert(
              op,
              LogEntry {
                client,
                request,
                body: Body::Repairing(body_checksum),
              },
            );
          }
        }
      }
      Outcome::StaleCommitted => {
        // The persisted vsr_header says this committed slot's canonical body differs from the WAL's:
        // class it permanently faulty IMMEDIATELY (no retry — the mismatch is authoritative). The
        // existing peer fault-repair path then drops it from the `log` cache (`recover_progress`) and `advance_commit`
        // peer-repairs it on demand; the canonical body is fetched, never re-derived from the stale WAL.
        rec.reads.remove(&id.get());
        rec.pending.remove(&op);
        rec.faulty.insert(op);
      }
      Outcome::Fault => {
        // A fault on this op: spend a retry if any remain, else class it permanently faulty.
        rec.reads.remove(&id.get());
        let budget = rec.pending.get(&op).copied().unwrap_or(0);
        if budget > 0 {
          rec.pending.insert(op, budget - 1);
          let new_id = self.mint_op_id();
          // mint_op_id reborrows self; re-borrow rec to record the new in-flight read.
          if let Some(rec) = self.recover.as_mut() {
            rec.reads.insert(new_id.get(), op);
          }
          wal.submit_read(new_id, OpNumber::with(op));
        } else {
          rec.pending.remove(&op);
          rec.faulty.insert(op);
        }
      }
    }
    self.recover_progress(now, sb);
  }

  /// Handles a superblock completion while `Recovering`/`RecoveringHead` (Phase 2 of `recover`).
  /// A `CheckpointRead` restores the SM + client sessions (moved out of the old synchronous drain);
  /// a `Fault` is retried within the checkpoint budget. Calls `recover_progress` after each.
  pub(crate) fn on_recover_sb_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    done: SuperblockDone,
  ) {
    match done {
      SuperblockDone::CheckpointRead(cr) => {
        // Only react to the checkpoint read WE are awaiting (recover.checkpoint); a foreign/stale
        // completion is ignored, never trusted.
        let is_ours = self
          .recover
          .as_ref()
          .and_then(|r| r.checkpoint)
          .is_some_and(|want| want == cr.id().get());
        if !is_ours {
          return;
        }
        // VERIFY before restore: a `CheckpointRead` matching our read id is NOT yet
        // trustworthy — a corrupted / stale / torn superblock checkpoint could return wrong bytes. The
        // durable root (`sb.state()`) is the authority for which checkpoint this recovery targets, so
        // the read must match it on BOTH the op and the content hash, AND parse cleanly. The state-sync
        // path verifies the id the same way (`on_sync_checkpoint`); the recover path must too, or a bad
        // read would restore the wrong SM/sessions while `commit_min == checkpoint_op` — silent
        // committed-prefix loss, exactly what the checkpoint hash exists to prevent.
        let state = sb.state();
        let id_ok = crate::checkpoint_id(cr.snapshot()) == state.checkpoint_id();
        let op_ok = cr.op() == state.checkpoint_op();
        let decoded = Self::decode_checkpoint(cr.snapshot());
        // The op BOUND inside the envelope must equal the read's advertised op; a mismatch means
        // the bytes are an older checkpoint shipped under a newer op (their hash would then disagree
        // with the durable id too, but we check the bound op explicitly so the binding is load-bearing).
        let bound_ok = decoded
          .as_ref()
          .is_some_and(|(bound_op, _, _)| *bound_op == cr.op());
        let Some((_, sessions, sm_tail)) = decoded.filter(|_| id_ok && op_ok && bound_ok) else {
          // Any mismatch (wrong op / wrong hash / wrong bound op / unparsable) is a FAULT — route to the
          // SAME retry path as `SuperblockDone::Fault`: re-submit within the recover budget (or, on
          // exhaustion, escalate to a peer fetch), do NOT restore, do NOT panic. (If the bytes happened
          // to parse but failed a check, we still discard them.)
          self.retry_recover_checkpoint_read(now, wal, sb);
          return;
        };
        self.sm.restore(sm_tail);
        self.clients = sessions;
        if let Some(rec) = self.recover.as_mut() {
          rec.checkpoint = None;
        }
        self.recover_progress(now, sb);
      }
      SuperblockDone::Fault(id) => {
        let is_ours = self
          .recover
          .as_ref()
          .and_then(|r| r.checkpoint)
          .is_some_and(|want| want == id.get());
        if !is_ours {
          return;
        }
        self.retry_recover_checkpoint_read(now, wal, sb);
      }
      SuperblockDone::Wrote(_) => {
        // A stale durable-root/checkpoint *write* completion from before the crash cannot occur
        // (a fresh recover issues no writes); ignore defensively rather than panic.
      }
    }
  }

  /// Re-submit the recover checkpoint read within the retry budget — or, on EXHAUSTION, escalate to a
  /// PEER FETCH. Shared by the `Fault` arm and the VERIFY-failure path (a `CheckpointRead` whose
  /// op/hash mismatched or that failed to parse) of [`Self::on_recover_sb_done`], so a corrupt/torn/
  /// stale read is retried EXACTLY like a transient fault — never restored, never panicked on.
  ///
  /// While the budget remains, a transient checkpoint-read `Fault`/mismatch is re-submitted (the
  /// common case — the durable root usually names a fully-written snapshot, the root write being
  /// step 2 after the snapshot is durable, so the budget clears). EXHAUSTION means the durable root
  /// names a snapshot that is PERMANENTLY unreadable or permanently inconsistent with the root (wrong
  /// op/hash/unparsable on EVERY read) — bit-rot/torn write in this replica's single durable copy.
  /// We must NOT panic on storage-controlled bytes (a malicious/faulty superblock could otherwise
  /// crash the replica at will). The replica instead FETCHES the checkpoint from a peer via the
  /// state-sync machinery: it arms a FORCED [`SyncState`] targeting its own `checkpoint_op` (a peer
  /// with a checkpoint `>= ours` answers) and broadcasts a `RequestSync`, then marks
  /// `awaiting_peer_checkpoint` so `recover_progress` does NOT complete (the SM is not yet restored)
  /// and `handle_message` accepts the incoming `SyncCheckpoint`. A permanent single-copy corruption
  /// that no peer can serve leaves the replica re-soliciting in this recoverable fault state (never a
  /// panic); it ultimately needs backend redundancy (spec §10) — but a healthy cluster heals it.
  fn retry_recover_checkpoint_read<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
  ) {
    let budget = self
      .recover
      .as_ref()
      .map(|r| r.checkpoint_retries)
      .unwrap_or(0);
    if budget == 0 {
      // Budget exhausted → escalate to a peer fetch instead of panicking.
      self.escalate_checkpoint_to_peer_fetch(now);
      let _ = &mut *wal;
      return;
    }
    let new_id = self.mint_op_id();
    if let Some(rec) = self.recover.as_mut() {
      rec.checkpoint = Some(new_id.get());
      rec.checkpoint_retries = budget - 1;
    }
    sb.submit_read_checkpoint(new_id);
    // No progress to report yet (still awaiting the snapshot); but keep wal in the signature uniform
    // with on_recover_wal_done for the handle_storage call site.
    let _ = &mut *wal;
  }

  /// Escalate a permanently-unreadable own checkpoint to a PEER FETCH. Stops local checkpoint
  /// retries, arms a FORCED state-sync targeting our own `checkpoint_op` (so a peer holding a
  /// checkpoint `>= ours` answers), broadcasts the `RequestSync`, and marks `awaiting_peer_checkpoint`
  /// so the recovery stays open (never completes to Normal with an unrestored SM) and `handle_message`
  /// accepts the answering `SyncCheckpoint`. Idempotent: if already escalated, it just (re-)solicits.
  fn escalate_checkpoint_to_peer_fetch(&mut self, now: Instant) {
    // Stop local checkpoint reads and latch the awaiting-peer state.
    if let Some(rec) = self.recover.as_mut() {
      rec.checkpoint = None;
      rec.awaiting_peer_checkpoint = true;
    }
    // Arm a FORCED sync to our own (corrupt) checkpoint_op: any peer whose durable checkpoint is at or
    // above it can serve a snapshot that subsumes ours. `forced` selects `apply_sync`'s relaxed
    // (never-rewind-the-applied-frontier) assert — correct here, where the synced op `>= checkpoint_op
    // == commit_min`. Only arm if not already syncing (anti-thrash); otherwise the existing solicit
    // stands and we just re-broadcast below.
    if self.sync.is_none() {
      self.nonce = self.nonce.wrapping_add(1);
      self.sync = Some(SyncState {
        target: self.checkpoint_op,
        nonce: self.nonce,
        forced: true,
      });
    }
    // Broadcast the solicitation now; the recover-retry timer (`recover_timeouts`) re-broadcasts on a
    // cadence while `awaiting_peer_checkpoint` holds (the Normal-only `sync_timeouts` does not run
    // during recovery).
    self.send_request_sync(now);
    self.arm_timers(now);
  }

  /// Drop every permanently-faulty committed-band slot's EMPTY placeholder from the dense `log` cache,
  /// turning it into a genuine repair hole — the fault-repair durability invariant, CENTRALIZED here so EVERY
  /// recovery-completion / continuation path enforces it.
  ///
  /// Phase 1 of `recover` seeds each tail slot with an EMPTY body (`Bytes::new()`) and a verified read
  /// fills it; a slot whose read exhausted its retry budget stays in `rec.faulty` STILL HOLDING that
  /// empty placeholder. If it is left in `self.log`, the apply path (`advance_commit`/`commit_op`) finds
  /// `Some({body: EMPTY})` — NOT a hole — and applies the committed op with `&[]` → committed-state
  /// divergence; and a canonical-head adoption (`adopt_log`, RecoveringHead path) would PRESERVE it as a
  /// held op and retire its hole, applying it empty cluster-wide. Dropping it makes the slot a real
  /// repair hole, so `advance_commit` request-repairs the canonical body from a committed-vouching peer
  /// (safety + liveness). Every dropped slot is `> checkpoint_op` (Phase 1 materializes only the offset
  /// tail `(checkpoint_op .. hi]`), so dropping it can never disturb the applied prefix `[1..=
  /// checkpoint_op]`. It also closes the `committed_band_headers` corollary: with the empty slot gone
  /// from `self.log`, a subsequent durable-root/checkpoint write can no longer persist an empty-body
  /// canonical header (`body_checksum == fnv1a_128(&[])`) for it — so no poisoned self-justifying header
  /// can make the empty body MATCH on a later recover.
  ///
  /// A `Body::Repairing` slot is the ONE faulty-band entry this MUST NOT drop: a durable-header
  /// body-faulty read kept the op header-only as a `Repairing` hole (`Outcome::KeepRepairing`), so its
  /// EXISTENCE + canonical `body_checksum` are already preserved and the op must SURVIVE recovery (else
  /// a later view change re-mints its number). It is already a hole (`as_present()` is `None`), so it
  /// CANNOT apply empty — the empty-placeholder hazard above does not apply to it. `Outcome::KeepRepairing`
  /// does not even add the op to `rec.faulty`, so it is normally never iterated here; the explicit
  /// `Repairing` skip is a correct-by-construction backstop (a kept op is NEVER dropped even if a future
  /// path tracks it as faulty). Only genuinely-absent / stale slots (an EMPTY `Present` placeholder, or
  /// no entry) are dropped.
  ///
  /// Idempotent (re-running drops nothing new). Call ONLY once tail verification is settled
  /// (`rec.pending.is_empty()`), so `rec.faulty` is final and a still-in-flight retry cannot resurrect a
  /// just-dropped slot; the `Outcome::Verified` arm re-inserts a body that arrives after a drop, so even
  /// a timer-driven re-read that clears a transient fault is not lost.
  fn drop_faulty_committed_slots(&mut self) {
    let Some(rec) = self.recover.as_ref() else {
      return;
    };
    let faulty: std::vec::Vec<u64> = rec.faulty.iter().copied().collect();
    for op in faulty {
      // KEEP a durable-header body-faulty op held as a `Body::Repairing` hole — its existence is
      // preserved + the body is peer-repaired on demand, so dropping it would LOSE the op. It is already
      // a hole (no bytes to apply empty), so the empty-placeholder safety this fn enforces is moot for
      // it. (Normally unreachable — `Outcome::KeepRepairing` does not add the op to `rec.faulty` — but a
      // correct-by-construction guard so no kept op is ever dropped.)
      if matches!(self.log.get(&op), Some(e) if e.body.is_repairing()) {
        continue;
      }
      // Committed-survival backstop: a faulty committed slot is `> checkpoint_op` (only the offset tail
      // is materialized), so it is NOT covered by the snapshot — survival relies on it being TRACKED for
      // repair. It is in `rec.faulty` here, which `recover_progress` promotes to a `self.repair` hole on
      // the `→ Normal` transition (or drives `RecoveringHead`), so the canonical body is re-fetched; the
      // helper's tracked-for-repair clause witnesses that. Asserted per dropped op.
      self.assert_committed_survives(op, self.checkpoint_op.get());
      self.log.remove(&op);
    }
  }

  /// The SINGLE recovery-completion choke for the faulty-slot drop: run
  /// [`Self::drop_faulty_committed_slots`] EXACTLY once, then DEBUG-ASSERT no permanently-faulty
  /// committed-band slot survived as a populated `self.log` entry into the terminal status. Every
  /// recovery-completion / continuation path (`recover_progress` once tail verification settles, and the
  /// peer-checkpoint-fetch completion in `on_recover_sync_checkpoint`) funnels the drop through here, so
  /// the "guard on some completion paths, missing on a new one" shape (the original empty-body CRITICAL)
  /// fails a debug-assert instead of silently applying a committed op with `&[]`.
  ///
  /// The assert is the regression net: a faulty op left in `self.log` is `Some({body: EMPTY})` (NOT a
  /// hole), which `advance_commit`/`adopt_log` would apply empty cluster-wide. After the drop EVERY op in
  /// `rec.faulty` must be ABSENT from `self.log` (a genuine repair hole `advance_commit` peer-repairs on
  /// demand). It runs while `rec` is still live (`recover` is cleared only AFTER, by the terminal
  /// dispatch), so it can witness the final `rec.faulty` set. Idempotent (the drop is), so re-running on a
  /// later continuation is a no-op + a re-assert.
  fn finalize_recovery(&mut self) {
    self.drop_faulty_committed_slots();
    self.assert_no_faulty_committed_survives();
  }

  /// DEBUG-ASSERT no permanently-faulty committed-band slot survived into the terminal recovery status
  /// as a POPULATED-with-bytes `self.log` entry. A faulty op left as `Some({body: Present(EMPTY)})` is
  /// NOT a hole — `advance_commit`/`adopt_log` would apply it empty cluster-wide (the original
  /// empty-body CRITICAL). After [`Self::finalize_recovery`]'s drop EVERY op in `rec.faulty` MUST be
  /// either ABSENT from `self.log` OR a `Body::Repairing` hole (a kept body-faulty op whose existence is
  /// preserved and whose body is peer-repaired on demand — also not a bytes-bearing entry, so it cannot
  /// apply empty). This fires only if a future edit leaves a faulty op as a `Present` entry, or routes a
  /// completion through here with such a slot still populated. Body is a `debug_assert!`, a no-op in
  /// release (zero cost, like `assert_committed_survives`). Runs while `rec` is still live (the terminal
  /// dispatch clears `recover` only AFTER), so it can witness the final `rec.faulty` set.
  pub(crate) fn assert_no_faulty_committed_survives(&self) {
    #[cfg(debug_assertions)]
    if let Some(rec) = self.recover.as_ref() {
      for &op in &rec.faulty {
        debug_assert!(
          !matches!(self.log.get(&op), Some(e) if e.body.is_present()),
          "faulty committed slot {op} survived into the terminal recovery status as a populated \
           Present log entry (would be applied empty) — the drop choke was bypassed"
        );
      }
    }
  }

  /// The recovery transition decider (Phase 2), called after every recovery read completion. Stays
  /// `Recovering` while any tail read or the checkpoint read is still outstanding; once all reads are
  /// satisfied it transitions to `Normal` (tail consistent / non-head holes peer-repaired) or
  /// `RecoveringHead` (the HEAD slot is permanently faulty — it cannot trust its head and must learn
  /// the canonical head from a peer).
  ///
  /// A non-head permanently-faulty committed slot is repaired peer-to-peer: it is necessarily
  /// ABOVE the applied frontier (`commit_min == checkpoint_op`; the restored SM already holds
  /// `[1..=checkpoint_op]`, so a faulty `op <= checkpoint_op` is never re-applied and does not block
  /// the apply path), so the replica safely returns to `Normal` and re-fetches the op on demand via
  /// `RequestPrepare` when its commit reaches it — HOLDING the commit below the hole until then. This
  /// is what lets a recovering replica with a rotted committed slot rejoin without losing the op.
  fn recover_progress<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    let Some(rec) = self.recover.as_ref() else {
      return;
    };
    // Still draining the TAIL reads? Keep the recover_retry timer armed (via arm_timers for the current
    // Recovering status) so an owner re-submits any dropped/slow read. While a tail read is in flight
    // `rec.faulty` is not yet final, so we must NOT drop yet (a retry could resurrect the slot).
    if !rec.pending.is_empty() {
      self.arm_timers(now);
      return;
    }
    // Tail verification is settled (no tail read in flight) → `rec.faulty` is FINAL. Drop every faulty
    // committed-band slot's empty placeholder NOW, BEFORE the checkpoint/peer continuation early-return
    // below: this is the CENTRALIZED enforcement so the awaiting-peer-checkpoint path (which stays
    // Recovering and later completes via `on_recover_sync_checkpoint` → `apply_sync`, NOT through the
    // finalize tail of this function) cannot leave an empty slot in `self.log` to be applied empty. The
    // drop is idempotent, so re-running it on the finalize paths below is harmless. Previously the
    // drop lived only at the finalize tail, BELOW this early-return, so the peer-fetch escalation
    // skipped it. Routed through the `finalize_recovery` choke, which also
    // debug-asserts no faulty slot survives into the terminal status.
    self.finalize_recovery();
    let Some(rec) = self.recover.as_ref() else {
      return; // (defensive; the helper never clears `recover`)
    };
    // The checkpoint snapshot not yet restored, OR awaiting a PEER checkpoint after our own read
    // exhausted. Stay Recovering and re-arm: an owner re-submits any dropped/slow checkpoint read
    // AND re-solicits the peer checkpoint. Crucially, `awaiting_peer_checkpoint` blocks completion: we
    // must NEVER reach Normal with the SM unrestored (`commit_min == checkpoint_op` would then be a
    // silent committed-prefix loss) — recovery completes only once a verified `SyncCheckpoint` restores
    // the SM (via `on_recover_sync_checkpoint` → `apply_sync`), which drops the faulty slots again
    // (belt-and-suspenders) before applying.
    if rec.checkpoint.is_some() || rec.awaiting_peer_checkpoint {
      self.arm_timers(now);
      return;
    }
    if rec.faulty.is_empty() {
      // Tail consistent: every body is present + checksum-verified → settle the terminal status. A
      // recovered backup resumes Normal (it waits for the primary's Prepare/Commit to re-announce
      // commit); a replica that was the established PRIMARY (or crashed mid-view-change) does NOT
      // resume as that primary — `complete_recovery` abdicates / re-drives the view change instead.
      self.complete_recovery(now, sb);
      return;
    }
    // Some slot read back permanently faulty (the per-slot retry budget — and the on-disk recover_retry
    // re-reads — were exhausted, so it cannot be cleared from this replica's own disk). Its empty
    // placeholder was already dropped from `self.log` by `drop_faulty_committed_slots` above, so it is a
    // genuine repair hole on every path below.
    let head = self.op.get();
    let faulty: std::vec::Vec<u64> = rec.faulty.iter().copied().collect();
    if faulty.contains(&head) {
      // The head cannot be trusted → RecoveringHead: do not participate. Solicit the canonical head
      // from a peer (the primary answers with a `RecoveryResponse`; a `StartView` also adopts), and
      // keep `recover` so the head stays flagged until adoption returns to Normal. We do NOT
      // pre-register the non-head faulty slots as repair holes: a faulty slot above the
      // checkpoint may be UNCOMMITTED (at recovery we only know `commit_min == checkpoint_op`), and a
      // pre-registered hole for an uncommitted op can NEVER be filled due to the repair restrictions
      // (a peer serves only `op <= commit`; `fill_repair` rejects `commit < op`), wedging the
      // `on_request` guard into a client-serving deadlock. A COMMITTED faulty slot is instead requested
      // ON DEMAND by `advance_commit` once commit reaches it (which only happens once it is committed);
      // an UNCOMMITTED one is simply truncated away if a later view change rewinds the tail.
      self.status = Status::RecoveringHead;
      self.arm_timers(now);
      self.send_recovery(now);
      return;
    }
    // Only non-head committed slots are faulty. We do NOT pre-register them as repair holes here
    //: see the RecoveringHead branch above — a faulty slot above the checkpoint may be
    // uncommitted, and pre-registering it would be an unfillable hole that deadlocks `on_request`.
    // `advance_commit` requests each missing op ON DEMAND when commit reaches it (only committed ops
    // are ever reached); the dropped empty placeholder is never resurrected (the slot was removed from
    // `self.log` above, so the apply path treats it as a hole until a verified Prepare fills it).
    // Settle the terminal status: a recovered primary abdicates / a mid-view-change recovery re-drives
    // (`complete_recovery`); only a replica that actually resumes Normal can serve the hole solicitation
    // now (a Recovering/ViewChange replica drops all messages, so it could not receive the repair
    // `Prepare` — the repair_retry timer re-solicits once it next resumes Normal).
    self.complete_recovery(now, sb);
    if self.status.is_normal() {
      // Solicit every hole now (the timer also re-solicits on a cadence until each is filled).
      let ops: std::vec::Vec<u64> = self.repair.iter().copied().collect();
      for op in ops {
        self.send_request_prepare(op);
      }
    }
  }

  /// Settle the terminal status of a recovered replica once its tail is resolved — a faithful port of
  /// TigerBeetle `replica.zig` open()'s participation decision. A replica that crashed AS the
  /// established primary has NO in-memory pipeline (`inflight` is empty) and its session table is only
  /// at `checkpoint_op`, so it MUST NOT resume as that primary: resuming Normal would freeze commit at
  /// `checkpoint_op` (every re-acked PrepareOk drops on the empty `inflight`) and could re-execute a
  /// client request retried in `(checkpoint_op, op]` (the session table no longer remembers it). So:
  ///
  /// - `log_view < view`  → crashed MID-VIEW-CHANGE (the durable view advanced but the new log was not
  ///   yet installed): re-drive `VC(view)` so the in-progress change completes.
  /// - was Normal AS the PRIMARY (`log_view == view` and we lead `view`) → ABDICATE to `view + 1`: the
  ///   clean view change rebuilds the pipeline (DVC collection → `start_view_as_new_primary`), and
  ///   `on_request` returns early while status != Normal, closing the double-execute hazard.
  /// - otherwise (a BACKUP, or a SOLO replica that is its own primary) → resume Normal.
  ///
  /// SOLO (`replica_count == 1`): a solo replica is always its own primary and CANNOT view-change (no
  /// peer quorum) — abdicating would deadlock, so it resumes Normal. But a solo primary commits via the
  /// `inflight` pipeline (quorum 1: the own append-done vote alone commits), so an empty `inflight`
  /// would stall its recovered tail `(commit_min, op]` — ops it had already committed pre-crash. We
  /// therefore REBUILD that pipeline (own-vote set, mirroring `start_view_as_new_primary`) and drive
  /// `try_commit`, so the solo primary re-commits its tail and makes progress immediately.
  fn complete_recovery<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    self.recover = None;
    if self.log_view.get() < self.view.get() {
      // Crashed mid-view-change (durable view advanced, new log not yet installed): re-drive VC(view).
      self.enter_view_change_from_recovery(now, sb, self.view);
    } else if self.config.replica_count() > 1 && self.config.is_primary(self.view) {
      // Was Normal as the PRIMARY → abdicate: a restarted primary has no in-memory pipeline and a
      // checkpoint-only session table, so it forces a clean view change to view + 1 rather than
      // resuming as the established primary.
      self.enter_view_change_from_recovery(now, sb, self.view.next());
    } else {
      // Backup, or a SOLO replica (its own primary, no quorum to view-change) → resume Normal.
      self.status = Status::Normal;
      if self.config.replica_count() == 1 {
        // Solo: rebuild the pipeline for the recovered tail so `try_commit` can re-commit ops the
        // solo primary had already committed pre-crash (an empty `inflight` would stall them — solo
        // commits via the own-vote quorum of 1). Mirror `start_view_as_new_primary`'s rebuild.
        self.inflight.clear();
        let own = 1u64 << self.config.replica().get();
        for op in (self.commit_min.get() + 1)..=self.op.get() {
          self.inflight.insert(
            op,
            Inflight {
              oks: own,
              committed: false,
            },
          );
        }
        self.arm_timers(now);
        self.try_commit(now, sb);
      } else {
        self.arm_timers(now);
      }
    }
  }

  /// Recover-retry timer: re-submit every still-unsatisfied tail read (and the checkpoint read), so
  /// the loop terminates even if a real async driver dropped a completion or a transient fault only
  /// clears on a later read. Resets each unsatisfied op to exactly ONE fresh outstanding read with a
  /// full budget (dropping its stale `reads` entries), avoiding duplicate-completion ambiguity.
  pub(crate) fn recover_timeouts<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
  ) {
    if self.timers.recover_retry.is_none_or(|d| d > now) {
      return;
    }
    // Collect the ops needing a (re)read: those still pending OR classed faulty. (Snapshot the set
    // first so we can mutate `recover` while iterating.)
    let (ops, want_checkpoint, awaiting_peer) = match self.recover.as_ref() {
      Some(rec) => {
        let mut ops: std::vec::Vec<u64> = rec.pending.keys().copied().collect();
        ops.extend(rec.faulty.iter().copied());
        ops.sort_unstable();
        ops.dedup();
        (ops, rec.checkpoint, rec.awaiting_peer_checkpoint)
      }
      None => (std::vec::Vec::new(), None, false),
    };
    // Peer-fetch: if our own checkpoint read exhausted and we are awaiting a PEER `SyncCheckpoint`,
    // re-broadcast the `RequestSync` on this cadence (the Normal-only `sync_timeouts` does not run
    // while Recovering). A peer holding a checkpoint `>= ours` answers; until then we stay here.
    if awaiting_peer && self.sync.is_some() {
      self.send_request_sync(now);
    }
    for op in ops {
      let new_id = self.mint_op_id();
      if let Some(rec) = self.recover.as_mut() {
        // Drop any prior in-flight read entries for this op (a dropped/duplicate completion now
        // resolves to nothing), then register exactly one fresh read with a full budget.
        rec.reads.retain(|_, &mut o| o != op);
        rec.reads.insert(new_id.get(), op);
        rec.faulty.remove(&op);
        rec.pending.insert(op, RECOVER_READ_RETRIES);
      }
      wal.submit_read(new_id, OpNumber::with(op));
    }
    // Re-issue the checkpoint read if it is still outstanding and its prior completion was dropped.
    if want_checkpoint.is_some() {
      let new_id = self.mint_op_id();
      if let Some(rec) = self.recover.as_mut() {
        rec.checkpoint = Some(new_id.get());
        rec.checkpoint_retries = RECOVER_READ_RETRIES;
      }
      sb.submit_read_checkpoint(new_id);
    }
    // Re-arm so we keep retrying until the loop completes.
    self.timers.recover_retry = Some(now + RECOVER_READ_RETRANSMIT);
  }

  /// RecoveringHead solicitation timer: re-broadcast the `Recovery` request (and re-arm) until a
  /// peer's `RecoveryResponse`/`StartView` re-establishes the head and adoption returns us to Normal.
  pub(crate) fn recover_head_timeouts(&mut self, now: Instant) {
    if self.timers.recover_head.is_some_and(|d| d <= now) {
      self.send_recovery(now); // re-broadcasts and re-arms recover_head
    }
  }

  /// Receive a `SyncCheckpoint` while RECOVERING and AWAITING A PEER CHECKPOINT — the escalation
  /// path for a replica whose OWN durable checkpoint snapshot read back permanently unreadable/
  /// inconsistent ([`Self::retry_recover_checkpoint_read`] exhaustion). It cannot restore its SM from
  /// disk, so it solicited a peer; this verifies and applies the answer, completing recovery.
  ///
  /// Verification (no SM mutation until ALL pass): an outstanding forced `sync` with a matching nonce;
  /// the peer is at least as advanced as our corrupt checkpoint (`checkpoint_op >= self.checkpoint_op`,
  /// so its snapshot subsumes ours and never rewinds the applied frontier — `commit_min ==
  /// checkpoint_op` here); the LOAD-BEARING self-consistency integrity gate `checkpoint_id(snapshot)
  /// == checkpoint_id`; and a clean decode. Any failure REJECTS the message (no panic, no restore) and
  /// leaves us awaiting — the recover-retry timer re-solicits and another peer answers.
  ///
  /// On full success it hands off to the SHARED [`Self::apply_sync`] (restore SM + sessions, advance to
  /// the synced point, durably RE-PERSIST so a re-crash recovers cleanly at the synced point, not the
  /// corrupt one): it abandons local recovery (`recover = None`) and flips to `Normal` FIRST so the
  /// re-persist's superblock completions route through the ordinary `on_sb_done` (which clears the
  /// sync + counts a forced state-sync on the root write), exactly like a Normal state-sync — recovery
  /// is thereby complete the instant the synced checkpoint is durable.
  pub(crate) fn on_recover_sync_checkpoint<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: crate::SyncCheckpoint,
  ) {
    debug_assert!(self.status.is_recovering() && self.awaiting_peer_checkpoint());
    let Some(s) = self.sync else {
      return; // no sync outstanding — ignore (should not happen while awaiting, but be defensive).
    };
    if m.nonce() != s.nonce {
      return; // a reply to a prior solicitation / forged — not fresh.
    }
    if m.checkpoint_op().get() < self.checkpoint_op.get() {
      return; // does not even reach our (corrupt) checkpoint — cannot subsume it; ignore.
    }
    // The load-bearing integrity gate: never restore a snapshot whose bytes do not hash to the
    // advertised id (corrupt / forged / torn). Verified BEFORE any mutation; reject + keep awaiting.
    if crate::checkpoint_id(m.snapshot()) != m.checkpoint_id() {
      return;
    }
    // Decode must succeed before we commit to applying (apply_sync also decodes, but verifying here
    // keeps the irreversible status flip below from ever stranding us Normal with an unrestored SM).
    // The op BOUND into the snapshot must equal the advertised `checkpoint_op` — a faulty peer
    // shipping stale bytes under an overstated op would otherwise advance our frontier past the
    // snapshot's real content. Verified HERE too (not only in `apply_sync`) so the Normal flip below
    // never strands us with an unrestored SM on a bind mismatch.
    match Self::decode_checkpoint(m.snapshot()) {
      Some((bound_op, _, _)) if bound_op == m.checkpoint_op() => {}
      _ => return, // unparsable, or the bound op disagrees with the advertised op — reject, keep awaiting.
    }
    // CENTRALIZED faulty-slot drop, via the `finalize_recovery` choke: before we
    // abandon local recovery (`recover = None` discards `rec.faulty`) and `apply_sync` (whose held-tail
    // retain KEEPS `self.log` entries above the synced checkpoint), drop every permanently-faulty
    // committed-band slot's EMPTY placeholder. Otherwise such a slot survives `apply_sync` as
    // `Some({body: EMPTY})` and a later `advance_commit` applies the committed op with `&[]` —
    // committed-state divergence. This is the SAME invariant `recover_progress` enforces; the
    // peer-checkpoint-fetch path completes HERE (not through `recover_progress`'s finalize tail), so it
    // routes the drop through the SAME choke (which also debug-asserts no faulty slot survives). After the
    // drop the faulty slot is a genuine repair hole `advance_commit` peer-repairs on demand.
    // (`recover_progress` already dropped these once tail verification settled, so this is normally a
    // no-op; it is belt-and-suspenders for any path that reaches here with a faulty slot still in
    // `self.log`.)
    self.finalize_recovery();
    // Fully verified → abandon local recovery and apply via the shared state-sync core. Flip to Normal
    // FIRST so the re-persist completions route through the ordinary `on_sb_done` (which clears `sync` +
    // counts a forced state-sync on the root write), then `apply_sync` STAGES the durable re-persist.
    self.recover = None;
    self.status = Status::Normal;
    self.apply_sync(now, sb, &m);
    // EAGER INSTALL: the Normal state-sync path DEFERS the destructive install to the
    // durable root (so a view change cannot strand a pruned-but-stale band), but the RECOVERY peer-fetch
    // path must NOT reach Normal with an UNRESTORED SM — its own checkpoint snapshot is permanently
    // unreadable, so until the restore lands the SM is indeterminate, and a Normal replica must hold a
    // valid SM (the `escalate_checkpoint_to_peer_fetch` invariant: "never completes to Normal with an
    // unrestored SM"). So install IMMEDIATELY here — restore the SM/sessions + advance/prune at flip
    // time — while the staged re-persist still goes durable in the background. The `on_sb_done` root
    // completion then finds `pending_install` already taken (no second install) and runs only the sync
    // completion bookkeeping (clear `sync`, count the forced sync, re-arm). This path is not subject to
    // deferred-install wedge: a `Recovering` replica is not a Normal replica advertising a checkpoint, and the
    // restore-at-flip keeps the long-standing recovery safety contract intact.
    if let Some(install) = self.pending_install.take() {
      self.install_sync(wal, install);
    }
    // STEP DOWN if we are the primary (async-superblock path), via the single
    // `abdicate_if_primary` chokepoint. This peer-checkpoint fetch RESTORED our SM from a
    // peer snapshot and KEPT our retained tail `(commit_min .. op]`, but — exactly like a state-sync on a
    // Normal primary, and like a restarted primary in `complete_recovery` — it left `inflight` (the
    // commit pipeline) CLEARED while we remain the primary of our view. A Normal primary with a torn-down
    // pipeline wedges: `try_commit` cannot advance past `commit_min` (the missing inflight entry at
    // `commit_min + 1` breaks the in-order loop; re-acked PrepareOks drop on the empty pipeline). So a
    // multi-replica primary ABDICATES (the chokepoint flags the deferred forfeit + bootstraps the
    // serviceable `svc_message` wake so the next `primary_timeouts` re-proposes `view + 1` and a
    // caught-up replica leads; every replica already holds the committed tail durably). The SM is
    // restored (we needed the snapshot to recover at all), so we abdicate AFTER applying — unlike
    // `on_sync_checkpoint`, where a Normal primary's SM is already valid and we step down without
    // applying. SOLO is a no-op (no peers ⇒ this peer-fetch path is unreachable; `complete_recovery`
    // enforces the same abdication for a disk-recovered primary).
    self.abdicate_if_primary(now);
  }

  /// Higher-view rule: a newer primary already exists (we saw its Prepare/Commit/PrepareOk) and we
  /// are merely stale. Fetch its log via GetView; do NOT broadcast a StartViewChange. If catch-up
  /// stalls, `view_change_status` escalates us to a real, self-driven change.
  pub(crate) fn catch_up_to_view(&mut self, now: Instant, view: View) {
    assert!(
      view.get() > self.view.get(),
      "catch-up target must be strictly newer than our view"
    );
    self.view = view;
    self.status = Status::ViewChange;
    self.svc_target = view;
    // Tear down ALL old-generation in-flight state in one place: SVC bits, in-flight
    // appends, peer-checkpoint reports, in-flight checkpoint, in-flight sync + its deferred install
    // (cancelled together — durable-before-install leaves the old state intact), and the
    // forfeit sub-state. See [`Self::reset_for_view_transition`] for the per-field rationale.
    self.reset_for_view_transition();
    // ViewChange ENTRY (the higher-view catch-up): install a fresh collection with `catching_up = true`
    // — this entry sends GetView, not SVC/DVC. (`is_some() == is_view_change()` coupling.)
    self.view_change = Some(ViewChangeCollection::entering(true));
    // The primary pipeline + backup reorder buffer are dropped on this catch-up (kept OUT of the shared
    // reset because `adopt_canonical_head` preserves a live primary pipeline).
    self.inflight.clear();
    self.buffer.clear();
    // GetView is a catch-up probe, not a vote; no superblock write needed. Clear any prior-view
    // pending_sb (supersession): a stale completion from the prior view must not fire. (This is the
    // distinguishing `pending_sb` action — the two durable-view-writing entries overwrite it instead.)
    self.pending_sb = None;
    self.arm_timers(now);
    self.send_get_view(now);
  }

  pub(crate) fn send_get_view(&mut self, now: Instant) {
    let primary = self.config.primary(self.view);
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(primary)),
      Message::GetView(crate::GetView::new(
        self.view,
        self.config.replica(),
        self.nonce,
      )),
    ));
    self.timers.get_view_message = Some(now + VC_MESSAGE_RETRANSMIT);
  }

  /// Broadcast a `Recovery` solicitation (RecoveringHead) and re-arm the solicitation timer. The
  /// stable `self.nonce` tags the request so a `RecoveryResponse` to THIS replica's recovery is
  /// distinguished from unrelated traffic and matched across retries.
  fn send_recovery(&mut self, now: Instant) {
    self.emit(Outgoing::new(
      Recipient::Backups,
      Message::Recovery(crate::Recovery::new(self.config.replica(), self.nonce)),
    ));
    self.timers.recover_head = Some(now + RECOVER_HEAD_SOLICIT);
  }

  pub(crate) fn on_get_view(&mut self, _now: Instant, m: crate::GetView) {
    // Only a Normal primary at the requested view (or higher) can answer authoritatively — AND only
    // once its view is DURABLE: `participates_as_primary` adds the `pending_sb.is_none()`
    // clause, so a primary that just adopted its view but has not yet persisted it does NOT hand out a
    // `StartView` for that not-yet-recoverable view (it would, on crash, regress out of a view it had
    // already vouched for to a soliciting peer). The deferred `start_view_participate` broadcasts the
    // StartView once the view is durable, and a later `GetView` is then answered normally.
    if self.participates_as_primary() && self.view.get() >= m.view().get() {
      self.emit(Outgoing::new(
        Recipient::To(Peer::Replica(m.replica())),
        Message::StartView(crate::StartView::new(
          self.view,
          self.op,
          self.commit_min,
          self.config.replica(),
          self.log_entries(),
        )),
      ));
    }
  }

  /// Answer a peer's `Recovery` solicitation (it is in `RecoveringHead`, soliciting the canonical
  /// head). Only a `Normal` replica answers — a recovering/view-changing replica has no stable head
  /// to report. The primary answers authoritatively with its canonical log + head + commit (the
  /// recovery-handshake equivalent of a `StartView`); a Normal backup answers with only its view +
  /// echoed nonce (empty log), which still lets the soliciting replica learn the current generation
  /// and re-target the primary. The `nonce` is echoed for the requester's freshness check.
  pub(crate) fn on_recovery(&mut self, _now: Instant, m: crate::Recovery) {
    if !self.status.is_normal() {
      return; // only a Normal replica has a trustworthy view/head to report
    }
    // Durable-view-before-participate: while a view-change/adoption superblock write is
    // pending, status is Normal but the current view is NOT yet durable. A primary answering here with
    // its canonical `(op, commit, log)` — and even a Normal backup answering with its (non-durable)
    // view + echoed nonce — reports authority in a view a crash could regress out of, the same
    // cross-view hazard `on_get_view`'s StartView gate closes. Gate the WHOLE handler: a recovering
    // peer simply re-solicits (its `recover_head` timer retransmits the `Recovery`) until our view is
    // durable, at which point we answer normally. (Backups have no canonical head anyway; the strict
    // gate keeps both branches from reporting a not-yet-recoverable view.)
    if self.pending_sb.is_some() {
      return;
    }
    if m.replica().get() >= self.config.replica_count() {
      return; // ignore malformed/out-of-range replica id
    }
    let (op, commit, log) = if self.is_primary() {
      (self.op, self.commit_min, self.log_entries())
    } else {
      // A backup cannot hand out a canonical head; it reports only its view (+ echoed nonce).
      (OpNumber::new(), OpNumber::new(), std::vec::Vec::new())
    };
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(m.replica())),
      Message::RecoveryResponse(crate::RecoveryResponse::new(
        self.view,
        op,
        commit,
        self.config.replica(),
        m.nonce(),
        log,
      )),
    ));
  }

  /// Handle a `RecoveryResponse` to our own `Recovery` solicitation. Only meaningful while
  /// `RecoveringHead` (awaiting the canonical head): in any other status it is a stale completion
  /// from a prior recovery and is ignored. A response is adopted ONLY if (a) its nonce matches our
  /// outstanding solicitation (freshness — a stale response from an earlier attempt is rejected) and
  /// (b) it is from the responder's view's primary (only the primary hands out a canonical head). A
  /// backup's response (empty log) merely confirms a view; the `recover_head` timer re-solicits.
  pub(crate) fn on_recovery_response<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    m: crate::RecoveryResponse,
  ) {
    if !self.status.is_recovering_head() {
      return; // not awaiting a head (already Normal, or never solicited) — ignore the stale reply
    }
    if m.nonce() != self.nonce {
      return; // a response to a prior solicitation (or forged) — not fresh, ignore
    }
    if m.view().get() < self.view.get() {
      return; // a stale-view response cannot re-establish our head
    }
    if m.replica() != self.config.primary(m.view()) {
      // A non-primary response (empty log) only confirms the current generation; we cannot adopt a
      // head from it. Stay RecoveringHead; the recover_head timer keeps soliciting until the
      // primary answers (or a StartView arrives).
      return;
    }
    self.adopt_canonical_head(now, sb, m.view(), m.op(), m.commit(), m.log_slice());
    self.truncate_wal_above_adopted_head(wal);
  }
}

#[cfg(test)]
mod verdict_tests {
  use super::{SlotVerdict, classify_committed_slot};
  use crate::{ClientId, RequestNumber};

  // The slot's own identity (what the read returned), and a DIFFERENT identity (a stale slot's, or a
  // same-payload-different-client slot's). The third tuple field is the body_checksum (`u128`).
  const SLOT: (ClientId, RequestNumber, u128) = (ClientId::new(7), RequestNumber::with(3), 0xABCD);
  // Differs in EVERY field — a header-mismatch under any of client/request/body is StaleCommitted; one
  // representative is enough since the verdict compares the tuples for equality as a whole.
  const OTHER: (ClientId, RequestNumber, u128) = (ClientId::new(9), RequestNumber::with(4), 0x1234);

  /// FREEZE the totality of `classify_committed_slot` as a test contract: enumerate the FULL
  /// cross-product {header present / absent} × {identity matches / mismatches} × {op <= / > durable_commit}
  /// × {slot_view < / >= durable_log_view} and assert the verdict for EVERY cell, documenting WHY. The
  /// function is total ONLY by arm ordering; this test fails a future reorder that re-opens a
  /// stale-committed-body hole (the worst class) — a unit failure, not a rare schedule.
  #[test]
  fn classify_committed_slot_is_total_over_the_staleness_space() {
    // Fixed reference frontiers; we move `op`/`slot_view` around them to flip the C and V dimensions.
    const DURABLE_COMMIT: u64 = 100;
    const DURABLE_LOG_VIEW: u64 = 5;
    // op <= durable_commit (C = true, KNOWN-COMMITTED) vs op > durable_commit (C = false, above-band).
    let op_committed = 100; // == durable_commit ⇒ known-committed
    let op_above = 101; // > durable_commit ⇒ above the committed frontier
    // slot_view < durable_log_view (V = true, SUPERSEDED) vs >= (V = false, current generation). The
    // `>=` arm must hold at BOTH strictly-greater and EQUAL, so we test the `==` boundary explicitly.
    let view_superseded = 4; // < 5 ⇒ an abandoned earlier-view proposal
    let view_current_eq = 5; // == 5 ⇒ current generation (boundary of the `>=` predicate)
    let view_current_gt = 6; // > 5 ⇒ current generation

    let verdict = |canonical, op, slot_view| {
      classify_committed_slot(
        SLOT,
        canonical,
        op,
        slot_view,
        DURABLE_COMMIT,
        DURABLE_LOG_VIEW,
      )
    };

    // ── HEADER PRESENT + identity MATCHES (canonical == slot) ────────────────────────────────────────
    // a locally-held canonical committed op is KEPT — its own sparse header vouches it, so this
    // replica's only surviving copy is not destroyed. The match VERDICT is independent of op/view: a held
    // committed op above a LOWER header-less hole is still Verified. All 4 (C × V) cells → Verified.
    for &op in &[op_committed, op_above] {
      for &v in &[view_superseded, view_current_gt] {
        assert_eq!(
          verdict(Some(SLOT), op, v),
          SlotVerdict::Verified,
          "header present + identity match is ALWAYS Verified: op={op}, view={v}"
        );
      }
    }

    // ── HEADER PRESENT + identity MISMATCHES (canonical != slot) ─────────────────────────────────────
    // the persisted `vsr_headers` say a different body, OR the same body under a different
    // client/request — a superseded/stale slot. The mismatch VERDICT is independent of op/view:
    // a header that disagrees is authoritative. All 4 (C × V) cells → StaleCommitted.
    for &op in &[op_committed, op_above] {
      for &v in &[view_superseded, view_current_gt] {
        assert_eq!(
          verdict(Some(OTHER), op, v),
          SlotVerdict::StaleCommitted,
          "header present + identity mismatch is ALWAYS StaleCommitted: op={op}, view={v}"
        );
      }
    }

    // ── HEADER ABSENT + KNOWN-COMMITTED (op <= durable_commit) ───────────────────────────────────────
    // the sparse set has one header per committed-band op the writer HELD, so NO header ⇒ the
    // writer did not hold this committed op (a genuine hole / stale leftover the headers do not vouch).
    // The local self-verifying body is UNPROVEN and must be peer-repaired. The VERDICT is independent of
    // the view (the committed-band arm wins before the view is even consulted). Both V cells →
    // StaleCommitted.
    for &v in &[view_superseded, view_current_gt] {
      assert_eq!(
        verdict(None, op_committed, v),
        SlotVerdict::StaleCommitted,
        "header absent + known-committed is StaleCommitted: view={v}"
      );
    }

    // ── HEADER ABSENT + ABOVE-commit (op > durable_commit) + SUPERSEDED view (slot_view < log_view) ───
    // An above-band tail op from a generation we have already superseded — we advanced
    // `log_view` past its view, so its body is an abandoned earlier-view proposal. → StaleCommitted.
    assert_eq!(
      verdict(None, op_above, view_superseded),
      SlotVerdict::StaleCommitted,
      "header absent + above-commit + superseded view is StaleCommitted"
    );

    // ── HEADER ABSENT + ABOVE-commit (op > durable_commit) + CURRENT-generation view (>= log_view) ────
    // A current uncommitted tail op (no canonical header, not superseded): kept to be re-acked. → Verified.
    // Tested at BOTH the `==` boundary and strictly-greater so the `>=` predicate is pinned.
    for &v in &[view_current_eq, view_current_gt] {
      assert_eq!(
        verdict(None, op_above, v),
        SlotVerdict::Verified,
        "header absent + above-commit + current-generation view is Verified (current tail): view={v}"
      );
    }

    // ── Boundary corollary: the KNOWN-COMMITTED predicate is `op <= durable_commit` (INCLUSIVE). An op
    // EXACTLY AT durable_commit with no header is StaleCommitted (covered above via op_committed == 100);
    // the very next op (durable_commit + 1) with no header + current view is Verified (op_above above).
    // This pins the `<=` boundary so an off-by-one to `<` cannot silently trust a not-held committed op.
    assert_eq!(
      verdict(None, DURABLE_COMMIT, view_current_gt),
      SlotVerdict::StaleCommitted,
      "op == durable_commit (no header) is known-committed ⇒ StaleCommitted (the `<=` boundary)"
    );
    assert_eq!(
      verdict(None, DURABLE_COMMIT + 1, view_current_gt),
      SlotVerdict::Verified,
      "op == durable_commit + 1 (no header, current view) is above-band ⇒ Verified"
    );
  }
}

use super::*;

/// Why a NEW op cannot be minted right now — the shared, op-content-INDEPENDENT admission verdict that
/// fences BOTH the client-request path ([`Endpoint::on_request`]) and the reconfiguration-proposal path
/// ([`Endpoint::propose_membership`](crate::Endpoint::propose_membership)). It enumerates EXACTLY the
/// preconditions `on_request` checks before minting that do not depend on the client/session identity
/// (the session dedup + the session-table cap stay in `on_request`, being client-op-specific). Every
/// variant is TRANSIENT — it self-releases as the cluster makes progress — so a proposer maps it to a
/// RETRYABLE error rather than treating it as a permanent rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NewOpReject {
  /// Not a `Normal` primary (a backup, or mid-view-change/recovery) — only a `Normal` primary mints.
  NotNormalPrimary,
  /// A view-CHANGING durable-view write is pending OR a state-sync / checkpoint-persist is in flight:
  /// minting now would advertise an op in a view this node may roll back, or reuse an op number a
  /// `self.op` reset is about to free. The whole `pending_sb` / `sync` / `pending_checkpoint` guard.
  Busy,
  /// A forfeit/step-down is flagged (`pending_forfeit`): this primary has decided to abdicate and reset
  /// `self.op` below a value the cluster moved past, so a new op would reuse a committed op number.
  SteppingDown,
  /// The committed prefix is not yet applied (`commit_max > commit_min`, or a repair hole): a fresh op
  /// on a stale session table could double-execute a retry once the gap fills. Catch up first.
  CommitGap,
  /// The accepted-but-uncommitted pipeline `(commit_min, op]` is at [`MAX_PIPELINE`] depth.
  PipelineFull,
  /// Minting the next op would overflow the bounded WAL ring OR push the header-only view-change-carrier
  /// band past its frame-fit depth ([`Endpoint::band_at_capacity`]) — physical back-pressure.
  AtCapacity,
}

impl<S: StateMachine, R: Reconfig> Endpoint<S, R> {
  pub(crate) fn primary_timeouts<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
    // Deferred forfeit: a primary that hit the force-sync strand
    // ([`Self::maybe_force_sync`]) flagged a step-down rather than reset its `op` (which would let it
    // reuse op numbers in this view). Act on it FIRST, on EVERY primary tick while the flag is set —
    // and crucially do NOT clear it one-shot. A one-shot forfeit broadcasts a SINGLE
    // StartViewChange and then resumes heartbeating; if that lone SVC is dropped/partitioned the
    // primary keeps heartbeating, every backup keeps resetting its `primary_idle` (so none starts its
    // own view change), and the SVC retransmit timer is not serviced while Normal — the stuck primary
    // WEDGES the cluster below the unrepairable hole. Instead we keep forfeiting until the view
    // actually changes:
    //   1. RE-PROPOSE the next view on the SVC RETRANSMIT CADENCE — `propose_next_view` is idempotent
    //      at `view+1` (it only resets the SVC collection when raising the target, never escalates to
    //      `view+2,+3` while we stay Normal-primary), so this just RE-BROADCASTS the
    //      `StartViewChange{view+1}` under loss. It is gated on the `svc_message` timer (exactly as
    //      `view_change_timeouts` re-broadcasts a backup's SVC), NOT fired every tick: an unconditional
    //      per-tick re-broadcast is an unbounded StartViewChange STORM that, in the nanosecond-clock
    //      simulator, floods the network and pins the virtual clock to sub-millisecond steps — starving
    //      the LIVE view's primary's 50ms Commit heartbeat so a stale-view holdout never learns the new
    //      view to catch up, livelocking the cluster under an adversarial schedule. `propose_next_view` → `join_svc`
    //      re-arms `svc_message`, so this self-paces; the `is_none_or` also fires once if the timer is
    //      somehow unset (it never is while latched — the transition handlers clear both together), so a
    //      forfeit can never silently stop re-proposing.
    //   2. RETIRE the commit heartbeat + prepare retransmit (clear both timers, then the early `return`
    //      skips the arming code below), so backups STOP hearing this primary; their `primary_idle` fires
    //      and they JOIN the SVC for `view+1` → an SVC quorum forms → the view changes (a caught-up replica
    //      leads). RETIRING — not merely skipping — `commit`/`prepare` is load-bearing for a deadline-driven
    //      driver: a real driver advances virtual time to `poll_timeout()` (the EARLIEST armed
    //      deadline) before each `handle_timeout`, so a still-armed-and-due `commit` (50ms, earlier than the
    //      SVC retransmit cadence) — which this branch never services — would be re-returned every step,
    //      pinning the clock at that instant and never reaching `svc_message`: the view change stalls (the
    //      old primary silent but not stepping down). Clearing them makes `svc_message` the SOLE primary-side
    //      driver while forfeiting.
    // The flag is cleared ONLY when this replica LEAVES Normal-primary — the transition handlers
    // (`transition_to_view_change_status` / `adopt_canonical_head` / `catch_up_to_view` /
    // `start_view_as_new_primary`) all clear `pending_forfeit`, so once the view changes the new
    // generation re-evaluates from scratch (no same-view re-forfeit, no cross-view leak).
    if self.pending_forfeit {
      // RETIRE the normal-primary cadence timers: a forfeiting primary STOPS heartbeating/retransmitting,
      // so leaving `commit`/`prepare` armed-and-due wedges a poll_timeout()-driven driver (it advances only
      // to the next armed deadline) by spinning at the stale commit deadline, never reaching `svc_message`
      //. `svc_message` is the SOLE
      // primary-side driver while forfeiting; `propose_next_view` -> `join_svc` keeps it armed. Clearing them
      // on every forfeit tick is intended (idempotent once None; nothing re-arms them while `pending_forfeit`,
      // since the heartbeat/retransmit arming below sits under this early return).
      self.timers.commit = None;
      self.timers.prepare = None;
      // Also RETIRE the forfeit grace timer. A primary can
      // reach `pending_forfeit` via the force-sync / sync-checkpoint STEP-DOWN
      // (`maybe_force_sync` / `on_sync_checkpoint` / `on_recover_sync_checkpoint`) rather than via
      // `forfeit()` — and that path does NOT disarm `forfeit_armed` (only `forfeit()` does). This branch
      // never calls `maybe_forfeit` (the early `return` below skips the heartbeat/forfeit tick), so a
      // `forfeit_armed` left over from a pre-step-down `maybe_forfeit` (e.g. this primary was already
      // grace-armed on a committed `repair` hole) would be armed-but-never-serviced — the SAME spin a
      // poll_timeout()-driven driver hits on the stale `commit` deadline above (the grace deadline,
      // 300ms, is later than the svc cadence, so the spin surfaces once virtual time reaches it).
      // Clearing it (idempotent once None; the deferred-forfeit latch, not the grace timer, drives the
      // step-down retries now) keeps `svc_message` the sole primary-side driver while forfeiting.
      self.timers.forfeit_armed = None;
      if self.timers.svc_message.is_none_or(|d| d <= now) {
        self.propose_next_view(now, storage);
      }
      return;
    }
    // Durable-view-before-participate: until the new-primary view-change superblock
    // write is durable, status is Normal but the view is NOT yet recoverable. A primary must NOT
    // heartbeat (`Commit`) nor retransmit prepares (`Prepare`) in a view it could regress out of on
    // crash — those assert this replica's authority in the not-yet-durable view (the same hazard the
    // `on_get_view`/`on_recovery` gates close on the message side). Skip the whole heartbeat /
    // retransmit / forfeit-evaluation tick while a VIEW-CHANGING write is pending; `start_view_participate`
    // (run from `on_sb_done` once the view IS durable) arms the timers and begins committing, after which
    // ordinary ticks resume. The deferred forfeit above is exempt: it is a STEP-DOWN (it proposes a
    // higher view via `propose_next_view`), not participation as this view's primary.
    //
    // A commit-first SwapEpoch root in flight is NOT gated here ([`Self::pending_durable_view`] excludes
    // it): the view stays durable through an epoch swap, so the primary MUST keep heartbeating + committing
    // AT the predecessor epoch through the stage→durable-root window — that advertised commit is what lets
    // backups commit the `Reconfigure` op, stage their own swap, and converge. The successor epoch is still
    // un-installed in this window (the install runs only at `on_sb_done`), so this is participation at E,
    // the durable view + epoch, exactly as before the swap was staged.
    if self.pending_durable_view() {
      // RETIRE every cadence timer for this window — the SAME
      // timer-level wedge as the forfeit branch above. `start_view_as_new_primary` flips status to
      // Normal-primary but DEFERS `arm_timers` to `start_view_participate` (on `on_sb_done`), so the
      // STALE ViewChange timers (`svc_message`/`dvc_message`/`view_change_status`, armed by
      // `enter_view_change`) are still armed here AND are status-foreign: this branch never services
      // them and `view_change_timeouts` (which would) runs only in ViewChange status. Left armed, the
      // earliest stale deadline spins a poll_timeout()-driven driver (it advances to that deadline, this
      // branch does nothing, `poll_timeout()` re-returns it) — the clock never reaches the in-flight
      // superblock completion that begins participation, wedging the new primary. This window is driven
      // SOLELY by that superblock completion (no timer), so clearing them is correct: `poll_timeout()`
      // then yields `None` until `on_sb_done` → `start_view_participate` arms the real Normal-primary
      // timers. Idempotent (once None they stay None; nothing re-arms them while the view write holds).
      self.timers.commit = None;
      self.timers.prepare = None;
      self.timers.svc_message = None;
      self.timers.dvc_message = None;
      self.timers.view_change_status = None;
      return;
    }
    // Bootstrap the heartbeat the first time we're ticked as primary.
    if self.timers.commit.is_none() {
      self.timers.commit = Some(now + COMMIT_HEARTBEAT);
    }
    if self.timers.commit.is_some_and(|d| d <= now) {
      self.emit(Outgoing::new(
        Recipient::Backups,
        Message::Commit(Commit::new(
          self.view,
          self.commit_min,
          self.checkpoint_op,
          self.membership.epoch(),
          self.membership.config_id(),
        )),
      ));
      self.timers.commit = Some(now + COMMIT_HEARTBEAT); // re-arm THIS timer only
    }
    if self.timers.prepare.is_some_and(|d| d <= now) {
      // Retransmit un-committed prepares in op order, WINDOWED to the first
      // [`PREPARE_RETRANSMIT_WINDOW`] ops of `(commit_min, op]` — the ones the commit is waiting on.
      // Re-broadcasting the WHOLE window with full bodies every 100ms is unbounded work once the
      // pipeline is deep (it can legally hold up to MAX_PIPELINE ops); the lowest ops are the only
      // ones whose acks ADVANCE `commit_min`, and each advance slides this window up, so the tail
      // drains incrementally. A backup that fell BELOW the primary's `commit_min` is caught up not by
      // this (those ops are `<= commit_min`) but by its OWN tail-gap solicitation
      // ([`Self::request_tail_gap`], driven on every Commit heartbeat) — and the same tail-gap pull
      // covers a backup missing an op ABOVE this window that it has learned is committed, so the
      // window bounds only the primary-push side, never strands an op.
      //
      // The window ships BATCHED: instead of one full-body `Prepare` frame per windowed op per tick
      // (up to [`PREPARE_RETRANSMIT_WINDOW`] frames per backup under loss), the entries accumulate
      // into [`crate::PrepareBatch`]es bounded by the frame budget — the same accumulate-until-cap
      // shape as the repair serve ([`Self::on_request_prepare_range`]) — so one tick emits one (or,
      // past the budget, a few) frames carrying the same prepares. The receiver replays each entry
      // through `on_prepare` ([`Self::on_prepare_batch`]), so every per-op gate re-evaluates exactly
      // as for the per-op form. Only this RETRANSMIT path batches: the accept-path fresh broadcast
      // stays a per-op `Prepare` (each op ships the moment it is minted — there is no accumulated
      // window to batch, and batching it would need a flush trigger the mint path has no business
      // owning).
      let lo = self.commit_min.get() + 1;
      let hi = self.op.get().min(
        lo.saturating_add(PREPARE_RETRANSMIT_WINDOW)
          .saturating_sub(1),
      );
      // The budget is the frame cap less the `PrepareBatch` carrier framing; each `Present` entry
      // costs `present_entry_encoded_len(body)`, so a produced batch never exceeds the frame cap.
      let budget =
        crate::message::MAX_FRAME_LEN as usize - crate::message::PREPARE_BATCH_CARRIER_OVERHEAD;
      let mut running = 0usize;
      let mut entries: std::vec::Vec<crate::PreparedEntry> = std::vec::Vec::new();
      for op in lo..=hi {
        // SKIP a body-`Repairing` hole: a retransmitted entry carries the body bytes, which an
        // absent-body op does not hold, so it cannot be retransmitted. A primary CAN legitimately
        // hold such holes inside the un-acked window — a view-change adoption installs header-only
        // entries for ops whose bodies no donor shipped (the log carriers are header-only) — and the
        // windowed repair channel (`RequestPrepareRange` → `RepairBatch`) owns filling them; this
        // primary is itself soliciting those bodies, so there is nothing to push. A `Body::Reconfigure`
        // op IS body-bearing (`body_bytes()` yields its `encode_body()`) and MUST be retransmitted like a
        // client op — else a dropped initial reconfiguration `Prepare` is never resent, the op sits in
        // `(commit_min, op]` blocking later proposals (`has_pending_reconfigure`), and ordered commit
        // stalls behind it until a view change happens to truncate it. The retransmitted entry carries the
        // flat wire bytes; the receiver replays it through `on_prepare`, which rebuilds the typed
        // `Body::Reconfigure` from the `RECONFIGURATION` client id (so the wire form is uniform).
        if let Some(entry) = self.log.get(&op).cloned()
          && let Some(body) = entry.body_bytes()
        {
          let (client, request) = (entry.client, entry.request);
          let cost = crate::message::present_entry_encoded_len(body.len());
          // Adding this entry would push the batch past the frame budget — flush what accumulated
          // and start the next batch with it. The FIRST entry of a batch is always included (an
          // empty `entries` never flushes): a single op's body fits a one-entry batch by the
          // request-body bound (see [`crate::message::MAX_REQUEST_BODY_OVERHEAD`], which accounts
          // for the single-entry `PrepareBatch` carrier), so the window always makes progress.
          if !entries.is_empty() && running + cost > budget {
            self.prepare_batches_sent += 1;
            self.emit(Outgoing::new(
              Recipient::Backups,
              Message::PrepareBatch(crate::PrepareBatch::new(
                self.view,
                self.commit_min,
                self.checkpoint_op,
                self.membership.epoch(),
                self.membership.config_id(),
                core::mem::take(&mut entries),
              )),
            ));
            running = 0;
          }
          running += cost;
          entries.push(crate::PreparedEntry::new(
            OpNumber::with(op),
            client,
            request,
            body,
          ));
        }
      }
      if !entries.is_empty() {
        self.prepare_batches_sent += 1;
        self.emit(Outgoing::new(
          Recipient::Backups,
          Message::PrepareBatch(crate::PrepareBatch::new(
            self.view,
            self.commit_min,
            self.checkpoint_op,
            self.membership.epoch(),
            self.membership.config_id(),
            entries,
          )),
        ));
      }
      // re-arm THIS timer only (clear once everything is committed)
      self.timers.prepare = if self.commit_min.get() < self.op.get() {
        Some(now + PREPARE_RETRANSMIT)
      } else {
        None
      };
    }
    // A primary that has fallen a full checkpoint interval behind the quorum's durable
    // checkpoint — continuously for the grace window — forfeits primacy (steps down via a view
    // change). Checked each primary tick, AFTER the heartbeat/retransmit above (so an alive primary
    // still heartbeats while it is being given its grace window to catch up).
    self.maybe_forfeit(now, storage);
  }

  /// The shared NEW-op admission gate: EVERY op-content-independent precondition `on_request` enforces
  /// before minting a client op, so the reconfiguration-proposal path
  /// ([`Endpoint::propose_membership`](crate::Endpoint::propose_membership)) honours the IDENTICAL
  /// fences rather than mirroring NONE of them and minting straight through a pending durable-view write
  /// (the durable-view-before-participate violation). Read-only; the caller owns any per-path bookkeeping
  /// (the `wal_stalls` observability bump on `AtCapacity`, the client session row) and the actual mint.
  ///
  /// `on_request` additionally applies the client-op-specific session dedup + session-table cap, which
  /// are NOT here (a reconfiguration uses the reserved sentinel client and no session row). Mapping these
  /// transient verdicts back: `on_request` drops the request silently (the client retransmits);
  /// `propose_membership` returns a retryable [`ProposeMembershipError`](crate::ProposeMembershipError).
  pub(crate) fn check_new_op_admission<W: Wal, B: Superblock>(
    &self,
    storage: &Storage<W, B, S>,
  ) -> Result<(), NewOpReject> {
    if !self.status.is_normal() || !self.is_primary() {
      return Err(NewOpReject::NotNormalPrimary);
    }
    // Durable-view-before-participate: a pending superblock view-change write means status==Normal
    // but our view is not yet persisted. Minting now would create+commit an op in a view we could regress
    // out of on crash. ALSO refuse while a state-sync OR a checkpoint-persist is in flight: both can RESET
    // `self.op` (a sync to the checkpoint via `apply_sync`; a checkpoint completion advances
    // `checkpoint_op` and GCs), so assigning a new op now risks reusing an op number a backup still holds
    // under different bytes (the op-reuse divergence `maybe_force_sync`'s primary step-down guards against).
    if self.pending_sb.is_some() || self.sync.is_some() || self.pending_checkpoint.is_some() {
      return Err(NewOpReject::Busy);
    }
    // Fence client minting while a reconfiguration is IN FLIGHT (proposed-but-not-committed OR
    // committed-but-not-installed — [`Self::has_pending_reconfigure`]): a `Reconfigure` op must be the LAST
    // op of its epoch (VSR-Revisited §5). Otherwise a client op minted ABOVE the reconfiguration op `N`
    // commits under the OLD epoch's quorum (which can include a being-removed voter) yet is NOT covered by
    // the cross-config quorum-intersection at the epoch swap — that argument spans only ops at/below `N`, so
    // a subsequent E+1 view change can form at head `N` and silently drop the client-acked op above it.
    // Blocking here makes every op `> N` mint + commit under E+1's own (sound) quorum instead. Returns
    // `Busy` so the client simply retries once the swap installs (the same self-releasing shape as the
    // in-flight guard above); the reconfiguration's OWN first proposal is unaffected (the predicate is false
    // until that op is in the log). `propose_membership`'s single-flight guard already blocks a SECOND
    // reconfiguration, so this does not deadlock the change itself.
    if self.has_pending_reconfigure() {
      return Err(NewOpReject::Busy);
    }
    // A primary that has FLAGGED a forfeit (a step-down — `maybe_force_sync`'s primary guard, or the
    // recovery-peer-fetch / state-sync apply that reset `self.op` back to a checkpoint) must NOT assign
    // new ops: it has reset `self.op` below a value the cluster moved PAST (a newer view's primary already
    // committed ops at those numbers), so a new op reuses a committed op number with DIFFERENT bytes.
    if self.pending_forfeit {
      return Err(NewOpReject::SteppingDown);
    }
    // Do not mint while our committed prefix is not yet applied (`commit_max > commit_min` — a committed
    // op known but not applied, e.g. held by a repair hole): the session table is stale for the unapplied
    // ops, and a fresh op assigned to a retry of one would double-execute it once the gap fills (the apply
    // loop has no dedup). `!self.repair.is_empty()` is subsumed (a hole implies the gap) but stated for intent.
    if self.commit_max.get() > self.commit_min.get() || !self.repair.is_empty() {
      return Err(NewOpReject::CommitGap);
    }
    // Pipeline-cap: never let the accepted-but-uncommitted window `(commit_min, op]` exceed [`MAX_PIPELINE`].
    // Releases as commits advance `commit_min`; bounds the prepare-retransmit working set and the bodies a
    // slow quorum can pin above the commit frontier.
    if self.op.get().saturating_sub(self.commit_min.get()) >= MAX_PIPELINE {
      return Err(NewOpReject::PipelineFull);
    }
    // Physical WAL-ring stall-before-wrap: never assign an op whose ring slot still holds an un-pruned
    // op (one not yet checkpoint-subsumed on a quorum). The un-pruned window `(floor, op]` must fit in
    // the EFFECTIVE ring ([`effective_wal_capacity`] — the backend's own ring, or the proto-imposed ring
    // for a ring-less backend); minting the next op makes it `next_op - floor` wide, so if THAT exceeds
    // the ring we STALL. Enforcing the ring even for a ring-less backend is what keeps
    // `op_head <= checkpoint_op + effective` true for every replica — the geometry `recover()`'s read
    // ceiling leans on to cap a bit-rotted `op_head` without ever clipping a legitimately-held tail.
    // ALSO the header-only view-change-carrier band frame-fit bound ([`Self::band_at_capacity`]). Both
    // self-release as `quorum_checkpoint_op` rises and `run_gc` frees slots / shrinks the band.
    let next_op = self.op.get().saturating_add(1);
    let unpruned_window = next_op.saturating_sub(self.prune_floor().get());
    let wal_would_overflow = unpruned_window > self.effective_wal_capacity(storage);
    let band_would_overflow = self.band_at_capacity();
    if wal_would_overflow || band_would_overflow {
      return Err(NewOpReject::AtCapacity);
    }
    Ok(())
  }

  pub(crate) fn on_request<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    _from: Peer,
    r: crate::Request,
  ) {
    // RESERVED-CLIENT INGRESS FENCE (consensus safety): [`ClientId::RECONFIGURATION`] is the high
    // sentinel under which the cluster mints its INTERNAL `Body::Reconfigure` membership ops via
    // `propose_membership`. No real client owns it, so no genuine client `Request` ever carries it.
    // Reject it here — BEFORE session dedup / admission / minting — so a client-originated `Request`
    // bearing the reserved id cannot be type-erased into a `Body::Present` op on the primary while
    // every backup reconstructs the same prepare's bytes as a typed `Body::Reconfigure`
    // (`log_entry_from_prepare` → `from_committed_body` keys on this id). That would BYPASS
    // `propose_membership`'s entire admission ladder (the closed `SingleVoterDelta` vocabulary, the
    // PromoteLearner catch-up gate, the single-change gate, the predecessor-delta validation, the
    // single-writer `reconfigure_inflight` latch) and yield a primary/backup membership SPLIT or a committed-log
    // divergence (the same committed op typed differently on the primary vs. the backups). Drop it
    // silently: emit no `Prepare`, mint no op, insert no session row, send no reply (this id is never
    // a real session, so there is nothing to ack). This guards ONLY the CLIENT `Request` ingress —
    // the internal reconfiguration mint (`propose_membership`, which legitimately uses the reserved
    // id and never routes through here) is untouched.
    if r.client() == ClientId::RECONFIGURATION {
      return;
    }
    // The shared op-content-independent admission gate (Normal-primary, no pending durable-view / sync /
    // checkpoint write, no flagged forfeit, no commit gap, pipeline depth, WAL/carrier capacity). It is
    // split across the session dedup below to PRESERVE this path's exact behaviour: the EARLY-state fences
    // (not-primary / busy / stepping-down / commit-gap) drop the request BEFORE dedup, while the LATE
    // CAPACITY fences (pipeline / WAL / band) are applied AFTER dedup — so a stale/duplicate request still
    // gets its cached-reply RESEND (the dedup mints no op, and a capacity stall gates only a would-be NEW
    // op, never a reply resend), exactly as the in-line order did before the extraction. `propose_membership`
    // applies the whole gate up front (it has no session/dedup to interleave).
    let admission = self.check_new_op_admission(storage);
    if matches!(
      admission,
      Err(
        NewOpReject::NotNormalPrimary
          | NewOpReject::Busy
          | NewOpReject::SteppingDown
          | NewOpReject::CommitGap
      )
    ) {
      return;
    }
    // Dedup against an EXISTING session (clients send one request at a time, numbered 1..). An
    // UNKNOWN client mints NO row in this pass — its row is inserted only at ACCEPT below — so a
    // stale/gap/refused probe from an unregistered client id cannot grow the table.
    let key = r.client().get();
    if let Some(session) = self.clients.get(&key) {
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
          self.emit(Outgoing::new(
            Recipient::To(Peer::Client(r.client())),
            Message::Reply(reply),
          ));
        }
        return; // either resent the cached reply, or it's still in flight
      }
      if r.request().get() != session.request.get() + 1 {
        return; // gap: client violated one-in-flight; ignore
      }
    } else {
      // A brand-new client (no session row): only request 1 opens a fresh session — the same gap
      // rule as an existing watermark-0 row, without minting the row for a refused probe. This is
      // also the EVICTED-CLIENT contract surface ([`crate::MAX_CLIENT_SESSIONS`]): an evicted client
      // that returns mid-numbering is silently dropped here until it re-registers from request 1.
      if r.request().get() != 1 {
        return;
      }
      // SessionsFull admission backstop: never mint a NEW provisional row past the hard bound
      // (the applied cap plus a pipeline of in-flight provisional rows). Apply-time eviction keeps
      // the APPLIED table at the cap, the pipeline-cap admission below bounds the in-flight
      // provisional rows, and view transitions drop stale provisionals — so this is unreachable in
      // healthy operation: a structural memory floor, not a normal-path limit. Silent drop (no
      // non-committed error-Reply path exists): the client retries and is admitted once in-flight
      // rows transition to applied (eviction then frees applied slots).
      if self.clients.len() >= self.session_table_hard_bound() {
        return;
      }
    }

    // The LATE CAPACITY fences (pipeline depth / WAL-ring / carrier-band), applied here — AFTER the dedup
    // resend above — so a would-be NEW op is dropped under back-pressure WITHOUT advancing the session
    // watermark or minting, while a duplicate already got its reply resend. `AtCapacity` bumps the
    // back-pressure observability counter exactly as the in-line stall did.
    match admission {
      Err(NewOpReject::AtCapacity) => {
        self.wal_stalls += 1; // observability: prove the admission stall genuinely engaged
        return;
      }
      Err(NewOpReject::PipelineFull) => return,
      _ => {}
    }

    // Accept: assign the next op, submit to WAL, cache, broadcast Prepare.
    // The primary's own vote is counted in on_wal_done when the append is durable.
    let client = r.client();
    let request = r.request();
    let body_bytes = r.body_bytes();
    // The accept-time session row: PROVISIONAL for a brand-new client (`last_op` stays 0 — invisible
    // to the deterministic eviction until its op APPLIES; see [`Session::last_op`]); for a known
    // client this only bumps the watermark so the in-flight request's retransmits dedup.
    let session = self.clients.entry(key).or_default();
    session.request = request;
    // DEFENSE-IN-DEPTH for the reserved-client ingress fence above: this is the SOLE site that mints a
    // client `Request` as a `Body::Present` op. The reserved id MUST never reach here — a `Body::Present`
    // op carrying `ClientId::RECONFIGURATION` would, on every backup, reconstruct from its prepare bytes
    // as a typed `Body::Reconfigure` (`from_committed_body` keys on this id), typing the SAME committed
    // op differently on the primary vs. the backups. The early `on_request` fence already guarantees
    // this; the assert FREEZES the invariant so a future ingress path that reaches the mint without the
    // fence is caught.
    debug_assert!(
      client != ClientId::RECONFIGURATION,
      "a client Request minting a Body::Present op carried the reserved ClientId::RECONFIGURATION — \
       the reserved-client ingress fence was bypassed (backups would type this committed op as \
       Body::Reconfigure)",
    );
    self.mint_op(
      now,
      storage,
      client,
      request,
      body_bytes.clone(),
      Body::Present(body_bytes),
    );
  }

  /// The shared op-mint tail: assign `self.op + 1`, submit the WAL append, cache the entry, seed the
  /// inflight vote tracker (content-addressed by the operation identity), record the pending ack, and
  /// broadcast the `Prepare`. The SINGLE source of the append-before-ack append + Prepare emission, so
  /// the client-request path ([`Self::on_request`]) and the reconfiguration-proposal path
  /// ([`Endpoint::propose_membership`](crate::Endpoint::propose_membership)) cannot drift.
  ///
  /// `body_bytes` is the canonical wire body the WAL stores and the `Prepare` carries — the client
  /// bytes for a client op, the encoded successor membership for a `Body::Reconfigure` op (whose
  /// canonical `body_checksum` equals `fnv1a_128(body_bytes)` by construction). `body` is the
  /// in-memory log entry's [`Body`] (it distinguishes a client op from a reconfiguration op), wrapped
  /// under the same `(client, request)` identity passed here.
  ///
  /// Callers own the admission gating and any per-path bookkeeping (the client path's session row, the
  /// reconfiguration path's single-writer latch) BEFORE calling — this mints unconditionally.
  pub(crate) fn mint_op<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    client: ClientId,
    request: RequestNumber,
    body_bytes: Bytes,
    body: Body,
  ) {
    self.op = self.op.next();
    let header = Header::new(self.op, self.view, client, request, &body_bytes);
    // Through the slot-quiescence choke: a freshly minted op can land on a ring slot whose OLD
    // write is still in flight (op reuse after a truncation lowered the head; a ring wrap over a
    // GC-freed slot), and completion reordering must not let those stale bytes land over this op.
    self.submit_or_defer_append(
      storage,
      self.op,
      header,
      body_bytes.clone(),
      Pending::Ack(self.op),
    );
    self.log.insert(
      self.op.get(),
      LogEntry {
        client,
        request,
        body,
      },
    );
    self.inflight.insert(
      self.op.get(),
      Inflight {
        oks: 0, // own bit set on append-done in on_wal_done
        committed: false,
        // Content-address this op's votes by the OPERATION IDENTITY being driven (client, request,
        // body): only a PrepareOk carrying this same prepare_checksum is counted, so a stale ack for a
        // reused op number — even one whose body bytes match — cannot forge a quorum (mirrors
        // TigerBeetle's (op, prepare_checksum) namespace).
        prepare_checksum: crate::storage::prepare_identity(
          client,
          request,
          crate::storage::fnv1a_128(&body_bytes),
        ),
      },
    );
    // Append-before-ack: op is in flight until its `on_wal_done`. The primary's own vote is
    // likewise gated — `record_own_vote` fires only on completion — but tracking it here keeps the
    // "durable?" predicate uniform across every votable append (and the choke-point debug_assert).
    self.appending.insert(self.op.get());

    self.emit(Outgoing::new(
      Recipient::Backups,
      Message::Prepare(Prepare::new(
        self.view,
        self.op,
        self.commit_min,
        self.checkpoint_op,
        self.membership.epoch(),
        self.membership.config_id(),
        client,
        request,
        body_bytes,
      )),
    ));

    self.arm_timers(now);
    // NOTE: try_commit() is NOT called here — the own vote is recorded in on_wal_done when the
    // append is durable, which then calls try_commit.
  }

  /// Whether op `op`'s recorded `PrepareOk` bitset `oks` meets the ADDITIONAL commit requirement a
  /// voter-set-SHRINKING [`Body::Reconfigure`] op carries: a quorum of the SUCCESSOR configuration's
  /// voters must be among the acks. `true` for every other op — a client op, a missing or
  /// body-`Repairing` entry, and a non-shrinking reconfiguration — which keeps the uniform
  /// predecessor-quorum threshold the sole requirement there.
  ///
  /// A shrink seats a configuration with FEWER voters. Committed on a bare predecessor quorum, the
  /// shrink can land while a SUCCESSOR voter is already gone — an ack set the predecessor tolerates
  /// (it can spare the missing voter) seats a successor that cannot (it needs that voter for its own
  /// quorum), converting one tolerated crash into an installed outage. Requiring a successor quorum
  /// IN the committing ack set is a DURABILITY witness: an ack follows a durable append, so at the
  /// instant the shrink commits a quorum of the successor's own voters durably holds it — the
  /// successor never seats on a thinner durable footprint than it needs to operate. The witness also
  /// NARROWS the exposure window: a successor voter's crash strands the installed successor only if
  /// it lands between that voter's durable ack and the commit, where an unwitnessed commit could
  /// seat a successor missing a voter for the whole exchange. The race inside that residual window
  /// is IRREDUCIBLE by any commit-side rule — the commit predicate reads acks banked in the past and
  /// cannot observe liveness at the instant it fires — and is owned by the successor's own crash
  /// tolerance, like any crash after the install.
  ///
  /// The requirement is ADD-ONLY — a second popcount over the same acks — so it can only delay a
  /// commit, never admit one the predecessor-quorum rule would refuse:
  /// - even `n` → `n−1`: any predecessor quorum holds at most one leaving voter's bit, so it already
  ///   contains a successor quorum — the conjunction is implied and nothing changes. (Exactly the
  ///   shrinks that preserve the cluster's crash tolerance.)
  /// - odd `n` → `n−1`: the conjunction genuinely binds — exactly the shrinks that reduce crash
  ///   tolerance, where a predecessor quorum can carry the shrink without any successor majority.
  ///
  /// While the successor quorum is absent the op (and the contiguous commit behind it) WAITS under
  /// the still-authoritative predecessor configuration, and resumes when a successor voter acks (a
  /// retransmitted `Prepare` reaches it, or it recovers) — the same heal condition as, and a
  /// strictly better stuck-state than, installing a successor that cannot serve.
  fn shrink_successor_quorum_met(&self, op: u64, oks: u64) -> bool {
    // Only a held `Body::Reconfigure` can name a shrink. A missing or body-`Repairing` entry imposes
    // nothing here — `commit_op` holds the commit at such a hole until peer repair supplies the
    // body, and this predicate is then re-evaluated against it.
    let Some(payload) = self.log.get(&op).and_then(|e| e.body.as_reconfigure()) else {
      return true;
    };
    let n_pred = self.membership.replica_count();
    let n_succ = payload.replica_count();
    if n_succ >= n_pred {
      return true; // not a voter-set shrink — no successor requirement beyond the uniform one.
    }
    // The RETAINED voters' predecessor slots: every predecessor voter seated as a SUCCESSOR voter.
    // `oks` bits are confined to predecessor voter slots (`on_prepare_ok` bounds the slot and a
    // learner never acks), so masking to the retained slots drops exactly the leaving voters' bits.
    let successor_voters = &payload.members()[..n_succ as usize];
    let predecessor_voters = &self.membership.members_slice()[..n_pred as usize];
    let mut retained = 0u64;
    for (slot, member) in predecessor_voters.iter().enumerate() {
      if successor_voters.contains(member) {
        retained |= 1u64 << slot;
      }
    }
    // A single-voter shrink retains the successor's voters verbatim at predecessor slots; anything
    // else cannot assemble here (propose validates the delta, and the committed-payload fence
    // re-proves the successor seats no brand-new voter). The mask formula stays fail-closed for an
    // unassemblable payload regardless: fewer retained bits can only strengthen the requirement.
    debug_assert_eq!(
      retained.count_ones(),
      u32::from(n_succ),
      "a voter-set shrink retains exactly the successor's voters at predecessor slots"
    );
    let successor_quorum = u32::from(n_succ) / 2 + 1;
    (oks & retained).count_ones() >= successor_quorum
  }

  /// Commits the longest contiguous quorum-acked prefix beyond `commit_min`.
  ///
  /// Returns the commit tail's status outcome: [`CommitFlow::EnteredRecovery`] when the tail tore
  /// the generation down into the recovery peer-fetch, on which every caller must short-circuit
  /// (see [`CommitFlow`]).
  pub(crate) fn try_commit<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) -> CommitFlow {
    // Tallying votes into a commit — and advertising it — is the PRIMARY's authority, judged
    // against the membership in force NOW, not when the triggering action was staged. Every
    // legitimate caller is the primary of the current view (the own-append and repair-fill
    // completions gate on `is_primary`, `on_prepare_ok`'s ingress does, the new-primary
    // participation and the solo-voter resume are primary by construction); the path this refuses
    // is a completion staged under primary authority and delivered after a landing-driven install
    // withdrew it — a retained learner's delayed `AdoptVote` completion must not count a tally,
    // commit, apply, or emit `Commit`. Non-primaries advance only through externally-proven
    // commits (`advance_commit`).
    if !self.is_primary() {
      return CommitFlow::Continue;
    }
    // Do NOT apply ops while the SM is mid-replacement or does not yet hold its checkpoint — the SAME gate
    // `advance_commit` takes. A node owing a post-root SM-reconstruct (`self.checkpoint_op == M`, SM still
    // at the OLD content) can become a Normal PRIMARY through a view change that PRESERVES the obligation;
    // with a forced-sync held tail this would otherwise apply `M+1` against the un-restored SM — a
    // double-skip over the unrestored `(.., M]` prefix → committed-state corruption. The retry reconstructs
    // the SM under the fixed M pointer; the held tail re-commits once it clears. (A pre-root
    // `pending_install` on a primary is unreachable — a primary abdicates rather than stage a sync — but
    // the gate stays symmetric with `advance_commit`.)
    if self.pending_install.is_some() || self.sm_reconstruct_owed() {
      return CommitFlow::Continue;
    }
    let quorum = self.membership.quorum() as u32;
    // Count only CURRENT-VOTER slots toward the quorum. `on_prepare_ok` bounds every ingress bit
    // to a voter slot and the install-time rekey drops removed members' bits, but a bit minted
    // between a stage and a completion under a different membership (a preserved inflight entry's
    // stale slot) must not be able to satisfy a quorum — masking at the tally is the structural
    // closure that makes any such bit inert regardless of which path set it. Voting slots are
    // `[0, replica_count)`, capped at 64 by the membership invariant.
    let n = u32::from(self.membership.replica_count());
    let voter_mask = if n >= u64::BITS {
      u64::MAX
    } else {
      (1u64 << n) - 1
    };
    let mut advanced = false;
    loop {
      let next = self.commit_min.get() + 1;
      // Extract needed data while holding a short-lived shared borrow, so the
      // borrow ends before commit_op (which needs &mut self).
      let ready = self
        .inflight
        .get(&next)
        .map(|inf| (!inf.committed, inf.oks & voter_mask))
        .is_some_and(|(not_committed, oks)| {
          // The uniform predecessor-quorum threshold, plus the successor-quorum conjunction a
          // voter-set-shrinking `Reconfigure` op additionally carries. The conjunction only ever
          // ADDS to the predecessor quorum — both counts read the same `oks` — so no op can commit
          // below the predecessor quorum.
          not_committed && oks.count_ones() >= quorum && self.shrink_successor_quorum_met(next, oks)
        });
      if !ready {
        break;
      }
      // `commit_op` HOLDS the commit (returns false without advancing) if `next`'s body read back
      // permanently faulty and must be peer-repaired — never skip a hole. Stop the loop; the repair
      // timer re-fetches it and a later try_commit resumes from exactly here.
      if !self.commit_op(now, storage, next) {
        break;
      }
      advanced = true;
    }
    self.commit_max = OpNumber::with(self.commit_max.get().max(self.commit_min.get()));
    if advanced && !self.pending_durable_view() {
      // Tell backups the commit advanced (also serves as a heartbeat). Suppressed only while a view-CHANGING
      // durable-view write is in flight (`pending_durable_view`): advertising the commit there would assert
      // authority in a view not yet durable — the durable-view-before-participate fence the `emit` chokepoint
      // enforces. A commit-first SwapEpoch root does NOT suppress it (the view is durable through an epoch
      // swap), which is exactly what lets a backup learn the `Reconfigure` op committed, stage its own swap,
      // and converge. The next commit tick or heartbeat re-advertises once any pending root lands.
      self.emit(Outgoing::new(
        Recipient::Backups,
        Message::Commit(Commit::new(
          self.view,
          self.commit_min,
          self.checkpoint_op,
          self.membership.epoch(),
          self.membership.config_id(),
        )),
      ));
    }
    // Cancel an outstanding FORCED sync the commit just satisfied (its target is
    // now `<= commit_min`). A primary normally forfeits rather than force-sync (`maybe_force_sync`), so
    // this rarely fires here — but a forced sync ARMED while this replica was a backup, then satisfied by
    // ordinary commit after it regained primacy, must not linger to admit a stale SyncCheckpoint.
    self.cancel_forced_sync_if_satisfied();
    // Adopt an owed INHERITED checkpoint frontier first (commit_min may have just reached it), so
    // the cadence below computes its boundary off the adopted pointer in the same tail — then
    // re-drive an owed orphaned-re-persist reconciliation the settle site had to defer (its
    // deferral conditions clear on events this tail observes). Entering it ends the generation:
    // nothing below runs over the teardown, and the caller short-circuits on the returned flow.
    self.maybe_adopt_inherited_frontier();
    if self
      .maybe_enter_orphan_repersist_recovery(now, storage)
      .entered_recovery()
    {
      return CommitFlow::EnteredRecovery;
    }
    // commit_min may have advanced past a checkpoint boundary — take a checkpoint if due.
    self.maybe_checkpoint(storage);
    // Pay any swap-checkpoint DEBT (`config_install_op > checkpoint_op` on a recovered root): commit just
    // advanced, so if it reached the reconfigure op force the owed checkpoint (the re-entrancy guard makes
    // this routine's own `advance_commit` a no-op here). No-op when no debt is owed.
    self.maybe_pay_checkpoint_debt(now, storage);
    // Re-submit a staged epoch swap that is waiting for a free superblock slot — chiefly a `pending_swap`
    // that SURVIVED a view change whose new generation issued no durable-view write (a `catch_up_to_view`):
    // there is no `on_sb_done` re-trigger on that path, so the commit tail is the re-submit point. No-op
    // unless a swap is staged AND the superblock is free (the same exclusion `maybe_checkpoint` enforces;
    // a checkpoint queued just above keeps the swap waiting its turn, re-submitted from `on_sb_done`).
    self.maybe_swap_epoch(storage);
    CommitFlow::Continue
  }

  /// Applies op `op` on the primary, caches + sends the reply, emits the event. Returns `true` if it
  /// applied (or recognized + staged a consensus-layer reconfiguration); `false` if the body is
  /// missing (read back permanently faulty) — in which case it registers the op for peer fault-repair
  /// and does NOT advance `commit_min`, so the caller HOLDS the commit at the hole until a peer
  /// supplies the op.
  #[must_use]
  fn commit_op<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    op: u64,
  ) -> bool {
    // Faults-as-data (peer fault-repair): a committed op whose body read back
    // permanently faulty (bit-rot / torn) is ABSENT from the dense `log` cache (the recover loop
    // dropped it rather than adopt a wrong/empty body), OR is present as a body-`Repairing` HOLE (the
    // op's existence survived but its bytes did not). Either way, instead of panicking, hold the commit
    // and fetch the WHOLE contiguous hole run from a peer (`RequestPrepareRange` → `RepairBatch`),
    // windowed so a deep header-only band is repaired pipelined rather than one round trip per op; a
    // later try_commit resumes here.
    let Some(entry) = self.log.get(&op).cloned() else {
      self.request_repair_run(now, op);
      return false;
    };
    // This locally-counted commit path is reached only through `try_commit`'s readiness predicate;
    // re-derive the shrink conjunction from the log + inflight as an INDEPENDENT witness that a
    // voter-set-shrinking `Reconfigure` op never commits here without its successor quorum.
    // (Externally-proven commits — a backup following `Commit`, a laggard adopting a peer
    // checkpoint or a state sync — advance through `advance_commit`, never through this path.)
    debug_assert!(
      self
        .inflight
        .get(&op)
        .is_none_or(|inf| self.shrink_successor_quorum_met(op, inf.oks)),
      "op {op} is committing without the successor quorum its voter-set shrink requires"
    );
    // Consensus-layer reconfiguration: a `Body::Reconfigure` op is NOT applied to the state machine —
    // at commit it triggers the COMMIT-FIRST epoch swap (stage the successor + a durable SwapEpoch
    // root; the in-memory swap is deferred to the durable root). Recognized BEFORE the `as_present`
    // hole check below (a `Reconfigure` body is `as_present() == None`, which would otherwise route it
    // to peer-repair). Returns committed — the op IS committed; only its EFFECT is the epoch swap, not
    // an `sm.apply`.
    if self.commit_reconfigure(op, &entry.body, storage) {
      return true;
    }
    let Some(body) = entry.body.as_present() else {
      // A body-absent (`Repairing`) hole: handled EXACTLY like a wholly-missing slot above — hold the
      // commit and peer-repair the contiguous hole run.
      self.request_repair_run(now, op);
      return false;
    };
    let reply_body = self.sm.apply(OpNumber::with(op), body);
    self.note_sm_advanced(OpNumber::with(op));
    // Reply-size contract (see `StateMachine::apply`): an over-bound reply encodes past the frame
    // cap and the transport refuses the send — unrecoverable, since the op is already committed.
    debug_assert!(
      reply_body.len() <= crate::message::max_reply_body_len(),
      "StateMachine::apply returned a {}-byte reply for op {} (> max_reply_body_len {}): the Reply \
       cannot be framed and the committed result is undeliverable",
      reply_body.len(),
      op,
      crate::message::max_reply_body_len(),
    );
    self.set_commit_min(OpNumber::with(op));
    if let Some(inflight) = self.inflight.get_mut(&op) {
      inflight.committed = true;
    }
    // The SHARED apply-time session update (watermark + reply cache + last-activity stamp +
    // deterministic cap eviction) — identical to the backup path in `advance_commit`, so primary and
    // backups converge on identical tables at identical applied ops.
    self.note_applied_session(op, entry.client, entry.request, &reply_body);

    self.emit(Outgoing::new(
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

  /// The SINGLE recognition+routing of a committed `Body::Reconfigure` op, shared by the primary's
  /// [`Self::commit_op`] and the backup's [`Self::advance_commit`] so the two apply loops cannot drift
  /// on what a committed reconfiguration does. Returns `true` (and performs the swap staging) iff
  /// `body` is `Body::Reconfigure`; `false` for an ordinary client op (the caller applies it normally).
  ///
  /// On a reconfiguration it: (1) marks the op committed and advances `commit_min` past it — the op IS
  /// committed at the consensus layer, so the applied frontier moves even though no `sm.apply` runs;
  /// (2) computes the SUCCESSOR membership by chaining off the CURRENT (predecessor) membership via
  /// [`Membership::reconfigure`](crate::Membership) — the SAME chain `Membership::apply_delta` used at
  /// propose, single-sourced so the successor `epoch`/`config_id` are byte-identical to the proposer's
  /// (and to every other committing replica's, since all commit at the identical predecessor); and
  /// (3) STAGES the epoch swap ([`Self::stage_epoch_swap`]) — latch the successor, clear the
  /// single-writer latch, and submit (or queue) the durable SwapEpoch root. The epoch is NOT advanced
  /// in memory here (the durable-epoch-before-participate fence — install runs only at the durable
  /// root). The op is NOT delivered to `S::apply` and no client `Reply`/`Committed` event is emitted
  /// (it carries no client request).
  fn commit_reconfigure<W: Wal, B: Superblock>(
    &mut self,
    op: u64,
    body: &Body,
    storage: &mut Storage<W, B, S>,
  ) -> bool {
    let Some(payload) = body.as_reconfigure() else {
      return false;
    };
    // The op is committed at the consensus layer regardless of whether THIS node stages the swap: advance
    // the applied frontier past it (no `sm.apply`) and mark it committed for the primary's inflight
    // tracker (a backup holds no inflight entry — the `if let` is a no-op). The SM-content witness is
    // accounted alongside — a `Reconfigure` op's SM-effect is vacuous by design (the epoch swap, not an
    // apply, is its effect), so "fully performed" is immediate and `sm_at` stays sequential per
    // committed op through reconfiguration epochs.
    self.set_commit_min(OpNumber::with(op));
    self.note_sm_advanced(OpNumber::with(op));
    // Lift the KNOWN-committed frontier to cover this op BEFORE staging the swap. On the PRIMARY commit
    // path (`commit_op` ← `try_commit`) `commit_max` is raised to `commit_min` only AFTER the commit
    // loop, but the SwapEpoch root is staged HERE, mid-loop: `submit_swap_epoch` reads `self.commit_max`
    // as the root's durable `commit`, and `committed_band_headers` is bounded by `commit_max` — so a
    // stale `commit_max` would mint a root recording the just-committed reconfigure op as NOT committed
    // (commit < op, its band header omitted). A node recovering an E+1 membership off that root reads
    // back a `commit_max` below the op (committed-loss; durable-epoch-before-participate + exact-catch-up
    // violated). The op IS committed by construction here, so lifting `commit_max` to `commit_min` is
    // honest, keeps the `commit_max >= commit_min` invariant intact across the stage, and makes the root
    // durably prove the op committed. (The backup path's `advance_commit` already raised `commit_max` to
    // its target before the loop, so this `.max` is a no-op there.)
    self.commit_max = OpNumber::with(self.commit_max.get().max(self.commit_min.get()));
    if let Some(inflight) = self.inflight.get_mut(&op) {
      inflight.committed = true;
    }
    // PREDECESSOR-PINNED swap staging (the anti-fork gate). The successor `(epoch, config_id)` is derived
    // by CHAINING off a predecessor (`epoch+1`, `config_id = hash(.., prev_config_id)`), so it is correct
    // ONLY when chained from the EXACT predecessor the op was proposed against — pinned in the op as
    // `prev_config_id`. Stage the swap iff this node's CURRENT configuration IS that predecessor:
    // - match ⇒ this is the first time we cross this reconfiguration at its predecessor; chain + stage.
    // - mismatch ⇒ we are NOT at the pinned predecessor: either we ALREADY installed this op's swap and
    //   our `commit_min` later regressed below it (a state-sync / recovery install reset the applied
    //   frontier while the durable membership stayed the post-swap one) and re-reached it, OR we are a
    //   laggard not yet advanced to the predecessor. Either way re-deriving here would chain off the WRONG
    //   configuration and FORK a grand-successor — so SKIP staging; the op stays committed (commit_min
    //   advanced above) and the swap that already happened (or will, once we reach the predecessor) stands.
    if self.membership.config_id() == payload.prev_config_id() {
      // INSTALL-TIME VOTER-ADMISSION FENCE: every voter the committed successor seats must already be
      // a member (voter or learner) of the EXACT predecessor it chains from — `self.membership`, just
      // proven by the pin above. A brand-new voter holds no committed prefix (it was never a member,
      // so it never appended, let alone committed, any prior op), yet it counts toward the successor's
      // view-change quorum, so a quorum formed without the prefix-holding retained voters could elect
      // a leader that drops a committed op. Voters enter via AddLearner → durable catch-up →
      // PromoteLearner (the promote-time proof), never directly.
      //
      // PANIC, not skip: this arm runs only for a COMMITTED op, and no compliant cluster can commit
      // one — the [`SingleVoterDelta`] vocabulary cannot even EXPRESS a direct voter add (there is no
      // such delta to propose, so a compliant primary cannot mint the op), and every vote is refused
      // at its mint: `send_prepare_ok` never acks such an op, `record_own_vote` never counts the own
      // bit, and the solo-voter recovery reseed seeds none (the
      // append seam additionally drops the `Prepare` before it burns a WAL slot), so it can never
      // assemble a quorum of compliant votes. By that induction no committed state, and hence no
      // state-sync donor checkpoint, ever contains a direct-add configuration — and the induction's
      // base is ENFORCED, not assumed: `VsrState::decode` admits only the exact current
      // `SUPERBLOCK_VERSION`, so recovery can only load stores this fence's code wrote (the one
      // shape no runtime predicate can re-check — a direct-add successor an unfenced writer already
      // INSTALLED into a durable root — never decodes), and the transport hello admits only peers
      // speaking the exact current wire version, so every live donor/committer runs it. Reaching
      // here therefore means in-process corruption or an embedder-fabricated store. A deterministic
      // fail-stop surfaces that immediately and never diverges; skipping the swap instead would
      // quietly re-interpret the op and fork against any node that installs it.
      if let Some(added) = self
        .membership
        .first_new_voter(payload.replica_count(), payload.members())
      {
        panic!(
          "refusing to install the committed Reconfigure op {op}: it seats {added:?} as a voter \
           without prior membership — a brand-new voter holds no committed prefix, so admitting it \
           directly can drop a committed op across the configuration change; add it as a learner, \
           catch it up, then promote it"
        );
      }
      // Chain the successor off the (now proven-correct) predecessor membership. A committed
      // reconfiguration's payload was validated at propose AND re-validated when the wire body decoded
      // into `Body::Reconfigure`, so `reconfigure`'s structural re-check cannot fail here.
      let successor = self
        .membership
        .reconfigure(
          payload.replica_count(),
          payload.learner_count(),
          payload.members().to_vec(),
        )
        .expect("a committed reconfiguration op carries a structurally valid successor membership");
      // Capture the reconfigure op NUMBER for the install-time `MembershipChanged` — `commit_min` is at
      // it NOW but may advance past it before the durable root lands (the primary keeps committing
      // through the SwapEpoch window), so the install must name THIS op, not `commit_min` then.
      self.stage_epoch_swap(OpNumber::with(op), successor, storage);
    }
    true
  }

  pub(crate) fn on_prepare<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    p: Prepare,
  ) {
    // Peer fault-repair: a `Prepare` answering our `RequestPrepare` for a committed-op hole is
    // handled BEFORE the view/role guards below — its op's content is view-independent (a committed op
    // is immutable), so a reply from a holder in any view fills the hole; we must NOT let the
    // higher-view rule yank us into a view change, nor the `is_primary`/same-view guards drop it (a
    // recovered PRIMARY can also hold a hole). `fill_repair` verifies (checksum + placement) and
    // returns false for a non-hole / unverifiable body, so a normal Prepare falls through unchanged.
    if self.fill_repair(now, storage, &p) {
      return;
    }
    // A registered repair hole is owned EXCLUSIVELY by the repair path:
    // `fill_repair` above already had its chance. If it DECLINED (a stale `commit < op`, an unverifiable
    // body, or — returning `true`, handled above — a RepairFill already in flight), this `Prepare` is
    // NOT the canonical fill for the hole, so drop it NOW — BEFORE the higher-view `catch_up_to_view`
    // below or the normal append / re-ack path can act on a hole-targeted `Prepare`. In particular a
    // higher-view non-canonical hole `Prepare` (which still passes the repair-hole ingress escape) must
    // NOT yank us into a spurious view change off a body the repair path explicitly rejected; the repair
    // solicitation re-asks until a committed-vouching `Prepare` fills the hole via `fill_repair`.
    if self.repair.contains(&p.op().get()) {
      return;
    }
    // STRICT epoch gate for the NORMAL head-advancing arm. The repair-serve arm above
    // (`fill_repair` + the hole-ownership guard) has already consumed any committed-hole serve, which
    // is AGNOSTIC (its `config_id` lineage was checked at the central ingress gate). Everything
    // reaching here drives the head: a `catch_up_to_view`, a normal append + `PrepareOk` vote, or a
    // current-view re-ack — all AUTHORITY in MY configuration, so the sending primary must be in MY
    // epoch. (The `config_id` half was already proven in-lineage at the central
    // `epoch_authority_admits` gate; in PR1 in-lineage == same-config, so this completes the strict
    // `(epoch, config_id)` match for the normal arm.) A foreign-epoch Prepare contributes nothing.
    if p.epoch() != self.membership.epoch() {
      return;
    }
    if p.view().get() > self.view.get() {
      self.catch_up_to_view(now, storage, p.view());
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
    //
    // EXCEPTION: a NORMAL-STATUS speculative CROSS-EPOCH sync ([`Self::cross_epoch_speculative_sync`]) is
    // TRANSPARENT here. That laggard is behind-but-OPERATIONAL in its OWN epoch: this SAME-epoch
    // head-extending `Prepare` is a legitimate op within reach (op+1), NOT below an out-of-reach cluster
    // checkpoint, so dropping it would freeze an operational replica out of its own epoch (the strict
    // ingress witness). It keeps appending + acking same-epoch ops; the cross-epoch sync sits armed (it may
    // never even get a reply) and crosses only when `apply_sync` installs the verified crossing checkpoint,
    // which then DISCARDS this same-epoch tail (the crossing install forces `held_tail = false`).
    if self.sync.is_some() && !self.cross_epoch_speculative_sync() {
      return;
    }
    // Durable-view-before-participate: a pending view-CHANGING superblock write means status==Normal
    // but our view is not yet persisted. Acking a prepare now would cast a vote in a view we could
    // regress out of on crash → cross-view double-vote. Drop it; the primary retransmits the prepare.
    // A backup's OWN commit-first SwapEpoch root in flight is NOT gated here ([`Self::pending_durable_view`]
    // excludes it): the view is durable through an epoch swap, so the `PrepareOk` vote (which carries
    // `self.view`, not the epoch) is sound — and continuing to ack keeps op-assignment live through the
    // swap window rather than stalling it on the backup's own root write.
    if self.pending_durable_view() {
      return;
    }
    // Learn the primary's commit (apply anything we already have). The commit tail can enter the
    // owed orphaned-re-persist reconciliation — the generation this prepare addressed is then
    // gone, so drop it (a Recovering node acks nothing; the primary retransmits).
    if self
      .advance_commit(now, storage, p.commit().get())
      .entered_recovery()
    {
      return;
    }

    let pop = p.op().get();
    if pop <= self.op.get() {
      // NOTE: a hole-targeted `Prepare` that `fill_repair` declined was ALREADY dropped at the top of
      // `on_prepare` (the hole-ownership guard, moved up to run before the higher-view
      // catch-up), so `pop` here is NEVER one of our registered repair holes — the re-ack /
      // interior-re-append branch below can never write a declined hole `Prepare` into the committed
      // hole's WAL slot nor mark it `appending` (which would masquerade as an in-flight RepairFill).
      // Already at/below the head; (re)ack so a lost prepare_ok is recovered. Ops are immutable within a
      // view, and the higher-view rule (top of this fn) + the `view != self.view` reject mean this
      // branch only fires for a current-view prepare.
      //
      // RE-ACK MUST PROVE IDENTITY. A re-ack is only sound if this replica genuinely holds
      // the CANONICAL body for `pop`. For an op ABOVE the checkpoint that is required: `self.log[pop]` must
      // EXIST and MATCH the incoming Prepare's identity `(client, request, body)`. Matching `self.log` ⇒
      // the WAL slot is the canonical body (the dense `log` cache mirrors the durable WAL except for a
      // dropped-stale slot). The OLD code consulted ONLY the WAL durability oracle (`op_durably_appended`),
      // which a `recover`-DROPPED stale slot still satisfies: recover drops a superseded interior op (its
      // header `view` < durable `log_view`) from `self.log` but the WAL slot still holds the
      // STALE view-0 body as `Clean`. So `op_durably_appended(pop)` was TRUE for a slot whose CANONICAL
      // body this replica does NOT hold → it false-acked the canonical Prepare off the stale body
      // (append-before-ack + committed-op-survival broken: a quorum could be this false ack + the primary,
      // and the primary crashing loses the op).
      //
      // An op AT/BELOW the checkpoint (`pop <= checkpoint_op`) is folded into the DURABLE snapshot — the
      // dense `log` cache was GC-pruned there, so it legitimately has no entry, yet the canonical body is
      // held (in the snapshot). It is durable by definition (`op_durably_appended`'s checkpoint clause) and
      // is NOT a dropped-stale slot, so it keeps the durability-gated re-ack (re-appending below the prune
      // floor would be wrong). In practice a primary never retransmits such an op (it is below the
      // primary's `commit_min`), so this fall-through is for a stray/buffered Prepare.
      // A body-`Repairing` entry does NOT hold the canonical body (only its checksum), so its
      // `body_bytes()` is `None` and the identity match fails — this op falls through to the re-append
      // path (it is itself awaiting the canonical body), never re-acked off an absent body. A
      // `Body::Reconfigure` op IS body-bearing — its `body_bytes()` is the `encode_body()` the
      // `RECONFIGURATION` `Prepare` carries, so a re-acked reconfiguration op matches by its wire bytes
      // exactly like a client op (the comparison is over the wire body, not the typed in-memory form).
      let canonical_held = pop <= self.checkpoint_op.get()
        || self.log.get(&pop).is_some_and(|entry| {
          entry.client == p.client()
            && entry.request == p.request()
            && entry.body_bytes().as_deref() == Some(p.body())
        });
      if canonical_held {
        // We hold the canonical body (in `self.log` above the checkpoint, or in the snapshot at/below it).
        // Append-before-ack: re-ack INLINE only if `pop` is DURABLE and not still IN FLIGHT.
        // The durability oracle is the WAL itself (`op_durably_appended`), NOT just `appending`: a view
        // change / catch-up clears `appending` while an async append abandoned in an old generation is
        // STILL staged in the WAL — and once such an op commits, the re-append range `(commit_min+1 ..=
        // op]` never re-marks it, so `appending` alone would wrongly green-light a re-ack of a
        // committed-but-still-in-flight op. We keep the `appending` guard too, so the
        // in-flight-then-just-completed window defers its single ack to `on_wal_done` (whose
        // `Pending::Ack(pop)` owes exactly one PrepareOk) rather than emitting a redundant inline duplicate.
        if !self.appending.contains(&pop) && self.op_durably_appended(storage, pop) {
          self.send_prepare_ok(p.op());
        }
        return;
      }
      // `self.log[pop]` is MISSING or MISMATCHED and `pop > checkpoint_op` — the dropped-stale interior
      // case. We must NOT re-ack (the stale/absent body is not the canonical one). The incoming
      // current-view Prepare carries the CANONICAL body (the top-of-fn guards already proved
      // `p.view() == self.view`), so durably (re)APPEND it — an INTERIOR overwrite at `pop < self.op` that
      // overwrites the stale WAL slot — and DEFER the ack to `on_wal_done` (a `Pending::Ack(pop)`), WITHOUT
      // rewinding `self.op`. The ack is then append-before-ack-correct: it waits for the canonical append
      // to land. (If an append for `pop` is already in flight — `appending` set — do NOT start a second
      // one; its own `on_wal_done` will ack once the in-flight append completes.)
      if !self.appending.contains(&pop) {
        self.reappend_canonical_prepare(storage, &p);
      }
      return;
    }
    if pop == self.op.get() + 1 {
      // a SUB-QUORUM laggard on a bounded ring may have fallen BELOW its ring window —
      // appending this head-extending op would PHYSICALLY overwrite an op it has not yet
      // checkpoint-subsumed (`pop - checkpoint_op > capacity`). It cannot hold the full live tail, so it
      // state-syncs to the cluster checkpoint instead of wrapping away a needed slot (and DROPS this
      // prepare). Inert for an unbounded WAL / an in-quorum backup (no overflow). Checked AFTER
      // `advance_commit` above, so a commit that just advanced the checkpoint can avert a needless sync.
      if self.maybe_sync_below_ring_window(now, storage, pop, p.checkpoint_op()) {
        return;
      }
      // Header-only view-change-carrier backpressure on the BACKUP head-extend — the unbounded-WAL
      // analogue of the ring-window stall above, gating the carrier instead of the ring (see
      // [`Self::band_at_capacity`]). REFUSE to extend the head (drop this prepare; the primary
      // retransmits); releases as the backup checkpoints + `run_gc` trims `self.log`.
      if self.band_at_capacity() {
        return;
      }
      self.append_prepare(storage, p);
      // Drain any buffered, now-contiguous prepares — each also extends the head, so it too could fall
      // below the ring window OR push the carrier band past the frame-fit depth. Stop draining at the
      // first op that would overflow (it + every higher buffered op is unreachable until the sync just
      // armed installs / a checkpoint frees band; the `sync.is_some()` guard then drops their retransmits,
      // and a later heartbeat re-drains the buffer once the band has room).
      while let Some(next) = self.buffer.get(&(self.op.get() + 1)) {
        let (next_op, next_ckpt) = (next.op().get(), next.checkpoint_op());
        let (next_view, next_epoch) = (next.view(), next.epoch());
        // A buffered `Prepare` stamped for an OLD view/epoch must NEVER be spliced into the current view. A
        // backup carries its reorder `buffer` across a `StartView` adoption (`adopt_canonical_head` keeps it
        // by design), so after a view/epoch advance a stale entry can still sit here — and the new view may
        // have re-minted a DIFFERENT op at this number. `LogEntry` records no per-entry view, so a spliced
        // stale body is indistinguishable later: it would apply off a `Commit` heartbeat (agreement
        // violation) or poison a future DVC. Drop it; the current primary's canonical `Prepare` for this op
        // re-extends the head. Mirrors the `on_prepare` ingress epoch+view gate the buffered entry bypassed
        // (it was admitted under a prior view). A stale entry is a hole, so draining stops here — any higher
        // buffered op is unreachable until the real current-view `Prepare` fills the gap.
        if next_epoch != self.membership.epoch() || next_view != self.view {
          self.buffer.remove(&(self.op.get() + 1));
          break;
        }
        if self.maybe_sync_below_ring_window(now, storage, next_op, next_ckpt)
          || self.band_at_capacity()
        {
          break;
        }
        let next = self
          .buffer
          .remove(&(self.op.get() + 1))
          .expect("just peeked");
        self.append_prepare(storage, next);
      }
      // After appending, apply any ops now available up to the learned commit. Nothing follows in
      // this arm, so a teardown in the tail has nothing left to short-circuit; discard the flow.
      let target = self.commit_max.get();
      let _ = self.advance_commit(now, storage, target);
    } else {
      // Future op: buffer it, and solicit the committed band between our head and it that the primary's
      // retransmit (only `commit_min+1..=op`) will never re-send (those ops are `<= commit_min`). This
      // fills the gap so the buffered op becomes reachable instead of stranding the backup at its head.
      //
      // BOUNDED: only an op within [`TAIL_GAP_WINDOW`] of the head is buffered — each entry can hold
      // a frame-sized body, so an in-threat-model buggy primary emitting sparse far-future Prepares
      // must not grow the buffer without bound. A beyond-window Prepare is DROPPED, the same
      // backpressure shape as the ring stall: it is unreachable until the head closes the gap (one
      // tail-gap window at a time) anyway, and the primary's retransmit redelivers it once it is.
      if pop <= self.op.get().saturating_add(TAIL_GAP_WINDOW) {
        self.buffer.insert(pop, p);
      }
      self.request_tail_gap();
    }
  }

  /// Apply the primary's batched prepare retransmit ([`crate::PrepareBatch`]): reconstruct the per-op
  /// [`Prepare`] from the batch envelope (`view`/`commit`/`checkpoint_op`) + each entry's
  /// (`op`/`client`/`request`/body) and feed it through the ordinary [`Self::on_prepare`] ingress.
  /// This is purely an UN-BATCHING — NOT a parallel prepare path: every per-op gate (the repair-fill
  /// short-circuit, the higher-view catch-up, the status/view/role guards, the sync drop, the
  /// durable-view drop, the ring-window/band-cap stalls, the re-ack identity proof, the tail-gap
  /// buffer window) re-evaluates per entry inside `on_prepare` itself, so a batch of N entries is
  /// semantically the N separate `Prepare` deliveries it replaces, in the same ascending-op order.
  /// An entry a gate drops is dropped exactly as its per-op form would be (the primary's next
  /// retransmit re-ships it); a header-only (`Repairing`) entry carries no bytes to prepare, so it
  /// is SKIPPED — the sender never emits one (its retransmit loop skips its own holes), and
  /// hole-filling is owned by the windowed repair channel, not the retransmit.
  pub(crate) fn on_prepare_batch<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    m: crate::PrepareBatch,
  ) {
    let (view, commit, checkpoint_op, epoch, config_id) = (
      m.view(),
      m.commit(),
      m.checkpoint_op(),
      m.epoch(),
      m.config_id(),
    );
    for e in m.into_log() {
      // The wire body bytes are taken from the entry via `body_bytes()` — a `Present` op's bytes or a
      // `Reconfigure` op's `encode_body()` (both body-bearing); a header-only (`Repairing`) entry has no
      // body and is SKIPPED (the sender never batches its own holes). The reconstructed per-op `Prepare`
      // carries the flat bytes; `on_prepare` rebuilds the typed `Body::Reconfigure` from the
      // `RECONFIGURATION` client id, so a batched reconfiguration op un-batches identically to a client op.
      let (op, client, request, body) = e.into_parts();
      let Some(body) = body.body_bytes() else {
        continue;
      };
      self.on_prepare(
        now,
        storage,
        // Each reconstructed per-op `Prepare` carries the BATCH's epoch-policy pair (the envelope
        // every per-op `Prepare` would have carried), not this replica's — the un-batching preserves
        // the sender's `(epoch, config_id)` exactly as it preserves `view`/`commit`/`checkpoint_op`.
        Prepare::new(
          view,
          op,
          commit,
          checkpoint_op,
          epoch,
          config_id,
          client,
          request,
          body,
        ),
      );
    }
  }

  /// Whether the retained `self.log` band has reached the header-only view-change-carrier frame-fit
  /// depth — the SINGLE source of truth for the carrier backpressure on every path that GROWS
  /// `self.log` (the primary's `on_request` op mint, the backup's `on_prepare` head-extend + buffer
  /// drain). Two clauses, each load-bearing for a different carrier:
  ///
  /// - **The COUNT clause (`self.log.len()`) bounds THIS replica's own carrier.** The carrier is the
  ///   ACTUAL retained log: `log_entries()` emits one HEADER-ONLY entry per `self.log` op (no range
  ///   filter), so `self.log.len()` IS the entry count a `DoViewChange` / `StartView` /
  ///   `RecoveryResponse` would encode. At `MAX_HEADER_ONLY_BAND_DEPTH` the next growth would make
  ///   the carrier exceed `MAX_FRAME_LEN` (the transport then drops it on the send path — wedging a
  ///   view change/recovery). Gating on the len — NOT a `next_op - prune_floor` proxy — is
  ///   load-bearing: `prune_floor` advances the instant a quorum checkpoint REPORT raises
  ///   `quorum_checkpoint_op`, but `self.log` is trimmed only by `run_gc` at the next LOCAL
  ///   checkpoint, so the proxy can sit below the real retained span (GC lag) and under-count.
  ///
  /// - **The SPAN clause (`op - log_floor`) bounds the next view change's FLOORED UNION.** The len
  ///   alone does not bound the band's op-number WIDTH: interior holes (recovery-faulty drops,
  ///   repair-pending gaps) let the head extend while the count stays flat, so `op - log_floor`
  ///   can outrun the len. `select_canonical_log` floors its cross-donor union at the canonical
  ///   generation's max advertised floor and bounds the union's entry count by the HEAD donor's span
  ///   `op_head - its log_floor` — so every replica must keep that span within the same depth, or
  ///   its band (unioned with a lower-floor donor's) could push the canonical carrier over the
  ///   frame even though each donor's len was individually within bound. Same backpressure, gating
  ///   the SPAN the union inherits rather than the count this replica re-emits.
  ///
  /// Both release as the replica checkpoints/state-syncs (run_gc trims the len; `log_floor` rises
  /// with the checkpoint, shrinking the span). The bound is huge (~342k), far above any realistic
  /// in-flight band, so this never perturbs normal liveness or the VOPR — a release-build frame-fit
  /// floor under `log_entries()`'s / `select_canonical_log`'s `debug_assert`s, not a normal-path
  /// limit.
  fn band_at_capacity(&self) -> bool {
    self.log.len() >= crate::message::MAX_HEADER_ONLY_BAND_DEPTH
      || self.op.get().saturating_sub(self.log_floor.get())
        >= crate::message::MAX_HEADER_ONLY_BAND_DEPTH as u64
  }

  /// Build the in-memory [`LogEntry`] for a backup appending `p`, choosing ONE typed representation
  /// so a committed `Body::Reconfigure` op is recognized uniformly on the primary AND every backup
  /// (decision (a) — a single representation everywhere avoids a decode-at-commit footgun). Delegates to
  /// the shared [`LogEntry::from_committed_body`] reconstruction: a [`ClientId::RECONFIGURATION`]
  /// prepare's flat wire `body` decodes back to a typed `Body::Reconfigure`; every other prepare is a
  /// `Body::Present` client op carrying the raw bytes. The WAL still stores the body BYTES regardless
  /// (the caller's `submit_append` already ran) — only the in-memory `LogEntry::body` distinguishes the
  /// two. The repair-fill and recovery WAL-read paths reconstruct through the SAME helper, so a
  /// RECONFIGURATION op is never type-erased into a `Present` op on any ingress path.
  pub(crate) fn log_entry_from_prepare(&self, p: &Prepare) -> LogEntry {
    LogEntry::from_committed_body(p.client(), p.request(), p.body_bytes())
  }

  /// Whether `payload`'s successor, chained from THIS node's current configuration (the payload pins
  /// its exact predecessor and it matches), seats a brand-new voter — the unsafe direct voter
  /// admission the commit-time fence in [`Self::commit_reconfigure`] refuses. The shared core of
  /// every screen: the append-seam `Prepare` drop ([`Self::is_direct_voter_add_prepare`]) and the
  /// vote-mint refusals ([`Self::op_is_direct_voter_add`]). A payload pinned to a DIFFERENT
  /// predecessor is deliberately NOT classified — this node cannot evaluate the diff without holding
  /// that predecessor; if such an op ever commits, the commit-time fence at its pinned predecessor
  /// is the authority (and the predecessor pin in `commit_reconfigure` means a mismatched op can
  /// never stage a swap HERE either).
  fn seats_new_voter_against_current(&self, payload: &crate::message::ReconfigurePayload) -> bool {
    payload.prev_config_id() == self.membership.config_id()
      && self
        .membership
        .first_new_voter(payload.replica_count(), payload.members())
        .is_some()
  }

  /// Whether the entry this replica holds at `op` is a reconfiguration op seating a brand-new voter
  /// against the CURRENT configuration ([`Self::seats_new_voter_against_current`]), read from the
  /// TYPED log body — every lane that stores a reconfiguration op stores it typed
  /// (`Body::Reconfigure`: the prepare append, the view-change adoption, the peer-repair fill, and
  /// recovery's rebuild), so the vote-mint screens classify without a re-decode. `false` for an
  /// absent entry (an op at/below the checkpoint is committed, and a committed reconfiguration
  /// already passed — or refused — the commit-time fence) and for a header-only `Repairing` body
  /// (no vote is ever cast off an absent body: the re-ack identity match fails, the adoption
  /// re-append skips it, and the repair fill inserts the typed body before its completion votes).
  pub(crate) fn op_is_direct_voter_add(&self, op: u64) -> bool {
    self.log.get(&op).is_some_and(|e| {
      e.body
        .as_reconfigure()
        .is_some_and(|payload| self.seats_new_voter_against_current(payload))
    })
  }

  /// Whether `p` carries a reconfiguration whose successor seats a brand-new voter against THIS
  /// node's current configuration ([`Self::seats_new_voter_against_current`]) — the append-seam form
  /// of the screen, evaluated on the incoming `Prepare` BEFORE it reaches the log. Dropping at the
  /// seam is ingress hygiene: the op burns no WAL slot, takes no log entry, and is never carried
  /// into a `DoViewChange`/`StartView` from here. The vote-safety AUTHORITY is the pair of mint
  /// screens — [`Self::send_prepare_ok`] refuses the ack and [`Self::record_own_vote`] refuses the
  /// own bit — which cover every ack/vote lane, including an entry that reaches the log without
  /// crossing this seam (a view-change adoption, a recovered WAL). A decode failure falls through
  /// unscreened (the append path's shared reconstruction owns that handling).
  fn is_direct_voter_add_prepare(&self, p: &Prepare) -> bool {
    if p.client() != ClientId::RECONFIGURATION {
      return false;
    }
    let Ok(payload) = crate::message::ReconfigurePayload::decode_body(p.body()) else {
      return false;
    };
    self.seats_new_voter_against_current(&payload)
  }

  fn append_prepare<W: Wal, B: Superblock>(&mut self, storage: &mut Storage<W, B, S>, p: Prepare) {
    // Refuse a direct voter admission at the append seam: dropped exactly like the ring-window/band
    // stalls (no WAL write, no log entry, no head advance, and — by append-before-ack — no PrepareOk),
    // so the op cannot commit on compliant replicas. See `commit_reconfigure`'s fence for the safety
    // argument. Screening inside the append seam covers the head-extend, the buffered-prepare drain
    // (which removes an entry before appending it, so a dropped entry cannot re-drain), and every
    // future caller by construction.
    if self.is_direct_voter_add_prepare(&p) {
      return;
    }
    // the backup-overflow guard ([`Self::maybe_sync_below_ring_window`]) runs in
    // `on_prepare` BEFORE every head-extend append (the new-op branch + each buffered-prepare drain), so
    // an append never overwrites an un-pruned slot of the EFFECTIVE ring ([`effective_wal_capacity`] —
    // the backend's own ring, or the proto-imposed ring for a ring-less backend). This debug-assert
    // FREEZES that contract: a future caller that extends the head without the guard (re-opening the
    // resident-tail-overflow class — `recover` would then read a wrapped-away op) trips it.
    // `pop == self.op + 1 > checkpoint_op` here, so the condition asserted is the exact negation of the
    // guard's overflow test (`pop - checkpoint_op > effective`).
    debug_assert!(
      p.op().get().saturating_sub(self.checkpoint_op.get()) <= self.effective_wal_capacity(storage),
      "WAL-ring backup-overflow: appending op {} would overwrite an un-pruned ring slot \
       (checkpoint_op={}, effective capacity={}) — the maybe_sync_below_ring_window guard was bypassed",
      p.op().get(),
      self.checkpoint_op.get(),
      self.effective_wal_capacity(storage),
    );
    self.op = p.op();
    let header = Header::new(p.op(), p.view(), p.client(), p.request(), p.body());
    // Through the slot-quiescence choke: a backup's head extension can reuse an op number a
    // truncation released (or ring-wrap a GC-freed slot) whose old write is still in flight.
    self.submit_or_defer_append(
      storage,
      p.op(),
      header,
      p.body_bytes(),
      Pending::Ack(p.op()),
    );
    let entry = self.log_entry_from_prepare(&p);
    self.log.insert(p.op().get(), entry);
    // Append-before-ack: mark op in-flight so neither this op's deferred ack NOR a
    // retransmit-driven re-ack (`on_prepare`'s `pop <= self.op` branch) can emit a PrepareOk before
    // `on_wal_done` clears it. PrepareOk is deferred to on_wal_done when the append is durable.
    self.appending.insert(p.op().get());
  }

  /// Durably (re)append an INTERIOR current-view `Prepare` at `pop < self.op` whose `self.log` entry is
  /// MISSING or MISMATCHED, then DEFER the ack to `on_wal_done`. Unlike [`Self::append_prepare`]
  /// this does NOT advance (rewind) `self.op` — it is an interior overwrite of one stale/absent slot, not a
  /// head extension — and it does not drain the buffer (a head concern). It overwrites the canonical body
  /// into the `log` cache + the durable WAL slot (so a future read / DVC / crash-restart serves the canonical
  /// op, never the stale one) and records a `Pending::Ack(pop)` so the single PrepareOk follows durability
  /// (append-before-ack). Caller guarantees `pop` is not already `appending` (no double in-flight append) and
  /// that the Prepare is current-view (`p.view() == self.view`), so overwriting the slot is safe: the op is
  /// either committed-or-current-view-canonical, and only a stale superseded earlier-view body is replaced.
  fn reappend_canonical_prepare<W: Wal, B: Superblock>(
    &mut self,
    storage: &mut Storage<W, B, S>,
    p: &Prepare,
  ) {
    // The same direct-voter-admission screen as `append_prepare`: an interior overwrite also appends
    // and acks, so it must equally refuse to seat a brand-new voter (drop; no overwrite, no ack).
    if self.is_direct_voter_add_prepare(p) {
      return;
    }
    // The interior overwrite obeys the same ring-window discipline as every other append lane
    // (`maybe_sync_below_ring_window` on the head-extends, the `adopt_append`/`fill_repair` wrap
    // guards): physically writing this slot from more than a full window above `checkpoint_op`
    // would evict the un-pruned op one ring below it, which recovery and peer repair may still
    // need. Drop instead — the primary's retransmit re-delivers this Prepare, and the laggard's
    // committed-band catch-up keeps its ordinary checkpoints firing, so the window slides until
    // the re-delivery fits.
    if self.ring_append_would_wrap(storage, p.op().get()) {
      return;
    }
    let header = Header::new(p.op(), p.view(), p.client(), p.request(), p.body());
    // Through the slot-quiescence choke: an interior overwrite by definition re-targets a slot an
    // earlier write may still hold in flight (its own superseded stale append included).
    self.submit_or_defer_append(
      storage,
      p.op(),
      header,
      p.body_bytes(),
      Pending::Ack(p.op()),
    );
    let entry = self.log_entry_from_prepare(p);
    self.log.insert(p.op().get(), entry);
    // Mark in-flight so a further retransmit-driven re-ack defers to `on_wal_done` (which clears it +
    // sends the single PrepareOk once the canonical append is durable). NO head rewind: `self.op` stays.
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
  pub(crate) fn op_durably_appended<W: Wal, B: Superblock>(
    &self,
    storage: &Storage<W, B, S>,
    op: u64,
  ) -> bool {
    op <= self.checkpoint_op.get()
      || matches!(
        storage.wal().status(OpNumber::with(op)),
        SlotStatus::Clean | SlotStatus::Faulty
      )
  }

  /// The single append-before-ack choke point: emits a `PrepareOk` for `op` to the primary. `op` MUST
  /// be durable — NOT in `self.appending` — at every call. The `debug_assert!` is the systematic guard
  ///: any future caller that tries to ack an op whose WAL append is still in flight trips
  /// in tests, so the violation class cannot silently relocate. Callers (`on_wal_done` after the append
  /// lands; `on_prepare`'s in-flight-gated re-ack branch) are responsible for not calling this for an
  /// in-flight op — this assert backstops that contract.
  pub(crate) fn send_prepare_ok(&mut self, op: OpNumber) {
    if self.is_learner() {
      // A non-voting replica applies the committed log but never acknowledges a prepare: its ack would
      // be dropped at the primary's vote ingress regardless, and a learner is outside every quorum.
      return;
    }
    debug_assert!(
      !self.appending.contains(&op.get()),
      "append-before-ack: PrepareOk for op {} whose WAL append is still in flight",
      op.get()
    );
    // Never vouch for a reconfiguration op that seats a brand-new voter against this node's current
    // configuration. This is the ack half of the vote-mint screen pair (the own-vote half is
    // [`Self::record_own_vote`]): every `PrepareOk` is minted here — the append completion, the
    // canonical re-ack, and the view-change adoption re-ack all funnel through — so refusing at the
    // mint covers each lane, including an entry that reached the log WITHOUT crossing the screened
    // prepare append (a view-change adoption, a recovered WAL). Withholding the ack starves the op
    // of a compliant quorum, which is what keeps the commit-time fence in
    // [`Self::commit_reconfigure`] unreachable rather than a cluster-wide fail-stop. The
    // checkpoint-report re-ack ([`Self::report_checkpoint_to_primary`]) passes an at/below-checkpoint
    // op whose entry is GC-pruned: the screen reads no entry and lets it through — that op is
    // committed (the commit-time fence already ruled on it), and the report's vote is inert (its
    // identity stamp matches no live inflight entry).
    if self.op_is_direct_voter_add(op.get()) {
      return;
    }
    // Content-address the vote: stamp the OPERATION IDENTITY (client, request, body_checksum) of the op
    // THIS replica actually holds at `op`, so the primary counts it only against the operation it is
    // itself driving (a stale or different-operation ack — even a same-body one for a re-minted op
    // number — carries a different identity and is dropped). The op is `Present` in `self.log` for every
    // real ack/re-ack of an above-checkpoint op (it was just appended). The lone exception is
    // `report_checkpoint_to_primary`'s re-ack of `checkpoint_op` (a pure checkpoint REPORT, not a commit
    // vote): that op is folded into the snapshot and GC-pruned from `self.log`, so it has no entry and
    // stamps `0` — harmless, since the primary holds no live `inflight` entry at `checkpoint_op` to
    // match the vote against (it re-ORs an already-pruned bit, a no-op).
    let prepare_checksum = self
      .log
      .get(&op.get())
      .map(|e| crate::storage::prepare_identity(e.client, e.request, e.body.body_checksum()))
      .unwrap_or(0);
    let primary = self.membership.primary(self.view);
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(primary)),
      Message::PrepareOk(PrepareOk::new(
        self.view,
        op,
        self.local_slot(),
        self.checkpoint_op,
        prepare_checksum,
        self.membership.epoch(),
        self.membership.config_id(),
      )),
    ));
  }

  /// Applies committed ops we hold, up to `min(target, op)`, strictly in order. Backups discard the
  /// reply but emit `Committed` so observers can verify agreement.
  ///
  /// Returns the commit tail's status outcome: [`CommitFlow::EnteredRecovery`] when the tail tore
  /// the generation down into the recovery peer-fetch, on which every caller must short-circuit
  /// (see [`CommitFlow`]).
  pub(crate) fn advance_commit<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    target: u64,
  ) -> CommitFlow {
    // A PRE-ROOT staged install (`pending_install`) is about to wholesale-REPLACE the SM at the synced
    // point (`install_sync`), and keeps `commit_min`/`commit_max`/`self.op` FROZEN across the STAGE→install
    // window so the install is the single atomic mutation point (the captured held-tail decision + the
    // monotonic advances stay exactly as at STAGE, no commit_max rewind). Return BEFORE learning the commit.
    if self.pending_install.is_some() {
      return CommitFlow::Continue;
    }
    // Record the learned commit regardless of whether we hold — or can yet apply — the ops: `commit_max` is
    // a re-learnable HINT, not an apply effect. An SM-reconstruct-owed node MUST still raise it, unlike the
    // frozen install case: otherwise a view change it wins forms with a stale `commit_max` (the
    // `advance_commit(commit_star)` in `start_view_as_new_primary` would no-op below), and the
    // repair-or-truncate grace then classifies genuinely-committed header-only ops in `(checkpoint_op,
    // commit*]` as truncation candidates (`op > commit_max`) and can truncate a client-acked op.
    self.commit_max = OpNumber::with(self.commit_max.get().max(target));
    // SM-RECONSTRUCT owed (`sm_reconstruct`): a post-root restore faulted, so `self.checkpoint_op == M` is
    // durable but the SM still holds the OLD content — applying an op over it would corrupt committed state
    // (the warm analogue of cold-start `recover()`'s un-reconstructed-SM window). We LEARNED the commit
    // above but must NOT apply here; the retry reconstructs the SM under the fixed M pointer and ops
    // re-apply via the next Commit/Prepare once the obligation clears.
    if self.sm_reconstruct_owed() {
      return CommitFlow::Continue;
    }
    while self.commit_min.get() < target && self.commit_min.get() < self.op.get() {
      let op = self.commit_min.get() + 1;
      // Faults-as-data (peer fault-repair): a committed op whose body read back
      // permanently faulty (bit-rot / torn) is ABSENT from the dense `log` cache (the recover loop
      // dropped it rather than adopt a wrong/empty body), OR is present as a body-`Repairing` HOLE (the
      // op's existence survived but its bytes did not). Instead of panicking, HOLD the commit at the
      // hole — never skip op N to apply N+1 — and fetch the WHOLE contiguous hole run from a peer
      // (`RequestPrepareRange` → `RepairBatch`), windowed so a deep header-only band (a view-change
      // carrier carrying the whole uncheckpointed log as `Repairing` holes) is repaired PIPELINED rather
      // than one round trip per op; a later advance_commit (after the ops arrive) resumes from exactly here.
      let Some(entry) = self.log.get(&op).cloned() else {
        self.request_repair_run(now, op);
        break;
      };
      // Consensus-layer reconfiguration: a `Body::Reconfigure` op is NOT applied to the SM — at commit
      // it stages the COMMIT-FIRST epoch swap (the durable swap install is deferred to its SwapEpoch
      // root). Recognized BEFORE the `as_present` hole check below (a `Reconfigure` body is
      // `as_present() == None`, which would otherwise route it to peer-repair). The op IS committed, so
      // `commit_min` advances past it; the loop then continues to any further committed ops. Identical
      // recognition to the primary's `commit_op`, so primary and backup install the SAME successor.
      if self.commit_reconfigure(op, &entry.body, storage) {
        continue;
      }
      let Some(body) = entry.body.as_present() else {
        // A body-absent (`Repairing`) hole: handled EXACTLY like a wholly-missing slot above — hold the
        // commit and peer-repair the contiguous hole run.
        self.request_repair_run(now, op);
        break;
      };
      let reply = self.sm.apply(OpNumber::with(op), body);
      self.note_sm_advanced(OpNumber::with(op));
      // Reply-size contract (see `StateMachine::apply`): mirrors the primary's apply-site assert.
      debug_assert!(
        reply.len() <= crate::message::max_reply_body_len(),
        "StateMachine::apply returned a {}-byte reply for op {} (> max_reply_body_len {}): the \
         Reply cannot be framed and the committed result is undeliverable",
        reply.len(),
        op,
        crate::message::max_reply_body_len(),
      );
      self.set_commit_min(OpNumber::with(op));
      // The SHARED apply-time session update (watermark + reply cache + last-activity stamp +
      // deterministic cap eviction; see [`Self::note_applied_session`]) — identical to the primary's
      // `commit_op`, so primary and backups converge on identical tables at identical applied ops.
      self.note_applied_session(op, entry.client, entry.request, &reply);
      self
        .events
        .push_back(Event::Committed(crate::Committed::new(
          OpNumber::with(op),
          entry.client,
          entry.request,
          reply,
        )));
    }
    // If applying past a filled repair hole has carried `commit_min` to/past an
    // outstanding FORCED sync's target, the hole the force-sync was working around is recovered the cheap
    // way — cancel the now-unneeded forced sync (clears `sync` + its solicit timer) so a delayed, stale
    // SyncCheckpoint for that target never reaches `apply_sync` below the advanced frontier.
    self.cancel_forced_sync_if_satisfied();
    // Adopt an owed INHERITED checkpoint frontier first (commit_min may have just reached it), so
    // the cadence below computes its boundary off the adopted pointer in the same tail — then
    // re-drive an owed orphaned-re-persist reconciliation the settle site had to defer (its
    // deferral conditions clear on events this tail observes). Entering it ends the generation:
    // nothing below runs over the teardown, and the caller short-circuits on the returned flow.
    self.maybe_adopt_inherited_frontier();
    if self
      .maybe_enter_orphan_repersist_recovery(now, storage)
      .entered_recovery()
    {
      return CommitFlow::EnteredRecovery;
    }
    // commit_min may have advanced past a checkpoint boundary — take a checkpoint if due.
    self.maybe_checkpoint(storage);
    // Pay any swap-checkpoint DEBT (`config_install_op > checkpoint_op` on a recovered root): commit just
    // advanced, so if it reached the reconfigure op force the owed checkpoint. The re-entrancy guard makes
    // this routine's own `advance_commit` a no-op here (the loop above already drove commit). No-op when
    // no debt is owed (the common path).
    self.maybe_pay_checkpoint_debt(now, storage);
    // Re-submit a staged epoch swap waiting for a free superblock slot (mirrors `try_commit`'s tail) —
    // chiefly a `pending_swap` that survived a `catch_up_to_view` view change (no durable-view write, so
    // no `on_sb_done` re-trigger). No-op unless a swap is staged and the superblock is free.
    self.maybe_swap_epoch(storage);
    CommitFlow::Continue
  }

  /// The SINGLE apply-time client-session update, shared by the primary's [`Self::commit_op`] and the
  /// backup's [`Self::advance_commit`] so both roles run the IDENTICAL update at the IDENTICAL applied
  /// op — the structural basis of session-table determinism (the table rides every checkpoint
  /// envelope, so divergent updates would diverge checkpoint content across replicas).
  ///
  /// Per applied op it:
  /// - advances the at-most-once dedup WATERMARK (monotone max — the watermark a backup-turned-primary
  ///   needs in `on_request`; tracked at every apply, NOT reconstructed from the GC-pruned `log`, and
  ///   also restored from checkpoint snapshots, so it survives GC and restores);
  /// - caches the REPLY body whenever this apply is the freshest for the session (no LATER request's
  ///   reply already cached — per-client requests apply in order, so the guard only rejects a stale
  ///   overwrite). Caching on EVERY replica closes the failover lost-reply gap: a backup-turned-primary
  ///   resends the cached reply to a duplicate whose original reply was lost. The watermark and the
  ///   reply cache are deliberately SEPARATE concerns: the watermark can sit at/above this request
  ///   without a cached reply (accept-time seeding, snapshot restore, view-change backfill), and gating
  ///   the cache on the watermark advancing would then skip the reply forever (the client's retry would
  ///   dedup with no reply — a permanent hang);
  /// - stamps the session's LAST-ACTIVITY op (`last_op = op` — a row's first stamp makes it APPLIED,
  ///   visible to the eviction order below);
  /// - enforces the session cap ([`Config::max_client_sessions`]) by DETERMINISTIC EVICTION: when this
  ///   apply grew the APPLIED-session count past the cap, evict the session with the smallest
  ///   `(last_op, client)` — the oldest-activity row, ties (only possible among restored/injected
  ///   rows; live applied stamps are unique) broken by lowest client id. The decision reads ONLY
  ///   applied rows (`last_op > 0`): provisional accept-time/backfill rows exist solely on the replica
  ///   that minted them, so counting or evicting them would diverge primary and backup tables — they
  ///   stay invisible until their own op applies (identically everywhere). The evicted client's
  ///   at-most-once history is gone — the table-residency contract on [`crate::MAX_CLIENT_SESSIONS`].
  fn note_applied_session(
    &mut self,
    op: u64,
    client: ClientId,
    request: RequestNumber,
    reply: &Bytes,
  ) {
    let session = self.clients.entry(client.get()).or_default();
    let newly_applied = session.last_op.get() == 0;
    session.last_op = OpNumber::with(op);
    if request.get() > session.request.get() {
      session.request = request;
    }
    if session
      .reply
      .as_ref()
      .is_none_or(|(rn, _)| rn.get() <= request.get())
    {
      session.reply = Some((request, reply.clone()));
    }
    // The applied count can only have GROWN if this apply turned a provisional/absent row applied;
    // the (rare) count + eviction scan runs only then, never on the steady per-op path.
    if !newly_applied {
      return;
    }
    let cap = self.config.max_client_sessions() as usize;
    let mut applied = self
      .clients
      .values()
      .filter(|s| s.last_op.get() > 0)
      .count();
    while applied > cap {
      let victim = self
        .clients
        .iter()
        .filter(|(_, s)| s.last_op.get() > 0)
        .map(|(&c, s)| (s.last_op.get(), c))
        .min()
        .map(|(_, c)| c)
        .expect("an over-cap applied table is non-empty");
      // `cap >= 1` (Config-validated) and `applied > cap` ⇒ at least two applied rows, and the
      // just-applied row holds the maximal `last_op` (this op) — so the minimum is never it.
      debug_assert!(
        victim != client.get(),
        "the just-applied session must never be its own eviction victim"
      );
      self.clients.remove(&victim);
      self.sessions_evicted += 1;
      applied -= 1;
    }
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
  /// under an adversarial fault schedule (a laggard crashed while two backups were transiently behind).
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
    // A NORMAL-STATUS speculative cross-epoch sync ([`Self::cross_epoch_speculative_sync`]) is transparent
    // here too: the operational laggard still tail-gap-repairs the SAME-epoch committed band above its head
    // (those ops are in reach, NOT below the cluster checkpoint), staying caught up in its own epoch until
    // the crossing checkpoint lands. An ordinary / forced sync still suppresses tail-gap (futile — the gap
    // is below the cluster checkpoint, state-sync territory).
    if !self.status.is_normal()
      || self.is_primary()
      || (self.sync.is_some() && !self.cross_epoch_speculative_sync())
    {
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

  /// Cross-epoch catch-up trigger. A `Prepare`/`Commit` (or a minimal `EpochAhead` hint) from a STRICTLY
  /// HIGHER epoch than ours is inadmissible at the central ingress (its descendant `config_id` is absent
  /// from our ancestor lineage, and we must not act on a not-yet-reached configuration's content). But it
  /// is the catch-up HEARTBEAT we otherwise lost: once the cluster swapped epochs, the primary's
  /// heartbeats became epoch-inadmissible, so the periodic catch-up that `on_commit` drives never
  /// re-fires — and a voter that lagged at the reconfigure commit strands at the OLD epoch. We trust NONE
  /// of this message's content; we act only on the epoch-ordering signal that a configuration ahead of
  /// ours exists, and the catch-up state we fetch is self-verifying.
  ///
  /// The `EpochAhead` shape is the SYMMETRIC pull (the epoch-mismatch response in `handle_message_inner`):
  /// a slot-shifted laggard that cannot bind the new primary keeps sending FUTILE old-epoch traffic to the
  /// RETAINED voters it CAN bind; one of those ANSWERS with this minimal higher-epoch hint, so the laggard
  /// triggers the SAME forced peer-fetch from a bindable peer it already knows — it never needs to bind the
  /// new primary. The hint carries NO quorum authority a forged one could abuse (the crossing fetch
  /// authenticates the state, not the hint).
  ///
  /// Both laggard shapes UNIFY at the CROSSING REQUIREMENT (a FORCED, crossing-required sync to the
  /// advertised cluster checkpoint that completes ONLY on a strictly-higher-epoch successor-membership
  /// checkpoint at/above target) — but NOT at the STATUS transition:
  ///
  /// - **non-Normal** (a `ViewChange`/`Recovering` laggard, already off Normal): crosses via the recovery
  ///   peer-fetch ([`Self::enter_cross_epoch_peer_fetch`] — enter `Recovering`, FORCED-sync, then
  ///   `complete_recovery` lands it `Normal` at E+1). There is no Normal state to preserve.
  /// - **Normal** (a behind-but-OPERATIONAL voter): arms a NORMAL-STATUS crossing-required sync and STAYS
  ///   Normal. A single higher-epoch message from a configured member must NOT knock an operational laggard
  ///   out of Normal — doing so would make it DROP subsequent LEGITIMATE same-epoch traffic (the strict
  ///   ingress witness). It transitions to E+1 ONLY when `apply_sync` installs the verified crossing
  ///   checkpoint (which advances `commit_min` to `M >= N`, installs the successor membership, and discards
  ///   the stale tail) — so the speculative arm itself moves no accumulator (`op`/`commit`/`view` are
  ///   untouched until install). A higher-epoch message no longer disrupts the strict-epoch lane.
  ///
  /// The forced sync is NOT `> op`-gated, so it crosses even when `op == N` (the laggard appended the
  /// reconfigure op but missed its commit). The SyncCheckpoint we fetch is self-verifying (its
  /// `checkpoint_id` + the successor's `config_id` hash-chain are checked in `apply_sync`), so a forged
  /// higher-epoch heartbeat cannot install unvouched state.
  ///
  /// The triggering message is still DROPPED by the caller (we acted on no E+1 content).
  pub(crate) fn maybe_request_cross_epoch_catchup<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    from: Peer,
    msg: &Message,
  ) {
    // The trigger is a STRICTLY-higher-epoch `Prepare`/`Commit`, regardless of our status. The
    // `checkpoint_op` it advertises is the cluster checkpoint a Normal laggard syncs toward. Run this
    // BEFORE `sender_matches`'s predecessor-primary binding: a live removal can change the primary slot,
    // so the honest E+1 primary is a DIFFERENT retained voter the laggard does not yet expect for its
    // view — its heartbeat would otherwise be dropped at the sender binding before reaching here.
    let checkpoint = match msg {
      Message::Prepare(m) if m.epoch() > self.membership.epoch() => m.checkpoint_op(),
      Message::Commit(m) if m.epoch() > self.membership.epoch() => m.checkpoint_op(),
      // The SYMMETRIC pull: a stranded laggard whose own futile old-epoch traffic elicited a minimal
      // higher-epoch hint from a BINDABLE retained voter (the epoch-mismatch response below). It carries
      // NO quorum content — only the epoch-ordering signal + the cluster checkpoint to cross to — so it
      // drives the SAME forced peer-fetch as a higher-epoch heartbeat, from `from` (a retained voter in
      // OUR config), needing no new-primary binding.
      Message::EpochAhead(m) if m.epoch() > self.membership.epoch() => m.checkpoint_op(),
      _ => return,
    };
    // Authenticate the SENDER as a CURRENT MEMBER of OUR config — the transport-bound `from` resolving to a
    // `member_at` slot, mirroring [`Self::maybe_answer_lower_epoch`] — and act on NONE of the message's
    // content, only the epoch-ordering signal. A NON-member (a misrouted or forged hint from an
    // out-of-config slot) must NOT drive catch-up: on an IDLE checkpoint-0 primary it would arm a forced
    // crossing sync that no donor can ever answer (every `checkpoint_op` is 0) with no same-epoch authority
    // ingress to clear the stale intent, wedging writes (`sync.is_some()`) at the old epoch forever. The
    // reliable catch-up signal is the `EpochAhead` from a RETAINED voter — a member of our config, and a
    // single-voter change always retains at least one; the crossing fetch (forced + crossing-required,
    // self-verifying) authenticates the STATE, but the trigger still gates the SENDER to a current member.
    // The trigger sender is authenticated as either a RESOLVED current member (its slot is in our
    // membership) or a QUARANTINED attested member (a `Peer::Member` our membership does not resolve —
    // a laggard partitioned across a rolling replacement, whose higher-epoch heartbeats
    // arrive on quarantined conns from the new members it cannot yet resolve). A client / out-of-config
    // slot elicits nothing. Provenance matters for the bounded probe below: a RESOLVED-member hint is
    // authoritative (unbounded); a quarantine-sourced one arms a BOUNDED probe and records the donor to
    // solicit directly (our `RequestSync` fan-out reaches only bound members — for such a laggard those
    // are its dead old peers).
    let quarantined_source = match from {
      Peer::Replica(slot) if self.membership.member_at(slot).is_some() => false,
      Peer::Member(_) => true,
      _ => return,
    };
    if quarantined_source {
      // Record the donor to solicit directly and ARM the bounded-probe deadline (once — a repeated
      // heartbeat must not slide it forward, or a faster-than-window primary would postpone expiry).
      self.quarantined_donor = Some(from);
      self.arm_quarantine_probe(now);
    } else {
      // A resolved member vouches the crossing authoritatively — drop any quarantine bound so the
      // crossing is no longer probe-limited (and stop soliciting a now-superseded quarantined donor).
      self.quarantined_donor = None;
      self.quarantine_probe_deadline = None;
    }
    // PIN the PERSISTENT crossing intent: the highest hinted crossing `checkpoint_op` this node must
    // reach. The arm/upgrade below sets the IN-FLIGHT `SyncState`'s `require_cross_epoch`, but that flag
    // is cleared the instant `on_sb_done` clears `self.sync` on a NON-crossing install — so if a sync had
    // already STAGED its install when this trigger arrived, the staged install completes at the old epoch
    // and the crossing requirement is lost. The intent OUTLIVES that lifecycle: a non-crossing install
    // completing while the intent is still `Some` re-arms the crossing afresh (`on_sb_done`). Cleared on a
    // real cross (`install_sync`) and on stale same-epoch evidence (`cancel_stale_cross_epoch_sync`).
    self.cross_epoch_intent = Some(
      self
        .cross_epoch_intent
        .map_or(checkpoint, |existing| existing.max(checkpoint)),
    );
    // A NON-Normal laggard (already off Normal: a `ViewChange` driving a futile old-epoch election, or a
    // `Recovering`/`RecoveringHead` at the superseded epoch) crosses via the recovery peer-fetch — it
    // enters Recovering, FORCED-syncs the cluster checkpoint, and `complete_recovery` lands it Normal at
    // E+1. There is no Normal state to preserve, so the status transition is free.
    if !self.status.is_normal() {
      self.enter_cross_epoch_peer_fetch(now, storage, checkpoint);
      return;
    }
    // A NORMAL laggard arms a NORMAL-STATUS crossing-required sync and STAYS Normal — it must keep
    // processing legitimate same-epoch traffic until a real crossing checkpoint lands. We deliberately do
    // NOT use `maybe_request_sync`: that is gated `incoming_checkpoint > self.op`, so a laggard that
    // APPENDED op `N` but missed its commit (`op == N`, `commit_min < N`) sees a checkpoint at `M == N == op`
    // and would NOT sync, stranding at the old epoch. Instead arm directly through the `arm_sync` chokepoint:
    //
    // - `target = checkpoint` (the advertised cluster crossing point, `>= N` because the epoch swap
    //   forces a checkpoint at `M >= N`) — the cross-epoch crossing checkpoint a donor serves at `M >= N`.
    // - `forced = true` — so `apply_sync`'s discard-direction assert uses the relaxed `checkpoint_op >=
    //   commit_min` invariant (needed for the `op == N` case, where the synced checkpoint sits at/below the
    //   head); the arm is NOT `> op`-gated, so `op == N` still crosses.
    // - `require_cross_epoch = true` — the crossing requirement: `apply_sync` completes this sync ONLY on a
    //   strictly-higher-epoch successor-membership checkpoint at/above target, never an early exit at the
    //   old epoch off a below-`N` / empty-membership reply.
    //
    // Arming a sync does NOT reset `op` and does NOT change status — `op`/`commit`/`view` stay untouched
    // until `apply_sync` INSTALLS the verified crossing checkpoint (which then advances `commit_min` to
    // `M >= N`, installs the successor membership, and discards the stale tail). So a higher-epoch message
    // moves no accumulator; the speculative sync just keeps re-soliciting until a donor's `M >= N` crossing
    // checkpoint lands (the epoch swap's forced checkpoint guarantees one exists). UPGRADE an
    // outstanding sync to a forced pinned crossing
    // (keeping the higher target, anti-thrash on the nonce); otherwise fresh-arm a crossing sync.
    match self.sync {
      Some(s) => {
        // ANY genuine higher-epoch trigger PINS the crossing requirement on an outstanding sync — even
        // when the hinted checkpoint does NOT exceed the current target. An ordinary same-epoch sync
        // already at/above the hint MUST still be upgraded to `forced` + `require_cross_epoch`: otherwise a
        // legitimate below-target successor checkpoint is rejected by the ordinary `< target` freshness
        // gate (or an ordinary reply completes WITHOUT crossing), and the laggard never leaves the old
        // epoch until another higher-epoch trigger happens to arrive. Keep the nonce and the HIGHER of the
        // two targets (no regression). A raised cross-epoch target does NOT abort a pinned transfer: the
        // target is only the solicit floor (a possibly-bogus hint), NOT a hard install bound — a legitimate
        // below-hint crossing transfer survives to install, and a stale same-epoch (empty-membership) one
        // cannot wrongly install (`apply_sync`'s successor-verification gate rejects it, then the next
        // solicit re-pins; `drop_transfer_below_forced_target` correctly no-ops for a crossing sync).
        self.sync = Some(SyncState {
          target: s.target.max(checkpoint),
          nonce: s.nonce,
          forced: true,
          require_cross_epoch: true,
        });
        // When this trigger UPGRADES an ORDINARY (`!require_cross_epoch`) sync to a crossing IN PLACE, its
        // live `block_fetch` is an ordinary same-epoch fetch pinned to a same-config checkpoint that can
        // never satisfy `apply_sync`'s crossing gate. Drop it so the freshly-upgraded crossing re-pins to a
        // CROSSING checkpoint via the next-line `send_request_sync` rather than burning round trips on the
        // wrong DAG. (Its `crossing_answered` bit was already `false` — an ordinary fetch never presents a
        // crossing — so the crossing-answer predicates would not have read it as answered regardless; the
        // drop is the behavioral re-pin, not the shield.) An already-CROSSING sync's live fetch is kept (the
        // upgrade is then idempotent, and a crossing-presenting fetch's bit legitimately shields it).
        if !s.require_cross_epoch {
          self.block_fetch = None;
        }
        self.send_request_sync(now);
      }
      None => self.arm_sync(now, checkpoint, true, true),
    }
  }

  /// Periodic checkpoint REPORT to the primary, piggybacked on the `Commit` heartbeat.
  /// A backup ordinarily reports its `checkpoint_op` to the primary ONLY inside a `PrepareOk` answering a
  /// `Prepare`. That couples the primary's view of the quorum checkpoint to fresh op traffic — which the
  /// bounded-WAL stall can HALT: once op-assignment stalls (the un-pruned window hit the ring
  /// bound), the primary broadcasts no new `Prepare`s, so backups send no fresh `PrepareOk`s, so the
  /// primary's `peer_checkpoint` for them goes STALE. The prune floor `min(checkpoint_op,
  /// quorum_checkpoint_op())` then under-counts the quorum's true checkpoint and the stall never releases
  /// — a deadlock when the pipeline drains exactly at the ring bound (every head op committed+acked, no
  /// in-flight `Prepare` whose `PrepareOk` would refresh the report). To keep the report fresh
  /// independent of op flow, a caught-up Normal backup RE-ACKS its OWN durable `checkpoint_op` on each
  /// heartbeat: the `PrepareOk` carries that `checkpoint_op`, so the primary's `quorum_checkpoint_op`
  /// (and thus the prune floor + the stall release) tracks the real quorum checkpoint even while
  /// op-assignment is stalled.
  ///
  /// Re-acking `checkpoint_op` (NOT `commit_min` / the head) is deliberately the SAFEST possible op to
  /// vouch for: it is at/below the applied frontier, so it is durable + committed and the
  /// `on_prepare_ok` side-effects are inert — it re-ORs an already-pruned `inflight` bit (a no-op,
  /// `run_gc` freed it) and `try_commit` advances nothing; ONLY `record_peer_checkpoint` (the report)
  /// takes effect. Gated like every other backup participation: skip while a view-CHANGING durable-view
  /// write is pending (`pending_durable_view` — the durable-view-before-participate rule, enforced at the
  /// `emit` chokepoint; a commit-first SwapEpoch root does NOT raise it, the view being durable through an
  /// epoch swap), while syncing, or before anything is checkpointed (`checkpoint_op == 0` — the floor is
  /// already 0, nothing to un-stall). The append-before-ack guard is EXPLICIT here (`!appending`): even
  /// the checkpoint-boundary slot can be transiently IN FLIGHT — a state-sync install / recovery keeps
  /// the WAL slot AT `checkpoint_op` and may re-append it (staged), marking it `appending` — and
  /// `send_prepare_ok` MUST NOT vouch for an op whose append has not completed (it `debug_assert!`s this).
  /// No-op for the primary. None of these skips harm stall-release liveness: the stall
  /// only needs fresh reports during STEADY operation (when the view write/`sync`/the boundary re-append
  /// are all clear), which is exactly when this fires.
  fn report_checkpoint_to_primary(&mut self) {
    if !self.status.is_normal()
      || self.is_primary()
      || self.sync.is_some()
      || self.pending_durable_view()
      || self.checkpoint_op.get() == 0
      || self.appending.contains(&self.checkpoint_op.get())
    {
      return;
    }
    self.send_prepare_ok(self.checkpoint_op);
  }

  pub(crate) fn on_prepare_ok<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    ok: PrepareOk,
  ) {
    if ok.view().get() > self.view.get() {
      self.catch_up_to_view(now, storage, ok.view());
      return;
    }
    if !self.status.is_normal() || !self.is_primary() || ok.view() != self.view {
      return;
    }
    if ok.replica().get() >= self.membership.replica_count() as u16 {
      return; // ignore malformed/out-of-range replica id
    }
    // Record this backup's reported checkpoint for the checkpoint-quorum (the range check above
    // guards the key). Independent of inflight: even an ok for an op we no longer track still
    // carries a fresh checkpoint report. Drives `quorum_checkpoint_op` → the GC prune floor.
    // MONOTONE: a reordered older report must never lower the recorded value (the GC floor and the
    // force-sync trigger that read it must not regress under reordering/partitions).
    self.record_peer_checkpoint(ok.replica(), ok.checkpoint_op());
    // A peer's reported checkpoint is proof its checkpointed prefix is committed (a replica checkpoints
    // only an already-committed op), so a primary whose own commit lags the highest peer checkpoint is
    // behind a provably-durable committed frontier — adopt it and apply the ops we already hold. This
    // recovers a crash-restarted primary that recovered its HEAD (the offset tail holds the bodies) but
    // not its full committed prefix, while an ahead sub-quorum GC-pruned the gap past its own checkpoint
    // and so can no longer re-ack it: without this the primary wedges — it cannot re-commit the gap (no
    // quorum can re-ack a pruned op), cannot state-sync (it already holds the bodies, so the
    // checkpoint-above-head sync trigger below stays dormant), and cannot forfeit (the checkpoint-FLOOR
    // lag `maybe_forfeit` reads is zero — it sits AT the quorum floor). Keying on a single peer's
    // checkpoint is the same trust `maybe_force_sync` already extends. The commit-side complement of
    // `maybe_request_sync` below, which covers the same evidence ABOVE our head (no bodies held → sync).
    let peer_checkpoint = self.max_peer_checkpoint_op();
    if peer_checkpoint.get() > self.commit_max.get()
      && self
        .advance_commit(now, storage, peer_checkpoint.get())
        .entered_recovery()
    {
      // The commit tail entered the owed reconciliation: this ack's generation is gone — no
      // sync trigger, no vote tally, no commit attempt over the teardown.
      return;
    }
    // State-sync trigger (symmetric): a backup reporting a checkpoint above our head means we are the
    // laggard (e.g. a partition-healed old primary). The `> self.op` gate keeps this a no-op normally.
    self.maybe_request_sync(now, ok.checkpoint_op());
    // Force-sync escalation: a fresh quorum-checkpoint report may have just crossed a `repair`
    // hole we hold, rendering its `RequestPrepare` futile (the op is pruned everywhere on the quorum).
    self.maybe_force_sync(now);
    // Content-addressed vote gate (TigerBeetle's (op, prepare_checksum) namespace): count this ack
    // toward the commit quorum ONLY if its prepare_checksum matches the OPERATION IDENTITY (client,
    // request, body) the primary is driving at this op. A mismatch means the ack is for a DIFFERENT or
    // STALE operation — e.g. a delayed PrepareOk for the OLD op at op number N that the liveness
    // truncation re-minted for a different request (even one whose body bytes match), or a backup
    // holding a different operation at the same op number — so DROP it (do not OR the vote). Without
    // this, such a stale ack could forge a quorum for an operation the primary never drove → divergence.
    if let Some(inflight) = self.inflight.get_mut(&ok.op().get())
      && ok.prepare_checksum() == inflight.prepare_checksum
    {
      inflight.oks |= 1u64 << ok.replica().get();
    }
    // Nothing follows: a teardown in the tail has nothing left to short-circuit; discard the flow.
    let _ = self.try_commit(now, storage);
  }

  pub(crate) fn on_commit<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    c: Commit,
  ) {
    if c.view().get() > self.view.get() {
      self.catch_up_to_view(now, storage, c.view());
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
    self.record_peer_checkpoint(self.membership.primary(self.view), c.checkpoint_op());
    // State-sync trigger: if the cluster has checkpointed past our WAL head, solicit a SyncCheckpoint
    // (the ops we'd need are below the cluster checkpoint and may be pruned — tail-apply can't reach).
    self.maybe_request_sync(now, c.checkpoint_op());
    // Force-sync escalation: the primary's just-recorded checkpoint may have crossed a `repair`
    // hole we hold below it (pruned everywhere on the quorum) → escalate to a forced `RequestSync`.
    self.maybe_force_sync(now);
    // The commit tail can enter the owed orphaned-re-persist reconciliation: the generation this
    // heartbeat addressed is then gone — solicit no tail gap and report no checkpoint over it.
    if self
      .advance_commit(now, storage, c.commit().get())
      .entered_recovery()
    {
      return;
    }
    // Tail-gap repair: if the primary's commit is ABOVE our head (committed ops we are missing, above
    // the cluster checkpoint), solicit them via `RequestPrepare` — the primary's retransmit (only
    // `commit_min+1..=op`) never re-sends a committed op below its own commit_min, so a backup that fell
    // behind would otherwise be stranded at its head. Self-retrying on each heartbeat until caught up.
    self.request_tail_gap();
    // Re-report our checkpoint to the primary on the heartbeat (a `PrepareOk` for
    // `commit_min` carrying `checkpoint_op`), so the primary's `quorum_checkpoint_op` — the bounded-WAL
    // prune floor / stall-release signal — stays fresh even when op-assignment is stalled and no new
    // `Prepare`/`PrepareOk` traffic flows. Without this the stall can deadlock at the ring bound.
    self.report_checkpoint_to_primary();
  }
}

use super::*;
use crate::id::{Epoch, MemberId};

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

/// The outcome of [`Endpoint::recover`]: this node either still belongs to the recovered membership
/// (`Active`, holding a recovering [`Endpoint`]) or was removed by a reconfiguration (`Retired`, a
/// terminal handle).
///
/// A node absent from the recovered membership has been removed by a reconfiguration; it recovers
/// `Retired` and must not act as a replica. The membership is resolved from the DURABLE root: a v4
/// root's own membership wins; a legacy (v1-3) root bridges to the genesis membership the caller
/// supplies. This node is then resolved by its stable [`MemberId`] ([`Config::local`](crate::Config));
/// present (a voter or learner) → `Active`, absent → `Retired`.
///
/// `large_enum_variant` is allowed deliberately: this is a `Result`-shaped, transient START-UP
/// handle — `recover` returns exactly ONE, the caller destructures it immediately, and it is never
/// stored in a collection — so the per-`Active`-variant memory the lint guards against is irrelevant,
/// while boxing the common (`Active`) path would add a needless heap allocation on every successful
/// recover (the same reason [`Result`] does not box its `Ok`).
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Recovered<S, R = RestartOnly> {
  /// This node occupies a slot in the recovered membership — a recovering [`Endpoint`] resuming the
  /// durable view in [`Status::Recovering`].
  Active(Endpoint<S, R>),
  /// This node is absent from the recovered membership (removed by a reconfiguration) — a terminal
  /// [`Retired`] handle that does not participate.
  Retired(Retired),
}

/// A terminal handle for a node that recovered into a membership it is no longer part of: its stable
/// [`MemberId`] ([`Config::local`](crate::Config)) did not resolve to any slot in the durable root's
/// membership, so a reconfiguration removed it. It carries only the local member id and the epoch it
/// was retired at; it holds NO consensus state and participates in NOTHING (it never votes, prepares,
/// or leads). The driver surfaces it as a hard error rather than running a replica loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retired {
  local: MemberId,
  epoch: Epoch,
}

impl<S, R> Recovered<S, R> {
  /// Unwraps the [`Recovered::Active`] endpoint, panicking on [`Recovered::Retired`]. Test-only: the
  /// fixtures always recover a present member, so they assert presence by construction.
  #[cfg(test)]
  pub(crate) fn expect_active(self) -> Endpoint<S, R> {
    match self {
      Recovered::Active(endpoint) => endpoint,
      Recovered::Retired(retired) => {
        panic!(
          "expected Recovered::Active, got Retired({})",
          retired.local()
        )
      }
    }
  }
}

impl Retired {
  /// This node's stable member id — the [`Config::local`](crate::Config) that the recovered
  /// membership no longer contains.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn local(&self) -> MemberId {
    self.local
  }

  /// The configuration epoch this node was retired at — the epoch of the recovered membership that
  /// no longer contains it.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }
}

impl<S: StateMachine> Endpoint<S, RestartOnly> {
  /// Reconstructs an endpoint from durable storage after a restart — the ergonomic [`RestartOnly`]
  /// recover (the DEFAULT capability), so a bare un-annotated `Endpoint::recover(..)` resolves to
  /// [`Recovered`]`<S, RestartOnly>`. A stronger capability is opted into explicitly via
  /// [`Self::recover_with_reconfig`]. See that method for the full Phase-1/Phase-2 recovery contract.
  pub fn recover<W: Wal, B: Superblock>(
    config: Config,
    membership: Membership,
    seed: u64,
    sm: S,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) -> Recovered<S, RestartOnly> {
    Self::recover_with_reconfig(config, membership, seed, sm, wal, sb, blocks)
  }
}

impl<S: StateMachine, R: Reconfig> Endpoint<S, R> {
  /// Reconstructs an endpoint under an EXPLICIT reconfiguration capability marker `R` from durable
  /// storage after a restart — a **metadata-only constructor** that enters [`Status::Recovering`] and
  /// defers all fallible reads to an async `handle_storage` loop (faults-as-data; spec §2/§6). It does
  /// NOT return in `Normal`. The ergonomic [`Self::recover`] is the [`RestartOnly`] entry point and
  /// defers here, so every bare `Endpoint::recover(..)` call resolves unannotated.
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
  ///
  /// **`membership` (the EFFECTIVE-membership rule).** The active membership is resolved from the
  /// DURABLE root, not blindly from the param: a v4 root (`state.membership_opt().is_some()`) wins —
  /// the durable config is authoritative, so an offline reconfiguration pre-written into the root
  /// takes effect on the next recover regardless of what the caller passes.
  /// A legacy (v1-3) root (`membership_opt().is_none()`) has no durable membership, so `recover`
  /// BRIDGES to the passed `membership` — the genesis the embedder supplies (the param stays in the
  /// signature solely as this legacy fallback). This node is then resolved against the effective
  /// membership by its stable [`MemberId`] ([`Config::local`]): present (a voter or learner) →
  /// [`Recovered::Active`] holding the recovering endpoint; ABSENT → [`Recovered::Retired`] (a
  /// reconfiguration removed it — it must not act as a replica). The `Active` endpoint stores the
  /// EFFECTIVE membership (so a v4 root's membership, never the param).
  ///
  /// **`seed` must carry fresh entropy per incarnation.** The freshness nonce that tags this
  /// incarnation's solicitations (`Recovery`/`GetView`/`RequestSync`) is derived deterministically
  /// from `seed` alone (`Prng::new(seed)`), and nothing else the endpoint holds is guaranteed to
  /// differ across a crash + re-`recover` at the same durable state — so re-recovering with the SAME
  /// seed re-mints the SAME nonce, and a DELAYED `RecoveryResponse`/`SyncCheckpoint` addressed to the
  /// PREVIOUS incarnation then passes this incarnation's nonce check
  /// (`Self::on_recovery_response`) and can adopt a stale head. That is never a committed-op loss
  /// (the adopted head is validated against the responding primary, and the ordinary repair /
  /// view-change machinery re-converges) — but it opens a needless divergence window the nonce
  /// exists to close. The embedder/driver MUST therefore supply per-incarnation entropy here: OS
  /// randomness, a persisted boot counter, or any value that cannot repeat across restarts of the
  /// same replica. (The deterministic simulation does this with its seeded PRNG, drawing a distinct
  /// value per replica incarnation.)
  pub fn recover_with_reconfig<W: Wal, B: Superblock>(
    config: Config,
    membership: Membership,
    seed: u64,
    sm: S,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) -> Recovered<S, R> {
    let state = sb.state();
    // The EFFECTIVE membership: a v4 root's OWN membership is authoritative (the durable config wins,
    // so an offline reconfiguration pre-written into the root takes effect here); a legacy (v1-3) root
    // carries none, so bridge to the passed genesis `membership`. The struct stores THIS one.
    let membership = match state.membership_opt() {
      Some(durable) => durable.clone(),
      None => membership,
    };
    // Resolve this node by its stable `MemberId` against the effective membership. ABSENT ⇒ a
    // reconfiguration removed it: recover Retired (a terminal handle that never participates), BEFORE
    // any storage read is submitted. PRESENT (a voter or learner) ⇒ build the recovering Endpoint.
    let Some(local_slot) = membership.slot_of(config.local()) else {
      return Recovered::Retired(Retired {
        local: config.local(),
        epoch: membership.epoch(),
      });
    };
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

    // `local_slot` is this node's slot in the EFFECTIVE membership, resolved by its stable `MemberId`
    // at the top (the Retired early-return already handled an absent member).
    // The own durable checkpoint seeds the quorum-th order statistic only when self is a VOTER in a
    // solo voting set (`quorum == 1`) — there the single voter's own checkpoint IS the quorum.
    // Computed before `membership` is moved into the struct below (it is not `Copy`).
    let seed_own_checkpoint = membership.quorum() == 1 && membership.is_voter(local_slot);

    // RESTORE the recent-prior `config_id` ring from the durable root (a v5 root persists the superseded
    // ancestor ids). The ring widens `in_lineage` so a retained OLD-epoch laggard's cross-epoch catch-up
    // (RequestSync/RequestPrepare carrying the predecessor `config_id`) is still ADMITTED after a
    // reconfiguration. Without restoring it, a node that recovers into a post-reconfiguration epoch would
    // seed every slot with only the CURRENT id, so once the new-epoch donors restart the laggard's
    // predecessor-`config_id` catch-up is rejected and it is stranded (a liveness loss). Each restored slot
    // takes the durable id; any slot the root did not record (an empty/short lineage — a v4 or pre-swap
    // root) falls back to the current `config_id` (the pre-v5 behaviour, a harmless self-duplicate that
    // admits nothing extra). For a no-reconfiguration cluster the durable lineage is genesis-only, so this
    // is byte-identical to the old `[config_id; LINEAGE_RING]` seeding.
    let mut lineage = [membership.config_id(); LINEAGE_RING];
    for (slot, id) in lineage.iter_mut().zip(state.prior_config_ids()) {
      *slot = *id;
    }
    let mut endpoint = Self {
      config,
      membership,
      // The durable backward link of the lineage: a v4 root carries its own `prev_epoch`; a legacy
      // (v1-3) root reads `prev_epoch == epoch == 0`, which equals the bridged genesis membership's
      // epoch — so this is correct for both, and every durable-root write this incarnation makes
      // re-persists the membership as a v4 root carrying it.
      prev_epoch: state.prev_epoch(),
      lineage,
      // RESTORE the cross-epoch serve gate: the op that produced the recovered membership. A v6 root
      // carries it durably (the SwapEpoch / checkpoint / sync-successor / offline-restart writer threaded
      // it); a pre-v6 root defaults it to its own `checkpoint_op` in `decode`. Without restoring it a donor
      // recovered into a swapped-but-not-yet-checkpointed window would re-attach its E+1 membership to a
      // checkpoint BELOW the reconfigure op, letting a laggard install E+1 without the committed prefix
      // through it.
      config_install_op: state.config_install_op(),
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
      // Set when the durable checkpoint envelope is read back + restored (`on_recover_sb_done`),
      // which decodes the `sm_root`; `None` until then (block GC skips a cycle without a live root).
      checkpoint_sm_root: None,
      checkpoint_sessions_root: None,
      // The vouched log floor restarts at the DURABLE checkpoint: an adoption-learned (in-memory)
      // floor does not survive a crash, so a pre-crash floored adoption re-learns the cluster floor
      // from the next carrier / Commit it hears. Until then this replica's own carrier may exceed
      // the frame if its WAL still spans the pre-adoption band (the un-synced crash window); the
      // force-sync escalation re-narrows it as soon as a peer checkpoint is heard.
      log_floor: OpNumber::with(checkpoint_op),
      peer_checkpoint: BTreeMap::new(),
      // The quorum-th order statistic over {own durable checkpoint, no peer reports} — coherent with
      // `recompute_quorum_checkpoint` (and its staleness assert) over the fields above. The own
      // checkpoint seeds the statistic only when self is a VOTER in a solo voting set (`quorum == 1`):
      // there the single voter's own checkpoint IS the quorum. Otherwise — more than one voter, or a
      // non-voting member (which `compute_quorum_checkpoint_op` excludes from the statistic entirely) —
      // the unheard voters pin it to 0. Without the voter gate a recovering learner in a 1-voter cluster
      // would seed its own checkpoint here while a fresh compute yields 0, tripping the staleness assert.
      quorum_checkpoint: if seed_own_checkpoint {
        OpNumber::with(checkpoint_op)
      } else {
        OpNumber::new()
      },
      recover: None,
      repair: std::collections::BTreeSet::new(),
      sync: None,
      // IN-MEMORY only: a crash drops the crossing intent; the recovery checkpoint-debt machine + the
      // cluster's higher-epoch heartbeats re-establish it after restart, so it starts `None` here.
      cross_epoch_intent: None,
      pending_install: None,
      block_fetch: None,
      sm_reconstruct: None,
      sync_serving: BTreeMap::new(),
      state_syncs_applied: 0,
      forced_syncs_applied: 0,
      wal_stalls: 0,
      below_ring_window_syncs: 0,
      unions_floored: 0,
      repair_batches_served: 0,
      prepare_batches_sent: 0,
      header_only_carriers_emitted: 0,
      sessions_evicted: 0,
      pending_forfeit: false,
      reconfigure_inflight: None,
      pending_swap: None,
      paying_checkpoint_debt: false,
      peer_progress: BTreeMap::new(),
      learner_proof: None,
      _reconfig: core::marker::PhantomData,
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
    endpoint.recover_progress(Instant::ZERO, sb, blocks);
    Recovered::Active(endpoint)
  }

  /// Handles a WAL completion while `Recovering`/`RecoveringHead` (Phase 2 of `recover`). Adopts a
  /// body ONLY after `Header::verify` (the faults-as-data chokepoint: a torn write / bit-rot fails
  /// verify and is treated as a `Fault`). A clean read resolves its op (Verified body, KeepRepairing
  /// hole, or StaleCommitted drop) and retires ALL of the op's in-flight ids; a `Fault`/`Absent`/
  /// mismatch only drops THIS id and leaves the op PENDING — `recover_timeouts` is the sole owner of
  /// retransmission, the absolute per-op budget, and the budget-exhaustion resolution
  /// (`resolve_exhausted_tail_read`). Calls `recover_progress` after each.
  pub(crate) fn on_recover_wal_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
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
    // `wal` is part of the uniform recover-completion signature (the `handle_storage` call site passes
    // it the same way to every `on_recover_*` handler), but a completion now carries its own outcome —
    // the Fault arm no longer re-submits here (`recover_timeouts` owns retry/resolve), so no read is
    // submitted from this handler.
    let _ = &mut *wal;
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
        // Adopt the verified body, retiring EVERY in-flight read for this op. Normally the Phase-1
        // header-only placeholder is still present and we just fill its body; but if this slot had earlier
        // been classed faulty and DROPPED from `self.log` (`drop_faulty_committed_slots`), a later
        // timer-driven re-read that clears the transient must RE-INSERT the full entry rather than
        // silently lose the recovered op. `recover_timeouts` mints reads ADDITIVELY (one op can have
        // several outstanding ids), so drop ALL of op's ids — a late duplicate under another id must be
        // ignored, never re-processed.
        rec.reads.retain(|_, &mut o| o != op);
        rec.pending.remove(&op);
        rec.faulty.remove(&op);
        // Replace the FULL identity from the verified read (client, request, body) — `insert` overwrites
        // any existing placeholder or seeds a fresh one, both with the verified identity. NOT a partial
        // body-only overwrite that could strand a Phase-1 placeholder's stale (client, request) beside the
        // new body (a mixed identity whose reply would route to the wrong client/request). Reconstruct via
        // the SHARED typed helper (`from_committed_body`), NOT a bare `LogEntry::present`: a recovered
        // RECONFIGURATION op's body must be rebuilt as a typed `Body::Reconfigure` exactly as the
        // normal-prepare and repair-fill paths do — storing it as an opaque `Body::Present` would make
        // `commit_reconfigure` miss it at commit, mis-applying the membership bytes to the state machine
        // and re-typing the committed op number (the live-reconfiguration op-reuse divergence).
        self
          .log
          .insert(op, LogEntry::from_committed_body(client, request, body));
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
        // placeholder is REPLACED with the `Repairing` hole (the empty body must never apply). Retire
        // EVERY in-flight read for this op (additive ids — a late duplicate must be ignored).
        rec.reads.retain(|_, &mut o| o != op);
        rec.pending.remove(&op);
        rec.faulty.remove(&op);
        // Replace the FULL identity from the verified header (client, request, body_checksum) — never a
        // partial body-only overwrite that could strand a Phase-1 placeholder's stale (client, request)
        // beside the new checksum, an unfillable mixed identity that peer repair (which validates all
        // three fields) cannot fill.
        self.log.insert(
          op,
          LogEntry {
            client,
            request,
            body: Body::Repairing(body_checksum),
          },
        );
      }
      Outcome::StaleCommitted => {
        // The persisted vsr_header says this committed slot's canonical body differs from the WAL's:
        // class it permanently faulty IMMEDIATELY (no retry — the mismatch is authoritative). The
        // existing peer fault-repair path then drops it from the `log` cache (`recover_progress`) and `advance_commit`
        // peer-repairs it on demand; the canonical body is fetched, never re-derived from the stale WAL.
        // Retire EVERY in-flight read for this op (additive ids — a late duplicate must be ignored).
        rec.reads.retain(|_, &mut o| o != op);
        rec.pending.remove(&op);
        rec.faulty.insert(op);
      }
      Outcome::Fault => {
        // A faulted read: drop this id and leave the op PENDING. `recover_timeouts` re-submits it
        // (additive) and decrements the ABSOLUTE budget; when the budget exhausts it resolves the op via
        // `resolve_exhausted_tail_read`. We do NOT retry/resolve here — keeping a single retry+budget
        // owner avoids the id-churn that dropped a slow completion (a re-mint that retired the id the
        // late completion arrives under).
        rec.reads.remove(&id.get());
      }
    }
    self.recover_progress(now, sb, blocks);
  }

  /// The placement + `classify_committed_slot` verdict for resolving an in-flight tail op from its
  /// DURABLE header alone (no body): `Some(client, request, body_checksum)` when the durable header is
  /// placement-valid (`header().op() == op`) AND classifies `Verified` — keep it header-only as a
  /// `Body::Repairing` hole; `None` otherwise. The SINGLE source of the verdict the Fault
  /// retry-exhaustion path (`resolve_exhausted_tail_read`) and the peer-checkpoint completion
  /// (`on_recover_sync_checkpoint`) both apply, so they cannot drift.
  fn inflight_tail_repairing_identity<W: Wal>(
    &self,
    wal: &W,
    op: u64,
  ) -> Option<(ClientId, RequestNumber, u128)> {
    let canonical = self
      .recover
      .as_ref()
      .and_then(|r| r.canonical.get(&op).copied());
    wal
      .header(OpNumber::with(op))
      // PLACEMENT: the durable header must be FOR `op`. `Wal::header` returns the header at `op`'s slot,
      // which a misdirected write can leave holding a SIBLING op's header — not a trustworthy read of
      // THIS op. Guard it exactly as the ReadOk/BodyFaulty arms do via `header().op() == op`.
      .filter(|h| h.op() == OpNumber::with(op))
      .filter(|h| {
        matches!(
          classify_committed_slot(
            (h.client(), h.request(), h.body_checksum()),
            canonical,
            op,
            h.view().get(),
            self.commit_max.get(),
            self.log_view.get(),
          ),
          SlotVerdict::Verified
        )
      })
      .map(|h| (h.client(), h.request(), h.body_checksum()))
  }

  /// Resolve a tail op whose ABSOLUTE read budget is exhausted, from its durable header. A held
  /// COMMITTED op (`op <= commit_max`) whose durable header classifies `Verified` is KEPT header-only
  /// as `Body::Repairing` (existence + identity preserved so a later view change cannot re-mint its op
  /// number); every other case — a StaleCommitted/superseded committed slot, a committed slot with no
  /// durable header, OR an UNCOMMITTED op (`op > commit_max`, the faulty HEAD included, which must stay
  /// faulty to drive `RecoveringHead` / be truncated) — is routed to `rec.faulty` (a peer-repaired
  /// hole). This is the STORAGE-path resolution `recover_timeouts` invokes on budget exhaustion. It shares
  /// the VERDICT (`inflight_tail_repairing_identity`) with the peer-checkpoint completion's per-op
  /// resolution (`on_recover_sync_checkpoint`) so the two cannot drift, but DIFFERS on an UNCOMMITTED op:
  /// here it routes one to faulty (so a faulty head still drives `RecoveringHead` / is truncated), whereas
  /// the always-Normal-bound message path keeps a Verified uncommitted op header-only as `Body::Repairing`.
  fn resolve_exhausted_tail_read<W: Wal>(&mut self, wal: &W, op: u64) {
    let keep = (op <= self.commit_max.get())
      .then(|| self.inflight_tail_repairing_identity(wal, op))
      .flatten();
    if let Some(rec) = self.recover.as_mut() {
      rec.pending.remove(&op);
      rec.reads.retain(|_, &mut o| o != op); // drop ALL of op's in-flight ids
    }
    match keep {
      Some((client, request, body_checksum)) => {
        if let Some(rec) = self.recover.as_mut() {
          rec.faulty.remove(&op);
        }
        // Replace the FULL identity (never a partial body-only overwrite that could strand a Phase-1
        // placeholder's stale client/request beside the new checksum — an unfillable mixed identity peer
        // repair, which validates all three fields, cannot fill).
        self.log.insert(
          op,
          LogEntry {
            client,
            request,
            body: Body::Repairing(body_checksum),
          },
        );
      }
      None => {
        if let Some(rec) = self.recover.as_mut() {
          rec.faulty.insert(op);
        }
      }
    }
  }

  /// Handles a superblock completion while `Recovering`/`RecoveringHead` (Phase 2 of `recover`). A VALID
  /// `CheckpointRead` (verified against the durable root) restores the SM + client sessions and drives
  /// `recover_progress`; a `Fault` or a verify-mismatch is DISCARDED — `recover_timeouts` is the sole owner
  /// of the checkpoint retry + ABSOLUTE budget (decremented per tick), re-submitting until a valid read
  /// lands or the budget exhausts into a peer fetch.
  pub(crate) fn on_recover_sb_done<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
    done: SuperblockDone,
  ) {
    match done {
      SuperblockDone::CheckpointRead(cr) => {
        // React to ANY checkpoint read while one is OUTSTANDING (`recover.checkpoint.is_some()`), not only
        // the latest id: the recover-retry timer re-submits ADDITIVELY (a fresh id without retiring the
        // prior), so on a real async superblock a slow read completing after a retransmit arrives under an
        // EARLIER id and must still be accepted (matching only the latest id would drop it and wedge). The
        // bytes are checksum-verified below regardless of which submission delivered them, and once a valid
        // read restores the SM (`checkpoint = None`) any late duplicate is ignored. A completion while NO
        // checkpoint read is outstanding is foreign/stale — never trusted.
        let is_ours = self.recover.as_ref().and_then(|r| r.checkpoint).is_some();
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
        let Some((_, sm_root, sessions_root)) = decoded.filter(|_| id_ok && op_ok && bound_ok)
        else {
          // Any mismatch (wrong op / wrong hash / wrong bound op / unparsable) is treated as a FAULT:
          // DISCARD the bytes and leave the checkpoint outstanding for `recover_timeouts` to re-submit — it
          // owns the checkpoint retry + ABSOLUTE budget (decremented per tick), exactly as for a real
          // `SuperblockDone::Fault`. Do NOT restore, do NOT panic. A permanently root-inconsistent snapshot
          // (mismatch on EVERY read) thus exhausts the budget on the timer and escalates to a peer fetch,
          // identical to a permanently-faulting read.
          return;
        };
        // The envelope is valid, but the SM state AND the client-session table now live in the
        // content-addressed BlockStore — the envelope only NAMES them by `sm_root` / `sessions_root`, and
        // its hash does NOT cover the blocks. So before restoring, confirm every block reachable from BOTH
        // roots is present locally (a disk fault could have dropped one): walk each DAG via a `BlockSync`
        // over only the local store. If both drain (`next_request` returns no missing block) the DAGs are
        // complete — restore. A MISSING/malformed block is treated like a corrupt read — DISCARD and leave
        // the checkpoint outstanding, so `recover_timeouts` exhausts the budget and escalates to a peer
        // block-fetch.
        let mut sm_walk =
          super::block_sync::BlockSync::<super::block_sync::SmRefs<S>>::new(sm_root);
        let mut session_walk =
          super::block_sync::BlockSync::<super::block_sync::SessionRefs>::new(sessions_root);
        match (
          sm_walk.next_request(&*blocks),
          session_walk.next_request(&*blocks),
        ) {
          (Ok(None), Ok(None)) => {} // complete — every reachable block of both DAGs is present locally.
          _ => return, // a missing/malformed block in either: discard, retry, escalate (peer block-fetch).
        }
        // Reconstruct through a VERIFY-ON-READ view: the walks above drained, but a block can bit-rot or
        // be misdirected in the window before this destructive reconstruct, so check every block read
        // against its content address. Reconstruct the SESSION table first into a local value, then the SM;
        // a missing/corrupt block in either aborts (`None` / `RestoreError`), handled like a missing walk
        // block above (discard, retry, escalate). On error nothing has mutated.
        let verified = crate::block_store::VerifiedBlocks::new(&*blocks);
        let Some(sessions) = super::session_blocks::decode_sessions(sessions_root, &verified)
        else {
          return;
        };
        if self.sm.restore(sm_root, &verified).is_err() {
          return;
        }
        self.clients = sessions;
        // Record the restored SM + session DAG roots as the live roots the block GC marks from.
        self.checkpoint_sm_root = Some(sm_root);
        self.checkpoint_sessions_root = Some(sessions_root);
        if let Some(rec) = self.recover.as_mut() {
          rec.checkpoint = None;
        }
        self.recover_progress(now, sb, blocks);
      }
      SuperblockDone::Fault(_) => {
        // A checkpoint-read FAULT needs no in-band handling: `recover_timeouts` is the SOLE checkpoint
        // retry+budget owner (it re-submits ADDITIVELY and decrements the ABSOLUTE budget per tick,
        // escalating to a peer fetch on exhaustion), the exact mirror of the tail-read `Fault` arm in
        // `on_recover_wal_done`. Counting the budget on the TIMER rather than here is what makes it robust
        // both to a fault STORM (several superseded additive reads faulting out of order) and to a fault
        // landing AFTER a re-mint (latency over the retransmit interval): neither over- nor under-counts.
        // The checkpoint stays outstanding (`recover.checkpoint` still `Some`), so the timer keeps retrying
        // until a valid read restores it or the budget exhausts.
      }
      SuperblockDone::Wrote(_) => {
        // A stale durable-root/checkpoint *write* completion from before the crash cannot occur
        // (a fresh recover issues no writes); ignore defensively rather than panic.
      }
    }
  }

  /// Escalate to a PEER FETCH: stop local checkpoint retries, arm a FORCED state-sync to `target` (so a
  /// peer holding a checkpoint `>= target` answers), broadcast the `RequestSync`, and mark
  /// `awaiting_peer_checkpoint` so the recovery stays open (never completes to Normal with an unrestored
  /// SM) and `handle_message` accepts the answering `SyncCheckpoint`. Idempotent: if already escalated, it
  /// just (re-)solicits.
  ///
  /// Two callers, distinguished by `target` + `require_cross_epoch`:
  /// - the permanently-unreadable own-checkpoint recovery (`target = self.checkpoint_op`,
  ///   `require_cross_epoch = false`): any peer at/above our corrupt checkpoint subsumes it.
  /// - the cross-epoch crossing fetch ([`Self::enter_cross_epoch_peer_fetch`]) (`target` = the advertised
  ///   cluster checkpoint, `require_cross_epoch = true`): the fetch MUST cross into E+1 — `apply_sync`
  ///   rejects any non-crossing reply (see [`SyncState::require_cross_epoch`]).
  fn escalate_checkpoint_to_peer_fetch(
    &mut self,
    now: Instant,
    target: OpNumber,
    require_cross_epoch: bool,
  ) {
    // Stop local checkpoint reads and latch the awaiting-peer state.
    if let Some(rec) = self.recover.as_mut() {
      rec.checkpoint = None;
      rec.awaiting_peer_checkpoint = true;
    }
    // Arm a FORCED sync to `target`: any peer whose durable checkpoint is at or above it can serve a
    // snapshot that subsumes ours. `forced` selects `apply_sync`'s relaxed
    // (never-rewind-the-applied-frontier) assert — correct here, where the synced op `>= checkpoint_op
    // == commit_min`. Only arm if not already syncing (anti-thrash; the fresh-arm chokepoint
    // `arm_sync` broadcasts the solicitation itself); an already-armed sync just re-broadcasts.
    // Either way the recover-retry timer (`recover_timeouts`) keeps re-broadcasting on a cadence
    // while `awaiting_peer_checkpoint` holds (the Normal-only `sync_timeouts` does not run during
    // recovery).
    if self.sync.is_none() {
      self.arm_sync(now, target, true, require_cross_epoch);
    } else {
      self.send_request_sync(now);
    }
    self.arm_timers(now);
  }

  /// Route a NON-NORMAL laggard stranded at the OLD epoch into the RECOVERY peer-fetch — the cross-epoch
  /// catch-up for a replica whose status is not `Normal` (a `ViewChange` driving a now-futile old-epoch
  /// election, or a `Recovering`/`RecoveringHead` whose own durable state is at the superseded epoch).
  /// Such a replica cannot state-sync directly (the sync trigger/serve are `Normal`-gated) and its
  /// old-epoch view-change/recovery is epoch-inadmissible from the swapped cluster, so it would strand
  /// forever; the Normal-path cross-epoch catch-up ([`Self::maybe_request_cross_epoch_catchup`]) does not
  /// apply. The ONE clean "rebuild from the cluster, end Normal" mechanism is the recovery peer-fetch
  /// (`awaiting_peer_checkpoint`): it solicits a `SyncCheckpoint` (which carries the E+1 successor
  /// membership), `apply_sync` installs it cross-epoch, and `complete_recovery` lands the replica `Normal`
  /// at the new epoch. This abandons the futile old-epoch view-change/recovery and enters that path.
  ///
  /// Triggered off a STRICTLY-higher-epoch `Prepare`/`Commit` (the same committed-vouched signal the
  /// Normal path uses) — we act on NONE of its content, only on learning a configuration ahead of ours
  /// exists; the SyncCheckpoint we fetch is self-verifying (its `checkpoint_id` + the successor's
  /// `config_id` hash-chain are checked in `apply_sync`), so a forged higher-epoch heartbeat cannot
  /// install unvouched state. Safety fences, in order:
  ///
  /// - **Idempotent**: already awaiting a peer checkpoint ⇒ the `recover_retry` cadence re-solicits;
  ///   nothing to re-enter.
  /// - **Never disturb LOCAL recovery progress**: a `Recovering` replica still draining its own durable
  ///   tail/checkpoint reads (`rec.pending` non-empty or `rec.checkpoint` outstanding) may yet recover
  ///   from its own disk to its (old-epoch) durable state — let it; a later higher-epoch heartbeat
  ///   re-triggers this from the settled status.
  /// - **Never abandon an in-flight DURABLE-VIEW write** (`pending_durable_view` — a `ViewChange`'s
  ///   `SendDoViewChange`, or an `AdoptedStartView`, write not yet landed): tearing it down mid-write
  ///   could regress a view the replica is vouching for. Defer; the next heartbeat re-triggers once the
  ///   write settles. (A committed-first `SwapEpoch` root does NOT raise this fence, but a non-Normal
  ///   laggard never holds one.) We keep `self.view`/`self.log_view` — the cross-epoch sync does not
  ///   regress them; the post-recovery Normal path catches the view up via `catch_up_to_view`.
  /// - **Never abandon an in-flight ORDINARY checkpoint** (`pending_checkpoint` — a Normal laggard can
  ///   have a snapshot two-write persist underway when the cross-epoch trigger arrives): the teardown's
  ///   `reset_for_view_transition` clears `pending_checkpoint`, and abandoning it mid-persist is a
  ///   durable-sequencing hazard. Defer; the trigger is sticky (re-fires on each higher-epoch heartbeat /
  ///   `EpochAhead`), so we re-enter cleanly once the ordinary checkpoint completes.
  ///
  /// `checkpoint` is the advertised cluster checkpoint (the higher-epoch trigger's `checkpoint_op`) — the
  /// crossing TARGET. The forced sync REQUIRES crossing (`require_cross_epoch`): `apply_sync` rejects any
  /// reply that is not a strictly-higher epoch carrying the successor membership, so the fetch can ONLY
  /// complete by installing E+1 (it never exits Recovering at the old epoch off a below-`N`/empty reply).
  ///
  /// On entry: tear down the old-generation in-flight state ([`Self::reset_for_view_transition`] — the
  /// in-flight sync + its deferred install, the pipeline-adjacent submissions, the forfeit sub-state),
  /// drop the pipeline/buffer + the `ViewChange` collection + any prior-view `pending_sb` (so the status
  /// flip to `Recovering` keeps the `view_change.is_some() == is_view_change()` coupling and no stale
  /// completion fires), enter `Recovering` with a FRESH `RecoverState` latched at `awaiting_peer_checkpoint`
  /// (no local reads — the WAL/SM are consistent at the stale point, just hopelessly behind the pruned
  /// cluster), and arm the FORCED peer-fetch exactly as the checkpoint-exhaustion escalation does.
  pub(crate) fn enter_cross_epoch_peer_fetch(&mut self, now: Instant, checkpoint: OpNumber) {
    if self.awaiting_peer_checkpoint() {
      return; // already fetching — `recover_timeouts` re-solicits on its cadence.
    }
    if let Some(rec) = self.recover.as_ref()
      && (!rec.pending.is_empty() || rec.checkpoint.is_some())
    {
      return; // still draining local recovery reads — may recover from own disk first.
    }
    if self.pending_durable_view() {
      return; // a durable-view write is in flight — do not abandon it mid-write.
    }
    if self.pending_checkpoint.is_some() {
      return; // an ordinary checkpoint is persisting — do not abandon it; the sticky trigger re-fires.
    }
    // Tear down the futile old-generation in-flight state (sync + deferred install, in-flight appends,
    // peer-checkpoint reports, in-flight checkpoint, forfeit sub-state) in the shared chokepoint, then the
    // pieces it deliberately leaves to the call site: the primary pipeline + backup reorder buffer, the
    // `ViewChange`-only collection (so the imminent `Recovering` status keeps the
    // `view_change.is_some() == is_view_change()` coupling), and any prior-view `pending_sb` (a stale
    // completion is then ignored in `on_sb_done`, the `catch_up_to_view` shape).
    self.reset_for_view_transition(now);
    // A SAME-CONFIG pre-root staged install (if `reset_for_view_transition` preserved one) is SUPERSEDED
    // here: the crossing this path arms targets `>= N > M` (`N` is the reconfigure op, strictly above this
    // laggard's frontier, and M was at/below it), so the crossing is a strictly-NEWER checkpoint that
    // legitimately replaces M forward — and `escalate_checkpoint_to_peer_fetch` below installs a fresh
    // `sync` with that even-HIGHER `require_cross_epoch` lower bound. Clear the stale staging so the
    // crossing starts clean (leaving the old `pending_install` would orphan it under the new sync). M's
    // durable root stays at M on disk and the crossing's `>= N` floor admits nothing below M, so dropping
    // it here cannot rewind M's root; a crash recovers off M's durable root unchanged. No-op off the rare
    // overlap of a pre-root retry being crossed cross-epoch.
    self.pending_install = None;
    // Drop the live block-fetch: it belonged to the OLD sync this path supersedes (the crossing
    // `escalate_checkpoint_to_peer_fetch` arms below is a fresh sync), so it cannot shield the new
    // crossing as already-answered.
    self.block_fetch = None;
    self.inflight.clear();
    self.buffer.clear();
    self.view_change = None;
    self.pending_sb = None;
    // Sweep in-flight serve-reads: a Recovering node abandons its donor role. A leaked `sync_serving`
    // entry (its completion is dropped as foreign by `on_recover_sb_done` without removing the entry) would
    // make `submit_or_refresh_serve` dedupe every future `RequestSync` from that requester — never
    // re-submitting a read once Normal again — and keep `has_inflight_storage()` (hence
    // `seal_committed_frontier`) wedged forever. Any read still outstanding in the superblock completes as
    // foreign and is dropped; the requesters re-solicit and are served afresh after this node is Normal.
    self.sync_serving.clear();
    // Enter Recovering with a fresh, read-free RecoverState: the WAL/SM are already consistent at our
    // (stale) durable point, so there is no local tail/checkpoint read to drain — we go straight to the
    // peer fetch. The FORCED sync targets `max(checkpoint, self.checkpoint_op)`: at/above the advertised
    // cluster crossing point AND at/above our own checkpoint, so the only satisfiable reply is the donor's
    // `M >= N` crossing checkpoint (`apply_sync`'s forced path never rewinds the applied frontier — the
    // synced op `>= checkpoint_op == commit_min`). The recovery `RequestSync` is admitted at the E+1
    // server (our predecessor `config_id` is an ANCESTOR in its lineage ring; its E+1 answer is admitted
    // here via `sync.is_some()`). `require_cross_epoch = true` pins the crossing requirement in `apply_sync`.
    self.set_status(Status::Recovering);
    self.recover = Some(RecoverState::default());
    let target = OpNumber::with(checkpoint.get().max(self.checkpoint_op.get()));
    self.escalate_checkpoint_to_peer_fetch(now, target, true);
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
  fn recover_progress<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
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
      self.complete_recovery(now, sb, blocks);
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
      self.set_status(Status::RecoveringHead);
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
    self.complete_recovery(now, sb, blocks);
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
  pub(crate) fn complete_recovery<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
    self.recover = None;
    if self.log_view.get() < self.view.get() {
      // Crashed mid-view-change (the durable view advanced past `log_view` — the new view's log was not
      // yet installed). A learner persists this same view-ahead-of-log_view shape as a voter does (it
      // adopts the new view before installing its log), but the RE-ESTABLISHMENT differs by role:
      //
      // - VOTER → re-drive `VC(view)` (`enter_view_change_from_recovery`): it casts its DoViewChange so
      //   the in-progress change completes and the new primary's StartView reinstalls its log.
      // - NON-VOTING LEARNER → catch-up posture at the CURRENT view (`enter_catch_up_posture`), NOT a
      //   re-drive: a learner is never a view-change voter or candidate primary, so it must NOT emit a
      //   DoViewChange. It instead solicits GetView and adopts the (same-view) StartView, which restores
      //   `log_view == view` and returns it to Normal — exactly the catching-up lane a learner uses when
      //   it falls behind in view (`view_change_status` is voter-only, so it never escalates to active).
      if self.is_voter() {
        self.enter_view_change_from_recovery(now, sb, self.view);
      } else {
        self.enter_catch_up_posture(now);
      }
    } else if self.membership.replica_count() > 1
      && self
        .membership
        .is_primary_slot(self.local_slot(), self.view)
    {
      // Was Normal as the PRIMARY → abdicate: a restarted primary has no in-memory pipeline and a
      // checkpoint-only session table, so it forces a clean view change to view + 1 rather than
      // resuming as the established primary.
      self.enter_view_change_from_recovery(now, sb, self.view.next());
    } else {
      // Backup, a non-voting learner, or a SOLO replica (its own primary, no quorum to view-change)
      // → resume Normal.
      self.set_status(Status::Normal);
      if self.membership.replica_count() == 1 && !self.is_learner() {
        // Solo VOTER: rebuild the pipeline for the recovered tail so `try_commit` re-commits ops it holds
        // (an empty `inflight` would stall them). A learner in a single-voter cluster is a follower, not
        // the solo primary, so it takes the backup path.
        self.resume_solo_voter_pipeline(now, sb, blocks);
      } else {
        self.arm_timers(now);
      }
      // A crash in the swap-checkpoint window left a durable root whose E+1 membership is AHEAD of the
      // checkpoint (`config_install_op > checkpoint_op`). Pay that debt off the recovered root NOW —
      // BEFORE any traffic — driving the committed band to `>= config_install_op` and forcing the owed
      // checkpoint, so a freshly-restarted quiescent donor still converges to a servable E+1 checkpoint
      // with zero heartbeats. No-op when no debt is owed (the common recovery). The primary/mid-view-
      // change branches above do NOT call this: they re-enter a transition and pay once they next settle
      // Normal (the debt is sticky — re-checked from the commit-advance tails).
      self.maybe_pay_checkpoint_debt(now, sb, blocks);
    }
  }

  /// Rebuild a solo VOTER's commit pipeline for its recovered tail `(commit_min .. op]`, arm the
  /// Normal-primary timers, and drive `try_commit` — so the solo primary re-commits ops it already holds
  /// (an empty `inflight` would stall them; a solo voter commits via its own-vote quorum of 1). Mirrors
  /// `start_view_as_new_primary`'s rebuild. The caller establishes this IS the solo voter (a single-voter
  /// cluster, not a learner). Each rebuilt entry is content-addressed by the recovered operation IDENTITY
  /// (client, request, body) the op holds, keeping the `inflight.prepare_checksum == op driven` invariant
  /// uniform across seeding sites — a solo replica has no peers, so no PrepareOk is matched against it (the
  /// own-vote quorum-of-1 commits via `oks` directly), but the identity is stamped consistently.
  pub(crate) fn resume_solo_voter_pipeline<B: Superblock>(
    &mut self,
    now: Instant,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
    self.inflight.clear();
    let own = 1u64 << self.local_slot().get();
    for op in (self.commit_min.get() + 1)..=self.op.get() {
      let prepare_checksum = self
        .log
        .get(&op)
        .map(|e| crate::storage::prepare_identity(e.client, e.request, e.body.body_checksum()))
        .unwrap_or(0);
      self.inflight.insert(
        op,
        Inflight {
          oks: own,
          committed: false,
          prepare_checksum,
        },
      );
    }
    self.arm_timers(now);
    self.try_commit(now, sb, blocks);
  }

  /// Recover-retry timer: the SOLE retry+budget owner for the tail reads (and the checkpoint read), so
  /// the loop terminates even when a real async driver delivers a completion later than this cadence
  /// or drops one. For each still-PENDING op it re-submits an ADDITIVE read (a fresh id WITHOUT
  /// retiring the op's existing in-flight ids) and decrements the op's ABSOLUTE retransmission budget;
  /// once that budget reaches zero the op is resolved via [`Self::resolve_exhausted_tail_read`].
  ///
  /// The budget is ABSOLUTE (seeded once at the Phase-1 submit to `RECOVER_READ_RETRIES`, decremented
  /// ONLY here, never reset and never decremented by the Fault completion arm). Additivity is what
  /// fixes the slow-read wedge: every retransmission of an op shares the SAME op, so a (late)
  /// completion arriving under ANY still-live id resolves the op — whereas retiring the prior ids on
  /// each retry (the old behaviour) dropped a completion slower than `RECOVER_READ_RETRANSMIT` (its id
  /// was always already retired) and the budget — being reset — never reached zero, wedging recovery
  /// forever. A genuinely-dead slot still terminates: its budget counts down to zero across a bounded
  /// number of retransmissions and `resolve_exhausted_tail_read` routes it to peer-repair.
  ///
  /// Faulty ops are NOT re-read here: a `rec.faulty` op is already resolved (a peer-repaired hole), and
  /// the read fault that produced it is replayed by neither the completion arm nor this timer — only a
  /// still-PENDING op (one whose read has not yet resolved it) is retransmitted.
  pub(crate) fn recover_timeouts<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
    if self.timers.recover_retry.is_none_or(|d| d > now) {
      return;
    }
    // FIRST, self-heal an owed LOCAL install whose flush barrier faulted during the recovery peer-fetch
    // (`on_recover_sync_checkpoint` → `apply_sync`): the complete verified DAG is already local, so re-flush
    // + re-stage LOCALLY here (the Normal-only `sync_timeouts` does not run while Recovering). On success the
    // re-persist root drives `install_sync` + the flip to Normal; a still-failing flush leaves it owed and
    // the recover cadence re-attempts. No-op when none is owed / a write is in flight.
    self.retry_install_flush(now, sb, blocks);
    // If that just STAGED the re-persist (the flush succeeded), the recovery READ phase is done: the node
    // now waits for the `on_sb_done` root completion, not a timer. Retire the recovery/solicit bookkeeping
    // exactly as `on_recover_sync_checkpoint` does on a fresh staged reply — a still-armed recover-retry /
    // sync-solicit would spin a poll_timeout driver (neither is serviced while Recovering with a staged sync).
    if self.pending_checkpoint.is_some() {
      self.recover = None;
      self.timers.recover_retry = None;
      self.timers.sync_solicit = None;
      return;
    }
    // Snapshot the PENDING ops (the in-flight tail reads) so we can re-borrow `recover` per op while
    // iterating. Faulty ops are NOT re-read (already resolved to a peer-repaired hole).
    let (ops, want_checkpoint, checkpoint_retries, awaiting_peer) = match self.recover.as_ref() {
      Some(rec) => (
        rec.pending.keys().copied().collect::<std::vec::Vec<u64>>(),
        rec.checkpoint,
        rec.checkpoint_retries,
        rec.awaiting_peer_checkpoint,
      ),
      None => (std::vec::Vec::new(), None, 0, false),
    };
    // Peer-fetch: if our own checkpoint read exhausted and we are awaiting a PEER `SyncCheckpoint`,
    // re-broadcast the `RequestSync` on this cadence (the Normal-only `sync_timeouts` does not run
    // while Recovering). A peer holding a checkpoint `>= ours` answers; until then we stay here.
    // With a block-fetch in progress (the SM checkpoint DAG is being pulled), this cadence is also
    // its ARQ: re-send the one outstanding `RequestBlock` for the frontier's next-missing block first,
    // exactly as `sync_timeouts` does for a Normal receiver.
    if awaiting_peer && self.sync.is_some() {
      self.send_request_block(now, blocks);
      self.send_request_sync(now);
    }
    for op in ops {
      // Read the op's ABSOLUTE budget under a brief immutable borrow, released before the method calls
      // below (`resolve_exhausted_tail_read`/`mint_op_id` re-borrow `self`/`self.recover`).
      let budget = self
        .recover
        .as_ref()
        .and_then(|rec| rec.pending.get(&op).copied());
      match budget {
        // Exhausted: resolve from the durable header (keep header-only as Repairing, or route to
        // peer-repair). This both removes `op` from `rec.pending` and drops all its in-flight ids.
        Some(0) => self.resolve_exhausted_tail_read(wal, op),
        Some(budget) => {
          // Re-submit an ADDITIVE read — a fresh id that does NOT retire the op's existing in-flight
          // ids, so a slow completion under an earlier id still resolves the op — and decrement the
          // absolute budget by one.
          let new_id = self.mint_op_id();
          if let Some(rec) = self.recover.as_mut() {
            rec.pending.insert(op, budget - 1);
            rec.reads.insert(new_id.get(), op);
          }
          wal.submit_read(new_id, OpNumber::with(op));
        }
        // No budget entry ⇒ `op` is no longer pending (resolved between the snapshot and here) — skip.
        None => {}
      }
    }
    // Re-issue the checkpoint read if it is still outstanding (a prior completion was dropped or is slow),
    // decrementing the ABSOLUTE budget — `recover_timeouts` is the SOLE checkpoint retry+budget owner, the
    // exact mirror of the tail-read ownership above. ADDITIVE: submit a fresh id but do NOT retire prior
    // in-flight reads (`on_recover_sb_done` accepts any VALID read while one is outstanding, so a slow read
    // completing after this retransmit still resolves). Counting the budget per TICK here — never per FAULT
    // in the completion arm — is what makes it robust BOTH to a fault STORM (several superseded additive
    // reads faulting out of order would each over-count a per-fault budget) AND to a fault that lands AFTER
    // this re-mint (latency over the retransmit interval would be missed by a strict per-id fault match):
    // the count is independent of which id any fault arrives under. On exhaustion (budget zero) escalate to
    // a PEER FETCH — the durable root names a permanently-unreadable or root-inconsistent snapshot
    // (bit-rot/torn write in this replica's single durable copy), unrecoverable from local disk.
    if want_checkpoint.is_some() {
      if checkpoint_retries == 0 {
        // Permanently-unreadable OWN checkpoint: any peer at/above it subsumes ours — NOT a cross-epoch
        // crossing (no epoch target to pin), so target our own `checkpoint_op` with the requirement off.
        self.escalate_checkpoint_to_peer_fetch(now, self.checkpoint_op, false);
      } else {
        let new_id = self.mint_op_id();
        if let Some(rec) = self.recover.as_mut() {
          rec.checkpoint = Some(new_id.get());
          rec.checkpoint_retries = checkpoint_retries - 1;
        }
        sb.submit_read_checkpoint(new_id);
      }
    }
    // Re-arm so we keep retrying until the loop completes.
    self.timers.recover_retry = Some(now + RECOVER_READ_RETRANSMIT);
    // Drive the transition decider: a budget-exhaustion resolution above
    // (`resolve_exhausted_tail_read`) removed the op from `rec.pending` WITHOUT producing a WAL
    // completion, so unlike a clean read it does NOT route through `on_recover_wal_done` →
    // `recover_progress`. Without this call, exhausting the LAST pending op's budget here would leave
    // recovery stuck `Recovering` forever (nothing else re-evaluates the transition). Idempotent: it
    // re-arms and returns while any read is still pending, and finalizes only once `rec.pending` empties.
    self.recover_progress(now, sb, blocks);
  }

  /// RecoveringHead solicitation timer: re-broadcast the `Recovery` request (and re-arm) until a
  /// peer's `RecoveryResponse`/`StartView` re-establishes the head and adoption returns us to Normal.
  ///
  /// This is also the ONE evaluation point of the re-formation ESCALATION. A coordinated
  /// all-restart into a bumped epoch can leave a voting quorum in `RecoveringHead` with no `Normal`
  /// node to answer a `Recovery` — `RecoveringHead` otherwise has no escalation path, a permanent
  /// wedge. We escalate into a view change iff ALL of:
  /// - `epoch > prev_epoch` — a reconfiguration genuinely happened. The only endpoint assignments to
  ///   `prev_epoch` are genesis (`prev_epoch == epoch`) and `recover` (the durable root's
  ///   `prev_epoch`), so off an offline restart this is unsatisfiable — the gate is wholly inert without
  ///   a real reconfiguration, and stays true for the whole reset incarnation (so it re-arms across a
  ///   re-wedge at any view), auto-expiring only on a further genuine `epoch++`.
  /// - `reform_attempts >= RECOVER_HEAD_REFORM_ATTEMPTS` (G1) — enough solicitation windows elapsed
  ///   that a LIVE quorum would have answered, so a legitimately-slow recovery never escalates.
  /// - `peers_recovering.count_ones() >= quorum - 1` (G2) — at least the OTHER voters of a voting
  ///   quorum (exclude self) are concurrently `RecoveringHead`, the actual wedge signature.
  ///
  /// READ-BEFORE-CLEAR: the gate is evaluated on the CURRENT `peers_recovering` snapshot, which is
  /// only then cleared for the next window — clearing first would pin G2 at 0 and never fire. On a
  /// fire we escalate and DO NOT also re-broadcast `Recovery` this tick.
  pub(crate) fn recover_head_timeouts<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    if self.timers.recover_head.is_none_or(|d| d > now) {
      return;
    }
    // Per-window bookkeeping under one `recover` borrow (absent a live incarnation there is nothing to
    // escalate): count this solicitation window toward G1 (saturating); INTERSECT the current window's
    // co-recovering OTHER-voter set with the PREVIOUS window's, so only a voter seen co-recovering in
    // TWO CONSECUTIVE windows counts toward G2; then roll the ring (this window becomes `prev`) and
    // CLEAR for the next window (read-before-clear). The two-window intersection is freshness by
    // construction — see [`Self::may_escalate_reformation`].
    let commit_max = self.commit_max.get();
    let Some((reform_attempts, fresh_corecovering, committed_band_intact)) =
      self.recover.as_mut().map(|rec| {
        rec.reform_attempts = rec.reform_attempts.saturating_add(1);
        let fresh = rec.peers_recovering & rec.peers_recovering_prev;
        rec.peers_recovering_prev = rec.peers_recovering;
        rec.peers_recovering = 0;
        // No faulty slot remains in the COMMITTED band: a committed op this replica cannot vouch (a
        // StaleCommitted slot, or one it never held — both routed to `rec.faulty`, NOT the now-Repairing
        // read-fault path) would be OMITTED from its DoViewChange, so escalating + solo/minimal-forming a
        // view change could lose it. Refuse to escalate while one exists; stay RecoveringHead and keep
        // soliciting — a peer that holds the op can re-establish the head and supply it. (Every
        // `rec.faulty` op is above `checkpoint_op`; we test the committed band `op <= commit_max`.)
        let intact = !rec.faulty.iter().any(|&op| op <= commit_max);
        (rec.reform_attempts, fresh, intact)
      })
    else {
      return;
    };
    if self.may_escalate_reformation(reform_attempts, fresh_corecovering, committed_band_intact) {
      self.retire_recover_and_escalate(now, sb);
      return;
    }
    self.send_recovery(now); // re-broadcasts and re-arms recover_head
  }

  /// Whether a `RecoveringHead` voter may escalate the all-`RecoveringHead` wedge into a view change —
  /// the SINGLE chokepoint for the whole re-formation gate, so no sub-case can be reopened in isolation.
  /// ALL must hold:
  /// - `replica_count() > 1`: a SOLO voting set cannot view-change (no quorum to re-form among, and
  ///   `quorum - 1 == 0` would make the co-recovering check vacuous) — like `forfeit` holding a solo
  ///   primary rather than abdicating to a non-existent quorum.
  /// - `is_voter(local_slot())`: only a VOTER escalates; a LEARNER reaches `RecoveringHead` too but is
  ///   never a view-change / SVC / DVC participant.
  /// - `epoch() > prev_epoch`: an offline reset — off-axis-unsatisfiable, the byte-identity fence.
  /// - `reform_attempts >= RECOVER_HEAD_REFORM_ATTEMPTS` (G1): enough solicitation windows elapsed that
  ///   a reachable Normal quorum would have answered and pulled this node OUT of `RecoveringHead`.
  /// - `fresh_corecovering.count_ones() >= quorum - 1` (G2): a quorum of OTHER voters CONTINUOUSLY
  ///   co-recovering across the last two solicitation windows (`peers_recovering & peers_recovering_prev`).
  ///   The two-window intersection is FRESHNESS BY CONSTRUCTION: a peer is `RecoveringHead` for at most
  ///   ONE contiguous interval per incarnation (the sole entry sets it and every exit leaves it, with no
  ///   path back without a fresh `recover()`), re-broadcasting `Recovery` EVERY window for that whole
  ///   interval and emitting none once it leaves — so a genuinely-wedged peer's bit is in BOTH windows,
  ///   while a single late stale `Recovery` from a since-recovered peer is in at most one window and the
  ///   intersection drops it.
  ///
  /// G2 is a BEST-EFFORT disruption-avoidance heuristic, NOT a safety gate. The network is unreliable —
  /// it may DELAY and DUPLICATE messages — so two stale same-epoch `Recovery` duplicates from a peer
  /// that has since returned to `Normal` can both land within the two-window intersection and spuriously
  /// satisfy G2, triggering an escalation with no live co-recovering quorum. That is harmless: a spurious
  /// escalation only recruits the healthy quorum into one unnecessary but always-SAFE, convergent view
  /// change. Committed-op safety rests SOLELY on `select_canonical_log` (the write-quorum ∩
  /// view-change-quorum intersection retains every committed op, the canonical-generation union, the
  /// `commit_star` floor and its release-active `commit_star <= op_head` fail-stop, and
  /// `assert_committed_survives` at every destructive site) — NEVER on G2's freshness. The escalator
  /// enters the view change at the SAME `log_view` as the rest (the escalation bumps `view`, never
  /// `log_view`), so it is an equal co-canonical donor whose only droppable op is its own
  /// strictly-uncommitted faulty tail. Hardening G2 against replay would treat a liveness heuristic as if
  /// safety depended on it (and need a wire-format sequence + per-peer state) — a posture this
  /// crash-fault state machine deliberately avoids, exactly like TigerBeetle.
  ///
  /// `committed_band_intact` IS a safety guard (unlike G2): this replica must hold NO unvouchable slot in
  /// its committed band (`op <= commit_max`). A committed op it cannot vouch would be OMITTED from its
  /// DoViewChange, and if it then becomes the solo/minimal-quorum primary for `view + 1` (decisively at
  /// `quorum_view_change == 1`) the op is lost. Refusing keeps it `RecoveringHead`, soliciting — a peer
  /// that holds the op can re-establish the head and supply it; a liveness wedge is the correct trade
  /// over a committed-op loss. (A held committed read-fault is now carried as `Body::Repairing`, not
  /// faulty, so this fires only for a genuinely unvouchable committed slot.)
  fn may_escalate_reformation(
    &self,
    reform_attempts: u8,
    fresh_corecovering: u64,
    committed_band_intact: bool,
  ) -> bool {
    let other_voters = self.membership.quorum().saturating_sub(1);
    self.membership.replica_count() > 1
      && self.membership.is_voter(self.local_slot())
      && self.membership.epoch() > self.prev_epoch
      && committed_band_intact
      && reform_attempts >= RECOVER_HEAD_REFORM_ATTEMPTS
      && (fresh_corecovering.count_ones() as usize) >= other_voters
  }

  /// Retire `RecoveringHead` and escalate into a view change at `view + 1` — the re-formation
  /// chokepoint, fired by [`Self::recover_head_timeouts`] once the gate holds. EVERY wedged voter
  /// recovered the SAME durable view `V` from the coordinated reset, so all target `V + 1` uniformly
  /// and the cluster re-forms.
  ///
  /// `recover = None` is EXPLICIT (`reset_for_view_transition`, reached via `enter_view_change`, does
  /// NOT clear `recover`), dropping the re-formation counters with it. This deliberately does NOT go
  /// through `complete_recovery`: that path's primary/backup role-branching (abdicate to `view + 1`
  /// vs resume Normal) would split a freshly-reset cluster's view targets, whereas every wedged voter
  /// must converge on the single `view + 1`.
  fn retire_recover_and_escalate<B: Superblock>(&mut self, now: Instant, sb: &mut B) {
    self.recover = None;
    self.enter_view_change_from_recovery(now, sb, self.view.next());
  }

  /// Receive a `SyncCheckpoint` while RECOVERING and AWAITING A PEER CHECKPOINT — the escalation
  /// path for a replica whose OWN durable checkpoint snapshot read back permanently unreadable/
  /// inconsistent ([`Self::recover_timeouts`] checkpoint-budget exhaustion → a peer fetch). It cannot
  /// restore its SM from disk, so it solicited a peer; this verifies and applies the answer,
  /// completing recovery.
  ///
  /// Verification (no SM mutation until ALL pass): an outstanding forced `sync` with a matching nonce;
  /// the peer is at least as advanced as our corrupt checkpoint (`checkpoint_op >= self.checkpoint_op`,
  /// so its snapshot subsumes ours and never rewinds the applied frontier — `commit_min ==
  /// checkpoint_op` here); the LOAD-BEARING self-consistency integrity gate `checkpoint_id(snapshot)
  /// == checkpoint_id`; and a clean decode. Any failure REJECTS the message (no panic, no restore) and
  /// leaves us awaiting — the recover-retry timer re-solicits and another peer answers.
  ///
  /// On full success it hands off to the SHARED [`Self::apply_sync`], which STAGES the durable re-persist
  /// (write the snapshot, then in `on_sb_done` the new root naming it) but does NOTHING destructive yet —
  /// it abandons local recovery (`recover = None`) and STAYS `Recovering`. Both the install (restore
  /// SM + sessions, advance the frontier, prune the WAL) AND the flip to `Normal` DEFER to `on_sb_done`
  /// (the durable root), exactly like the Normal deferred-sync path: its `CheckpointKind::SyncRepersist`
  /// arm installs, advances `checkpoint_op`, then `complete_recovery` flips to Normal and
  /// abdicates/rebuilds/resumes. The re-persist completion is routed by the TYPED `pc.kind` (not status),
  /// so staging while Recovering is sound, and a `Recovering` replica is excluded from all Normal-path
  /// participation by the central ingress — so there is NO window where a Normal node holds an advanced
  /// commit frontier + pruned WAL over a durable root still naming the OLD checkpoint. Recovery is
  /// complete the instant the synced checkpoint root is durable.
  pub(crate) fn on_recover_sync_checkpoint<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
    from: Peer,
    m: crate::SyncCheckpoint,
  ) {
    debug_assert!(self.status.is_recovering() && self.awaiting_peer_checkpoint());
    let Some(s) = self.sync else {
      return; // no sync outstanding — ignore (should not happen while awaiting, but be defensive).
    };
    if m.nonce() != s.nonce {
      return; // a reply to a prior solicitation / forged — not fresh.
    }
    // SINGLE-SUPERBLOCK-WRITER (the same fence the Normal ingress uses): defer the re-persist while a
    // root is in flight — a `Recovering` peer-fetch can have a recovery-driven durable-view write
    // (`pending_sb`) outstanding, and staging the two-write re-persist now would put a second
    // superblock root in flight. `sync` (+ the peer-fetch) stays armed; the solicit timer re-fetches
    // once the root lands. (`pending_checkpoint` cannot be set on this path — it stages none until
    // `apply_sync` — but the guard is symmetric with the Normal ingress.)
    if self.pending_sb.is_some() || self.pending_checkpoint.is_some() {
      return;
    }
    if m.checkpoint_op().get() < self.checkpoint_op.get() {
      return; // does not even reach our (corrupt) checkpoint — cannot subsume it; ignore.
    }
    // The load-bearing integrity gate: never restore a snapshot whose bytes do not hash to the
    // advertised id (corrupt / forged / torn). Verified BEFORE any mutation; reject + keep awaiting.
    if crate::checkpoint_id(m.snapshot()) != m.checkpoint_id() {
      return;
    }
    // SM-RECONSTRUCT obligation owed while still Recovering (a post-root restore faulted; `self.checkpoint_op
    // == M`): a fresh reply AT M re-pulls M's DAG from THIS donor — donor FAILOVER for a dead pinned donor —
    // rather than re-staging. A reply ABOVE M supersedes the obligation forward (it falls through, and
    // `begin_recover_block_sync` clears the obligation as it re-stages). The `< M` reply was already dropped.
    if self.sm_reconstruct_owed() && m.checkpoint_op() == self.checkpoint_op {
      self.refetch_sm_reconstruct(now, wal, sb, blocks, from, &m);
      return;
    }
    // Decode must succeed before we commit to applying (apply_sync also decodes, but verifying here
    // keeps the irreversible status flip below from ever stranding us Normal with an unrestored SM).
    // The op BOUND into the snapshot must equal the advertised `checkpoint_op` — a faulty peer
    // shipping stale bytes under an overstated op would otherwise advance our frontier past the
    // snapshot's real content. Verified HERE too (not only in `apply_sync`) so the Normal flip below
    // never strands us with an unrestored SM on a bind mismatch.
    let (sm_root, sessions_root) = match Self::decode_checkpoint(m.snapshot()) {
      Some((bound_op, sm_root, sessions_root)) if bound_op == m.checkpoint_op() => {
        (sm_root, sessions_root)
      }
      _ => return, // unparsable, or the bound op disagrees with the advertised op — reject, keep awaiting.
    };
    // The SM state AND the session table live in the BlockStore (the envelope only names them by
    // `sm_root` / `sessions_root`). Fetch BOTH checkpoint DAGs before installing: arm a `block_fetch`
    // (saving this verified `SyncCheckpoint` to replay once both drain) and pull the first missing block,
    // staying Recovering. When the frontiers drain, `on_block_response`'s recovering branch re-enters HERE
    // with the DAGs fully present, at which point `begin_recover_block_sync` reports complete and we fall
    // through to the tail-resolution + `apply_sync` below. A malformed DAG drops the fetch and keeps the
    // peer-fetch armed (re-solicits). A stale same-config reply whose blocks are already local drains the
    // block-fetch here (clearing `block_fetch = None`), but `apply_sync` keeps `sync` Some for a crossing,
    // and `recover_timeouts` re-arms the `RequestSync` solicit — so the crossing is never permanently
    // wedged by a stale drain.
    if !self.begin_recover_block_sync(now, blocks, from, &m, sm_root, sessions_root) {
      return; // blocks still missing (or malformed) — the fetch/ARQ continues; nothing installed yet.
    }
    // Every still-IN-FLIGHT tail op that `apply_sync` would RETAIN above the synced checkpoint holds only
    // a Phase-1 `Present(empty)` placeholder, and its WAL read completion is ignored once `recover` is
    // cleared below — so it must NOT survive into Normal: `advance_commit` would apply a committed op with
    // `&[]`, and a view change would advertise the empty-body header (an op above this replica's stale
    // durable `commit_max` can still be committed later, or already be committed elsewhere). Resolve each
    // from its durable header instead of WAITING for the read: this path ABANDONS local recovery
    // (`recover = None` below) and flips to Normal, so a later read completion is ignored — there is no
    // one left to drive `rec.pending` to empty. Apply the SAME verdict the storage-path exhaustion uses,
    // via the shared `inflight_tail_repairing_identity`: KEEP it header-only as `Body::Repairing` only
    // when Verified — a committed op that matches the canonical band, or an uncommitted op whose header
    // is CURRENT-GENERATION (its `view` is not below the durable `log_view`, so it is not a superseded
    // earlier-view proposal this replica has abandoned). Else DROP it to a peer-repaired hole (a committed
    // StaleCommitted slot routes through `rec.faulty` so the `finalize_recovery` survival assert holds; an
    // uncommitted hole is just removed, never advertised).
    let durable_commit = self.commit_max.get();
    let synced_checkpoint = m.checkpoint_op().get();
    let pending_tail: std::vec::Vec<u64> = self
      .recover
      .as_ref()
      .map(|rec| {
        rec
          .pending
          .keys()
          .copied()
          .filter(|&op| op > synced_checkpoint)
          .collect()
      })
      .unwrap_or_default();
    for op in pending_tail {
      // The SAME placement + `classify_committed_slot` verdict the storage-path exhaustion uses
      // (`resolve_exhausted_tail_read`), via the one shared source so the two paths cannot drift.
      let keep = self.inflight_tail_repairing_identity(wal, op);
      if let Some(rec) = self.recover.as_mut() {
        rec.pending.remove(&op);
        rec.reads.retain(|_, &mut o| o != op);
      }
      match keep {
        Some((client, request, body_checksum)) => {
          if let Some(rec) = self.recover.as_mut() {
            rec.faulty.remove(&op);
          }
          self.log.insert(
            op,
            LogEntry {
              client,
              request,
              body: Body::Repairing(body_checksum),
            },
          );
        }
        None if op <= durable_commit => {
          if let Some(rec) = self.recover.as_mut() {
            rec.faulty.insert(op);
          }
        }
        None => {
          self.log.remove(&op);
        }
      }
    }
    // CENTRALIZED committed-band drop via the `finalize_recovery` choke: before we abandon local recovery
    // (`recover = None` discards `rec.faulty`) and `apply_sync` (whose held-tail retain KEEPS `self.log`
    // entries above the synced checkpoint), drop every faulty committed-band slot's EMPTY placeholder
    // (including the now-faulty in-flight reads routed above) so none survives as `Some({body: EMPTY})`
    // for a later `advance_commit` to apply with `&[]`. The peer-checkpoint-fetch path completes HERE (not
    // through `recover_progress`'s finalize tail), so it routes the drop through the SAME choke (which
    // also debug-asserts no faulty slot survives). Each dropped slot is a genuine repair hole
    // `advance_commit` peer-repairs on demand.
    self.finalize_recovery();
    // STAGE the durable re-persist via the shared state-sync core, but STAY Recovering: both the
    // destructive install (`install_sync`: restore the SM/sessions, advance `commit_min`/`commit_max`/`op`,
    // prune the WAL) AND the flip-to-Normal DEFER to `on_sb_done` (the durable root), exactly like the
    // Normal deferred-sync path. A `Recovering` replica is excluded from ALL Normal-path participation by
    // the central ingress (it accepts only `SyncCheckpoint` + the `BlockResponse`s that feed the fetch),
    // so there is NO window where a Normal node holds an advanced commit frontier + pruned WAL over a
    // durable root still naming the OLD checkpoint. The re-persist completion is routed by the TYPED
    // `pc.kind` (not status), so staging while
    // Recovering is sound; `on_sb_done`'s SyncRepersist arm installs, advances `checkpoint_op`, then
    // `complete_recovery` flips to Normal and abdicates/rebuilds/resumes — atomically, with the durable
    // root already caught up to the synced frontier.
    //
    // Pin the donor to the AUTHENTICATED sender slot — the slot the recovery sender-binding established
    // this laggard routes to (NOT the donor's self-claimed, possibly-shifted `replica()`). `apply_sync`
    // records it on the staged install so a POST-ROOT install error can re-pull THIS checkpoint's block
    // from the same donor. A non-routeable sender cannot have answered this fetch (the ingress binding
    // dropped it); keep the peer-fetch armed for the re-solicit rather than fabricate a target.
    let Some(donor) = from.as_replica() else {
      return;
    };
    self.apply_sync(now, sb, blocks, donor, &m);
    // `apply_sync` STAGES a `pending_checkpoint` (+ `pending_install`) iff it accepted the reply; it stages
    // NOTHING on a reject (a corrupt membership, or — the cross-epoch crossing requirement — a below-target
    // / empty-membership reply that does not cross). ONLY when it staged is the recovery READ phase done:
    // abandon local recovery bookkeeping and retire the recovery/solicit timers (the node waits for
    // `on_sb_done`, not a timer; a still-armed recover-retry / sync-solicit would spin a poll_timeout-driven
    // driver, neither serviced while Recovering with a staged sync). On a REJECT we must KEEP the peer-fetch
    // armed (`recover` + `awaiting_peer_checkpoint` + the solicit timer) so it re-fetches from another donor
    // — tearing `recover` down here would silently end the fetch at the old epoch.
    if self.pending_checkpoint.is_some() {
      self.recover = None;
      self.timers.recover_retry = None;
      self.timers.sync_solicit = None;
    }
  }

  /// Drive the recovery peer-fetch's SM-checkpoint-DAG block fetch. Returns `true` iff the DAG rooted at
  /// `sm_root` is FULLY present (the caller then proceeds to install via `apply_sync`); `false` iff it
  /// armed (or re-pumped) a `block_fetch` and is still pulling — or aborted a malformed DAG — in which
  /// case nothing is installed yet and the ARQ continues. The verified `SyncCheckpoint` `m` is saved into
  /// the `block_fetch` so `on_block_response`'s recovering branch replays it back into
  /// `on_recover_sync_checkpoint` once the frontier drains. Mirrors [`Self::begin_block_sync`] but stays
  /// Recovering (the install + flip-to-Normal defer to the durable re-persist root).
  fn begin_recover_block_sync(
    &mut self,
    now: Instant,
    blocks: &mut dyn BlockStore,
    from: Peer,
    m: &crate::SyncCheckpoint,
    sm_root: BlockAddress,
    sessions_root: BlockAddress,
  ) -> bool {
    // A reply reaching here while an SM-reconstruct obligation is owed is, by the ingress gates, a
    // STRICTLY-NEWER checkpoint (`> self.checkpoint_op == M`): it SUPERSEDES the obligation forward (its own
    // install reconstructs the SM to the newer point). The obligation is KEPT owed through this peer-fetch,
    // mirroring `begin_block_sync`: it is dropped only when `apply_sync` atomically stages the replacement
    // `pending_install`, so a STALLED fetch or a REJECTED reply leaves the obligation to keep reconstructing
    // M rather than wiping it. The drain routes a SAME-M fetch to the SM-content retry and a NEWER M'
    // through `on_recover_sync_checkpoint` → `apply_sync` (which clears the obligation at stage time).
    // A RETAINED-but-not-staged install (a prior verified install whose flush faulted, still owed as
    // `pending_install` with no in-flight checkpoint — the ingress gate rules out a staged one) is LEFT INTACT
    // here, mirroring `begin_block_sync`: it is the local flush-retry source, a LIVE GC root, and a verified
    // crossing's `cross_epoch_intent` shield. A fresh peer-fetch may STALL or have its reply REJECTED by
    // `apply_sync`, so clearing on entry would leave nothing to re-flush + drop the owed DAG's GC mark before
    // any replacement exists. The owed install is dropped ONLY when `apply_sync` stages a fresh
    // `PendingInstall` (which atomically REPLACES it) or a teardown cancels it.
    // Pin the donor to the AUTHENTICATED sender slot (the slot the recovery sender-binding check
    // established this laggard routes to), not the donor's self-claimed (possibly shifted) `replica()` — a
    // cross-epoch donor's successor-epoch slot is un-routeable in this OLD-epoch laggard's membership. A
    // non-replica sender cannot have answered; abort the fetch (keeping the peer-fetch armed for the
    // re-solicit) rather than fabricate a target.
    let Some(donor) = from.as_replica() else {
      self.block_fetch = None;
      return false;
    };
    // Seed both frontiers (SM + session). The fetch is complete only when BOTH drain.
    let mut bf = BlockFetch {
      checkpoint: m.clone(),
      sm_root,
      sessions_root,
      donor,
      block_sync: super::block_sync::BlockSync::new(sm_root),
      session_sync: super::block_sync::BlockSync::new(sessions_root),
      // A recovery peer-fetch can itself be cross-epoch — record the crossing presentation from the
      // checkpoint metadata (the non-Normal `awaiting_peer_checkpoint` shield already governs the crossing
      // predicates here, so this only keeps the bit consistent across all arming sites).
      crossing_answered: self.checkpoint_presents_crossing(m),
      // Carry the re-solicit latch forward across a same-root re-pin: a DUPLICATE same-root recovery
      // checkpoint re-walks the same front and inherits the latch, so it cannot re-arm one re-solicit per
      // duplicate; a genuine NEW root resets to `None` so its first absent legitimately re-solicits.
      resolicited_front: self.carry_resolicit_latch(sm_root, sessions_root),
    };
    let next = match bf.next_missing(&*blocks) {
      Ok(next) => next,
      Err(_) => {
        // A malformed/foreign DAG: abort the fetch, keep the peer-fetch armed (re-solicits a fresh one).
        self.block_fetch = None;
        return false;
      }
    };
    match next {
      None => {
        // Both DAGs are present — clear any in-flight fetch and tell the caller to install.
        self.block_fetch = None;
        true
      }
      Some(addr) => {
        // REPLACE the whole block-fetch (superseding any prior fetch — the recovery re-pin strand cannot
        // leave a stale frontier).
        self.block_fetch = Some(bf);
        self.emit(Outgoing::new(
          Recipient::To(Peer::Replica(donor)),
          Message::RequestBlock(addr),
        ));
        // While Recovering the `recover_retry` cadence (not `sync_solicit`) re-drives the pull, so
        // re-arm that timer to keep the ARQ alive.
        self.arm_timers(now);
        false
      }
    }
  }

  /// Higher-view rule: a newer primary already exists (we saw its Prepare/Commit/PrepareOk) and we
  /// are merely stale. Fetch its log via GetView; do NOT broadcast a StartViewChange. If catch-up
  /// stalls, `view_change_status` escalates us to a real, self-driven change.
  ///
  /// **Plausibility-clamped at ingress.** This is the one place an UNVALIDATED view scalar (a
  /// `Prepare`/`PrepareOk`/`Commit` view field, carrying no adoptable payload to cross-check) is
  /// adopted wholesale, so an implausible claim — more than [`MAX_VIEW_JUMP`] ahead of the local
  /// view — is dropped here as a no-op (the message it rode in on is ignored) rather than stranding
  /// this replica in a `ViewChange` no real primary can answer. Every earnable lag is far below the
  /// bound (see the constant's rationale), so a legitimate catch-up is never rejected; the validated
  /// adoption vehicles (`on_start_view`/`on_recovery_response`, sender-bound to the claimed view's
  /// primary) remain unclamped.
  pub(crate) fn catch_up_to_view(&mut self, now: Instant, view: View) {
    if self.sync_repersist_root_staged() {
      // Defer: a state-sync re-persist root is staged. Let it install to the synced point first (the
      // install is destructive and cannot run interleaved with the catch-up posture). The higher-view
      // Prepare/Commit/PrepareOk that drove us here retransmits, re-driving catch-up from the synced state.
      return;
    }
    if view.get() > self.view.get().saturating_add(MAX_VIEW_JUMP) {
      return; // implausible advertised view (see MAX_VIEW_JUMP) — ignore the claim, stay put.
    }
    assert!(
      view.get() > self.view.get(),
      "catch-up target must be strictly newer than our view"
    );
    self.view = view;
    self.enter_catch_up_posture(now);
  }

  /// Enter the catching-up `ViewChange` posture AT the current `self.view`: reset old-generation
  /// in-flight state, install a `catching_up = true` collection, and solicit `GetView`. It sends NO
  /// StartViewChange / DoViewChange (the `view_change_status` escalation that would emit one is
  /// voter-only), so a non-voting learner can use it to re-fetch the canonical head without ever casting a
  /// view-change vote — adopting the (same-or-newer-view) StartView restores `log_view == view` and returns it to
  /// Normal. The two callers establish `self.view` themselves: [`Self::catch_up_to_view`] advances it to
  /// a strictly-higher advertised view first; the learner recovery re-establishment
  /// ([`Self::complete_recovery`]) leaves it at the current view (re-fetching THIS view's installed log
  /// after a crash left `log_view < view`).
  fn enter_catch_up_posture(&mut self, now: Instant) {
    self.set_status(Status::ViewChange);
    self.svc_target = self.view;
    // Tear down ALL old-generation in-flight state in one place: SVC bits, in-flight
    // appends, peer-checkpoint reports, in-flight checkpoint, in-flight sync + its deferred install
    // (cancelled together — durable-before-install leaves the old state intact), and the
    // forfeit sub-state. See [`Self::reset_for_view_transition`] for the per-field rationale.
    self.reset_for_view_transition(now);
    // ViewChange ENTRY (the catch-up): install a fresh collection with `catching_up = true` — this entry
    // sends GetView, not SVC/DVC. (`is_some() == is_view_change()` coupling.)
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
    let primary = self.membership.primary(self.view);
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(primary)),
      Message::GetView(crate::GetView::new(
        self.view,
        self.local_slot(),
        self.nonce,
        self.membership.epoch(),
        self.membership.config_id(),
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
      Message::Recovery(crate::Recovery::new(
        self.local_slot(),
        self.nonce,
        self.membership.epoch(),
        self.membership.config_id(),
      )),
    ));
    self.timers.recover_head = Some(now + RECOVER_HEAD_SOLICIT);
  }

  pub(crate) fn on_get_view(&mut self, _now: Instant, m: crate::GetView) {
    // Only a Normal primary at the requested view (or higher) can answer authoritatively — AND only
    // once its view is DURABLE: `participates_as_primary` adds the `!pending_durable_view()`
    // clause, so a primary that just adopted its view but has not yet persisted it does NOT hand out a
    // `StartView` for that not-yet-recoverable view (it would, on crash, regress out of a view it had
    // already vouched for to a soliciting peer). A commit-first SwapEpoch root does NOT block it (the view
    // is durable through an epoch swap). The deferred `start_view_participate` broadcasts the StartView
    // once the view is durable, and a later `GetView` is then answered normally.
    if self.participates_as_primary() && self.view.get() >= m.view().get() {
      // Advertise the KNOWN-committed frontier `commit_max`, not the APPLIED frontier `commit_min`
      // (which stalls below an unrepaired committed `Repairing` hole) — see `start_view_participate`.
      // A catching-up peer that adopts a committed op (op <= commit_max) thereby learns it is committed
      // and HOLDS at the hole until peer-repair fills the body, instead of treating it as a truncatable
      // uncommitted tail. `commit_max <= self.op` on a Normal primary, so the receiver's `commit <= op`
      // adopt guard holds.
      let entries = self.log_entries();
      self.emit(Outgoing::new(
        Recipient::To(Peer::Replica(m.replica())),
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
          // The vouched floor of the carried log: an op it omits at/below this is
          // checkpoint-subsumed (the catching-up adopter trims its own sub-floor band + records the
          // floor for its force-sync escalation).
          .with_checkpoint_op(self.log_floor),
        ),
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
    // Durable-view-before-participate: while a view-CHANGING/adoption superblock write is
    // pending, status is Normal but the current view is NOT yet durable. A primary answering here with
    // its canonical `(op, commit, log)` — and even a Normal backup answering with its (non-durable)
    // view + echoed nonce — reports authority in a view a crash could regress out of, the same
    // cross-view hazard `on_get_view`'s StartView gate closes. A commit-first SwapEpoch root does NOT
    // raise this fence (the view is durable through an epoch swap — [`Self::pending_durable_view`]). Gate
    // the WHOLE handler: a recovering peer simply re-solicits (its `recover_head` timer retransmits the
    // `Recovery`) until our view is durable, at which point we answer normally. (Backups have no canonical
    // head anyway; the strict gate keeps both branches from reporting a not-yet-recoverable view.)
    if self.pending_durable_view() {
      return;
    }
    if m.replica().get() >= self.membership.node_count() {
      return; // the requester must be a configured cluster member (in `0..node_count`)
    }
    let (op, commit, floor, log) = if self.is_primary() {
      // Advertise the KNOWN-committed frontier `commit_max`, not the APPLIED frontier `commit_min`
      // (which stalls below an unrepaired committed `Repairing` hole) — the recovery-handshake
      // equivalent of `start_view_participate`'s StartView. A recovering peer that adopts a committed
      // op (op <= commit_max) thereby learns it is committed and HOLDS at the hole until peer-repair
      // fills the body, never re-classifying it as a truncatable uncommitted tail. `commit_max <=
      // self.op` on a Normal primary, so the receiver's `commit <= op` adopt guard holds. The
      // vouched log floor rides along so the adopter trims its own sub-floor band + records the
      // floor for its force-sync escalation (same as a StartView).
      (self.op, self.commit_max, self.log_floor, self.log_entries())
    } else {
      // A backup cannot hand out a canonical head; it reports only its view (+ echoed nonce).
      (
        OpNumber::new(),
        OpNumber::new(),
        OpNumber::new(),
        std::vec::Vec::new(),
      )
    };
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(m.replica())),
      Message::RecoveryResponse(
        crate::RecoveryResponse::new(
          self.view,
          op,
          commit,
          self.membership.epoch(),
          self.membership.config_id(),
          self.local_slot(),
          m.nonce(),
          log,
        )
        .with_checkpoint_op(floor),
      ),
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
    blocks: &mut dyn BlockStore,
    m: crate::RecoveryResponse,
  ) {
    if !self.status.is_recovering_head() {
      return; // not awaiting a head (already Normal, or never solicited) — ignore the stale reply
    }
    // Freshness is only as strong as the nonce: it is seed-derived, so distinguishing THIS
    // incarnation's solicitation from a previous incarnation's relies on the embedder feeding
    // `recover()` per-incarnation entropy (see the `seed` contract there). With a reused seed a
    // delayed prior-incarnation response passes this check.
    if m.nonce() != self.nonce {
      return; // a response to a prior solicitation (or forged) — not fresh, ignore
    }
    if m.view().get() < self.view.get() {
      return; // a stale-view response cannot re-establish our head
    }
    if m.replica() != self.membership.primary(m.view()) {
      // A non-primary response (empty log) only confirms the current generation; we cannot adopt a
      // head from it. Stay RecoveringHead; the recover_head timer keeps soliciting until the
      // primary answers (or a StartView arrives).
      return;
    }
    if self.sync_repersist_root_staged() {
      // Defensive (a `RecoveringHead` replica carries no Normal-path state-sync re-persist): defer the
      // adopt while a re-persist root is staged, symmetric with `on_start_view`. The recover-head timer
      // re-solicits, re-driving the adopt once the sync installs.
      return;
    }
    self.adopt_canonical_head(
      now,
      sb,
      blocks,
      m.view(),
      m.op(),
      m.commit(),
      m.checkpoint_op(),
      m.log_slice(),
    );
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

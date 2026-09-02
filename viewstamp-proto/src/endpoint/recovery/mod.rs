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

/// Why [`Endpoint::recover`] refused to reconstruct an endpoint from the durable store.
///
/// Every variant is a fail-fast STARTUP refusal, raised before any storage read is submitted or any
/// message emitted: the store itself is intact, but booting over it with the offered live parameters
/// would be unsafe (geometry drift silently moves the recovery scan window off a committed WAL tail)
/// or dead-on-arrival (a WAL below the liveness floor wedges the primary at its first un-releasable
/// mint stall). The remedy is operational — restore the recorded parameters, or perform an explicit
/// offline migration — never a retry loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecoverError {
  /// The backend's [`Wal::capacity`] is below [`Config::minimum_wal_capacity`](crate::Config) — one
  /// full checkpoint interval plus one op of progress room — so the mint stall could never release
  /// and the primary would wedge.
  #[error(
    "Wal::capacity() {capacity} is below the liveness floor {minimum} (one checkpoint interval + 1)"
  )]
  WalCapacityBelowMinimum {
    /// The capacity the backend reported.
    capacity: u64,
    /// The floor the active `Config` requires ([`Config::minimum_wal_capacity`](crate::Config)).
    minimum: u64,
  },
  /// The durable root pinned a different `checkpoint_ops` than the live [`Config`](crate::Config)
  /// carries. The recovery scan window is derived from the interval, so restarting under a smaller
  /// one can clip a committed WAL tail out of the scan (amnesia); a changed interval also breaks the
  /// cluster-wide checkpoint cadence agreement. Restore the recorded value (or migrate offline).
  #[error(
    "Config::checkpoint_ops {configured} differs from the {stored} this store was written under"
  )]
  CheckpointOpsChanged {
    /// The interval the durable root pinned.
    stored: u64,
    /// The interval the live `Config` carries.
    configured: u64,
  },
  /// The backend reported a different [`Wal::capacity`] than the durable root pinned. Capacity
  /// determines both the recovery scan window and a bounded backend's physical op→slot placement, so
  /// reopening under a different value silently relocates/clips committed slots. Restore the recorded
  /// capacity (or migrate the ring offline and rewrite the root).
  #[error("Wal::capacity() {reported} differs from the {stored} this store was written under")]
  WalCapacityChanged {
    /// The capacity the durable root pinned.
    stored: u64,
    /// The capacity the backend reports now.
    reported: u64,
  },
  /// The durable root carries consensus state but records no complete WAL-GEOMETRY pair (a zero
  /// `checkpoint_ops` or `wal_capacity` half) — an un-stamped root this codebase never writes. With an
  /// unrecorded pair there is nothing to validate the live parameters against, and scanning under
  /// UNVALIDATED live geometry can silently move the recovery window off a committed WAL tail (the
  /// amnesia hazard the fence exists to close) — so recovery refuses FAIL-CLOSED rather than
  /// proceeding on trust. Recovery never auto-pins (that would bless the live geometry as if it were
  /// the writer's); the remedy is an explicit offline migration: rewrite the root as a
  /// current-version root recording the verified historical geometry. A VIRGIN store
  /// ([`VsrState::new()`](crate::VsrState)) is not this case — it has no consensus state to lose and
  /// routes to the wiped-voter / genesis logic instead.
  #[error(
    "the durable root carries consensus state but no recorded WAL geometry (checkpoint_ops {checkpoint_ops}, wal_capacity {wal_capacity}): migrate the store offline to a root recording its verified geometry"
  )]
  GeometryNotRecorded {
    /// The `checkpoint_ops` half the durable root recorded (`0` = unrecorded).
    checkpoint_ops: u64,
    /// The `wal_capacity` half the durable root recorded (`0` = unrecorded).
    wal_capacity: u64,
  },
  /// This node is a VOTER and its durable root is empty (`VsrState::new()`) — a WIPED disk (its only
  /// durable copy replaced with an empty store), or a virgin store the operator forgot to
  /// [`format()`](crate::format). Raised for ANY empty-rooted voter regardless of surviving WAL headers:
  /// a voter's genesis always writes a durable format root, so an empty root means that witness (and the
  /// durable view it voted in) is gone. A wipe destroys exactly the durable vote that made the old commit
  /// quorum intersect a new view's quorum, so letting an empty-rooted voter back into the voting set —
  /// even resuming as a backup, or abdicating as primary — can let that view commit a DIFFERENT value
  /// at an already-committed op number (quorum-intersection amnesia). The wiped state is beyond the
  /// fault budget and must FAIL-STOP: re-provision explicitly ([`format()`](crate::format) as a new
  /// member, or restore the store from backup; a first-class rejoin-by-sync is a later capability). A
  /// FORMATTED store is exempt (its geometry witness a wipe cannot forge); a non-voting learner is
  /// exempt (it never votes and may resume empty to state-sync from the voters).
  #[error(
    "this node is a voter with an empty durable root (wiped or unformatted): format a new cluster or restore from backup"
  )]
  UnformattedVoter,
}

/// Why [`format()`](crate::format) refused to initialize a store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FormatError {
  /// The superblock already carries a durable root — the store is not empty. `format` is a
  /// once-per-store cluster-creation step and never clobbers existing consensus state; an existing
  /// member restarts via [`Endpoint::recover`] instead.
  #[error("format refused: the store already carries a durable root")]
  AlreadyInitialized,
  /// The backend's [`Wal::capacity`] is below [`Config::minimum_wal_capacity`](crate::Config) — one
  /// full checkpoint interval plus one op of progress room — so a cluster formatted over it could
  /// never release the mint stall (a wedged primary), and [`Endpoint::recover`](crate::Endpoint)
  /// would refuse the store outright ([`RecoverError::WalCapacityBelowMinimum`]). Refused BEFORE the
  /// genesis write, so the store stays VIRGIN: the operator re-`format`s over a correctly-sized WAL
  /// (nothing was pinned, nothing to migrate). Validating here is what keeps `format` from durably
  /// initializing an unbootable store — the genesis root pins the geometry pair, so a floor
  /// violation pinned once would leave every later boot refused (`recover` rejects the floor,
  /// resizing trips the capacity fence, re-`format` is `AlreadyInitialized`).
  #[error(
    "format refused: Wal::capacity() {capacity} is below the liveness floor {minimum} (one checkpoint interval + 1)"
  )]
  WalCapacityBelowMinimum {
    /// The capacity the backend reported.
    capacity: u64,
    /// The floor the `Config` requires ([`Config::minimum_wal_capacity`](crate::Config)).
    minimum: u64,
  },
  /// The declared WAL capacity (the `wal_capacity` a [`Genesis`](crate::Genesis) carries, passed to
  /// [`Endpoint::new`](crate::Endpoint::new) / [`Endpoint::with_reconfig`](crate::Endpoint::with_reconfig))
  /// does not equal the backend's live [`Wal::capacity`]. [`Genesis::commit`](crate::Genesis::commit)
  /// pins the ACTUAL `wal.capacity()` into the durable genesis root, so a declared value that disagrees
  /// with the backend would yield a runnable voter whose in-memory geometry contradicts its own durable
  /// root: later checkpoint/view roots stamp one capacity while the WAL is physically laid out under the
  /// other, which can pass recovery's geometry fence at the next boot yet scan under a layout different
  /// from the WAL's real one — the hidden-committed-tail amnesia that fence exists to close. Refused
  /// BEFORE the genesis write, so the store stays VIRGIN: re-declare the capacity as the backend's
  /// [`Wal::capacity`] (`u64::MAX` for an unbounded backend) and commit again.
  #[error(
    "genesis commit refused: declared Wal capacity {declared} does not match the backend's {actual}"
  )]
  WalCapacityMismatch {
    /// The capacity the caller DECLARED (the `wal_capacity` the [`Genesis`](crate::Genesis) carries).
    declared: u64,
    /// The capacity the backend actually reports ([`Wal::capacity`]).
    actual: u64,
  },
  /// The genesis-root write did not become durable synchronously: [`Superblock::poll`] drained
  /// without delivering the write's [`SuperblockDone::Wrote`], so the store is NOT yet formatted.
  /// `format` is a one-time init that requires the superblock to complete the genesis write
  /// synchronously (a blocking write + fsync, distinct from the async steady-state path a running
  /// driver pumps); a backend whose writes only complete under a running I/O loop must be driven to
  /// durability by that loop before the genesis root can be witnessed. Returning this rather than a
  /// silent `Ok` prevents booting a "formatted" store whose root never actually landed.
  #[error(
    "format failed: the genesis-root write did not complete synchronously (store not formatted)"
  )]
  WriteNotDurable,
}

/// Initialize a VIRGIN store as a member of a NEW cluster — the trusted cluster-creation step, the
/// analogue of TigerBeetle's `format`. It writes the durable GENESIS ROOT: empty consensus state
/// (view 0, op 0, no checkpoint) carrying the genesis `membership` and the WAL-GEOMETRY pair
/// (`config.checkpoint_ops()` + the backend's [`Wal::capacity`]) pinned, and confirms it landed
/// synchronously.
///
/// This is the SOLE producer of the FORMATTED witness that [`Endpoint::recover`] keys its
/// genesis-primary decision on: a formatted root carries a nonzero `checkpoint_ops` that an
/// empty-consensus wipe can never forge, so recovery can safely resume a formatted genesis store's
/// designated primary at view 0 while refusing to do so for an unformatted (fresh or WIPED) store —
/// the wiped member abdicates and re-learns any committed op it forgot from a surviving peer, rather
/// than resuming as a view-0 primary and recommitting an op number under an intersecting quorum.
///
/// **Synchronous-durability contract.** `format` runs at cluster creation, BEFORE any driver run
/// loop exists to pump async I/O, so it requires the superblock to complete the genesis-root write
/// SYNCHRONOUSLY — the write must be durable (delivered as [`SuperblockDone::Wrote`] on a
/// [`Superblock::poll`] before `format` returns), exactly as TigerBeetle's `format` does one blocking
/// write + fsync and exits. A disk backend's format-time write is that blocking path, distinct from
/// the async steady-state writes the running driver pumps. If the write does NOT land synchronously,
/// `format` returns [`FormatError::WriteNotDurable`] rather than a silent `Ok` over a store whose
/// genesis root never became durable (which a later `recover` would read as unformatted, or a crash
/// would lose).
///
/// Call it ONCE per store at cluster creation (before the first [`Endpoint::recover`]); a restarting
/// existing member does NOT call it. It is deliberately not idempotent past initialization.
///
/// # Errors
/// [`FormatError::AlreadyInitialized`] if the superblock already holds a durable root (a non-empty
/// [`VsrState`](crate::VsrState)) — `format` never overwrites existing consensus state.
/// [`FormatError::WalCapacityBelowMinimum`] if the backend's [`Wal::capacity`] is below
/// [`Config::minimum_wal_capacity`](crate::Config) — refused BEFORE the genesis write, so the store
/// stays virgin and re-formattable over a correctly-sized WAL (pinning the undersized geometry would
/// otherwise brick the store: every later `recover` refuses the floor, and re-`format` refuses the
/// now-initialized store).
/// [`FormatError::WriteNotDurable`] if the genesis-root write did not complete synchronously.
pub fn format<W: Wal, B: Superblock>(
  config: &Config,
  membership: &Membership,
  wal: &W,
  sb: &mut B,
) -> Result<(), FormatError> {
  // Refuse to clobber a store that already carries consensus state. A wiped/virgin store decodes as
  // `VsrState::new()` and is initializable; a formatted or previously-run store is not (the operator
  // restarts it via `recover`). `state()` is the authority — a rot-able `op_head()` scalar is never
  // the basis for a durability decision (the recovery contract's core rule). Checked FIRST: an
  // initialized store's recorded geometry governs it (recover validates against the root), so the
  // live capacity is not this call's business there.
  if sb.state() != crate::VsrState::new() {
    return Err(FormatError::AlreadyInitialized);
  }
  // Validate the geometry BEFORE the one-time genesis write, while the store is still virgin. The
  // genesis root pins `(config.checkpoint_ops(), wal.capacity())` irreversibly, so an undersized
  // capacity pinned here would initialize a store no boot can ever accept: `recover` refuses the
  // liveness floor, resizing the ring trips the capacity fence, and re-`format` refuses the
  // initialized store. Refusing pre-write keeps the failure recoverable (fix the WAL, format again).
  // The floor also guarantees the pinned capacity is nonzero (`minimum >= checkpoint_ops + 1 >= 2`),
  // so a formatted root always carries a fully-recorded geometry pair.
  let capacity = wal.capacity();
  let minimum = config.minimum_wal_capacity();
  if capacity < minimum {
    return Err(FormatError::WalCapacityBelowMinimum { capacity, minimum });
  }
  let root = genesis_root(config, membership, capacity);
  // Tag the write with an incarnation of its own. If the genesis write does not land synchronously
  // this call returns `WriteNotDurable`, but the write is already with the backend and may complete
  // LATER; that leaked `Wrote` names an incarnation no endpoint holds, so any endpoint recovered over
  // this store refuses it at the choke. Without that, a leaked completion could match the first id a
  // recovered endpoint mints — sequences restart at 1 — and release a `DoViewChange` before its
  // durable-view root landed.
  sb.submit_write(
    crate::WriteId::new(super::next_incarnation(), 1),
    root.clone(),
  );
  // Drain completions so a synchronous backend's write becomes visible on `state()`, then require the
  // durable root to equal EXACTLY the root THIS call submitted. That single equality is both:
  //  - the SYNCHRONOUS-DURABILITY check: an async backend whose write has not completed leaves
  //    `state()` at the old empty root (`!= root`), so `format` returns `WriteNotDurable` rather than a
  //    silent `Ok` over a non-durable root (there is no run loop here to pump an async write — `format`
  //    precedes the driver — exactly as TigerBeetle's `format` does one blocking write + fsync);
  //  - the RETRY-SAFETY guard: a second `format` attempt over a store whose first attempt is still
  //    outstanding must NOT confirm success off the FIRST attempt's completion. `format` drains every
  //    completion without inspecting ids, so requiring
  //    `state() == root` means B succeeds only when the CURRENT durable root is B's own (equal to A's
  //    only when they carry the same membership — the harmless case). Root writes complete in
  //    submission order (the write-ordering contract), so no earlier attempt lands after a later Ok.
  // A root write completes only as `Wrote` — its `WriteId` admits no fault verdict — so no fault arm
  // is needed.
  while sb.poll().is_some() {}
  if sb.state() != root {
    return Err(FormatError::WriteNotDurable);
  }
  Ok(())
}

/// Build the canonical GENESIS ROOT for `membership` under `config`, with the WAL-geometry pair
/// pinned to `(config.checkpoint_ops(), wal_capacity)`. Empty consensus state (view 0, log_view 0,
/// commit 0, checkpoint_op 0, no committed-band headers); genesis epoch/prev_epoch/lineage; genesis
/// `config_install_op` and `log_floor` (both 0). Byte-identical to the root a fresh
/// [`Endpoint::with_reconfig`] endpoint's `durable_root` would produce for the same backend capacity
/// — [`format()`](crate::format) is the durable-init path, `durable_root` the running-node path, one shape.
fn genesis_root(config: &Config, membership: &Membership, wal_capacity: u64) -> crate::VsrState {
  crate::VsrState::try_new_v4(
    View::new(),
    View::new(),
    OpNumber::new(),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
    membership.epoch(),
    // Genesis: the lineage has no predecessor, so prev_epoch == the genesis epoch and the prior-id
    // ring is seeded with the genesis config_id (mirrors `with_reconfig`).
    membership.epoch(),
    membership.clone(),
    std::vec![membership.config_id(); LINEAGE_RING],
    OpNumber::new(),
  )
  .expect("a genesis root satisfies every VsrState invariant by construction")
  .with_log_floor(OpNumber::new())
  .expect("log_floor 0 == checkpoint_op 0")
  .with_wal_geometry(config.checkpoint_ops(), wal_capacity)
}

/// The outcome of [`Endpoint::recover`]: this node either still belongs to the recovered membership
/// (`Active`, holding a recovering [`Endpoint`]) or was removed by a reconfiguration (`Retired`, a
/// terminal handle).
///
/// A node absent from the recovered membership has been removed by a reconfiguration; it recovers
/// `Retired` and must not act as a replica. The membership is resolved from the DURABLE root: a
/// root carrying its own membership wins; a membership-less root bridges to the genesis membership
/// the caller supplies. This node is then resolved by its stable [`MemberId`]
/// ([`Config::local`](crate::Config)); present (a voter or learner) → `Active`, absent → `Retired`.
///
/// `large_enum_variant` is allowed deliberately: this is a `Result`-shaped, transient START-UP
/// handle — `recover` returns exactly ONE, the caller destructures it immediately, and it is never
/// stored in a collection — so the per-`Active`-variant memory the lint guards against is irrelevant,
/// while boxing the common (`Active`) path would add a needless heap allocation on every successful
/// recover (the same reason [`Result`] does not box its `Ok`).
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Recovered<S: StateMachine, R = RestartOnly> {
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

impl<S: StateMachine, R> Recovered<S, R> {
  /// True iff this is [`Recovered::Active`] (the node occupies a slot and resumes as an endpoint).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_active(&self) -> bool {
    matches!(self, Recovered::Active(_))
  }

  /// True iff this is [`Recovered::Retired`] (a reconfiguration removed the node).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_retired(&self) -> bool {
    matches!(self, Recovered::Retired(_))
  }

  /// Consumes the outcome, yielding the recovering endpoint — `None` for a retired node.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn try_active(self) -> Option<Endpoint<S, R>> {
    match self {
      Recovered::Active(endpoint) => Some(endpoint),
      Recovered::Retired(_) => None,
    }
  }

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
  ///
  /// # Errors
  /// [`RecoverError`] when the live parameters are unsafe over this store — a WAL below the liveness
  /// floor, a non-virgin root whose geometry pair is unrecorded or differs from the live values, or
  /// a wiped voter; see [`Self::recover_with_reconfig`].
  pub fn recover<W: Wal, B: Superblock>(
    config: Config,
    membership: Membership,
    seed: u64,
    sm: S,
    storage: &mut Storage<W, B, S>,
  ) -> Result<Recovered<S, RestartOnly>, RecoverError> {
    Self::recover_with_reconfig(config, membership, seed, sm, storage)
  }
}

impl<S: StateMachine, R: Reconfig> Endpoint<S, R> {
  /// Reconstructs an endpoint under an EXPLICIT reconfiguration capability marker `R` from durable
  /// storage after a restart — a **metadata-only constructor** that enters [`Status::Recovering`] and
  /// defers all fallible reads to an async `handle_storage` loop (faults-as-data; spec §2/§6). It does
  /// NOT return in `Normal`. The ergonomic [`Self::recover`] is the [`RestartOnly`] entry point and
  /// defers here, so every bare `Endpoint::recover(..)` call resolves unannotated.
  ///
  /// **Phase 1 (here, sync + infallible).** Reads only synchronous trait metadata — the session's
  /// two roots (the LANDED `sb.state()` and the EFFECTIVE `Storage::effective_root`, one value
  /// whenever no root write is in flight; the constructor body states the per-field split rule)
  /// and `wal.header(op)` (the durable-header scan that derives the written extent) — and
  /// constructs the endpoint with:
  /// - `view`/`log_view` from the EFFECTIVE root (every root this endpoint writes stamps them from
  ///   live memory, so baselining below the timeline would mint rewinding roots), `op` = the
  ///   scanned written extent floored at the durable commit (never the `op_head()` scalar),
  ///   `checkpoint_op` from the LANDED root (the backend serves reads against the durable root's
  ///   generation), `commit_min = checkpoint_op` (the restored SM already
  ///   reflects `[1..=checkpoint_op]`, so this prevents a double-apply), and `commit_max` from the
  ///   EFFECTIVE root's commit — the known-committed frontier the medium is guaranteed to reach,
  ///   `>= checkpoint_op` and possibly above it, so
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
  /// is trustworthy: a recovered replica resumes the view it was in when it last participated. Over
  /// a LIVE session the two halves of that sentence can name different roots, and the constructor
  /// keeps them apart: `view` baselines on the EFFECTIVE root (an inherited in-flight root write
  /// lands in queue order underneath the successor, so any root this endpoint later writes must
  /// carry a view at least the timeline's — baselining below it would rewind the durable view the
  /// moment the inherited root landed first), while `durable_view` baselines on the LANDED root
  /// (only landed state survives a process death; an in-flight root that dies with the process must
  /// not have licensed participation in its view). The gap closes without any action of this
  /// endpoint's: the inherited landing is settled by the session and absorbed in `on_sb_done`,
  /// which lifts the witness — until then every participation gate holds, exactly as it holds for
  /// an own durable-view write still in flight.
  ///
  /// **`membership` (the DURABLE-membership rule).** The active membership is resolved from the
  /// LANDED root — never from a root still in flight, and not blindly from the param: installing a
  /// configuration (or retiring a member) is participation, and participation follows durable
  /// proof, so an in-flight epoch-advancing root confers nothing until its landing is absorbed
  /// (`on_sb_done`'s configuration adoption installs it then, with the durable proof in hand). A
  /// membership-bearing landed root wins — the durable config is authoritative, so an offline
  /// reconfiguration pre-written into the root takes effect on the next recover regardless of what
  /// the caller passes. A membership-less root (`membership_opt().is_none()`) has no durable
  /// membership, so `recover` BRIDGES to the passed `membership` — the genesis the embedder
  /// supplies (the param stays in the signature solely as this fallback). This node is then
  /// resolved against that membership by its stable [`MemberId`] ([`Config::local`]):
  /// present (a voter or learner) → [`Recovered::Active`] holding the recovering endpoint; ABSENT →
  /// [`Recovered::Retired`] (a reconfiguration DURABLY removed it — it must not act as a replica;
  /// an in-flight root that would remove it retires it live at the landing instead, never off
  /// un-landed state). The `Active` endpoint stores the resolved membership (a durable membership,
  /// never the param, when the root carries one).
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
  ///
  /// **The block lane is not this constructor's concern**, because nothing about it is reborn here.
  /// Its queue, the per-kind slots that bound its depth (one cell for each kind but `Serve`, plus
  /// the outstanding-serve cap) and the order its completions must arrive in all live in the
  /// [`Storage`] session, whose lifetime is the store's. So an endpoint rebuilt over a lane that
  /// never drained polls exactly the jobs its predecessor queued, and each completion — refused at
  /// the incarnation choke, publishing nothing — still releases the slot that admitted it. There is no occupancy to state, and therefore no way to state one that does
  /// not match what the lane will deliver.
  ///
  /// **Fail-fast parameter validation (the WAL-geometry fence).** Before any storage I/O, the live
  /// parameters are validated against the store. [`Wal::capacity`] below
  /// [`Config::minimum_wal_capacity`](crate::Config) is refused (the primary would wedge). A
  /// NON-virgin store (any durable root other than `VsrState::new()`) must record its full geometry
  /// pair ([`VsrState::checkpoint_ops`](crate::VsrState::checkpoint_ops) /
  /// [`VsrState::wal_capacity`](crate::VsrState::wal_capacity), both nonzero — every root this
  /// codebase writes does) AND that pair must match the live values — the scan window and a bounded
  /// ring's op→slot placement are derived from it, so a restart under different geometry could clip
  /// a committed tail. A non-virgin root with EITHER half unrecorded (an un-stamped root no
  /// persisting writer produces) is
  /// refused FAIL-CLOSED ([`RecoverError::GeometryNotRecorded`]): recovery never AUTO-pins an
  /// unrecorded store (that would bless the live geometry as the writer's) and never scans over one
  /// on trust; such stores must be migrated offline (rewritten as a current-version root recording
  /// the verified historical geometry) before recovery. A VIRGIN store (`VsrState::new()` — never
  /// formatted, or WIPED) has no consensus state a geometry drift could clip and nothing recorded to
  /// validate: it continues, and the format-witness gate in `complete_recovery` keeps it from
  /// resuming as a view-0 primary (an empty-store voter fails-stop with
  /// [`RecoverError::UnformattedVoter`], having no peer to recover from).
  ///
  /// # Errors
  /// [`RecoverError::WalCapacityBelowMinimum`], [`RecoverError::GeometryNotRecorded`],
  /// [`RecoverError::CheckpointOpsChanged`], [`RecoverError::WalCapacityChanged`], or
  /// [`RecoverError::UnformattedVoter`] — all raised before any storage read/write is submitted.
  pub fn recover_with_reconfig<W: Wal, B: Superblock>(
    config: Config,
    membership: Membership,
    seed: u64,
    sm: S,
    storage: &mut Storage<W, B, S>,
  ) -> Result<Recovered<S, R>, RecoverError> {
    // The recovery baseline is SPLIT across the session's two roots, by one rule per field:
    //
    // - A field baselines on the EFFECTIVE root (the back of the timeline — the state the medium
    //   is guaranteed to converge to, since completions arrive in queue order and the last one
    //   wins) iff this endpoint's own root writes stamp it FROM LIVE MEMORY, so an under-baseline
    //   would mint a root that lands after an inherited one and rewinds the durable value. That is
    //   `view`/`log_view` (every root carries `self.view`/`self.log_view`) and the known-committed
    //   frontier (every root carries `self.commit_max`).
    // - A field baselines on the LANDED root (`sb().state()` — what a crash of this process would
    //   recover, and what the backend serves reads against) iff participation or a terminal
    //   verdict depends on it, so an over-baseline would act on state a process death rolls back.
    //   That is the durable-view witness, the CONFIGURATION block (membership, `prev_epoch`, the
    //   lineage ring, `config_install_op`, and the `Active`/`Retired` resolution — installing a
    //   configuration, or retiring a member, off a root that never lands would be participation
    //   without durable proof), and the checkpoint anchor (`checkpoint_op`, the canonical band,
    //   `log_floor` — the backend's `submit_read_checkpoint` serves the DURABLE root's generation,
    //   so a restore targeted off the timeline could never read back locally).
    //
    // Landed-baselined fields never rewind through this endpoint's writes because the ROOT WRITERS
    // source them from the timeline, not from these baselines: the checkpoint pair and the
    // configuration block are copied forward off the effective root at every submit. The gap the
    // split leaves — memory at the landed root while an inherited root is still in flight — closes
    // without any action of this endpoint's: the landing settles through the session and
    // `on_sb_done` absorbs it (the durable-view lift, the configuration adoption, the inherited
    // checkpoint frontier). With no root in flight (every recovery after a real process death —
    // the queue died with the process) the two roots are one value and nothing here changes.
    //
    // FIRST, collapse every PARKED root on the timeline. Construction is the one moment at which
    // "no live correlation awaits any parked entry" is a structural fact — the session serves one
    // endpoint at a time and this one has minted nothing yet — so whoever parked a root is dead,
    // and a parked root was never handed to the medium (no completion can ever name it, nothing
    // physical exists for quiescence to wait on). Depth needs no help here — a dead incarnation's
    // parked root occupies the same role cell a live one's would — but BASELINING on it would be
    // baselining on state only a dead endpoint ever promised to write, and leaving it parked
    // would eventually LAND that promise. Collapsing reduces the timeline to what a crash
    // restart would recover PLUS the still-owed submitted front — every schedule this produces,
    // a crash at the same point also produces, minus the front the medium still owes either way.
    storage.collapse_parked_roots();
    let landed = storage.sb().state();
    let effective = storage.effective_root();
    // Fail-fast parameter validation, BEFORE any storage I/O is submitted. Order: the liveness floor
    // first (an under-sized ring is unsafe regardless of what the root pinned), then the pinned
    // geometry pair on any NON-virgin store — recorded-ness before value comparison, so the
    // changed-value fences only ever compare fully-recorded pairs.
    let capacity = storage.wal().capacity();
    let minimum = config.minimum_wal_capacity();
    if capacity < minimum {
      return Err(RecoverError::WalCapacityBelowMinimum { capacity, minimum });
    }
    // VIRGIN = the empty durable root `VsrState::new()` — a never-formatted or WIPED store. It has no
    // consensus state whose scan window a geometry drift could clip and nothing recorded to validate,
    // so it skips the geometry fence and routes to the wiped-voter fail-stop / genesis logic below.
    // The FORMATTED witness: a durable root written by [`format()`](crate::format) pins a nonzero
    // `checkpoint_ops`, which an empty-consensus wipe can never forge (a wiped store decodes as
    // `VsrState::new()`, geometry `(0, 0)`). On every path that proceeds past the fence the two
    // notions coincide (`formatted == !virgin`): a virgin root's geometry is `(0, 0)` by
    // construction, and a non-virgin root with EITHER half unrecorded is refused just below.
    let virgin = landed == crate::VsrState::new();
    let formatted = landed.checkpoint_ops() != 0;
    if !virgin {
      // A non-virgin store's geometry pair must be FULLY recorded. Every root this codebase writes
      // records both halves nonzero (`format` validates the floor; a live endpoint stamps its
      // config's validated interval and its declared/observed backend capacity), so a zero half here
      // is a root no persisting writer produces. There is nothing to validate the live parameters
      // against, and scanning under unvalidated live geometry can silently move the recovery window
      // off a committed tail — so refuse FAIL-CLOSED rather than proceed on trust. Recovery never
      // auto-pins an unrecorded store (that would bless the live geometry as if it were the
      // writer's — a committed-loss hazard on a dirty store); the remedy is an explicit offline
      // migration to a root recording the verified historical geometry.
      if landed.checkpoint_ops() == 0 || landed.wal_capacity() == 0 {
        return Err(RecoverError::GeometryNotRecorded {
          checkpoint_ops: landed.checkpoint_ops(),
          wal_capacity: landed.wal_capacity(),
        });
      }
      // The recorded pair MUST match the live configuration — the recovery scan window and a bounded
      // ring's op→slot placement are both derived from it, so a restart under different geometry
      // silently clips a committed tail.
      if landed.checkpoint_ops() != config.checkpoint_ops() {
        return Err(RecoverError::CheckpointOpsChanged {
          stored: landed.checkpoint_ops(),
          configured: config.checkpoint_ops(),
        });
      }
      if landed.wal_capacity() != capacity {
        return Err(RecoverError::WalCapacityChanged {
          stored: landed.wal_capacity(),
          reported: capacity,
        });
      }
    }
    // The DURABLE membership: the LANDED root's own membership is authoritative (the durable
    // config wins, so an offline reconfiguration pre-written into the root takes effect here); a
    // membership-less root carries none, so bridge to the passed genesis `membership`. The struct
    // stores THIS one — never a membership still in flight on the timeline: installing it (or
    // retiring on it) before its root lands would be participation a process death rolls back, so
    // an in-flight successor installs at its landing instead (`adopt_landed_configuration`).
    let membership = match landed.membership_opt() {
      Some(durable) => durable.clone(),
      None => membership,
    };
    // Resolve this node by its stable `MemberId` against the durable membership. ABSENT ⇒ a
    // reconfiguration DURABLY removed it: recover Retired (a terminal handle that never
    // participates), BEFORE any storage read is submitted. PRESENT (a voter or learner) ⇒ build
    // the recovering Endpoint — a still-in-flight root that removes it retires it live at the
    // landing, with the durable proof in hand, never here off un-landed state.
    let Some(local_slot) = membership.slot_of(config.local()) else {
      return Ok(Recovered::Retired(Retired {
        local: config.local(),
        epoch: membership.epoch(),
      }));
    };
    let nonce = Prng::new(seed).next_u64();
    let checkpoint_op = landed.checkpoint_op().get();
    // The recovery head is DERIVED by scanning the WAL's durable headers — TigerBeetle's
    // `op = journal.op_maximum()` — never trusted from the `op_head()` scalar, which bit-rot can turn
    // in EITHER direction: inflated (a phantom tail that would force unbounded work) or under-reporting
    // (hiding written committed slots — including a client-acked op in the band above the durable
    // `state.commit()`, which lags live `commit_max` between checkpoints and so witnesses nothing
    // there). The ring itself is the witness: `Wal::header(op)` is `Some` exactly for a completed
    // append (headers are durable independently of bodies — the trait-level header-durability
    // contract), so the highest placement-valid header in `(checkpoint_op .. checkpoint_op + effective]`
    // IS the written extent. The scan is synchronous, header-index-backed, and bounded by the EFFECTIVE
    // ring (`effective_wal_capacity` — the backend's own ring, or the proto-imposed ring for a ring-less
    // backend): the maximum extent a conforming append can reach above the checkpoint, enforced at
    // append time by the on_request mint stall + the ring-window backup guard. Scanning DOWN from the
    // ring top, the first hit is the head (the probes above it are the price of deriving instead of
    // trusting). The scan checks OCCUPANCY only — `header(probe).is_some()`, which the trait keys by op
    // (`Some` exactly for a completed append; `None` for never-written / pruned / ring-wrapped) — and
    // deliberately neither placement nor the header checksum: its question is written-ness, and bit-rot
    // does not un-append a slot, so a slot whose stored header content rotted (its `op` field included)
    // still bounds the window rather than being silently skipped below a held — possibly client-acked —
    // tail op. Every occupied slot's read then classifies the CONTENT: placement + `Header::verify` on
    // the completion, `verify_header` + the canonical-root fallback at the exhaustion resolver, and the
    // faulty-head machinery for what cannot be identified. Skipping is the loss direction;
    // over-inclusion only ever adds reads that resolve conservatively. Body reads are submitted only
    // for the REAL extent — a corrupt-inflated scalar no longer causes a phantom read storm; it causes
    // nothing at all.
    //
    // The window is additionally FLOORED at the top of the durable root's CANONICAL COMMITTED BAND
    // (`committed_headers_slice()`, op-ascending — the checksummed record of exactly the committed-band
    // ops this writer HELD): a held committed slot whose WAL HEADER also rotted is invisible to the
    // scan, but the band still vouches it, so the floor forces its read, which resolves through the
    // root's identity into a committed repair hole, peer-repaired on demand. The floor is the band's
    // EVIDENCE, deliberately NOT the raw `state.commit()` scalar: a corrupt in-model peer `commit` can
    // be adopted into live `commit_max` and then SEALED into a durable root, and a raw-scalar floor
    // would turn that poison into an unbounded dense read at every restart — whereas the band stops at
    // ops the writer genuinely held (it is size-validated, and a poisoned scalar mints no headers), so
    // the floor extends the window only by evidence-backed progress. Ops the root records as committed
    // but NOT held (no band entry — commit knowledge without the ops, the laggard shape) have nothing
    // local to read; they stay covered by `commit_max = state.commit()` and the Normal-path tail-gap /
    // repair solicitation, exactly as a synced/truncated replica's above-head band is. The floor never
    // inflates the SETTLED head: a floored slot genuinely gone reads back ABSENT and the settle
    // collapses `self.op` to the highest written op.
    //
    // The loop reads `(checkpoint_op .. hi]` in a SINGLE pass. `self.op` is PROVISIONAL here (the read
    // frontier); `recover_progress` re-derives it as the highest present-or-faulty op once the reads
    // resolve. Capping `self.op` at a verified op (never a phantom above the real head) preserves
    // append-before-ack: a later `Prepare` for a not-held op takes the append branch (the primary
    // re-sends; idempotent) rather than a blind re-ack.
    let ring_top = checkpoint_op.saturating_add(effective_wal_capacity(
      storage.wal().capacity(),
      config.checkpoint_ops(),
    ));
    let scan_head = (checkpoint_op.saturating_add(1)..=ring_top)
      .rev()
      .find(|&probe| storage.wal().header(OpNumber::with(probe)).is_some())
      .unwrap_or(checkpoint_op);
    // A VIRGIN VOTER must NOT boot — regardless of any surviving WAL headers. A voter's genesis ALWAYS
    // writes a durable FORMAT root (the only public route to a runnable voter is
    // [`Genesis::commit`](crate::Genesis::commit), which formats, or [`Endpoint::recover`] over an
    // already-durable store), so an empty durable root (`VsrState::new()`) on a voter means that format
    // witness is GONE: a wiped disk replaced its only durable copy, or the operator never formatted it.
    // A wipe destroys exactly the durable vote that made the old commit quorum intersect a new view's
    // quorum, so letting an empty-rooted voter back into the voting set — even resuming as a backup, or
    // abdicating as primary — can let a view commit a DIFFERENT value at an already-committed op number
    // (quorum-intersection amnesia). Surviving WAL headers do NOT rescue it: with the durable root (and
    // its recorded geometry) gone, the scan runs under UNVALIDATED live geometry that can silently hide
    // a committed tail, and the durable view it voted in is lost — so a virgin voter fails-stop whether
    // or not headers remain, rather than trusting them. Fail-stop: the wiped state is beyond the fault
    // budget and must be surfaced (re-`format` as a new member, or restore from backup; a first-class
    // rejoin-by-sync is a later capability). Exemptions: a FORMATTED store (`state != VsrState::new()`,
    // its nonzero-`checkpoint_ops` geometry witness a wipe cannot forge) recovers normally — a genesis
    // primary resumes and a recovered voter carries its real state; and a non-voting LEARNER — it never
    // votes, so it may resume empty and state-sync from the voters.
    if virgin && membership.is_voter(local_slot) {
      return Err(RecoverError::UnformattedVoter);
    }
    let canonical_top = landed
      .committed_headers_slice()
      .last()
      .map(|h| h.op().get())
      .unwrap_or(checkpoint_op);
    let hi = scan_head.max(canonical_top);
    // Never below the durable checkpoint (the SM snapshot owns `[1..=checkpoint_op]`, so the recovered
    // head must be at least `checkpoint_op` to preserve `op >= commit_max >= commit_min == checkpoint_op`).
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
    // takes the durable id; any slot the root did not record (an empty/short lineage — a pre-swap
    // root) falls back to the current `config_id` (a harmless self-duplicate that
    // admits nothing extra). For a no-reconfiguration cluster the durable lineage is genesis-only, so this
    // equals the plain `[config_id; LINEAGE_RING]` seeding.
    let mut lineage = [membership.config_id(); LINEAGE_RING];
    for (slot, id) in lineage.iter_mut().zip(landed.prior_config_ids()) {
      *slot = *id;
    }
    let mut endpoint = Self {
      config,
      // The backend capacity observed THIS incarnation (validated against the pinned root geometry
      // above), stamped into every durable root this incarnation writes.
      wal_capacity: storage.wal().capacity(),
      membership,
      // The durable backward link of the lineage: the root carries its own `prev_epoch`; a
      // membership-less root reads `prev_epoch == epoch == 0`, which equals the bridged genesis
      // membership's epoch — so this is correct for both, and every durable-root write this
      // incarnation makes re-persists the membership as a membership-bearing root carrying it.
      prev_epoch: landed.prev_epoch(),
      lineage,
      // RESTORE the cross-epoch serve gate: the op that produced the recovered membership. The root
      // carries it durably (the SwapEpoch / checkpoint / sync-successor / offline-restart writer threaded
      // it); a membership-less root defaults it to its own `checkpoint_op`. Without restoring it a donor
      // recovered into a swapped-but-not-yet-checkpointed window would re-attach its E+1 membership to a
      // checkpoint BELOW the reconfigure op, letting a laggard install E+1 without the committed prefix
      // through it.
      config_install_op: landed.config_install_op(),
      status: Status::Recovering,
      view: effective.view(),
      // The durable-view witness measures what a CRASH recovers, so it baselines on the LANDED
      // root — never the effective one: an inherited in-flight root dies with the process, and a
      // view licensed off it would be participation a crash rolls back (the cross-crash
      // double-vote the witness exists to prevent). While the timeline is ahead of the landed
      // root, `durable_view < view` and every participation gate holds; the inherited landing —
      // settled by the session, absorbed in `on_sb_done` — lifts the witness without any write of
      // this endpoint's. With no root in flight this equals the effective view exactly as before.
      durable_view: landed.view(),
      op: OpNumber::with(op),
      // The restored SM reflects [1..=checkpoint_op] exactly; commit_min = checkpoint_op so those ops
      // are NOT re-applied. commit_max = the EFFECTIVE root's commit (the known-committed frontier
      // the medium is guaranteed to reach — every root this endpoint writes stamps `commit_max`
      // from memory, so baselining below the timeline would mint a commit-rewinding root),
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
      // The caller-supplied SM is FRESH (content position 0) until the Recovering checkpoint read
      // restores it at `checkpoint_op` (`note_sm_restored`); the divergence from `commit_min` above
      // is exactly the recovery behind-window the (5c) content witness exempts by status. With no
      // durable checkpoint (`checkpoint_op == 0`, nothing to restore) the two start equal.
      sm_at: OpNumber::new(),
      commit_max: effective.commit(),
      log_view: effective.log_view(),
      svc_from: 0,
      svc_target: effective.view(),
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
      incarnation: super::next_incarnation(),
      next_op_id: 1,
      foreign_completions_rejected: 0,
      block_jobs_superseded: 0,
      block_serves_refused: 0,
      pending: BTreeMap::new(),
      // The slot-quiescence witnesses do NOT restart with the endpoint: they live in the
      // `Storage` session this successor is recovered over, with the medium's lifetime, so any
      // writes a predecessor still has with the device keep fencing their slots here exactly as
      // they did in the incarnation that submitted them. What is endpoint-lifetime is only the
      // LOGICAL half (`pending`/`appending`/`deferred_appends`): a fresh incarnation owes no
      // actions of its own yet.
      deferred_appends: BTreeMap::new(),
      // No op is wrongly judged "released" before the first `run_gc` re-raises this from 0: a
      // released-op judgment applies only to this incarnation's own writes.
      wal_pruned: 0,
      appending: std::collections::BTreeSet::new(),
      pending_sb: None,
      pending_checkpoint: None,
      inherited_frontier: None,
      // A successor baselines at/above every in-flight root (the effective root includes the
      // front), so no landing it inherits can outrun its own frontier the way an orphaned
      // re-persist outruns the incarnation that staged it.
      repersist_orphan: None,
      checkpoint_op: OpNumber::with(checkpoint_op),
      // Set when the durable checkpoint envelope is read back + restored (`on_recover_sb_done`),
      // which decodes the `sm_root`; `None` until then (block GC skips a cycle without a live root).
      checkpoint_sm_root: None,
      checkpoint_sessions_root: None,
      // The vouched log floor RESTORES from the durable root (the root persists the
      // adoption-learned cluster floor; the plain constructors default it to the root's own
      // `checkpoint_op` — the restart-at-checkpoint floor), capped at the recovered head: the floor bounds the carrier
      // span `op − log_floor`, and a floor above the head this WAL actually retained (an adoption
      // band un-synced at the crash) has nothing left to bound below it — the force-sync escalation
      // re-learns the cluster floor upward from the next carrier / peer checkpoint, exactly as
      // before. `state.log_floor() >= checkpoint_op` is decode-validated, and `op >= checkpoint_op`
      // by construction above, so the cap keeps both `(5b)` invariants (`log_floor >= checkpoint_op`,
      // `op >= log_floor`).
      log_floor: OpNumber::with(landed.log_floor().get().min(op)),
      peer_checkpoint: BTreeMap::new(),
      nack_from: BTreeMap::new(),
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
      sync_carried_faulty: std::collections::BTreeSet::new(),
      repair: std::collections::BTreeSet::new(),
      sync: None,
      // IN-MEMORY only: a crash drops the crossing intent; the recovery checkpoint-debt machine + the
      // cluster's higher-epoch heartbeats re-establish it after restart, so it starts `None` here.
      cross_epoch_intent: None,
      quarantined_donor: None,
      quarantine_probe_deadline: None,
      quarantine_probe_progress_mark: 0,
      sync_fetch_progress: 0,
      pending_install: None,
      block_fetch: None,
      deferred_pin: None,
      sm_reconstruct: None,
      sync_serving: BTreeMap::new(),
      state_syncs_applied: 0,
      forced_syncs_applied: 0,
      wal_stalls: 0,
      below_ring_window_syncs: 0,
      dag_walks_capped: 0,
      walk_pins_refused: 0,
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
      health_probe: None,
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
    // `formatted` is carried into the async completion path: `complete_recovery`'s genesis-primary
    // exemption reads it long after this synchronous Phase-1 setup returns.
    let mut rec = RecoverState {
      formatted,
      ..RecoverState::default()
    };
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
    // The band comes off the LANDED root while `commit_max` comes off the effective one, so a held
    // op committed only by a still-in-flight root ((landed commit .. effective commit]) has no
    // entry here: the read loop then classes its local copy UNPROVEN and peer-repairs it — the
    // conservative lane for identity evidence this store cannot yet vouch durably.
    for h in landed.committed_headers_slice() {
      rec
        .canonical
        .insert(h.op().get(), (h.client(), h.request(), h.body_checksum()));
    }
    // Read the whole tail window `(checkpoint_op .. hi]` in a SINGLE pass — `hi` is the scanned written
    // extent floored at the durable commit (see the window derivation above), so a conforming backend's
    // held tail is fully covered for any checkpoint interval with body reads proportional to the REAL
    // extent. `recover_progress` re-derives `self.op` as the highest VERIFIED op once the reads resolve.
    let lo = checkpoint_op.saturating_add(1);
    endpoint.recover = Some(rec);
    endpoint.submit_recover_tail_batch(storage, lo, hi);
    if checkpoint_op > 0 {
      let id = endpoint.mint_read_id();
      storage.submit_checkpoint_read(id);
      if let Some(rec) = endpoint.recover.as_mut() {
        rec.checkpoint = Some(id.seq());
        rec.checkpoint_retries = RECOVER_READ_RETRIES;
      }
    }
    // Settle the transition decider once: an EMPTY WAL with no checkpoint (the scan found no written
    // slot) has nothing to read, so it settles the terminal status HERE (a formatted genesis store
    // resumes Normal at view 0; an unformatted store abdicates / backs up — never a view-0 primary).
    // Otherwise this arms the recover_retry timer so an owner driving `poll_timeout`/`handle_timeout`
    // re-submits any read whose completion is dropped or whose transient fault clears on a later read.
    endpoint.recover_progress(Instant::ZERO, storage);
    Ok(Recovered::Active(endpoint))
  }

  /// Submit tail-body reads for the whole window `(lo ..= hi]`: materialize a Phase-1 header-only
  /// placeholder where the WAL already holds the durable header, and submit an authoritative read for EVERY
  /// slot (even one whose header is absent/faulty now — the read is the authoritative resolution, and a
  /// `Fault`/`Absent` completion routes through the retry/verdict path). Each read gets a freshly minted
  /// `OpId` (never aliases a future real op — `next_op_id` grows).
  fn submit_recover_tail_batch<W: Wal, B: Superblock>(
    &mut self,
    storage: &mut Storage<W, B, S>,
    lo: u64,
    hi: u64,
  ) {
    for op in lo..=hi {
      if let Some(h) = storage.wal().header(OpNumber::with(op)) {
        // A Phase-1 header-only PLACEHOLDER: the body is filled in by the read completion
        // (`on_recover_wal_done`). Kept as a `Present(empty)` body — NOT a `Body::Repairing` hole — a
        // recovering replica does not apply ops, so the empty placeholder is never read by the commit
        // path (it is filled, or dropped + peer-repaired, first).
        self
          .log
          .insert(op, LogEntry::present(h.client(), h.request(), Bytes::new()));
      }
      let id = self.mint_read_id();
      storage.submit_wal_read(id, OpNumber::with(op));
      if let Some(rec) = self.recover.as_mut() {
        rec.reads.insert(id.seq(), op);
        rec.pending.insert(op, RECOVER_READ_RETRIES);
      }
    }
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
    storage: &mut Storage<W, B, S>,
    done: WalDone,
  ) {
    // The OpId of the completed read identifies which tail op it resolves (recover.reads). An
    // append completion (Appended) or an OpId we are not tracking is a stale/foreign completion —
    // ignore it (never panic): faults-as-data.
    let id = match &done {
      WalDone::ReadOk(r) => r.id(),
      WalDone::Absent(id) | WalDone::Fault(id) => *id,
      WalDone::BodyFaulty(bf) => bf.id(),
      // An append completion whose write this endpoint still witnesses never reaches here —
      // `on_wal_done` absorbs it (retiring its `wal_writes` entry) BEFORE the recovering-status
      // routing, because a cross-epoch peer-fetch escalation can carry a live laggard's in-flight
      // appends into `Recovering`. What remains is stale/foreign: ignore, faults-as-data.
      WalDone::Appended(_) | WalDone::Cancelled(_) => return,
    };
    // `storage` is part of the uniform recover-completion signature (`handle_storage` passes it the
    // same way to every `on_recover_*` handler), but a completion carries its own outcome and this
    // handler submits no read — `recover_timeouts` owns retry/resolve.
    let _ = &mut *storage;
    // Capture the durable known-committed frontier + log_view BEFORE borrowing `rec` (the above-band
    // view check reads them, and `rec` mutably borrows `self.recover`). Both are
    // immutable during the recover loop (`advance_commit` runs only after recovery completes).
    let durable_commit = self.commit_max.get();
    let durable_log_view = self.log_view.get();
    let Some(rec) = self.recover.as_mut() else {
      return;
    };
    let Some(&op) = rec.reads.get(&id.seq()) else {
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
      // The WAL has NO slot for this op (never written). DEFINITIVE (a re-read stays absent), so it is
      // resolved immediately (never retried) into `rec.absent` — a slot the read window covered (the
      // durable-commit floor, or a scan/read inconsistency) that was never appended, resolved by
      // `recover_progress` (cap the head / reclassify an interior hole), NOT a retryable fault.
      Absent,
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
      // A durable-header read whose BODY is faulty (torn/rotted/absent): the header must first prove
      // ITSELF (`verify_header` — the backend may return it as stored, and a bit-rotted header with a
      // surviving `op` field is no identity witness) and land on the op we asked for; then run the SAME
      // `classify_committed_slot` verdict a clean read runs — only the body verdict differs (we lack
      // the bytes). A BodyFaulty that fails either gate — a misdirected-read sibling, or a
      // checksum-failing header — falls to `Fault` (the catch-all below) and retries, exactly like a
      // ReadOk that fails `verify`: a transient rot may clear on a re-read, and on exhaustion the
      // resolver (`inflight_tail_repairing_identity`, the ONE owner of the definitive no-body verdict)
      // applies the same `verify_header` gate with the canonical-root fallback.
      //   * Verified → KEEP the op header-only as `Body::Repairing` (existence preserved, body
      //     peer-repaired) rather than drop it — so a later view change can never re-mint its number.
      //   * StaleCommitted → drop + peer-repair the canonical body (a superseded/stale slot must NOT be
      //     resurrected as `Repairing`), exactly as a stale ReadOk is dropped.
      WalDone::BodyFaulty(bf)
        if bf.header().op() == OpNumber::with(op) && bf.header().verify_header() =>
      {
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
      // A slot the WAL does not have: DEFINITIVE (no retry). If the durable ROOT's canonical committed
      // band vouches the op (`rec.canonical` — the writer HELD it committed), the slot rotted away
      // rather than never existing: keep it header-only as `Body::Repairing` from the root's identity,
      // exactly as the header-absent exhaustion resolver does (`inflight_tail_repairing_identity`'s
      // canonical fallback) — a backend may report the rotted slot as `Absent` instead of faulting, and
      // the verdict must not depend on which of the two no-slot answers it gives. Otherwise a genuinely
      // never-written phantom → `rec.absent` — distinct from a Fault (a written-but-corrupt slot that
      // IS retried and drives `RecoveringHead` if it is the head).
      WalDone::Absent(_) => match rec.canonical.get(&op).copied() {
        Some((client, request, body_checksum)) => {
          Outcome::KeepRepairing(client, request, body_checksum)
        }
        None => Outcome::Absent,
      },
      _ => Outcome::Fault, // Fault, misdirected, OR a ReadOk that fails verify (torn/bit-rot).
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
        rec.reads.remove(&id.seq());
      }
      Outcome::Absent => {
        // The WAL has NO slot here (never written). DEFINITIVE — a re-read stays absent — so resolve it
        // immediately into `rec.absent` (never retry) and retire ALL of the op's reads. Drop any Phase-1
        // placeholder (an absent slot has no durable header, so normally there is none; defensive). This is
        // the phantom an over-counted / bit-rotted `op_head` reports above the highest slot actually
        // written; `recover_progress` caps `self.op` at the real head and discards the phantom (or, for an
        // op BELOW the real head, reclassifies it a faulty interior hole).
        rec.reads.retain(|_, &mut o| o != op);
        rec.pending.remove(&op);
        rec.faulty.remove(&op);
        rec.absent.insert(op);
        self.log.remove(&op);
      }
    }
    self.recover_progress(now, storage);
  }

  /// The identity verdict for resolving an in-flight tail op WITHOUT its body, from either durable
  /// witness: `Some(client, request, body_checksum)` — keep the op header-only as a `Body::Repairing`
  /// hole — when EITHER the WAL's durable header is SELF-CONSISTENT (`verify_header()` — a rotted
  /// header is no witness), placement-valid (`header().op() == op`), and classifies `Verified`, OR the
  /// WAL holds no usable header for the op (absent, or failing its own checksum) but the durable ROOT's
  /// canonical committed band does (`rec.canonical`, seeded from the checksummed `VsrState`): a
  /// root-vouched committed op whose WAL slot rotted entirely still has its existence + full identity
  /// witnessed by the root, so it becomes a committed repair hole (peer-repaired on demand) rather than
  /// `rec.faulty` — which, at the head, would drive `RecoveringHead` and wedge an all-restart quorum's
  /// reformation (the reform gate refuses while a committed faulty slot remains) even though the root
  /// carries everything needed to repair. A header that IS present but placement-invalid or
  /// non-`Verified` (a stale/superseded slot) still resolves `None` → faulty (the pinned
  /// drop-and-peer-repair semantics — the fallback never launders a stale slot through the root's
  /// identity). `None` otherwise. The SINGLE source of the verdict the Fault retry-exhaustion path
  /// (`resolve_exhausted_tail_read`) and the peer-checkpoint completion (`on_recover_sync_checkpoint`)
  /// both apply, so they cannot drift.
  fn inflight_tail_repairing_identity<W: Wal, B: Superblock>(
    &self,
    storage: &Storage<W, B, S>,
    op: u64,
  ) -> Option<(ClientId, RequestNumber, u128)> {
    let canonical = self
      .recover
      .as_ref()
      .and_then(|r| r.canonical.get(&op).copied());
    let Some(h) = storage.wal().header(OpNumber::with(op)) else {
      // No WAL header at all (the slot — header included — rotted away, or was never written): the
      // durable ROOT is the remaining witness. `rec.canonical` has entries only for committed-band ops
      // the writer HELD, so an uncommitted / never-held op still resolves `None` → faulty.
      return canonical;
    };
    if !h.verify_header() {
      // A header that fails its OWN checksum is no witness — bit-rot with a surviving `op` field must
      // not smuggle a corrupted `(client, request, body_checksum)` into a `Repairing` identity (peer
      // repair validates all three fields, so a garbage identity is an unfillable hole), nor drive the
      // classify-mismatch → faulty → `RecoveringHead` lane for an op the ROOT can still vouch.
      // Equivalent to the slot having no header: the root is the remaining witness.
      return canonical;
    }
    Some(h)
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

  /// Resolve a tail op whose ABSOLUTE read budget is exhausted, from its durable header. Any op whose
  /// durable header classifies `Verified` is KEPT header-only as `Body::Repairing` (existence + identity
  /// preserved so a later view change cannot re-mint its op number); a StaleCommitted/superseded slot or a
  /// slot with no durable header is routed to `rec.faulty` (a peer-repaired hole). This is the STORAGE-path
  /// resolution `recover_timeouts` invokes on budget exhaustion; it shares the VERDICT
  /// (`inflight_tail_repairing_identity`) with the always-Normal-bound message path
  /// (`on_recover_sync_checkpoint`), so the two do not drift.
  ///
  /// This does NOT itself decide the non-committed-faulty-HEAD case (route the head to `RecoveringHead`):
  /// under batched reads `self.op` here is only the PROVISIONAL batch frontier, so a boundary op with
  /// written ops in later batches is INTERIOR, not the head. `recover_progress` makes that call once the
  /// VERIFIED head is known — a `Repairing` head above `commit_max` is promoted to `rec.faulty` there.
  ///
  /// Keeping a NON-HEAD op ABOVE `commit_max` (an acked, cluster-committed op whose commit knowledge was
  /// not yet durable — the storage-fault committed-loss shape) is what makes the nack-truncation counting
  /// proof SOUND: a write-quorum member whose body faulted keeps a header and therefore does NOT nack, so a
  /// committed op can never accrue the `f+1` nacks that truncate. A genuinely-uncommitted such op (held by
  /// no one else) is still safely removed — it reaches `f+1` nacks from the non-holders and is nack-truncated
  /// on the new primary — so keeping it here never wedges. (Dropping it to `rec.faulty` would instead let its
  /// number be silently re-minted, the committed loss this closes.)
  fn resolve_exhausted_tail_read<W: Wal, B: Superblock>(
    &mut self,
    storage: &Storage<W, B, S>,
    op: u64,
  ) {
    let keep = self.inflight_tail_repairing_identity(storage, op);
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
  /// lands or the budget exhausts into a peer fetch. A valid read that cannot start its presence
  /// probe because the lane still owes an inherited walk is neither restored nor discarded: it is
  /// RETAINED as a verified obligation (`probe_deferred`) the walk's settle re-drives, outside the
  /// read budget — deferral is not a read fault.
  pub(crate) fn on_recover_sb_done<W: Wal, B: Superblock>(
    &mut self,
    storage: &mut Storage<W, B, S>,
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
        // A reconstruct is already executing for this checkpoint: the retry timer re-submits reads
        // ADDITIVELY, so a duplicate can land mid-reconstruct. Starting a second one would waste a
        // seed capture and leave the loser's verdict answering a token it no longer holds.
        if self.recover.as_ref().and_then(|r| r.reconstruct).is_some() {
          return;
        }
        // VERIFY before restore: a `CheckpointRead` matching our read id is NOT yet
        // trustworthy — a corrupted / stale / torn superblock checkpoint could return wrong bytes.
        // The CURRENT DURABLE root is the authority for which checkpoint this read can have
        // served: the backend's `submit_read_checkpoint` contract serves the snapshot the durable
        // root names at service time — never a staged-but-unrooted one — so the read must match
        // the durable root on BOTH the op and the content hash, AND parse cleanly. Phase 1
        // baselined `checkpoint_op` on the same (landed) root, so the common case verifies on the
        // first read and recovery completes locally, whatever is still in flight on the timeline.
        // The verdict is read at COMPLETION time, so an inherited checkpoint root landing between
        // the read's service and this handler can race it: the served bytes then name the
        // PRE-landing generation while this check reads the post-landing root — the mismatch
        // reads as a fault, the retry re-reads the new generation, and the restore-above-frontier
        // branch in `on_recovered_checkpoint_restored` carries the recovery scalars up to it. One
        // extra retry round, never a deterministic wedge. The state-sync path verifies the id
        // the same way (`on_sync_checkpoint`); the recover path must too, or a bad read would
        // restore the wrong SM/sessions while `commit_min == checkpoint_op` — silent
        // committed-prefix loss, exactly what the checkpoint hash exists to prevent.
        let state = storage.sb().state();
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
        // The envelope is valid, but the SM state AND the client-session table live in the
        // content-addressed BlockStore — the envelope only NAMES them by `sm_root` / `sessions_root`, and
        // its hash does NOT cover the blocks. So before reconstructing, confirm every block reachable from
        // BOTH roots is present locally (a disk fault could have dropped one) by WALKING each DAG against
        // the local store alone, as a job. Its completion ([`Self::on_recover_probe_walked`]) issues the
        // reconstruct when both drain, and treats a missing/malformed block like a corrupt read —
        // DISCARD, leaving the checkpoint outstanding so `recover_timeouts` exhausts the budget and
        // escalates to a peer block-fetch.
        //
        // Defer while the LANE still owes a walk. The `rec.reconstruct` guard above is this
        // incarnation's, but the lane's walk slot has the SESSION's lifetime: an endpoint
        // rebuilt over a live session inherits a predecessor's queued-or-executing walk (a transfer
        // ARQ's, or this same probe's), and admitting a second one is refused fail-stop at the
        // lane's admission assert. The read is NOT discarded: it already VERIFIED against the
        // durable root, so the deferral RETAINS it as an obligation (`probe_deferred`) that the
        // inherited walk's settle re-drives directly — the completion is refused by the
        // incarnation choke, but the lane settles it first, and that settle frees the slot this
        // probe needs ([`Endpoint::redrive_deferred_recover_probe`]). While the obligation is
        // held, `recover_timeouts` neither re-reads nor decrements the checkpoint budget: that
        // budget pays for READ faults, and spending it on lane contention would exhaust it into a
        // peer fetch while the local checkpoint is perfectly valid — on a solo deployment (or any
        // replica with no reachable donor) a permanent wedge, since nothing re-arms the local path
        // after the escalation. (The transfer walk's issuer, `issue_walk`, observes this same
        // lane gate; its re-drive is the ARQ cadence, which spends no budget.)
        if storage.walk_owed() {
          if let Some(rec) = self.recover.as_mut() {
            rec.probe_deferred = Some((
              state.checkpoint_id(),
              RecoveredCheckpoint {
                op: cr.op(),
                sm_root,
                sessions_root,
              },
            ));
          }
          return;
        }
        let id = self.mint_job_id();
        storage.enqueue_block_job(
          id,
          BlockJobKind::Walk {
            walks: super::block_sync::BlockWalks::new(sm_root, sessions_root),
            fetched: None,
            purpose: WalkPurpose::RecoverProbe(RecoveredCheckpoint {
              op: cr.op(),
              sm_root,
              sessions_root,
            }),
          },
        );
        if let Some(rec) = self.recover.as_mut() {
          rec.reconstruct = Some(id);
          // A retained obligation is answered by this admission: the probe it deferred is the one
          // just enqueued (a fresh read re-verified the same durable root), so an already-settled
          // walk must not re-drive it again behind this one.
          rec.probe_deferred = None;
        }
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
        // A stale durable-root/checkpoint write completion from before the crash cannot occur
        // (a fresh recover issues no writes — geometry is pinned by `format`, not recovery); ignore
        // defensively rather than panic.
      }
    }
  }

  /// The cold-start reconstruct of this replica's OWN durable checkpoint completed.
  ///
  /// On success the restored SM + session table install together, the two DAG roots become the live
  /// GC roots, the outstanding checkpoint read retires, and recovery resumes. On a missing/corrupt
  /// block in either DAG NOTHING is installed (the live SM was never touched — the job filled a
  /// detached seed): the checkpoint read stays outstanding, so `recover_timeouts` — the sole owner of
  /// the retry + ABSOLUTE budget — re-reads until a clean reconstruct lands or the budget exhausts
  /// into a peer fetch. That is the identical disposition a faulted read gets.
  pub(super) fn on_recovered_checkpoint_restored<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    checkpoint: RecoveredCheckpoint,
    result: Result<(S, std::collections::BTreeMap<u128, Session>), crate::RestoreError>,
  ) {
    if let Some(rec) = self.recover.as_mut() {
      rec.reconstruct = None;
    }
    let Ok((sm, sessions)) = result else {
      return; // discard; the timer re-reads and re-issues, and exhaustion escalates to a peer fetch.
    };
    self.sm = sm;
    self.clients = sessions;
    // The SM now holds the durable checkpoint's content (the read's op was verified against the
    // durable root before the reconstruct was issued).
    self.note_sm_restored(checkpoint.op);
    // Record the restored SM + session DAG roots as the live roots the block GC marks from.
    self.checkpoint_sm_root = Some(checkpoint.sm_root);
    self.checkpoint_sessions_root = Some(checkpoint.sessions_root);
    // The restored checkpoint can sit ABOVE the frontier the constructor pinned: a dead
    // incarnation's in-flight checkpoint root can land between this endpoint's construction and
    // the read's service (a restart in place), and the read serves — and `on_recover_sb_done`
    // verifies against — the checkpoint the CURRENT durable root names. The recovery scalars must
    // move WITH the restore: left at the pre-landing values, `commit_min` would sit below an SM
    // that already holds the prefix, and the committed band above it would be re-applied onto
    // content that already reflects it — a double-apply of every op in the gap
    // (`commit_min == checkpoint_op` at restore is exactly the guard this preserves). Everything
    // the restored snapshot subsumes is trimmed, the same filter `complete_state_sync` applies to
    // what an installed checkpoint subsumed.
    if checkpoint.op > self.checkpoint_op {
      // An owed inherited frontier at/below the restore is met by it (the landing that set the
      // marker is the same one that advanced the durable root this restore was verified
      // against) — retired inside the pointer-advance choke.
      self.advance_checkpoint_op(checkpoint.op);
      self.set_commit_min(checkpoint.op);
      self.commit_max = self.commit_max.max(checkpoint.op);
      self.op = self.op.max(checkpoint.op);
      // The snapshot owns `[1..=checkpoint.op]`: drop the subsumed header-cache entries and every
      // piece of recovery bookkeeping below the restored frontier — a pending tail read's slot is
      // now vouched by the snapshot (a late completion for a dropped read finds no entry and is
      // ignored), a canonical cross-check entry no longer binds, and a sub-frontier faulty verdict
      // must not count against ops the checkpoint subsumes.
      self.trim_log_to_checkpoint(checkpoint.op.get(), checkpoint.op.get());
      if let Some(rec) = self.recover.as_mut() {
        let floor = checkpoint.op.get();
        rec.canonical.retain(|&op, _| op > floor);
        rec.faulty.retain(|&op| op > floor);
        rec.pending.retain(|&op, _| op > floor);
        rec.reads.retain(|_, &mut op| op > floor);
      }
    }
    if let Some(rec) = self.recover.as_mut() {
      rec.checkpoint = None;
    }
    self.recover_progress(now, storage);
  }

  /// Escalate to a PEER FETCH: stop local checkpoint retries, arm a FORCED state-sync to `target` (so a
  /// peer holding a checkpoint `>= target` answers), broadcast the `RequestSync`, and mark
  /// `awaiting_peer_checkpoint` so the recovery stays open (never completes to Normal with an unrestored
  /// SM) and `handle_message` accepts the answering `SyncCheckpoint`. Idempotent: if already escalated, it
  /// just (re-)solicits.
  ///
  /// Three callers, distinguished by `target` + `require_cross_epoch`:
  /// - the permanently-unreadable own-checkpoint recovery (`target = self.checkpoint_op`,
  ///   `require_cross_epoch = false`): any peer at/above our corrupt checkpoint subsumes it.
  /// - the cross-epoch crossing fetch ([`Self::enter_cross_epoch_peer_fetch`]) (`target` = the advertised
  ///   cluster checkpoint, `require_cross_epoch = true`): the fetch MUST cross into E+1 — `apply_sync`
  ///   rejects any non-crossing reply (see [`SyncState::require_cross_epoch`]).
  /// - the orphaned-re-persist reconciliation ([`Self::maybe_enter_orphan_repersist_fetch`])
  ///   (`target` = the orphaned root's landed frontier, at/above our own checkpoint,
  ///   `require_cross_epoch = false`): the durable root already names the synced point, so only a
  ///   reply that subsumes it can install — which `apply_sync`'s timeline admission enforces
  ///   independently off the effective root.
  pub(crate) fn escalate_checkpoint_to_peer_fetch(
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
  pub(crate) fn enter_cross_epoch_peer_fetch<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    checkpoint: OpNumber,
  ) {
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
    self.reset_for_view_transition(now, storage);
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
    // Only a Seal or SwapEpoch action can still be armed here (the `pending_durable_view` guard
    // above deferred the three view-changing actions): abandon it — its completion must not fire
    // mid-recovery — and abandon its root with the correlation, so a parked one leaves its cell.
    // A SUBMITTED one still lands, and an epoch-advancing landing still installs the successor
    // through the landing absorb, exactly as any superseded swap's does.
    if let Some((abandoned, _)) = self.pending_sb.take() {
      storage.abandon_root(RootRole::DurableView, abandoned);
    }
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
    // server (a state-sync pull is served to any authenticated CURRENT member regardless of how far its
    // config has aged — the pull carries no authority and its reply is content-verified on install; its
    // E+1 answer is admitted here via `sync.is_some()`). `require_cross_epoch = true` pins the crossing
    // requirement in `apply_sync`.
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
      // repair. It is in `rec.faulty` here (which `is_tracked_for_repair` reads) and is DROPPED from
      // `self.log` below, leaving an absent committed-band slot. It is NOT pre-registered as a `self.repair`
      // hole on the `→ Normal` transition; instead `advance_commit`, applying through the committed band,
      // re-requests the absent slot on demand (`request_repair_run`, which registers `self.repair`) and
      // peer-repairs the canonical body — a permanently-faulty head drives `RecoveringHead` instead.
      // Asserted per dropped op.
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

  /// Enforce that no permanently-faulty committed-band slot survived into the terminal recovery status
  /// as a POPULATED-with-bytes `self.log` entry. A faulty op left as `Some({body: Present(EMPTY)})` is
  /// NOT a hole — `advance_commit`/`adopt_log` would apply it empty cluster-wide (the original
  /// empty-body CRITICAL). After [`Self::finalize_recovery`]'s drop EVERY op in `rec.faulty` MUST be
  /// either ABSENT from `self.log` OR a `Body::Repairing` hole (a kept body-faulty op whose existence is
  /// preserved and whose body is peer-repaired on demand — also not a bytes-bearing entry, so it cannot
  /// apply empty). This fires only if a future edit leaves a faulty op as a `Present` entry, or routes a
  /// completion through here with such a slot still populated. Enforced in every profile: the surviving
  /// entry would be APPLIED, corrupting committed state cluster-wide, so a fail-stop at the recovery
  /// exit is the safe outcome — and the walk is bounded by the recovered faulty set, once per recovery.
  /// Runs while `rec` is still live (the terminal dispatch clears `recover` only AFTER), so it can
  /// witness the final `rec.faulty` set.
  pub(crate) fn assert_no_faulty_committed_survives(&self) {
    if let Some(rec) = self.recover.as_ref() {
      for &op in &rec.faulty {
        assert!(
          !matches!(self.log.get(&op), Some(e) if e.body.is_present()),
          "faulty committed slot {op} survived into the terminal recovery status as a populated \
           Present log entry (would be applied empty) — the drop choke was bypassed"
        );
      }
    }
  }

  /// Settle the VERIFIED recovery head — TigerBeetle's `op = journal.op_maximum()` (the highest slot the
  /// WAL actually WROTE), replacing the PROVISIONAL read-window `self.op`. A slot counts as written if it
  /// is present in `self.log` (a verified / `Repairing` body) or in `rec.faulty` (a written-but-corrupt
  /// slot). Every op that read ABSENT is a never-written phantom the reported / bit-rotted `op_head`
  /// over-counts: cap `self.op` at the real head (floored at the durable checkpoint) and DISCARD the
  /// phantom absents above it — no committed op lives above the highest written slot, so this is a clean
  /// cap, never `RecoveringHead` for a mere over-count. An absent BELOW the real head is a genuine
  /// interior hole (a written region straddling it), so reclassify it faulty and let `advance_commit`
  /// peer-repair it on demand. Returns the settled head, or `None` when recovery is already retired.
  ///
  /// This is the SINGLE settle choke: EVERY path that leaves the recovery read phase runs it —
  /// `recover_progress` (the completion/timeout drains, which then also decide `RecoveringHead`) and the
  /// peer-checkpoint escape (`on_recover_sync_checkpoint`, which abandons local recovery for
  /// `apply_sync`) — so no exit can carry a provisional, unverified head into `Normal`/`ViewChange`
  /// (an unheld head would be blind-re-acked on a later `Prepare` and advertised in a `DoViewChange`).
  fn settle_recover_verified_head(&mut self) -> Option<u64> {
    let cp = self.checkpoint_op.get();
    let present_head = self.log.keys().next_back().copied().unwrap_or(0);
    let rec = self.recover.as_mut()?;
    let faulty_head = rec.faulty.iter().next_back().copied().unwrap_or(0);
    let real_head = present_head.max(faulty_head).max(cp);
    let interior: std::vec::Vec<u64> = rec
      .absent
      .iter()
      .copied()
      .filter(|&op| op <= real_head)
      .collect();
    for op in interior {
      rec.faulty.insert(op);
    }
    rec.absent.clear();
    if real_head < self.op.get() {
      self.op = OpNumber::with(real_head);
      // No `self.log` entry lives above the highest present op by construction; retain defensively so a
      // stray placeholder above the capped head can never be applied / carried.
      self.log.retain(|&op, _| op <= real_head);
    }
    Some(real_head)
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
  fn recover_progress<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
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
    // Reads settled → settle the VERIFIED head through the shared choke.
    let Some(real_head) = self.settle_recover_verified_head() else {
      return;
    };
    // Deferred non-committed-faulty-HEAD decision. `resolve_exhausted_tail_read` keeps EVERY placement-valid
    // durable header as `Repairing` — it cannot decide head-vs-interior itself, since while reads are in
    // flight `self.op` is only the PROVISIONAL read-window top (an op at the momentary frontier with written
    // ops above it is INTERIOR, not the head). Now that the VERIFIED head is known: a head kept header-only
    // as `Repairing` (its body permanently unreadable) that sits ABOVE the durable `commit_max` is an
    // un-truthed head this replica must NOT hold — route it to `rec.faulty` (the head-fault check below
    // drives `RecoveringHead`, soliciting the canonical head from a peer) AND make it NOT HELD: remove its
    // `Repairing` entry from `self.log`. The removal is load-bearing: `drop_faulty_committed_slots`
    // deliberately KEEPS `Repairing` entries (they are committed body-repairs), so without this the head
    // would survive as an ordinary log entry and a later reformation (which clears `recover` before
    // ViewChange) would carry it into a DoViewChange/StartView — advertising an uncommitted head this
    // replica cannot vouch. A `Repairing` head at/below `commit_max` is a committed body-repair (kept); a
    // NON-head `Repairing` op above `commit_max` also stays kept — the storage-fault preservation (it does
    // not nack, so a committed op is never truncated). This promotion is recover_progress-only: the
    // peer-checkpoint escape (`on_recover_sync_checkpoint`) runs the settle choke but keeps a `Repairing`
    // head held — it vouches the durable header (existence, not body) and lets the online repair/nack
    // machinery resolve it, the established semantics of that path.
    let promote_faulty_head = real_head > self.commit_max.get()
      && matches!(
        self.log.get(&real_head).map(|e| &e.body),
        Some(Body::Repairing(_))
      );
    if promote_faulty_head {
      self.log.remove(&real_head);
      if let Some(rec) = self.recover.as_mut() {
        rec.faulty.insert(real_head);
      }
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
    // AND re-solicits the peer checkpoint. Crucially, `awaiting_peer_checkpoint` blocks completion:
    // we must NEVER reach Normal with the SM unrestored (`commit_min == checkpoint_op` would then be
    // a silent committed-prefix loss) — recovery completes only once a verified `SyncCheckpoint`
    // restores the SM (via `on_recover_sync_checkpoint` → `apply_sync`), which drops the faulty slots
    // again (belt-and-suspenders) before applying.
    if rec.checkpoint.is_some() || rec.awaiting_peer_checkpoint {
      self.arm_timers(now);
      return;
    }
    if rec.faulty.is_empty() {
      // Tail consistent: every body is present + checksum-verified → settle the terminal status. A
      // recovered backup resumes Normal (it waits for the primary's Prepare/Commit to re-announce
      // commit); a replica that was the established PRIMARY (or crashed mid-view-change) does NOT
      // resume as that primary — `complete_recovery` abdicates / re-drives the view change instead.
      self.complete_recovery(now, storage);
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
    self.complete_recovery(now, storage);
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
  pub(crate) fn complete_recovery<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
    // Read the FORMATTED witness before dropping the recover state — it gates the genesis-primary
    // exemption below. A re-latched recovery (`on_recover_sync_checkpoint` builds a default state)
    // carries `formatted = false`, which is correct: a re-syncing node is never at genesis.
    let formatted = self.recover.as_ref().is_some_and(|r| r.formatted);
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
        self.enter_view_change_from_recovery(now, storage, self.view);
      } else {
        self.enter_catch_up_posture(now, storage);
      }
    } else if self.membership.replica_count() > 1
      && self
        .membership
        .is_primary_slot(self.local_slot(), self.view)
      // A FORMATTED genesis store is exempt from abdication: with a durable format witness (a pinned
      // root a wipe cannot forge), no view ever formed beyond 0, no op ever appended, and no commit
      // ever witnessed, the abdication rationale is vacuous — no pipeline was lost, no session a
      // retried client could double-execute against — so the designated view-0 primary resumes Normal
      // and serves, exactly as a freshly `format`-ed cluster should. Withholding the format witness is
      // what closes the wipe-amnesia hole: an UNFORMATTED store with these same empty scalars (a wiped
      // member whose disk was replaced) is a member that may have committed ops it forgot, so it must
      // NOT resume as primary — it abdicates, and the view change recovers those ops from a surviving
      // peer whose log still holds them.
      && !(formatted
        && self.view.get() == 0
        && self.op.get() == 0
        && self.commit_max.get() == 0)
    {
      // Was Normal as the PRIMARY (or an unformatted empty store that must not resume as one) →
      // abdicate: a restarted primary has no in-memory pipeline and a checkpoint-only session table,
      // so it forces a clean view change to view + 1 rather than resuming as the established primary.
      self.enter_view_change_from_recovery(now, storage, self.view.next());
    } else {
      // Backup, a non-voting learner, or a SOLO replica (its own primary, no quorum to view-change)
      // → resume Normal.
      self.set_status(Status::Normal);
      if self.membership.replica_count() == 1 && !self.is_learner() {
        // Solo VOTER: rebuild the pipeline for the recovered tail so `try_commit` re-commits ops it holds
        // (an empty `inflight` would stall them). A learner in a single-voter cluster is a follower, not
        // the solo primary, so it takes the backup path.
        self.resume_solo_voter_pipeline(now, storage);
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
      self.maybe_pay_checkpoint_debt(now, storage);
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
  pub(crate) fn resume_solo_voter_pipeline<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
    self.inflight.clear();
    let own = 1u64 << self.local_slot().get();
    for op in (self.commit_min.get() + 1)..=self.op.get() {
      let prepare_checksum = self
        .log
        .get(&op)
        .map(|e| crate::storage::prepare_identity(e.client, e.request, e.body.body_checksum()))
        .unwrap_or(0);
      // The same voter-admission refusal as `record_own_vote`, applied at this second own-bit
      // seeding site: a reconfiguration op seating a brand-new voter against the current
      // configuration earns no own bit (the entry is seeded voteless), so the solo voter's
      // quorum-of-1 can never re-commit it and the commit-time fence stays unreachable. On a
      // compliant store this shape cannot occur (the delta vocabulary cannot express a direct voter
      // add, so a solo voter cannot mint one; it receives no Prepares, and its trivial view changes
      // adopt only its own log) — the screen is completeness: every site that sets an own bit
      // enforces one refusal.
      let oks = if self.op_is_direct_voter_add(op) {
        0
      } else {
        own
      };
      self.inflight.insert(
        op,
        Inflight {
          oks,
          committed: false,
          prepare_checksum,
        },
      );
    }
    self.arm_timers(now);
    // Nothing follows: a teardown in the tail has nothing left to short-circuit; discard the flow.
    let _ = self.try_commit(now, storage);
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
    storage: &mut Storage<W, B, S>,
  ) {
    if self.timers.recover_retry.is_none_or(|d| d > now) {
      return;
    }
    // FIRST, self-heal an owed LOCAL install whose flush barrier faulted during the recovery peer-fetch
    // (`on_recover_sync_checkpoint` → `apply_sync`): the complete verified DAG is already local, so re-flush
    // + re-stage LOCALLY here (the Normal-only `sync_timeouts` does not run while Recovering). On success the
    // re-persist root drives `install_sync` + the flip to Normal; a still-failing flush leaves it owed and
    // the recover cadence re-attempts. No-op when none is owed / a write is in flight.
    self.retry_install_flush(now, storage);
    // A durability barrier (or the re-persist it stages) is now outstanding: the node waits on that
    // completion, not on a read retry. Keep the cadence armed so a FAULTED barrier is re-attempted —
    // the recovery bookkeeping is retired by the staging itself
    // ([`Endpoint::on_checkpoint_blocks_flushed`]), which is the only point the superblock write is
    // actually submitted, so a barrier that faults leaves the read phase intact for this retry.
    if self.pending_checkpoint.is_some() {
      self.timers.recover_retry = Some(now + RECOVER_READ_RETRANSMIT);
      return;
    }
    // Snapshot the PENDING ops (the in-flight tail reads) so we can re-borrow `recover` per op while
    // iterating. Faulty ops are NOT re-read (already resolved to a peer-repaired hole).
    let (ops, want_checkpoint, checkpoint_retries, awaiting_peer, probe_deferred) =
      match self.recover.as_ref() {
        Some(rec) => (
          rec.pending.keys().copied().collect::<std::vec::Vec<u64>>(),
          rec.checkpoint,
          rec.checkpoint_retries,
          rec.awaiting_peer_checkpoint,
          rec.probe_deferred.is_some(),
        ),
        None => (std::vec::Vec::new(), None, 0, false, false),
      };
    // Peer-fetch: if our own checkpoint read exhausted and we are awaiting a PEER `SyncCheckpoint`,
    // re-broadcast the `RequestSync` on this cadence (the Normal-only `sync_timeouts` does not run
    // while Recovering). A peer holding a checkpoint `>= ours` answers; until then we stay here.
    // With a block-fetch in progress (the SM checkpoint DAG is being pulled), this cadence is also
    // its ARQ: re-send the one outstanding `RequestBlock` for the frontier's next-missing block first,
    // exactly as `sync_timeouts` does for a Normal receiver.
    if awaiting_peer && self.sync.is_some() {
      self.send_request_block(now, storage);
      self.send_request_sync(now);
    }
    for op in ops {
      // Read the op's ABSOLUTE budget under a brief immutable borrow, released before the method calls
      // below (`resolve_exhausted_tail_read`/`mint_read_id` re-borrow `self`/`self.recover`).
      let budget = self
        .recover
        .as_ref()
        .and_then(|rec| rec.pending.get(&op).copied());
      match budget {
        // Exhausted: resolve from the durable header (keep header-only as Repairing, or route to
        // peer-repair). This both removes `op` from `rec.pending` and drops all its in-flight ids.
        Some(0) => self.resolve_exhausted_tail_read(storage, op),
        Some(budget) => {
          // Re-submit an ADDITIVE read — a fresh id that does NOT retire the op's existing in-flight
          // ids, so a slow completion under an earlier id still resolves the op — and decrement the
          // absolute budget by one.
          let new_id = self.mint_read_id();
          if let Some(rec) = self.recover.as_mut() {
            rec.pending.insert(op, budget - 1);
            rec.reads.insert(new_id.seq(), op);
          }
          storage.submit_wal_read(new_id, OpNumber::with(op));
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
    //
    // NOT while a verified read is retained as a deferred probe obligation (`probe_deferred`): the
    // read phase already SUCCEEDED — the wait is on the inherited walk's completion, which the
    // lane owes and whose settle re-drives the probe directly. Re-reading would only duplicate a
    // verified result, and decrementing here would spend the READ-fault budget on lane contention:
    // exhausted, it escalates to a peer fetch that nothing ever re-arms the local path from — on a
    // solo replica (or any replica with no reachable donor) a permanent wedge over a perfectly
    // valid local checkpoint, strictly worse than the wait. This mirrors the `pending_checkpoint`
    // early-return above: an owed completion is waited on, never retried against.
    if want_checkpoint.is_some() && !probe_deferred {
      if checkpoint_retries == 0 {
        // Permanently-unreadable OWN checkpoint: any peer at/above it subsumes ours — NOT a cross-epoch
        // crossing (no epoch target to pin), so target our own `checkpoint_op` with the requirement off.
        self.escalate_checkpoint_to_peer_fetch(now, self.checkpoint_op, false);
      } else {
        let new_id = self.mint_read_id();
        if let Some(rec) = self.recover.as_mut() {
          rec.checkpoint = Some(new_id.seq());
          rec.checkpoint_retries = checkpoint_retries - 1;
        }
        storage.submit_checkpoint_read(new_id);
      }
    }
    // Re-arm so we keep retrying until the loop completes.
    self.timers.recover_retry = Some(now + RECOVER_READ_RETRANSMIT);
    // A budget-exhaustion resolution above (`resolve_exhausted_tail_read`) removes the op from
    // `rec.pending` WITHOUT producing a WAL completion, so — unlike a clean read — it does NOT route
    // through `on_recover_wal_done` → `recover_progress`. Without this call, exhausting the LAST pending
    // op's budget here would leave recovery stuck `Recovering` forever (nothing else re-evaluates the
    // transition). Idempotent: it re-arms and returns while any read is still pending, and finalizes only
    // once `rec.pending` empties.
    self.recover_progress(now, storage);
  }

  /// Retire the local recovery bookkeeping once a sync install is STAGED (`pending_checkpoint` set),
  /// FIRST carrying the faulty verdicts across the install — the shared chokepoint of BOTH staging
  /// lanes: the fresh `SyncCheckpoint` escape (`on_recover_sync_checkpoint`) and the local flush-retry
  /// (`recover_timeouts` → `retry_install_flush`, reached when the escape's first flush FAULTED so no
  /// `pending_checkpoint` existed there and `recover` survived into the retry cadence). The read phase
  /// settled its verdicts before either staging, but the `awaiting_peer_checkpoint` gate in
  /// `recover_progress` sits BEFORE its faulty-head → `RecoveringHead` decision — so a
  /// permanently-faulty (occupied-but-unidentifiable) HEAD reaches staging still marked only in
  /// `rec.faulty`, which this teardown discards. Carrying the WHOLE set (`sync_carried_faulty`) lets
  /// the install completion route to `RecoveringHead` instead of `Normal` when the installed
  /// checkpoint does not subsume the head (completing `Normal` would hold an op with no identity
  /// anywhere: blind re-acks; a DVC advertising an unheld head), with the interior verdicts riding
  /// along because the reform-escalation gate (`committed_band_intact`) must keep refusing same-epoch
  /// reformation while a COMMITTED-band faulty slot remains. Replace-only-when-non-empty: a re-fetch
  /// reply after an install error re-runs a staging with a fresh READ-FREE `RecoverState` (empty
  /// `faulty`) and must not erase the original verdicts — nothing was re-read, so they stand until
  /// consumed by `complete_state_sync`.
  pub(super) fn retire_recover_for_staged_sync(&mut self) {
    if let Some(rec) = self.recover.as_ref()
      && !rec.faulty.is_empty()
    {
      self.sync_carried_faulty = rec.faulty.clone();
    }
    self.recover = None;
    self.timers.recover_retry = None;
    self.timers.sync_solicit = None;
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
  pub(crate) fn recover_head_timeouts<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
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
      self.retire_recover_and_escalate(now, storage);
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
  pub(crate) fn retire_recover_and_escalate<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
    self.recover = None;
    self.enter_view_change_from_recovery(now, storage, self.view.next());
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
    storage: &mut Storage<W, B, S>,
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
    // rather than re-staging. A reply ABOVE M supersedes the obligation forward (it falls through to
    // `begin_recover_block_sync`, which keeps the obligation owed until `install_sync` installs the newer
    // point). The `< M` reply was already dropped. GATE on `pending_install.is_none()` for the same reason as
    // the Normal mirror: a retained newer install (a superseding sync whose flush faulted) subsumes M and is
    // retried locally, so a same-M reconstruct here would orphan it.
    if self.sm_reconstruct_owed()
      && self.pending_install.is_none()
      && m.checkpoint_op() == self.checkpoint_op
    {
      self.refetch_sm_reconstruct(now, storage, from, &m);
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
    // (saving this verified `SyncCheckpoint` to replay once both drain) and walk it, staying
    // Recovering. When the frontiers drain, the walk's completion runs
    // [`Self::complete_recover_peer_fetch`] — the tail-resolution + `apply_sync` this call used to fall
    // through to. A malformed DAG drops the fetch and keeps the peer-fetch armed (re-solicits). A stale
    // same-config reply whose blocks are already local drains immediately, but `apply_sync` keeps
    // `sync` Some for a crossing and `recover_timeouts` re-arms the `RequestSync` solicit — so the
    // crossing is never permanently wedged by a stale drain.
    self.begin_recover_block_sync(now, storage, from, &m, sm_root, sessions_root);
  }

  /// The recovery peer-fetch's POST-FETCH tail: both DAGs of the verified `SyncCheckpoint` `m` are now
  /// present locally, so resolve the still-in-flight tail reads, settle the verified head, drop the
  /// faulty committed-band placeholders, and STAGE the durable re-persist through the shared
  /// state-sync core.
  ///
  /// Reached from the frontier walk's completion (the drain), which is why it is separate from the
  /// verification head above: re-entering that head would re-walk an already-drained transfer forever.
  /// `donor` is the AUTHENTICATED sender slot the transfer was pinned to — a current member
  /// (`Peer::Replica`) or a quarantined attested member (`Peer::Member`) — never the checkpoint's
  /// self-claimed, possibly-shifted `replica()`; a client could not have answered (the arming path
  /// dropped it).
  pub(super) fn complete_recover_peer_fetch<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    donor: Peer,
    m: crate::SyncCheckpoint,
  ) {
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
    // Whether the local tail-read pass is UNSETTLED at this reply — reads still in flight (the head is the
    // PROVISIONAL read-window top) or absent verdicts not yet consumed by a settle. Captured BEFORE the
    // resolution loop below empties `pending`; gates the settle choke after it. The read-FREE lanes that
    // also route through here (the cross-epoch crossing fetch and the install-error re-pull arm a fresh
    // `RecoverState` with no reads) must NOT be settled against: there `self.op` is the node's LIVE head,
    // whose committed on-demand repair holes legitimately have no `self.log` entry, so a settle would
    // wrongly cap `op` below the applied frontier.
    let tail_unsettled = self
      .recover
      .as_ref()
      .is_some_and(|rec| !rec.pending.is_empty() || !rec.absent.is_empty());
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
      let keep = self.inflight_tail_repairing_identity(storage, op);
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
    // Settle the VERIFIED head through the shared choke BEFORE abandoning local recovery, so this exit
    // upholds the recovery exit invariant LOCALLY: no path leaves the read phase with `self.op` still the
    // PROVISIONAL read-window top (which, under an over-counted / bit-rotted `op_head`, includes a phantom
    // suffix this replica never wrote — an unheld head a later `Prepare` would blind-re-ack and a DVC
    // would falsely advertise). On today's schedules this is a defensive no-op — every path that arms
    // `awaiting_peer_checkpoint` (the ingress gate for this reply) is already settled-or-read-free: the
    // own-checkpoint exhaustion shares its retry budget cadence with the tail reads, so `recover_timeouts`
    // resolves the last pending op and runs `recover_progress`'s settle in the SAME call that escalates;
    // the cross-epoch fetch and the install-error re-pull arm a fresh READ-FREE `RecoverState`. But that
    // is a global argument spanning the budget cadence, `recover_timeouts`'s internal order, and the
    // ingress gate — this call makes the invariant hold by construction instead, so a future escalation
    // lane or budget change cannot silently reopen it. Gated on `tail_unsettled`: only a reply landing
    // mid-read-pass needs settling (the just-resolved in-flight ops are then already in `self.log` as
    // `Repairing` or in `rec.faulty`, so the settle sees the full written tail); the read-free lanes are
    // excluded (see `tail_unsettled`). Unlike `recover_progress`, a `Repairing` real head is NOT
    // re-classified here (no `RecoveringHead` on this path): the durable header is vouched header-only
    // and the online repair/nack machinery resolves it.
    if tail_unsettled {
      self.settle_recover_verified_head();
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
    // `apply_sync` records the pinned donor on the staged install so a POST-ROOT reconstruct fault can
    // re-pull THIS checkpoint's block from the same donor `Peer`.
    self.apply_sync(now, storage, donor, &m);
    // `apply_sync` accepts or rejects the reply; on acceptance it issues the durability barrier whose
    // completion STAGES the re-persist. The recovery READ phase is retired by that staging
    // ([`Endpoint::on_checkpoint_blocks_flushed`] → `retire_recover_for_staged_sync`), never here: a
    // barrier that faults stages nothing, and the peer-fetch bookkeeping (`recover` +
    // `awaiting_peer_checkpoint` + the solicit timer) must survive for the local retry — tearing it
    // down on a mere acceptance would silently end the fetch at the old epoch.
  }

  /// Arm (or re-pin) the recovery peer-fetch's checkpoint-DAG transfer and issue its first frontier
  /// walk, staying Recovering.
  ///
  /// The verified `SyncCheckpoint` `m` is saved into the transfer so the walk's completion replays it
  /// into [`Self::complete_recover_peer_fetch`] once both DAGs drain. Mirrors
  /// [`Self::begin_block_sync`], except the install + flip-to-Normal defer to the durable re-persist
  /// root rather than running here.
  fn begin_recover_block_sync<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    from: Peer,
    m: &crate::SyncCheckpoint,
    sm_root: BlockAddress,
    sessions_root: BlockAddress,
  ) {
    // A reply reaching here while an SM-reconstruct obligation is owed is, by the ingress gates, a
    // STRICTLY-NEWER checkpoint (`> self.checkpoint_op == M`): it SUPERSEDES the obligation forward (its own
    // install reconstructs the SM to the newer point). The obligation is KEPT owed through this peer-fetch
    // AND through the staged-but-pre-root install, mirroring `begin_block_sync`: it is dropped only when
    // `install_sync` actually installs the replacement (root durable). So a STALLED fetch, a REJECTED reply,
    // or a view transition cancelling the pre-root install leaves the obligation to keep reconstructing M
    // rather than wiping it. The drain routes a SAME-M fetch to the SM-content retry and a NEWER M' through
    // `complete_recover_peer_fetch` → `apply_sync`.
    // A RETAINED-but-not-staged install (a prior verified install whose flush faulted, still owed as
    // `pending_install` with no in-flight checkpoint — the ingress gate rules out a staged one) is LEFT INTACT
    // here, mirroring `begin_block_sync`: it is the local flush-retry source, a LIVE GC root, and a verified
    // crossing's `cross_epoch_intent` shield. A fresh peer-fetch may STALL or have its reply REJECTED by
    // `apply_sync`, so clearing on entry would leave nothing to re-flush + drop the owed DAG's GC mark before
    // any replacement exists. The owed install is dropped ONLY when `apply_sync` stages a fresh
    // `PendingInstall` (which atomically REPLACES it) or a teardown cancels it.
    // Pin the donor to the AUTHENTICATED sender slot (the slot the recovery sender-binding check
    // established this laggard routes to), not the donor's self-claimed (possibly shifted) `replica()` — a
    // cross-epoch donor's successor-epoch slot is un-routeable in this OLD-epoch laggard's membership. The
    // donor `Peer` is a current member (`Peer::Replica`) or a quarantined attested member
    // (`Peer::Member`); a client cannot have answered — abort the fetch (keeping the peer-fetch armed
    // for the re-solicit) rather than fabricate a target.
    if from.is_client() {
      self.block_fetch = None;
      return;
    }
    // ONE PIN AT A TIME (mirrors `begin_block_sync`): a reply is not admitted while the live transfer
    // is mid-walk. It is RETAINED, and re-delivered the moment that walk lands.
    if self.transfer_walk_in_flight() {
      self.defer_pin_until_walk_completes(from, m.clone());
      return;
    }
    // PROVENANCE-AWARE replacement (mirrors `begin_block_sync`): a non-crossing reply must never DOWNGRADE
    // a live crossing fetch. The recovery `recover_retry` re-solicit fans to old-config `Backups` AND the
    // quarantined donor, so once the quarantined donor has presented a crossing here, a later same-config
    // reply from an old-config donor would otherwise evict that crossing fetch and its block would land
    // off-frontier — the same endless disarm/rearm strand as the Normal path. Keep the crossing fetch (the
    // recover ARQ re-drives its pull); a crossing reply still supersedes normally below.
    if self
      .block_fetch
      .as_ref()
      .is_some_and(|bf| bf.crossing_answered)
      && !self.checkpoint_presents_crossing(m)
    {
      return;
    }
    // REPLACE the whole block-fetch (superseding any prior fetch — the recovery re-pin strand cannot
    // leave a stale frontier). The transfer is complete only when BOTH frontiers drain.
    self.block_fetch = Some(BlockFetch {
      checkpoint: m.clone(),
      sm_root,
      sessions_root,
      donor: from,
      walks: WalkState::Idle(super::block_sync::BlockWalks::new(sm_root, sessions_root)),
      // A recovery peer-fetch can itself be cross-epoch — record the crossing presentation from the
      // checkpoint metadata (the non-Normal `awaiting_peer_checkpoint` shield already governs the crossing
      // predicates here, so this only keeps the bit consistent across all arming sites).
      crossing_answered: self.checkpoint_presents_crossing(m),
      // Carry the re-solicit latch forward across a same-root re-pin: a DUPLICATE same-root recovery
      // checkpoint re-walks the same front and inherits the latch, so it cannot re-arm one re-solicit per
      // duplicate; a genuine NEW root resets to `None` so its first absent legitimately re-solicits.
      resolicited_front: self.carry_resolicit_latch(sm_root, sessions_root),
    });
    self.issue_walk(storage, WalkPurpose::Arm, None);
    // While Recovering the `recover_retry` cadence (not `sync_solicit`) re-drives the pull, so re-arm
    // that timer to keep the ARQ alive.
    self.arm_timers(now);
  }

  /// Re-drive a deferred cold-start presence probe the moment the lane's walk slot frees.
  ///
  /// Runs on every walk settle (`on_block_done`, BEFORE the incarnation choke): the walk that held
  /// the slot is typically an inherited one — a dead incarnation's, whose completion the choke
  /// refuses — so the settle is the ONLY event that can resume the deferred local recovery, and it
  /// must fire on refused completions too. A no-op unless a verified obligation is actually held
  /// (`probe_deferred`), the slot is genuinely free, and no probe/reconstruct of this incarnation
  /// is already executing.
  ///
  /// The obligation carries the durable `checkpoint_id` it was verified against, and the re-drive
  /// re-checks the durable root against it: an inherited checkpoint root landing between the
  /// deferral and this settle moves the root to a NEWER generation, and walking the stale roots
  /// would probe (and then restore) a checkpoint the durable root no longer names. A stale
  /// obligation is dropped instead — the checkpoint read is still outstanding, so
  /// `recover_timeouts` re-reads the new generation on its cadence with the budget intact (one
  /// extra retransmit interval, never a wedge; the same one-extra-round shape as the read-time
  /// race in `on_recover_sb_done`).
  pub(super) fn redrive_deferred_recover_probe<W: Wal, B: Superblock>(
    &mut self,
    storage: &mut Storage<W, B, S>,
  ) {
    if storage.walk_owed() {
      return; // another walk still holds the slot — its settle re-runs this
    }
    let Some(rec) = self.recover.as_mut() else {
      return;
    };
    if rec.reconstruct.is_some() {
      return; // this incarnation's probe/reconstruct is already executing
    }
    let Some((verified_id, checkpoint)) = rec.probe_deferred.take() else {
      return;
    };
    let state = storage.sb().state();
    if state.checkpoint_op() != checkpoint.op || state.checkpoint_id() != verified_id {
      return; // stale — an inherited root landed past it; the retry cadence re-reads
    }
    let id = self.mint_job_id();
    storage.enqueue_block_job(
      id,
      BlockJobKind::Walk {
        walks: super::block_sync::BlockWalks::new(checkpoint.sm_root, checkpoint.sessions_root),
        fetched: None,
        purpose: WalkPurpose::RecoverProbe(checkpoint),
      },
    );
    if let Some(rec) = self.recover.as_mut() {
      rec.reconstruct = Some(id);
    }
  }

  /// The cold-start LOCAL presence probe completed: every block reachable from BOTH roots of this
  /// replica's own durable checkpoint was walked against the local store alone.
  ///
  /// Complete ⇒ issue the reconstruct. A MISSING block, or a reachable-block-bound breach on a
  /// malformed/oversized DAG, is treated exactly like a corrupt read: DISCARD and leave the checkpoint
  /// read outstanding, so `recover_timeouts` — the sole owner of the retry + ABSOLUTE budget —
  /// exhausts it into a peer block-fetch.
  pub(super) fn on_recover_probe_walked<W: Wal, B: Superblock>(
    &mut self,
    storage: &mut Storage<W, B, S>,
    job: crate::JobId,
    checkpoint: RecoveredCheckpoint,
    next: Result<Option<BlockAddress>, ()>,
  ) {
    if self.recover.as_ref().and_then(|r| r.reconstruct) != Some(job) {
      self.block_jobs_superseded = self.block_jobs_superseded.saturating_add(1);
      return;
    }
    if let Some(rec) = self.recover.as_mut() {
      rec.reconstruct = None;
    }
    match next {
      // Complete — every reachable block of both DAGs is present locally.
      Ok(None) => {}
      // A reachable-block-bound breach (a malformed / oversized checkpoint DAG): count the abort ONCE
      // for observability — `recover_timeouts` would otherwise re-read it silently — then
      // discard/retry/escalate to a peer block-fetch, exactly like a missing block.
      Err(()) => {
        self.dag_walks_capped += 1;
        return;
      }
      // A missing block: NOT a bound breach — discard, retry, escalate.
      Ok(Some(_)) => return,
    }
    // Defer while the LANE still owes a reconstruct — the same lane-slot gate the synced-checkpoint
    // reconstruct observes, and for the same reason: an inherited reconstruct still occupies the
    // lane after the endpoint that issued it is gone, and this incarnation's recovery bookkeeping
    // cannot see it. The disposition matches the missing-block arm just above — leave the checkpoint
    // read outstanding so `recover_timeouts` re-drives on its own cadence with the budget intact.
    // Unreachable in the current tree for the reason stated at the synced-checkpoint site (a
    // reconstruct only ever follows a frontier walk's delivery, and the walk slot serializes those),
    // so it is the structural backstop for a future issue site.
    if storage.restore_owed() {
      return;
    }
    // Reconstruct OFF the pump, through the VERIFY-ON-READ path: the walk above drained, but a block
    // can bit-rot or be misdirected in the window before the reconstruct runs, so every block read is
    // checked against its content address. The SM is rebuilt into a DETACHED seed the completion swaps
    // in only on success, so a fault leaves the live SM untouched and is handled exactly like a missing
    // walk block above. The token on the recovery bookkeeping is what makes a superseded reconstruct's
    // verdict inert.
    let seed = self.sm.restore_seed();
    let job = self.issue_block_job(
      storage,
      BlockJobKind::Restore {
        sm_root: checkpoint.sm_root,
        sessions_root: checkpoint.sessions_root,
        seed,
        purpose: RestorePurpose::RecoveredCheckpoint(checkpoint),
      },
    );
    if let Some(rec) = self.recover.as_mut() {
      rec.reconstruct = Some(job);
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
  pub(crate) fn catch_up_to_view<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    view: View,
  ) {
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
    self.enter_catch_up_posture(now, storage);
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
  fn enter_catch_up_posture<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
    self.set_status(Status::ViewChange);
    self.svc_target = self.view;
    // Tear down ALL old-generation in-flight state in one place: SVC bits, in-flight
    // appends, peer-checkpoint reports, in-flight checkpoint, in-flight sync + its deferred install
    // (cancelled together — durable-before-install leaves the old state intact), and the
    // forfeit sub-state. See [`Self::reset_for_view_transition`] for the per-field rationale.
    self.reset_for_view_transition(now, storage);
    // ViewChange ENTRY (the catch-up): install a fresh collection with `catching_up = true` — this entry
    // sends GetView, not SVC/DVC. (`is_some() == is_view_change()` coupling.)
    self.view_change = Some(ViewChangeCollection::entering(true));
    // The primary pipeline + backup reorder buffer are dropped on this catch-up (kept OUT of the shared
    // reset because `adopt_canonical_head` preserves a live primary pipeline).
    self.inflight.clear();
    self.buffer.clear();
    // GetView is a catch-up probe, not a vote; no superblock write needed. ABANDON any prior-view
    // pending_sb: a stale completion from the prior view must not fire, and the abandoned root —
    // if still parked — leaves its cell with its correlation, so an alternating submit/catch-up
    // schedule wastes no landing on a root nothing awaits. (This is the distinguishing
    // `pending_sb` action — the two durable-view-writing entries overwrite it instead.)
    if let Some((abandoned, _)) = self.pending_sb.take() {
      storage.abandon_root(RootRole::DurableView, abandoned);
    }
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
  pub(crate) fn send_recovery(&mut self, now: Instant) {
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
    storage: &mut Storage<W, B, S>,
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
    // An adoption that routed into the recovery peer-fetch adopted the head as data but ended the
    // generation: leave the WAL tail to the reconciling install (it prunes and truncates at the
    // synced point), mirroring `on_start_view`.
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
}

#[cfg(test)]
mod tests;

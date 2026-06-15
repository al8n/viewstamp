//! Deterministic in-memory `Wal`/`Superblock` impls for the DST harness.
//!
//! Reliable + synchronous by default (each submit completes immediately into the
//! completion queue). [`InMemoryWal::with_async_appends`] adds an OPT-IN async-append mode that
//! STAGES each append as not-yet-durable for a seeded number of `poll`s — reopening the in-flight
//! window a real `fsync`-between-ticks WAL has (and the synchronous default closes), which the
//! append-before-ack invariant must survive. The default stays synchronous so existing
//! gates are unaffected. Seeded fault injection ([`StorageFaults`]) adds: TRANSIENT WAL read
//! faults (each read independently rolls — a retry may succeed, exercising the proto's
//! `Status::Recovering` retry loop), permanent torn writes (a flipped body byte ⇒ `Header::verify`
//! fails on read-back), and permanent bit-rot (every read of the slot faults). All faults surface as
//! data (`WalDone::Fault`/`Absent`, `SlotStatus::Faulty`) — the WAL never silently fixes a corrupt
//! body, so the proto's checksum chokepoint always sees it.
//!
//! A later axis adds a TRANSIENT **misdirected-read** fault (`misdirect_read_per_mille`): a WAL read
//! for op X occasionally returns a DIFFERENT present, valid, checksum-CORRECT slot's entry
//! (`header.op() != X`) — TigerBeetle's misdirected-IO hazard, where a read lands on the wrong sector.
//! A misdirected entry self-VERIFIES, so the checksum chokepoint cannot catch it; the proto's
//! PLACEMENT check (recovery's `header.op() == op`) does, routing it to the retry path. It is the read
//! analogue of the torn/bit-rot WRITE faults: faults-as-data the proto must defend against by op
//! placement, not body checksum alone.
//!
//! The OPT-IN **bounded ring** mode ([`InMemoryWal::with_capacity`]) makes the WAL a fixed ring
//! of `n` slots where op `K` occupies slot `K mod n`, so a durable append at `K` physically OVERWRITES
//! whatever op last held that slot (op `K - n`). A read of a wrapped-over op then returns `Absent` (its
//! bytes are gone — a clean wrap). [`Wal::capacity`] reports `n` (the unbounded default reports
//! `u64::MAX`), which engages the proto's stall-before-wrap: the primary refuses to assign an op whose
//! ring slot still holds an un-pruned op, so a committed-but-unpruned op is never the one overwritten.
//! The default stays UNBOUNDED so existing gates are unaffected, and every fault/async mode composes
//! with the ring (a bounded slot can still be torn / bit-rotted / misdirected / staged in flight).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bytes::Bytes;
use viewstamp_proto::{
  BodyFaulty, CheckpointRead, Header, OpId, OpNumber, Prng, ReadOk, SlotStatus, Superblock,
  SuperblockDone, VsrState, Wal, WalDone,
};

/// Seeded storage-fault plan for one replica's WAL + superblock. Deterministic per (seed, replica):
/// the same seed reproduces the same fault decisions, and permanent verdicts (torn / bit-rot) live
/// in the durable struct so they survive a crash + restart unchanged.
///
/// All probabilities are out of 1000 (per mille), mirroring [`crate::Faults`] for the network. Like
/// `Faults`, this is a plain sim-harness config value with public fields — the "no public fields"
/// golden rule is enforced on `viewstamp-proto` (the library), not on the simulation test harness, which
/// already uses pub-field config structs for ergonomic test setup.
///
/// # The transient-vs-permanent distinction
///
/// - **`read_fault_per_mille`** — TRANSIENT. Each `submit_read` rolls independently, so a faulted
///   read may succeed on retry; the proto's recover loop (budget `RECOVER_READ_RETRIES`) clears it.
///   The "committed ops survive crash + storage-fault + restart" gate uses ONLY this, so a
///   restarted replica always recovers from its OWN disk and reaches `Normal` — no peer needed.
/// - **`torn_write_per_mille` / `bit_rot_per_mille`** — PERMANENT (a slot is gone until rewritten /
///   for good on this replica). Recovering such a committed slot needs a PEER: a permanently-faulty
///   HEAD slot ⇒ `RecoveringHead` + `StartView`/`RecoveryResponse` adoption (B1); a permanently-faulty
///   NON-head committed slot ⇒ peer fault-repair via `RequestPrepare` → `Prepare`, with the commit
///   HELD below the hole until the op arrives (B4). The transient-only gate sets these to `0` so a
///   restarted replica recovers from its own disk; the permanent-fault gate turns them on and proves no
///   committed op is lost across crash + permanent fault + restart.
#[derive(Debug, Clone, Copy)]
pub struct StorageFaults {
  /// Per-read probability (out of 1000) that a WAL read returns `Fault` instead of the entry.
  /// TRANSIENT: re-rolled on every read, so a retry can succeed (the recover loop relies on this).
  pub read_fault_per_mille: u32,
  /// Per-append probability (out of 1000) that the durable body is written TORN (one flipped byte
  /// with the ORIGINAL header ⇒ `Header::verify` fails on read-back). Permanent until rewritten.
  pub torn_write_per_mille: u32,
  /// Per-append probability (out of 1000) that the slot is PERMANENTLY corrupt (bit-rot): every read
  /// of it faults, modelling unrecoverable media damage. `0` in the transient-only gates.
  pub bit_rot_per_mille: u32,
  /// Per-append probability (out of 1000) that the slot loses its HEADER too: the append completes
  /// (`WalDone::Appended` fires) but the slot retains NO recoverable header — [`Wal::header`] returns
  /// `None`, [`Wal::status`] reports `Empty`, and a read resolves `Absent`, as if the append had
  /// never happened. This DELIBERATELY VIOLATES the `Wal` header-durability contract (slot headers
  /// MUST survive body-level faults — see the trait docs in `viewstamp-proto/src/storage.rs`), which
  /// the committed-op-survival design (`Body::Repairing` keep-header-only) leans on. It exists ONLY
  /// for the torn-header contract-violation probe lane, which measures the blast radius when an
  /// embedder breaks that contract. PERMANENT until the slot is rewritten/truncated/pruned.
  /// `0` everywhere except the probe lane.
  pub torn_header_per_mille: u32,
  /// Per-read probability (out of 1000) that a WAL read for op X is MISDIRECTED: instead of X's bytes
  /// (or `Absent`), it returns a DIFFERENT present, valid, checksum-CORRECT slot's `ReadOk`
  /// (`header.op() != X`) — TigerBeetle's misdirected-IO hazard, where a read lands on the wrong
  /// sector and returns another op's self-consistent entry. TRANSIENT (re-rolled per read), so the
  /// proto's recover/repair RETRY clears it. The defense is the proto's PLACEMENT check
  /// (`recover`'s `header.op() == op`, `fill_repair`'s `repair.contains(op)`): a misdirected read
  /// checksum-VERIFIES cleanly, so only the op/placement match catches it. `0` ⇒ no misdirection (all
  /// pre-existing gates). Sibling slot is chosen deterministically from the durable `entries`, so the
  /// fault stays a pure function of the per-replica seed.
  pub misdirect_read_per_mille: u32,
  /// Per-read probability (out of 1000) that a CHECKPOINT read returns CORRUPT-but-PARSEABLE bytes:
  /// the live snapshot with one trailing SM-tail byte flipped. The bytes STILL DECODE
  /// (`Endpoint::decode_checkpoint` treats the SM snapshot as an opaque tail) and keep the right BOUND
  /// op (only the tail flips, never the leading op u64), so a donor's `cr.op() == checkpoint_op` gate
  /// passes — but they hash to a DIFFERENT id than the durable root. This is the in-model disk fault
  /// (bit-rot in the snapshot region that still decodes) the serve/recover paths must NOT restore from:
  /// a donor computing the shipped id FROM these bytes would otherwise ship a self-consistent-but-wrong
  /// (id, snapshot) pair, and `recover` would restore corrupt SM/session state — both verify the read
  /// against the DURABLE checkpoint id and DROP it. TRANSIENT (re-rolled per read), so a retry clears it
  /// and a re-solicit / next clean read serves. `0` ⇒ no checkpoint-read content corruption (all
  /// pre-existing gates). Distinct from `read_fault_per_mille`, which faults the read OUTRIGHT.
  pub corrupt_checkpoint_read_per_mille: u32,
}

impl StorageFaults {
  /// No faults: every read succeeds, no torn writes, no bit-rot, no torn headers, no misdirection.
  pub const fn none() -> Self {
    Self {
      read_fault_per_mille: 0,
      torn_write_per_mille: 0,
      bit_rot_per_mille: 0,
      torn_header_per_mille: 0,
      misdirect_read_per_mille: 0,
      corrupt_checkpoint_read_per_mille: 0,
    }
  }
}

impl Default for StorageFaults {
  fn default() -> Self {
    Self::none()
  }
}

/// A staged, not-yet-durable append (async-append mode only). Submitted via `submit_append`, it
/// becomes durable — moved into `entries`, with its `Appended` completion offered by `poll` — only
/// after `remaining` `poll`s have ticked it down to zero. The torn/bit-rot verdict is decided at
/// SUBMIT time (so the same seed reproduces it whether sync or async) and carried here: `body` is
/// already the (possibly torn) bytes to store, and `rot` records whether the slot must land in
/// `rotted` on completion. While staged, the slot is `SlotStatus::Dirty` and reads return `Absent`.
#[derive(Debug, Clone)]
struct PendingAppend {
  /// Polls remaining before this append becomes durable (counts down in `poll`, releases at 0).
  remaining: u32,
  id: OpId,
  op: u64,
  header: Header,
  /// The bytes to store on completion (already torn if the torn-write roll fired at submit time).
  body: Bytes,
  /// Whether to mark `op` permanently bit-rotted on completion (the bit-rot roll fired at submit).
  rot: bool,
  /// Whether to mark `op` torn-HEADER on completion (the contract-violation probe roll fired at
  /// submit): the slot then reports no header at all.
  torn_header: bool,
}

/// A seeded in-memory write-ahead log. With [`StorageFaults::none`] it is reliable + synchronous
///; with faults it injects transient read faults + permanent torn/bit-rot.
///
/// # Async-append mode (opt-in, [`InMemoryWal::with_async_appends`])
///
/// By DEFAULT every `submit_append` completes SYNCHRONOUSLY (the entry is durable and its `Appended`
/// completion is queued in the same call) — the synchronous behaviour all existing gates rely on.
/// Async mode instead STAGES each append as not-yet-durable for a seeded number of `poll`s before it
/// becomes durable, modelling a real WAL whose `fsync` lands between ticks rather than inline. This
/// opens the window a real driver has — and the synchronous default closed — where the proto's head
/// (`self.op`) has advanced past an op whose bytes are still in flight, which is exactly the state
/// the append-before-ack invariant must hold across. It composes with the fault rolls:
/// the torn/bit-rot verdict is still decided at submit time, just applied on completion.
#[derive(Debug)]
pub struct InMemoryWal {
  entries: BTreeMap<u64, (Header, Bytes)>,
  head: u64,
  completions: VecDeque<WalDone>,
  faults: StorageFaults,
  /// Drives the TRANSIENT `read_fault_per_mille` decision. Re-rolled per read (independent attempts),
  /// so a faulted read clears on retry. Persists across restart in the struct (transient verdicts
  /// need not be stable; only permanent ones do, and those live in `entries`/`rotted`).
  prng: Prng,
  /// Slots marked PERMANENTLY corrupt (bit-rot) at append time: every read faults, `status` reports
  /// `Faulty`, `header` reports `None`. Persists across restart (the struct survives crash/restart).
  rotted: BTreeSet<u64>,
  /// Slots whose HEADER was lost at append time (the torn-header contract-violation probe): the
  /// completed append left NO recoverable header, so `header()` is `None`, `status()` is `Empty`, and
  /// a read is `Absent` — the slot vanished as if never written. Deliberately violates the `Wal`
  /// header-durability contract (the probe lane measures the blast radius). Persists across restart;
  /// cleared when the slot is rewritten/truncated/pruned/ring-evicted, like `rotted`.
  torn_headers: BTreeSet<u64>,
  /// Slots whose READS are made to fault PERMANENTLY by an explicit test injection
  /// ([`fault_read_at`](Self::fault_read_at)) — NOT a seeded roll. Every read of such a slot resolves
  /// `WalDone::Fault` (the `header()`/`status()` of the slot are otherwise untouched: the entry stays
  /// in `entries`, so the slot's HEADER and committed bytes are intact). It models an UNRECOVERABLE
  /// read of an UNCOMMITTED tail/head op on a node's own disk — the targeted fault that drives a
  /// restart into `RecoveringHead` (the head slot cannot be trusted) without a probabilistic
  /// `read_fault_per_mille` roll exhausting retries by luck. Because it is only ever set by an explicit
  /// `fault_read_at` call (never a PRNG draw), an unfaulted WAL keeps its exact fault-PRNG stream, so
  /// every existing seed reproduces byte-for-byte. Persists across restart (the struct survives
  /// crash/restart) and clears when the slot is rewritten/truncated/pruned/ring-evicted, like `rotted`.
  head_read_faults: BTreeSet<u64>,
  /// `None` (default) ⇒ synchronous appends. `Some(d)` ⇒ async mode: each `submit_append` stages for
  /// `d` `poll`s before becoming durable. `d == 0` releases on the very next `poll` (still NOT inline,
  /// so the in-flight window still exists for at least one tick).
  async_delay: Option<u32>,
  /// Async mode: appends submitted but not yet durable, in submission order (a serial WAL writer
  /// completes them FIFO). Empty in synchronous mode.
  staged: VecDeque<PendingAppend>,
  /// Observability: how many reads this WAL has actually MISDIRECTED (returned a wrong-op sibling)
  /// since construction. Lets the VOPR sweep assert the misdirected-read axis is NON-vacuous (it
  /// really fired, so the proto's placement check was genuinely exercised) rather than merely armed.
  misdirects_fired: u64,
  /// Observability: how many completed appends LOST their header (the torn-header verdict fired)
  /// since construction. Lets the torn-header probe lane assert it is NON-vacuous (committed slots
  /// genuinely vanished header-and-all) rather than merely armed.
  torn_headers_fired: u64,
  /// `None` (default) ⇒ UNBOUNDED: `entries` grows without a physical cap and `capacity()` reports
  /// `u64::MAX`. `Some(n)` ⇒ a fixed RING of `n` slots: op `K` occupies slot `K mod n`, and a
  /// durable append at `K` physically OVERWRITES whatever op last held that slot (op `K - n`). A read of
  /// a wrapped-over op then finds no resident entry and returns `Absent` (a clean wrap — its bytes are
  /// gone). The proto's stall-before-wrap keeps the un-pruned window `(prune_floor, op]` within `n`, so a
  /// committed-but-unpruned op is never the one overwritten; see [`InMemoryWal::with_capacity`].
  capacity: Option<u64>,
}

impl Default for InMemoryWal {
  fn default() -> Self {
    Self::new()
  }
}

impl InMemoryWal {
  /// Creates an empty, reliable WAL (no faults).
  pub fn new() -> Self {
    Self::with_faults(StorageFaults::none(), 0)
  }

  /// Creates an empty WAL with a seeded fault plan. `seed` drives the transient read-fault rolls and
  /// the per-append torn/bit-rot decisions deterministically. Synchronous appends (no async delay).
  pub fn with_faults(faults: StorageFaults, seed: u64) -> Self {
    Self {
      entries: BTreeMap::new(),
      head: 0,
      completions: VecDeque::new(),
      faults,
      prng: Prng::new(seed),
      rotted: BTreeSet::new(),
      torn_headers: BTreeSet::new(),
      head_read_faults: BTreeSet::new(),
      async_delay: None,
      staged: VecDeque::new(),
      misdirects_fired: 0,
      torn_headers_fired: 0,
      capacity: None,
    }
  }

  /// Creates an empty, reliable WAL as a **fixed RING of `n` slots**. Op `K`
  /// occupies slot `K mod n`; a durable append at `K` physically OVERWRITES whatever op last held that
  /// slot (op `K - n`), and a read of that wrapped-over op then returns `Absent` (its bytes are gone — a
  /// clean wrap, which the proto's placement check `header.op() == op` would reject as a torn/misdirect
  /// anyway, so we model it as `Absent` outright). [`capacity`](InMemoryWal::capacity) reports `n`, so
  /// the proto's bounded-WAL stall engages and refuses to assign an op whose ring slot still holds an
  /// un-pruned op. OPT-IN; the default ([`new`](Self::new)/[`with_faults`](Self::with_faults)) stays
  /// UNBOUNDED (`capacity() == u64::MAX`) so existing gates are unaffected. `n` must be non-zero. All
  /// fault/async modes compose with the ring (a bounded slot can still be torn/bit-rotted/misdirected,
  /// or staged in flight); use [`with_capacity_faults`](Self::with_capacity_faults) /
  /// [`set_capacity`](Self::set_capacity) for those.
  pub fn with_capacity(n: u64) -> Self {
    Self::with_capacity_faults(n, StorageFaults::none(), 0)
  }

  /// Like [`with_capacity`](Self::with_capacity) but with a seeded fault plan, so the bounded ring
  /// composes with torn/bit-rot/misdirected-read faults (a wrapped ring slot can still be corrupt).
  pub fn with_capacity_faults(n: u64, faults: StorageFaults, seed: u64) -> Self {
    assert!(n > 0, "a bounded WAL ring needs at least one slot");
    let mut w = Self::with_faults(faults, seed);
    w.capacity = Some(n);
    w
  }

  /// Test/harness helper: switch an EMPTY WAL between unbounded (`None`) and a fixed ring of `n` slots
  /// (`Some(n)`), preserving the existing fault plan / async mode. Mirrors how the cluster harness
  /// rebuilds storage when toggling a mode. Panics if called on a non-empty WAL (the resident set would
  /// not match the new ring geometry) or with `Some(0)`.
  pub fn set_capacity(&mut self, n: Option<u64>) {
    assert!(
      self.entries.is_empty()
        && self.staged.is_empty()
        && self.rotted.is_empty()
        && self.torn_headers.is_empty(),
      "set_capacity must be called on an empty WAL"
    );
    assert!(n != Some(0), "a bounded WAL ring needs at least one slot");
    self.capacity = n;
  }

  /// Creates an empty, reliable WAL in **async-append mode**: every `submit_append` stages the entry
  /// as not-yet-durable for `delay_ticks` `poll`s, then it becomes durable and `poll` yields its
  /// `Appended`. Opt-in; the default ([`new`](Self::new)/[`with_faults`](Self::with_faults)) stays
  /// synchronous so existing gates are unaffected. Until an append completes the slot is
  /// [`SlotStatus::Dirty`] (never `Clean`) and a read of it returns `Absent` — modelling the in-flight
  /// window a real async WAL has, where the proto's head has advanced past bytes not yet on disk
  ///. `delay_ticks == 0` still defers to the next `poll` (never inline).
  pub fn with_async_appends(delay_ticks: u32) -> Self {
    let mut w = Self::with_faults(StorageFaults::none(), 0);
    w.async_delay = Some(delay_ticks);
    w
  }

  /// Enables async-append mode on an existing WAL with a seeded fault plan, so the in-flight window
  /// composes with transient/permanent faults. Mirrors [`with_async_appends`](Self::with_async_appends)
  /// but keeps the configured `faults`/`seed`.
  pub fn with_async_appends_and_faults(faults: StorageFaults, seed: u64, delay_ticks: u32) -> Self {
    let mut w = Self::with_faults(faults, seed);
    w.async_delay = Some(delay_ticks);
    w
  }

  /// Test-only: the number of staged (submitted-but-not-yet-durable) appends. `0` in synchronous
  /// mode and whenever the async staging queue has drained. Lets a reproduction assert it is
  /// genuinely exercising the in-flight window (an append is really pending when the re-ack fires).
  #[doc(hidden)]
  pub fn staged_len(&self) -> usize {
    self.staged.len()
  }

  /// Test-only: the number of PERMANENTLY-corrupt slots in `1..=op` — bit-rotted (every read faults)
  /// or torn (the stored body fails its header's `verify`). Used by the permanent-fault gate to
  /// assert the crashed replica's recovery is non-vacuous (it really does read back faulty committed
  /// slots that must be peer-repaired).
  #[doc(hidden)]
  pub fn corrupt_slots_at_or_below_for_test(&self, op: u64) -> usize {
    (1..=op)
      .filter(|&o| {
        self.rotted.contains(&o) || self.entries.get(&o).is_some_and(|(h, b)| !h.verify(b))
      })
      .count()
  }

  /// The number of durable slots currently held (after any prune/truncate). Used by the
  /// boundedness checker to assert the WAL stays bounded over a long run with checkpoint GC.
  pub fn len(&self) -> usize {
    self.entries.len()
  }

  /// True iff the WAL holds no durable slots.
  pub fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }

  /// Drop every STAGED (submitted-but-not-yet-durable) append WITHOUT letting it become durable —
  /// modelling a crash that loses any WAL `fsync` still in flight (faithful fsync-loss-on-crash). The
  /// already-durable log (`entries`/`head`, plus the permanent `rotted` verdicts of completed slots)
  /// is left exactly at its last-COMPLETED state — what a restart recovers from. A no-op in
  /// synchronous mode (`staged` is always empty there). Mirrors
  /// [`InMemorySuperblock::discard_inflight`].
  ///
  /// Truncate/prune are applied synchronously (they mutate `entries`/`rotted`/`staged` inline, never
  /// staged), so the only un-released queue to clear is `staged` — clearing it abandons exactly the
  /// in-flight appends and nothing durable. Called by the cluster's `crash` so a not-yet-`fsync`'d WAL
  /// append is genuinely LOST on crash (it never resurfaces as durable post-restart), exercising the
  /// stale-WAL-slot class the proto must defend against.
  pub fn discard_inflight(&mut self) {
    self.staged.clear();
  }

  /// Pick a deterministic MISDIRECTED-read sibling for a read of `op`: a DIFFERENT durable slot
  /// (`!= op`) whose stored `(header, body)` self-VERIFIES (`Header::verify` — excludes torn slots,
  /// whose body is corrupt) and is NOT bit-rotted. Returns its `(Header, body)` to return under the
  /// requesting read's `OpId` (so `header.op() != op` — the placement violation the proto's recovery
  /// `header.op() == op` check must reject). `None` if no such sibling exists (then the caller does the
  /// honest read). The candidate is chosen by a seeded index into the (op-ordered) candidate set, so
  /// the misdirection target is a pure function of the per-replica seed. Draws from `self.prng` (hence
  /// `&mut self`), AFTER the misdirect probability roll, keeping a masked (`VOPR_NO_MISDIRECT`) run on
  /// the same stream as far as the probability gate.
  fn misdirect_sibling(&mut self, op: u64) -> Option<(Header, Bytes)> {
    // Candidate VALID sibling slots: present, op != requested, self-verifying, not bit-rotted, not
    // torn-header (a vanished slot has no readable bytes to land on). A torn
    // slot (body fails verify) is excluded — a misdirected read returns a CHECKSUM-CORRECT entry, so
    // the only thing the proto can use to reject it is the op/placement mismatch, not the checksum.
    let candidates: VecDeque<u64> = self
      .entries
      .iter()
      .filter(|&(&o, (h, b))| {
        o != op && !self.rotted.contains(&o) && !self.torn_headers.contains(&o) && h.verify(b)
      })
      .map(|(&o, _)| o)
      .collect();
    if candidates.is_empty() {
      return None;
    }
    let idx = self.prng.below(candidates.len() as u64) as usize;
    let pick = candidates[idx];
    let sib = self.entries.get(&pick).map(|(h, b)| (*h, b.clone()));
    if sib.is_some() {
      self.misdirects_fired += 1;
    }
    sib
  }

  /// Test-only: how many reads this WAL has MISDIRECTED (returned a wrong-op valid sibling) since
  /// construction. `> 0` proves the misdirected-read axis genuinely fired (the proto's placement check
  /// was actually exercised). Persists across `restart` because the WAL struct does.
  #[doc(hidden)]
  pub fn misdirects_fired(&self) -> u64 {
    self.misdirects_fired
  }

  /// Test-only: how many completed appends LOST their header (the torn-header contract-violation
  /// verdict fired) since construction. `> 0` proves the probe lane genuinely made slots vanish
  /// header-and-all. Persists across `restart` because the WAL struct does.
  #[doc(hidden)]
  pub fn torn_headers_fired(&self) -> u64 {
    self.torn_headers_fired
  }

  /// Test-only: make EVERY read of op `op` fault PERMANENTLY (an unrecoverable read of this slot on
  /// this replica's own disk). The slot's stored `(header, body)` is left untouched, so its
  /// `header()`/`status()` still report a durable entry — only `submit_read` resolves `Fault`. Used to
  /// drive a restart into `RecoveringHead`: faulting the (uncommitted) HEAD slot means recovery
  /// exhausts its per-slot retry budget and cannot trust its head, the exact precondition the offline-restart
  /// re-formation escalation must resolve. Targeted at a chosen op (no PRNG draw), so an unfaulted WAL
  /// keeps its exact fault stream and every existing seed reproduces byte-for-byte. The injection
  /// persists across restart and clears when the slot is truncated/pruned/ring-evicted, like a bit-rot
  /// verdict. Faulting an UNCOMMITTED op keeps committed data sound (the durability checker stays
  /// satisfied); it is the caller's responsibility to target the uncommitted tail, never a committed op.
  #[doc(hidden)]
  pub fn fault_read_at(&mut self, op: OpNumber) {
    self.head_read_faults.insert(op.get());
  }

  /// Bounded-ring physical slot reuse: when a durable append at `op` lands in slot `op mod n`,
  /// EVICT whatever DIFFERENT op last held that slot (op `op - n`) — its bytes are physically gone (a
  /// clean wrap), so it leaves `entries`/`rotted`/`staged` and a subsequent read of it returns `Absent`.
  /// A no-op in unbounded mode (`capacity == None`). Called at the moment a slot is PHYSICALLY written:
  /// inline in `submit_append` (sync) or on release in `poll` (async). Removing the wrapped op from
  /// `rotted` too is correct — overwriting a bit-rotted slot rewrites the media, clearing the verdict.
  fn evict_wrapped_slot(&mut self, op: u64) {
    let Some(n) = self.capacity else {
      return;
    };
    let slot = op % n;
    // The resident set keeps at most one op per slot, so this removes the single congruent occupant
    // (`op - n`) if present, never `op` itself.
    self.entries.retain(|&o, _| o == op || o % n != slot);
    self.rotted.retain(|&o| o == op || o % n != slot);
    self.torn_headers.retain(|&o| o == op || o % n != slot);
    self.head_read_faults.retain(|&o| o == op || o % n != slot);
    self.staged.retain(|s| s.op == op || s.op % n != slot);
  }
}

/// Flips one byte of a body so `Header::verify` fails on read-back (a torn write). An empty body
/// grows by one junk byte (so it no longer matches a header computed over `b""`).
fn tear(body: &Bytes) -> Bytes {
  let mut v = body.to_vec();
  match v.first_mut() {
    Some(b) => *b ^= 0xFF,
    None => v.push(0xFF),
  }
  Bytes::from(v)
}

impl Wal for InMemoryWal {
  fn op_head(&self) -> OpNumber {
    OpNumber::with(self.head)
  }

  fn capacity(&self) -> u64 {
    // Unbounded by default (`u64::MAX` ⇒ the proto's capacity back-pressure never engages, so the
    // existing gates are unaffected). In bounded mode ([`with_capacity`](InMemoryWal::with_capacity))
    // this reports the fixed ring size `n`, engaging the proto's stall-before-wrap so it refuses
    // to assign an op whose ring slot still holds an un-pruned op.
    self.capacity.unwrap_or(u64::MAX)
  }

  fn header(&self, op: OpNumber) -> Option<Header> {
    // TORN-HEADER probe verdict: the completed append left NO recoverable header, so the slot reports
    // none at all — the deliberate violation of the trait's header-durability contract that the probe
    // lane measures. Checked first: it overrides the in-model durability below.
    if self.torn_headers.contains(&op.get()) {
      return None;
    }
    // The header tuple lives in `entries` and is durable from the moment the append completed
    // (it is always written intact — only the BODY can be torn or bit-rotted). Both fault
    // classes therefore leave the header readable: a bit-rotted slot still has its `entries`
    // tuple, and a torn slot's header was never touched by the tear. Return `Some` for any op
    // present in `entries`, reserving `None` for ops that were never durably appended (or were
    // subsequently truncated / pruned / ring-wrapped).
    self.entries.get(&op.get()).map(|(h, _)| *h)
  }

  fn status(&self, op: OpNumber) -> SlotStatus {
    // TORN-HEADER probe verdict first: the slot vanished as if the append had never happened, so it
    // reports `Empty` — not `Faulty`, which would still admit "this op exists here" (the very
    // knowledge the lost header was carrying).
    if self.torn_headers.contains(&op.get()) {
      SlotStatus::Empty
    } else if self.rotted.contains(&op.get()) {
      SlotStatus::Faulty
    } else if self.entries.contains_key(&op.get()) {
      SlotStatus::Clean
    } else if self.staged.iter().any(|s| s.op == op.get()) {
      // Async mode: a submitted-but-not-yet-durable append is DIRTY, never Clean — the bytes are not
      // on disk yet, so the proto must not treat this slot as a durable voter copy.
      SlotStatus::Dirty
    } else {
      SlotStatus::Empty
    }
  }

  fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes) {
    // The fault verdict is decided HERE (at submit) in BOTH modes, so the same seed reproduces the
    // same torn/bit-rot decisions whether appends are synchronous or staged. In async mode the
    // verdict is merely carried on the staged entry and applied when it becomes durable.
    // PERMANENT bit-rot: mark the slot so every future read faults (and status/header report it).
    let rot =
      self.faults.bit_rot_per_mille > 0 && self.prng.chance(self.faults.bit_rot_per_mille, 1000);
    // PERMANENT torn write: persist the ORIGINAL header with a corrupted body so `Header::verify`
    // fails on read-back. Never silently fix it — the proto's checksum chokepoint must detect it.
    let stored = if self.faults.torn_write_per_mille > 0
      && self.prng.chance(self.faults.torn_write_per_mille, 1000)
    {
      tear(&body)
    } else {
      body
    };
    // TORN-HEADER probe verdict (contract violation, probe lane only): the slot completes its append
    // but loses the header too — it will read back as if never written. Rolled AFTER the other
    // verdicts and only when armed (`per_mille > 0` short-circuits the draw), so every zero-rate run
    // keeps its exact fault-PRNG stream (pinned seeds reproduce).
    let torn_header = self.faults.torn_header_per_mille > 0
      && self.prng.chance(self.faults.torn_header_per_mille, 1000);
    match self.async_delay {
      // SYNCHRONOUS (default): durable immediately, completion queued in this call.
      None => {
        // Bounded ring: writing slot `op mod n` physically evicts the op that last held it.
        self.evict_wrapped_slot(op.get());
        if rot {
          self.rotted.insert(op.get());
        }
        if torn_header {
          self.torn_headers.insert(op.get());
          self.torn_headers_fired += 1;
        } else {
          // Rewriting a slot whose previous occupant (same op, e.g. a repair re-append) lost its
          // header clears the verdict — the media was rewritten whole.
          self.torn_headers.remove(&op.get());
        }
        self.entries.insert(op.get(), (header, stored));
        self.head = self.head.max(op.get());
        self.completions.push_back(WalDone::Appended(id));
      }
      // ASYNC: STAGE as not-yet-durable. `self.head`/`entries`/`rotted` are left untouched (so the
      // slot reads `Dirty`/`Absent` and `op_head` does not yet count it) until `poll` releases it
      // after `delay` ticks — opening the in-flight window the synchronous path never had.
      Some(delay) => self.staged.push_back(PendingAppend {
        remaining: delay,
        id,
        op: op.get(),
        header,
        body: stored,
        rot,
        torn_header,
      }),
    }
  }

  fn submit_read(&mut self, id: OpId, op: OpNumber) {
    // TORN-HEADER probe verdict: the slot retains NOTHING recoverable — not even the header — so the
    // read resolves `Absent`, exactly as if the append had never happened. (The contract violation
    // the probe lane measures: a real backend must never lose a completed append's header.)
    if self.torn_headers.contains(&op.get()) {
      self.completions.push_back(WalDone::Absent(id));
      return;
    }
    // PERMANENT bit-rot: the header is durable (it lives in `entries`) but the body is
    // unrecoverable from this replica. Emit BodyFaulty so the caller knows the op exists and
    // can identify it, without pretending the body is valid.
    if self.rotted.contains(&op.get()) {
      // The header must be present in `entries` whenever a rot verdict is held (rot is set
      // only at append-completion time, so the entry was written before the rot fired).
      let stored_header = self
        .entries
        .get(&op.get())
        .map(|(h, _)| *h)
        .expect("rot entry must be present in entries");
      self
        .completions
        .push_back(WalDone::BodyFaulty(BodyFaulty::new(id, stored_header)));
      return;
    }
    // TARGETED PERMANENT read fault (an explicit `fault_read_at` injection, NOT a seeded roll): every
    // read of this slot faults outright, modelling an unrecoverable read of an uncommitted tail/head op.
    // Checked before the transient roll so it is DETERMINISTIC (no luck needed to exhaust the recover
    // retry budget); the slot's header/body remain intact in `entries`, so only reads fault.
    if self.head_read_faults.contains(&op.get()) {
      self.completions.push_back(WalDone::Fault(id));
      return;
    }
    // TRANSIENT read fault: rolled independently per read, so a retry may succeed — this is what the
    // proto's recover retry loop relies on to clear a transient fault from its OWN disk.
    if self.faults.read_fault_per_mille > 0
      && self.prng.chance(self.faults.read_fault_per_mille, 1000)
    {
      self.completions.push_back(WalDone::Fault(id));
      return;
    }
    // MISDIRECTED READ (TigerBeetle's misdirected-IO hazard): occasionally return a DIFFERENT present,
    // valid, checksum-CORRECT slot's entry under THIS read's `id` (so `header.op() != op`). A misdirect
    // checksum-VERIFIES cleanly — the body is some real op's body — so the proto cannot reject it by
    // `Header::verify` alone; only its PLACEMENT check (`recover`'s `header.op() == op`) catches it,
    // routing it to the SAME retry path as a fault. TRANSIENT (re-rolled per read): a later read of the
    // same slot lands correctly, so the recover loop clears it. We only misdirect when a valid sibling
    // (`!= op`, present, self-verifying, not bit-rotted) exists — else fall through to the honest read.
    if self.faults.misdirect_read_per_mille > 0
      && self.prng.chance(self.faults.misdirect_read_per_mille, 1000)
      && let Some((h, b)) = self.misdirect_sibling(op.get())
    {
      self
        .completions
        .push_back(WalDone::ReadOk(ReadOk::new(id, h, b)));
      return;
    }
    // Otherwise return the stored entry. A torn body (header present but body fails verify) is
    // promoted to BodyFaulty — the header is durable, only the body is corrupt. An op never
    // durably appended (not in `entries`) yields Absent.
    let done = match self.entries.get(&op.get()) {
      Some((h, b)) if !h.verify(b) => WalDone::BodyFaulty(BodyFaulty::new(id, *h)),
      Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    };
    self.completions.push_back(done);
  }

  fn truncate(&mut self, above: OpNumber) {
    self.entries.retain(|&op, _| op <= above.get());
    // A truncated-away slot is no longer corrupt (it will be rewritten by a later append).
    self.rotted.retain(|&op| op <= above.get());
    self.torn_headers.retain(|&op| op <= above.get());
    self.head_read_faults.retain(|&op| op <= above.get());
    // Drop any staged (in-flight) append above the truncation point: those bytes are abandoned and
    // must never later become durable above the new head (async mode only; a no-op otherwise).
    self.staged.retain(|s| s.op <= above.get());
    self.head = self.head.min(above.get());
  }

  fn prune(&mut self, below: OpNumber) {
    self.entries.retain(|&op, _| op >= below.get());
    self.rotted.retain(|&op| op >= below.get());
    self.torn_headers.retain(|&op| op >= below.get());
    self.head_read_faults.retain(|&op| op >= below.get());
    // A staged append below the GC floor is moot; drop it (async mode only).
    self.staged.retain(|s| s.op >= below.get());
  }

  fn poll(&mut self) -> Option<WalDone> {
    // Async mode: tick the staged (in-flight) appends. A serial WAL writer completes them in
    // submission order, so we count down the FRONT entry and make it durable when it reaches zero —
    // at which point its bytes land in `entries`/`rotted` (the fault verdict taken at submit) and its
    // `Appended` is queued. This is the ONLY place a staged append becomes durable: until then the
    // slot is `Dirty`/`Absent` and the proto's head sits above not-yet-durable bytes (the
    // append-before-ack window). A no-op in synchronous mode (`staged` is always empty there).
    if let Some(front) = self.staged.front_mut() {
      if front.remaining == 0 {
        let done = self.staged.pop_front().expect("front exists");
        // Bounded ring: the physical write happens HERE (on release), so the slot-`op mod n`
        // eviction of the wrapped-over op happens here too, not at submit time.
        self.evict_wrapped_slot(done.op);
        if done.rot {
          self.rotted.insert(done.op);
        }
        if done.torn_header {
          self.torn_headers.insert(done.op);
          self.torn_headers_fired += 1;
        } else {
          self.torn_headers.remove(&done.op);
        }
        self.entries.insert(done.op, (done.header, done.body));
        self.head = self.head.max(done.op);
        self.completions.push_back(WalDone::Appended(done.id));
      } else {
        front.remaining -= 1;
      }
    }
    self.completions.pop_front()
  }
}

/// A staged, not-yet-durable superblock write (async-write mode only). Submitted via `submit_write`
/// (a durable-root write) or `submit_write_checkpoint` (a snapshot write), it becomes durable — its
/// effect PUBLISHED, with its `Wrote` completion offered by `poll` — only after `remaining` `poll`s
/// have ticked it down to zero. Until then `state()` still returns the LAST-completed root and
/// `submit_read_checkpoint` reads the last-completed snapshot, modelling a real superblock whose
/// `fsync` lands between ticks. A serial writer completes these FIFO (preserving the trait's
/// root-write ordering contract), and the effect is applied ON COMPLETION, in order.
#[derive(Debug, Clone)]
enum StagedSbWrite {
  /// A durable-root write: on completion, publishes `state` as the new durable root.
  Root { id: OpId, state: VsrState },
  /// A checkpoint snapshot write: on completion, publishes `(op, snapshot)` as the readable checkpoint.
  Checkpoint {
    id: OpId,
    op: OpNumber,
    snapshot: Bytes,
  },
}

impl StagedSbWrite {
  fn id(&self) -> OpId {
    match self {
      StagedSbWrite::Root { id, .. } | StagedSbWrite::Checkpoint { id, .. } => *id,
    }
  }
}

/// A seeded in-memory superblock + checkpoint store. The only fault it injects is a TRANSIENT
/// checkpoint-read fault (`read_fault_per_mille`): the recover loop retries it within budget. It
/// NEVER permanently corrupts a checkpoint the durable root names (preserving the invariant
/// that the root only ever names a fully-written snapshot), so the recover path always eventually
/// restores. Torn/bit-rot are WAL-only.
///
/// # Redundant checkpoint copies — retain the last-ROOTED snapshot
///
/// The checkpoint store keeps a SMALL set of recent snapshot generations (`snapshots`, op → bytes),
/// not a single clobberable slot, modelling a faithful redundant-copy superblock backend. A
/// `submit_read_checkpoint` always serves the snapshot whose op the CURRENT durable root names
/// (`state().checkpoint_op()`) — so the snapshot recovery reads ALWAYS satisfies recover's
/// `cr.op() == state.checkpoint_op()` placement check. The proto writes a checkpoint in two steps —
/// `submit_write_checkpoint(op, snapshot)` then a durable `submit_write(root)` whose
/// `state.checkpoint_op() == op` — so a newly-written snapshot becomes READABLE only once a subsequent
/// ROOT actually names it (the durable root is the authority for which generation is live). A
/// staged-but-unrooted snapshot (its root never landed — e.g. the checkpoint was abandoned by a view
/// change, or the crash interrupted the root write) is therefore NEVER served, and a `crash`
/// ([`discard_inflight`](InMemorySuperblock::discard_inflight)) drops it, keeping the last-rooted
/// snapshot readable. This is what lets `recover` restore from its OWN disk in the orphaned-checkpoint
/// case (the new snapshot landed but its root did not) instead of escalating to a spurious peer fetch
/// a redundant-copy backend would never need. (Before this, a single slot let a new snapshot clobber
/// the last-rooted one even when its root never landed → the recover checkpoint read returned bytes
/// whose op disagreed with the durable root → retry exhaustion → peer-fetch escalation.)
///
/// Retention stays bounded: snapshots STRICTLY OLDER than the live root's `checkpoint_op` are GC'd —
/// but only once the in-flight `staged` queue has drained, since a later-completing root can still
/// reset `state` to an older `checkpoint_op` (the proto's serialized-root-ordering supersession: a
/// checkpoint's step-2 root, left in flight when a view change issues a durable-view root naming the
/// OLD checkpoint, completes FIRST but is superseded by that later durable-view root). So an older
/// rooted snapshot is retained until no queued root could re-name it — at most a couple of generations.
///
/// # Async-write mode (opt-in, [`InMemorySuperblock::with_async_writes_and_faults`])
///
/// By DEFAULT every `submit_write`/`submit_write_checkpoint` completes SYNCHRONOUSLY (the effect is
/// applied and the `Wrote` completion queued in the same call) — the synchronous behaviour all existing
/// gates rely on. Async mode instead STAGES each write as not-yet-durable for a seeded number of
/// `poll`s before it becomes durable, modelling a real superblock whose `fsync` lands between ticks.
/// This opens the **pending durable-view window** the proto's durable-view-before-participate gate
/// must hold across: a replica that just became primary has set `Status::Normal` and
/// minted the view-change root write, but that root is still in flight — so `pending_sb` is armed and
/// `state()` still names the OLD view, exactly the window where a delayed `GetView`/`Recovery` or a
/// primary timer must NOT make it act in the not-yet-durable view. The synchronous default never
/// opens this window (the write is durable inline). Completions are FIFO so the root-write ordering
/// contract holds; the effect (new root / new checkpoint bytes) is applied on completion.
#[derive(Debug)]
pub struct InMemorySuperblock {
  state: VsrState,
  /// Recent checkpoint snapshot generations, keyed by op (the value `submit_write_checkpoint` was
  /// called with). `submit_read_checkpoint` serves the entry the CURRENT durable root names
  /// (`state().checkpoint_op()`); newer staged generations whose root has not landed are retained but
  /// not served, and strictly-older-than-live generations are GC'd once no in-flight root could
  /// re-name them. Modelling redundant copies, not a single clobberable slot.
  snapshots: BTreeMap<u64, Bytes>,
  completions: VecDeque<SuperblockDone>,
  faults: StorageFaults,
  prng: Prng,
  /// `None` (default) ⇒ synchronous writes. `Some(d)` ⇒ async mode: each submitted write stages for
  /// `d` `poll`s before becoming durable. `d == 0` releases on the very next `poll` (still NOT inline,
  /// so the pending-durable-view window exists for at least one tick).
  async_delay: Option<u32>,
  /// Async mode: writes submitted but not yet durable, in submission order (a serial superblock writer
  /// completes them FIFO). Empty in synchronous mode.
  staged: VecDeque<(u32, StagedSbWrite)>,
}

impl Default for InMemorySuperblock {
  fn default() -> Self {
    Self::new()
  }
}

impl InMemorySuperblock {
  /// Creates a fresh-cluster superblock (`VsrState::new`, no checkpoint, no faults).
  pub fn new() -> Self {
    Self::with_faults(StorageFaults::none(), 0)
  }

  /// Creates a fresh-cluster superblock with a seeded fault plan. Only `read_fault_per_mille` (a
  /// transient checkpoint-read fault) is honoured; torn/bit-rot do not apply to the superblock.
  /// Synchronous writes (no async delay).
  pub fn with_faults(faults: StorageFaults, seed: u64) -> Self {
    Self {
      state: VsrState::new(),
      snapshots: BTreeMap::new(),
      completions: VecDeque::new(),
      faults,
      prng: Prng::new(seed),
      async_delay: None,
      staged: VecDeque::new(),
    }
  }

  /// Creates a fresh-cluster superblock with a seeded fault plan in **async-write mode**: every
  /// `submit_write`/`submit_write_checkpoint` stages the write as not-yet-durable for `delay_ticks`
  /// `poll`s, then it becomes durable and `poll` yields its `Wrote`. Opt-in; the default
  /// ([`new`](Self::new)/[`with_faults`](Self::with_faults)) stays synchronous so existing gates are
  /// unaffected. Until a write completes, `state()` returns the prior durable root and
  /// `submit_read_checkpoint` reads the prior snapshot — opening the pending-durable-view window the
  /// proto's durable-view-before-participate gate must survive. `delay_ticks == 0` still
  /// defers to the next `poll` (never inline).
  pub fn with_async_writes_and_faults(faults: StorageFaults, seed: u64, delay_ticks: u32) -> Self {
    let mut sb = Self::with_faults(faults, seed);
    sb.async_delay = Some(delay_ticks);
    sb
  }

  /// Test-only: the number of staged (submitted-but-not-yet-durable) superblock writes. `0` in
  /// synchronous mode and whenever the async staging queue has drained. Lets a reproduction assert it
  /// is genuinely exercising the pending durable-view/checkpoint window.
  #[doc(hidden)]
  pub fn staged_len(&self) -> usize {
    self.staged.len()
  }

  /// Drop every staged (not-yet-durable) write WITHOUT publishing its effect — modelling a crash that
  /// loses any superblock `fsync` still in flight. The durable root is left at its last COMPLETED value
  /// (what a restart recovers from). A no-op for the root in synchronous mode (`staged` is always
  /// empty). Called by the cluster's `crash` so a crash genuinely loses a not-yet-durable view write
  /// (the precondition for the durable-view-before-participate property to mean anything).
  ///
  /// It ALSO discards any staged-but-unrooted checkpoint snapshot — a generation whose bytes landed
  /// but whose durable ROOT never did (the `state` still names an OLDER checkpoint). Such a snapshot
  /// was never the live checkpoint, so a faithful redundant-copy backend's crash leaves only the
  /// last-rooted snapshot readable. Concretely: drop every `snapshots` entry whose op
  /// is NOT the live root's `checkpoint_op` (strictly newer unrooted generations; older ones are
  /// already GC'd in steady state). After this the only retained snapshot is exactly the one the
  /// durable root names, so a restart's recover restores from its OWN disk — not a spurious peer fetch.
  pub fn discard_inflight(&mut self) {
    self.staged.clear();
    let live = self.state.checkpoint_op().get();
    self.snapshots.retain(|&op, _| op == live);
  }

  /// Test-only: DIRECTLY install `state` as the durable root, bypassing the write path — modelling an
  /// operator PRE-WRITING a successor durable root onto a STOPPED node during an offline
  /// reconfiguration. Any in-flight staged write is dropped first (the node is stopped, like a crash),
  /// and the retained checkpoint snapshots are left intact: an offline-restart successor root PRESERVES
  /// `checkpoint_op` / `checkpoint_id` (see [`prepare_restart`](viewstamp_proto::prepare_restart)), so
  /// the live snapshot generation it names is still present and readable. The node then recovers off
  /// this root on the next [`Endpoint::recover`](viewstamp_proto::Endpoint::recover). Only legitimate
  /// while the node is not being polled (offline) — it makes the new root durable INSTANTLY, the
  /// faithful "pre-written while stopped" semantics.
  #[doc(hidden)]
  pub fn install_root_for_test(&mut self, state: VsrState) {
    self.staged.clear();
    self.state = state;
  }

  /// The op the CURRENT durable root names as its checkpoint — the generation `submit_read_checkpoint`
  /// must serve so recover's `cr.op() == state.checkpoint_op()` placement check always holds.
  fn live_checkpoint_op(&self) -> u64 {
    self.state.checkpoint_op().get()
  }

  /// Test-only: the byte length of the LIVE ROOTED checkpoint envelope (the bytes a serve-read
  /// returns — exactly what a `SyncCheckpoint`/chunked transfer would carry), or `None` when no
  /// checkpoint has been rooted. The large-snapshot gate reads this to assert the envelope genuinely
  /// exceeded the one-frame threshold (the would-have-wedged precondition).
  #[doc(hidden)]
  pub fn live_checkpoint_len(&self) -> Option<usize> {
    let live = self.live_checkpoint_op();
    if live == 0 {
      return None;
    }
    self.snapshots.get(&live).map(Bytes::len)
  }

  /// GC checkpoint snapshot generations no longer reachable: drop every entry STRICTLY OLDER than the
  /// live root's `checkpoint_op`. Deferred until the in-flight `staged` queue has drained, because a
  /// later-completing root can still reset `state` to an OLDER `checkpoint_op` (the proto's serialized
  /// root-ordering supersession — a stale in-flight checkpoint root completes before a durable-view
  /// root naming the older checkpoint), and that older snapshot must stay readable until no queued root
  /// could re-name it. Newer-than-live generations (a written snapshot whose root has not landed yet)
  /// are RETAINED — a pending checkpoint root will promote one to live. Bounds the map to a couple of
  /// generations in steady state.
  fn gc_snapshots(&mut self) {
    if !self.staged.is_empty() {
      return;
    }
    let live = self.live_checkpoint_op();
    self.snapshots.retain(|&op, _| op >= live);
  }
}

impl Superblock for InMemorySuperblock {
  fn state(&self) -> VsrState {
    self.state.clone()
  }

  fn submit_write(&mut self, id: OpId, state: VsrState) {
    match self.async_delay {
      // SYNCHRONOUS (default): durable immediately, completion queued in this call. The new
      // durable root may NAME a just-written snapshot generation (a checkpoint's step-2 root) — which
      // becomes the live/readable checkpoint by virtue of `state.checkpoint_op()` now pointing at it;
      // GC then drops strictly-older generations (staged is empty in sync mode, so GC runs inline).
      None => {
        self.state = state;
        self.gc_snapshots();
        self.completions.push_back(SuperblockDone::Wrote(id));
      }
      // ASYNC: STAGE as not-yet-durable. `self.state` is left at the prior durable root until `poll`
      // releases this write after `delay` ticks — opening the pending durable-view window.
      Some(delay) => self
        .staged
        .push_back((delay, StagedSbWrite::Root { id, state })),
    }
  }

  fn submit_write_checkpoint(&mut self, id: OpId, op: OpNumber, snapshot: Bytes) {
    match self.async_delay {
      // SYNCHRONOUS (default): the snapshot generation lands in the store immediately, but is NOT yet
      // the live/readable checkpoint — it becomes readable only when a subsequent ROOT write names its
      // op (the proto's step 2). Until then `submit_read_checkpoint` still serves the last-rooted
      // generation. (Modelling redundant copies: a written-but-unrooted snapshot is not yet authority.)
      None => {
        self.snapshots.insert(op.get(), snapshot);
        self.completions.push_back(SuperblockDone::Wrote(id));
      }
      // ASYNC: STAGE; the snapshot is not even WRITTEN (let alone rooted) until this write completes
      // (the prior live checkpoint stays readable meanwhile). The proto sequences the snapshot write
      // before its root write, and FIFO completion preserves that ordering.
      Some(delay) => self
        .staged
        .push_back((delay, StagedSbWrite::Checkpoint { id, op, snapshot })),
    }
  }

  fn submit_read_checkpoint(&mut self, id: OpId) {
    // Serve the generation the CURRENT durable root names (`state().checkpoint_op()`), so a recover
    // read ALWAYS satisfies `cr.op() == state.checkpoint_op()`. A newer staged-but-unrooted snapshot in
    // the store is deliberately NOT served (its root has not landed). `live == 0` means no checkpoint
    // has ever been rooted → Fault (the no-checkpoint case), as before.
    let live = self.live_checkpoint_op();
    let readable = if live == 0 {
      None
    } else {
      self.snapshots.get(&live).map(|snap| (live, snap.clone()))
    };
    // TRANSIENT checkpoint-read fault: rolled independently per read, so the proto's recover loop
    // clears it within budget. NEVER permanent — the live root always names a fully-written snapshot,
    // so a real `None` (no checkpoint rooted) is the only non-transient `Fault`.
    if readable.is_some()
      && self.faults.read_fault_per_mille > 0
      && self.prng.chance(self.faults.read_fault_per_mille, 1000)
    {
      self.completions.push_back(SuperblockDone::Fault(id));
      return;
    }
    // TRANSIENT corrupt-but-PARSEABLE checkpoint read: flip one trailing SM-tail byte of
    // the live snapshot. The bytes still DECODE and keep the leading bound op (the envelope is >= 12
    // bytes: op u64 + sessions_len u32, so the last byte is never the op), so a donor's `cr.op() ==
    // checkpoint_op` gate passes — but they now hash to a DIFFERENT id than the durable root. The proto
    // MUST reject these against the durable id (serve + recover) rather than restore corrupt SM/session
    // state. Rolled INDEPENDENTLY of the outright-fault roll above so both stay a pure function of the
    // per-replica seed; transient, so a re-read serves the clean bytes.
    let readable = match readable {
      Some((op, snap))
        if !snap.is_empty()
          && self.faults.corrupt_checkpoint_read_per_mille > 0
          && self
            .prng
            .chance(self.faults.corrupt_checkpoint_read_per_mille, 1000) =>
      {
        let mut bytes = snap.to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        Some((op, Bytes::from(bytes)))
      }
      other => other,
    };
    let done = match readable {
      Some((op, snap)) => {
        SuperblockDone::CheckpointRead(CheckpointRead::new(id, OpNumber::with(op), snap))
      }
      None => SuperblockDone::Fault(id),
    };
    self.completions.push_back(done);
  }

  fn poll(&mut self) -> Option<SuperblockDone> {
    // Async mode: tick the staged (in-flight) writes. A serial superblock writer completes them in
    // submission order, so we count down the FRONT entry and PUBLISH its effect when it reaches zero —
    // the new durable root, or the now-readable checkpoint snapshot. FIFO completion satisfies the
    // trait's root-write ordering contract (the LAST-submitted root wins once all complete). This is
    // the ONLY place a staged write becomes durable: until then `state()`/the readable checkpoint sit
    // at their prior values (the pending-durable-view window). A no-op in synchronous mode.
    if let Some((remaining, _)) = self.staged.front_mut() {
      if *remaining == 0 {
        let (_, write) = self.staged.pop_front().expect("front exists");
        let id = write.id();
        match write {
          // A root becoming durable publishes the new `state`; if it NAMES a written snapshot
          // generation, that generation becomes the live/readable checkpoint (served by
          // `submit_read_checkpoint` via `state.checkpoint_op()`). GC then trims strictly-older
          // generations — but only once `staged` has drained, so a later root that re-names an older
          // checkpoint (supersession) can still find its snapshot.
          StagedSbWrite::Root { state, .. } => {
            self.state = state;
            self.gc_snapshots();
          }
          // A checkpoint snapshot becoming durable lands in the store, but is NOT yet readable — it
          // becomes the live checkpoint only when a later ROOT names its op (above). Until then the
          // prior rooted generation stays the one `submit_read_checkpoint` serves.
          StagedSbWrite::Checkpoint { op, snapshot, .. } => {
            self.snapshots.insert(op.get(), snapshot);
          }
        }
        self.completions.push_back(SuperblockDone::Wrote(id));
      } else {
        *remaining -= 1;
      }
    }
    self.completions.pop_front()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use viewstamp_proto::{
    ClientId, Header, OpId, OpNumber, RequestNumber, Superblock, View, VsrState, Wal, WalDone,
  };

  #[test]
  fn append_then_read_round_trips() {
    let mut w = InMemoryWal::new();
    let h = Header::new(
      OpNumber::with(1),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(1),
      b"x",
    );
    w.submit_append(
      OpId::new(1),
      OpNumber::with(1),
      h,
      bytes::Bytes::from_static(b"x"),
    );
    assert_eq!(w.poll(), Some(WalDone::Appended(OpId::new(1))));
    assert_eq!(w.op_head(), OpNumber::with(1));
    assert_eq!(w.header(OpNumber::with(1)), Some(h));
    w.submit_read(OpId::new(2), OpNumber::with(1));
    match w.poll() {
      Some(WalDone::ReadOk(r)) => {
        assert_eq!(r.op(), OpNumber::with(1));
        assert_eq!(r.body(), b"x");
      }
      other => panic!("expected ReadOk, got {other:?}"),
    }
    w.submit_read(OpId::new(3), OpNumber::with(9));
    assert_eq!(w.poll(), Some(WalDone::Absent(OpId::new(3))));
  }

  #[test]
  fn truncate_and_prune() {
    let mut w = InMemoryWal::new();
    for op in 1..=5u64 {
      let h = Header::new(
        OpNumber::with(op),
        View::new(),
        ClientId::new(1),
        RequestNumber::with(op),
        b"x",
      );
      w.submit_append(
        OpId::new(op),
        OpNumber::with(op),
        h,
        bytes::Bytes::from_static(b"x"),
      );
      let _ = w.poll();
    }
    w.truncate(OpNumber::with(3));
    assert_eq!(w.op_head(), OpNumber::with(3));
    assert!(w.header(OpNumber::with(4)).is_none());
    w.prune(OpNumber::with(2));
    assert!(w.header(OpNumber::with(1)).is_none());
    assert!(w.header(OpNumber::with(2)).is_some());
  }

  #[test]
  fn superblock_write_reflects_in_state() {
    let mut sb = InMemorySuperblock::new();
    assert_eq!(sb.state(), VsrState::new());
    // Include canonical committed-band headers (ops 1..=3) so the vsr_headers round-trip through
    // submit_write/state() too (the superblock stores VsrState by value).
    let headers: std::vec::Vec<Header> = (1..=3)
      .map(|op| {
        Header::new(
          OpNumber::with(op),
          View::with(2),
          ClientId::new(1),
          RequestNumber::with(op),
          &[op as u8],
        )
      })
      .collect();
    let next = VsrState::try_new(
      View::with(2),
      View::with(2),
      OpNumber::with(3),
      OpNumber::with(0),
      0,
      headers,
    )
    .unwrap();
    sb.submit_write(OpId::new(1), next.clone());
    assert!(sb.poll().is_some());
    assert_eq!(sb.state(), next);
    assert_eq!(sb.state().committed_headers_slice().len(), 3);
  }

  /// Appends one entry `body` at `op` and drains the `Appended` completion.
  fn append(w: &mut InMemoryWal, op: u64, body: &'static [u8]) {
    let h = Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(1),
      RequestNumber::with(op),
      body,
    );
    w.submit_append(
      OpId::new(op),
      OpNumber::with(op),
      h,
      Bytes::from_static(body),
    );
    let _ = w.poll();
  }

  #[test]
  fn seeded_read_fault_is_deterministic_and_transient() {
    let mk = || {
      let mut w = InMemoryWal::with_faults(
        StorageFaults {
          read_fault_per_mille: 500,
          ..StorageFaults::none()
        },
        7,
      );
      append(&mut w, 1, b"x");
      w
    };
    let (mut a, mut b) = (mk(), mk());
    // Same seed ⇒ identical fault verdicts across two independent WALs; and a faulted read is
    // TRANSIENT (a later read of the same slot can succeed — verified by seeing both outcomes).
    let mut saw_fault = false;
    let mut saw_ok = false;
    for i in 0..40u64 {
      a.submit_read(OpId::new(i), OpNumber::with(1));
      b.submit_read(OpId::new(i), OpNumber::with(1));
      let fa = a.poll().unwrap().is_fault();
      let fb = b.poll().unwrap().is_fault();
      assert_eq!(fa, fb, "deterministic per seed");
      saw_fault |= fa;
      saw_ok |= !fa;
    }
    assert!(saw_fault, "read_fault_per_mille=500 must fault some reads");
    assert!(
      saw_ok,
      "a transient fault clears: some reads of the same slot succeed"
    );
  }

  #[test]
  fn read_faults_clear_within_the_proto_retry_budget() {
    // The load-bearing property for the transient-fault gate: a TRANSIENT read fault must clear within the
    // proto's RECOVER_READ_RETRIES (8) immediate retries — otherwise a recovering replica strands.
    // We model that exact budget (9 attempts per round) and assert a clean read is almost certain.
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        read_fault_per_mille: 80,
        ..StorageFaults::none()
      },
      1234,
    );
    append(&mut w, 1, b"payload");
    let mut stranded_rounds = 0;
    for round in 0..1000u64 {
      let mut cleared = false;
      for attempt in 0..9u64 {
        w.submit_read(OpId::new(round * 9 + attempt), OpNumber::with(1));
        if !w.poll().unwrap().is_fault() {
          cleared = true;
          break;
        }
      }
      if !cleared {
        stranded_rounds += 1;
      }
    }
    assert_eq!(
      stranded_rounds, 0,
      "a transient read fault (8%) must clear within the 9-attempt retry budget every round"
    );
  }

  #[test]
  fn bit_rot_makes_a_slot_permanently_body_faulty() {
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        bit_rot_per_mille: 1000,
        ..StorageFaults::none()
      },
      1,
    );
    append(&mut w, 1, b"x");
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Faulty,
      "bit-rotted slot is Faulty"
    );
    // The header is durable even when the body is permanently corrupt — the append wrote the
    // header successfully before the rot verdict fired.
    let stored_header = w
      .header(OpNumber::with(1))
      .expect("bit-rotted slot still has a durable header");
    assert_eq!(
      stored_header.op(),
      OpNumber::with(1),
      "the durable header carries the correct op"
    );
    // Every read of a bit-rotted slot yields BodyFaulty carrying the durable header, not a bare
    // Fault — the op is identified, only the body is unrecoverable from this replica.
    for i in 0..5u64 {
      w.submit_read(OpId::new(i), OpNumber::with(1));
      match w.poll() {
        Some(WalDone::BodyFaulty(bf)) => {
          assert_eq!(
            bf.header(),
            stored_header,
            "BodyFaulty carries the durable header"
          );
        }
        other => panic!("permanent bit-rot must yield BodyFaulty, got {other:?}"),
      }
    }
  }

  #[test]
  fn torn_write_yields_body_faulty_on_read() {
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        torn_write_per_mille: 1000,
        ..StorageFaults::none()
      },
      1,
    );
    append(&mut w, 1, b"intact");
    // A torn slot keeps its ORIGINAL header (the tear is latent — only the stored body bytes are
    // corrupt) and reports Clean. The header is fully durable and readable.
    assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
    let stored_header = w
      .header(OpNumber::with(1))
      .expect("torn slot still has its original durable header");
    assert_eq!(stored_header.op(), OpNumber::with(1));
    // A read of a torn slot yields BodyFaulty (header durable, body unverifiable) — not a bare
    // ReadOk with a corrupt body that the caller must re-check, and not a bare Fault that
    // discards the known-durable header.
    w.submit_read(OpId::new(2), OpNumber::with(1));
    match w.poll() {
      Some(WalDone::BodyFaulty(bf)) => {
        assert_eq!(
          bf.header(),
          stored_header,
          "BodyFaulty carries the durable original header"
        );
      }
      other => panic!("torn write must yield BodyFaulty, got {other:?}"),
    }
  }

  #[test]
  fn misdirected_read_returns_a_wrong_op_but_valid_entry() {
    // A misdirected read for op X returns a DIFFERENT present, valid slot's entry: the body
    // checksum-VERIFIES (it is a real op's body), so only the PLACEMENT check (`header.op() == X`)
    // catches it. We use a 1000-per-mille rate so it always fires, and several distinct durable slots
    // so a sibling exists.
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        misdirect_read_per_mille: 1000,
        ..StorageFaults::none()
      },
      7,
    );
    for op in 1..=4u64 {
      append(&mut w, op, b"body");
    }
    // Read op 2: every read is misdirected, so it returns SOME other op's (valid) entry, never op 2's.
    let mut saw_misdirect = false;
    for i in 0..20u64 {
      w.submit_read(OpId::new(100 + i), OpNumber::with(2));
      match w.poll() {
        Some(WalDone::ReadOk(r)) => {
          assert!(
            r.header().verify(r.body()),
            "a misdirected read still returns a CHECKSUM-CORRECT entry (only the op is wrong)"
          );
          assert_ne!(
            r.header().op(),
            OpNumber::with(2),
            "the misdirected entry is for a DIFFERENT op — the placement check (header.op() == op) \
             is exactly what must reject it"
          );
          saw_misdirect = true;
        }
        other => panic!("expected a (misdirected) ReadOk, got {other:?}"),
      }
    }
    assert!(
      saw_misdirect,
      "misdirect_read_per_mille=1000 must misdirect"
    );
  }

  #[test]
  fn misdirected_read_falls_through_when_no_sibling_exists() {
    // With only ONE durable slot there is no valid sibling to misdirect to, so the read is HONEST even
    // at a 1000-per-mille misdirect rate (a misdirect never fabricates an entry — it can only return a
    // real, different present slot, and there is none).
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        misdirect_read_per_mille: 1000,
        ..StorageFaults::none()
      },
      7,
    );
    append(&mut w, 1, b"only");
    for i in 0..10u64 {
      w.submit_read(OpId::new(i), OpNumber::with(1));
      match w.poll() {
        Some(WalDone::ReadOk(r)) => {
          assert_eq!(
            r.header().op(),
            OpNumber::with(1),
            "honest read of the sole slot"
          );
          assert_eq!(r.body(), b"only");
        }
        other => panic!("expected the honest ReadOk, got {other:?}"),
      }
    }
  }

  #[test]
  fn misdirected_read_is_deterministic_per_seed() {
    // Same seed + same plan ⇒ identical misdirect targets (the sibling pick uses the seeded PRNG).
    let run = || {
      let mut w = InMemoryWal::with_faults(
        StorageFaults {
          misdirect_read_per_mille: 500,
          ..StorageFaults::none()
        },
        1234,
      );
      for op in 1..=4u64 {
        append(&mut w, op, b"b");
      }
      let mut out = std::vec::Vec::new();
      for i in 0..30u64 {
        w.submit_read(OpId::new(i), OpNumber::with(2));
        match w.poll() {
          Some(WalDone::ReadOk(r)) => out.push(r.header().op().get()),
          Some(WalDone::Absent(_)) => out.push(0),
          other => panic!("unexpected {other:?}"),
        }
      }
      out
    };
    assert_eq!(
      run(),
      run(),
      "misdirected reads are a pure function of the seed"
    );
  }

  #[test]
  fn permanent_verdicts_survive_a_restart_via_the_persisted_struct() {
    // A bit-rotted slot stays rotted across a crash/restart because the WAL struct persists in the
    // Cluster (the `rotted` set lives in the struct). This is what makes the permanent-fault
    // gate meaningful; here we assert the struct-level persistence directly.
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        bit_rot_per_mille: 1000,
        ..StorageFaults::none()
      },
      9,
    );
    append(&mut w, 1, b"x");
    assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Faulty);
    // No "restart" resets the struct — the Cluster reuses the same `InMemoryWal`. Re-reading still
    // yields BodyFaulty (the rot verdict is permanent), proving the verdict is stable for the
    // lifetime of the durable medium.
    for i in 0..3u64 {
      w.submit_read(OpId::new(i), OpNumber::with(1));
      assert!(
        w.poll().unwrap().is_body_faulty(),
        "a permanently bit-rotted slot always yields BodyFaulty"
      );
    }
  }

  // ── Task-2 durable-header tests ──

  #[test]
  fn rotted_op_header_survives_and_read_yields_body_faulty() {
    // An appended-then-rotted op must keep its durable header (the header tuple in `entries` is
    // intact; only the body is unrecoverable from this replica). A read must yield BodyFaulty
    // carrying that header, not a bare Fault.
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        bit_rot_per_mille: 1000,
        ..StorageFaults::none()
      },
      42,
    );
    append(&mut w, 3, b"payload");
    // header() returns Some even for a rotted slot.
    let stored = w
      .header(OpNumber::with(3))
      .expect("rotted slot still has a durable header");
    assert_eq!(stored.op(), OpNumber::with(3));
    // A read yields BodyFaulty carrying the durable header.
    w.submit_read(OpId::new(1), OpNumber::with(3));
    match w.poll() {
      Some(WalDone::BodyFaulty(bf)) => {
        assert_eq!(bf.id(), OpId::new(1));
        assert_eq!(bf.header(), stored, "carries the durable header");
      }
      other => panic!("rotted slot must yield BodyFaulty, got {other:?}"),
    }
  }

  #[test]
  fn torn_op_header_survives_and_read_yields_body_faulty() {
    // An appended-then-torn op must keep its durable header (the tear only flips a body byte;
    // the stored header tuple in `entries` is the original intact header). A read must yield
    // BodyFaulty carrying that header.
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        torn_write_per_mille: 1000,
        ..StorageFaults::none()
      },
      42,
    );
    append(&mut w, 7, b"content");
    // header() returns Some for a torn slot (the tear is latent — only the body is corrupt).
    let stored = w
      .header(OpNumber::with(7))
      .expect("torn slot still has its original durable header");
    assert_eq!(stored.op(), OpNumber::with(7));
    // A read yields BodyFaulty carrying the durable header.
    w.submit_read(OpId::new(1), OpNumber::with(7));
    match w.poll() {
      Some(WalDone::BodyFaulty(bf)) => {
        assert_eq!(bf.id(), OpId::new(1));
        assert_eq!(bf.header(), stored, "carries the original durable header");
      }
      other => panic!("torn slot must yield BodyFaulty, got {other:?}"),
    }
  }

  #[test]
  fn torn_header_slot_vanishes_entirely() {
    // The torn-header contract-violation probe: a completed append whose verdict fired retains NO
    // recoverable header — `header()` is None, `status()` is Empty, a read is Absent — exactly the
    // shape the `Wal` header-durability contract forbids a real backend from producing. The append
    // COMPLETED normally (`Appended` fired), so the proto acked it believing it durable.
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        torn_header_per_mille: 1000,
        ..StorageFaults::none()
      },
      42,
    );
    append(&mut w, 5, b"gone");
    assert_eq!(w.torn_headers_fired(), 1, "the verdict fired");
    assert!(
      w.header(OpNumber::with(5)).is_none(),
      "a torn-header slot has NO recoverable header"
    );
    assert_eq!(
      w.status(OpNumber::with(5)),
      SlotStatus::Empty,
      "a torn-header slot reports Empty — as if never written"
    );
    w.submit_read(OpId::new(1), OpNumber::with(5));
    assert_eq!(
      w.poll(),
      Some(WalDone::Absent(OpId::new(1))),
      "a read of a torn-header slot is Absent"
    );
    // Truncating the slot away clears the verdict with it (no ghost entry under a gone op).
    w.truncate(OpNumber::with(0));
    assert_eq!(w.status(OpNumber::with(5)), SlotStatus::Empty);
    assert_eq!(
      w.torn_headers_fired(),
      1,
      "the witness counter is cumulative"
    );
  }

  #[test]
  fn never_appended_op_yields_absent() {
    // An op that was never durably appended (not in `entries`) must yield Absent on a read —
    // not BodyFaulty (there is no durable header to carry) and not Fault.
    let mut w = InMemoryWal::new();
    // Append op 1 to keep the WAL non-empty; op 99 was never appended.
    append(&mut w, 1, b"x");
    assert!(
      w.header(OpNumber::with(99)).is_none(),
      "a never-appended op has no durable header"
    );
    w.submit_read(OpId::new(5), OpNumber::with(99));
    assert_eq!(
      w.poll(),
      Some(WalDone::Absent(OpId::new(5))),
      "a never-appended op yields Absent, not BodyFaulty"
    );
  }

  /// A durable VSR root naming `checkpoint_op` (with a matching `commit >= checkpoint_op` and no
  /// committed-band headers) — the proto's step-2 root that makes a just-written snapshot the live
  /// checkpoint. Used by the two-slot superblock tests to ROOT a snapshot the way `recover` expects.
  fn root_naming_checkpoint(checkpoint_op: u64) -> VsrState {
    VsrState::try_new(
      View::new(),
      View::new(),
      OpNumber::with(checkpoint_op),
      OpNumber::with(checkpoint_op),
      // A non-zero checkpoint id; the exact value is irrelevant to these storage-level tests (the
      // proto's id cross-check lives above this layer).
      0x1234,
      std::vec::Vec::new(),
    )
    .expect("commit == checkpoint_op and log_view <= view")
  }

  /// Pump an async-mode superblock until its staged writes have all become durable and all `Wrote`
  /// completions are consumed (bounded). Used by the supersession test to land each staged root/
  /// snapshot in FIFO order.
  fn drain(sb: &mut InMemorySuperblock) {
    for _ in 0..256 {
      let had = sb.poll().is_some();
      if !had && sb.staged_len() == 0 {
        return;
      }
    }
    panic!("superblock did not drain within the bound");
  }

  /// Sync-mode: write a checkpoint snapshot at `op` AND its durable root, so the snapshot becomes the
  /// live/readable checkpoint (the full proto two-step sequence). Drains both `Wrote` completions.
  fn write_rooted_checkpoint(sb: &mut InMemorySuperblock, op: u64, snap: &'static [u8]) {
    sb.submit_write_checkpoint(
      OpId::new(900 + op),
      OpNumber::with(op),
      Bytes::from_static(snap),
    );
    let _ = sb.poll();
    sb.submit_write(OpId::new(800 + op), root_naming_checkpoint(op));
    let _ = sb.poll();
  }

  #[test]
  fn superblock_checkpoint_read_fault_is_transient() {
    use viewstamp_proto::SuperblockDone;
    let mut sb = InMemorySuperblock::with_faults(
      StorageFaults {
        read_fault_per_mille: 500,
        ..StorageFaults::none()
      },
      3,
    );
    // Write AND root a checkpoint (the proto two-step sequence) so reads have a live, readable
    // checkpoint to (transiently) fault on.
    write_rooted_checkpoint(&mut sb, 4, b"snap");
    let mut saw_fault = false;
    let mut saw_read = false;
    for i in 1..40u64 {
      sb.submit_read_checkpoint(OpId::new(i));
      match sb.poll().unwrap() {
        SuperblockDone::Fault(_) => saw_fault = true,
        SuperblockDone::CheckpointRead(cr) => {
          assert_eq!(cr.op(), OpNumber::with(4));
          saw_read = true;
        }
        other => panic!("unexpected superblock completion: {other:?}"),
      }
    }
    assert!(saw_fault, "checkpoint reads must transiently fault");
    assert!(
      saw_read,
      "a transient checkpoint fault clears: some reads succeed"
    );
  }

  #[test]
  fn superblock_corrupt_checkpoint_read_returns_parseable_but_altered_bytes() {
    use viewstamp_proto::SuperblockDone;
    // the corrupt-checkpoint-read fault returns a `CheckpointRead` for the RIGHT op whose
    // bytes are the live snapshot with one trailing byte flipped — still a `CheckpointRead` (parseable),
    // but NOT byte-identical to the written snapshot, so it hashes to a different checkpoint id. Proven
    // TRANSIENT: across many reads some return the GENUINE bytes (a re-read serves the clean snapshot).
    let mut sb = InMemorySuperblock::with_faults(
      StorageFaults {
        corrupt_checkpoint_read_per_mille: 500,
        ..StorageFaults::none()
      },
      3,
    );
    let genuine: &[u8] = b"a-genuine-checkpoint-snapshot";
    write_rooted_checkpoint(&mut sb, 4, b"a-genuine-checkpoint-snapshot");
    let mut saw_corrupt = false;
    let mut saw_genuine = false;
    for i in 1..64u64 {
      sb.submit_read_checkpoint(OpId::new(i));
      match sb.poll().unwrap() {
        SuperblockDone::CheckpointRead(cr) => {
          assert_eq!(
            cr.op(),
            OpNumber::with(4),
            "the corrupt read keeps its bound op"
          );
          assert_eq!(
            cr.snapshot().len(),
            genuine.len(),
            "the fault flips a byte in place, never changes the length",
          );
          if cr.snapshot() == genuine {
            saw_genuine = true;
          } else {
            // Differs from the written bytes ⇒ a different content hash, but still a CheckpointRead.
            assert_ne!(
              viewstamp_proto::checkpoint_id(cr.snapshot()),
              viewstamp_proto::checkpoint_id(genuine),
              "corrupt bytes hash to a DIFFERENT id than the genuine snapshot",
            );
            saw_corrupt = true;
          }
        }
        other => panic!("unexpected superblock completion: {other:?}"),
      }
    }
    assert!(saw_corrupt, "the corrupt-checkpoint-read fault must fire");
    assert!(
      saw_genuine,
      "the fault is transient: some reads return the genuine snapshot"
    );
  }

  /// Reads the live checkpoint synchronously (no faults), asserting it is a `CheckpointRead` and
  /// returning its `(op, body)`; panics on a `Fault`/unexpected completion.
  fn read_live_checkpoint(sb: &mut InMemorySuperblock) -> (u64, Vec<u8>) {
    use viewstamp_proto::SuperblockDone;
    sb.submit_read_checkpoint(OpId::new(7777));
    match sb.poll() {
      Some(SuperblockDone::CheckpointRead(cr)) => (cr.op().get(), cr.snapshot().to_vec()),
      other => panic!("expected a live CheckpointRead, got {other:?}"),
    }
  }

  #[test]
  fn checkpoint_unreadable_until_a_root_names_it() {
    use viewstamp_proto::SuperblockDone;
    // A written-but-unrooted snapshot is NOT yet the live checkpoint (redundant-copy model, finding B):
    // the durable root is the authority for which generation is readable.
    let mut sb = InMemorySuperblock::new();
    // No checkpoint at all → read faults (the no-checkpoint case).
    sb.submit_read_checkpoint(OpId::new(1));
    assert!(matches!(sb.poll(), Some(SuperblockDone::Fault(_))));
    // Write a snapshot at op 4 but do NOT root it → still no live checkpoint.
    sb.submit_write_checkpoint(
      OpId::new(2),
      OpNumber::with(4),
      Bytes::from_static(b"snap4"),
    );
    let _ = sb.poll();
    sb.submit_read_checkpoint(OpId::new(3));
    assert!(
      matches!(sb.poll(), Some(SuperblockDone::Fault(_))),
      "an unrooted snapshot is not yet readable"
    );
    // Now write the durable root naming op 4 → the snapshot becomes the live, readable checkpoint.
    sb.submit_write(OpId::new(4), root_naming_checkpoint(4));
    let _ = sb.poll();
    assert_eq!(read_live_checkpoint(&mut sb), (4, b"snap4".to_vec()));
  }

  #[test]
  fn orphaned_checkpoint_restores_the_last_rooted_snapshot() {
    // THE finding-B case. Root a checkpoint at op 4; then write a NEWER snapshot at op 8 whose ROOT
    // never lands (orphaned — e.g. the checkpoint was abandoned, or a crash interrupted its root). A
    // faithful redundant-copy backend must still serve the last-ROOTED snapshot (op 4) — NOT the
    // orphaned op-8 bytes — so recover restores from its own disk (`cr.op() == state.checkpoint_op()`)
    // instead of escalating to a spurious peer fetch.
    let mut sb = InMemorySuperblock::new();
    write_rooted_checkpoint(&mut sb, 4, b"snap4");
    assert_eq!(read_live_checkpoint(&mut sb), (4, b"snap4".to_vec()));
    // A newer snapshot lands but its root never does.
    sb.submit_write_checkpoint(
      OpId::new(50),
      OpNumber::with(8),
      Bytes::from_static(b"snap8"),
    );
    let _ = sb.poll();
    // The live checkpoint is STILL the rooted op-4 snapshot (the durable root still names op 4), and
    // crucially its op MATCHES what `state().checkpoint_op()` reports — so recover's placement check
    // (`cr.op() == state.checkpoint_op()`) passes and it restores locally.
    assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
    assert_eq!(read_live_checkpoint(&mut sb), (4, b"snap4".to_vec()));
  }

  #[test]
  fn crash_discards_a_staged_but_unrooted_snapshot_keeping_the_rooted_one() {
    // A crash (`discard_inflight`) drops a staged-but-unrooted snapshot, keeping the last-rooted one
    // readable — the redundant-copy crash semantics (finding B).
    let mut sb = InMemorySuperblock::new();
    write_rooted_checkpoint(&mut sb, 4, b"snap4");
    // A newer snapshot lands (root not yet written).
    sb.submit_write_checkpoint(
      OpId::new(50),
      OpNumber::with(8),
      Bytes::from_static(b"snap8"),
    );
    let _ = sb.poll();
    // Crash: the unrooted op-8 snapshot is lost; the rooted op-4 one survives, readable and matching
    // the durable root.
    sb.discard_inflight();
    assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
    assert_eq!(read_live_checkpoint(&mut sb), (4, b"snap4".to_vec()));
    // A subsequent root that DOES name op 8 cannot resurrect the discarded snapshot — it was lost.
    sb.submit_write(OpId::new(60), root_naming_checkpoint(8));
    let _ = sb.poll();
    use viewstamp_proto::SuperblockDone;
    sb.submit_read_checkpoint(OpId::new(61));
    assert!(
      matches!(sb.poll(), Some(SuperblockDone::Fault(_))),
      "the discarded op-8 snapshot is gone; naming it leaves no readable snapshot"
    );
  }

  #[test]
  fn supersession_keeps_the_older_rooted_snapshot_readable() {
    // The serialized-root-ordering supersession (the proto's `submit_durable_view` comment): a
    // checkpoint's step-2 root (naming the NEW op) is left in flight when a view change issues a
    // durable-view root naming the OLD checkpoint; FIFO completes the new-op root FIRST but the later
    // old-op root supersedes it. The live checkpoint must end up the OLD one, and its snapshot must
    // still be readable (not GC'd by the transient new-op-rooted window). Async mode to stage both.
    let mut sb = InMemorySuperblock::with_async_writes_and_faults(StorageFaults::none(), 1, 1);
    // Establish a rooted checkpoint at op 4 first (drain fully).
    sb.submit_write_checkpoint(
      OpId::new(1),
      OpNumber::with(4),
      Bytes::from_static(b"snap4"),
    );
    drain(&mut sb);
    sb.submit_write(OpId::new(2), root_naming_checkpoint(4));
    drain(&mut sb);
    assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
    // A new checkpoint at op 8: snapshot written + its step-2 root staged...
    sb.submit_write_checkpoint(
      OpId::new(3),
      OpNumber::with(8),
      Bytes::from_static(b"snap8"),
    );
    drain(&mut sb); // snapshot durable; op-8 root not yet submitted
    sb.submit_write(OpId::new(4), root_naming_checkpoint(8)); // step-2 root for op 8 (staged)
    // ...then a view change supersedes it with a durable-view root naming the OLD op 4 (staged AFTER).
    sb.submit_write(OpId::new(5), root_naming_checkpoint(4));
    drain(&mut sb);
    // The FINAL durable root names op 4 (supersession), and the op-4 snapshot is STILL readable.
    assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
    assert_eq!(read_live_checkpoint(&mut sb), (4, b"snap4".to_vec()));
  }

  #[test]
  fn no_faults_is_byte_for_byte_reliable() {
    // StorageFaults::none() must reproduce the old reliable behaviour exactly.
    let mut w = InMemoryWal::with_faults(StorageFaults::none(), 42);
    append(&mut w, 1, b"intact");
    assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
    for i in 0..10u64 {
      w.submit_read(OpId::new(i), OpNumber::with(1));
      match w.poll() {
        Some(WalDone::ReadOk(r)) => assert!(r.header().verify(r.body())),
        other => panic!("no-faults WAL must always ReadOk a present slot, got {other:?}"),
      }
    }
  }

  /// Submits (does NOT poll) an append at `op`, returning its `OpId` — for async-mode tests that must
  /// observe the staged (in-flight) state before completion.
  fn submit(w: &mut InMemoryWal, id: u64, op: u64, body: &'static [u8]) -> OpId {
    let h = Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(1),
      RequestNumber::with(op),
      body,
    );
    let oid = OpId::new(id);
    w.submit_append(oid, OpNumber::with(op), h, Bytes::from_static(body));
    oid
  }

  #[test]
  fn async_append_stays_dirty_until_the_delay_elapses_then_becomes_durable() {
    // The core async-mode primitive: a submitted append is NOT durable for `delay`
    // polls — `status` is Dirty (never Clean), `op_head` does not count it, a read returns Absent, and
    // `poll` yields no Appended — then exactly at the delay it becomes durable and `poll` yields it.
    let mut w = InMemoryWal::with_async_appends(3);
    let id = submit(&mut w, 1, 1, b"x");
    assert_eq!(w.staged_len(), 1, "the append is staged, not yet durable");

    // While in flight, the non-ticking inspectors (status/op_head/header) all report not-durable, and
    // a read returns Absent. Verify the read FIRST (one poll for it — which also ticks 3→2).
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Dirty,
      "in-flight: Dirty"
    );
    assert_eq!(
      w.op_head(),
      OpNumber::with(0),
      "op_head ignores an in-flight slot"
    );
    assert!(
      w.header(OpNumber::with(1)).is_none(),
      "no readable header in flight"
    );
    w.submit_read(OpId::new(100), OpNumber::with(1));
    assert!(
      matches!(w.poll(), Some(WalDone::Absent(_))),
      "a read of a staged slot returns Absent"
    );
    // `delay` was 3; one poll above ticked it to 2. Two more polls reach 0 WITHOUT releasing.
    assert_eq!(
      w.poll(),
      None,
      "still in flight (remaining 2→1): no Appended"
    );
    assert_eq!(
      w.poll(),
      None,
      "still in flight (remaining 1→0): no Appended"
    );
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Dirty,
      "still Dirty at the boundary"
    );
    assert_eq!(w.staged_len(), 1, "still staged until the release poll");
    // The next poll (remaining == 0) releases the append: it becomes durable and yields its Appended.
    assert_eq!(
      w.poll(),
      Some(WalDone::Appended(id)),
      "the staged append becomes durable and yields its Appended"
    );
    assert_eq!(w.staged_len(), 0, "the staging queue drained");
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Clean,
      "now durable"
    );
    assert_eq!(w.op_head(), OpNumber::with(1));
    w.submit_read(OpId::new(200), OpNumber::with(1));
    match w.poll() {
      Some(WalDone::ReadOk(r)) => {
        assert_eq!(r.op(), OpNumber::with(1));
        assert!(r.header().verify(r.body()));
      }
      other => panic!("a durable slot reads back ReadOk, got {other:?}"),
    }
  }

  #[test]
  fn async_delay_zero_still_defers_to_the_next_poll_never_inline() {
    // `delay == 0` must NOT complete inline in `submit_append` (that would be the synchronous path):
    // the in-flight window must exist for at least the gap until the next poll.
    let mut w = InMemoryWal::with_async_appends(0);
    let id = submit(&mut w, 1, 1, b"x");
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Dirty,
      "delay=0 is still staged at submit time (not inline-durable)"
    );
    assert_eq!(
      w.poll(),
      Some(WalDone::Appended(id)),
      "released on next poll"
    );
    assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
  }

  #[test]
  fn async_appends_complete_in_submission_order() {
    // A serial WAL writer: staged appends become durable FIFO. With delay=1, op1 releases, then op2.
    let mut w = InMemoryWal::with_async_appends(1);
    let id1 = submit(&mut w, 1, 1, b"a");
    let id2 = submit(&mut w, 2, 2, b"b");
    assert_eq!(w.staged_len(), 2);
    assert_eq!(
      w.poll(),
      None,
      "tick 1: op1 counts down from 1, nothing ready yet"
    );
    assert_eq!(w.poll(), Some(WalDone::Appended(id1)), "op1 durable first");
    assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
    assert_eq!(
      w.status(OpNumber::with(2)),
      SlotStatus::Dirty,
      "op2 still in flight while op1's window closed"
    );
    assert_eq!(w.poll(), None, "op2 counts down from 1");
    assert_eq!(w.poll(), Some(WalDone::Appended(id2)), "op2 durable second");
    assert_eq!(w.op_head(), OpNumber::with(2));
  }

  #[test]
  fn async_mode_composes_with_a_torn_write() {
    // The torn-write verdict is taken at SUBMIT and applied on COMPLETION: while staged the slot is
    // Dirty; once durable it carries the original header but a corrupt body (fails proto verify).
    let mut w = InMemoryWal::with_async_appends_and_faults(
      StorageFaults {
        torn_write_per_mille: 1000,
        ..StorageFaults::none()
      },
      1,
      2,
    );
    submit(&mut w, 1, 1, b"intact");
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Dirty,
      "staged: Dirty regardless of the (already-decided) torn verdict"
    );
    // Tick past the delay (delay=2 → 2 countdown polls, then release).
    assert_eq!(w.poll(), None);
    assert_eq!(w.poll(), None);
    assert_eq!(w.poll(), Some(WalDone::Appended(OpId::new(1))));
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Clean,
      "a torn slot is Clean (latent tear) once durable"
    );
    w.submit_read(OpId::new(9), OpNumber::with(1));
    match w.poll() {
      Some(WalDone::BodyFaulty(bf)) => {
        assert_eq!(
          bf.header().op(),
          OpNumber::with(1),
          "BodyFaulty carries the durable header for the async torn write"
        );
      }
      other => panic!("expected BodyFaulty for a durable torn slot, got {other:?}"),
    }
  }

  #[test]
  fn sync_mode_is_the_default_and_unchanged() {
    // The default constructors must NOT stage: an append is durable inline (existing-gate behaviour).
    for mut w in [
      InMemoryWal::new(),
      InMemoryWal::with_faults(StorageFaults::none(), 7),
    ] {
      let id = submit(&mut w, 1, 1, b"x");
      assert_eq!(w.staged_len(), 0, "default mode never stages");
      assert_eq!(
        w.status(OpNumber::with(1)),
        SlotStatus::Clean,
        "default append is durable inline"
      );
      assert_eq!(w.op_head(), OpNumber::with(1));
      assert_eq!(w.poll(), Some(WalDone::Appended(id)));
    }
  }

  #[test]
  fn discard_inflight_drops_staged_appends_but_keeps_durable_entries() {
    // The faithful fsync-loss-on-crash model: a crash drops every STAGED (not-yet-durable) append
    // WITHOUT ever letting it become durable, while the already-durable log survives untouched.
    let mut w = InMemoryWal::with_async_appends(3);
    // op1 is appended and fully released → durable; op2 is submitted but still in flight.
    let id1 = submit(&mut w, 1, 1, b"a");
    // Release op1 (delay 3 → tick 3,2,1,0 then the release poll yields Appended).
    for _ in 0..3 {
      assert_eq!(w.poll(), None);
    }
    assert_eq!(
      w.poll(),
      Some(WalDone::Appended(id1)),
      "op1 becomes durable"
    );
    assert_eq!(w.op_head(), OpNumber::with(1));
    let _id2 = submit(&mut w, 2, 2, b"b");
    assert_eq!(w.staged_len(), 1, "op2 is staged, in flight");
    assert_eq!(w.status(OpNumber::with(2)), SlotStatus::Dirty);

    // Crash: discard the in-flight op2. The durable op1 stays; op2 is GONE and never resurfaces.
    w.discard_inflight();
    assert_eq!(w.staged_len(), 0, "the in-flight append was discarded");
    assert_eq!(
      w.op_head(),
      OpNumber::with(1),
      "head sits at the last DURABLE op — the lost in-flight write never advanced it"
    );
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Clean,
      "the durable op survives the crash"
    );
    assert_eq!(
      w.status(OpNumber::with(2)),
      SlotStatus::Empty,
      "the lost in-flight op leaves no slot behind"
    );
    // A post-crash poll never resurrects op2 as durable (no stale `Appended` after recovery).
    for _ in 0..8 {
      assert_eq!(w.poll(), None, "no staged append resurfaces post-discard");
    }
    assert_eq!(w.op_head(), OpNumber::with(1));
    // op1 still reads back intact.
    w.submit_read(OpId::new(99), OpNumber::with(1));
    assert!(matches!(w.poll(), Some(WalDone::ReadOk(_))));
  }

  #[test]
  fn discard_inflight_is_a_noop_in_sync_mode() {
    // Synchronous mode never stages, so a crash-time discard is a harmless no-op (durable log intact).
    let mut w = InMemoryWal::new();
    let id = submit(&mut w, 1, 1, b"x");
    assert_eq!(w.poll(), Some(WalDone::Appended(id)));
    w.discard_inflight();
    assert_eq!(w.op_head(), OpNumber::with(1), "sync durable op untouched");
    assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
  }

  #[test]
  fn bounded_capacity_reports_the_ring_size() {
    // The unbounded default reports u64::MAX (the proto's stall never engages); a bounded ring reports
    // its slot count n (the stall engages against it).
    assert_eq!(InMemoryWal::new().capacity(), u64::MAX);
    assert_eq!(InMemoryWal::with_capacity(3).capacity(), 3);
    assert_eq!(InMemoryWal::with_capacity(12).capacity(), 12);
  }

  #[test]
  fn bounded_ring_append_wraps_and_a_wrapped_over_op_reads_absent() {
    // The core ring semantics: op K lands in slot K mod n, so an append at K physically OVERWRITES the
    // op that last held that slot (op K-n). A read of the wrapped-over op then returns Absent (its
    // bytes are gone — a clean wrap), while the op currently resident in the slot reads back.
    let mut w = InMemoryWal::with_capacity(3); // slots {0,1,2}
    for op in 1..=3u64 {
      append(&mut w, op, b"v");
    }
    // All three residents are present; the head is the highest op.
    assert_eq!(w.op_head(), OpNumber::with(3));
    for op in 1..=3u64 {
      assert_eq!(w.status(OpNumber::with(op)), SlotStatus::Clean);
      assert!(w.header(OpNumber::with(op)).is_some());
    }
    // Append op 4 → slot 4 mod 3 == 1 == op 1's slot: op 1 is physically overwritten by op 4.
    append(&mut w, 4, b"v");
    assert_eq!(w.op_head(), OpNumber::with(4));
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Empty,
      "op 1 was wrapped over by op 4 (same ring slot) — its slot no longer holds it"
    );
    assert!(
      w.header(OpNumber::with(1)).is_none(),
      "a wrapped-over op has no resident header"
    );
    w.submit_read(OpId::new(100), OpNumber::with(1));
    assert!(
      matches!(w.poll(), Some(WalDone::Absent(_))),
      "a read of the wrapped-over op is Absent (a clean wrap; its bytes are gone)"
    );
    // op 4 (the new occupant of slot 1) and the untouched residents (ops 2, 3) read back intact.
    for op in [2u64, 3, 4] {
      assert_eq!(w.status(OpNumber::with(op)), SlotStatus::Clean);
      w.submit_read(OpId::new(200 + op), OpNumber::with(op));
      match w.poll() {
        Some(WalDone::ReadOk(r)) => assert_eq!(r.op(), OpNumber::with(op)),
        other => panic!("op {op} should read back ReadOk, got {other:?}"),
      }
    }
  }

  #[test]
  fn bounded_ring_eviction_clears_a_wrapped_bit_rot_verdict() {
    // Overwriting a bit-rotted ring slot physically rewrites the media, so the OLD op's permanent rot
    // verdict is cleared from the WAL (it leaves `rotted`): op 1 is rotted, then op 4 (same slot in an
    // n=3 ring) wraps over it. op 1 must read `Empty`, NOT `Faulty` — proving the eviction dropped its
    // rot entry rather than leaving a ghost verdict under a wrapped-away op number.
    let mut w = InMemoryWal::with_capacity_faults(
      3,
      StorageFaults {
        bit_rot_per_mille: 1000, // every append here rots its slot (we only need op 1's, for the wrap)
        ..StorageFaults::none()
      },
      1,
    );
    append(&mut w, 1, b"x");
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Faulty,
      "op 1 rotted"
    );
    // Append ops 2, 3 (distinct slots), then op 4 wraps over op 1's slot (4 mod 3 == 1).
    append(&mut w, 2, b"x");
    append(&mut w, 3, b"x");
    append(&mut w, 4, b"x");
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Empty,
      "op 1 (rotted) was physically overwritten by op 4 → no longer resident, and its rot verdict cleared"
    );
    // op 4 is the new resident of the slot (its OWN append-time verdict applies, not op 1's stale one).
    assert_ne!(
      w.status(OpNumber::with(4)),
      SlotStatus::Empty,
      "op 4 is the new resident of the slot"
    );
  }

  #[test]
  fn bounded_ring_prune_and_truncate_work_on_the_resident_set() {
    // GC/view-change ops operate on the currently-resident ring ops exactly as in unbounded mode.
    let mut w = InMemoryWal::with_capacity(8);
    for op in 1..=5u64 {
      append(&mut w, op, b"v");
    }
    w.truncate(OpNumber::with(3));
    assert_eq!(w.op_head(), OpNumber::with(3));
    assert!(w.header(OpNumber::with(4)).is_none());
    w.prune(OpNumber::with(2));
    assert!(w.header(OpNumber::with(1)).is_none());
    assert!(w.header(OpNumber::with(2)).is_some());
    assert!(w.header(OpNumber::with(3)).is_some());
  }

  #[test]
  fn bounded_ring_composes_with_async_appends() {
    // A bounded ring in async-append mode: the physical write (and thus the wrap-eviction) happens on
    // RELEASE, not at submit. An n=2 ring; op 1 then op 3 share slot 1. Stage + release op 1, then op 3
    // overwrites it on release. `set_capacity` makes an EMPTY async WAL bounded (exercising the setter).
    let mut w = InMemoryWal::with_async_appends(0);
    w.set_capacity(Some(2));
    let id1 = submit(&mut w, 1, 1, b"a");
    assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Dirty, "staged");
    assert_eq!(w.poll(), Some(WalDone::Appended(id1)), "op 1 durable");
    assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
    // op 3 shares op 1's slot (3 mod 2 == 1). Stage + release it → it overwrites op 1 on release.
    let id3 = submit(&mut w, 3, 3, b"c");
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Clean,
      "op 1 still resident while op 3 is only STAGED (physical write deferred to release)"
    );
    assert_eq!(w.poll(), Some(WalDone::Appended(id3)), "op 3 durable");
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Empty,
      "op 3's release physically overwrote op 1's slot"
    );
    assert_eq!(w.status(OpNumber::with(3)), SlotStatus::Clean);
    assert_eq!(w.op_head(), OpNumber::with(3));
  }
}

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
  BodyFaulty, CheckpointRead, Header, OpNumber, Prng, ReadId, ReadOk, SlotStatus, Superblock,
  SuperblockDone, VsrState, Wal, WalDone, WriteId, checkpoint_id,
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
  id: WriteId,
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
  /// `None` (default) ⇒ ORDERED writes: the staged queue releases FIFO (front-only) and
  /// `truncate`/`prune` synchronously CANCEL the staged appends they trim (reporting their ids). Both
  /// behaviours stay byte-identical to every existing gate. `Some(prng)` ⇒ **WRITE-CHAOS mode**
  /// ([`set_write_chaos`](InMemoryWal::set_write_chaos)): a proactor whose submitted writes are already
  /// at the device — every append stages with a seeded JITTERED delay, `poll` ticks ALL staged entries
  /// and lands a seeded choice among the READY ones (completions genuinely reorder relative to
  /// submission), and `truncate`/`prune` KEEP every staged append (un-cancellable device writes that
  /// land late — the resurrection/eviction shape the endpoint's slot-quiescence fence must survive)
  /// and report nothing cancelled.
  write_chaos: Option<Prng>,
  /// Observability: how many chaos-mode releases landed an entry that was NOT the oldest staged one —
  /// a completion genuinely delivered out of submission order. `> 0` proves the write-chaos axis
  /// actually REORDERED completions (the fence was exercised), not merely staged them FIFO. Persists
  /// across `restart` because the WAL struct does.
  chaos_reorders_fired: u64,
  /// The medium's own record of who last wrote each durable slot: op → the ENDPOINT INCARNATION
  /// carried by the write whose landing last populated `entries` for that op. Endpoint incarnations
  /// are minted from a process-monotone counter, so ordering two writers is a plain comparison: a
  /// landing that carries a LOWER incarnation than the slot's recorded holder is an OLDER writer's
  /// bytes physically evicting content a NEWER writer already landed — the stale-landing shape the
  /// endpoint's slot-quiescence fence exists to make impossible, including across endpoint rebuilds
  /// over this same live WAL. Trimmed wherever `entries` is (truncate / prune / ring eviction), and
  /// deliberately KEPT across `crash`/`restart` (the durable content it describes survives too).
  landed_by: BTreeMap<u64, u64>,
  /// The first stale landing observed (see [`InMemoryWal::landed_by`]): the op plus a description of
  /// the eviction — which incarnations collided and what identity each header carried. Held until
  /// drained ([`take_stale_landing`](Self::take_stale_landing)); later stale landings only advance
  /// the counter.
  stale_landing: Option<(u64, String)>,
  /// How many stale landings occurred since construction. `> 0` is the non-vacuity witness that an
  /// older incarnation's write genuinely landed over a newer incarnation's durable slot content.
  stale_landings_fired: u64,
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
      write_chaos: None,
      chaos_reorders_fired: 0,
      landed_by: BTreeMap::new(),
      stale_landing: None,
      stale_landings_fired: 0,
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

  /// Test/harness helper: enable (`Some(seed)`) or disable (`None`) **write-chaos mode** on an EMPTY
  /// WAL, preserving the existing fault plan / async / ring modes. In chaos mode every
  /// `submit_append` STAGES with a seeded jittered delay, `poll` releases a seeded choice among the
  /// READY staged entries (so append completions genuinely reorder relative to submission), and
  /// `truncate`/`prune` KEEP staged entries — un-cancellable writes already at the device, which land
  /// late into the trimmed region (the resurrection/eviction shape the endpoint's slot-quiescence
  /// fence defers conflicting re-appends around) — reporting nothing cancelled. The `None` default
  /// keeps the FIFO + synchronously-cancelling behaviour byte-identical for every existing gate.
  /// Panics if called on a non-empty WAL (mirrors [`set_capacity`](Self::set_capacity)).
  pub fn set_write_chaos(&mut self, seed: Option<u64>) {
    assert!(
      self.entries.is_empty() && self.staged.is_empty(),
      "set_write_chaos must be called on an empty WAL"
    );
    self.write_chaos = seed.map(Prng::new);
  }

  /// Test-only: how many chaos-mode releases landed a staged append that was NOT the oldest one — a
  /// completion genuinely delivered out of submission order. `> 0` proves the write-chaos axis
  /// actually reordered completions rather than merely staging them FIFO. Persists across `restart`
  /// because the WAL struct does.
  #[doc(hidden)]
  pub fn chaos_reorders_fired(&self) -> u64 {
    self.chaos_reorders_fired
  }

  /// Test-only: drain the first recorded STALE LANDING — `(op, description)` of a write minted by an
  /// OLDER endpoint incarnation landing over durable slot content a NEWER incarnation had already
  /// landed (see [`InMemoryWal::landed_by`]). `None` when none has occurred since the last drain.
  #[doc(hidden)]
  pub fn take_stale_landing(&mut self) -> Option<(u64, String)> {
    self.stale_landing.take()
  }

  /// Test-only: how many stale landings occurred since construction (every older-over-newer slot
  /// eviction, not only the first). Persists across `restart` because the WAL struct does.
  #[doc(hidden)]
  pub fn stale_landings_fired(&self) -> u64 {
    self.stale_landings_fired
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
  /// requesting read's `ReadId` (so `header.op() != op` — the placement violation the proto's recovery
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
    self.landed_by.retain(|&o, _| o == op || o % n != slot);
  }

  /// Record a physical landing at `op` by the write `id`, checking it against the slot's current
  /// holder ([`InMemoryWal::landed_by`]): a landing whose incarnation is LOWER than the holder's is
  /// an older writer's bytes evicting content a newer writer already landed — recorded as a stale
  /// landing for [`take_stale_landing`](Self::take_stale_landing) to drain. Called at the one moment
  /// a write reaches `entries`, in both the synchronous and the staged paths, BEFORE the insert (so
  /// the evicted header is still readable for the description).
  fn note_landing(&mut self, op: u64, id: WriteId, header: &Header) {
    if let Some(&holder) = self.landed_by.get(&op)
      && id.incarnation() < holder
    {
      self.stale_landings_fired += 1;
      if self.stale_landing.is_none() {
        let evicted = self.entries.get(&op).map(|(h, _)| {
          format!(
            "(client={}, request={}, body_checksum={:#x})",
            h.client().get(),
            h.request().get(),
            h.body_checksum()
          )
        });
        self.stale_landing = Some((
          op,
          format!(
            "a WAL write minted by incarnation {} landed at op {op} OVER content landed by \
             incarnation {holder}: the slot now holds (client={}, request={}, body_checksum={:#x}) \
             where it durably held {} — an abandoned old write physically evicted a newer \
             endpoint's landed slot",
            id.incarnation(),
            header.client().get(),
            header.request().get(),
            header.body_checksum(),
            evicted.as_deref().unwrap_or("nothing readable"),
          ),
        ));
      }
    }
    self.landed_by.insert(op, id.incarnation());
  }

  /// Land a staged append: the physical write happens NOW — the bounded-ring eviction of the
  /// wrapped-over slot occupant, the submit-time fault verdicts (bit-rot / torn header), the durable
  /// `entries` insert, the head raise, and the `Appended` completion. The ONE definition of "a staged
  /// append becomes durable", shared by the FIFO front release and the write-chaos seeded release,
  /// so the two release modes cannot drift on what landing does.
  fn land_staged(&mut self, done: PendingAppend) {
    self.evict_wrapped_slot(done.op);
    self.note_landing(done.op, done.id, &done.header);
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

  fn submit_append(&mut self, id: WriteId, op: OpNumber, header: Header, body: Bytes) {
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
    // WRITE-CHAOS mode: stage EVERY append with a seeded JITTERED delay (centred on the async delay,
    // spanning `1 ..= 2 * base`), so two in-flight appends genuinely complete out of submission order
    // — the reordering device the endpoint's slot-quiescence fence exists to survive. The fault
    // verdicts above were already decided at submit, exactly like the async path.
    if let Some(prng) = &mut self.write_chaos {
      let base = self.async_delay.unwrap_or(0).max(1) as u64;
      let remaining = 1 + prng.below(base * 2) as u32;
      self.staged.push_back(PendingAppend {
        remaining,
        id,
        op: op.get(),
        header,
        body: stored,
        rot,
        torn_header,
      });
      return;
    }
    match self.async_delay {
      // SYNCHRONOUS (default): durable immediately, completion queued in this call.
      None => {
        // Bounded ring: writing slot `op mod n` physically evicts the op that last held it.
        self.evict_wrapped_slot(op.get());
        // The landing ledger records the synchronous write too (an inline landing can never be
        // stale — nothing is ever in flight to reorder around — but the holder record must be
        // current so a later staged landing is compared against the true last writer).
        self.note_landing(op.get(), id, &header);
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

  fn submit_read(&mut self, id: ReadId, op: OpNumber) {
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

  fn truncate(&mut self, above: OpNumber) -> Vec<WriteId> {
    self.entries.retain(|&op, _| op <= above.get());
    // A truncated-away slot is no longer corrupt (it will be rewritten by a later append).
    self.rotted.retain(|&op| op <= above.get());
    self.torn_headers.retain(|&op| op <= above.get());
    self.head_read_faults.retain(|&op| op <= above.get());
    // A truncated slot holds nothing, so it has no holder for a later landing to be stale against.
    self.landed_by.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
    // WRITE-CHAOS mode: the staged appends are ALREADY AT THE DEVICE — un-cancellable. They stay in
    // flight (each keeps ticking and lands late, briefly resurrecting the trimmed region — the
    // tolerated shape the endpoint re-classifies and its fence defers conflicting re-appends around)
    // and NOTHING is reported cancelled, so the endpoint awaits each completion as its quiescence
    // witness.
    if self.write_chaos.is_some() {
      return Vec::new();
    }
    // Discard any staged (in-flight) append above the truncation point — those bytes are abandoned
    // and must never later become durable above the new head (async mode only; a no-op otherwise) —
    // reporting each discarded id as SYNCHRONOUSLY CANCELLED, per the trait's cancellation contract:
    // the staged queue is this WAL's own submission queue, so removal provably prevents both the
    // landing and any later completion. This models the ideal cancelling backend; a backend whose
    // writes are already at the device instead keeps them in flight and lets the endpoint's fence
    // await their completions.
    let mut cancelled = Vec::new();
    self.staged.retain(|s| {
      if s.op <= above.get() {
        true
      } else {
        cancelled.push(s.id);
        false
      }
    });
    cancelled
  }

  fn prune(&mut self, below: OpNumber) -> Vec<WriteId> {
    self.entries.retain(|&op, _| op >= below.get());
    self.rotted.retain(|&op| op >= below.get());
    self.torn_headers.retain(|&op| op >= below.get());
    self.head_read_faults.retain(|&op| op >= below.get());
    self.landed_by.retain(|&op, _| op >= below.get());
    // WRITE-CHAOS mode: staged appends below the floor stay in flight (un-cancellable device writes;
    // a late landing below the checkpoint is inert — the snapshot owns that prefix), exactly as in
    // `truncate` above.
    if self.write_chaos.is_some() {
      return Vec::new();
    }
    // A staged append below the GC floor is moot; discard it (async mode only), reporting it
    // synchronously cancelled exactly as `truncate` does.
    let mut cancelled = Vec::new();
    self.staged.retain(|s| {
      if s.op >= below.get() {
        true
      } else {
        cancelled.push(s.id);
        false
      }
    });
    cancelled
  }

  fn poll(&mut self) -> Option<WalDone> {
    // WRITE-CHAOS mode: tick ALL staged appends (a device with several writes in flight progresses
    // them all concurrently), then land ONE seeded choice among those READY (`remaining == 0`) —
    // NOT the front — so completions genuinely arrive out of submission order, exercising the
    // endpoint's any-order completion tolerance and its slot-quiescence fence.
    if self.write_chaos.is_some() {
      for s in &mut self.staged {
        if s.remaining > 0 {
          s.remaining -= 1;
        }
      }
      let ready: Vec<usize> = self
        .staged
        .iter()
        .enumerate()
        .filter(|(_, s)| s.remaining == 0)
        .map(|(i, _)| i)
        .collect();
      if !ready.is_empty() {
        let prng = self.write_chaos.as_mut().expect("chaos mode is enabled");
        let pick = ready[prng.below(ready.len() as u64) as usize];
        // Landing anything but the OLDEST staged entry is a genuine out-of-submission-order
        // completion — the reorder witness the chaos sweep asserts is non-vacuous.
        if pick != 0 {
          self.chaos_reorders_fired += 1;
        }
        let done = self.staged.remove(pick).expect("picked index is staged");
        self.land_staged(done);
      }
      return self.completions.pop_front();
    }
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
        self.land_staged(done);
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
  Root { id: WriteId, state: VsrState },
  /// A checkpoint snapshot write: on completion, publishes `(op, snapshot)` as the readable checkpoint.
  Checkpoint {
    id: WriteId,
    op: OpNumber,
    snapshot: Bytes,
  },
}

impl StagedSbWrite {
  fn id(&self) -> WriteId {
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

  /// Suspends async-write staging, returning the delay so
  /// [`resume_async_writes`](Self::resume_async_writes) can put it back.
  ///
  /// Cluster creation writes the genesis root through a BLOCKING call that requires the write durable
  /// before it returns, with no run loop yet in existence to pump an async completion. A harness that
  /// formats a store already configured for the async steady-state window suspends staging across that
  /// one call. The backend deliberately does not try to RECOGNIZE that write: it is an ordinary root
  /// write, distinguished only by who submits it and when, which the caller knows and the backend
  /// cannot soundly infer.
  ///
  /// EVERY genesis-write path must be wrapped this way — the endpoint builder's `commit` as much as
  /// the standalone `format`, at seeded construction and at every endpoint rebuild. A path that skips
  /// it fails with `WriteNotDurable` the moment its store carries an async delay, which no unit test
  /// reaches: only a lane that arms the async window and then rebuilds endpoints exposes it.
  pub fn suspend_async_writes(&mut self) -> Option<u32> {
    self.async_delay.take()
  }

  /// Restores the delay [`suspend_async_writes`](Self::suspend_async_writes) returned.
  pub fn resume_async_writes(&mut self, delay: Option<u32>) {
    self.async_delay = delay;
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

  /// Test-only: the checkpoint op named by a staged (in-flight) ROOT write that ADVANCES the durable
  /// checkpoint pointer past the current root's, if any. `None` in synchronous mode, when nothing is
  /// staged, and when every staged root keeps or rewinds the pointer. This is the window detector
  /// for "a checkpoint's step-2 root is with the device": the proto submits that root only after the
  /// checkpoint envelope write completed, so while this returns `Some(q)` the envelope for `q` is
  /// durably in the store and only the POINTER to it is still in flight.
  #[doc(hidden)]
  pub fn staged_checkpoint_root_op_for_test(&self) -> Option<u64> {
    let live = self.live_checkpoint_op();
    self.staged.iter().find_map(|(_, w)| match w {
      StagedSbWrite::Root { state, .. } if state.checkpoint_op().get() > live => {
        Some(state.checkpoint_op().get())
      }
      _ => None,
    })
  }

  /// Test-only: whether the DURABLE root's `(checkpoint_op, checkpoint_id)` pair names a checkpoint
  /// envelope this store actually holds — the stored generation at `checkpoint_op` exists and its
  /// bytes hash to `checkpoint_id`. Vacuously true while no checkpoint is rooted (`checkpoint_op ==
  /// 0`). `false` is the self-poisoned-pointer state: the two root fields were taken from two
  /// different checkpoints' timelines, so recovery's placement + content-address verification against
  /// this root cannot succeed from local disk and a replica with NO disk fault anywhere is forced to
  /// peer-fetch its own checkpoint.
  #[doc(hidden)]
  pub fn root_names_stored_checkpoint_for_test(&self) -> bool {
    let live = self.live_checkpoint_op();
    if live == 0 {
      return true;
    }
    self
      .snapshots
      .get(&live)
      .is_some_and(|snap| checkpoint_id(snap) == self.state.checkpoint_id())
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

  fn submit_write(&mut self, id: WriteId, state: VsrState) {
    match self.async_delay {
      // ASYNC steady-state: STAGE as not-yet-durable. `self.state` is left at the prior durable root
      // until `poll` releases this write after `delay` ticks — opening the pending durable-view window.
      Some(delay) => self
        .staged
        .push_back((delay, StagedSbWrite::Root { id, state })),
      // SYNCHRONOUS: durable immediately, completion queued in this call. The new durable root may
      // NAME a just-written snapshot generation (a checkpoint's step-2 root) — which becomes the
      // live/readable checkpoint by virtue of `state.checkpoint_op()` now pointing at it; GC then drops
      // strictly-older generations (staged is empty on this path, so GC runs inline).
      None => {
        self.state = state;
        self.gc_snapshots();
        self.completions.push_back(SuperblockDone::Wrote(id));
      }
    }
  }

  fn submit_write_checkpoint(&mut self, id: WriteId, op: OpNumber, snapshot: Bytes) {
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

  fn submit_read_checkpoint(&mut self, id: ReadId) {
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
mod tests;

//! Deterministic in-memory `Wal`/`Superblock` impls for the DST harness.
//!
//! M3.0/M3.1: reliable + synchronous (each submit completes immediately into the
//! completion queue). [`InMemoryWal::with_async_appends`] adds an OPT-IN async-append mode that
//! STAGES each append as not-yet-durable for a seeded number of `poll`s — reopening the in-flight
//! window a real `fsync`-between-ticks WAL has (and the synchronous default closes), which the
//! append-before-ack invariant must survive (codex R7-F1). The default stays synchronous so existing
//! gates are unaffected. M3.3a adds **seeded** fault injection ([`StorageFaults`]): TRANSIENT WAL read
//! faults (each read independently rolls — a retry may succeed, exercising the proto's
//! `Status::Recovering` retry loop), permanent torn writes (a flipped body byte ⇒ `Header::verify`
//! fails on read-back), and permanent bit-rot (every read of the slot faults). All faults surface as
//! data (`WalDone::Fault`/`Absent`, `SlotStatus::Faulty`) — the WAL never silently fixes a corrupt
//! body, so the proto's checksum chokepoint always sees it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bytes::Bytes;
use vsrr_proto::{
  CheckpointRead, Header, OpId, OpNumber, Prng, ReadOk, SlotStatus, Superblock, SuperblockDone,
  VsrState, Wal, WalDone,
};

/// Seeded storage-fault plan for one replica's WAL + superblock. Deterministic per (seed, replica):
/// the same seed reproduces the same fault decisions, and permanent verdicts (torn / bit-rot) live
/// in the durable struct so they survive a crash + restart unchanged.
///
/// All probabilities are out of 1000 (per mille), mirroring [`crate::Faults`] for the network. Like
/// `Faults`, this is a plain sim-harness config value with public fields — the "no public fields"
/// golden rule is enforced on `vsrr-proto` (the library), not on the simulation test harness, which
/// already uses pub-field config structs for ergonomic test setup.
///
/// # The transient-vs-permanent distinction (load-bearing for the M3.3a gate)
///
/// - **`read_fault_per_mille`** — TRANSIENT. Each `submit_read` rolls independently, so a faulted
///   read may succeed on retry; the proto's recover loop (budget `RECOVER_READ_RETRIES`) clears it.
///   The M3.3a "committed ops survive crash + storage-fault + restart" gate uses ONLY this, so a
///   restarted replica always recovers from its OWN disk and reaches `Normal` — no peer needed.
/// - **`torn_write_per_mille` / `bit_rot_per_mille`** — PERMANENT (a slot is gone until rewritten /
///   for good on this replica). Recovering such a committed slot needs a PEER: a permanently-faulty
///   HEAD slot ⇒ `RecoveringHead` + `StartView`/`RecoveryResponse` adoption (B1); a permanently-faulty
///   NON-head committed slot ⇒ peer fault-repair via `RequestPrepare` → `Prepare`, with the commit
///   HELD below the hole until the op arrives (B4). M3.3a gates set these to `0` because peer-repair
///   did not yet exist (a permanent committed-op fault would have tripped the old "committed op
///   present in log" expectation); the M3.3b permanent-fault gate turns them on and proves no
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
  /// of it faults, modelling unrecoverable media damage. (Used by M3.3b; `0` in M3.3a gates.)
  pub bit_rot_per_mille: u32,
}

impl StorageFaults {
  /// No faults: every read succeeds, no torn writes, no bit-rot.
  pub const fn none() -> Self {
    Self {
      read_fault_per_mille: 0,
      torn_write_per_mille: 0,
      bit_rot_per_mille: 0,
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
}

/// A seeded in-memory write-ahead log. With [`StorageFaults::none`] it is reliable + synchronous
/// (M3.0/M3.1 behaviour); with faults it injects transient read faults + permanent torn/bit-rot.
///
/// # Async-append mode (opt-in, [`InMemoryWal::with_async_appends`])
///
/// By DEFAULT every `submit_append` completes SYNCHRONOUSLY (the entry is durable and its `Appended`
/// completion is queued in the same call) — the M3.0/M3.1 behaviour all existing gates rely on.
/// Async mode instead STAGES each append as not-yet-durable for a seeded number of `poll`s before it
/// becomes durable, modelling a real WAL whose `fsync` lands between ticks rather than inline. This
/// opens the window a real driver has — and the synchronous default closed — where the proto's head
/// (`self.op`) has advanced past an op whose bytes are still in flight, which is exactly the state
/// the append-before-ack invariant must hold across (codex R7-F1). It composes with the fault rolls:
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
  /// `None` (default) ⇒ synchronous appends. `Some(d)` ⇒ async mode: each `submit_append` stages for
  /// `d` `poll`s before becoming durable. `d == 0` releases on the very next `poll` (still NOT inline,
  /// so the in-flight window still exists for at least one tick).
  async_delay: Option<u32>,
  /// Async mode: appends submitted but not yet durable, in submission order (a serial WAL writer
  /// completes them FIFO). Empty in synchronous mode.
  staged: VecDeque<PendingAppend>,
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
      async_delay: None,
      staged: VecDeque::new(),
    }
  }

  /// Creates an empty, reliable WAL in **async-append mode**: every `submit_append` stages the entry
  /// as not-yet-durable for `delay_ticks` `poll`s, then it becomes durable and `poll` yields its
  /// `Appended`. Opt-in; the default ([`new`](Self::new)/[`with_faults`](Self::with_faults)) stays
  /// synchronous so existing gates are unaffected. Until an append completes the slot is
  /// [`SlotStatus::Dirty`] (never `Clean`) and a read of it returns `Absent` — modelling the in-flight
  /// window a real async WAL has, where the proto's head has advanced past bytes not yet on disk
  /// (codex R7-F1). `delay_ticks == 0` still defers to the next `poll` (never inline).
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
  /// or torn (the stored body fails its header's `verify`). Used by the M3.3b permanent-fault gate to
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

  /// The number of durable slots currently held (after any prune/truncate). Used by the M3.4b
  /// boundedness checker to assert the WAL stays bounded over a long run with checkpoint GC.
  pub fn len(&self) -> usize {
    self.entries.len()
  }

  /// True iff the WAL holds no durable slots.
  pub fn is_empty(&self) -> bool {
    self.entries.is_empty()
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

  fn header(&self, op: OpNumber) -> Option<Header> {
    // A known-permanently-faulty (bit-rotted) slot reports no header, per the trait contract
    // ("None = absent OR known-faulty"). A torn slot still has its original header (the tear is
    // latent — only the body fails verify on read), so it reports its header as usual.
    if self.rotted.contains(&op.get()) {
      return None;
    }
    self.entries.get(&op.get()).map(|(h, _)| *h)
  }

  fn status(&self, op: OpNumber) -> SlotStatus {
    if self.rotted.contains(&op.get()) {
      SlotStatus::Faulty
    } else if self.entries.contains_key(&op.get()) {
      SlotStatus::Clean
    } else if self.staged.iter().any(|s| s.op == op.get()) {
      // Async mode: a submitted-but-not-yet-durable append is DIRTY, never Clean — the bytes are not
      // on disk yet, so the proto must not treat this slot as a durable voter copy (R7-F1).
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
    match self.async_delay {
      // SYNCHRONOUS (default): durable immediately, completion queued in this call (M3.0/M3.1).
      None => {
        if rot {
          self.rotted.insert(op.get());
        }
        self.entries.insert(op.get(), (header, stored));
        self.head = self.head.max(op.get());
        self.completions.push_back(WalDone::Appended(id));
      }
      // ASYNC: STAGE as not-yet-durable. `self.head`/`entries`/`rotted` are left untouched (so the
      // slot reads `Dirty`/`Absent` and `op_head` does not yet count it) until `poll` releases it
      // after `delay` ticks — opening the in-flight window the synchronous path never had (R7-F1).
      Some(delay) => self.staged.push_back(PendingAppend {
        remaining: delay,
        id,
        op: op.get(),
        header,
        body: stored,
        rot,
      }),
    }
  }

  fn submit_read(&mut self, id: OpId, op: OpNumber) {
    // PERMANENT bit-rot: this slot always faults.
    if self.rotted.contains(&op.get()) {
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
    // Otherwise return the stored entry. A torn body is returned AS-IS (it fails the proto's
    // `Header::verify`), never repaired.
    let done = match self.entries.get(&op.get()) {
      Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    };
    self.completions.push_back(done);
  }

  fn truncate(&mut self, above: OpNumber) {
    self.entries.retain(|&op, _| op <= above.get());
    // A truncated-away slot is no longer corrupt (it will be rewritten by a later append).
    self.rotted.retain(|&op| op <= above.get());
    // Drop any staged (in-flight) append above the truncation point: those bytes are abandoned and
    // must never later become durable above the new head (async mode only; a no-op otherwise).
    self.staged.retain(|s| s.op <= above.get());
    self.head = self.head.min(above.get());
  }

  fn prune(&mut self, below: OpNumber) {
    self.entries.retain(|&op, _| op >= below.get());
    self.rotted.retain(|&op| op >= below.get());
    // A staged append below the GC floor is moot; drop it (async mode only).
    self.staged.retain(|s| s.op >= below.get());
  }

  fn poll(&mut self) -> Option<WalDone> {
    // Async mode: tick the staged (in-flight) appends. A serial WAL writer completes them in
    // submission order, so we count down the FRONT entry and make it durable when it reaches zero —
    // at which point its bytes land in `entries`/`rotted` (the fault verdict taken at submit) and its
    // `Appended` is queued. This is the ONLY place a staged append becomes durable: until then the
    // slot is `Dirty`/`Absent` and the proto's head sits above not-yet-durable bytes (the R7-F1
    // window). A no-op in synchronous mode (`staged` is always empty there).
    if let Some(front) = self.staged.front_mut() {
      if front.remaining == 0 {
        let done = self.staged.pop_front().expect("front exists");
        if done.rot {
          self.rotted.insert(done.op);
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
/// NEVER permanently corrupts a checkpoint the durable root names (preserving the M3.2a invariant
/// that the root only ever names a fully-written snapshot), so the M3.3a recover always eventually
/// restores. Torn/bit-rot are WAL-only.
///
/// # Async-write mode (opt-in, [`InMemorySuperblock::with_async_writes_and_faults`])
///
/// By DEFAULT every `submit_write`/`submit_write_checkpoint` completes SYNCHRONOUSLY (the effect is
/// applied and the `Wrote` completion queued in the same call) — the M3.0/M3.1 behaviour all existing
/// gates rely on. Async mode instead STAGES each write as not-yet-durable for a seeded number of
/// `poll`s before it becomes durable, modelling a real superblock whose `fsync` lands between ticks.
/// This opens the **pending durable-view window** the proto's durable-view-before-participate gate
/// must hold across (codex R8-F1): a replica that just became primary has set `Status::Normal` and
/// minted the view-change root write, but that root is still in flight — so `pending_sb` is armed and
/// `state()` still names the OLD view, exactly the window where a delayed `GetView`/`Recovery` or a
/// primary timer must NOT make it act in the not-yet-durable view. The synchronous default never
/// opens this window (the write is durable inline). Completions are FIFO so the root-write ordering
/// contract holds; the effect (new root / new checkpoint bytes) is applied on completion.
#[derive(Debug)]
pub struct InMemorySuperblock {
  state: VsrState,
  checkpoint: Option<(OpNumber, Bytes)>,
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
  /// Creates a fresh-cluster superblock (`VsrState::initial`, no checkpoint, no faults).
  pub fn new() -> Self {
    Self::with_faults(StorageFaults::none(), 0)
  }

  /// Creates a fresh-cluster superblock with a seeded fault plan. Only `read_fault_per_mille` (a
  /// transient checkpoint-read fault) is honoured; torn/bit-rot do not apply to the superblock.
  /// Synchronous writes (no async delay).
  pub fn with_faults(faults: StorageFaults, seed: u64) -> Self {
    Self {
      state: VsrState::initial(),
      checkpoint: None,
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
  /// proto's durable-view-before-participate gate must survive (codex R8-F1). `delay_ticks == 0` still
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
  /// loses any superblock `fsync` still in flight. The durable root / checkpoint are left at their
  /// last COMPLETED values (what a restart recovers from). A no-op in synchronous mode (`staged` is
  /// always empty). Called by the cluster's `crash` so a crash genuinely loses a not-yet-durable view
  /// write (the precondition for the durable-view-before-participate property to mean anything).
  pub fn discard_inflight(&mut self) {
    self.staged.clear();
  }
}

impl Superblock for InMemorySuperblock {
  fn state(&self) -> VsrState {
    self.state.clone()
  }

  fn submit_write(&mut self, id: OpId, state: VsrState) {
    match self.async_delay {
      // SYNCHRONOUS (default): durable immediately, completion queued in this call (M3.0/M3.1).
      None => {
        self.state = state;
        self.completions.push_back(SuperblockDone::Wrote(id));
      }
      // ASYNC: STAGE as not-yet-durable. `self.state` is left at the prior durable root until `poll`
      // releases this write after `delay` ticks — opening the pending durable-view window (R8-F1).
      Some(delay) => self
        .staged
        .push_back((delay, StagedSbWrite::Root { id, state })),
    }
  }

  fn submit_write_checkpoint(&mut self, id: OpId, op: OpNumber, snapshot: Bytes) {
    match self.async_delay {
      None => {
        self.checkpoint = Some((op, snapshot));
        self.completions.push_back(SuperblockDone::Wrote(id));
      }
      // ASYNC: STAGE; the snapshot is not readable until this write completes (the prior checkpoint
      // stays readable meanwhile). The proto sequences the snapshot write before its root write, and
      // FIFO completion preserves that ordering.
      Some(delay) => self
        .staged
        .push_back((delay, StagedSbWrite::Checkpoint { id, op, snapshot })),
    }
  }

  fn submit_read_checkpoint(&mut self, id: OpId) {
    // TRANSIENT checkpoint-read fault: rolled independently per read, so the proto's recover loop
    // clears it within budget. NEVER permanent — the root always names a fully-written snapshot, so
    // a real `None` (no checkpoint) is the only non-transient `Fault`, returned unconditionally.
    if self.checkpoint.is_some()
      && self.faults.read_fault_per_mille > 0
      && self.prng.chance(self.faults.read_fault_per_mille, 1000)
    {
      self.completions.push_back(SuperblockDone::Fault(id));
      return;
    }
    let done = match &self.checkpoint {
      Some((op, snap)) => {
        SuperblockDone::CheckpointRead(CheckpointRead::new(id, *op, snap.clone()))
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
    // at their prior values (the R8-F1 pending-durable-view window). A no-op in synchronous mode.
    if let Some((remaining, _)) = self.staged.front_mut() {
      if *remaining == 0 {
        let (_, write) = self.staged.pop_front().expect("front exists");
        let id = write.id();
        match write {
          StagedSbWrite::Root { state, .. } => self.state = state,
          StagedSbWrite::Checkpoint { op, snapshot, .. } => self.checkpoint = Some((op, snapshot)),
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
  use vsrr_proto::{
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
    assert_eq!(sb.state(), VsrState::initial());
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
    assert_eq!(sb.state().committed_headers().len(), 3);
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
    // The load-bearing property for the M3.3a gate: a TRANSIENT read fault must clear within the
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
  fn bit_rot_makes_a_slot_permanently_faulty() {
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
    assert!(
      w.header(OpNumber::with(1)).is_none(),
      "a known-faulty slot reports no header"
    );
    for i in 0..5u64 {
      w.submit_read(OpId::new(i), OpNumber::with(1));
      assert!(
        w.poll().unwrap().is_fault(),
        "permanent: every read of a bit-rotted slot faults"
      );
    }
  }

  #[test]
  fn torn_write_fails_proto_verify_on_read() {
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        torn_write_per_mille: 1000,
        ..StorageFaults::none()
      },
      1,
    );
    append(&mut w, 1, b"intact");
    // A torn slot keeps its ORIGINAL header (the tear is latent) and reports Clean — only the body
    // fails verify on read, exactly the corruption a dumb backend cannot hide from the proto.
    assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
    assert!(w.header(OpNumber::with(1)).is_some());
    w.submit_read(OpId::new(2), OpNumber::with(1));
    match w.poll() {
      Some(WalDone::ReadOk(r)) => assert!(
        !r.header().verify(r.body()),
        "a torn body fails the proto's Header::verify"
      ),
      other => panic!("torn write should still yield a (corrupt) ReadOk, got {other:?}"),
    }
  }

  #[test]
  fn permanent_verdicts_survive_a_restart_via_the_persisted_struct() {
    // A bit-rotted slot stays rotted across a crash/restart because the WAL struct persists in the
    // Cluster (the `rotted` set lives in the struct). This is what makes the M3.3b permanent-fault
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
    // faults, proving the verdict is stable for the lifetime of the durable medium.
    for i in 0..3u64 {
      w.submit_read(OpId::new(i), OpNumber::with(1));
      assert!(w.poll().unwrap().is_fault());
    }
  }

  #[test]
  fn superblock_checkpoint_read_fault_is_transient() {
    use vsrr_proto::SuperblockDone;
    let mut sb = InMemorySuperblock::with_faults(
      StorageFaults {
        read_fault_per_mille: 500,
        ..StorageFaults::none()
      },
      3,
    );
    // Stage a checkpoint so reads have something to (transiently) fault on.
    sb.submit_write_checkpoint(OpId::new(1), OpNumber::with(4), Bytes::from_static(b"snap"));
    let _ = sb.poll();
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
    // The core async-mode primitive (R7-F1 harness): a submitted append is NOT durable for `delay`
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
      Some(WalDone::ReadOk(r)) => assert!(
        !r.header().verify(r.body()),
        "the durable torn body fails the proto's Header::verify"
      ),
      other => panic!("expected a (corrupt) ReadOk, got {other:?}"),
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
}

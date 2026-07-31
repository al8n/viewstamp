//! In-memory [`BlockStore`] for the simulation cluster.
//!
//! The proto ships a content-addressed [`BlockStore`] trait but its only impl is a `#[cfg(test)]`
//! fixture private to that crate. The sim cluster needs its own backing store for the DAG-based
//! checkpoint/state-sync path, so this module provides a `BTreeMap`-backed store.
//!
//! # The durability set
//!
//! The store separates the blocks a [`BlockStore::flush`] has made DURABLE from those merely
//! STAGED by a [`BlockStore::put`] since the last successful barrier. Nothing about the store's
//! answers depends on that split — a staged block reads back exactly like a flushed one, as a real
//! write-back backend's would — but it makes the barrier's meaning OBSERVABLE, which is what lets
//! the cluster assert the one oracle the seam exists for: a durable checkpoint root never names a
//! block that is not flushed.
//!
//! # Faults
//!
//! Both fault modes are OFF by default and inject nothing, so the seeded schedule is unchanged
//! unless a lane arms them:
//!
//! - a SEEDED flush fault ([`MemBlockStore::set_flush_faults`]) fails the barrier and leaves its
//!   staged blocks un-flushed — the endpoint must then publish no pointer over them and re-force the
//!   checkpoint on its cadence;
//! - an ARMED read fault ([`MemBlockStore::arm_read_faults`]) answers the next `n` reads ABSENT,
//!   which is how the cluster delivers a fault into one specific block job (a reconstruct) without
//!   the store needing to know what job it is serving.

use std::{
  cell::Cell,
  collections::{BTreeMap, BTreeSet},
};

use bytes::Bytes;
use viewstamp_proto::{BlockAddress, BlockDagWalk, BlockStore, Prng, block_address};

/// The per-mille rate at which the seeded plan FAILS a barrier, once installed.
///
/// Sized so a run crosses many faulted checkpoints while the great majority of barriers still
/// succeed: the checkpoint the fault drops must be RE-FORCED and land, and a rate near certainty
/// would starve the durable checkpoint entirely and turn a durability axis into a liveness one.
const FLUSH_FAULT_PER_MILLE: u32 = 150;

/// An in-memory content-addressed block store backed by a `BTreeMap`.
///
/// Keys are [`BlockAddress`] values (which are `Ord`), so iteration order is deterministic — a
/// property the seeded simulation relies on. Writes are idempotent: re-writing an address with
/// byte-identical content is a no-op-equivalent overwrite, exactly as content-addressing permits.
#[derive(Debug, Clone)]
pub struct MemBlockStore {
  blocks: BTreeMap<BlockAddress, Bytes>,
  /// Every held address a successful [`BlockStore::flush`] has made durable. A block enters here
  /// ONLY through a clean barrier and leaves only when the sweep frees it, so membership is exactly
  /// "this block would survive a crash" — the predicate the durable-checkpoint oracle reads.
  flushed: BTreeSet<BlockAddress>,
  /// Every held address written since the last SUCCESSFUL barrier. Disjoint from [`Self::flushed`]
  /// by construction: a clean flush moves the whole set across, a faulted one leaves it intact so
  /// the next barrier still owes it.
  staged: BTreeSet<BlockAddress>,
  /// The seeded flush-fault plan: `Some(prng)` ⇒ each barrier draws its verdict, `None` (the
  /// default) ⇒ every barrier succeeds. Held as a PRNG rather than a rate so a store's fault
  /// sequence is a pure function of its seed and survives the run.
  flush_faults: Option<Prng>,
  /// How many barriers the seeded plan FAILED. `0` with the plan absent; `> 0` is the fault axis's
  /// non-vacuity witness (the oracle below it judges a run where the fault genuinely fired).
  flush_faults_fired: u64,
  /// How many further [`BlockStore::read_block`] calls answer ABSENT. Counts down per read; `0` (the
  /// default) ⇒ every read answers from the map. Armed immediately before one block job executes, so
  /// the fault lands inside THAT job's reads and nowhere else. A [`Cell`] because `read_block` takes
  /// `&self`: consuming the arm is bookkeeping over the fault plan, not a mutation of stored blocks.
  read_faults_armed: Cell<u32>,
  /// How many reads the armed fault actually swallowed — the arming site's non-vacuity witness (a
  /// job that read nothing would consume no arm and prove nothing).
  read_faults_fired: Cell<u64>,
  /// Whether [`BlockStore::gc`] performs a real mark-and-sweep (`true`) or is a no-op (`false`).
  ///
  /// A real-GC store (the default, [`MemBlockStore::new`]) is what the GC tests + the
  /// incremental-sync oracle drive directly. The cluster's per-replica stores are built GC-DISABLED
  /// ([`MemBlockStore::new_gc_disabled`]): pruning a since-superseded checkpoint block mid-run would
  /// make a donor answer a peer's `RequestBlock` for that block ABSENT instead of present, shifting
  /// the seeded message schedule (a correct content-addressed re-request, but no longer byte-identical
  /// to the pinned VOPR baseline). The GC CONTRACT is verified by the dedicated mark-and-sweep tests;
  /// the seeded cluster schedule stays neutral by holding every block for the run's lifetime (a store
  /// that never GCs is explicitly a correct `BlockStore`).
  gc_enabled: bool,
}

impl Default for MemBlockStore {
  fn default() -> Self {
    Self::new()
  }
}

impl MemBlockStore {
  /// Creates an empty store whose [`BlockStore::gc`] performs a real mark-and-sweep.
  pub fn new() -> Self {
    Self::with_gc(true)
  }

  /// Creates an empty store whose [`BlockStore::gc`] is a NO-OP — the variant the seeded cluster uses
  /// so a mid-run prune never perturbs the byte-identical VOPR schedule (see the `gc_enabled` field).
  pub fn new_gc_disabled() -> Self {
    Self::with_gc(false)
  }

  /// The shared constructor: an empty store with no faults armed and `gc_enabled` as given.
  fn with_gc(gc_enabled: bool) -> Self {
    Self {
      blocks: BTreeMap::new(),
      flushed: BTreeSet::new(),
      staged: BTreeSet::new(),
      gc_enabled,
      flush_faults: None,
      flush_faults_fired: 0,
      read_faults_armed: Cell::new(0),
      read_faults_fired: Cell::new(0),
    }
  }

  /// Enables or disables the real mark-and-sweep in [`BlockStore::gc`]. The incremental-sync oracle
  /// flips this ON for its cluster (`Cluster::enable_block_gc`): GC keeps each store bounded over the
  /// oracle's long warm-up/drain (hundreds of thousands of ticks, a checkpoint every few ops), where a
  /// never-pruning store would grow without bound and make every per-tick `has_block` lookup slower.
  pub const fn set_gc_enabled(&mut self, enabled: bool) -> &mut Self {
    self.gc_enabled = enabled;
    self
  }

  /// The number of distinct blocks currently held.
  pub fn len(&self) -> usize {
    self.blocks.len()
  }

  /// Whether the store holds no blocks.
  pub fn is_empty(&self) -> bool {
    self.blocks.is_empty()
  }

  /// Plants `block` under `addr` WITHOUT deriving the address from the content — the sim's
  /// fault-injection backdoor for planting corrupt blocks (bytes that do not hash to their key),
  /// which [`BlockStore::put`] makes unrepresentable on the production path.
  ///
  /// The planted address joins the DURABLE set: the bit-rot / misdirected-write this models happens
  /// to media that already holds the block, so the fault must not read as "merely staged" and let the
  /// durable-checkpoint oracle blame it on a missing barrier.
  pub fn insert_raw(&mut self, addr: BlockAddress, block: Bytes) {
    self.blocks.insert(addr, block);
    self.staged.remove(&addr);
    self.flushed.insert(addr);
  }

  /// Empties the MEDIUM: every held block and its durability bookkeeping are gone, as a replaced
  /// disk's would be. Used by the cluster's wipe-and-restart to forfeit a replica's checkpoint DAGs
  /// alongside its WAL + superblock — the blocks ARE the durable checkpoint's contents, so a wipe
  /// that spared them would leave the replica able to restore and serve state it no longer has.
  ///
  /// The DEPLOYMENT survives the swap: the seeded flush-fault plan, the GC mode, and the lifetime
  /// fault witnesses are properties of the machine the new medium is installed in, not of the medium.
  /// Keeping the fault plan (rather than rebuilding a store without one) is what makes a wiped
  /// replica keep faulting barriers at the same seeded rate the rest of the run does; keeping the
  /// witnesses is what stops a wipe from silently retracting a fault an axis already observed.
  pub fn wipe(&mut self) {
    self.blocks.clear();
    self.flushed.clear();
    self.staged.clear();
  }

  /// Whether the store holds `addr` AND a successful barrier has made it durable. The predicate the
  /// durable-checkpoint oracle is stated over: a held-but-STAGED block answers `false`.
  pub fn is_flushed(&self, addr: BlockAddress) -> bool {
    self.flushed.contains(&addr)
  }

  /// How many held blocks are STAGED — written but not yet carried across a successful barrier.
  /// Non-zero only between a `put` and the `flush` that covers it (or after a FAULTED flush, which
  /// leaves the whole staged set owed to the next barrier).
  pub fn staged_len(&self) -> usize {
    self.staged.len()
  }

  /// Installs (`Some(seed)`) or removes (`None`, the default) the SEEDED flush-fault plan on an EMPTY
  /// store. Each [`BlockStore::flush`] then draws its verdict from the seeded stream: a fault returns
  /// `Err` and leaves every staged block un-flushed, so a checkpoint's roots stay un-durable and the
  /// endpoint must publish no pointer over them.
  ///
  /// Constrained to an empty store for the same reason the WAL's chaos mode is: the plan decides how
  /// blocks already written would have become durable, and installing it over a populated store would
  /// leave a durability set no seed reproduces.
  pub fn set_flush_faults(&mut self, seed: Option<u64>) {
    assert!(
      self.blocks.is_empty(),
      "set_flush_faults must be called on an empty block store"
    );
    self.flush_faults = seed.map(Prng::new);
  }

  /// How many barriers the seeded plan FAILED. `0` without a plan; the fault lane's non-vacuity
  /// witness.
  pub fn flush_faults_fired(&self) -> u64 {
    self.flush_faults_fired
  }

  /// Arms the next `n` [`BlockStore::read_block`] calls to answer ABSENT, replacing any previous arm.
  ///
  /// The store cannot see WHICH job is reading it, so the caller arms this immediately before
  /// executing the one job it means to fault and disarms after — which delivers a read fault into
  /// exactly that job's reads (a reconstruct's verify-on-read path, say) and leaves every other
  /// read untouched. Deterministic: no draw is taken here.
  pub fn arm_read_faults(&self, n: u32) {
    self.read_faults_armed.set(n);
  }

  /// How many reads the armed fault swallowed over this store's lifetime. The arming site's
  /// non-vacuity witness: an arm the executed job never consumed leaves this unchanged, so a lane
  /// that only THINKS it faulted a job reads zero here.
  pub fn read_faults_fired(&self) -> u64 {
    self.read_faults_fired.get()
  }
}

impl BlockStore for MemBlockStore {
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    // `read_block` takes `&self`, so the armed count is consumed through a cell rather than the
    // field: the arm is a per-job fault the caller installs and clears around one `execute_block_job`,
    // and a read it swallows must answer exactly as an absent block does — `None`, which the
    // verify-on-read path treats as data.
    let armed = self.read_faults_armed.get();
    if armed > 0 {
      self.read_faults_armed.set(armed - 1);
      self.read_faults_fired.set(self.read_faults_fired.get() + 1);
      return None;
    }
    self.blocks.get(&addr).cloned()
  }

  fn put(&mut self, block: Bytes) -> BlockAddress {
    let addr = block_address(&block);
    self.blocks.insert(addr, block);
    // Content-addressing makes a re-put of an ALREADY-DURABLE block a no-op on the medium (identical
    // bytes under an identical key), so it must not fall back out of the durable set and make the
    // oracle read a durable root as un-flushed. Only a genuinely new address is staged.
    if !self.flushed.contains(&addr) {
      self.staged.insert(addr);
    }
    addr
  }

  fn flush(&mut self) -> Result<(), viewstamp_proto::BlockStoreError> {
    if let Some(prng) = &mut self.flush_faults
      && prng.chance(FLUSH_FAULT_PER_MILLE, 1_000)
    {
      // The barrier FAILED: every staged block stays staged, so nothing this checkpoint wrote has
      // become durable and the endpoint owes the whole set to a later barrier.
      self.flush_faults_fired += 1;
      return Err(viewstamp_proto::BlockStoreError::new());
    }
    self.flushed.append(&mut self.staged);
    Ok(())
  }

  fn has_block(&self, addr: BlockAddress) -> bool {
    self.blocks.contains_key(&addr)
  }

  fn gc(&mut self, walks: &[BlockDagWalk<'_>]) {
    if !self.gc_enabled {
      return; // the seeded cluster's stores never prune (schedule neutrality — see `gc_enabled`).
    }
    // Mark: DFS the reachable set, one TYPED walk per DAG (the SM state DAG and the proto session DAG),
    // each followed by its OWN resolver — a session block is never handed to the SM resolver (nor vice
    // versa). The per-traversal `visited` guard is kept SEPARATE from the union `reachable` sweep set: an
    // address can be reachable in BOTH DAGs (block bytes are opaque and content-addressed, so an SM block
    // CAN be byte-identical to a session block, hence the same address), and a shared visited set would
    // let the first walk's mark make a later walk SKIP its own resolver on that shared address — wrongly
    // sweeping children reachable only through the skipped resolver. With a per-walk `visited`, each walk
    // runs its own resolver on a shared address, so every DAG's true children are marked (the union only
    // ever retains). An address not currently held is simply skipped — a live root whose DAG is only
    // partially present (an in-flight sync target mid-fetch) keeps the blocks it DOES hold and is never
    // over-pruned. A held block that does not hash to its address is corrupt: its edges are garbage, so
    // they are not followed, but the address stays marked so the corrupt block is not swept (a later
    // sync re-fetches the verified replacement rather than finding it silently pruned).
    let mut reachable = BTreeSet::new();
    for walk in walks {
      let mut visited = BTreeSet::new();
      let mut stack: Vec<BlockAddress> = walk.roots().to_vec();
      while let Some(addr) = stack.pop() {
        if !visited.insert(addr) {
          continue; // already traversed by THIS walk — skip (cycle / shared-subtree convergence).
        }
        reachable.insert(addr); // mark live in the union sweep set regardless of which walk reached it.
        if let Some(block) = self.blocks.get(&addr) {
          if block_address(block) != addr {
            continue; // corrupt block — do not follow its garbage edges.
          }
          for child in (walk.references())(block) {
            if !visited.contains(&child) {
              stack.push(child);
            }
          }
        }
      }
    }
    // Sweep: free every held block the mark phase did not reach, from the map AND from the durability
    // bookkeeping — a freed address is no longer held, so leaving it in either set would let a later
    // re-put of the same content read as already-durable when the medium no longer carries it.
    self.blocks.retain(|addr, _| reachable.contains(addr));
    self.flushed.retain(|addr| reachable.contains(addr));
    self.staged.retain(|addr| reachable.contains(addr));
  }
}

#[cfg(test)]
mod tests;

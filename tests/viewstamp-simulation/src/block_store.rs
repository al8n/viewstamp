//! In-memory [`BlockStore`] for the simulation cluster.
//!
//! The proto ships a content-addressed [`BlockStore`] trait but its only impl is a `#[cfg(test)]`
//! fixture private to that crate. The sim cluster needs its own backing store for the DAG-based
//! checkpoint/state-sync path, so this module provides a `BTreeMap`-backed store: all writes are
//! synchronous and never faulted, exactly the always-available block storage the deterministic
//! harness assumes.

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
use viewstamp_proto::{BlockAddress, BlockDagWalk, BlockStore, block_address};

/// An in-memory content-addressed block store backed by a `BTreeMap`.
///
/// Keys are [`BlockAddress`] values (which are `Ord`), so iteration order is deterministic — a
/// property the seeded simulation relies on. Writes are idempotent: re-writing an address with
/// byte-identical content is a no-op-equivalent overwrite, exactly as content-addressing permits.
#[derive(Debug, Clone)]
pub struct MemBlockStore {
  blocks: BTreeMap<BlockAddress, Bytes>,
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
    Self {
      blocks: BTreeMap::new(),
      gc_enabled: true,
    }
  }

  /// Creates an empty store whose [`BlockStore::gc`] is a NO-OP — the variant the seeded cluster uses
  /// so a mid-run prune never perturbs the byte-identical VOPR schedule (see the `gc_enabled` field).
  pub fn new_gc_disabled() -> Self {
    Self {
      blocks: BTreeMap::new(),
      gc_enabled: false,
    }
  }

  /// Enables or disables the real mark-and-sweep in [`BlockStore::gc`]. The incremental-sync oracle
  /// flips this ON for its cluster (`Cluster::enable_block_gc`): GC keeps each store bounded over the
  /// oracle's long warm-up/drain (hundreds of thousands of ticks, a checkpoint every few ops), where a
  /// never-pruning store would grow without bound and make every per-tick `has_block` lookup slower.
  pub fn set_gc_enabled(&mut self, enabled: bool) {
    self.gc_enabled = enabled;
  }

  /// The number of distinct blocks currently held.
  pub fn len(&self) -> usize {
    self.blocks.len()
  }

  /// Whether the store holds no blocks.
  pub fn is_empty(&self) -> bool {
    self.blocks.is_empty()
  }

  /// Writes `block` keyed by its content address.
  ///
  /// Equivalent to `write_block(block_address(&block), block)` — the address is derived from the
  /// content, so the caller need not supply it separately.
  pub fn write_verified(&mut self, block: Bytes) {
    let addr = block_address(&block);
    self.blocks.insert(addr, block);
  }
}

impl BlockStore for MemBlockStore {
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    self.blocks.get(&addr).cloned()
  }

  fn write_block(&mut self, addr: BlockAddress, block: Bytes) {
    self.blocks.insert(addr, block);
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
      let mut stack: Vec<BlockAddress> = walk.roots.to_vec();
      while let Some(addr) = stack.pop() {
        if !visited.insert(addr) {
          continue; // already traversed by THIS walk — skip (cycle / shared-subtree convergence).
        }
        reachable.insert(addr); // mark live in the union sweep set regardless of which walk reached it.
        if let Some(block) = self.blocks.get(&addr) {
          if block_address(block) != addr {
            continue; // corrupt block — do not follow its garbage edges.
          }
          for child in (walk.references)(block) {
            if !visited.contains(&child) {
              stack.push(child);
            }
          }
        }
      }
    }
    // Sweep: free every held block the mark phase did not reach.
    self.blocks.retain(|addr, _| reachable.contains(addr));
  }
}

#[cfg(test)]
mod tests;

//! Pure-logic missing-block frontier engine — the Sans-I/O form of TigerBeetle's
//! `grid_blocks_missing`.
//!
//! [`BlockSync`] reconstructs the checkpoint DAG rooted at a target `root` into a [`BlockStore`],
//! fetching ONLY the blocks the store is missing. It owns no I/O: it EMITS the address of the next
//! block to pull ([`BlockSync::next_request`]) and CONSUMES a fetched block's bytes
//! ([`BlockSync::on_block`]), driving a cycle-safe, bounded graph walk over the DAG edges the
//! [`StateMachine`] exposes through [`StateMachine::block_references`].
//!
//! # Walk
//!
//! Seeded at `root`, in discovery order: a discovered block the store already holds (and that hashes
//! back to its address) is walked LOCALLY without a fetch — so a laggard never re-pulls an unchanged
//! subtree it already has; a block the store is MISSING (or whose local bytes are corrupt, treated as
//! missing) is surfaced by `next_request`, and `on_block` verifies and writes the fetched bytes. A
//! corrupt block can therefore never advance state or have its edges followed.
//!
//! # Termination and bound
//!
//! The visited-set records every discovered address, so a block reachable by more than one path (a
//! diamond) is enqueued exactly once. A content-addressed DAG cannot encode a true reference cycle —
//! an address is the hash of content that would have to contain that address — but the visited-set
//! makes any multi-path graph terminate regardless. A per-sync [`MAX_REACHABLE_BLOCKS`] cap bounds a
//! malformed or foreign DAG, aborting with [`BlockSyncError::TooManyBlocks`] rather than fetching
//! unboundedly.

#[cfg(test)]
mod tests;

use core::marker::PhantomData;

use std::collections::{BTreeSet, VecDeque};

use bytes::Bytes;

use crate::{
  block_store::{BlockAddress, BlockStore, block_address, read_verified_block},
  state_machine::StateMachine,
};

/// The DAG-edge resolver a [`BlockSync`] walk uses: given a block's bytes, the child block addresses it
/// directly references. The proto syncs TWO content-addressed DAGs — the embedder's SM checkpoint
/// ([`SmRefs`] → [`StateMachine::block_references`]) and the proto's own client-session table
/// ([`SessionRefs`] → the session-table decoder) — whose block formats are UNRELATED. A content-
/// addressed DAG never cross-references between the two, so each is walked by its own resolver and one
/// frontier per DAG drains it exactly, rather than one ambiguous dispatcher guessing block kinds.
pub(crate) trait BlockRefs {
  /// The child addresses `block` directly references (an empty list for a leaf).
  fn references(block: &[u8]) -> std::vec::Vec<BlockAddress>;
}

/// [`BlockRefs`] over a [`StateMachine`]'s checkpoint DAG — forwards to
/// [`StateMachine::block_references`]. A zero-size marker carried only to fix `S` at the walk's
/// construction generation.
pub(crate) struct SmRefs<S>(PhantomData<fn() -> S>);

impl<S: StateMachine> BlockRefs for SmRefs<S> {
  fn references(block: &[u8]) -> std::vec::Vec<BlockAddress> {
    S::block_references(block)
  }
}

/// [`BlockRefs`] over the proto's client-session-table DAG — forwards to
/// [`session_blocks::session_block_references`](super::session_blocks::session_block_references).
pub(crate) struct SessionRefs;

impl BlockRefs for SessionRefs {
  fn references(block: &[u8]) -> std::vec::Vec<BlockAddress> {
    super::session_blocks::session_block_references(block)
  }
}

/// The maximum number of distinct blocks one sync may discover reachable from its root; crossing it
/// aborts with [`BlockSyncError::TooManyBlocks`].
///
/// Bounds the work a malformed or foreign DAG can induce: a checkpoint root that (by corruption or by
/// pointing at an unrelated graph) reaches far more blocks than any real checkpoint cannot drive an
/// unbounded fetch. Set far above any plausible real checkpoint block count.
pub(crate) const MAX_REACHABLE_BLOCKS: usize = 1 << 20;

/// The result of feeding a fetched block to [`BlockSync::on_block`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockOutcome {
  /// The block was the current outstanding frontier address: it was verified, written, and its
  /// children enqueued, and the walk advanced past it.
  Accepted,
  /// The block was NOT the current outstanding frontier address (a delayed response from a superseded
  /// transfer, or one answering a request the walk has moved past). It is INERT: nothing written, no
  /// children enqueued, frontier unchanged — the caller re-requests the actual front. Treating it as
  /// inert keeps an unrelated side DAG out of the active sync, which a write-and-enqueue would
  /// otherwise pull in and then stall or abort on.
  NonFrontier,
}

/// Why a [`BlockSync`] step failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BlockSyncError {
  /// A fetched block's bytes did not hash to the requested address, so it was rejected without being
  /// written or marked visited. The block remains re-requestable. A content-addressed store
  /// guarantees the correct bytes hash to the requested address; a mismatch is a corrupt, truncated,
  /// or misrouted transfer.
  #[error("fetched block hashes to {computed:?} but {requested:?} was requested")]
  AddressMismatch {
    /// The address that was requested (the address the bytes were expected to hash to).
    requested: BlockAddress,
    /// The address the supplied bytes actually hash to.
    computed: BlockAddress,
  },
  /// The set of blocks reachable from the root exceeded [`MAX_REACHABLE_BLOCKS`]. The DAG is
  /// malformed or foreign; the sync is aborted rather than fetching unboundedly.
  #[error("reachable block set exceeds the maximum of {MAX_REACHABLE_BLOCKS}")]
  TooManyBlocks,
}

/// A bounded, cycle-safe frontier that syncs the checkpoint DAG rooted at `root` into a
/// [`BlockStore`], fetching only the blocks the store is missing.
///
/// `R` is the [`BlockRefs`] resolver whose [`references`](BlockRefs::references) defines the DAG edges
/// (the SM checkpoint via [`SmRefs`], or the session table via [`SessionRefs`]); it is fixed at
/// construction (the DAG it walks) and carried as a zero-size marker. The store is supplied per call
/// rather than held, so one engine drives any [`BlockStore`].
pub(crate) struct BlockSync<R> {
  /// Discovered-but-not-yet-locally-processed addresses, in discovery order. The front is processed
  /// next: a PRESENT front is drained locally by `advance`; a MISSING front is what `next_request`
  /// surfaces and `on_block` consumes. Maintained so that after any `advance` the front (if any) is
  /// always a MISSING block.
  frontier: VecDeque<BlockAddress>,
  /// Every address ever discovered (enqueued). An address already here is never re-enqueued, which
  /// dedupes multi-path blocks, makes any graph terminate, and caps the walk at
  /// [`MAX_REACHABLE_BLOCKS`] distinct blocks.
  visited: BTreeSet<BlockAddress>,
  _refs: PhantomData<fn() -> R>,
}

// Hand-written so the `Debug` bound does not fall on `R` (the marker is `PhantomData<fn() -> R>`,
// which is `Debug` for any `R`); a derive would over-constrain `R: Debug`.
impl<R> core::fmt::Debug for BlockSync<R> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("BlockSync")
      .field("frontier", &self.frontier)
      .field("visited", &self.visited)
      .finish()
  }
}

impl<R> BlockSync<R> {
  /// Begins a sync of the DAG rooted at `root` — the only initially-discovered block.
  ///
  /// The walk is driven by pumping [`next_request`](Self::next_request) and feeding the result to
  /// [`on_block`](Self::on_block). Does not touch `R`, so it is callable without the `R: BlockRefs`
  /// bound the walk methods carry.
  pub(crate) fn new(root: BlockAddress) -> Self {
    let mut frontier = VecDeque::new();
    frontier.push_back(root);
    let mut visited = BTreeSet::new();
    visited.insert(root);
    Self {
      frontier,
      visited,
      _refs: PhantomData,
    }
  }

  /// Whether the frontier is drained (every reachable block present), reflecting the state left by the
  /// last [`next_request`](Self::next_request) / [`on_block`](Self::on_block).
  ///
  /// A test convenience for asserting the post-pump frontier; the driver uses `next_request() == None`
  /// (which itself drains) as the real completion signal.
  #[cfg(test)]
  pub(crate) fn is_complete(&self) -> bool {
    self.frontier.is_empty()
  }
}

impl<R: BlockRefs> BlockSync<R> {
  /// Returns the next MISSING block to fetch, or `None` when the sync is complete.
  ///
  /// First drains every PRESENT block at the front of the frontier — reading each from `store` and
  /// enqueueing its not-yet-visited children — so a subtree the store already holds is walked
  /// locally and never fetched. The first MISSING block encountered is returned (and left at the
  /// front, so repeated calls without an intervening successful `on_block` return the same address).
  /// `None` means every reachable block is present: the sync is complete.
  ///
  /// Returns [`BlockSyncError::TooManyBlocks`] if draining the present frontier discovers more than
  /// [`MAX_REACHABLE_BLOCKS`] blocks.
  pub(crate) fn next_request(
    &mut self,
    store: &dyn BlockStore,
  ) -> Result<Option<BlockAddress>, BlockSyncError> {
    self.advance(store)?;
    Ok(self.frontier.front().copied())
  }

  /// Accepts the bytes of a block fetched for the sync.
  ///
  /// `addr` must be the CURRENT outstanding frontier address — the value the last
  /// [`next_request`](Self::next_request) returned. Only that address is part of the active walk, so it
  /// is the gate: a block for any OTHER address is [`BlockOutcome::NonFrontier`] and INERT — nothing is
  /// written, no children are enqueued, the frontier is unchanged, and `next_request` still offers the
  /// real front. This rejects a delayed/superseded response (or one from a buggy member) that would
  /// otherwise graft an unrelated side DAG onto the active sync.
  ///
  /// For the frontier address, the bytes are verified against it ([`block_address`] of the bytes must
  /// equal `addr`); on mismatch the block is REJECTED — [`BlockSyncError::AddressMismatch`] is returned,
  /// the block is neither written nor marked processed, and `next_request` still offers `addr` (a
  /// corrupt block is re-requestable and cannot advance state). On success the block is written to
  /// `store`, its not-yet-visited children are enqueued, the walk advances, and [`BlockOutcome::Accepted`]
  /// is returned; any present children then at the front are drained.
  ///
  /// Returns [`BlockSyncError::TooManyBlocks`] if enqueueing this block's children, or draining the
  /// present frontier behind it, discovers more than [`MAX_REACHABLE_BLOCKS`] blocks.
  pub(crate) fn on_block(
    &mut self,
    addr: BlockAddress,
    bytes: Bytes,
    store: &mut dyn BlockStore,
  ) -> Result<BlockOutcome, BlockSyncError> {
    // Inert unless this is the address the walk is waiting on: writing an off-frontier block or
    // following its edges would graft a side DAG onto the active sync.
    if self.frontier.front() != Some(&addr) {
      return Ok(BlockOutcome::NonFrontier);
    }

    let computed = block_address(&bytes);
    if computed != addr {
      return Err(BlockSyncError::AddressMismatch {
        requested: addr,
        computed,
      });
    }

    // Read edges before writing. A later bound breach aborts the sync but harmlessly leaves this valid
    // block written.
    let children = R::references(&bytes);
    let stored = store.put(bytes);
    debug_assert_eq!(
      stored, addr,
      "put keys by content, and the bytes verified against addr"
    );

    // The front is now present: drop it, enqueue its children, and resume draining the front.
    self.frontier.pop_front();
    self.enqueue_children(&children)?;
    self.advance(&*store)?;
    Ok(BlockOutcome::Accepted)
  }

  /// Drains every PRESENT block at the front of the frontier: pop it, read it, enqueue its
  /// not-yet-visited children. Stops at the first MISSING block or when the frontier empties, so the
  /// post-condition is that the front (if any) is a MISSING block.
  ///
  /// "Present" means stored at the front address AND hashing back to it ([`read_verified_block`]). A
  /// corrupt block (bytes hash elsewhere) is treated as MISSING and left at the front, so the sync
  /// re-fetches it and `on_block`'s verified write replaces the corrupt bytes — its garbage edges are
  /// never followed.
  fn advance(&mut self, store: &dyn BlockStore) -> Result<(), BlockSyncError> {
    while let Some(&addr) = self.frontier.front() {
      let Some(bytes) = read_verified_block(store, addr) else {
        break; // front missing or corrupt — the next thing to fetch; leave it at the front.
      };
      self.frontier.pop_front();
      let children = R::references(&bytes);
      self.enqueue_children(&children)?;
    }
    Ok(())
  }

  /// Enqueues each not-yet-visited child, inserting it into the visited-set. A child already visited
  /// (reachable by another path) is skipped, so each block is discovered exactly once. Crossing
  /// [`MAX_REACHABLE_BLOCKS`] distinct discovered blocks aborts with
  /// [`BlockSyncError::TooManyBlocks`].
  fn enqueue_children(&mut self, children: &[BlockAddress]) -> Result<(), BlockSyncError> {
    for &child in children {
      if self.visited.insert(child) {
        if self.visited.len() > MAX_REACHABLE_BLOCKS {
          return Err(BlockSyncError::TooManyBlocks);
        }
        self.frontier.push_back(child);
      }
    }
    Ok(())
  }
}

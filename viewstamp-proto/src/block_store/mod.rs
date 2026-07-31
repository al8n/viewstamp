//! Content-addressed block storage primitives.
//!
//! A [`BlockAddress`] is the canonical identifier for a block of bytes: the address IS the content
//! hash, so two byte slices with identical content produce the same address and two with distinct
//! content produce distinct addresses (with overwhelming probability under FNV-1a-128). This
//! property lets the state-sync layer deduplicate and verify blocks without additional metadata.
//!
//! [`BlockStore`] is the embedder-supplied backing store for named blocks. It is content-addressed
//! by construction: [`BlockStore::put`] derives the key from the content INSIDE the store, so a
//! block can never be recorded under an address its bytes do not hash to.

use bytes::Bytes;

use crate::storage::fnv1a_128;

/// The content address of a block — its FNV-1a-128 hash encoded as 16 big-endian bytes.
///
/// The address is both an identifier and an integrity check: recomputing [`block_address`] on a
/// received block verifies the bytes were not corrupted or substituted in transit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockAddress([u8; 16]);

impl BlockAddress {
  /// Returns the address as its 16 raw bytes (big-endian FNV-1a-128 digest).
  pub const fn as_bytes(&self) -> &[u8; 16] {
    &self.0
  }

  /// Constructs a `BlockAddress` from 16 raw bytes.
  ///
  /// The caller is responsible for ensuring that `b` was produced by hashing the
  /// intended block with [`block_address`].
  pub const fn from_bytes(b: [u8; 16]) -> Self {
    Self(b)
  }
}

/// Returns the content address of `block`: its FNV-1a-128 digest in big-endian byte order.
pub fn block_address(block: &[u8]) -> BlockAddress {
  BlockAddress(fnv1a_128(block).to_be_bytes())
}

/// A [`BlockStore::flush`] durability barrier did not make the previously-written blocks durable.
///
/// The proto treats this exactly like the other storage faults: the checkpoint whose blocks failed
/// to flush is NOT installed (its superblock pointer is not advanced), so the durable checkpoint can
/// never name a block the store has not persisted, and the checkpoint is retried on the next cadence.
/// The opaque payload (`()`) keeps the proto agnostic to the backend's I/O error — a flush is a
/// pure "made durable / did not" verdict, not a typed cause channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("block store flush failed: previously written blocks are not durable")]
pub struct BlockStoreError(());

impl BlockStoreError {
  /// Constructs the flush-failed error.
  pub const fn new() -> Self {
    Self(())
  }
}

impl Default for BlockStoreError {
  fn default() -> Self {
    Self::new()
  }
}

/// One TYPED mark walk for [`BlockStore::gc`]: the live roots of a single block DAG paired with the
/// resolver that parses THAT DAG's blocks.
///
/// A shared block store holds more than one kind of DAG (the SM state DAG and the proto's
/// client-session DAG), each with its own block format and edge resolver. GC passes ONE walk per DAG
/// so each root set is followed by the resolver that understands its blocks — never the other DAG's.
/// Feeding a block to the wrong resolver (e.g. a session block to the SM's `block_references`) could
/// panic or return bogus edges in a strict parser, which is why the resolvers are kept SEPARATE rather
/// than unioned into one closure.
pub struct BlockDagWalk<'a> {
  roots: &'a [BlockAddress],
  references: &'a dyn Fn(&[u8]) -> std::vec::Vec<BlockAddress>,
}

impl<'a> BlockDagWalk<'a> {
  /// Pairs one DAG's live roots with the resolver that parses that DAG's blocks: `roots` are the
  /// live roots (a current durable checkpoint root and/or an in-flight sync target root), and
  /// `references` is the edge resolver for THIS DAG's block format — given a block's bytes it
  /// returns the direct child addresses, and it is only ever invoked on blocks reached from
  /// `roots`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    roots: &'a [BlockAddress],
    references: &'a dyn Fn(&[u8]) -> std::vec::Vec<BlockAddress>,
  ) -> Self {
    Self { roots, references }
  }

  /// The live roots of this DAG. Returns the descriptor's own 'a borrow (the fields are copies of
  /// caller-owned references), so a caller holding the walk by value can extract a slice that
  /// outlives it — exactly what the public fields allowed.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn roots(&self) -> &'a [BlockAddress] {
    self.roots
  }

  /// The edge resolver for this DAG's block format (the descriptor's own 'a borrow, as with
  /// [`Self::roots`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn references(&self) -> &'a dyn Fn(&[u8]) -> std::vec::Vec<BlockAddress> {
    self.references
  }
}

/// Reads the block at `addr`, returning it ONLY if its bytes hash back to `addr`.
///
/// A faithful block always satisfies `block_address(bytes) == addr`, so bytes hashing to a different
/// address are a mis-stored block (bit-rot, a misdirected write, a truncated payload), reported as
/// MISSING (`None`) exactly as if never written. The caller then re-fetches from a peer, and the
/// verified replacement re-keys the corrupt local bytes correctly.
///
/// This is the SINGLE verified-read predicate: every consumer that trusts a locally-read block (the
/// sync frontier's local fast path, the GC mark phase, the donor serve path, the SM-restore view
/// [`VerifiedView`]) reads THROUGH it, so a corrupt local block can never be trusted as a checkpoint
/// block, have its garbage edges followed, or be handed to `restore`.
pub(crate) fn read_verified_block(store: &dyn BlockStore, addr: BlockAddress) -> Option<Bytes> {
  let bytes = store.read_block(addr)?;
  (block_address(&bytes) == addr).then_some(bytes)
}

/// A read-only verify-on-read view over a [`BlockStore`], passed to
/// [`StateMachine::restore`](crate::StateMachine::restore) in place of the raw store so EVERY block
/// the SM reads is checked against its content address by construction.
///
/// The frontier walk verified each block as it drained but does not PIN the bytes, and the
/// restore runs later; a bit-rot or misdirected read in that window would otherwise hand corrupt
/// bytes to the SM under a valid checkpoint id. Through this view [`read_block`](Self::read_block)
/// returns `None` for a corrupt block (reads as absent), so the SM's missing-block handling surfaces a
/// [`RestoreError`](crate::state_machine::RestoreError) and the proto re-fetches the clean replacement.
///
/// Read-only BY TYPE: the view exposes only the verified read methods, so a restore cannot write,
/// flush, or GC through it.
pub struct VerifiedView<'a> {
  inner: &'a dyn BlockStore,
}

impl<'a> VerifiedView<'a> {
  /// Wraps `inner` in a verify-on-read view.
  pub fn new(inner: &'a dyn BlockStore) -> Self {
    Self { inner }
  }

  /// Returns the block at `addr` ONLY if its stored bytes hash back to `addr`; a missing OR corrupt
  /// block reads as `None`.
  pub fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    read_verified_block(self.inner, addr)
  }

  /// Whether a block is present AND verified at `addr`: a corrupt block is reported absent,
  /// consistent with [`read_block`](Self::read_block) returning `None` for it.
  pub fn has_block(&self, addr: BlockAddress) -> bool {
    read_verified_block(self.inner, addr).is_some()
  }
}

/// Embedder-supplied content-addressed block store.
///
/// The store maps [`BlockAddress`] keys to opaque byte payloads. The store itself derives every
/// key from the content it is handed ([`put`](Self::put)), so a block can never be recorded under
/// an address its bytes do not hash to — the mis-addressed-write class is closed at the trait
/// boundary rather than policed at every call site.
///
/// The trait is intentionally object-safe (`&mut dyn BlockStore` is valid) so the job executor can
/// hold it without a generic parameter.
pub trait BlockStore {
  /// Returns the block at `addr`, or `None` if it has never been written.
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes>;

  /// Stores `block` under its content address and returns that address.
  ///
  /// The implementation MUST key the block by [`block_address`]`(&block)` and return exactly that
  /// value — the address is derived INSIDE the store, so a caller cannot record bytes under a key
  /// they do not hash to. Storing byte-identical content twice is idempotent (same address, same
  /// bytes).
  ///
  /// `put` is INFALLIBLE and carries NO durability guarantee on its own — it only records the
  /// bytes (a real backend may buffer them). Durability is established by [`flush`](Self::flush):
  /// the job executor writes a checkpoint's whole block DAG with `put`, then `flush`es, and only a
  /// successful flush lets the endpoint submit the superblock pointer that names those blocks.
  fn put(&mut self, block: Bytes) -> BlockAddress;

  /// Durability barrier: when this returns `Ok(())`, EVERY block recorded by an earlier
  /// [`put`](Self::put) (since the last `flush`) is durable — it will survive a crash and is
  /// readable on restart, by this node, by a peer GC pass, and after the WAL below it is pruned.
  ///
  /// **The proto orders a `flush` BEFORE the superblock checkpoint pointer that names its blocks**, so
  /// a durable checkpoint pointer can never reference a block that is not yet durable. This is the
  /// block-store half of the durable checkpoint transaction (the superblock root is the other half):
  /// without it, a crash after the checkpoint pointer is durable but before the blocks are could strand
  /// committed state behind a pointer naming MISSING blocks. The Sans-I/O boundary is preserved — the
  /// proto sequences the calls, the embedder's `flush` supplies the real `fsync`/barrier.
  ///
  /// An `Err(`[`BlockStoreError`]`)` means the previously written blocks are NOT durable. The proto
  /// then does NOT advance the checkpoint pointer (no torn checkpoint that names un-flushed blocks) and
  /// retries the checkpoint on the next cadence — mirroring how a faulted read is treated as data.
  ///
  /// REQUIRED deliberately (no default body): the barrier is the load-bearing half of the durable
  /// checkpoint transaction, and a backend that inherited a silent `Ok(())` while buffering writes
  /// would publish checkpoint roots naming blocks a crash discards. An in-memory store is durable
  /// for the lifetime it models and returns `Ok(())` explicitly ([`InMemoryBlockStore`] does); a
  /// store backed by real media implements its `fsync`/barrier here.
  fn flush(&mut self) -> Result<(), BlockStoreError>;

  /// Returns `true` if a block has been written at `addr`.
  fn has_block(&self, addr: BlockAddress) -> bool;

  /// Prunes every block UNREACHABLE from the live roots (mark-and-sweep). `walks` is one TYPED
  /// [`BlockDagWalk`] per DAG the store holds (the SM state DAG and the proto's client-session DAG): the
  /// store marks the set reachable from EACH walk's `roots` using THAT walk's `references` resolver, then
  /// frees every held block in NONE of the marked sets. A block reachable from any walk's roots MUST be
  /// retained; every other block MAY be freed.
  ///
  /// **The walks are kept SEPARATE so each DAG's blocks are parsed only by their own resolver** — a
  /// session block is never handed to the SM's `block_references` (nor vice versa), which a strict
  /// parser could panic on or mis-resolve. An overriding sweep MUST give each walk its OWN per-traversal
  /// visited set and union the marked addresses into a SEPARATE sweep set: an address can be reachable in
  /// MORE THAN ONE walk (block bytes are opaque, so two DAGs can hold byte-identical — hence
  /// same-address — blocks), and a shared visited set would let the first walk's mark make a later walk
  /// SKIP its own resolver on that shared address, leaving children reachable only through the skipped
  /// resolver wrongly swept. With a per-walk visited set every walk runs its own resolver on a shared
  /// address, so each DAG's true children are always marked. Unioning the MARKED SETS is then GC-safe: a
  /// block reachable from any DAG survives, no block is followed by a foreign resolver, and over-marking
  /// only ever RETAINS — so a reachable block is never freed and a freed block is genuinely unreferenced
  /// by every DAG.
  ///
  /// The default is a NO-OP: a store with bounded capacity (or one that never GCs) is correct, just not
  /// space-optimal. Called only AFTER the durable checkpoint root that justifies the new live set has
  /// landed, so a freed block is provably unreferenced by any live checkpoint.
  ///
  /// An overriding sweep MUST confirm each block hashes back to the address it is stored under
  /// ([`block_address`]) BEFORE following its edges: a corrupt block's edges are garbage, and following
  /// them would free an arbitrary live block. A corrupt block's address must NOT be swept either — it
  /// is left for a later sync to re-fetch the verified replacement.
  ///
  /// A walk that reaches an address the store does NOT hold simply stops there — a partially-fetched
  /// DAG (a checkpoint transfer still pulling blocks) is the ordinary case. Blocks reachable ONLY
  /// THROUGH such a missing interior block are therefore unmarked, and MAY be swept. That is BENIGN and
  /// needs no special handling: presence is recomputed from what the store actually holds every time a
  /// transfer re-walks the frontier, so a swept descendant is simply re-fetched. It costs a round trip
  /// and can never corrupt a checkpoint — a durable root is published only over a DAG the store held
  /// whole at its barrier. [`InMemoryBlockStore`]'s sweep behaves exactly this way.
  fn gc(&mut self, walks: &[BlockDagWalk<'_>]) {
    let _ = walks;
  }
}

/// A volatile in-memory [`BlockStore`] backed by a `BTreeMap`.
///
/// Every `put` is recorded immediately and `flush` succeeds (in-memory content is durable for the
/// process lifetime it models), so it is a correct store for tests, simulations, and embedders
/// whose checkpoint content is reconstructible. Iteration order is deterministic (`BTreeMap` keyed
/// by address), which seeded harnesses rely on.
///
/// Fault injection for tests rides on the same type: [`script_flush_fault`](Self::script_flush_fault)
/// makes the next flushes fail so a harness can prove the checkpoint pointer is not advanced over
/// an unflushed DAG, and [`insert_raw`](Self::insert_raw) plants bytes under an arbitrary address
/// so verify-on-read paths can be exercised against corrupt blocks.
#[derive(Debug, Default, Clone)]
pub struct InMemoryBlockStore {
  blocks: std::collections::BTreeMap<BlockAddress, Bytes>,
  /// The next `flush_faults` calls to [`flush`](BlockStore::flush) return `Err` (the rest `Ok`),
  /// modelling a backend whose durability barrier fails. In-memory is otherwise always durable.
  flush_faults: u8,
}

impl InMemoryBlockStore {
  /// Creates an empty store.
  pub fn new() -> Self {
    Self::default()
  }

  /// Scripts the next `times` flushes to fail (return `Err(`[`BlockStoreError`]`)`), so a test can
  /// prove a flush fault holds the checkpoint pointer back.
  pub fn script_flush_fault(&mut self, times: u8) {
    self.flush_faults = times;
  }

  /// Plants `block` under `addr` WITHOUT deriving the address from the content — the
  /// fault-injection backdoor for tests that need a block whose bytes do NOT hash to its key
  /// (bit-rot, a misdirected write). Production writes go through [`BlockStore::put`], which makes
  /// this mismatch unrepresentable; a store poisoned through here exercises the verify-on-read
  /// paths that treat such a block as absent.
  pub fn insert_raw(&mut self, addr: BlockAddress, block: Bytes) {
    self.blocks.insert(addr, block);
  }

  /// The number of distinct blocks currently held (introspection for GC assertions).
  pub fn len(&self) -> usize {
    self.blocks.len()
  }

  /// Whether the store holds no blocks.
  pub fn is_empty(&self) -> bool {
    self.blocks.is_empty()
  }
}

impl BlockStore for InMemoryBlockStore {
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    self.blocks.get(&addr).cloned()
  }

  fn put(&mut self, block: Bytes) -> BlockAddress {
    let addr = block_address(&block);
    self.blocks.insert(addr, block);
    addr
  }

  fn flush(&mut self) -> Result<(), BlockStoreError> {
    if self.flush_faults > 0 {
      self.flush_faults -= 1;
      return Err(BlockStoreError::new());
    }
    Ok(()) // in-memory is durable: nothing to do on a successful barrier.
  }

  fn has_block(&self, addr: BlockAddress) -> bool {
    self.blocks.contains_key(&addr)
  }

  fn gc(&mut self, walks: &[BlockDagWalk<'_>]) {
    // Mark the union of the per-DAG reachable sets, then sweep every held block the mark did not reach.
    // Each walk follows ONLY its own resolver from its own roots — a block reached by the SM walk is
    // never handed to the session resolver (nor vice versa). The per-traversal `visited` guard is kept
    // SEPARATE from the union `reachable` set: a block address can be reachable in BOTH DAGs (block bytes
    // are opaque and content-addressed, so an SM block CAN be byte-identical to a session block, hence the
    // SAME address), and a shared visited set would let the first walk's mark make the second walk treat
    // that shared address as visited and SKIP its own resolver — leaving children reachable ONLY through
    // the skipped resolver unmarked and wrongly swept. With a per-walk `visited`, EACH walk runs its own
    // resolver on a shared address, so every DAG's true children are marked; the union only ever RETAINS
    // (over-marking is safe, under-marking is impossible). A corrupt block is marked reachable (so it
    // survives for a later sync to re-fetch) but its garbage edges are not followed.
    let mut reachable = std::collections::BTreeSet::new();
    for walk in walks {
      let mut visited = std::collections::BTreeSet::new();
      let mut stack: std::vec::Vec<BlockAddress> = walk.roots.to_vec();
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
    self.blocks.retain(|addr, _| reachable.contains(addr));
  }
}

#[cfg(test)]
mod tests;

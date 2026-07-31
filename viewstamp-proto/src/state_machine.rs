use bytes::Bytes;

use crate::{
  OpNumber,
  block_store::{BlockAddress, BlockStore, VerifiedView},
};

/// A block required by [`StateMachine::restore`] was missing from the store, or its stored bytes did
/// not hash back to the address that names it (restore reads through a verify-on-read view, so a
/// corrupt block reads as absent).
///
/// Returning this — rather than feeding unverified bytes to the SM or panicking — lets the proto
/// re-fetch a clean copy: a state-sync install re-solicits the checkpoint, a recovery restore
/// escalates to a peer block-fetch, and the restore retries. See [`restore`](StateMachine::restore)
/// for the discard semantics that make a returned error harmless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("checkpoint block {address:?} is missing or does not hash to its address")]
pub struct RestoreError {
  /// The address of the missing or corrupt block that aborted reconstruction.
  pub address: BlockAddress,
}

impl RestoreError {
  /// Constructs the error for a missing or corrupt block at `address`.
  pub const fn new(address: BlockAddress) -> Self {
    Self { address }
  }
}

/// The replicated application driven by the consensus log.
///
/// `apply` must be deterministic and side-effect-free apart from mutating `self`:
/// every replica applies the same committed ops in the same order and must reach
/// identical state.
///
/// The checkpoint methods support checkpoints + state-sync over a content-addressed block DAG
/// (TigerBeetle's grid model), split so that **no block I/O ever runs on the consensus pump**:
/// - [`checkpoint_image`](Self::checkpoint_image) CAPTURES a consistent image of the applied state
///   on the pump — a pure, in-memory snapshot with no storage access;
/// - [`materialize`](Self::materialize) WRITES that image into the embedder's [`BlockStore`] as a
///   DAG of immutable, content-addressed blocks and returns the root [`BlockAddress`] — executed
///   off the pump (the driver's storage lane) as part of a block job;
/// - [`block_references`](Self::block_references) exposes the DAG edges so a laggard walks the DAG
///   from the root and fetches ONLY the blocks it is missing (an unchanged subtree keeps its hash
///   and is never re-fetched);
/// - [`restore_seed`](Self::restore_seed) + [`restore`](Self::restore) rebuild the state from a
///   local store: the seed carries the instance CONFIGURATION (everything not derived from the
///   DAG), and `restore` — also executed off the pump — fills it from the checkpoint DAG. The
///   endpoint replaces its live SM with the restored seed only on success, so a failed restore can
///   never leave the live SM partially mutated.
///
/// The proto is agnostic to *how* the image is made incremental (copy-on-write, dirty-set, …): it
/// sees only `checkpoint_image -> materialize -> root`, the edges `block_references` exposes, and
/// `restore`.
///
/// **Embedder obligations** (correctness rests on these):
/// - **Stable serialization** — unchanged logical content MUST materialize to byte-identical blocks
///   (hence identical addresses), so a laggard recognizes and skips them. WITHOUT it, incrementality
///   silently degrades to a full re-fetch (correct but not incremental).
/// - **Bounded blocks** — every emitted block fits one transport frame.
pub trait StateMachine: Sized {
  /// A captured, self-contained image of the checkpointed state: everything
  /// [`materialize`](Self::materialize) needs to write the checkpoint DAG, detached from `self`.
  ///
  /// Captured on the consensus pump and carried into a storage job that may execute on another
  /// thread (`Send + 'static`), while the live SM keeps applying ops — so the image MUST be a
  /// value snapshot (shared immutable data such as [`Bytes`] is ideal), never a live borrow.
  type Image: Send + 'static;

  /// Applies a committed operation and returns the reply payload.
  ///
  /// **Reply-size bound (embedder obligation):** the returned reply must be at most
  /// [`max_reply_body_len`](crate::max_reply_body_len) bytes. The reply ships to the client as ONE
  /// `Reply` message, and a reply whose encoding exceeds the transport's frame cap is refused on the
  /// send path — with no in-protocol recovery, because the op is ALREADY COMMITTED by the time the
  /// reply exists (the request cannot be re-executed, and every resend of the cached reply re-fails
  /// the same way). The endpoint `debug_assert`s the bound at both apply sites, so a violation fails
  /// loudly in tests/sims; in release the over-bound reply is the embedder's bug to prevent, exactly
  /// as the driver-side `max_request_body_len()` bounds the request body at submit.
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes;

  /// Captures a consistent image of the SM's applied state, to be written into the block store by a
  /// later [`materialize`](Self::materialize).
  ///
  /// Runs ON the consensus pump, so it must perform NO storage I/O and should be cheap (share
  /// immutable structures; clone-on-write). `&self` receiver: the capture MUST NOT mutate the
  /// LOGICAL state — interior mutability for caches is permitted, but two captures with no
  /// intervening `apply` must produce images that materialize to byte-identical DAGs.
  ///
  /// The image reflects the applied prefix exactly at capture time: all ops applied so far, none
  /// after. The endpoint captures at a committed boundary, so the image is the checkpoint content
  /// for that boundary even though the SM keeps applying while the image is materialized.
  fn checkpoint_image(&self) -> Self::Image;

  /// Writes a captured image into `store` as content-addressed blocks and returns the root
  /// [`BlockAddress`] — the block-writing half of the old synchronous `checkpoint`, executed OFF
  /// the consensus pump (inside [`execute_block_job`](crate::execute_block_job) on the driver's
  /// storage lane).
  ///
  /// The root address is the stable identifier for this checkpoint generation: a syncing peer
  /// requests the root and then walks [`block_references`](Self::block_references) recursively to
  /// determine which blocks it is missing before fetching them. A trivial SM may write its whole
  /// image as one leaf block (and return an empty `block_references`); a structured SM writes a
  /// multi-block DAG so a peer fetching an incremental diff only transfers the changed subtrees.
  ///
  /// An associated function (no `&self`): the live SM is NOT available where the job executes, and
  /// everything the write needs must already be in the image. Durability is NOT this method's job —
  /// the executor flushes after materialize and the endpoint publishes the root only after that
  /// flush reports success.
  fn materialize(image: &Self::Image, store: &mut dyn BlockStore) -> BlockAddress;

  /// Returns the child [`BlockAddress`] values that `block` directly references (none for a leaf).
  ///
  /// The sync engine walks the DAG by calling this on each block it fetches to discover what to
  /// request next. The default returns an empty list — every block a leaf, correct for an SM that
  /// writes its whole state as one block. A structured SM that writes index or manifest blocks
  /// overrides this to expose the links embedded in those blocks.
  fn block_references(_block: &[u8]) -> std::vec::Vec<BlockAddress> {
    std::vec::Vec::new()
  }

  /// Returns a fresh instance carrying this SM's CONFIGURATION — everything that is not derived
  /// from the checkpoint DAG (mode flags, tuning, resources) — with EMPTY logical state, ready for
  /// [`restore`](Self::restore) to fill.
  ///
  /// Runs ON the pump (must be cheap, no I/O). The seed is carried into the restore job; the
  /// endpoint REPLACES its live SM with the restored seed only when `restore` succeeds, so the live
  /// SM is never touched by a failed restore — partial mutation of live state is structurally
  /// unrepresentable. For an SM whose type carries no configuration this is just `Self::default()`
  /// in spirit.
  fn restore_seed(&self) -> Self;

  /// Rebuilds SM state from the checkpoint DAG rooted at `root`, leaving `self` in exactly the
  /// state that produced the checkpoint — identical to the checkpointing replica's state at that
  /// generation. Executed OFF the consensus pump, and ONLY on a detached
  /// [`restore_seed`](Self::restore_seed) (never on the live SM), so on `Err` the whole seed is
  /// discarded — implementations need no internal atomicity discipline.
  ///
  /// `store` is a VERIFY-ON-READ view: every [`read_block`](VerifiedView::read_block) checks the
  /// bytes against their content address and returns `None` for a block that is missing OR whose
  /// stored bytes are corrupt (bit-rot, a misdirected write under a content-addressed key). The
  /// implementation MUST treat a `None` read as a fault and return [`RestoreError`] for that
  /// address rather than `unwrap`/`expect` or feed unverified bytes into its state — a corrupt
  /// block reaching the SM would rebuild committed state from garbage under a valid checkpoint id.
  /// The proto then re-fetches the offending block (state-sync re-solicits; recovery escalates to a
  /// peer block-fetch) and retries the restore against the repaired store.
  fn restore(&mut self, root: BlockAddress, store: &VerifiedView<'_>) -> Result<(), RestoreError>;
}

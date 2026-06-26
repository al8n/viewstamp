use bytes::Bytes;

use crate::{
  OpNumber,
  block_store::{BlockAddress, BlockStore},
};

/// A block required by [`StateMachine::restore`] was missing from the store, or its stored bytes did
/// not hash back to the address that names it (restore reads through a verify-on-read view, so a
/// corrupt block reads as absent).
///
/// Returning this — rather than feeding unverified bytes to the SM or panicking — lets the proto
/// re-fetch a clean copy: a state-sync install re-solicits the checkpoint, a recovery restore
/// escalates to a peer block-fetch, and the restore retries. See [`restore`](StateMachine::restore)
/// for the atomicity the SM must uphold when it returns this.
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
/// `checkpoint`, `block_references`, and `restore` support checkpoints + state-sync over a
/// content-addressed block DAG (TigerBeetle's grid model): a replica captures its applied state as a
/// DAG of immutable, content-addressed blocks in the embedder's [`BlockStore`] and returns the root
/// [`BlockAddress`]; a laggard walks the DAG from the root and fetches ONLY the blocks it is missing
/// (an unchanged subtree keeps its hash and is never re-fetched), then rebuilds from the local store.
/// The proto is agnostic to *how* `checkpoint` is made incremental (copy-on-write, dirty-set, …): it
/// sees only `checkpoint -> root`, the edges `block_references` exposes, and `restore(root, store)`.
///
/// **Embedder obligations** (correctness rests on these):
/// - **Stable serialization** — unchanged logical content MUST serialize to byte-identical blocks
///   (hence identical addresses), so a laggard recognizes and skips them. WITHOUT it, incrementality
///   silently degrades to a full re-fetch (correct but not incremental).
/// - **Bounded blocks** — every emitted block fits one transport frame.
pub trait StateMachine {
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

  /// Writes the SM's checkpointed state into `store` as content-addressed blocks and returns the
  /// root [`BlockAddress`].
  ///
  /// The root address is the stable identifier for this checkpoint generation: a syncing peer
  /// requests the root and then walks `block_references` recursively to determine which blocks it is
  /// missing before fetching them. A trivial SM may write its whole state as one leaf block (and
  /// return an empty `block_references`); a structured SM writes a multi-block DAG so a peer fetching
  /// an incremental diff only transfers the changed subtrees.
  fn checkpoint(&mut self, store: &mut dyn BlockStore) -> BlockAddress;

  /// Returns the child [`BlockAddress`] values that `block` directly references (none for a leaf).
  ///
  /// The sync engine walks the DAG by calling this on each block it fetches to discover what to
  /// request next. The default returns an empty list — every block a leaf, correct for an SM that
  /// writes its whole state as one block. A structured SM that writes index or manifest blocks
  /// overrides this to expose the links embedded in those blocks.
  fn block_references(_block: &[u8]) -> std::vec::Vec<BlockAddress> {
    std::vec::Vec::new()
  }

  /// Rebuilds SM state from the checkpoint DAG rooted at `root`, leaving the SM in exactly the state
  /// that produced the checkpoint — identical to the checkpointing replica's state at that generation.
  ///
  /// `store` is a VERIFY-ON-READ view: every `read_block` checks the bytes against their content
  /// address and returns `None` for a block that is missing OR whose stored bytes are corrupt (bit-rot,
  /// a misdirected write under a content-addressed key). The implementation MUST therefore treat a
  /// `None` read as a fault and return [`RestoreError`] for that address rather than `unwrap`/`expect`
  /// or feed unverified bytes into its state — a corrupt block reaching the SM would rebuild committed
  /// state from garbage under a valid checkpoint id. On `Ok(())` every block was present and verified.
  ///
  /// MUST be atomic against failure: reconstruct into a local value and assign it to `self` only after
  /// the whole DAG reads back successfully, so a returned error leaves the SM UNCHANGED. The proto then
  /// re-fetches the offending block (state-sync re-solicits; recovery escalates to a peer block-fetch)
  /// and retries the restore against the repaired store.
  fn restore(&mut self, root: BlockAddress, store: &dyn BlockStore) -> Result<(), RestoreError>;
}

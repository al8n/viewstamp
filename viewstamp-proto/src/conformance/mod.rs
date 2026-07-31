//! Conformance harnesses for the two embedder-supplied storage traits, [`BlockStore`] and
//! [`StateMachine`]: reusable checks a THIRD-PARTY implementation can run from its own test suite,
//! not just assertions this crate happens to make about [`InMemoryBlockStore`] or its own test
//! state machines.
//!
//! Each function panics (via `assert!`/`expect`) on the first contract violation it finds, so
//! calling one from inside a `#[test]` fn is the whole check: build the type under test, hand it
//! to the harness, and a clean return is the pass.

use bytes::Bytes;

use crate::{
  block_store::{BlockAddress, BlockStore, InMemoryBlockStore, VerifiedView, block_address},
  state_machine::StateMachine,
};

/// Checks the [`BlockStore`] flush-durability contract: stage every block in `blocks`, `flush`,
/// `reopen` the store, and confirm every block staged before the flush is still present — and
/// still hashes to the address it was returned under — through the reopened handle.
///
/// `reopen` is the caller's stand-in for "the store closes and is opened again": for a real
/// backend it should drop `store` (releasing file handles/locks exactly as a genuine close would)
/// and construct a fresh handle over the SAME backing media (e.g. `MyStore::open(&same_path)`).
/// Returns the reopened store so the caller can layer further assertions on it.
///
/// # What this proves
///
/// If `flush` returns `Ok`, every block `put` before it survives whatever `reopen` models — the
/// store's half of the durable-checkpoint transaction (see [`BlockStore::flush`]).
///
/// # What this does NOT prove
///
/// **An in-process reopen cannot prove real crash durability.** Everything here runs in one
/// process, on one live OS, with no power loss, kernel panic, torn write, or dropped page cache in
/// the mix. `reopen` is exactly as strong as the closure the caller supplies: a closure that drops
/// and rebuilds a Rust value without ever closing an OS file handle — relying on the process
/// itself staying alive to keep buffered writes intact — will pass a store that would lose data on
/// a genuine restart. A pass here is a NECESSARY property of a conforming store, never SUFFICIENT
/// evidence of crash durability; that needs kill-and-restart testing against the real medium (fault
/// injection, or an actual process boundary), which no in-process harness can exercise.
///
/// # Panics
///
/// Panics on the first violation: `blocks` is empty (the harness would prove nothing), `flush`
/// returns `Err`, or a pre-flush block is missing, reported absent, or hashes to a different
/// address after `reopen`.
pub fn assert_flush_then_reopen_preserves_blocks<S: BlockStore>(
  mut store: S,
  blocks: impl IntoIterator<Item = Bytes>,
  reopen: impl FnOnce(S) -> S,
) -> S {
  let mut addrs = std::vec::Vec::new();
  for block in blocks {
    addrs.push(store.put(block));
  }
  assert!(
    !addrs.is_empty(),
    "the harness needs at least one staged block — an empty `blocks` proves nothing"
  );
  store
    .flush()
    .expect("flush must return Ok before the harness reopens the store");

  let reopened = reopen(store);
  for addr in addrs {
    assert!(
      reopened.has_block(addr),
      "block {addr:?} staged before flush is reported absent after reopen"
    );
    let bytes = reopened
      .read_block(addr)
      .unwrap_or_else(|| panic!("block {addr:?} staged before flush is missing after reopen"));
    assert_eq!(
      block_address(&bytes),
      addr,
      "block {addr:?} read back after reopen does not hash to its own address"
    );
  }
  reopened
}

/// Checks the [`StateMachine`] restore contract against `sm`: (1)
/// [`checkpoint_image`](StateMachine::checkpoint_image) captures without mutating logical state,
/// and (2) restore behaves as a constructor — a failure never touches the checkpointing instance,
/// and a later attempt against a repaired store still succeeds.
///
/// Drives everything through [`InMemoryBlockStore`]: this harness checks the STATE MACHINE's
/// contract, not a `BlockStore`'s (see [`assert_flush_then_reopen_preserves_blocks`] for that), and
/// the in-memory store's [`insert_raw`](InMemoryBlockStore::insert_raw) backdoor is what lets it
/// manufacture a corrupt checkpoint deterministically, independent of which block a `restore`
/// implementation happens to read first.
///
/// `sm` should already carry whatever applied state makes its checkpoint non-trivial for the
/// implementation under test; an all-default instance still runs every check, it just exercises
/// less of the encoding.
///
/// # Panics
///
/// Panics on the first violation: two `checkpoint_image` captures with no intervening `apply`
/// materialize to different roots, a restore against an all-corrupt checkpoint unexpectedly
/// succeeds, the checkpointing instance's own checkpoint moves after that failed restore, or a
/// fresh restore against the repaired store fails or reconstructs a different root.
pub fn assert_restore_contract<S: StateMachine>(sm: &S) {
  let mut store = InMemoryBlockStore::new();

  // (1) Purity: two captures with no intervening `apply` must materialize to the identical root —
  // the documented `StateMachine::checkpoint_image` obligation.
  let root_1 = S::materialize(&sm.checkpoint_image(), &mut store);
  let root_2 = S::materialize(&sm.checkpoint_image(), &mut store);
  assert_eq!(
    root_1, root_2,
    "checkpoint_image must not mutate logical state: two captures with no intervening `apply` \
     materialized to different roots"
  );
  store
    .flush()
    .expect("flush must succeed before the harness attempts a restore");
  let root = root_1;

  // (2) restore is a constructor. Corrupt every block the checkpoint reaches — not just the root —
  // so whatever order the implementation reads them in, it hits a corrupt one.
  let corrupted = corrupt_every_reachable_block::<S>(&store, root);
  let mut seed = sm.restore_seed();
  seed
    .restore(root, &VerifiedView::new(&corrupted))
    .expect_err(
      "restore against a checkpoint whose every reachable block is corrupt must return Err",
    );

  // The checkpointing instance is untouched: re-checkpointing `sm` reaches the SAME root as
  // before — the failed restore ran only on the detached `seed`, never on `sm`.
  let root_after_failure = S::materialize(&sm.checkpoint_image(), &mut store);
  assert_eq!(
    root_after_failure, root,
    "a failed restore must never affect the checkpointing instance — restore runs only on a \
     detached `restore_seed()` value, never on `sm` itself"
  );

  // A fresh restore against the REPAIRED (uncorrupted) store still succeeds and reconstructs the
  // exact checkpointed root, proving the earlier failure left nothing poisoned.
  let mut fresh_seed = sm.restore_seed();
  fresh_seed
    .restore(root, &VerifiedView::new(&store))
    .expect("restore against the uncorrupted store must succeed after an unrelated failed attempt");
  let mut reconstructed_store = InMemoryBlockStore::new();
  let reconstructed_root = S::materialize(&fresh_seed.checkpoint_image(), &mut reconstructed_store);
  assert_eq!(
    reconstructed_root, root,
    "the restored instance must materialize back to the exact checkpointed root"
  );
}

/// Every address [`StateMachine::block_references`] reaches by walking from `root` over `clean`,
/// re-keyed to garbage bytes in a clone of `clean` — a corrupt checkpoint whose blocks fail
/// verification no matter which one a `restore` implementation reads first.
fn corrupt_every_reachable_block<S: StateMachine>(
  clean: &InMemoryBlockStore,
  root: BlockAddress,
) -> InMemoryBlockStore {
  let mut reachable = std::collections::BTreeSet::new();
  let mut stack = std::vec::Vec::new();
  stack.push(root);
  while let Some(addr) = stack.pop() {
    if !reachable.insert(addr) {
      continue; // already walked from another path to the same address.
    }
    if let Some(bytes) = clean.read_block(addr) {
      for child in S::block_references(&bytes) {
        stack.push(child);
      }
    }
  }

  let mut corrupted = clean.clone();
  for addr in reachable {
    corrupted.insert_raw(
      addr,
      Bytes::from_static(b"conformance-harness-injected-corruption"),
    );
  }
  corrupted
}

#[cfg(test)]
mod tests;

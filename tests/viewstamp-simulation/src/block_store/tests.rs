use std::collections::BTreeSet;

use bytes::Bytes;
use viewstamp_proto::{
  BlockAddress, BlockDagWalk, BlockStore, OpNumber, StateMachine, block_address,
};

use super::MemBlockStore;
use crate::sm::{LogSm, materialize_sm};

/// The reachable set from `root` over a [`LogSm`] checkpoint DAG, every block required present in
/// `store` (the proto contract that a sync frontier drains before reconstruction). Used by the GC
/// tests to name the expected survivor set independently of the GC walk itself.
fn reachable_from(root: BlockAddress, store: &MemBlockStore) -> BTreeSet<BlockAddress> {
  let mut seen = BTreeSet::new();
  let mut stack = vec![root];
  while let Some(addr) = stack.pop() {
    if !seen.insert(addr) {
      continue;
    }
    let block = store
      .read_block(addr)
      .expect("every reachable block is present in the store");
    for child in <LogSm as StateMachine>::block_references(&block) {
      stack.push(child);
    }
  }
  seen
}

/// Checkpoints `n` ops of an append-only [`LogSm`] into `store`, returning the root address. With
/// `DAG_LEAF_RUN == 4`, distinct `n` that share a full-leaf prefix produce DAGs that share those
/// earlier leaves verbatim (identical content addresses) — the incremental-checkpoint property GC
/// must respect.
fn checkpoint_log(n: u64, store: &mut MemBlockStore) -> BlockAddress {
  let mut sm = LogSm::default();
  for op in 1..=n {
    sm.apply(OpNumber::with(op), format!("body-{op}").as_bytes());
  }
  materialize_sm(&sm, store)
}

/// The `references` closure the proto hands `BlockStore::gc` (the SM's `block_references`).
fn log_refs(block: &[u8]) -> Vec<BlockAddress> {
  <LogSm as StateMachine>::block_references(block)
}

/// One typed mark walk over the SM DAG (`log_refs` resolver) for these single-DAG GC tests. The
/// proto passes a per-DAG walk; these tests exercise only the SM DAG, so they build the one walk.
fn sm_walk(roots: &[BlockAddress]) -> [BlockDagWalk<'_>; 1] {
  [BlockDagWalk::new(roots, &log_refs)]
}

#[test]
fn roundtrips_and_reports_membership() {
  let mut store = MemBlockStore::new();
  assert!(store.is_empty());

  let block = Bytes::from_static(b"a block");
  let addr = block_address(&block);

  assert!(!store.has_block(addr));
  assert_eq!(store.read_block(addr), None);

  assert_eq!(
    store.put(block.clone()),
    addr,
    "put returns the content address"
  );
  assert!(store.has_block(addr));
  assert_eq!(store.read_block(addr), Some(block));
  assert_eq!(store.len(), 1);
  assert!(!store.is_empty());
}

#[test]
fn idempotent_rewrite_keeps_one_entry() {
  let mut store = MemBlockStore::new();
  let block = Bytes::from_static(b"same bytes");
  store.put(block.clone());
  store.put(block);
  // Re-writing identical content under the same content address does not grow the store.
  assert_eq!(store.len(), 1);
}

#[test]
fn insert_raw_honours_caller_supplied_address() {
  // The fault-injection backdoor stores under exactly the given key (even one the bytes do not
  // hash to) — the mismatch `put` makes unrepresentable, needed to plant corrupt blocks.
  let mut store = MemBlockStore::new();
  let block = Bytes::from_static(b"explicit");
  let addr = block_address(b"a different key");
  store.insert_raw(addr, block.clone());
  assert_eq!(store.read_block(addr), Some(block));
}

#[test]
fn gc_keeps_a_shared_subtree_and_prunes_the_old_only_blocks() {
  // Two checkpoint DAGs that SHARE a subtree: an older root over 4 ops (one full leaf + the index)
  // and a newer root over 9 ops. The append-only log re-uses the first full leaf (ops 1..=4)
  // verbatim, so the newer DAG references the older DAG's leaf by identical content address — the
  // incremental-checkpoint property GC must respect.
  let mut store = MemBlockStore::new();
  let old_root = checkpoint_log(4, &mut store);
  let new_root = checkpoint_log(9, &mut store);

  let old_set = reachable_from(old_root, &store);
  let new_set = reachable_from(new_root, &store);
  assert_ne!(old_root, new_root, "distinct logs ⇒ distinct roots");

  // The shared subtree is non-empty (the ops-1..=4 leaf is common to both DAGs) and the older DAG
  // holds at least one block the newer one does not (its now-superseded index root).
  let shared: BTreeSet<_> = old_set.intersection(&new_set).copied().collect();
  let old_only: BTreeSet<_> = old_set.difference(&new_set).copied().collect();
  assert!(
    !shared.is_empty(),
    "the two DAGs must share the earlier full leaf"
  );
  assert!(
    !old_only.is_empty(),
    "the older DAG must hold a block the newer one does not (its old index root)"
  );

  // Before GC the store holds the UNION (every block of both DAGs is present).
  let union: BTreeSet<_> = old_set.union(&new_set).copied().collect();
  assert_eq!(
    store.len(),
    union.len(),
    "pre-GC the store holds both DAGs in full"
  );

  // GC with ONLY the newer root live (the old checkpoint was superseded).
  store.gc(&sm_walk(&[new_root]));

  // Exactly the newer DAG's reachable set survives — INCLUDING the shared subtree — and every
  // old-only block is gone.
  for &addr in &new_set {
    assert!(
      store.has_block(addr),
      "a block reachable from the live (newer) root was pruned: {addr:?}"
    );
  }
  for &addr in &shared {
    assert!(
      store.has_block(addr),
      "a SHARED-subtree block was pruned even though the live newer root references it: {addr:?}"
    );
  }
  for &addr in &old_only {
    assert!(
      !store.has_block(addr),
      "an old-only block unreachable from the live root survived GC: {addr:?}"
    );
  }
  assert_eq!(
    store.len(),
    new_set.len(),
    "exactly the newer DAG's reachable set survives — no more, no less"
  );

  // The survivor set still reconstructs the newer checkpoint faithfully (GC freed only dead blocks).
  let mut restored = LogSm::default();
  restored
    .restore(new_root, &viewstamp_proto::VerifiedView::new(&store))
    .expect("all blocks present after GC");
  assert_eq!(
    restored.applied().len(),
    9,
    "the GC'd store still reconstructs the live checkpoint"
  );
}

#[test]
fn gc_with_multiple_live_roots_retains_every_referenced_block() {
  // Two live roots over different (non-prefix) lengths keep the UNION of their reachable sets; a
  // third, superseded root's exclusive blocks are pruned.
  let mut store = MemBlockStore::new();
  let dead_root = checkpoint_log(2, &mut store); // one partial leaf + index
  let live_a = checkpoint_log(5, &mut store);
  let live_b = checkpoint_log(8, &mut store);

  let dead_set = reachable_from(dead_root, &store);
  let live_union: BTreeSet<_> = reachable_from(live_a, &store)
    .union(&reachable_from(live_b, &store))
    .copied()
    .collect();
  let dead_only: BTreeSet<_> = dead_set.difference(&live_union).copied().collect();
  assert!(
    !dead_only.is_empty(),
    "the superseded root must hold an exclusive block (its old index)"
  );

  store.gc(&sm_walk(&[live_a, live_b]));

  for &addr in &live_union {
    assert!(store.has_block(addr), "a live-union block was pruned");
  }
  for &addr in &dead_only {
    assert!(!store.has_block(addr), "a dead-only block survived GC");
  }
  assert_eq!(
    store.len(),
    live_union.len(),
    "exactly the live union survives"
  );
}

#[test]
fn gc_with_no_live_roots_prunes_everything() {
  let mut store = MemBlockStore::new();
  let _ = checkpoint_log(6, &mut store);
  assert!(!store.is_empty());
  // No live root ⇒ nothing is reachable ⇒ the whole store is freed. (The proto SKIPS calling `gc`
  // when it holds no durable root; this asserts the sweep itself frees the unreachable set.)
  store.gc(&sm_walk(&[]));
  assert!(store.is_empty(), "an empty live set prunes every block");
}

#[test]
fn gc_is_idempotent_and_a_no_op_when_nothing_is_unreachable() {
  let mut store = MemBlockStore::new();
  let root = checkpoint_log(7, &mut store);
  let before = store.len();
  store.gc(&sm_walk(&[root]));
  assert_eq!(
    store.len(),
    before,
    "GC over a fully-live store frees nothing"
  );
  store.gc(&sm_walk(&[root]));
  assert_eq!(store.len(), before, "a second GC is a no-op");
}

#[test]
fn gc_does_not_follow_a_corrupt_block_and_does_not_sweep_it() {
  // A held block whose bytes do not hash to its address is corrupt (bit-rot / a misdirected write).
  // The GC mark phase must NOT follow its (garbage) edges — doing so could mark an arbitrary live
  // block unreachable and free it — and must NOT sweep the corrupt block itself: it is left in place
  // for a later sync to re-fetch the verified replacement rather than silently dropped.
  let mut store = MemBlockStore::new();
  let root = checkpoint_log(9, &mut store); // a multi-leaf DAG: index root + several leaves.
  let set = reachable_from(root, &store);

  // Corrupt the INDEX root in place: overwrite its address with bytes that hash elsewhere. Its real
  // edges (to the leaves) become unfollowable. The leaves remain present and verified.
  let bogus = Bytes::from_static(b"corrupt index bytes");
  assert_ne!(block_address(&bogus), root);
  store.insert_raw(root, bogus); // mis-store under `root`.

  store.gc(&sm_walk(&[root]));

  // The corrupt root is RETAINED (marked reachable as a live root, never swept) so a re-fetch can
  // replace it; it was not silently dropped.
  assert!(
    store.has_block(root),
    "the corrupt live-root block must be retained for re-fetch, not swept"
  );
  // The leaves were reachable ONLY through the corrupt index's now-unfollowable edges, so a
  // best-effort GC may free them — that is liveness-only and self-heals on the next sync. The
  // load-bearing guarantee is that the GC did not PANIC or corrupt its own bookkeeping by following
  // garbage edges: every surviving block still hashes to its address.
  for &addr in &set {
    if let Some(bytes) = store.read_block(addr) {
      if addr == root {
        continue; // the deliberately-corrupt block.
      }
      assert_eq!(
        block_address(&bytes),
        addr,
        "a surviving block must still hash to its address"
      );
    }
  }
}

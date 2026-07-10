use super::*;
use crate::{OpNumber, RestoreError, state_machine::StateMachine, storage::fnv1a_128};

#[test]
fn address_is_fnv1a128_and_stable() {
  // Identical input produces identical address (content-addressable).
  assert_eq!(block_address(b"abc"), block_address(b"abc"));
  // Distinct input produces distinct address (collision-free for these inputs).
  assert_ne!(block_address(b"abc"), block_address(b"abd"));
  // The byte representation equals fnv1a_128 in big-endian order.
  assert_eq!(
    block_address(b"abc").as_bytes(),
    &fnv1a_128(b"abc").to_be_bytes()
  );
}

#[test]
fn mem_store_roundtrips_and_reports_membership() {
  let mut store = MemBlockStore::new();
  let block = bytes::Bytes::from_static(b"hello block");
  let addr = block_address(&block);

  // Before any write the address is absent.
  assert!(!store.has_block(addr));
  assert_eq!(store.read_block(addr), None);

  // write_verified keys by content hash and the block becomes retrievable.
  store.write_verified(block.clone());
  assert!(store.has_block(addr));
  assert_eq!(store.read_block(addr), Some(block));

  // A distinct address that was never written remains absent.
  let other_addr = block_address(b"other");
  assert!(!store.has_block(other_addr));
  assert_eq!(store.read_block(other_addr), None);
}

// A minimal StateMachine whose full state is a u64 counter.
struct TrivialSm {
  count: u64,
}

impl TrivialSm {
  fn snapshot(&self) -> bytes::Bytes {
    bytes::Bytes::copy_from_slice(&self.count.to_be_bytes())
  }
}

impl StateMachine for TrivialSm {
  fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> bytes::Bytes {
    self.count += 1;
    bytes::Bytes::new()
  }

  fn checkpoint(&mut self, store: &mut dyn BlockStore) -> BlockAddress {
    let block = self.snapshot();
    let addr = block_address(&block);
    store.write_block(addr, block);
    addr
  }

  fn restore(
    &mut self,
    root: BlockAddress,
    store: &dyn BlockStore,
  ) -> Result<(), crate::RestoreError> {
    let block = store
      .read_block(root)
      .ok_or(crate::RestoreError::new(root))?;
    self.count = u64::from_be_bytes(block[..].try_into().unwrap());
    Ok(())
  }
}

/// Encodes a test index block: a `0x01` tag, the child count as `u32-be`, then each child address
/// (16 bytes). A leaf block is any payload NOT starting with this tag.
fn index_block(children: &[BlockAddress]) -> bytes::Bytes {
  let mut out = std::vec::Vec::new();
  out.push(0x01u8);
  out.extend_from_slice(&(children.len() as u32).to_be_bytes());
  for c in children {
    out.extend_from_slice(c.as_bytes());
  }
  bytes::Bytes::from(out)
}

/// The child addresses a test block references: an index block yields its child list; any other
/// block is a leaf with no references. The closure `gc` is handed in production (the SM's
/// `block_references`).
fn test_refs(block: &[u8]) -> std::vec::Vec<BlockAddress> {
  if block.first() == Some(&0x01) {
    let count = u32::from_be_bytes(block[1..5].try_into().unwrap()) as usize;
    let mut refs = std::vec::Vec::with_capacity(count);
    let mut i = 5usize;
    for _ in 0..count {
      let mut raw = [0u8; 16];
      raw.copy_from_slice(&block[i..i + 16]);
      refs.push(BlockAddress::from_bytes(raw));
      i += 16;
    }
    refs
  } else {
    std::vec::Vec::new()
  }
}

#[test]
fn gc_marks_from_live_roots_keeps_shared_subtree_and_sweeps_the_rest() {
  let mut store = MemBlockStore::new();
  // A shared leaf, plus two roots that both reference it. The OLD root also references an
  // old-only leaf; the NEW root references a new-only leaf. The shared leaf is the subtree both
  // DAGs hold by identical content address (incremental checkpointing's defining property).
  let shared = bytes::Bytes::from_static(b"shared-leaf");
  let old_only = bytes::Bytes::from_static(b"old-only-leaf");
  let new_only = bytes::Bytes::from_static(b"new-only-leaf");
  let (shared_a, old_a, new_a) = (
    block_address(&shared),
    block_address(&old_only),
    block_address(&new_only),
  );
  store.write_verified(shared.clone());
  store.write_verified(old_only);
  store.write_verified(new_only.clone());

  let old_index = index_block(&[shared_a, old_a]);
  let new_index = index_block(&[shared_a, new_a]);
  let (old_root, new_root) = (block_address(&old_index), block_address(&new_index));
  store.write_block(old_root, old_index);
  store.write_block(new_root, new_index);
  assert_eq!(store.len(), 5, "two indexes + three leaves");

  // GC with ONLY the newer root live (one DAG → one typed walk).
  store.gc(&[BlockDagWalk::new(&[new_root], &test_refs)]);

  // The newer DAG — root, shared leaf, new-only leaf — survives; the old root and its exclusive
  // leaf are pruned.
  assert!(store.has_block(new_root), "the live root survives");
  assert!(store.has_block(shared_a), "the SHARED subtree survives");
  assert!(store.has_block(new_a), "the new-only leaf survives");
  assert!(!store.has_block(old_root), "the superseded root is pruned");
  assert!(!store.has_block(old_a), "the old-only leaf is pruned");
  assert_eq!(
    store.len(),
    3,
    "exactly the newer DAG's reachable set survives"
  );

  // A restore from the live root still reads its blocks (GC freed only unreachable bytes).
  assert_eq!(store.read_block(new_root).unwrap()[0], 0x01);
  assert_eq!(store.read_block(shared_a), Some(shared));
  assert_eq!(store.read_block(new_a), Some(new_only));
}

#[test]
fn gc_with_no_live_roots_frees_every_block() {
  let mut store = MemBlockStore::new();
  store.write_verified(bytes::Bytes::from_static(b"a"));
  store.write_verified(bytes::Bytes::from_static(b"b"));
  assert_eq!(store.len(), 2);
  store.gc(&[BlockDagWalk::new(&[], &test_refs)]);
  assert_eq!(store.len(), 0, "an empty live set prunes every block");
}

#[test]
fn gc_runs_each_dag_with_only_its_own_resolver_and_unions_the_marked_sets() {
  // The TWO-WALK contract: a shared store holding two DAGs (e.g. the SM state DAG and the proto
  // session DAG) GC's each from its own roots with its OWN resolver, never the other's. A resolver
  // handed a foreign block could panic in a strict parser — so this models that exactly: each
  // resolver PANICS if it is ever called on a block belonging to the OTHER DAG. GC must still mark
  // (the union of) both reachable sets and sweep only the genuinely-unreferenced block.
  let mut store = MemBlockStore::new();
  // DAG A: index `a_root` → leaf `a_leaf`. DAG B: index `b_root` → leaf `b_leaf`. The two index
  // blocks are byte-distinct (different children), so they have distinct addresses; a `dead` leaf is
  // reachable from NEITHER and must be swept.
  let a_leaf = bytes::Bytes::from_static(b"A-leaf");
  let b_leaf = bytes::Bytes::from_static(b"B-leaf");
  let dead = bytes::Bytes::from_static(b"DEAD-leaf");
  let (a_leaf_a, b_leaf_a, dead_a) = (
    block_address(&a_leaf),
    block_address(&b_leaf),
    block_address(&dead),
  );
  store.write_verified(a_leaf.clone());
  store.write_verified(b_leaf.clone());
  store.write_verified(dead);
  let a_index = index_block(&[a_leaf_a]);
  let b_index = index_block(&[b_leaf_a]);
  let (a_root, b_root) = (block_address(&a_index), block_address(&b_index));
  store.write_block(a_root, a_index);
  store.write_block(b_root, b_index);
  assert_eq!(
    store.len(),
    5,
    "two indexes + two live leaves + one dead leaf"
  );

  // Resolvers that prove each DAG's blocks are parsed ONLY by their own walk: each accepts only the
  // index/leaf addresses of ITS DAG and panics on the other's — so a single mark pass would blow up.
  let a_refs = |block: &[u8]| -> std::vec::Vec<BlockAddress> {
    let refs = test_refs(block);
    assert!(
      !refs.contains(&b_leaf_a),
      "DAG A's resolver must never see a DAG B block"
    );
    refs
  };
  let b_refs = |block: &[u8]| -> std::vec::Vec<BlockAddress> {
    let refs = test_refs(block);
    assert!(
      !refs.contains(&a_leaf_a),
      "DAG B's resolver must never see a DAG A block"
    );
    refs
  };

  store.gc(&[
    BlockDagWalk::new(&[a_root], &a_refs),
    BlockDagWalk::new(&[b_root], &b_refs),
  ]);

  // Both DAGs' reachable sets survive (the UNION of the marked sets); only the unreferenced leaf is freed.
  assert!(
    store.has_block(a_root) && store.has_block(a_leaf_a),
    "DAG A survives"
  );
  assert!(
    store.has_block(b_root) && store.has_block(b_leaf_a),
    "DAG B survives"
  );
  assert!(
    !store.has_block(dead_a),
    "the leaf reachable from neither DAG is swept"
  );
  assert_eq!(
    store.len(),
    4,
    "exactly the union of both DAGs' reachable sets survives"
  );
}

#[test]
fn gc_retains_session_only_children_of_a_block_also_reachable_from_the_sm_dag() {
  // The under-mark hazard a SHARED visited set would create: one block address is reachable from BOTH
  // DAG roots (block bytes are opaque + content-addressed, so an SM block CAN be byte-identical to a
  // session block — the same address). The two DAGs' resolvers parse those same bytes DIFFERENTLY: the
  // SM resolver reads the shared block as an opaque LEAF (no edges), while the session resolver reads it
  // as an INDEX whose child is a SESSION-ONLY leaf. If the SM walk marks the shared address first and the
  // session walk then treats it as visited and SKIPS its own resolver, the session-only child is never
  // marked and gets wrongly swept even though it is live under the durable checkpoint. With a per-walk
  // visited set the session walk runs its OWN resolver on the shared address, so its child is marked.
  let mut store = MemBlockStore::new();
  // The session-only leaf, reachable ONLY through the session resolver's view of the shared block.
  let session_child = bytes::Bytes::from_static(b"session-only-child-leaf");
  let session_child_a = block_address(&session_child);
  store.write_verified(session_child.clone());
  // The SHARED block: under `test_refs` (an index whose tag byte is 0x01) it is a session INDEX listing
  // `session_child`; the SM resolver below deliberately reads the SAME bytes as a leaf (returns nothing),
  // modelling two parsers that disagree on opaque bytes. It is the SM root AND the session root at once.
  let shared_index = index_block(&[session_child_a]);
  let shared_root = block_address(&shared_index);
  store.write_block(shared_root, shared_index);
  assert_eq!(
    store.len(),
    2,
    "the shared index block + its session-only child"
  );

  // The SM resolver treats EVERY block as an opaque leaf (no edges) — it never sees the session child.
  let sm_refs = |_block: &[u8]| -> std::vec::Vec<BlockAddress> { std::vec::Vec::new() };
  // The session resolver parses the index and yields the session-only child.
  let session_refs = test_refs;

  // SM walk listed FIRST so it marks the shared address before the session walk reaches it (the order
  // that triggers the under-mark under a shared visited set).
  store.gc(&[
    BlockDagWalk::new(&[shared_root], &sm_refs),
    BlockDagWalk::new(&[shared_root], &session_refs),
  ]);

  assert!(
    store.has_block(shared_root),
    "the shared root is reachable from both DAGs and survives"
  );
  assert!(
    store.has_block(session_child_a),
    "the session-only child (reachable ONLY through the session resolver of the shared block) must be \
     retained — a shared visited set would have skipped the session walk's resolver and swept it"
  );
  assert_eq!(store.len(), 2, "no reachable block is freed");
}

#[test]
fn checkpoint_produces_snapshot_address_and_restore_reconstructs() {
  let mut sm = TrivialSm { count: 42 };
  let mut store = MemBlockStore::new();

  // checkpoint writes the snapshot as a single leaf block; the returned root equals
  // block_address(snapshot()).
  let expected_root = block_address(&sm.snapshot());
  let root = sm.checkpoint(&mut store);
  assert_eq!(root, expected_root);

  // The block is retrievable from the store.
  assert!(store.has_block(root));

  // A fresh SM reconstructed from the checkpoint root reaches the same state.
  let mut fresh = TrivialSm { count: 0 };
  fresh
    .restore(root, &store)
    .expect("the whole DAG is present");
  assert_eq!(fresh.count, 42);

  // The default implementation treats every block as a leaf with no child references.
  let leaf_bytes = store.read_block(root).unwrap();
  let refs = TrivialSm::block_references(&leaf_bytes);
  assert!(refs.is_empty());
}

#[test]
fn verified_blocks_rejects_corrupt_block_and_passes_clean_block() {
  // VerifiedBlocks wraps a store and makes read_block return Some only when the block's bytes
  // hash back to the requested address. A block whose stored bytes do not hash to its key is
  // corrupt (bit-rot or a misdirected write); reading it through the view returns None, so
  // StateMachine::restore surfaces a RestoreError rather than feeding corrupt bytes to the SM.
  // A non-corrupt block reads through normally and restore succeeds.

  // --- Part A: a corrupt block returns RestoreError; SM is left unchanged. ---

  // Build and checkpoint the SM (count = 7).
  let mut sm = TrivialSm { count: 7 };
  let mut store = MemBlockStore::new();
  let root = sm.checkpoint(&mut store);

  // Overwrite the root address with bytes that do NOT hash to root — simulating bit-rot.
  let garbage = bytes::Bytes::from_static(b"garbage-that-does-not-hash-to-root");
  assert_ne!(
    block_address(&garbage),
    root,
    "sanity: garbage hashes elsewhere"
  );
  store.write_block(root, garbage);
  assert!(
    store.has_block(root),
    "the corrupt block is present in the raw store"
  );
  // Raw read returns the garbage bytes — the store does NOT verify.
  assert_eq!(
    block_address(&store.read_block(root).unwrap()),
    block_address(b"garbage-that-does-not-hash-to-root")
  );

  // Restore through VerifiedBlocks: the corrupt block reads as None, so the SM returns Err.
  let mut fresh = TrivialSm { count: 0 };
  let verified = VerifiedBlocks::new(&store);
  let err = fresh
    .restore(root, &verified)
    .expect_err("corrupt block through VerifiedBlocks must surface RestoreError");
  assert_eq!(err, RestoreError::new(root));
  // SM is left unchanged: count stays 0, not 7.
  assert_eq!(
    fresh.count, 0,
    "SM must be unchanged when restore returns Err"
  );

  // --- Part B: a clean block reads through and restore succeeds. ---

  let mut sm2 = TrivialSm { count: 99 };
  let mut store2 = MemBlockStore::new();
  let root2 = sm2.checkpoint(&mut store2);
  // The block IS correctly keyed: block_address(bytes) == root2.
  let good_bytes = store2.read_block(root2).unwrap();
  assert_eq!(
    block_address(&good_bytes),
    root2,
    "sanity: clean block hashes correctly"
  );

  let mut fresh2 = TrivialSm { count: 0 };
  let verified2 = VerifiedBlocks::new(&store2);
  fresh2
    .restore(root2, &verified2)
    .expect("clean block through VerifiedBlocks must restore successfully");
  assert_eq!(
    fresh2.count, 99,
    "restored SM reaches the checkpointed state"
  );
}

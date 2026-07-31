use std::collections::BTreeSet;

use super::*;
use crate::{
  OpNumber,
  block_store::{InMemoryBlockStore, block_address},
  state_machine::StateMachine,
};

// A tiny test block format: a 1-byte tag (`b'L'` leaf, `b'I'` internal) followed by zero or more
// child addresses, each 16 raw bytes. `block_references` parses the trailing addresses; a leaf
// (tag `b'L'`, or any block shorter than one address) yields none. The tag is decorative — it lets
// distinct blocks have distinct content (hence distinct addresses) so a DAG's blocks do not collide.
fn block(tag: u8, children: &[BlockAddress]) -> Bytes {
  let mut buf = std::vec::Vec::with_capacity(1 + children.len() * 16);
  buf.push(tag);
  for c in children {
    buf.extend_from_slice(c.as_bytes());
  }
  Bytes::from(buf)
}

fn leaf(tag: u8) -> Bytes {
  block(tag, &[])
}

// A StateMachine whose `block_references` parses the test block format above. Only `block_references`
// is exercised by the sync engine; the apply/checkpoint/restore methods are inert stubs.
struct DagSm;

impl StateMachine for DagSm {
  type Image = ();

  fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> Bytes {
    Bytes::new()
  }

  fn checkpoint_image(&self) -> Self::Image {}

  fn materialize(_image: &Self::Image, store: &mut dyn BlockStore) -> BlockAddress {
    store.put(Bytes::new())
  }

  fn restore_seed(&self) -> Self {
    DagSm
  }

  fn restore(
    &mut self,
    root: BlockAddress,
    store: &crate::VerifiedView<'_>,
  ) -> Result<(), crate::RestoreError> {
    store
      .read_block(root)
      .map(|_| ())
      .ok_or(crate::RestoreError::new(root))
  }

  fn block_references(block: &[u8]) -> std::vec::Vec<BlockAddress> {
    // Tag byte, then a sequence of 16-byte child addresses. A block too short to hold the tag, or
    // whose payload is not a whole number of addresses, contributes only its whole addresses.
    let payload = match block.split_first() {
      Some((_tag, rest)) => rest,
      None => return std::vec::Vec::new(),
    };
    payload
      .as_chunks::<16>()
      .0
      .iter()
      .map(|&a| BlockAddress::from_bytes(a))
      .collect()
  }
}

// Drives a `BlockSync` to completion, pulling every requested block from `donor` and feeding it via
// `on_block` into `laggard`. Records every requested address in order. Panics if a requested block is
// absent from the donor (a test-DAG construction error) or if `on_block` rejects a donor-faithful
// block. Returns the ordered list of requested addresses.
fn drive(
  sync: &mut BlockSync<SmRefs<DagSm>>,
  donor: &InMemoryBlockStore,
  laggard: &mut InMemoryBlockStore,
) -> std::vec::Vec<BlockAddress> {
  let mut requested = std::vec::Vec::new();
  while let Some(addr) = sync
    .next_request(laggard)
    .expect("the walk stays within the reachable bound")
  {
    requested.push(addr);
    let bytes = donor
      .read_block(addr)
      .expect("donor holds every reachable block");
    sync
      .on_block(addr, bytes, laggard)
      .expect("a donor-faithful block verifies");
  }
  requested
}

// Builds a fixed multi-level DAG into `store` and returns (root, [all addresses]). Shape:
//
//        root(I) ── a(I) ── x(L)
//          │         └───── y(L)
//          └─────── b(L)
//
// `a` is an internal node over two leaves; `b` is a leaf. Both hang off the root.
fn build_dag(store: &mut InMemoryBlockStore) -> (BlockAddress, [BlockAddress; 5]) {
  let x = leaf(b'x');
  let y = leaf(b'y');
  let xa = block_address(&x);
  let ya = block_address(&y);

  let a = block(b'A', &[xa, ya]);
  let aa = block_address(&a);

  let b = leaf(b'b');
  let ba = block_address(&b);

  let root = block(b'R', &[aa, ba]);
  let roota = block_address(&root);

  store.put(x);
  store.put(y);
  store.put(a);
  store.put(b);
  store.put(root);

  (roota, [roota, aa, ba, xa, ya])
}

#[test]
fn frontier_walks_dag_fetching_only_missing() {
  let mut donor = InMemoryBlockStore::new();
  let (root, [roota, aa, ba, xa, ya]) = build_dag(&mut donor);

  // The laggard already holds the `a` subtree unchanged: a, x, y. It is missing only root and b.
  let mut laggard = InMemoryBlockStore::new();
  laggard.put(donor.read_block(aa).unwrap());
  laggard.put(donor.read_block(xa).unwrap());
  laggard.put(donor.read_block(ya).unwrap());

  let mut sync = BlockSync::<SmRefs<DagSm>>::new(root);
  assert!(!sync.is_complete());

  let requested = drive(&mut sync, &donor, &mut laggard);

  // ONLY the two missing blocks are requested; the pre-held subtree (a, x, y) is never pulled.
  let req_set: BTreeSet<_> = requested.iter().copied().collect();
  assert_eq!(req_set, BTreeSet::from([roota, ba]));
  assert!(
    !requested.contains(&aa),
    "pre-held internal node re-fetched"
  );
  assert!(!requested.contains(&xa), "pre-held leaf re-fetched");
  assert!(!requested.contains(&ya), "pre-held leaf re-fetched");

  // The sync completes and the laggard ends holding the entire reachable set.
  assert!(sync.is_complete());
  assert_eq!(sync.next_request(&laggard), Ok(None));
  for addr in [roota, aa, ba, xa, ya] {
    assert!(laggard.has_block(addr), "laggard missing a reachable block");
  }
}

#[test]
fn corrupted_block_is_rejected_and_re_requested() {
  let mut donor = InMemoryBlockStore::new();
  let (root, _all) = build_dag(&mut donor);

  let mut laggard = InMemoryBlockStore::new();
  let mut sync = BlockSync::<SmRefs<DagSm>>::new(root);

  // The first requested block is the root (the only thing the empty laggard can ask for first).
  let addr = sync
    .next_request(&laggard)
    .expect("the walk stays within the reachable bound")
    .expect("root is requested first");
  assert_eq!(addr, root);

  // Feeding bytes that hash to a DIFFERENT address than requested is rejected.
  let wrong = leaf(b'!');
  assert_ne!(block_address(&wrong), addr);
  let err = sync
    .on_block(addr, wrong, &mut laggard)
    .expect_err("a mismatched block is rejected");
  assert_eq!(
    err,
    BlockSyncError::AddressMismatch {
      requested: addr,
      computed: block_address(&leaf(b'!')),
    }
  );

  // The corrupt block is NOT written, NOT marked visited: the same address is still requested.
  assert!(!laggard.has_block(addr), "rejected block was written");
  assert!(!sync.is_complete());
  assert_eq!(
    sync.next_request(&laggard),
    Ok(Some(addr)),
    "rejected block stays re-requestable"
  );

  // Re-requesting and feeding the CORRECT bytes now advances the walk.
  let good = donor.read_block(addr).unwrap();
  sync
    .on_block(addr, good, &mut laggard)
    .expect("the correct block verifies");
  assert!(laggard.has_block(addr));
}

#[test]
fn locally_corrupt_block_is_treated_as_missing_and_re_fetched() {
  // The local fast path (`advance`, reached through `next_request`) must NOT trust a locally-stored
  // block on its presence alone: a block whose stored bytes do not hash to its address is corrupt
  // (bit-rot, a misdirected write under a content-addressed key) and is treated as MISSING, so the
  // sync re-fetches it from a peer and `on_block`'s verified write overwrites the corrupt bytes. This
  // is the state-sync / recovery local-DAG drain, which restores SM state directly from the store.

  let mut donor = InMemoryBlockStore::new();
  let (root, [roota, aa, ba, xa, ya]) = build_dag(&mut donor);

  // The laggard holds the WHOLE DAG, so a presence-only fast path would drain immediately and report
  // the sync complete. But one interior leaf, `x`, is MIS-STORED: bytes that do not hash to `xa` are
  // written under `xa` (a content-address violation a disk fault produces). The block is "present" but
  // corrupt.
  let mut laggard = InMemoryBlockStore::new();
  for addr in [roota, aa, ba, ya] {
    laggard.put(donor.read_block(addr).unwrap());
  }
  let corrupt = leaf(b'#'); // distinct content, so it does not hash to `xa`.
  assert_ne!(block_address(&corrupt), xa);
  laggard.insert_raw(xa, corrupt); // mis-store: bytes at `xa` that hash elsewhere.
  assert!(
    laggard.has_block(xa),
    "the corrupt block is locally present"
  );

  // A presence-only walk would see `xa` present and complete; the verifying walk surfaces `xa` as the
  // one block to fetch (its parent `aa` is verified-present, so its edge to `xa` is followed; `xa`'s
  // stored bytes fail verification, so it is the missing front).
  let mut sync = BlockSync::<SmRefs<DagSm>>::new(root);
  let next = sync
    .next_request(&laggard)
    .expect("the walk stays within the reachable bound");
  assert_eq!(
    next,
    Some(xa),
    "the corrupt local block must be surfaced as the block to fetch, not silently accepted"
  );

  // Feeding the CLEAN replacement (the donor's faithful `x`) overwrites the corrupt local bytes — a
  // content-addressed re-key — and the walk drains to complete.
  let clean = donor.read_block(xa).unwrap();
  assert_eq!(block_address(&clean), xa);
  sync
    .on_block(xa, clean.clone(), &mut laggard)
    .expect("the clean replacement verifies");

  assert_eq!(
    sync.next_request(&laggard),
    Ok(None),
    "after the clean re-fetch the DAG drains to complete"
  );
  assert!(sync.is_complete());
  // The store now holds the VERIFIED block at `xa`: the corrupt bytes were overwritten, every block
  // hashes to its address, and the reconstructed DAG is correct.
  assert_eq!(laggard.read_block(xa), Some(clean));
  for addr in [roota, aa, ba, xa, ya] {
    let bytes = laggard.read_block(addr).expect("reachable block present");
    assert_eq!(
      block_address(&bytes),
      addr,
      "every reconstructed block hashes to its address"
    );
  }
}

#[test]
fn off_frontier_block_is_inert() {
  // A response whose address is NOT the current frontier front must be inert: nothing written,
  // no children enqueued, frontier front unchanged, next_request still returns the real front.
  // After the inert response, completing the sync via the real front must converge.
  let mut donor = InMemoryBlockStore::new();
  let (root, [roota, aa, ba, xa, ya]) = build_dag(&mut donor);

  let mut laggard = InMemoryBlockStore::new();
  let mut sync = BlockSync::<SmRefs<DagSm>>::new(root);

  // Pump once: the only requested block is the root (empty laggard, nothing locally present).
  let front = sync
    .next_request(&laggard)
    .expect("walk stays within bound")
    .expect("root is requested first");
  assert_eq!(front, roota);

  // Feed a VALID block — one that hashes correctly to its own address — but for an address that
  // is NOT the current frontier front. Use the leaf `b` (already in the donor, correct bytes).
  assert_ne!(ba, roota, "sanity: ba != roota, so it is off-frontier");
  let off_bytes = donor.read_block(ba).expect("donor holds ba");
  assert_eq!(
    block_address(&off_bytes),
    ba,
    "off-frontier bytes are self-consistent"
  );

  let outcome = sync
    .on_block(ba, off_bytes, &mut laggard)
    .expect("on_block does not error on an off-frontier address");
  assert_eq!(
    outcome,
    BlockOutcome::NonFrontier,
    "off-frontier response is NonFrontier"
  );

  // Nothing was written to the laggard: the off-frontier bytes must not land in the store.
  assert!(
    !laggard.has_block(ba),
    "off-frontier block must not be written to the store"
  );
  // Frontier unchanged: root is still the next request.
  assert_eq!(
    sync.next_request(&laggard),
    Ok(Some(roota)),
    "frontier front unchanged after inert off-frontier response"
  );
  assert!(
    !sync.is_complete(),
    "sync must not be complete after an inert response"
  );

  // None of the other DAG blocks are present either.
  for addr in [roota, aa, ba, xa, ya] {
    assert!(
      !laggard.has_block(addr),
      "no block written by inert response"
    );
  }

  // Now drive the sync to completion via the REAL frontier — must converge fully.
  let requested = drive(&mut sync, &donor, &mut laggard);
  assert!(sync.is_complete());
  assert_eq!(sync.next_request(&laggard), Ok(None));
  // The root was the real front; it must appear among the requested addresses.
  assert!(
    requested.contains(&roota),
    "root was fetched through the real frontier"
  );
  // Every reachable block is now in the laggard.
  for addr in [roota, aa, ba, xa, ya] {
    assert!(
      laggard.has_block(addr),
      "laggard holds every reachable block after convergence"
    );
  }
}

#[test]
fn cycle_and_bound_are_safe() {
  // A content-addressed DAG cannot encode a true reference cycle: an address is the hash of content
  // that would have to contain that very address, an unconstructable fixed point. The termination
  // hazard a content store DOES admit is a block reachable by more than one path (a repeated child,
  // or a diamond) — the visited-set must enqueue each such block exactly once so the walk drains
  // rather than re-traversing a shared subtree unboundedly. Both shapes are exercised here.

  // --- Repeated child: one block lists the SAME child address twice. ---
  let child = leaf(b'c');
  let ca = block_address(&child);
  let dup = block(b'D', &[ca, ca]);
  let dupa = block_address(&dup);

  let mut donor = InMemoryBlockStore::new();
  donor.put(child.clone());
  donor.put(dup);

  let mut laggard = InMemoryBlockStore::new();
  let mut sync = BlockSync::<SmRefs<DagSm>>::new(dupa);
  let requested = drive(&mut sync, &donor, &mut laggard);

  // The repeated child is requested exactly once; the walk terminates and completes.
  assert_eq!(requested.iter().filter(|&&a| a == ca).count(), 1);
  assert!(sync.is_complete());

  // --- Diamond: two distinct parents both reference one shared leaf. ---
  //
  //        root(I) ── p(I) ── shared(L)
  //          └─────── q(I) ──────┘
  //
  // The shared leaf is reachable by two paths; the visited-set must fetch it once.
  let shared = leaf(b's');
  let sa = block_address(&shared);
  let p = block(b'P', &[sa]);
  let pa = block_address(&p);
  let q = block(b'Q', &[sa]);
  let qa = block_address(&q);
  let droot = block(b'R', &[pa, qa]);
  let droota = block_address(&droot);

  let mut donor2 = InMemoryBlockStore::new();
  donor2.put(shared);
  donor2.put(p);
  donor2.put(q);
  donor2.put(droot);

  let mut laggard2 = InMemoryBlockStore::new();
  let mut sync2 = BlockSync::<SmRefs<DagSm>>::new(droota);
  let requested2 = drive(&mut sync2, &donor2, &mut laggard2);

  // The shared leaf is requested exactly once despite two referencing parents; the walk terminates.
  assert_eq!(requested2.iter().filter(|&&a| a == sa).count(), 1);
  assert!(sync2.is_complete());
  for addr in [droota, pa, qa, sa] {
    assert!(laggard2.has_block(addr));
  }

  // --- Bound: a reachable set exceeding MAX_REACHABLE_BLOCKS returns the bound error. ---
  //
  // A wide root references MAX_REACHABLE_BLOCKS distinct child addresses. Discovering the root alone
  // pushes (1 root + MAX children) > MAX into the reachable set, tripping the bound on enqueue —
  // BEFORE any child is fetched. The children therefore need no backing blocks in the donor: only
  // the root must carry their addresses (so `block_references` parses them). Each child address is a
  // distinct fabricated 16-byte value (the loop index), avoiding a million real block allocations.
  let mut wide_children = std::vec::Vec::with_capacity(MAX_REACHABLE_BLOCKS);
  for i in 0..MAX_REACHABLE_BLOCKS as u128 {
    wide_children.push(BlockAddress::from_bytes(i.to_be_bytes()));
  }
  let wide_root = block(b'W', &wide_children);
  let wide_root_a = block_address(&wide_root);

  let mut donor3 = InMemoryBlockStore::new();
  donor3.put(wide_root);

  let mut laggard3 = InMemoryBlockStore::new();
  let mut sync3 = BlockSync::<SmRefs<DagSm>>::new(wide_root_a);
  // Pull and feed the root; enqueuing its MAX children pushes the reachable count over the cap.
  let addr = sync3
    .next_request(&laggard3)
    .expect("the root alone is within the bound")
    .unwrap();
  assert_eq!(addr, wide_root_a);
  let bytes = donor3.read_block(addr).unwrap();
  let err = sync3
    .on_block(addr, bytes, &mut laggard3)
    .expect_err("an over-cap reachable set is rejected");
  assert_eq!(err, BlockSyncError::TooManyBlocks);
}

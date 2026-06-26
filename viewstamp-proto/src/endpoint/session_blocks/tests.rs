use bytes::Bytes;

use super::*;
use crate::block_store::MemBlockStore;

/// Builds a session record with the given fields. `reply` is the cached `(request_number, body)` or
/// `None`.
fn session(request: u64, last_op: u64, reply: Option<(u64, Bytes)>) -> Session {
  Session {
    request: RequestNumber::with(request),
    last_op: crate::OpNumber::with(last_op),
    reply: reply.map(|(rn, body)| (RequestNumber::with(rn), body)),
  }
}

/// Encodes `table` into a fresh store, decodes it back through the verified path, and asserts the
/// round-trip is exact AND the root is deterministic across two encodes.
fn assert_round_trip(table: &std::collections::BTreeMap<u128, Session>) -> BlockAddress {
  let mut store = MemBlockStore::new();
  let root = encode_sessions(table, &mut store);
  // Determinism: a second encode of the same table yields the same root (idempotent writes).
  let mut store2 = MemBlockStore::new();
  let root2 = encode_sessions(table, &mut store2);
  assert_eq!(
    root, root2,
    "same table must produce the same sessions_root"
  );
  // The verified decode reconstructs the exact table.
  let verified = crate::block_store::VerifiedBlocks::new(&store);
  let decoded = decode_sessions(root, &verified).expect("the whole DAG is present");
  assert_eq!(&decoded, table, "round-trip must be exact");
  root
}

#[test]
fn empty_table_round_trips_to_a_valid_root() {
  let table = std::collections::BTreeMap::new();
  let root = assert_round_trip(&table);
  // The empty table still produces a real (empty index) root, so the GC/sync walk can seed from it.
  let mut store = MemBlockStore::new();
  let encoded = encode_sessions(&table, &mut store);
  assert_eq!(encoded, root);
  assert!(store.has_block(root), "the empty root block is written");
}

#[test]
fn small_table_round_trips() {
  let mut table = std::collections::BTreeMap::new();
  table.insert(
    1u128,
    session(3, 10, Some((3, Bytes::from_static(b"reply-one")))),
  );
  table.insert(2u128, session(7, 20, None));
  table.insert(
    300u128,
    session(1, 5, Some((1, Bytes::from_static(b"another cached reply")))),
  );
  assert_round_trip(&table);
}

#[test]
fn a_single_large_cached_reply_is_externalized_and_round_trips() {
  // One cached reply far larger than a leaf budget — it must split into body-chunk blocks and still
  // round-trip exactly. Use a body several block-budgets long with POSITION-VARYING bytes so the chunks
  // have distinct content (and distinct content addresses — identical chunks would dedup to one block).
  let big = Bytes::from(
    (0..SESSION_BLOCK_BUDGET * 3 + 7)
      .map(|i| (i % 251) as u8)
      .collect::<std::vec::Vec<u8>>(),
  );
  let mut table = std::collections::BTreeMap::new();
  table.insert(1u128, session(2, 4, None));
  table.insert(42u128, session(9, 99, Some((9, big.clone()))));
  table.insert(
    43u128,
    session(1, 1, Some((1, Bytes::from_static(b"small")))),
  );
  let root = assert_round_trip(&table);

  // The body chunks are genuinely reachable from the DAG (so the sync frontier + GC see them).
  let mut store = MemBlockStore::new();
  let _ = encode_sessions(&table, &mut store);
  let mut seen = std::collections::BTreeSet::new();
  let mut stack = std::vec![root];
  let mut body_chunk_blocks = 0usize;
  while let Some(addr) = stack.pop() {
    if !seen.insert(addr) {
      continue;
    }
    let block = store.read_block(addr).expect("reachable block present");
    if block_kind(&block) == Some(TAG_BODY) {
      body_chunk_blocks += 1;
    }
    for child in session_block_references(&block) {
      stack.push(child);
    }
  }
  assert!(
    body_chunk_blocks >= 3,
    "the large reply externalized into multiple body-chunk blocks (saw {body_chunk_blocks})"
  );
}

#[test]
fn a_table_too_large_for_one_leaf_builds_multiple_leaves() {
  // Many sessions each with a moderate reply so the total exceeds one leaf budget and several leaves
  // (and a multi-child index) are produced. The round-trip must still be exact.
  let mut table = std::collections::BTreeMap::new();
  let body = Bytes::from(std::vec![0x5Au8; 4096]);
  let count = (SESSION_BLOCK_BUDGET / 4096) * 3; // comfortably more than one leaf's worth.
  for i in 0..count as u128 {
    table.insert(
      i,
      session(i as u64, i as u64, Some((i as u64, body.clone()))),
    );
  }
  let root = assert_round_trip(&table);

  // The root indexes more than one leaf.
  let mut store = MemBlockStore::new();
  let _ = encode_sessions(&table, &mut store);
  let root_block = store.read_block(root).expect("root present");
  assert_eq!(
    block_kind(&root_block),
    Some(TAG_INDEX),
    "root is an index block"
  );
  let leaves = index_children(&root_block);
  assert!(
    leaves.len() > 1,
    "a large table indexes multiple leaves (saw {})",
    leaves.len()
  );
}

#[test]
fn a_corrupt_session_block_is_rejected_by_the_verified_decode() {
  // A descendant block of the session DAG is mis-stored (bytes that hash elsewhere). The verified decode
  // must treat it as missing and return `None` — never reconstructing a partial/garbage table.
  let mut table = std::collections::BTreeMap::new();
  for i in 0..8u128 {
    table.insert(
      i,
      session(
        i as u64,
        i as u64,
        Some((i as u64, Bytes::from_static(b"r"))),
      ),
    );
  }
  let mut store = MemBlockStore::new();
  let root = encode_sessions(&table, &mut store);
  // Find a leaf (non-root) descendant and corrupt it.
  let root_block = store.read_block(root).expect("root present");
  let leaf_addr = *index_children(&root_block)
    .first()
    .expect("the table has at least one leaf");
  let corrupt = Bytes::from_static(b"corrupted session block bytes that hash elsewhere");
  assert_ne!(block_address(&corrupt), leaf_addr);
  store.write_block(leaf_addr, corrupt);

  let verified = crate::block_store::VerifiedBlocks::new(&store);
  assert!(
    decode_sessions(root, &verified).is_none(),
    "a corrupt session block must abort the decode (no partial install)"
  );
}

#[test]
fn an_embedder_sm_block_is_not_parsed_as_a_session_block() {
  // GC marks live from BOTH content-addressed roots in one pass over the SHARED store, resolving
  // children with a UNION of the SM resolver and `session_block_references`. The latter therefore runs
  // over EVERY live block, including embedder SM blocks. An SM block whose first bytes happen to look
  // like a session INDEX with a huge child count (`02 ff ff ff ff`, were the tag read at byte 0) must
  // NOT be parsed as one — the missing session magic makes `session_block_references` reject it in O(1),
  // so it yields no children and GC neither over-allocates nor frees a reachable block via a phantom
  // edge.
  let sm_block = Bytes::from_static(&[0x02, 0xff, 0xff, 0xff, 0xff]);
  assert_eq!(
    block_kind(&sm_block),
    None,
    "an SM block lacking the session magic is not a session block"
  );
  assert!(
    session_block_references(&sm_block).is_empty(),
    "the session resolver yields no children for a non-session SM block (no phantom edges into GC)"
  );

  // A real session block with the SAME tag byte at position 0 (under the magic) is still recognized: the
  // discriminator is the magic, not the tag's byte offset.
  let mut store = MemBlockStore::new();
  let mut table = std::collections::BTreeMap::new();
  table.insert(1u128, session(1, 1, Some((1, Bytes::from_static(b"x")))));
  let root = encode_sessions(&table, &mut store);
  let root_block = store.read_block(root).expect("root present");
  assert_eq!(
    block_kind(&root_block),
    Some(TAG_INDEX),
    "a genuine session index is recognized via its magic"
  );
  assert!(
    !session_block_references(&root_block).is_empty(),
    "a genuine session index still resolves its children"
  );
}

#[test]
fn an_index_block_claiming_more_children_than_its_bytes_hold_is_rejected() {
  // A (well-formed-magic) index block whose declared child count vastly exceeds the addresses actually
  // present must be rejected WITHOUT reserving `count` entries — never `Vec::with_capacity` from an
  // untrusted length. Hand-build `MAGIC || TAG_INDEX || count=u32::MAX || (one 16-byte address)`: the
  // count claims ~4 billion children but only one address follows.
  let mut block = std::vec::Vec::new();
  block.extend_from_slice(&MAGIC);
  block.push(TAG_INDEX);
  block.extend_from_slice(&u32::MAX.to_be_bytes());
  block.extend_from_slice(&[0u8; 16]); // a single child address — far fewer than claimed.
  let block = Bytes::from(block);

  assert_eq!(
    block_kind(&block),
    Some(TAG_INDEX),
    "the magic + tag are well-formed (the count is the hostile field)"
  );
  // The length check rejects the over-claim: no children, and crucially no giant allocation.
  assert!(
    session_block_references(&block).is_empty(),
    "an index over-claiming its child count yields no children (the count exceeds the bytes present)"
  );

  // Exactly-fitting counts are still honored: a count whose addresses all fit decodes normally.
  let mut ok = std::vec::Vec::new();
  ok.extend_from_slice(&MAGIC);
  ok.push(TAG_INDEX);
  ok.extend_from_slice(&2u32.to_be_bytes());
  ok.extend_from_slice(&[1u8; 16]);
  ok.extend_from_slice(&[2u8; 16]);
  let ok = Bytes::from(ok);
  assert_eq!(
    session_block_references(&ok).len(),
    2,
    "a count whose addresses all fit decodes every child"
  );
}

#[test]
fn references_expose_index_children_and_leaf_body_chunks() {
  // The reference function the GC/sync walk uses yields index children for an index block and body-chunk
  // addresses for a leaf whose record externalized its reply.
  let big = Bytes::from(std::vec![0x11u8; SESSION_BLOCK_BUDGET + 1]);
  let mut table = std::collections::BTreeMap::new();
  table.insert(7u128, session(1, 1, Some((1, big))));
  let mut store = MemBlockStore::new();
  let root = encode_sessions(&table, &mut store);

  let root_block = store.read_block(root).expect("root present");
  let children = session_block_references(&root_block);
  assert!(!children.is_empty(), "the index root references its leaves");

  // The leaf references the externalized body chunks.
  let leaf_addr = children[0];
  let leaf_block = store.read_block(leaf_addr).expect("leaf present");
  let body_refs = session_block_references(&leaf_block);
  assert!(
    !body_refs.is_empty(),
    "the leaf references the externalized body-chunk blocks"
  );
}

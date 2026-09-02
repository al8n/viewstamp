use bytes::Bytes;

use super::*;
use crate::block_store::{InMemoryBlockStore, block_address};

/// Builds a session record with the given fields. `reply` is the cached `(request_number, body)` or
/// `None`; the body is classified through the same choke the endpoint uses.
fn session(request: u64, last_op: u64, reply: Option<(u64, Bytes)>) -> Session {
  Session {
    request: RequestNumber::with(request),
    last_op: crate::OpNumber::with(last_op),
    reply: reply.map(|(rn, body)| (RequestNumber::with(rn), ReplyOutcome::from_applied(body))),
  }
}

/// Builds a session record whose cached outcome is the over-bound-reply REFUSAL rather than a body.
fn refused_session(request: u64, last_op: u64, rn: u64, len: usize) -> Session {
  Session {
    request: RequestNumber::with(request),
    last_op: crate::OpNumber::with(last_op),
    reply: Some((
      RequestNumber::with(rn),
      ReplyOutcome::TooLarge(ReplyTooLarge::new(len, ReplyBody::max_len())),
    )),
  }
}

/// Encodes `table` into a fresh store, decodes it back through the verified path, and asserts the
/// round-trip is exact AND the root is deterministic across two encodes.
fn assert_round_trip(table: &std::collections::BTreeMap<u128, Session>) -> BlockAddress {
  let mut store = InMemoryBlockStore::new();
  let root = encode_sessions(table, &mut store);
  // Determinism: a second encode of the same table yields the same root (idempotent writes).
  let mut store2 = InMemoryBlockStore::new();
  let root2 = encode_sessions(table, &mut store2);
  assert_eq!(
    root, root2,
    "same table must produce the same sessions_root"
  );
  // The verified decode reconstructs the exact table.

  let decoded = decode_sessions(root, &store).expect("the whole DAG is present");
  assert_eq!(&decoded, table, "round-trip must be exact");
  root
}

#[test]
fn empty_table_round_trips_to_a_valid_root() {
  let table = std::collections::BTreeMap::new();
  let root = assert_round_trip(&table);
  // The empty table still produces a real (empty index) root, so the GC/sync walk can seed from it.
  let mut store = InMemoryBlockStore::new();
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
fn a_refused_reply_record_round_trips_alongside_body_records() {
  // The refusal is a cached outcome like any other — the row must survive a checkpoint and restore
  // so a duplicate request after recovery is answered with the SAME refusal the client already had,
  // not with silence (no cached reply) and not with a body. Encoded in a table mixing all three
  // record kinds, so the reader cannot confuse the refusal's fixed layout with a body's.
  let max = crate::ReplyBody::max_len();
  let mut table = std::collections::BTreeMap::new();
  table.insert(
    1u128,
    session(3, 10, Some((3, Bytes::from_static(b"body")))),
  );
  table.insert(2u128, refused_session(7, 20, 7, max + 1));
  table.insert(3u128, session(4, 30, None));
  assert_round_trip(&table);

  // The refusal decoded back carries the offending length and the bound verbatim.
  let mut store = InMemoryBlockStore::new();
  let root = encode_sessions(&table, &mut store);
  let decoded = decode_sessions(root, &store).expect("the whole DAG is present");
  let outcome = decoded[&2u128]
    .reply
    .as_ref()
    .map(|(_, outcome)| outcome.clone())
    .expect("the refusal row keeps its cached outcome");
  assert_eq!(
    outcome,
    ReplyOutcome::TooLarge(ReplyTooLarge::new(max + 1, max))
  );
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
  let mut store = InMemoryBlockStore::new();
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
  let mut store = InMemoryBlockStore::new();
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
  let mut store = InMemoryBlockStore::new();
  let root = encode_sessions(&table, &mut store);
  // Find a leaf (non-root) descendant and corrupt it.
  let root_block = store.read_block(root).expect("root present");
  let leaf_addr = *index_children(&root_block)
    .first()
    .expect("the table has at least one leaf");
  let corrupt = Bytes::from_static(b"corrupted session block bytes that hash elsewhere");
  assert_ne!(block_address(&corrupt), leaf_addr);
  store.insert_raw(leaf_addr, corrupt);

  assert!(
    decode_sessions(root, &store).is_none(),
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
  let mut store = InMemoryBlockStore::new();
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
  let mut store = InMemoryBlockStore::new();
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

#[test]
fn index_children_and_leaf_body_refs_reject_the_wrong_block_kind() {
  let leaf = {
    let mut b = std::vec::Vec::new();
    b.extend_from_slice(&MAGIC);
    b.push(TAG_LEAF);
    Bytes::from(b)
  };
  assert!(
    index_children(&leaf).is_empty(),
    "index_children only parses an INDEX block"
  );

  let index = {
    let mut b = std::vec::Vec::new();
    b.extend_from_slice(&MAGIC);
    b.push(TAG_INDEX);
    b.extend_from_slice(&0u32.to_be_bytes());
    Bytes::from(b)
  };
  assert!(
    leaf_body_refs(&index).is_empty(),
    "leaf_body_refs only parses a LEAF block"
  );
}

#[test]
fn index_children_rejects_a_truncated_count_field() {
  // MAGIC + TAG_INDEX with fewer than 4 bytes following: the count field itself is truncated.
  let mut block = std::vec::Vec::new();
  block.extend_from_slice(&MAGIC);
  block.push(TAG_INDEX);
  block.extend_from_slice(&[0u8; 2]);
  assert!(index_children(&block).is_empty());
}

#[test]
fn build_index_tree_splits_into_a_second_level_past_the_fanout() {
  // One more leaf address than a single index block's fanout forces a second tree level: the root
  // then names two second-level index blocks instead of the raw leaves directly.
  let mut store = InMemoryBlockStore::new();
  let leaves: std::vec::Vec<BlockAddress> = (0u64..=INDEX_FANOUT as u64)
    .map(|i| {
      let mut b = [0u8; 16];
      b[8..].copy_from_slice(&i.to_be_bytes());
      BlockAddress::from_bytes(b)
    })
    .collect();
  assert_eq!(
    leaves.len(),
    INDEX_FANOUT + 1,
    "one more address than a single index block's fanout"
  );

  let root = build_index_tree(leaves.clone(), &mut store);

  let root_bytes = store.read_block(root).expect("root written");
  assert_eq!(block_kind(&root_bytes), Some(TAG_INDEX));
  let top_children = index_children(&root_bytes);
  assert_eq!(
    top_children.len(),
    2,
    "the fanout-plus-one leaves split into two second-level chunks"
  );

  let mut recovered = std::vec::Vec::new();
  for child in &top_children {
    let child_bytes = store.read_block(*child).expect("child index written");
    assert_eq!(
      block_kind(&child_bytes),
      Some(TAG_INDEX),
      "each top-level child is itself an index block, not a leaf"
    );
    recovered.extend(index_children(&child_bytes));
  }
  assert_eq!(
    recovered, leaves,
    "flattening both second-level chunks recovers every original leaf address, in order"
  );
}

#[test]
fn leaf_body_refs_skips_inline_replies_and_collects_only_externalized_chunk_addresses() {
  let mut table = std::collections::BTreeMap::new();
  // An INLINE reply (kind 1): small enough to stay embedded in the record — contributes no
  // body-chunk address.
  table.insert(
    1u128,
    session(1, 1, Some((1, Bytes::from_static(b"small-inline-reply")))),
  );
  // An EXTERNALIZED reply (kind 2): larger than one leaf on its own, so it splits into body-chunk
  // blocks — the only records leaf_body_refs should report addresses for.
  let big = Bytes::from(std::vec![0x42u8; SESSION_BLOCK_BUDGET + 1]);
  table.insert(2u128, session(2, 2, Some((2, big))));

  let mut store = InMemoryBlockStore::new();
  let root = encode_sessions(&table, &mut store);
  let root_block = store.read_block(root).expect("root present");
  let leaf_addrs = index_children(&root_block);
  assert_eq!(leaf_addrs.len(), 1, "both tiny records share one leaf");
  let leaf_block = store.read_block(leaf_addrs[0]).expect("leaf present");

  let refs = leaf_body_refs(&leaf_block);
  assert!(
    !refs.is_empty(),
    "the externalized record's chunk addresses are collected"
  );
  for addr in &refs {
    let chunk = store.read_block(*addr).expect("chunk present");
    assert_eq!(block_kind(&chunk), Some(TAG_BODY));
  }
}

#[test]
fn leaf_body_refs_stops_at_a_malformed_record_and_keeps_prior_references() {
  // A hand-built leaf: a well-formed EXTERNAL-reply record (kind 2, contributing one address)
  // followed by a record with an invalid reply-kind byte. `skip_record_collecting_body_refs`
  // rejects the second record, so `leaf_body_refs` stops scanning and returns exactly the address
  // already collected from the first.
  let chunk_addr = BlockAddress::from_bytes([7u8; 16]);
  let mut payload = std::vec::Vec::new();
  // Record 1: client=1, request=1, last_op=1, kind=2 (external), rn=1, count=1, one address.
  payload.extend_from_slice(&1u128.to_be_bytes());
  payload.extend_from_slice(&1u64.to_be_bytes());
  payload.extend_from_slice(&1u64.to_be_bytes());
  payload.push(2);
  payload.extend_from_slice(&1u64.to_be_bytes());
  payload.extend_from_slice(&1u32.to_be_bytes());
  payload.extend_from_slice(chunk_addr.as_bytes());
  // Record 2: client=2, request=2, last_op=2, kind=99 (invalid).
  payload.extend_from_slice(&2u128.to_be_bytes());
  payload.extend_from_slice(&2u64.to_be_bytes());
  payload.extend_from_slice(&2u64.to_be_bytes());
  payload.push(99);

  let mut block = std::vec::Vec::new();
  block.extend_from_slice(&MAGIC);
  block.push(TAG_LEAF);
  block.extend_from_slice(&payload);

  let refs = leaf_body_refs(&block);
  assert_eq!(
    refs,
    std::vec![chunk_addr],
    "the malformed second record halts the scan; only the first record's address is collected"
  );
}

#[test]
fn decode_record_rejects_a_wrong_kind_chunk_and_an_invalid_reply_kind_byte() {
  let mut store = InMemoryBlockStore::new();
  // A real stored block that is NOT a body chunk (an empty index block) — used as the address an
  // external-reply record's chunk list points at.
  let not_a_chunk = {
    let mut b = std::vec::Vec::new();
    b.extend_from_slice(&MAGIC);
    b.push(TAG_INDEX);
    b.extend_from_slice(&0u32.to_be_bytes());
    Bytes::from(b)
  };
  let not_a_chunk_addr = store.put(not_a_chunk);

  // client=1, request=1, last_op=1, kind=2 (external), rn=1, count=1, the wrong-kind address.
  let mut payload = std::vec::Vec::new();
  payload.extend_from_slice(&1u128.to_be_bytes());
  payload.extend_from_slice(&1u64.to_be_bytes());
  payload.extend_from_slice(&1u64.to_be_bytes());
  payload.push(2);
  payload.extend_from_slice(&1u64.to_be_bytes());
  payload.extend_from_slice(&1u32.to_be_bytes());
  payload.extend_from_slice(not_a_chunk_addr.as_bytes());
  let mut d = Decoder::new(&payload);
  assert_eq!(
    decode_record(&mut d, &store),
    None,
    "a resolved-but-wrong-kind chunk aborts the decode"
  );

  // A record whose reply-kind byte is neither 0, 1, nor 2.
  let mut invalid_kind = std::vec::Vec::new();
  invalid_kind.extend_from_slice(&2u128.to_be_bytes());
  invalid_kind.extend_from_slice(&2u64.to_be_bytes());
  invalid_kind.extend_from_slice(&2u64.to_be_bytes());
  invalid_kind.push(7);
  let mut d2 = Decoder::new(&invalid_kind);
  assert_eq!(decode_record(&mut d2, &store), None);
}

#[test]
fn ordered_leaves_visits_a_duplicated_child_only_once() {
  let mut store = InMemoryBlockStore::new();
  let leaf = {
    let mut b = std::vec::Vec::new();
    b.extend_from_slice(&MAGIC);
    b.push(TAG_LEAF);
    Bytes::from(b)
  };
  let leaf_addr = store.put(leaf);

  // An index naming the SAME leaf address twice.
  let index = {
    let mut b = std::vec::Vec::new();
    b.extend_from_slice(&MAGIC);
    b.push(TAG_INDEX);
    b.extend_from_slice(&2u32.to_be_bytes());
    b.extend_from_slice(leaf_addr.as_bytes());
    b.extend_from_slice(leaf_addr.as_bytes());
    Bytes::from(b)
  };
  let root = store.put(index);

  assert_eq!(
    ordered_leaves(root, &store).unwrap(),
    std::vec![leaf_addr],
    "the duplicated child is enqueued only once"
  );
}

#[test]
fn ordered_leaves_rejects_a_root_that_is_neither_index_nor_leaf() {
  let mut store = InMemoryBlockStore::new();
  let body_chunk = {
    let mut b = std::vec::Vec::new();
    b.extend_from_slice(&MAGIC);
    b.push(TAG_BODY);
    b.extend_from_slice(b"chunk-bytes");
    Bytes::from(b)
  };
  let addr = store.put(body_chunk);
  assert_eq!(ordered_leaves(addr, &store), None);
}

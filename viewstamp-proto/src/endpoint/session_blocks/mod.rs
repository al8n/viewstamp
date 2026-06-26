//! Proto-owned, content-addressed encoding of the client SESSION TABLE as a block DAG.
//!
//! The session table (`Endpoint::clients`: per-client `(request, last_op, cached reply)` records) is
//! state the PROTO owns, distinct from the embedder's state-machine. Before this module the table was
//! serialized INLINE into the `SyncCheckpoint` envelope, so a large table (the 4096-session default,
//! each with a cached reply body) could push the envelope past one transport frame and wedge state-sync.
//! Here the table becomes a content-addressed DAG — exactly like the SM checkpoint DAG — and the
//! envelope carries only its 16-byte root (`sessions_root`). The envelope is then always frame-sized,
//! and a laggard fetches the session blocks it is missing over the same verified `RequestBlock` path as
//! SM blocks.
//!
//! # DAG shape
//!
//! Every block's on-disk layout is `MAGIC(4) || tag(1) || payload` (the [`MAGIC`] distinguishes a
//! session block from an embedder SM block in the shared store — see [`block_kind`]). Three block kinds,
//! each bounded by [`SESSION_BLOCK_BUDGET`]:
//!
//! - **Leaf** ([`TAG_LEAF`]) — a run of fully-serialized session records, in client-id order. A record
//!   whose cached reply body would overflow a leaf is split: its body is externalized into a chain of
//!   **body-chunk** blocks and the record stores only their addresses, so no leaf ever exceeds the
//!   budget regardless of how large one cached reply is.
//! - **Body-chunk** ([`TAG_BODY`]) — one ≤[`SESSION_BLOCK_BUDGET`] slice of an externalized reply body.
//!   Concatenated in address order they reconstruct the body. A leaf, not the chunk, names them.
//! - **Index** ([`TAG_INDEX`]) — the ordered list of child addresses (leaves, or lower index blocks).
//!   The root is always an index block. If the leaves' addresses overflow one index, index blocks are
//!   stacked into a balanced tree until a single root remains, so an ARBITRARILY large table still roots
//!   at one bounded block.
//!
//! # Determinism
//!
//! Records are emitted in `BTreeMap` (client-id) order, packed greedily into fixed-budget leaves, and
//! body chunks are fixed-size — so the SAME table always produces byte-identical blocks and therefore
//! the SAME `sessions_root`. This is the property `checkpoint_id` (which now hashes `sessions_root`
//! rather than the inline bytes) and the donor↔laggard content-address match both rely on.

use bytes::Bytes;

use crate::{
  RequestNumber,
  block_store::{BlockAddress, BlockStore, block_address, read_verified_block},
};

use super::Session;

/// Per-block byte budget. Every emitted session block (leaf, body-chunk, index) is at most this many
/// bytes, so all fit one transport frame with framing overhead to spare (`MAX_FRAME_LEN` is 16 MiB);
/// large enough that a typical table roots at a shallow DAG.
pub(crate) const SESSION_BLOCK_BUDGET: usize = 1 << 20;

/// A 4-byte magic prefixing EVERY session block, ahead of its 1-byte kind tag.
///
/// It is a FAST PATH, not a safety mechanism: the GC mark walk resolves children for the SM and
/// session DAGs in one union pass over the shared store (see `Endpoint::gc_blocks`), and the magic
/// lets `session_block_references` reject a non-session block in O(1) instead of fully parsing every SM
/// block whose kind tag happens to collide. It does NOT guard against a hostile collision (an SM block
/// could begin with these bytes) — the union is already SAFE by over-marking; the magic only keeps it
/// cheap.
const MAGIC: [u8; 4] = *b"vSeS";
/// The byte offset of a session block's payload: the 4-byte magic plus the 1-byte kind tag.
const HEADER_LEN: usize = MAGIC.len() + 1;

/// Kind tag (at byte `MAGIC.len()`) of a LEAF block (a run of session records).
const TAG_LEAF: u8 = 0x00;
/// Kind tag of a BODY-CHUNK block (one slice of an externalized cached-reply body).
const TAG_BODY: u8 = 0x01;
/// Kind tag of an INDEX block (an ordered list of child block addresses).
const TAG_INDEX: u8 = 0x02;

/// The kind tag of a session `block`, or `None` if it is not a session block (the magic does not match).
/// O(1) — the fast reject for the GC union walk over an embedder SM block.
fn block_kind(block: &[u8]) -> Option<u8> {
  if block.get(..MAGIC.len()) != Some(&MAGIC[..]) {
    return None;
  }
  block.get(MAGIC.len()).copied()
}

/// The 16-byte child addresses an INDEX block names, or an empty list for any other block kind. Only
/// the index level forms internal edges; a leaf's body-chunk edges come from [`leaf_body_refs`].
///
/// The declared child count is bounded against the bytes that follow it (`count * 16 <= remaining`)
/// BEFORE any allocation, so a foreign or corrupt count field can never drive a huge
/// `Vec::with_capacity`. This runs over EVERY live block on the GC mark walk, where the count is
/// untrusted — a non-session SM block that happens to look like an index must not be parsed as one.
fn index_children(block: &[u8]) -> std::vec::Vec<BlockAddress> {
  if block_kind(block) != Some(TAG_INDEX) {
    return std::vec::Vec::new();
  }
  // [magic:4][tag:1][count:u32 BE][count × addr:16] — the payload starts at HEADER_LEN.
  let Some(count_bytes) = block.get(HEADER_LEN..HEADER_LEN + 4) else {
    return std::vec::Vec::new();
  };
  let count = u32::from_be_bytes(count_bytes.try_into().expect("4 bytes")) as usize;
  let remaining = block.len() - (HEADER_LEN + 4);
  // Never allocate from an untrusted length: the addresses must fit the bytes present.
  if count.checked_mul(16).is_none_or(|need| need > remaining) {
    return std::vec::Vec::new();
  }
  let mut out = std::vec::Vec::with_capacity(count);
  let mut i = HEADER_LEN + 4;
  for _ in 0..count {
    let raw = &block[i..i + 16]; // bounded above: `count * 16 <= remaining`.
    out.push(BlockAddress::from_bytes(raw.try_into().expect("16 bytes")));
    i += 16;
  }
  out
}

/// The body-chunk addresses a LEAF block's records reference (the externalized cached-reply bodies).
/// An index/body/non-session block yields none. Used by [`session_block_references`] so the DAG walk
/// (sync frontier + GC mark) reaches every body chunk a leaf points at.
fn leaf_body_refs(block: &[u8]) -> std::vec::Vec<BlockAddress> {
  let mut out = std::vec::Vec::new();
  if block_kind(block) != Some(TAG_LEAF) {
    return out;
  }
  let mut cur = Decoder::new(&block[HEADER_LEN..]);
  while !cur.is_empty() {
    if cur.skip_record_collecting_body_refs(&mut out).is_none() {
      break; // a truncated/malformed leaf — stop; the verified read already gated genuineness.
    }
  }
  out
}

/// The child addresses `block` directly references across ALL session-block kinds: an index's children
/// PLUS (for a leaf) the body-chunk addresses its records externalize. The session-DAG analogue of
/// `StateMachine::block_references`, supplied to the sync frontier and the GC mark walk so the WHOLE
/// session DAG is drained/retained.
///
/// Dispatched through [`block_kind`], so an embedder SM block (seen on the GC union walk, magic does
/// not match) yields NO children — GC resolves its edges through `StateMachine::block_references`.
pub(crate) fn session_block_references(block: &[u8]) -> std::vec::Vec<BlockAddress> {
  match block_kind(block) {
    Some(TAG_INDEX) => index_children(block),
    Some(TAG_LEAF) => leaf_body_refs(block),
    _ => std::vec::Vec::new(),
  }
}

// ── Encode ──

/// A growable record serializer. The per-record fields mirror the prior inline checkpoint encoding so
/// the record bytes are unchanged; only the framing into blocks is new.
struct RecordWriter {
  buf: std::vec::Vec<u8>,
}

impl RecordWriter {
  fn new() -> Self {
    Self {
      buf: std::vec::Vec::new(),
    }
  }

  /// Appends one session record. `body_refs` (when present) is the externalized cached-reply body as a
  /// list of chunk addresses; `inline_reply` is the in-line cached reply (small bodies). At most one of
  /// the two reply forms is set per record. Layout:
  ///
  /// `client:u128 | request:u64 | last_op:u64 | reply_kind:u8 | …reply…`
  ///
  /// where `reply_kind` is `0` (none), `1` (inline: `rn:u64 | len:u32 | bytes`), or `2` (external:
  /// `rn:u64 | chunk_count:u32 | chunk_count × addr:16`).
  fn push_record(&mut self, client: u128, session: &Session, reply_external: &[BlockAddress]) {
    self.buf.extend_from_slice(&client.to_be_bytes());
    self
      .buf
      .extend_from_slice(&session.request.get().to_be_bytes());
    self
      .buf
      .extend_from_slice(&session.last_op.get().to_be_bytes());
    match &session.reply {
      None => self.buf.push(0),
      Some((rn, body)) => {
        if reply_external.is_empty() {
          // INLINE reply.
          self.buf.push(1);
          self.buf.extend_from_slice(&rn.get().to_be_bytes());
          self
            .buf
            .extend_from_slice(&(body.len() as u32).to_be_bytes());
          self.buf.extend_from_slice(body);
        } else {
          // EXTERNAL reply: the body lives in `reply_external` body-chunk blocks.
          self.buf.push(2);
          self.buf.extend_from_slice(&rn.get().to_be_bytes());
          self
            .buf
            .extend_from_slice(&(reply_external.len() as u32).to_be_bytes());
          for addr in reply_external {
            self.buf.extend_from_slice(addr.as_bytes());
          }
        }
      }
    }
  }

  fn len(&self) -> usize {
    self.buf.len()
  }

  fn take(&mut self) -> std::vec::Vec<u8> {
    core::mem::take(&mut self.buf)
  }
}

/// Encodes one session record into a standalone buffer (used to size it against the leaf budget without
/// committing it to the running leaf).
fn encode_record(
  client: u128,
  session: &Session,
  reply_external: &[BlockAddress],
) -> std::vec::Vec<u8> {
  let mut w = RecordWriter::new();
  w.push_record(client, session, reply_external);
  w.take()
}

/// The body-chunk payload size: the per-block budget minus the [`HEADER_LEN`] (magic + tag).
const BODY_CHUNK_PAYLOAD: usize = SESSION_BLOCK_BUDGET - HEADER_LEN;

/// Writes a cached-reply body as a chain of body-chunk blocks (each ≤ [`SESSION_BLOCK_BUDGET`]) and
/// returns their addresses in order. Deterministic: a body splits at fixed offsets, so the same body
/// always yields the same chunk addresses.
fn write_body_chunks(body: &[u8], store: &mut dyn BlockStore) -> std::vec::Vec<BlockAddress> {
  let mut out = std::vec::Vec::new();
  for chunk in body.chunks(BODY_CHUNK_PAYLOAD) {
    let mut block = std::vec::Vec::with_capacity(HEADER_LEN + chunk.len());
    block.extend_from_slice(&MAGIC);
    block.push(TAG_BODY);
    block.extend_from_slice(chunk);
    let bytes = Bytes::from(block);
    let addr = block_address(&bytes);
    store.write_block(addr, bytes);
    out.push(addr);
  }
  out
}

/// Writes the session table into `store` as a content-addressed DAG and returns the root index block's
/// address. Round-trips EXACTLY via [`decode_sessions`]; deterministic (same table ⇒ same root).
///
/// An empty table still produces a real (empty) root index block, so `sessions_root` is always a valid
/// address the GC/sync walk can seed from.
pub(crate) fn encode_sessions(
  sessions: &std::collections::BTreeMap<u128, Session>,
  store: &mut dyn BlockStore,
) -> BlockAddress {
  // (1) Pack records into leaf blocks. A record is externalized into body chunks iff its inline form
  // would not fit a leaf on its own; otherwise it packs inline, greedily, up to the budget.
  let mut leaves = std::vec::Vec::new();
  let mut leaf = RecordWriter::new();
  // The leaf payload budget (after the magic + leaf tag header).
  let leaf_budget = SESSION_BLOCK_BUDGET - HEADER_LEN;

  let flush_leaf = |leaf: &mut RecordWriter,
                    leaves: &mut std::vec::Vec<BlockAddress>,
                    store: &mut dyn BlockStore| {
    if leaf.len() == 0 {
      return;
    }
    let payload = leaf.take();
    let mut block = std::vec::Vec::with_capacity(HEADER_LEN + payload.len());
    block.extend_from_slice(&MAGIC);
    block.push(TAG_LEAF);
    block.extend_from_slice(&payload);
    let bytes = Bytes::from(block);
    let addr = block_address(&bytes);
    store.write_block(addr, bytes);
    leaves.push(addr);
  };

  for (&client, session) in sessions {
    let inline = encode_record(client, session, &[]);
    let record = if inline.len() <= leaf_budget {
      inline
    } else {
      // The inline record overflows a whole leaf — externalize its reply body into chunks and re-encode
      // with the chunk addresses. The re-encoded record is always small (a fixed header plus 16 bytes
      // per chunk), so it fits the budget for any realistic chunk count.
      let body = session
        .reply
        .as_ref()
        .map(|(_, b)| b.clone())
        .unwrap_or_default();
      let chunks = write_body_chunks(&body, store);
      encode_record(client, session, &chunks)
    };
    // Start a new leaf if appending this record would overflow the current one (and the current leaf is
    // non-empty — a single record always gets at least its own leaf).
    if leaf.len() != 0 && leaf.len() + record.len() > leaf_budget {
      flush_leaf(&mut leaf, &mut leaves, store);
    }
    leaf.buf.extend_from_slice(&record);
  }
  flush_leaf(&mut leaf, &mut leaves, store);

  // (2) Build the index tree bottom-up over the leaf addresses until one root remains.
  build_index_tree(leaves, store)
}

/// The number of child addresses one index block can hold within the budget:
/// `(budget - header(magic+tag) - count(4)) / 16`.
const INDEX_FANOUT: usize = (SESSION_BLOCK_BUDGET - HEADER_LEN - 4) / 16;

/// Writes one index block naming `children` and returns its address.
fn write_index(children: &[BlockAddress], store: &mut dyn BlockStore) -> BlockAddress {
  let mut block = std::vec::Vec::with_capacity(HEADER_LEN + 4 + children.len() * 16);
  block.extend_from_slice(&MAGIC);
  block.push(TAG_INDEX);
  block.extend_from_slice(&(children.len() as u32).to_be_bytes());
  for addr in children {
    block.extend_from_slice(addr.as_bytes());
  }
  let bytes = Bytes::from(block);
  let addr = block_address(&bytes);
  store.write_block(addr, bytes);
  addr
}

/// Builds a balanced index tree over `leaves` and returns the single root address. A level that fits one
/// index block becomes the root; otherwise the level is chunked into index blocks and the process repeats
/// over those blocks' addresses. An empty `leaves` yields a single empty index block (the empty-table root).
fn build_index_tree(
  leaves: std::vec::Vec<BlockAddress>,
  store: &mut dyn BlockStore,
) -> BlockAddress {
  let mut level = leaves;
  loop {
    if level.len() <= INDEX_FANOUT {
      return write_index(&level, store); // fits one index block — that is the root.
    }
    let mut next = std::vec::Vec::new();
    for chunk in level.chunks(INDEX_FANOUT) {
      next.push(write_index(chunk, store));
    }
    level = next;
  }
}

// ── Decode ──

/// A bounds-checked big-endian reader over a block's payload.
struct Decoder<'a> {
  bytes: &'a [u8],
  i: usize,
}

impl<'a> Decoder<'a> {
  fn new(bytes: &'a [u8]) -> Self {
    Self { bytes, i: 0 }
  }

  fn is_empty(&self) -> bool {
    self.i >= self.bytes.len()
  }

  fn take(&mut self, n: usize) -> Option<&'a [u8]> {
    let s = self.bytes.get(self.i..self.i + n)?;
    self.i += n;
    Some(s)
  }

  fn u32(&mut self) -> Option<u32> {
    Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
  }

  fn u64(&mut self) -> Option<u64> {
    Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
  }

  fn u128(&mut self) -> Option<u128> {
    Some(u128::from_be_bytes(self.take(16)?.try_into().ok()?))
  }

  fn addr(&mut self) -> Option<BlockAddress> {
    Some(BlockAddress::from_bytes(self.take(16)?.try_into().ok()?))
  }

  /// Advances past one record, pushing any external body-chunk addresses into `out`. Returns `Some(())`
  /// on a well-formed record, `None` on truncation. Does NOT read body bytes (only references), so it is
  /// cheap and used by the reference walk.
  fn skip_record_collecting_body_refs(
    &mut self,
    out: &mut std::vec::Vec<BlockAddress>,
  ) -> Option<()> {
    self.u128()?; // client
    self.u64()?; // request
    self.u64()?; // last_op
    let kind = *self.take(1)?.first()?;
    match kind {
      0 => {}
      1 => {
        self.u64()?; // reply request number
        let len = self.u32()? as usize;
        self.take(len)?; // reply body bytes
      }
      2 => {
        self.u64()?; // reply request number
        let count = self.u32()? as usize;
        for _ in 0..count {
          out.push(self.addr()?);
        }
      }
      _ => return None,
    }
    Some(())
  }
}

/// Reads one record from a leaf decoder, resolving an external reply body from `store` (verified). On a
/// genuine block (the caller read it verified) a well-formed record always decodes; a truncation or a
/// missing/corrupt body chunk surfaces as `None` so the caller treats the whole decode as a fault and
/// re-fetches rather than installing partial state.
fn decode_record(d: &mut Decoder<'_>, store: &dyn BlockStore) -> Option<(u128, Session)> {
  let client = d.u128()?;
  let request = RequestNumber::with(d.u64()?);
  let last_op = crate::OpNumber::with(d.u64()?);
  let kind = *d.take(1)?.first()?;
  let reply = match kind {
    0 => None,
    1 => {
      let rn = RequestNumber::with(d.u64()?);
      let len = d.u32()? as usize;
      let body = Bytes::copy_from_slice(d.take(len)?);
      Some((rn, body))
    }
    2 => {
      let rn = RequestNumber::with(d.u64()?);
      let count = d.u32()? as usize;
      let mut body = std::vec::Vec::new();
      for _ in 0..count {
        let addr = d.addr()?;
        let chunk = read_verified_block(store, addr)?;
        // The chunk is a session body-chunk block (`MAGIC || TAG_BODY || payload`); take its payload.
        if block_kind(&chunk) != Some(TAG_BODY) {
          return None;
        }
        let payload = chunk.get(HEADER_LEN..)?;
        body.extend_from_slice(payload);
      }
      Some((rn, Bytes::from(body)))
    }
    _ => return None,
  };
  Some((
    client,
    Session {
      request,
      reply,
      last_op,
    },
  ))
}

/// Reconstructs the exact session table from the DAG rooted at `root`, reading every block through the
/// VERIFIED path (`read_verified_block`): a missing OR corrupt block (bytes that do not hash to their
/// address) reads as absent and aborts with `None`, so a fault re-fetches rather than installing partial
/// or corrupt state. Round-trips [`encode_sessions`] exactly.
///
/// The walk is iterative over the index tree (root → index levels → leaves), bounded by the same
/// reachable-set discipline the SM DAG uses: a cycle is impossible in a content-addressed DAG, and a
/// visited-set keeps a malformed multi-edge graph terminating.
pub(crate) fn decode_sessions(
  root: BlockAddress,
  store: &dyn BlockStore,
) -> Option<std::collections::BTreeMap<u128, Session>> {
  let mut sessions = std::collections::BTreeMap::new();
  // Decode leaves in DAG order. Records land in client-id order because the encoder emits leaves in
  // client-id order and the index tree preserves it.
  let ordered = ordered_leaves(root, store)?;
  for leaf_addr in ordered {
    let block = read_verified_block(store, leaf_addr)?;
    if block_kind(&block) != Some(TAG_LEAF) {
      return None; // `ordered_leaves` only enqueues leaves, but re-verify the magic + tag before decoding.
    }
    let payload = block.get(HEADER_LEN..)?; // strip the magic + leaf tag
    let mut d = Decoder::new(payload);
    while !d.is_empty() {
      let (client, session) = decode_record(&mut d, store)?;
      sessions.insert(client, session);
    }
  }
  Some(sessions)
}

/// Enumerates the leaf block addresses reachable from `root` in DAG (record) order. A pre-order walk
/// that, at each index block, descends its children left-to-right; leaves are appended as encountered.
/// `None` on a missing/corrupt/malformed block (verified read) or if the reachable set exceeds the bound.
fn ordered_leaves(
  root: BlockAddress,
  store: &dyn BlockStore,
) -> Option<std::vec::Vec<BlockAddress>> {
  let mut out = std::vec::Vec::new();
  let mut visited = std::collections::BTreeSet::new();
  // Work stack of addresses to expand, in REVERSE order so the top of the stack is the next-in-order node.
  let mut stack = std::vec![root];
  while let Some(addr) = stack.pop() {
    if !visited.insert(addr) {
      continue;
    }
    if visited.len() > super::block_sync::MAX_REACHABLE_BLOCKS {
      return None;
    }
    let block = read_verified_block(store, addr)?;
    match block_kind(&block) {
      Some(TAG_INDEX) => {
        for child in index_children(&block).into_iter().rev() {
          stack.push(child);
        }
      }
      Some(TAG_LEAF) => out.push(addr),
      _ => return None,
    }
  }
  Some(out)
}

#[cfg(test)]
mod tests;

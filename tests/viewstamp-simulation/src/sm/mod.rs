use bytes::Bytes;
use viewstamp_proto::{
  BatchView, BlockAddress, BlockStore, OpNumber, ReplyBuilder, RestoreError, StateMachine,
  block_address,
};

/// The number of consecutive `applied` entries packed into one DAG leaf block.
///
/// A leaf's bytes — and therefore its content address — depend ONLY on the entries it holds, so a
/// FULL leaf keeps the same address across later appends. That stability is what makes a checkpoint
/// incremental: appending past a full leaf rewrites only the (new) trailing leaf and the index
/// root, leaving every earlier full leaf shared by identical address.
const DAG_LEAF_RUN: usize = 4;

/// Tag byte prefixing a DAG leaf block (a run of `applied` entries).
const DAG_LEAF_TAG: u8 = 0x00;

/// Tag byte prefixing a DAG index (root) block (the ordered list of leaf addresses).
const DAG_INDEX_TAG: u8 = 0x01;

/// Encodes one DAG leaf: the leaf tag followed by `entries`, each `op:u64-be | len:u64-be | body`.
///
/// Because the bytes are a pure function of the entries (no position, no neighbours), a full leaf
/// hashes to the same [`BlockAddress`] regardless of what is appended after it.
fn encode_leaf(entries: &[(u64, Bytes)]) -> Bytes {
  let mut out = Vec::new();
  out.push(DAG_LEAF_TAG);
  for (op, body) in entries {
    out.extend_from_slice(&op.to_be_bytes());
    out.extend_from_slice(&(body.len() as u64).to_be_bytes());
    out.extend_from_slice(body);
  }
  Bytes::from(out)
}

/// Decodes a DAG leaf's entries. Panics on a malformed leaf — the sim only ever feeds back blocks
/// it wrote itself, so a parse failure is a sim bug, not a protocol input to recover from.
fn decode_leaf(block: &[u8]) -> Vec<(u64, Bytes)> {
  assert_eq!(
    block.first().copied(),
    Some(DAG_LEAF_TAG),
    "decode_leaf on a non-leaf block"
  );
  let mut entries = Vec::new();
  let mut i = 1usize;
  while i < block.len() {
    let op = u64::from_be_bytes(block[i..i + 8].try_into().unwrap());
    i += 8;
    let len = u64::from_be_bytes(block[i..i + 8].try_into().unwrap()) as usize;
    i += 8;
    entries.push((op, Bytes::copy_from_slice(&block[i..i + len])));
    i += len;
  }
  entries
}

/// Encodes the index (root) block: the index tag, the leaf count as `u32-be`, then each leaf
/// address (16 bytes) in log order.
fn encode_index(leaves: &[BlockAddress]) -> Bytes {
  let mut out = Vec::new();
  out.push(DAG_INDEX_TAG);
  out.extend_from_slice(&(leaves.len() as u32).to_be_bytes());
  for addr in leaves {
    out.extend_from_slice(addr.as_bytes());
  }
  Bytes::from(out)
}

/// Chunks `applied` into leaves of [`DAG_LEAF_RUN`] entries (the last leaf may be partial), writes
/// every leaf and the index block into `store`, and returns the index block's address as the root.
///
/// Re-writing an unchanged full leaf recomputes its identical address, so the write is idempotent;
/// only a changed trailing leaf and the index block differ from the previous checkpoint generation.
fn dag_checkpoint(applied: &[(u64, Bytes)], store: &mut dyn BlockStore) -> BlockAddress {
  let mut leaves = Vec::new();
  for chunk in applied.chunks(DAG_LEAF_RUN) {
    let block = encode_leaf(chunk);
    let addr = block_address(&block);
    store.write_block(addr, block);
    leaves.push(addr);
  }
  let index = encode_index(&leaves);
  let root = block_address(&index);
  store.write_block(root, index);
  root
}

/// The child addresses a block directly references: an index block yields its leaf addresses in log
/// order; a leaf block yields none.
fn dag_block_references(block: &[u8]) -> Vec<BlockAddress> {
  match block.first().copied() {
    Some(DAG_INDEX_TAG) => {
      let count = u32::from_be_bytes(block[1..5].try_into().unwrap()) as usize;
      let mut refs = Vec::with_capacity(count);
      let mut i = 5usize;
      for _ in 0..count {
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&block[i..i + 16]);
        refs.push(BlockAddress::from_bytes(raw));
        i += 16;
      }
      refs
    }
    _ => Vec::new(),
  }
}

/// Reconstructs the `applied` log from the DAG rooted at `root`: read the index, then read each
/// leaf in log order and concatenate its entries.
///
/// `store` is the verify-on-read view the proto hands `restore`: a block missing OR corrupt (its
/// stored bytes do not hash to its address) reads back as `None`, so a `None` is surfaced as a
/// [`RestoreError`] for the proto to re-fetch rather than feeding garbage into the log. Reconstruction
/// is into a LOCAL `Vec` returned only on full success, so the SM that calls this leaves itself
/// unchanged on error.
fn dag_restore(
  root: BlockAddress,
  store: &dyn BlockStore,
) -> Result<Vec<(u64, Bytes)>, RestoreError> {
  let index = store.read_block(root).ok_or(RestoreError::new(root))?;
  let mut applied = Vec::new();
  for leaf_addr in dag_block_references(&index) {
    let leaf = store
      .read_block(leaf_addr)
      .ok_or(RestoreError::new(leaf_addr))?;
    applied.extend(decode_leaf(&leaf));
  }
  Ok(applied)
}

/// The per-unit reply ceiling [`BatchSm`] declares to its [`ReplyBuilder`] and the batching client
/// model budgets each body against. Every [`BatchSm`] unit reply is exactly 8 bytes (the LogSm-style
/// big-endian count), so 32 is comfortably above the real size — the ceiling-priced reply budget is
/// then a strictly looser bound than reality, exactly the aggregator's worst-case-pricing contract.
pub const SIM_UNIT_REPLY_CEILING: usize = 32;

/// The reply-body budget [`BatchSm`] seals each reply batch to, and the second axis of the batching
/// client model's dual-budget packing rule: a body is admitted only while its CEILING-priced reply
/// (`BATCH_COUNT_OVERHEAD + units * (BATCH_UNIT_OVERHEAD + SIM_UNIT_REPLY_CEILING)`) fits this.
/// Far below the real `max_reply_body_len()` so the unit-count cap genuinely binds in the sim
/// (28 units per body) instead of being dwarfed by the request-byte budget.
pub const SIM_REPLY_BODY_BUDGET: usize = 1024;

/// A deterministic state machine that records the sequence of applied operations.
/// The reply is the post-apply length encoded as 8 big-endian bytes — enough for
/// the linearizability checker to verify ordering and uniqueness.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LogSm {
  applied: Vec<(u64, Bytes)>,
}

impl LogSm {
  /// The ordered list of applied `(op, body)` pairs.
  pub fn applied(&self) -> &[(u64, Bytes)] {
    &self.applied
  }
}

impl StateMachine for LogSm {
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes {
    self.applied.push((op.get(), Bytes::copy_from_slice(body)));
    Bytes::from((self.applied.len() as u64).to_be_bytes().to_vec())
  }

  fn checkpoint(&mut self, store: &mut dyn BlockStore) -> BlockAddress {
    dag_checkpoint(&self.applied, store)
  }

  fn block_references(block: &[u8]) -> Vec<BlockAddress> {
    dag_block_references(block)
  }

  fn restore(&mut self, root: BlockAddress, store: &dyn BlockStore) -> Result<(), RestoreError> {
    self.applied = dag_restore(root, store)?;
    Ok(())
  }
}

/// A batch-aware [`LogSm`]: every committed op body is a [`BatchView`]-encoded batch of units, each
/// applied in order with LogSm's per-apply semantics (record it; reply = the post-apply UNIT count
/// as 8 big-endian bytes), the per-unit replies sealed into one reply body by a [`ReplyBuilder`].
///
/// Two histories are recorded:
/// - the per-OP `(op, whole body)` log ([`Self::applied`]) — the same shape as [`LogSm::applied`],
///   so every existing op-level checker (agreement, durability, digests) judges batched runs
///   unchanged;
/// - the per-UNIT `(op, unit_index, unit_bytes)` log ([`Self::units`]) — what the per-unit oracle
///   asserts submitted units against. Derivable from the op log by re-parsing each body, which is
///   exactly how [`StateMachine::restore`] rebuilds it, so the snapshot stays byte-compatible with
///   [`LogSm`]'s encoding while still round-tripping the unit history.
///
/// The sim only produces codec-built bodies (the batching client model and the single-unit wrap
/// both go through the real [`BatchBuilder`](viewstamp_proto::BatchBuilder)), so a malformed body
/// reaching `apply` is a sim bug: it panics loudly rather than degrading into a parse-error path
/// the protocol would never see.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BatchSm {
  applied: Vec<(u64, Bytes)>,
  units: Vec<(u64, u32, Bytes)>,
}

impl BatchSm {
  /// The ordered list of applied `(op, body)` pairs (whole batch bodies, one per op).
  pub fn applied(&self) -> &[(u64, Bytes)] {
    &self.applied
  }

  /// The ordered per-unit history: `(op, unit_index, unit_bytes)`, one entry per applied unit, in
  /// apply order. The deterministic reply of the unit at position `k` is `(k + 1)` as 8 big-endian
  /// bytes — the LogSm count semantics, counting units instead of ops.
  pub fn units(&self) -> &[(u64, u32, Bytes)] {
    &self.units
  }

  /// Parses `body` as a batch and appends its units to the unit history. The single decode path
  /// shared by `apply` and `restore`, so the rebuilt-from-snapshot history is the applied history.
  fn record_units(&mut self, op: u64, body: &[u8]) -> usize {
    let view = match BatchView::parse(body) {
      Ok(view) => view,
      Err(err) => panic!(
        "BatchSm got a malformed body at op {op} ({} bytes): {err} — the sim only produces \
         codec-built bodies, so this is a sim bug",
        body.len()
      ),
    };
    let before = self.units.len();
    for (idx, unit) in view.units().enumerate() {
      self
        .units
        .push((op, idx as u32, Bytes::copy_from_slice(unit)));
    }
    self.units.len() - before
  }
}

impl StateMachine for BatchSm {
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes {
    self.applied.push((op.get(), Bytes::copy_from_slice(body)));
    let first = self.units.len();
    let count = self.record_units(op.get(), body);
    let mut reply = ReplyBuilder::new(SIM_REPLY_BODY_BUDGET, SIM_UNIT_REPLY_CEILING);
    for k in first..first + count {
      // The per-unit LogSm reply: the global unit count after this unit, 8 big-endian bytes.
      reply
        .push(&((k as u64 + 1).to_be_bytes()))
        .expect("8-byte unit replies of a model-capped batch fit the sim reply budget");
    }
    reply
      .finish()
      .expect("a parsed batch carries at least one unit")
  }

  fn checkpoint(&mut self, store: &mut dyn BlockStore) -> BlockAddress {
    dag_checkpoint(&self.applied, store)
  }

  fn block_references(block: &[u8]) -> Vec<BlockAddress> {
    dag_block_references(block)
  }

  fn restore(&mut self, root: BlockAddress, store: &dyn BlockStore) -> Result<(), RestoreError> {
    // Reconstruct the whole DAG FIRST (fallible); only on success replace `self`, so a missing/corrupt
    // block leaves the SM unchanged for the proto to re-fetch and retry.
    let applied = dag_restore(root, store)?;
    self.units.clear();
    for (op, body) in &applied {
      self.record_units(*op, body);
    }
    self.applied = applied;
    Ok(())
  }
}

/// The cluster's state-machine type: every replica runs one of these, and the whole cluster runs
/// the SAME variant (the mode is cluster configuration, fixed before the run starts). `Plain` is
/// the plain [`LogSm`] — the default, leaving per-seed schedules byte-identical — and
/// `Batch` is the batching lane's [`BatchSm`]. Delegation only: no extra state, no PRNG, identical
/// snapshot bytes per variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimSm {
  /// The plain op-level recorder (the default).
  Plain(LogSm),
  /// The batch-aware recorder (the batching lane).
  Batch(BatchSm),
}

impl SimSm {
  /// The ordered list of applied `(op, body)` pairs — the op-level history every existing checker
  /// reads, identical in shape across both variants.
  pub fn applied(&self) -> &[(u64, Bytes)] {
    match self {
      Self::Plain(sm) => sm.applied(),
      Self::Batch(sm) => sm.applied(),
    }
  }

  /// The per-unit history `(op, unit_index, unit_bytes)` — empty for the plain variant (no body is
  /// unit-structured there).
  pub fn units(&self) -> &[(u64, u32, Bytes)] {
    match self {
      Self::Plain(_) => &[],
      Self::Batch(sm) => sm.units(),
    }
  }
}

impl StateMachine for SimSm {
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes {
    match self {
      Self::Plain(sm) => sm.apply(op, body),
      Self::Batch(sm) => sm.apply(op, body),
    }
  }

  fn checkpoint(&mut self, store: &mut dyn BlockStore) -> BlockAddress {
    match self {
      Self::Plain(sm) => sm.checkpoint(store),
      Self::Batch(sm) => sm.checkpoint(store),
    }
  }

  fn block_references(block: &[u8]) -> Vec<BlockAddress> {
    // Both variants share the same DAG block layout, so the reference walk is variant-independent
    // (matching `block_references` being an associated fn with no receiver to dispatch on).
    dag_block_references(block)
  }

  fn restore(&mut self, root: BlockAddress, store: &dyn BlockStore) -> Result<(), RestoreError> {
    match self {
      Self::Plain(sm) => sm.restore(root, store),
      Self::Batch(sm) => sm.restore(root, store),
    }
  }
}

#[cfg(test)]
mod tests;

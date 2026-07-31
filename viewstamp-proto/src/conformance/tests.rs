use bytes::Bytes;

use super::{assert_flush_then_reopen_preserves_blocks, assert_restore_contract};
use crate::{
  OpNumber, RestoreError,
  block_store::{BlockAddress, BlockStore, BlockStoreError, VerifiedView, block_address},
  state_machine::StateMachine,
};

// --- assert_flush_then_reopen_preserves_blocks ---------------------------------------------

/// A store that separates STAGED (buffered, pre-flush) content from a shared "disk": `flush` moves
/// staged blocks onto the `Arc`, and [`reopen`](Self::reopen) drops this handle and builds a fresh
/// one over the SAME `Arc` — the in-process stand-in for "close the file, open it again" that a
/// real backend's harness invocation would perform against its actual medium.
struct SimulatedDiskStore {
  disk: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<BlockAddress, Bytes>>>,
  staged: std::collections::BTreeMap<BlockAddress, Bytes>,
}

impl SimulatedDiskStore {
  fn new() -> Self {
    Self {
      disk: std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new())),
      staged: std::collections::BTreeMap::new(),
    }
  }

  /// The in-process stand-in for a process restart: drop this handle (as a real close would drop
  /// file descriptors) and open a fresh handle over the SAME backing "disk".
  fn reopen(self) -> Self {
    let disk = std::sync::Arc::clone(&self.disk);
    drop(self);
    Self {
      disk,
      staged: std::collections::BTreeMap::new(),
    }
  }
}

impl BlockStore for SimulatedDiskStore {
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    self
      .staged
      .get(&addr)
      .cloned()
      .or_else(|| self.disk.lock().unwrap().get(&addr).cloned())
  }

  fn put(&mut self, block: Bytes) -> BlockAddress {
    let addr = block_address(&block);
    self.staged.insert(addr, block);
    addr
  }

  fn flush(&mut self) -> Result<(), BlockStoreError> {
    // `BTreeMap` has no `drain()`; `append` moves every entry into `disk`, leaving `staged` empty.
    self.disk.lock().unwrap().append(&mut self.staged);
    Ok(())
  }

  fn has_block(&self, addr: BlockAddress) -> bool {
    self.staged.contains_key(&addr) || self.disk.lock().unwrap().contains_key(&addr)
  }
}

#[test]
fn assert_flush_then_reopen_preserves_blocks_passes_a_conforming_store() {
  let store = SimulatedDiskStore::new();
  let blocks = [
    Bytes::from_static(b"one"),
    Bytes::from_static(b"two"),
    Bytes::from_static(b"three"),
  ];
  // The harness itself asserts everything; a clean return is the pass. The reopened store is
  // returned so a caller could keep inspecting it — here just proving it type-checks and is used.
  let reopened =
    assert_flush_then_reopen_preserves_blocks(store, blocks, SimulatedDiskStore::reopen);
  assert!(reopened.has_block(block_address(b"one")));
}

/// A store whose `flush` LIES: it reports `Ok` without making anything durable anywhere a
/// "reopen" can observe — every `reopen` in this test starts a brand-new, empty store, modelling a
/// backend that returns success from its durability barrier while the bytes never actually left
/// process memory (or were written to the wrong place, or not synced at all).
#[derive(Default)]
struct LyingFlushStore {
  staged: std::collections::BTreeMap<BlockAddress, Bytes>,
}

impl BlockStore for LyingFlushStore {
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    self.staged.get(&addr).cloned()
  }

  fn put(&mut self, block: Bytes) -> BlockAddress {
    let addr = block_address(&block);
    self.staged.insert(addr, block);
    addr
  }

  fn flush(&mut self) -> Result<(), BlockStoreError> {
    Ok(()) // lies: nothing staged here is actually durable anywhere a fresh handle can see.
  }

  fn has_block(&self, addr: BlockAddress) -> bool {
    self.staged.contains_key(&addr)
  }
}

#[test]
#[should_panic(expected = "is reported absent after reopen")]
fn assert_flush_then_reopen_preserves_blocks_catches_a_lying_flush() {
  assert_flush_then_reopen_preserves_blocks(
    LyingFlushStore::default(),
    [Bytes::from_static(b"a"), Bytes::from_static(b"b")],
    |_old| LyingFlushStore::default(), // "reopen" sees nothing carried over — the lie surfaces here.
  );
}

#[test]
#[should_panic(expected = "needs at least one staged block")]
fn assert_flush_then_reopen_preserves_blocks_refuses_an_empty_block_set() {
  assert_flush_then_reopen_preserves_blocks(LyingFlushStore::default(), [], |old| old);
}

// --- assert_restore_contract -----------------------------------------------------------------

/// A single-leaf state machine: the image is one counter, materialized as one block with the
/// default (empty) [`StateMachine::block_references`] — the base case the harness must handle
/// without any DAG structure at all.
#[derive(Default)]
struct SingleLeafSm {
  count: u64,
}

impl StateMachine for SingleLeafSm {
  type Image = u64;

  fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> Bytes {
    self.count += 1;
    Bytes::new()
  }

  fn checkpoint_image(&self) -> Self::Image {
    self.count
  }

  fn materialize(image: &Self::Image, store: &mut dyn BlockStore) -> BlockAddress {
    store.put(Bytes::copy_from_slice(&image.to_be_bytes()))
  }

  fn restore_seed(&self) -> Self {
    Self::default()
  }

  fn restore(&mut self, root: BlockAddress, store: &VerifiedView<'_>) -> Result<(), RestoreError> {
    let block = store.read_block(root).ok_or(RestoreError::new(root))?;
    self.count = u64::from_be_bytes(block[..].try_into().unwrap());
    Ok(())
  }
}

#[test]
fn assert_restore_contract_passes_a_single_leaf_state_machine() {
  assert_restore_contract(&SingleLeafSm { count: 42 });
}

/// A two-leaf state machine: the image is two independent counters, materialized as two leaf
/// blocks plus a 32-byte INDEX block listing both children — so a restore must read three blocks
/// (index + two leaves), proving the harness's corruption walk is not fooled by a single-block DAG.
#[derive(Default)]
struct TwoLeafSm {
  a: u64,
  b: u64,
}

impl StateMachine for TwoLeafSm {
  type Image = (u64, u64);

  fn apply(&mut self, _op: OpNumber, body: &[u8]) -> Bytes {
    if body.first() == Some(&0) {
      self.a += 1;
    } else {
      self.b += 1;
    }
    Bytes::new()
  }

  fn checkpoint_image(&self) -> Self::Image {
    (self.a, self.b)
  }

  fn materialize((a, b): &Self::Image, store: &mut dyn BlockStore) -> BlockAddress {
    let leaf_a = store.put(Bytes::copy_from_slice(&a.to_be_bytes()));
    let leaf_b = store.put(Bytes::copy_from_slice(&b.to_be_bytes()));
    let mut index = std::vec::Vec::new();
    index.extend_from_slice(leaf_a.as_bytes());
    index.extend_from_slice(leaf_b.as_bytes());
    store.put(Bytes::from(index))
  }

  fn block_references(block: &[u8]) -> std::vec::Vec<BlockAddress> {
    // Leaves are 8 bytes (a `u64`); only the 32-byte index block references children.
    if block.len() != 32 {
      return std::vec::Vec::new();
    }
    let mut a_raw = [0u8; 16];
    let mut b_raw = [0u8; 16];
    a_raw.copy_from_slice(&block[0..16]);
    b_raw.copy_from_slice(&block[16..32]);
    std::vec![
      BlockAddress::from_bytes(a_raw),
      BlockAddress::from_bytes(b_raw),
    ]
  }

  fn restore_seed(&self) -> Self {
    Self::default()
  }

  fn restore(&mut self, root: BlockAddress, store: &VerifiedView<'_>) -> Result<(), RestoreError> {
    let index = store.read_block(root).ok_or(RestoreError::new(root))?;
    let mut a_raw = [0u8; 16];
    let mut b_raw = [0u8; 16];
    a_raw.copy_from_slice(&index[0..16]);
    b_raw.copy_from_slice(&index[16..32]);
    let leaf_a = BlockAddress::from_bytes(a_raw);
    let leaf_b = BlockAddress::from_bytes(b_raw);
    let a_bytes = store.read_block(leaf_a).ok_or(RestoreError::new(leaf_a))?;
    let b_bytes = store.read_block(leaf_b).ok_or(RestoreError::new(leaf_b))?;
    self.a = u64::from_be_bytes(a_bytes[..].try_into().unwrap());
    self.b = u64::from_be_bytes(b_bytes[..].try_into().unwrap());
    Ok(())
  }
}

#[test]
fn assert_restore_contract_passes_a_multi_block_dag_state_machine() {
  assert_restore_contract(&TwoLeafSm { a: 3, b: 9 });
}

/// A state machine whose `checkpoint_image` is (deliberately, for this falsifier) IMPURE: each call
/// folds a call counter into the captured image, so two captures with no intervening `apply`
/// diverge — exactly the violation `assert_restore_contract` exists to catch.
#[derive(Default)]
struct ImpureCheckpointSm {
  count: u64,
  capture_calls: core::cell::Cell<u64>,
}

impl StateMachine for ImpureCheckpointSm {
  type Image = Bytes;

  fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> Bytes {
    self.count += 1;
    Bytes::new()
  }

  fn checkpoint_image(&self) -> Self::Image {
    let calls = self.capture_calls.get();
    self.capture_calls.set(calls + 1);
    let mut buf = std::vec::Vec::new();
    buf.extend_from_slice(&self.count.to_be_bytes());
    buf.extend_from_slice(&calls.to_be_bytes());
    Bytes::from(buf)
  }

  fn materialize(image: &Self::Image, store: &mut dyn BlockStore) -> BlockAddress {
    store.put(image.clone())
  }

  fn restore_seed(&self) -> Self {
    Self::default()
  }

  fn restore(&mut self, root: BlockAddress, store: &VerifiedView<'_>) -> Result<(), RestoreError> {
    let block = store.read_block(root).ok_or(RestoreError::new(root))?;
    self.count = u64::from_be_bytes(block[..8].try_into().unwrap());
    Ok(())
  }
}

#[test]
#[should_panic(expected = "checkpoint_image must not mutate logical state")]
fn assert_restore_contract_catches_an_impure_checkpoint_image() {
  assert_restore_contract(&ImpureCheckpointSm::default());
}

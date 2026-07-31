//! Synchronous in-memory `Wal`/`Superblock`/`StateMachine` doubles for the transport tests
//! (hoisted from the endpoint test harness; ack-immediately, deterministic).
#![cfg(test)]

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use crate::{
  BlockAddress, BlockStore, CheckpointRead, Header, Instant, MemberId, Membership, OpNumber, Peer,
  ReadId, ReadOk, SlotStatus, StateMachine, Superblock, SuperblockDone, VsrState, Wal, WalDone,
  WriteId, block_address,
  transport::stream::{Intake, RecordIo},
};

/// The genesis membership for an `n`-voter cluster (no learners) used across the transport tests:
/// `MemberId::new(i)` occupies slot `i`, so the relocated quorum/primary/voter logic is byte-identical
/// to the pre-`Membership` `Config` at epoch 0. Pair it with a `Config` whose local member is
/// `MemberId::new(old_replica_index)`.
///
/// Test fixtures use a fixed `config_id = 0` so hand-built test messages (which carry 0) pass the
/// strict ingress gate; production uses the hash-chained id (`Membership::genesis`).
pub(crate) fn genesis(n: u8) -> Membership {
  Membership::from_durable_parts(
    crate::Epoch::new(0),
    n,
    0,
    (0..n as u128).map(MemberId::new).collect(),
    0,
  )
  .expect("valid genesis membership")
}

/// A record layer with a settable authenticated identity and handshake flag, for router/conn tests.
pub(crate) struct MockRecords {
  inbound: std::vec::Vec<u8>,
  outbound: std::vec::Vec<u8>,
  handshaking: bool,
  identity: Option<Peer>,
  /// The most plaintext `write_plaintext` accepts in total before returning a short count, so a
  /// test can exercise the bounded send path. `usize::MAX` => accepts everything (the default).
  write_cap: usize,
  /// When set, `handle_transport_data` stages the input as readable plaintext and then returns
  /// `Intake::Failed`, so a test can drive a decorator's inner-failure path with staged plaintext
  /// that the decorator must refuse to surface afterwards.
  fails: bool,
}
impl MockRecords {
  pub(crate) fn new(handshaking: bool, identity: Option<Peer>) -> Self {
    Self {
      inbound: std::vec::Vec::new(),
      outbound: std::vec::Vec::new(),
      handshaking,
      identity,
      write_cap: usize::MAX,
      fails: false,
    }
  }
  /// Caps the total plaintext `write_plaintext` accepts, so a test can drive the short-write path.
  pub(crate) fn with_write_cap(mut self, cap: usize) -> Self {
    self.write_cap = cap;
    self
  }
  /// Makes `handle_transport_data` stage its input as readable plaintext and then return
  /// `Intake::Failed`, for driving a decorator's inner-failure path with staged plaintext present.
  pub(crate) fn failing(mut self) -> Self {
    self.fails = true;
    self
  }
}
impl RecordIo for MockRecords {
  fn handle_transport_data(&mut self, input: &[u8], _: Instant) -> Intake {
    self.inbound.extend_from_slice(input);
    if self.fails {
      Intake::Failed
    } else {
      Intake::Done
    }
  }
  fn poll_transport_transmit(&mut self, out: &mut std::vec::Vec<u8>) -> usize {
    let n = self.outbound.len();
    out.append(&mut self.outbound);
    n
  }
  fn read_plaintext(&mut self, out: &mut std::vec::Vec<u8>) -> usize {
    let n = self.inbound.len();
    out.append(&mut self.inbound);
    n
  }
  fn write_plaintext(&mut self, plaintext: &[u8]) -> usize {
    let room = self.write_cap.saturating_sub(self.outbound.len());
    let take = room.min(plaintext.len());
    self.outbound.extend_from_slice(&plaintext[..take]);
    take
  }
  fn buffered_outbound(&self) -> usize {
    self.outbound.len()
  }
  fn is_handshaking(&self) -> bool {
    self.handshaking
  }
  fn peer_identity(&self) -> Option<Peer> {
    self.identity
  }
  fn peer_has_closed(&self) -> bool {
    false
  }
  fn send_close_notify(&mut self) {}
  fn clear_outbound(&mut self) {
    self.outbound.clear();
  }
  fn is_secure() -> bool {
    false
  }
}

/// Records every applied `(op, body)` and round-trips them through `snapshot`/`restore`.
#[derive(Default)]
pub(crate) struct CountSm {
  applied: std::vec::Vec<(u64, std::vec::Vec<u8>)>,
}
impl CountSm {
  pub(crate) fn applied(&self) -> &[(u64, std::vec::Vec<u8>)] {
    &self.applied
  }
  fn snapshot(&self) -> Bytes {
    let mut out = std::vec::Vec::new();
    out.extend_from_slice(&(self.applied.len() as u64).to_be_bytes());
    for (op, body) in &self.applied {
      out.extend_from_slice(&op.to_be_bytes());
      out.extend_from_slice(&(body.len() as u64).to_be_bytes());
      out.extend_from_slice(body);
    }
    Bytes::from(out)
  }
  fn restore_bytes(&mut self, snapshot: &[u8]) {
    let mut applied = std::vec::Vec::new();
    let mut i = 0usize;
    let count = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
    i += 8;
    for _ in 0..count {
      let op = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
      i += 8;
      let len = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap()) as usize;
      i += 8;
      applied.push((op, snapshot[i..i + len].to_vec()));
      i += len;
    }
    self.applied = applied;
  }
}
impl StateMachine for CountSm {
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes {
    self.applied.push((op.get(), body.to_vec()));
    Bytes::copy_from_slice(body)
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
    self.restore_bytes(&block);
    Ok(())
  }
}

#[derive(Default)]
pub(crate) struct TestWal {
  entries: BTreeMap<u64, (Header, Bytes)>,
  head: u64,
  done: VecDeque<WalDone>,
}
impl Wal for TestWal {
  fn op_head(&self) -> OpNumber {
    OpNumber::with(self.head)
  }
  fn header(&self, op: OpNumber) -> Option<Header> {
    self.entries.get(&op.get()).map(|(h, _)| *h)
  }
  fn status(&self, op: OpNumber) -> SlotStatus {
    if self.entries.contains_key(&op.get()) {
      SlotStatus::Clean
    } else {
      SlotStatus::Empty
    }
  }
  fn submit_append(&mut self, id: WriteId, op: OpNumber, header: Header, body: Bytes) {
    self.entries.insert(op.get(), (header, body));
    self.head = self.head.max(op.get());
    self.done.push_back(WalDone::Appended(id));
  }
  fn submit_read(&mut self, id: ReadId, op: OpNumber) {
    self.done.push_back(match self.entries.get(&op.get()) {
      Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    });
  }
  fn truncate(&mut self, above: OpNumber) -> std::vec::Vec<WriteId> {
    self.entries.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
    std::vec::Vec::new()
  }
  fn prune(&mut self, below: OpNumber) -> std::vec::Vec<WriteId> {
    self.entries.retain(|&op, _| op >= below.get());
    std::vec::Vec::new()
  }
  fn poll(&mut self) -> Option<WalDone> {
    self.done.pop_front()
  }
}

#[derive(Default)]
pub(crate) struct TestSb {
  state: VsrState,
  done: VecDeque<SuperblockDone>,
  checkpoint: Option<(OpNumber, Bytes)>,
}
impl Superblock for TestSb {
  fn state(&self) -> VsrState {
    self.state.clone()
  }
  fn submit_write(&mut self, id: WriteId, state: VsrState) {
    self.state = state;
    self.done.push_back(SuperblockDone::Wrote(id));
  }
  fn submit_write_checkpoint(&mut self, id: WriteId, op: OpNumber, snapshot: Bytes) {
    self.checkpoint = Some((op, snapshot));
    self.done.push_back(SuperblockDone::Wrote(id));
  }
  fn submit_read_checkpoint(&mut self, id: ReadId) {
    let done = match &self.checkpoint {
      Some((op, snap)) => {
        SuperblockDone::CheckpointRead(CheckpointRead::new(id, *op, snap.clone()))
      }
      None => SuperblockDone::Fault(id),
    };
    self.done.push_back(done);
  }
  fn poll(&mut self) -> Option<SuperblockDone> {
    self.done.pop_front()
  }
}

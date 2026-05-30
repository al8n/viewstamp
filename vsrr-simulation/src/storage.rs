//! Deterministic in-memory `Wal`/`Superblock` impls for the DST harness.
//!
//! M3.0/M3.1: reliable + synchronous (each submit completes immediately into the
//! completion queue). Fault injection (torn / corrupt / absent / crash) is added in M3.3.

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;
use vsrr_proto::{
  CheckpointRead, Header, OpId, OpNumber, ReadOk, SlotStatus, Superblock, SuperblockDone, VsrState,
  Wal, WalDone,
};

/// A reliable in-memory write-ahead log.
#[derive(Debug, Default)]
pub struct InMemoryWal {
  entries: BTreeMap<u64, (Header, Bytes)>,
  head: u64,
  completions: VecDeque<WalDone>,
}

impl InMemoryWal {
  /// Creates an empty WAL.
  pub fn new() -> Self {
    Self {
      entries: BTreeMap::new(),
      head: 0,
      completions: VecDeque::new(),
    }
  }
}

impl Wal for InMemoryWal {
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

  fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes) {
    self.entries.insert(op.get(), (header, body));
    self.head = self.head.max(op.get());
    self.completions.push_back(WalDone::Appended(id));
  }

  fn submit_read(&mut self, id: OpId, op: OpNumber) {
    let done = match self.entries.get(&op.get()) {
      Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    };
    self.completions.push_back(done);
  }

  fn truncate(&mut self, above: OpNumber) {
    self.entries.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
  }

  fn prune(&mut self, below: OpNumber) {
    self.entries.retain(|&op, _| op >= below.get());
  }

  fn poll(&mut self) -> Option<WalDone> {
    self.completions.pop_front()
  }
}

/// A reliable in-memory superblock + checkpoint store.
#[derive(Debug)]
pub struct InMemorySuperblock {
  state: VsrState,
  checkpoint: Option<(OpNumber, Bytes)>,
  completions: VecDeque<SuperblockDone>,
}

impl Default for InMemorySuperblock {
  fn default() -> Self {
    Self::new()
  }
}

impl InMemorySuperblock {
  /// Creates a fresh-cluster superblock (`VsrState::initial`, no checkpoint).
  pub fn new() -> Self {
    Self {
      state: VsrState::initial(),
      checkpoint: None,
      completions: VecDeque::new(),
    }
  }
}

impl Superblock for InMemorySuperblock {
  fn state(&self) -> VsrState {
    self.state
  }

  fn submit_write(&mut self, id: OpId, state: VsrState) {
    self.state = state;
    self.completions.push_back(SuperblockDone::Wrote(id));
  }

  fn submit_write_checkpoint(&mut self, id: OpId, op: OpNumber, snapshot: Bytes) {
    self.checkpoint = Some((op, snapshot));
    self.completions.push_back(SuperblockDone::Wrote(id));
  }

  fn submit_read_checkpoint(&mut self, id: OpId) {
    let done = match &self.checkpoint {
      Some((op, snap)) => {
        SuperblockDone::CheckpointRead(CheckpointRead::new(id, *op, snap.clone()))
      }
      None => SuperblockDone::Fault(id),
    };
    self.completions.push_back(done);
  }

  fn poll(&mut self) -> Option<SuperblockDone> {
    self.completions.pop_front()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use vsrr_proto::{
    ClientId, Header, OpId, OpNumber, RequestNumber, Superblock, View, VsrState, Wal, WalDone,
  };

  #[test]
  fn append_then_read_round_trips() {
    let mut w = InMemoryWal::new();
    let h = Header::new(
      OpNumber::with(1),
      View::new(),
      ClientId::new(7),
      RequestNumber::with(1),
      b"x",
    );
    w.submit_append(
      OpId::new(1),
      OpNumber::with(1),
      h,
      bytes::Bytes::from_static(b"x"),
    );
    assert_eq!(w.poll(), Some(WalDone::Appended(OpId::new(1))));
    assert_eq!(w.op_head(), OpNumber::with(1));
    assert_eq!(w.header(OpNumber::with(1)), Some(h));
    w.submit_read(OpId::new(2), OpNumber::with(1));
    match w.poll() {
      Some(WalDone::ReadOk(r)) => {
        assert_eq!(r.op(), OpNumber::with(1));
        assert_eq!(r.body(), b"x");
      }
      other => panic!("expected ReadOk, got {other:?}"),
    }
    w.submit_read(OpId::new(3), OpNumber::with(9));
    assert_eq!(w.poll(), Some(WalDone::Absent(OpId::new(3))));
  }

  #[test]
  fn truncate_and_prune() {
    let mut w = InMemoryWal::new();
    for op in 1..=5u64 {
      let h = Header::new(
        OpNumber::with(op),
        View::new(),
        ClientId::new(1),
        RequestNumber::with(op),
        b"x",
      );
      w.submit_append(
        OpId::new(op),
        OpNumber::with(op),
        h,
        bytes::Bytes::from_static(b"x"),
      );
      let _ = w.poll();
    }
    w.truncate(OpNumber::with(3));
    assert_eq!(w.op_head(), OpNumber::with(3));
    assert!(w.header(OpNumber::with(4)).is_none());
    w.prune(OpNumber::with(2));
    assert!(w.header(OpNumber::with(1)).is_none());
    assert!(w.header(OpNumber::with(2)).is_some());
  }

  #[test]
  fn superblock_write_reflects_in_state() {
    let mut sb = InMemorySuperblock::new();
    assert_eq!(sb.state(), VsrState::initial());
    let next = VsrState::try_new(
      View::with(2),
      View::with(2),
      OpNumber::with(3),
      OpNumber::with(0),
      0,
    )
    .unwrap();
    sb.submit_write(OpId::new(1), next);
    assert!(sb.poll().is_some());
    assert_eq!(sb.state(), next);
  }
}

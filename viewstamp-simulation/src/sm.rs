use bytes::Bytes;
use viewstamp_proto::{OpNumber, StateMachine};

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

  fn snapshot(&self) -> Bytes {
    let mut out = Vec::new();
    out.extend_from_slice(&(self.applied.len() as u64).to_be_bytes());
    for (op, body) in &self.applied {
      out.extend_from_slice(&op.to_be_bytes());
      out.extend_from_slice(&(body.len() as u64).to_be_bytes());
      out.extend_from_slice(body);
    }
    Bytes::from(out)
  }

  fn restore(&mut self, snapshot: &[u8]) {
    let mut applied = Vec::new();
    let mut i = 0usize;
    let count = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
    i += 8;
    for _ in 0..count {
      let op = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
      i += 8;
      let len = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap()) as usize;
      i += 8;
      applied.push((op, Bytes::copy_from_slice(&snapshot[i..i + len])));
      i += len;
    }
    self.applied = applied;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn apply_records_and_counts() {
    let mut sm = LogSm::default();
    assert_eq!(
      sm.apply(OpNumber::with(1), b"a").as_ref(),
      &1u64.to_be_bytes()
    );
    assert_eq!(
      sm.apply(OpNumber::with(2), b"b").as_ref(),
      &2u64.to_be_bytes()
    );
    assert_eq!(sm.applied().len(), 2);
  }

  #[test]
  fn snapshot_round_trips() {
    let mut sm = LogSm::default();
    sm.apply(OpNumber::with(1), b"a");
    sm.apply(OpNumber::with(2), b"bb");
    let snap = sm.snapshot();
    let mut restored = LogSm::default();
    restored.restore(&snap);
    assert_eq!(restored.applied(), sm.applied());
  }
}

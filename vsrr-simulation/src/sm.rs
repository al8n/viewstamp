use vsrr_proto::{OpNumber, StateMachine};

/// A deterministic state machine that records the sequence of applied operations.
/// The reply is the post-apply length encoded as 8 big-endian bytes — enough for
/// the linearizability checker to verify ordering and uniqueness.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LogSm {
  applied: Vec<(u64, Vec<u8>)>,
}

impl LogSm {
  /// The ordered list of applied `(op, body)` pairs.
  pub fn applied(&self) -> &[(u64, Vec<u8>)] {
    &self.applied
  }
}

impl StateMachine for LogSm {
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Vec<u8> {
    self.applied.push((op.get(), body.to_vec()));
    (self.applied.len() as u64).to_be_bytes().to_vec()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn apply_records_and_counts() {
    let mut sm = LogSm::default();
    assert_eq!(sm.apply(OpNumber::with(1), b"a"), 1u64.to_be_bytes());
    assert_eq!(sm.apply(OpNumber::with(2), b"b"), 2u64.to_be_bytes());
    assert_eq!(sm.applied().len(), 2);
  }
}

use alloc::vec::Vec;

use crate::OpNumber;

/// The replicated application driven by the consensus log.
///
/// `apply` must be deterministic and side-effect-free apart from mutating `self`:
/// every replica applies the same committed ops in the same order and must reach
/// identical state. (Persistence/snapshotting is added in milestone M3.)
pub trait StateMachine {
  /// Applies a committed operation and returns the reply payload.
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Vec<u8>;
}

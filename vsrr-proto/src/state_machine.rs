use bytes::Bytes;

use crate::OpNumber;

/// The replicated application driven by the consensus log.
///
/// `apply` must be deterministic and side-effect-free apart from mutating `self`:
/// every replica applies the same committed ops in the same order and must reach
/// identical state.
///
/// `snapshot` and `restore` support checkpoints and state-sync: a primary can
/// capture its full applied state with `snapshot`, ship the opaque bytes to a
/// lagging replica, and that replica calls `restore` to fast-forward without
/// replaying the entire log.
pub trait StateMachine {
  /// Applies a committed operation and returns the reply payload.
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes;
  /// A deterministic, opaque snapshot of all applied state (for checkpoints + state-sync).
  fn snapshot(&self) -> Bytes;
  /// Restores state from a snapshot produced by [`StateMachine::snapshot`].
  fn restore(&mut self, snapshot: &[u8]);
}

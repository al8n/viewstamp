use bytes::Bytes;

use crate::{ClientId, OpNumber, RequestNumber};

/// An application-facing event emitted by an `Endpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
  /// An operation was committed and applied to the state machine.
  Committed {
    /// The committed op number.
    op: OpNumber,
    /// The client whose request this op carried.
    client: ClientId,
    /// The client request number.
    request: RequestNumber,
    /// The reply payload produced by the state machine.
    reply: Bytes,
  },
}

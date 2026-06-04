use bytes::Bytes;

use crate::{ClientId, OpNumber, RequestNumber};

/// A committed operation that was applied to the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committed {
  op: OpNumber,
  client: ClientId,
  request: RequestNumber,
  reply: Bytes,
}

impl Committed {
  /// Creates a committed-op record.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(op: OpNumber, client: ClientId, request: RequestNumber, reply: Bytes) -> Self {
    Self {
      op,
      client,
      request,
      reply,
    }
  }

  /// The committed op number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The client whose request this op carried.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn client(&self) -> ClientId {
    self.client
  }

  /// The client request number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn request(&self) -> RequestNumber {
    self.request
  }

  /// The reply payload produced by the state machine.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn reply(&self) -> &[u8] {
    self.reply.as_ref()
  }

  /// The reply payload as a cheap-clone `Bytes`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn reply_bytes(&self) -> Bytes {
    self.reply.clone()
  }
}

/// An application-facing event emitted by an `Endpoint`.
#[derive(
  Debug, Clone, PartialEq, Eq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
#[non_exhaustive]
pub enum Event {
  /// An operation was committed and applied to the state machine.
  Committed(Committed),
}
